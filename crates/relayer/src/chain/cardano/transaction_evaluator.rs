//! Independent phase-2 evaluation for Gateway-built transactions.
//!
//! Cardano's `is_valid` transaction wrapper is not covered by the transaction
//! body signature. Before signing, Hermes therefore asks an operator-configured
//! Ogmios instance to evaluate the exact unsigned CBOR and requires a successful
//! budget result for every redeemer in that transaction.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pallas_codec::minicbor;
use pallas_primitives::conway::{MintedTx, RedeemerTag};
use reqwest::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::redirect::Policy;
use reqwest::{Certificate, Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::config::CardanoConfig;
use super::error::Error;

const OGMIOS_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OGMIOS_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const OGMIOS_API_KEY_HEADER: HeaderName = HeaderName::from_static("dmtr-api-key");
const OGMIOS_VALIDITY_INTERVAL_ERROR_CODE: i64 = 3118;
const OGMIOS_SUBMISSION_MAX_RETRIES: usize = 5;
const CARDANO_SLOT_LENGTH: Duration = Duration::from_secs(1);
const OGMIOS_SUBMISSION_RETRY_BACKOFF: Duration = Duration::from_millis(250);

#[derive(Clone, Copy)]
struct SubmissionRetryPolicy {
    max_retries: usize,
    slot_length: Duration,
    backoff: Duration,
}

impl Default for SubmissionRetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: OGMIOS_SUBMISSION_MAX_RETRIES,
            slot_length: CARDANO_SLOT_LENGTH,
            backoff: OGMIOS_SUBMISSION_RETRY_BACKOFF,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ValidityIntervalRejection {
    current_slot: u64,
    invalid_before: Option<u64>,
    invalid_after: Option<u64>,
}

/// Script purpose used by Ogmios when identifying a transaction redeemer.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum RedeemerPurpose {
    Spend,
    Mint,
    Publish,
    Withdraw,
    Vote,
    Propose,
}

/// Execution budget independently returned for one transaction redeemer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedRedeemer {
    pub purpose: RedeemerPurpose,
    pub index: u32,
    pub memory: u64,
    pub cpu: u64,
}

/// Client for the Ogmios instance trusted by the local signing policy.
#[derive(Clone)]
pub struct OgmiosTransactionEvaluator {
    endpoint: Url,
    client: Client,
    api_key: Option<HeaderValue>,
}

impl OgmiosTransactionEvaluator {
    /// Construct an evaluator from the Cardano chain configuration.
    pub fn from_config(config: &CardanoConfig) -> Result<Self, Error> {
        let endpoint = config.signing_ogmios_url.as_deref().ok_or_else(|| {
            Error::Config(
                "signing_ogmios_url is required to independently evaluate transactions".to_string(),
            )
        })?;
        Self::new_with_security(
            endpoint,
            config.signing_ogmios_tls_ca_file.clone(),
            config.signing_ogmios_api_key_file.clone(),
        )
    }

    /// Construct an evaluator with optional private-CA trust and API-key authentication.
    pub fn new_with_security(
        endpoint: &str,
        tls_ca_file: Option<PathBuf>,
        api_key_file: Option<PathBuf>,
    ) -> Result<Self, Error> {
        let (endpoint, use_tls) = validate_ogmios_endpoint(endpoint)?;
        if !use_tls && tls_ca_file.is_some() {
            return Err(Error::Config(
                "signing_ogmios_tls_ca_file requires an https:// Ogmios endpoint".to_string(),
            ));
        }

        let mut client = Client::builder()
            .timeout(OGMIOS_REQUEST_TIMEOUT)
            .redirect(Policy::none());
        if let Some(path) = tls_ca_file.as_deref() {
            let pem = read_security_file(path, "TLS CA certificate")?;
            let certificate = Certificate::from_pem(&pem).map_err(|error| {
                Error::Config(format!(
                    "invalid signing Ogmios TLS CA certificate {}: {error}",
                    path.display()
                ))
            })?;
            client = client.add_root_certificate(certificate);
        }

        let api_key = api_key_file.as_deref().map(read_api_key).transpose()?;
        let client = client.build().map_err(|error| {
            Error::Config(format!(
                "failed to configure signing Ogmios client: {error}"
            ))
        })?;

        Ok(Self {
            endpoint,
            client,
            api_key,
        })
    }

    /// Evaluate the exact unsigned transaction and require complete redeemer coverage.
    pub async fn evaluate_unsigned_transaction(
        &self,
        unsigned_tx_cbor: &[u8],
    ) -> Result<Vec<EvaluatedRedeemer>, Error> {
        let declared = transaction_redeemer_budgets(unsigned_tx_cbor)?;
        if declared.is_empty() {
            return Err(Error::Transaction(
                "transaction has no redeemers to evaluate".to_string(),
            ));
        }

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "evaluateTransaction",
            params: EvaluateTransactionParams {
                transaction: SerializedTransaction {
                    cbor: hex::encode(unsigned_tx_cbor),
                },
                additional_utxo: Vec::new(),
            },
            id: 1,
        };
        let mut request_builder = self
            .client
            .post(self.endpoint.clone())
            .header(CONTENT_TYPE, "application/json")
            .json(&request);
        if let Some(api_key) = &self.api_key {
            request_builder = request_builder.header(OGMIOS_API_KEY_HEADER, api_key.clone());
        }

        let mut response = request_builder.send().await.map_err(|error| {
            Error::Transaction(format!(
                "trusted Ogmios transaction evaluation request failed: {}",
                error.without_url()
            ))
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Transaction(format!(
                "trusted Ogmios returned HTTP {status} while evaluating the transaction"
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_OGMIOS_RESPONSE_BYTES as u64)
        {
            return Err(Error::Transaction(format!(
                "trusted Ogmios evaluation response exceeds {MAX_OGMIOS_RESPONSE_BYTES} bytes"
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            Error::Transaction(format!(
                "failed to read trusted Ogmios evaluation response: {}",
                error.without_url()
            ))
        })? {
            let body_len = body.len().checked_add(chunk.len()).ok_or_else(|| {
                Error::Transaction(format!(
                    "trusted Ogmios evaluation response exceeds {MAX_OGMIOS_RESPONSE_BYTES} bytes"
                ))
            })?;
            if body_len > MAX_OGMIOS_RESPONSE_BYTES {
                return Err(Error::Transaction(format!(
                    "trusted Ogmios evaluation response exceeds {MAX_OGMIOS_RESPONSE_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let response: JsonRpcResponse = serde_json::from_slice(&body).map_err(|error| {
            Error::Transaction(format!(
                "trusted Ogmios returned malformed evaluation data: {error}"
            ))
        })?;
        if response.jsonrpc != "2.0" || response.id != 1 {
            return Err(Error::Transaction(
                "trusted Ogmios returned a mismatched JSON-RPC response".to_string(),
            ));
        }
        if let Some(error) = response.error {
            return Err(Error::Transaction(format!(
                "trusted Ogmios rejected transaction evaluation{}",
                format_json_rpc_error(&error)
            )));
        }
        let raw_results = response.result.ok_or_else(|| {
            Error::Transaction("trusted Ogmios evaluation response contains no result".to_string())
        })?;
        if raw_results.is_empty() {
            return Err(Error::Transaction(
                "trusted Ogmios returned an empty transaction evaluation".to_string(),
            ));
        }

        let mut actual = BTreeSet::new();
        let mut evaluated = Vec::with_capacity(raw_results.len());
        for result in raw_results {
            let index = u32::try_from(result.validator.index).map_err(|_| {
                Error::Transaction(format!(
                    "trusted Ogmios returned out-of-range redeemer index {}",
                    result.validator.index
                ))
            })?;
            let pointer = (result.validator.purpose, index);
            if !actual.insert(pointer) {
                return Err(Error::Transaction(format!(
                    "trusted Ogmios returned duplicate evaluation for {:?}[{index}]",
                    result.validator.purpose
                )));
            }
            if result.budget.memory == 0 || result.budget.cpu == 0 {
                return Err(Error::Transaction(format!(
                    "trusted Ogmios returned an empty execution budget for {:?}[{index}]",
                    result.validator.purpose
                )));
            }
            evaluated.push(EvaluatedRedeemer {
                purpose: result.validator.purpose,
                index,
                memory: result.budget.memory,
                cpu: result.budget.cpu,
            });
        }
        ensure_budget_totals_fit(
            evaluated.iter().map(|result| DeclaredBudget {
                memory: result.memory,
                cpu: result.cpu,
            }),
            "trusted Ogmios required",
        )?;

        let expected = declared.keys().copied().collect::<BTreeSet<_>>();
        if actual != expected {
            let missing = expected
                .difference(&actual)
                .map(|(purpose, index)| format!("{purpose:?}[{index}]"))
                .collect::<Vec<_>>();
            let unexpected = actual
                .difference(&expected)
                .map(|(purpose, index)| format!("{purpose:?}[{index}]"))
                .collect::<Vec<_>>();
            return Err(Error::Transaction(format!(
                "trusted Ogmios evaluation does not cover the transaction redeemers (missing: {}; unexpected: {})",
                display_pointer_list(&missing),
                display_pointer_list(&unexpected)
            )));
        }

        for result in &evaluated {
            let declared_budget = declared
                .get(&(result.purpose, result.index))
                .expect("Ogmios redeemer coverage was checked");
            if declared_budget.memory < result.memory || declared_budget.cpu < result.cpu {
                return Err(Error::Transaction(format!(
                    "trusted Ogmios requires {:?}[{}] execution budget memory={} cpu={}, which exceeds the transaction's declared memory={} cpu={}",
                    result.purpose,
                    result.index,
                    result.memory,
                    result.cpu,
                    declared_budget.memory,
                    declared_budget.cpu,
                )));
            }
        }

        evaluated.sort_by_key(|result| (result.purpose, result.index));
        Ok(evaluated)
    }

    /// Submit the exact signed transaction through the same trusted node path.
    ///
    /// This is security-sensitive: Cardano's `is_valid` wrapper is not covered
    /// by the body signature, so the signed bytes must never be handed back to
    /// the untrusted transaction builder for submission.
    pub async fn submit_signed_transaction(&self, signed_tx_cbor: &[u8]) -> Result<String, Error> {
        self.submit_signed_transaction_with_retry_policy(
            signed_tx_cbor,
            SubmissionRetryPolicy::default(),
        )
        .await
    }

    async fn submit_signed_transaction_with_retry_policy(
        &self,
        signed_tx_cbor: &[u8],
        retry_policy: SubmissionRetryPolicy,
    ) -> Result<String, Error> {
        let request = SubmitJsonRpcRequest {
            jsonrpc: "2.0",
            method: "submitTransaction",
            params: SubmitTransactionParams {
                transaction: SerializedTransaction {
                    cbor: hex::encode(signed_tx_cbor),
                },
            },
            id: 2,
        };

        for attempt in 0..=retry_policy.max_retries {
            let mut request_builder = self
                .client
                .post(self.endpoint.clone())
                .header(CONTENT_TYPE, "application/json")
                .json(&request);
            if let Some(api_key) = &self.api_key {
                request_builder = request_builder.header(OGMIOS_API_KEY_HEADER, api_key.clone());
            }

            let mut response = request_builder.send().await.map_err(|error| {
                Error::Transaction(format!(
                    "trusted Ogmios transaction submission request failed: {}",
                    error.without_url()
                ))
            })?;
            let status = response.status();
            if !status.is_success() {
                return Err(Error::Transaction(format!(
                    "trusted Ogmios returned HTTP {status} while submitting the transaction"
                )));
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_OGMIOS_RESPONSE_BYTES as u64)
            {
                return Err(Error::Transaction(format!(
                    "trusted Ogmios submission response exceeds {MAX_OGMIOS_RESPONSE_BYTES} bytes"
                )));
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|error| {
                Error::Transaction(format!(
                    "failed to read trusted Ogmios submission response: {}",
                    error.without_url()
                ))
            })? {
                let body_len = body.len().checked_add(chunk.len()).ok_or_else(|| {
                    Error::Transaction(format!(
                        "trusted Ogmios submission response exceeds {MAX_OGMIOS_RESPONSE_BYTES} bytes"
                    ))
                })?;
                if body_len > MAX_OGMIOS_RESPONSE_BYTES {
                    return Err(Error::Transaction(format!(
                        "trusted Ogmios submission response exceeds {MAX_OGMIOS_RESPONSE_BYTES} bytes"
                    )));
                }
                body.extend_from_slice(&chunk);
            }

            let response: SubmitJsonRpcResponse =
                serde_json::from_slice(&body).map_err(|error| {
                    Error::Transaction(format!(
                        "trusted Ogmios returned malformed submission data: {error}"
                    ))
                })?;
            if response.jsonrpc != "2.0" || response.id != 2 {
                return Err(Error::Transaction(
                    "trusted Ogmios returned a mismatched submission JSON-RPC response".to_string(),
                ));
            }
            if let Some(error) = response.error {
                if let Some(rejection) = parse_validity_interval_rejection(&error)? {
                    if let Some(invalid_after) = rejection.invalid_after {
                        if rejection.current_slot > invalid_after {
                            return Err(Error::Transaction(format!(
                                "trusted Ogmios rejected transaction submission as expired (current slot {}, invalid-after {})",
                                rejection.current_slot, invalid_after
                            )));
                        }
                    }

                    if let Some(invalid_before) = rejection.invalid_before {
                        if rejection.current_slot < invalid_before {
                            if attempt >= retry_policy.max_retries {
                                return Err(Error::Transaction(format!(
                                    "trusted Ogmios still rejected transaction submission as too early after {} retries (current slot {}, invalid-before {})",
                                    retry_policy.max_retries,
                                    rejection.current_slot,
                                    invalid_before
                                )));
                            }

                            let delay = submission_retry_delay(rejection, retry_policy)?;
                            tracing::warn!(
                                current_slot = rejection.current_slot,
                                invalid_before,
                                wait_ms = delay.as_millis(),
                                retry = attempt + 1,
                                max_retries = retry_policy.max_retries,
                                "Trusted Ogmios rejected transaction submission as too early; retrying the exact signed bytes"
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                    }
                }

                return Err(Error::Transaction(format!(
                    "trusted Ogmios rejected transaction submission{}",
                    format_json_rpc_error(&error)
                )));
            }
            let transaction_id = response
                .result
                .map(|result| result.transaction.id)
                .ok_or_else(|| {
                    Error::Transaction(
                        "trusted Ogmios submission response contains no transaction id".to_string(),
                    )
                })?;
            let transaction_id_bytes = hex::decode(&transaction_id).map_err(|_| {
                Error::Transaction(
                    "trusted Ogmios returned a non-hexadecimal transaction id".to_string(),
                )
            })?;
            if transaction_id_bytes.len() != 32 {
                return Err(Error::Transaction(format!(
                    "trusted Ogmios returned a transaction id of {} bytes instead of 32",
                    transaction_id_bytes.len()
                )));
            }
            return Ok(transaction_id);
        }

        Err(Error::Transaction(
            "trusted Ogmios submission retry loop exited unexpectedly".to_string(),
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeclaredBudget {
    memory: u64,
    cpu: u64,
}

fn transaction_redeemer_budgets(
    unsigned_tx_cbor: &[u8],
) -> Result<BTreeMap<(RedeemerPurpose, u32), DeclaredBudget>, Error> {
    let mut decoder = minicbor::Decoder::new(unsigned_tx_cbor);
    let tx: MintedTx<'_> = decoder.decode().map_err(|error| {
        Error::CborDecode(format!(
            "failed to decode transaction for Ogmios evaluation: {error:?}"
        ))
    })?;
    if decoder.position() != unsigned_tx_cbor.len() {
        return Err(Error::CborDecode(
            "failed to decode transaction for Ogmios evaluation: trailing CBOR data".to_string(),
        ));
    }

    let Some(redeemers) = tx.transaction_witness_set.redeemer.as_ref() else {
        return Ok(BTreeMap::new());
    };
    let mut budgets = BTreeMap::new();
    for (key, value) in redeemers.iter() {
        let pointer = (redeemer_purpose(key.tag), key.index);
        let budget = DeclaredBudget {
            memory: value.ex_units.mem,
            cpu: value.ex_units.steps,
        };
        if budgets.insert(pointer, budget).is_some() {
            return Err(Error::Transaction(format!(
                "transaction contains duplicate {:?}[{}] redeemer",
                pointer.0, pointer.1
            )));
        }
    }
    ensure_budget_totals_fit(budgets.values().copied(), "transaction's declared")?;
    Ok(budgets)
}

fn ensure_budget_totals_fit(
    budgets: impl IntoIterator<Item = DeclaredBudget>,
    description: &str,
) -> Result<(), Error> {
    let mut total_memory = 0u64;
    let mut total_cpu = 0u64;
    for budget in budgets {
        total_memory = total_memory.checked_add(budget.memory).ok_or_else(|| {
            Error::Transaction(format!(
                "{description} execution-memory total exceeds the supported u64 range"
            ))
        })?;
        total_cpu = total_cpu.checked_add(budget.cpu).ok_or_else(|| {
            Error::Transaction(format!(
                "{description} CPU-step total exceeds the supported u64 range"
            ))
        })?;
    }
    Ok(())
}

fn redeemer_purpose(tag: RedeemerTag) -> RedeemerPurpose {
    match tag {
        RedeemerTag::Spend => RedeemerPurpose::Spend,
        RedeemerTag::Mint => RedeemerPurpose::Mint,
        RedeemerTag::Cert => RedeemerPurpose::Publish,
        RedeemerTag::Reward => RedeemerPurpose::Withdraw,
        RedeemerTag::Vote => RedeemerPurpose::Vote,
        RedeemerTag::Propose => RedeemerPurpose::Propose,
    }
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    method: &'static str,
    params: EvaluateTransactionParams,
    id: u64,
}

#[derive(Debug, Serialize)]
struct SubmitJsonRpcRequest {
    jsonrpc: &'static str,
    method: &'static str,
    params: SubmitTransactionParams,
    id: u64,
}

#[derive(Debug, Serialize)]
struct SubmitTransactionParams {
    transaction: SerializedTransaction,
}

#[derive(Debug, Serialize)]
struct EvaluateTransactionParams {
    transaction: SerializedTransaction,
    #[serde(rename = "additionalUtxo")]
    additional_utxo: Vec<JsonValue>,
}

#[derive(Debug, Serialize)]
struct SerializedTransaction {
    cbor: String,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: JsonValue,
    #[serde(default)]
    result: Option<Vec<OgmiosEvaluation>>,
    #[serde(default)]
    error: Option<JsonValue>,
}

#[derive(Debug, Deserialize)]
struct SubmitJsonRpcResponse {
    jsonrpc: String,
    id: JsonValue,
    #[serde(default)]
    result: Option<SubmitTransactionResult>,
    #[serde(default)]
    error: Option<JsonValue>,
}

#[derive(Debug, Deserialize)]
struct SubmitTransactionResult {
    transaction: SubmittedTransaction,
}

#[derive(Debug, Deserialize)]
struct SubmittedTransaction {
    id: String,
}

#[derive(Debug, Deserialize)]
struct OgmiosEvaluation {
    validator: OgmiosValidator,
    budget: OgmiosBudget,
}

#[derive(Debug, Deserialize)]
struct OgmiosValidator {
    purpose: RedeemerPurpose,
    index: u64,
}

#[derive(Debug, Deserialize)]
struct OgmiosBudget {
    memory: u64,
    cpu: u64,
}

fn parse_validity_interval_rejection(
    error: &JsonValue,
) -> Result<Option<ValidityIntervalRejection>, Error> {
    if error.get("code").and_then(JsonValue::as_i64) != Some(OGMIOS_VALIDITY_INTERVAL_ERROR_CODE) {
        return Ok(None);
    }

    let data = error
        .get("data")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| {
            Error::Transaction(
                "trusted Ogmios returned malformed validity-interval rejection data".to_string(),
            )
        })?;
    let current_slot = data
        .get("currentSlot")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| {
            Error::Transaction(
                "trusted Ogmios validity-interval rejection has no unsigned currentSlot"
                    .to_string(),
            )
        })?;
    let validity_interval = data
        .get("validityInterval")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| {
            Error::Transaction(
                "trusted Ogmios validity-interval rejection has no validityInterval object"
                    .to_string(),
            )
        })?;
    let invalid_before = parse_optional_slot(validity_interval, "invalidBefore")?;
    let invalid_after = parse_optional_slot(validity_interval, "invalidAfter")?;
    if invalid_before.is_none() && invalid_after.is_none() {
        return Err(Error::Transaction(
            "trusted Ogmios validity-interval rejection contains no interval bounds".to_string(),
        ));
    }

    Ok(Some(ValidityIntervalRejection {
        current_slot,
        invalid_before,
        invalid_after,
    }))
}

fn parse_optional_slot(
    validity_interval: &serde_json::Map<String, JsonValue>,
    field: &str,
) -> Result<Option<u64>, Error> {
    match validity_interval.get(field) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            Error::Transaction(format!(
                "trusted Ogmios validity-interval rejection has a non-unsigned {field}"
            ))
        }),
    }
}

fn submission_retry_delay(
    rejection: ValidityIntervalRejection,
    retry_policy: SubmissionRetryPolicy,
) -> Result<Duration, Error> {
    let invalid_before = rejection.invalid_before.ok_or_else(|| {
        Error::Transaction(
            "trusted Ogmios validity-interval rejection has no invalid-before bound".to_string(),
        )
    })?;
    let wait_slots = invalid_before
        .checked_sub(rejection.current_slot)
        .filter(|wait_slots| *wait_slots > 0)
        .ok_or_else(|| {
            Error::Transaction(
                "trusted Ogmios validity-interval rejection is not a too-early response"
                    .to_string(),
            )
        })?;
    let wait_slots = u32::try_from(wait_slots).map_err(|_| {
        Error::Transaction(
            "trusted Ogmios validity-interval rejection requires an excessive retry delay"
                .to_string(),
        )
    })?;

    retry_policy
        .slot_length
        .checked_mul(wait_slots)
        .and_then(|delay| delay.checked_add(retry_policy.backoff))
        .ok_or_else(|| {
            Error::Transaction(
                "trusted Ogmios validity-interval rejection requires an excessive retry delay"
                    .to_string(),
            )
        })
}

fn format_json_rpc_error(error: &JsonValue) -> String {
    let code = error.get("code").and_then(JsonValue::as_i64);
    let message = error.get("message").and_then(JsonValue::as_str);
    match (code, message) {
        (Some(code), Some(message)) => format!(": code {code}: {message}"),
        (Some(code), None) => format!(": code {code}"),
        (None, Some(message)) => format!(": {message}"),
        (None, None) => String::new(),
    }
}

fn display_pointer_list(pointers: &[String]) -> String {
    if pointers.is_empty() {
        "none".to_string()
    } else {
        pointers.join(", ")
    }
}

fn validate_ogmios_endpoint(endpoint: &str) -> Result<(Url, bool), Error> {
    let endpoint = Url::parse(endpoint)
        .map_err(|error| Error::Config(format!("invalid signing Ogmios endpoint: {error}")))?;
    if endpoint.host_str().is_none() {
        return Err(Error::Config(
            "signing Ogmios endpoint must include a host".to_string(),
        ));
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err(Error::Config(
            "signing Ogmios endpoint must not contain credentials; use the API-key file"
                .to_string(),
        ));
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(Error::Config(
            "signing Ogmios endpoint must not contain a query or fragment".to_string(),
        ));
    }

    let use_tls = match endpoint.scheme() {
        "https" => true,
        "http" if is_loopback_host(endpoint.host_str().expect("host checked above")) => false,
        "http" => {
            return Err(Error::Config(format!(
                "refusing plaintext connection to non-loopback signing Ogmios host '{}'; use an https:// endpoint",
                endpoint.host_str().expect("host checked above")
            )))
        }
        scheme => {
            return Err(Error::Config(format!(
                "unsupported signing Ogmios endpoint scheme '{scheme}'; use https://, or http:// for loopback only"
            )))
        }
    };

    Ok((endpoint, use_tls))
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    host.eq_ignore_ascii_case("localhost")
        || matches!(host.parse::<IpAddr>(), Ok(address) if address.is_loopback())
}

fn read_security_file(path: &Path, description: &str) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|error| {
        Error::Config(format!(
            "failed to read signing Ogmios {description} file {}: {error}",
            path.display()
        ))
    })
}

fn read_api_key(path: &Path) -> Result<HeaderValue, Error> {
    let bytes = read_security_file(path, "API key")?;
    let api_key = std::str::from_utf8(&bytes).map_err(|error| {
        Error::Config(format!(
            "signing Ogmios API-key file {} is not valid UTF-8: {error}",
            path.display()
        ))
    })?;
    api_key_header(api_key)
}

fn api_key_header(api_key: &str) -> Result<HeaderValue, Error> {
    let api_key = api_key.trim();
    if api_key.is_empty() {
        return Err(Error::Config(
            "signing Ogmios API key must not be empty".to_string(),
        ));
    }
    let mut header = HeaderValue::from_str(api_key).map_err(|_| {
        Error::Config("signing Ogmios API key contains invalid HTTP header characters".to_string())
    })?;
    header.set_sensitive(true);
    Ok(header)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    fn unsigned_tx_with_redeemers() -> Vec<u8> {
        unsigned_tx_with_declared_budgets([(50, 500), (25, 250)])
    }

    fn unsigned_tx_with_declared_budgets(budgets: [(u64, u64); 2]) -> Vec<u8> {
        let mut output = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut output);
        encoder.array(4).unwrap();

        encoder.map(3).unwrap();
        encoder.u8(0).unwrap();
        encoder.array(0).unwrap();
        encoder.u8(1).unwrap();
        encoder.array(0).unwrap();
        encoder.u8(2).unwrap();
        encoder.u64(1).unwrap();

        encoder.map(1).unwrap();
        encoder.u8(5).unwrap();
        encoder.array(2).unwrap();
        for ((tag, index), (memory, cpu)) in [(0u8, 0u32), (1u8, 1u32)].into_iter().zip(budgets) {
            encoder.array(4).unwrap();
            encoder.u8(tag).unwrap();
            encoder.u32(index).unwrap();
            encoder.u64(0).unwrap();
            encoder.array(2).unwrap();
            encoder.u64(memory).unwrap();
            encoder.u64(cpu).unwrap();
        }

        encoder.bool(true).unwrap();
        encoder.null().unwrap();
        output
    }

    fn mock_ogmios(
        expected_cbor: Vec<u8>,
        response_body: String,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0, "client closed before sending HTTP headers");
                request.extend_from_slice(&buffer[..read]);
                if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    break position + 4;
                }
            };
            let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .map(str::parse::<usize>)
                })
                .transpose()
                .unwrap()
                .unwrap();
            while request.len() - header_end < content_length {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0, "client closed before sending HTTP body");
                request.extend_from_slice(&buffer[..read]);
            }
            let payload: JsonValue =
                serde_json::from_slice(&request[header_end..header_end + content_length]).unwrap();
            assert_eq!(payload["jsonrpc"], "2.0");
            assert_eq!(payload["method"], "evaluateTransaction");
            assert_eq!(payload["id"], 1);
            assert_eq!(
                payload["params"]["transaction"]["cbor"],
                hex::encode(expected_cbor)
            );
            assert_eq!(payload["params"]["additionalUtxo"], serde_json::json!([]));

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        (format!("http://{address}"), handle)
    }

    fn mock_submit_ogmios(
        expected_cbor: Vec<u8>,
        response_body: String,
    ) -> (String, thread::JoinHandle<()>) {
        mock_submit_ogmios_responses(expected_cbor, vec![response_body])
    }

    fn mock_submit_ogmios_responses(
        expected_cbor: Vec<u8>,
        response_bodies: Vec<String>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for response_body in response_bodies {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                let header_end = loop {
                    let read = stream.read(&mut buffer).unwrap();
                    assert!(read > 0, "client closed before sending HTTP headers");
                    request.extend_from_slice(&buffer[..read]);
                    if let Some(position) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break position + 4;
                    }
                };
                let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(str::trim)
                            .map(str::parse::<usize>)
                    })
                    .transpose()
                    .unwrap()
                    .unwrap();
                while request.len() - header_end < content_length {
                    let read = stream.read(&mut buffer).unwrap();
                    assert!(read > 0, "client closed before sending HTTP body");
                    request.extend_from_slice(&buffer[..read]);
                }
                let payload: JsonValue =
                    serde_json::from_slice(&request[header_end..header_end + content_length])
                        .unwrap();
                assert_eq!(payload["jsonrpc"], "2.0");
                assert_eq!(payload["method"], "submitTransaction");
                assert_eq!(payload["id"], 2);
                assert_eq!(
                    payload["params"]["transaction"]["cbor"],
                    hex::encode(&expected_cbor)
                );

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        (format!("http://{address}"), handle)
    }

    fn successful_evaluation() -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [
                {
                    "validator": { "purpose": "mint", "index": 1 },
                    "budget": { "memory": 20, "cpu": 200 }
                },
                {
                    "validator": { "purpose": "spend", "index": 0 },
                    "budget": { "memory": 10, "cpu": 100 }
                }
            ]
        })
        .to_string()
    }

    fn immediate_retry_policy(max_retries: usize) -> SubmissionRetryPolicy {
        SubmissionRetryPolicy {
            max_retries,
            slot_length: Duration::ZERO,
            backoff: Duration::ZERO,
        }
    }

    fn too_early_submission_response(
        current_slot: JsonValue,
        invalid_before: JsonValue,
        invalid_after: JsonValue,
    ) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "error": {
                "code": OGMIOS_VALIDITY_INTERVAL_ERROR_CODE,
                "message": "The transaction is outside of its validity interval.",
                "data": {
                    "currentSlot": current_slot,
                    "validityInterval": {
                        "invalidBefore": invalid_before,
                        "invalidAfter": invalid_after
                    }
                }
            }
        })
        .to_string()
    }

    #[tokio::test]
    async fn evaluates_exact_cbor_and_requires_all_redeemers() {
        let transaction = unsigned_tx_with_redeemers();
        let (endpoint, server) = mock_ogmios(transaction.clone(), successful_evaluation());
        let evaluator =
            OgmiosTransactionEvaluator::new_with_security(&endpoint, None, None).unwrap();

        let results = evaluator
            .evaluate_unsigned_transaction(&transaction)
            .await
            .unwrap();
        server.join().unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].purpose, RedeemerPurpose::Spend);
        assert_eq!(results[0].index, 0);
        assert_eq!(results[1].purpose, RedeemerPurpose::Mint);
        assert_eq!(results[1].index, 1);
    }

    #[tokio::test]
    async fn submits_exact_signed_cbor_through_trusted_ogmios() {
        let transaction = vec![0x84, 0x01, 0x02, 0x03];
        let expected_id = "ab".repeat(32);
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": { "transaction": { "id": expected_id } }
        })
        .to_string();
        let (endpoint, server) = mock_submit_ogmios(transaction.clone(), response);
        let evaluator =
            OgmiosTransactionEvaluator::new_with_security(&endpoint, None, None).unwrap();

        let transaction_id = evaluator
            .submit_signed_transaction(&transaction)
            .await
            .unwrap();
        server.join().unwrap();

        assert_eq!(transaction_id, expected_id);
    }

    #[tokio::test]
    async fn retries_the_exact_signed_cbor_after_a_too_early_rejection() {
        let transaction = vec![0x84, 0x01, 0x02, 0x03];
        let expected_id = "cd".repeat(32);
        let success = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": { "transaction": { "id": expected_id } }
        })
        .to_string();
        let responses = vec![
            too_early_submission_response(
                serde_json::json!(2965),
                serde_json::json!(2966),
                serde_json::json!(3066),
            ),
            success,
        ];
        let (endpoint, server) = mock_submit_ogmios_responses(transaction.clone(), responses);
        let evaluator =
            OgmiosTransactionEvaluator::new_with_security(&endpoint, None, None).unwrap();

        let transaction_id = evaluator
            .submit_signed_transaction_with_retry_policy(&transaction, immediate_retry_policy(1))
            .await
            .unwrap();
        server.join().unwrap();

        assert_eq!(transaction_id, expected_id);
    }

    #[tokio::test]
    async fn too_early_submission_retries_are_bounded() {
        let transaction = vec![0x84, 0x01, 0x02, 0x03];
        let rejection = too_early_submission_response(
            serde_json::json!(2965),
            serde_json::json!(2966),
            serde_json::json!(3066),
        );
        let (endpoint, server) =
            mock_submit_ogmios_responses(transaction.clone(), vec![rejection.clone(), rejection]);
        let evaluator =
            OgmiosTransactionEvaluator::new_with_security(&endpoint, None, None).unwrap();

        let error = evaluator
            .submit_signed_transaction_with_retry_policy(&transaction, immediate_retry_policy(1))
            .await
            .unwrap_err();
        server.join().unwrap();

        assert!(error.to_string().contains("too early after 1 retries"));
    }

    #[tokio::test]
    async fn expired_malformed_and_nonmatching_submission_errors_are_not_retried() {
        let transaction = vec![0x84, 0x01, 0x02, 0x03];
        let cases = [
            (
                too_early_submission_response(
                    serde_json::json!(3067),
                    serde_json::json!(2966),
                    serde_json::json!(3066),
                ),
                "expired",
            ),
            (
                too_early_submission_response(
                    serde_json::json!("not-a-slot"),
                    serde_json::json!(2966),
                    serde_json::json!(3066),
                ),
                "no unsigned currentSlot",
            ),
            (
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "error": { "code": 3010, "message": "Some scripts failed" }
                })
                .to_string(),
                "code 3010",
            ),
        ];

        for (response, expected_error) in cases {
            let (endpoint, server) = mock_submit_ogmios(transaction.clone(), response);
            let evaluator =
                OgmiosTransactionEvaluator::new_with_security(&endpoint, None, None).unwrap();
            let error = evaluator
                .submit_signed_transaction_with_retry_policy(
                    &transaction,
                    immediate_retry_policy(5),
                )
                .await
                .unwrap_err();
            server.join().unwrap();

            assert!(
                error.to_string().contains(expected_error),
                "unexpected error for {expected_error}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn request_errors_do_not_disclose_the_ogmios_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let secret_marker = "credential-marker";
        let endpoint = format!("http://{address}/{secret_marker}");
        let evaluator =
            OgmiosTransactionEvaluator::new_with_security(&endpoint, None, None).unwrap();

        let evaluation_error = evaluator
            .evaluate_unsigned_transaction(&unsigned_tx_with_redeemers())
            .await
            .unwrap_err()
            .to_string();
        let submission_error = evaluator
            .submit_signed_transaction(&[0x84, 0x01, 0x02, 0x03])
            .await
            .unwrap_err()
            .to_string();

        for error in [evaluation_error, submission_error] {
            assert!(
                error.contains("request failed"),
                "unexpected error: {error}"
            );
            assert!(!error.contains(secret_marker), "endpoint leaked: {error}");
            assert!(!error.contains(&endpoint), "endpoint leaked: {error}");
        }
    }

    #[tokio::test]
    async fn incomplete_evaluation_fails_closed() {
        let transaction = unsigned_tx_with_redeemers();
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [{
                "validator": { "purpose": "spend", "index": 0 },
                "budget": { "memory": 10, "cpu": 100 }
            }]
        })
        .to_string();
        let (endpoint, server) = mock_ogmios(transaction.clone(), response);
        let evaluator =
            OgmiosTransactionEvaluator::new_with_security(&endpoint, None, None).unwrap();

        let error = evaluator
            .evaluate_unsigned_transaction(&transaction)
            .await
            .unwrap_err();
        server.join().unwrap();
        assert!(error.to_string().contains("does not cover"));
    }

    #[tokio::test]
    async fn evaluated_budget_must_not_exceed_declared_ex_units() {
        for (spend_memory, spend_cpu, mint_memory, mint_cpu) in [
            (51, 500, 20, 200),
            (50, 501, 20, 200),
            (10, 100, 26, 250),
            (10, 100, 25, 251),
        ] {
            let transaction = unsigned_tx_with_redeemers();
            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": [
                    {
                        "validator": { "purpose": "spend", "index": 0 },
                        "budget": { "memory": spend_memory, "cpu": spend_cpu }
                    },
                    {
                        "validator": { "purpose": "mint", "index": 1 },
                        "budget": { "memory": mint_memory, "cpu": mint_cpu }
                    }
                ]
            })
            .to_string();
            let (endpoint, server) = mock_ogmios(transaction.clone(), response);
            let evaluator =
                OgmiosTransactionEvaluator::new_with_security(&endpoint, None, None).unwrap();

            let error = evaluator
                .evaluate_unsigned_transaction(&transaction)
                .await
                .unwrap_err();
            server.join().unwrap();
            assert!(
                error
                    .to_string()
                    .contains("exceeds the transaction's declared"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn declared_budget_total_overflow_fails_closed() {
        let transaction = unsigned_tx_with_declared_budgets([(u64::MAX, 1), (1, u64::MAX)]);
        let error = transaction_redeemer_budgets(&transaction).unwrap_err();
        assert!(
            error.to_string().contains("total exceeds"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn evaluated_budget_total_overflow_fails_closed() {
        let transaction = unsigned_tx_with_redeemers();
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [
                {
                    "validator": { "purpose": "spend", "index": 0 },
                    "budget": { "memory": u64::MAX, "cpu": 1 }
                },
                {
                    "validator": { "purpose": "mint", "index": 1 },
                    "budget": { "memory": 1, "cpu": 1 }
                }
            ]
        })
        .to_string();
        let (endpoint, server) = mock_ogmios(transaction.clone(), response);
        let evaluator =
            OgmiosTransactionEvaluator::new_with_security(&endpoint, None, None).unwrap();

        let error = evaluator
            .evaluate_unsigned_transaction(&transaction)
            .await
            .unwrap_err();
        server.join().unwrap();
        assert!(
            error.to_string().contains("total exceeds"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn ogmios_evaluation_error_fails_closed() {
        let transaction = unsigned_tx_with_redeemers();
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": 3010, "message": "Some scripts failed" }
        })
        .to_string();
        let (endpoint, server) = mock_ogmios(transaction.clone(), response);
        let evaluator =
            OgmiosTransactionEvaluator::new_with_security(&endpoint, None, None).unwrap();

        let error = evaluator
            .evaluate_unsigned_transaction(&transaction)
            .await
            .unwrap_err();
        server.join().unwrap();
        assert!(error.to_string().contains("code 3010"));
    }

    #[test]
    fn plaintext_ogmios_is_limited_to_loopback() {
        for endpoint in [
            "http://localhost:1337",
            "http://LOCALHOST.:1337",
            "http://127.0.0.1:1337",
            "http://127.42.0.9:1337",
            "http://[::1]:1337",
        ] {
            assert!(!validate_ogmios_endpoint(endpoint).unwrap().1);
        }
        for endpoint in [
            "http://ogmios:1337",
            "http://0.0.0.0:1337",
            "http://192.168.1.2:1337",
            "http://localhost.example:1337",
        ] {
            let error = validate_ogmios_endpoint(endpoint).unwrap_err();
            assert!(error.to_string().contains("refusing plaintext"));
        }
        assert!(
            validate_ogmios_endpoint("https://ogmios.example")
                .unwrap()
                .1
        );
    }

    #[test]
    fn api_key_header_is_sensitive_and_rejects_control_characters() {
        let header = api_key_header(" secret\n").unwrap();
        assert_eq!(header, "secret");
        assert!(header.is_sensitive());
        assert!(api_key_header("key\nwith-newline").is_err());
    }
}
