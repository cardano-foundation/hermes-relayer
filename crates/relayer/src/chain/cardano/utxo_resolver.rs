//! Independent UTxO resolution for transaction signing policy checks.
//!
//! The Gateway-provided transaction contains input references, but not the
//! addresses or values of the outputs being spent. This client resolves those
//! outputs through an operator-configured Kupo instance so that signing policy
//! does not have to trust the transaction builder for wallet accounting.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bech32::FromBase32;
use pallas_codec::minicbor;
use pallas_primitives::conway::MintedTx;
use reqwest::header::{HeaderName, HeaderValue, ACCEPT};
use reqwest::redirect::Policy;
use reqwest::{Certificate, Client, Url};
use serde::Deserialize;

use super::config::CardanoConfig;
use super::error::Error;

const KUPO_ACCEPT: &str = "application/json;asset-quantity=string";
const KUPO_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_KUPO_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const KUPO_API_KEY_HEADER: HeaderName = HeaderName::from_static("dmtr-api-key");

/// A Cardano transaction output reference.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransactionOutRef {
    pub transaction_id: [u8; 32],
    pub output_index: u64,
}

impl TransactionOutRef {
    pub fn from_transaction_input(input: &pallas_primitives::conway::TransactionInput) -> Self {
        let mut transaction_id = [0u8; 32];
        transaction_id.copy_from_slice(input.transaction_id.as_ref());
        Self {
            transaction_id,
            output_index: input.index,
        }
    }

    pub fn transaction_id_hex(&self) -> String {
        hex::encode(self.transaction_id)
    }
}

/// A native asset held by a resolved transaction output.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolvedAsset {
    pub policy_id: [u8; 28],
    pub asset_name: Vec<u8>,
    pub quantity: u64,
}

/// Security-relevant fields of an output consumed by the candidate transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedInput {
    pub address: Vec<u8>,
    pub lovelace: u64,
    pub assets: Vec<ResolvedAsset>,
}

/// Independently resolved regular and collateral inputs, keyed by output reference.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvedTransactionInputs {
    pub regular: BTreeMap<TransactionOutRef, ResolvedInput>,
    pub collateral: BTreeMap<TransactionOutRef, ResolvedInput>,
}

impl ResolvedTransactionInputs {
    pub fn regular_input(
        &self,
        input: &pallas_primitives::conway::TransactionInput,
    ) -> Option<&ResolvedInput> {
        self.regular
            .get(&TransactionOutRef::from_transaction_input(input))
    }

    pub fn collateral_input(
        &self,
        input: &pallas_primitives::conway::TransactionInput,
    ) -> Option<&ResolvedInput> {
        self.collateral
            .get(&TransactionOutRef::from_transaction_input(input))
    }
}

/// Client for the Kupo instance trusted by the local signing policy.
#[derive(Clone)]
pub struct KupoInputResolver {
    endpoint: Url,
    client: Client,
    api_key: Option<HeaderValue>,
}

impl KupoInputResolver {
    /// Construct a resolver from the Cardano chain configuration.
    pub fn from_config(config: &CardanoConfig) -> Result<Self, Error> {
        let endpoint = config.signing_utxo_kupo_url.as_deref().ok_or_else(|| {
            Error::Config(
                "signing_utxo_kupo_url is required to independently resolve transaction inputs"
                    .to_string(),
            )
        })?;

        Self::new_with_security(
            endpoint,
            config.signing_utxo_kupo_tls_ca_file.clone(),
            config.signing_utxo_kupo_api_key_file.clone(),
        )
    }

    /// Construct a resolver with optional private-CA trust and API-key authentication.
    pub fn new_with_security(
        endpoint: &str,
        tls_ca_file: Option<PathBuf>,
        api_key_file: Option<PathBuf>,
    ) -> Result<Self, Error> {
        let (endpoint, use_tls) = validate_kupo_endpoint(endpoint)?;
        if !use_tls && tls_ca_file.is_some() {
            return Err(Error::Config(
                "signing_utxo_kupo_tls_ca_file requires an https:// Kupo endpoint".to_string(),
            ));
        }

        let mut client = Client::builder()
            .timeout(KUPO_REQUEST_TIMEOUT)
            .redirect(Policy::none());
        if let Some(path) = tls_ca_file.as_deref() {
            let pem = read_security_file(path, "TLS CA certificate")?;
            let certificate = Certificate::from_pem(&pem).map_err(|error| {
                Error::Config(format!(
                    "invalid signing Kupo TLS CA certificate {}: {error}",
                    path.display()
                ))
            })?;
            client = client.add_root_certificate(certificate);
        }

        let api_key = api_key_file.as_deref().map(read_api_key).transpose()?;
        let client = client.build().map_err(|error| {
            Error::Config(format!("failed to configure signing Kupo client: {error}"))
        })?;

        Ok(Self {
            endpoint,
            client,
            api_key,
        })
    }

    /// Resolve every regular and collateral input in one unsigned transaction.
    ///
    /// The lookup fails unless Kupo returns exactly one unspent output for every
    /// requested reference. Duplicate records, missing records, malformed values,
    /// duplicate transaction inputs, and regular/collateral overlap are rejected.
    pub async fn resolve_unsigned_transaction(
        &self,
        unsigned_tx_cbor: &[u8],
    ) -> Result<ResolvedTransactionInputs, Error> {
        let requested = parse_input_references(unsigned_tx_cbor)?;
        let mut all_refs = requested.regular.clone();
        all_refs.extend(requested.collateral.iter().cloned());

        let mut refs_by_transaction = BTreeMap::<[u8; 32], BTreeSet<u64>>::new();
        for out_ref in &all_refs {
            refs_by_transaction
                .entry(out_ref.transaction_id)
                .or_default()
                .insert(out_ref.output_index);
        }

        let mut resolved = BTreeMap::new();
        for (transaction_id, output_indexes) in refs_by_transaction {
            self.resolve_transaction_outputs(transaction_id, &output_indexes, &mut resolved)
                .await?;
        }

        let missing: Vec<_> = all_refs
            .difference(&resolved.keys().cloned().collect())
            .map(format_out_ref)
            .collect();
        if !missing.is_empty() {
            return Err(Error::Query(format!(
                "trusted Kupo did not resolve unspent transaction inputs: {}",
                missing.join(", ")
            )));
        }

        let regular = requested
            .regular
            .into_iter()
            .map(|out_ref| {
                let output = resolved
                    .get(&out_ref)
                    .expect("all requested Kupo outputs were checked")
                    .clone();
                (out_ref, output)
            })
            .collect();
        let collateral = requested
            .collateral
            .into_iter()
            .map(|out_ref| {
                let output = resolved
                    .get(&out_ref)
                    .expect("all requested Kupo outputs were checked")
                    .clone();
                (out_ref, output)
            })
            .collect();

        Ok(ResolvedTransactionInputs {
            regular,
            collateral,
        })
    }

    async fn resolve_transaction_outputs(
        &self,
        transaction_id: [u8; 32],
        requested_indexes: &BTreeSet<u64>,
        resolved: &mut BTreeMap<TransactionOutRef, ResolvedInput>,
    ) -> Result<(), Error> {
        let transaction_id_hex = hex::encode(transaction_id);
        let url = format!(
            "{}/matches/*@{}?unspent",
            self.endpoint.as_str().trim_end_matches('/'),
            transaction_id_hex
        );
        let mut request = self.client.get(url).header(ACCEPT, KUPO_ACCEPT);
        if let Some(api_key) = &self.api_key {
            request = request.header(KUPO_API_KEY_HEADER, api_key.clone());
        }

        let mut response = request.send().await.map_err(|error| {
            Error::Query(format!(
                "failed to query trusted Kupo for transaction {transaction_id_hex}: {}",
                error.without_url()
            ))
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Query(format!(
                "trusted Kupo returned HTTP {status} for transaction {transaction_id_hex}"
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_KUPO_RESPONSE_BYTES as u64)
        {
            return Err(Error::Query(format!(
                "trusted Kupo response for transaction {transaction_id_hex} exceeds {MAX_KUPO_RESPONSE_BYTES} bytes"
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            Error::Query(format!(
                "failed to read trusted Kupo response for transaction {transaction_id_hex}: {}",
                error.without_url()
            ))
        })? {
            let body_len = body.len().checked_add(chunk.len()).ok_or_else(|| {
                Error::Query(format!(
                    "trusted Kupo response for transaction {transaction_id_hex} exceeds {MAX_KUPO_RESPONSE_BYTES} bytes"
                ))
            })?;
            if body_len > MAX_KUPO_RESPONSE_BYTES {
                return Err(Error::Query(format!(
                    "trusted Kupo response for transaction {transaction_id_hex} exceeds {MAX_KUPO_RESPONSE_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let matches: Vec<KupoMatch> = serde_json::from_slice(&body).map_err(|error| {
            Error::Query(format!(
                "trusted Kupo returned malformed output data for transaction {transaction_id_hex}: {error}"
            ))
        })?;

        for matched in matches {
            let matched_transaction_id =
                decode_fixed_hex::<32>(&matched.transaction_id, "Kupo transaction id")?;
            if matched_transaction_id != transaction_id {
                return Err(Error::Query(format!(
                    "trusted Kupo returned output for unexpected transaction {} while resolving {transaction_id_hex}",
                    matched.transaction_id
                )));
            }
            if !requested_indexes.contains(&matched.output_index) {
                continue;
            }

            let out_ref = TransactionOutRef {
                transaction_id,
                output_index: matched.output_index,
            };
            let output = parse_kupo_output(matched)?;
            if resolved.insert(out_ref.clone(), output).is_some() {
                return Err(Error::Query(format!(
                    "trusted Kupo returned duplicate unspent output {}",
                    format_out_ref(&out_ref)
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct RequestedInputReferences {
    regular: BTreeSet<TransactionOutRef>,
    collateral: BTreeSet<TransactionOutRef>,
}

fn parse_input_references(unsigned_tx_cbor: &[u8]) -> Result<RequestedInputReferences, Error> {
    let mut decoder = minicbor::Decoder::new(unsigned_tx_cbor);
    let tx: MintedTx<'_> = decoder.decode().map_err(|error| {
        Error::CborDecode(format!(
            "failed to decode transaction for input resolution: {error:?}"
        ))
    })?;
    if decoder.position() != unsigned_tx_cbor.len() {
        return Err(Error::CborDecode(
            "failed to decode transaction for input resolution: trailing CBOR data".to_string(),
        ));
    }

    let body = &*tx.transaction_body;
    let regular = collect_out_refs(body.inputs.iter(), "regular")?;
    let collateral = match body.collateral.as_ref() {
        Some(inputs) => collect_out_refs(inputs.iter(), "collateral")?,
        None => BTreeSet::new(),
    };

    if let Some(overlap) = regular.intersection(&collateral).next() {
        return Err(Error::Transaction(format!(
            "regular and collateral inputs overlap at {}",
            format_out_ref(overlap)
        )));
    }

    Ok(RequestedInputReferences {
        regular,
        collateral,
    })
}

fn collect_out_refs<'a>(
    inputs: impl Iterator<Item = &'a pallas_primitives::conway::TransactionInput>,
    kind: &str,
) -> Result<BTreeSet<TransactionOutRef>, Error> {
    let mut out_refs = BTreeSet::new();
    for input in inputs {
        let out_ref = TransactionOutRef::from_transaction_input(input);
        if !out_refs.insert(out_ref.clone()) {
            return Err(Error::Transaction(format!(
                "transaction contains duplicate {kind} input {}",
                format_out_ref(&out_ref)
            )));
        }
    }
    Ok(out_refs)
}

#[derive(Debug, Deserialize)]
struct KupoMatch {
    transaction_id: String,
    output_index: u64,
    address: String,
    value: KupoValue,
}

#[derive(Debug, Deserialize)]
struct KupoValue {
    coins: KupoQuantity,
    #[serde(default)]
    assets: BTreeMap<String, KupoQuantity>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum KupoQuantity {
    Number(u64),
    String(String),
}

impl KupoQuantity {
    fn into_u64(self, description: &str) -> Result<u64, Error> {
        match self {
            Self::Number(value) => Ok(value),
            Self::String(value)
                if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                value
                    .parse::<u64>()
                    .map_err(|_| Error::Query(format!("{description} exceeds the u64 range")))
            }
            Self::String(_) => Err(Error::Query(format!(
                "{description} is not an unsigned decimal integer"
            ))),
        }
    }
}

fn parse_kupo_output(output: KupoMatch) -> Result<ResolvedInput, Error> {
    let address = decode_kupo_address(&output.address)?;
    let lovelace = output.value.coins.into_u64("Kupo lovelace quantity")?;
    let mut assets = Vec::with_capacity(output.value.assets.len());
    let mut asset_ids = BTreeSet::new();

    for (unit, quantity) in output.value.assets {
        let (policy, name) = unit.split_once('.').ok_or_else(|| {
            Error::Query(format!(
                "Kupo asset unit '{unit}' must use policy-id.asset-name form"
            ))
        })?;
        if name.contains('.') {
            return Err(Error::Query(format!(
                "Kupo asset unit '{unit}' contains multiple separators"
            )));
        }
        let policy_id = decode_fixed_hex::<28>(policy, "Kupo asset policy id")?;
        if name.len() > 64 || name.len() % 2 != 0 {
            return Err(Error::Query(format!(
                "Kupo asset name in '{unit}' must contain at most 32 bytes of hexadecimal"
            )));
        }
        let asset_name = hex::decode(name).map_err(|error| {
            Error::Query(format!("invalid Kupo asset name in '{unit}': {error}"))
        })?;
        if !asset_ids.insert((policy_id, asset_name.clone())) {
            return Err(Error::Query(format!(
                "Kupo output contains duplicate normalized asset unit '{unit}'"
            )));
        }
        let quantity = quantity.into_u64("Kupo native-asset quantity")?;
        if quantity == 0 {
            return Err(Error::Query(format!(
                "Kupo asset unit '{unit}' has zero quantity"
            )));
        }
        assets.push(ResolvedAsset {
            policy_id,
            asset_name,
            quantity,
        });
    }
    assets.sort_unstable();

    Ok(ResolvedInput {
        address,
        lovelace,
        assets,
    })
}

fn decode_kupo_address(address: &str) -> Result<Vec<u8>, Error> {
    if address.starts_with("addr") {
        let (hrp, data, _) = bech32::decode(address)
            .map_err(|error| Error::Query(format!("invalid Kupo Cardano address: {error}")))?;
        if hrp != "addr" && hrp != "addr_test" {
            return Err(Error::Query(format!(
                "unsupported Kupo Cardano address prefix '{hrp}'"
            )));
        }
        return Vec::<u8>::from_base32(&data)
            .map_err(|error| Error::Query(format!("invalid Kupo address payload: {error}")));
    }

    let bytes = hex::decode(address)
        .map_err(|error| Error::Query(format!("invalid hexadecimal Kupo address: {error}")))?;
    if bytes.is_empty() {
        return Err(Error::Query("Kupo address is empty".to_string()));
    }
    Ok(bytes)
}

fn decode_fixed_hex<const N: usize>(value: &str, description: &str) -> Result<[u8; N], Error> {
    let bytes = hex::decode(value)
        .map_err(|error| Error::Query(format!("invalid {description}: {error}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        Error::Query(format!(
            "invalid {description}: expected {N} bytes, got {}",
            bytes.len()
        ))
    })
}

fn format_out_ref(out_ref: &TransactionOutRef) -> String {
    format!(
        "{}#{}",
        hex::encode(out_ref.transaction_id),
        out_ref.output_index
    )
}

fn validate_kupo_endpoint(endpoint: &str) -> Result<(Url, bool), Error> {
    let endpoint = Url::parse(endpoint)
        .map_err(|error| Error::Config(format!("invalid signing Kupo endpoint: {error}")))?;
    if endpoint.host_str().is_none() {
        return Err(Error::Config(
            "signing Kupo endpoint must include a host".to_string(),
        ));
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err(Error::Config(
            "signing Kupo endpoint must not contain credentials; use the API-key file".to_string(),
        ));
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(Error::Config(
            "signing Kupo endpoint must not contain a query or fragment".to_string(),
        ));
    }

    let use_tls = match endpoint.scheme() {
        "https" => true,
        "http" if is_loopback_host(endpoint.host_str().expect("host checked above")) => false,
        "http" => {
            return Err(Error::Config(format!(
                "refusing plaintext connection to non-loopback signing Kupo host '{}'; use an https:// endpoint",
                endpoint.host_str().expect("host checked above")
            )))
        }
        scheme => {
            return Err(Error::Config(format!(
                "unsupported signing Kupo endpoint scheme '{scheme}'; use https://, or http:// for loopback only"
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
            "failed to read signing Kupo {description} file {}: {error}",
            path.display()
        ))
    })
}

fn read_api_key(path: &Path) -> Result<HeaderValue, Error> {
    let bytes = read_security_file(path, "API key")?;
    let api_key = std::str::from_utf8(&bytes).map_err(|error| {
        Error::Config(format!(
            "signing Kupo API-key file {} is not valid UTF-8: {error}",
            path.display()
        ))
    })?;
    api_key_header(api_key)
}

fn api_key_header(api_key: &str) -> Result<HeaderValue, Error> {
    let api_key = api_key.trim();
    if api_key.is_empty() {
        return Err(Error::Config(
            "signing Kupo API key must not be empty".to_string(),
        ));
    }
    let mut header = HeaderValue::from_str(api_key).map_err(|_| {
        Error::Config("signing Kupo API key contains invalid HTTP header characters".to_string())
    })?;
    header.set_sensitive(true);
    Ok(header)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use pallas_codec::minicbor;
    use serde_json::json;

    use super::*;

    fn unsigned_tx_fixture(overlap: bool) -> Vec<u8> {
        let mut output = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut output);
        encoder.array(4).unwrap();
        encoder.map(4).unwrap();

        encoder.u8(0).unwrap();
        encoder.array(1).unwrap();
        encoder.array(2).unwrap();
        encoder.bytes(&[0x11; 32]).unwrap();
        encoder.u64(0).unwrap();

        encoder.u8(1).unwrap();
        encoder.array(0).unwrap();
        encoder.u8(2).unwrap();
        encoder.u64(1).unwrap();

        encoder.u8(13).unwrap();
        encoder.array(1).unwrap();
        encoder.array(2).unwrap();
        encoder.bytes(&[0x11; 32]).unwrap();
        encoder.u64(if overlap { 0 } else { 1 }).unwrap();

        encoder.map(0).unwrap();
        encoder.bool(true).unwrap();
        encoder.null().unwrap();
        output
    }

    fn mock_kupo(
        response_body: String,
        expected_api_key: Option<&str>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let expected_api_key = expected_api_key.map(str::to_string);
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 2048];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with(&format!(
                "GET /matches/*@{}?unspent HTTP/1.1",
                "11".repeat(32)
            )));
            assert!(request
                .to_ascii_lowercase()
                .contains("accept: application/json;asset-quantity=string"));
            if let Some(expected_api_key) = expected_api_key {
                assert!(request
                    .lines()
                    .any(|line| line
                        .eq_ignore_ascii_case(&format!("dmtr-api-key: {expected_api_key}"))));
                assert!(!request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer"));
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        (format!("http://{address}"), handle)
    }

    fn kupo_output(index: u64) -> serde_json::Value {
        json!({
            "transaction_id": "11".repeat(32),
            "output_index": index,
            "address": format!("60{}", "aa".repeat(28)),
            "value": {
                "coins": if index == 0 { "9007199254740993" } else { "5000000" },
                "assets": if index == 0 {
                    BTreeMap::from([(format!("{}.01", "bb".repeat(28)), "2")])
                } else {
                    BTreeMap::new()
                }
            }
        })
    }

    #[tokio::test]
    async fn resolves_every_regular_and_collateral_input() {
        let body = serde_json::to_string(&vec![kupo_output(0), kupo_output(1)]).unwrap();
        let (endpoint, server) = mock_kupo(body, Some("test-api-key"));
        let resolver = KupoInputResolver {
            endpoint: Url::parse(&endpoint).unwrap(),
            client: Client::builder()
                .timeout(KUPO_REQUEST_TIMEOUT)
                .build()
                .unwrap(),
            api_key: Some(api_key_header("test-api-key").unwrap()),
        };

        let resolved = resolver
            .resolve_unsigned_transaction(&unsigned_tx_fixture(false))
            .await
            .unwrap();
        server.join().unwrap();

        assert_eq!(resolved.regular.len(), 1);
        assert_eq!(resolved.collateral.len(), 1);
        let regular = resolved.regular.values().next().unwrap();
        assert_eq!(regular.address, [vec![0x60], vec![0xaa; 28]].concat());
        assert_eq!(regular.lovelace, 9_007_199_254_740_993);
        assert_eq!(regular.assets.len(), 1);
        assert_eq!(regular.assets[0].policy_id, [0xbb; 28]);
        assert_eq!(regular.assets[0].asset_name, vec![0x01]);
        assert_eq!(regular.assets[0].quantity, 2);
    }

    #[tokio::test]
    async fn missing_or_duplicate_unspent_outputs_fail_closed() {
        for outputs in [
            vec![kupo_output(0)],
            vec![kupo_output(0), kupo_output(0), kupo_output(1)],
        ] {
            let body = serde_json::to_string(&outputs).unwrap();
            let (endpoint, server) = mock_kupo(body, None);
            let resolver = KupoInputResolver::new_with_security(&endpoint, None, None).unwrap();
            let error = resolver
                .resolve_unsigned_transaction(&unsigned_tx_fixture(false))
                .await
                .unwrap_err();
            server.join().unwrap();

            assert!(
                error.to_string().contains("did not resolve")
                    || error.to_string().contains("duplicate unspent output"),
                "unexpected error: {error}"
            );
        }
    }

    #[tokio::test]
    async fn request_errors_do_not_disclose_the_kupo_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let secret_marker = "credential-marker";
        let endpoint = format!("http://{address}/{secret_marker}");
        let resolver = KupoInputResolver::new_with_security(&endpoint, None, None).unwrap();

        let error = resolver
            .resolve_unsigned_transaction(&unsigned_tx_fixture(false))
            .await
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("failed to query trusted Kupo"),
            "unexpected error: {error}"
        );
        assert!(!error.contains(secret_marker), "endpoint leaked: {error}");
        assert!(!error.contains(&endpoint), "endpoint leaked: {error}");
    }

    #[test]
    fn duplicate_or_overlapping_transaction_inputs_are_rejected() {
        let error = parse_input_references(&unsigned_tx_fixture(true)).unwrap_err();
        assert!(error
            .to_string()
            .contains("regular and collateral inputs overlap"));
    }

    #[test]
    fn transaction_decoder_rejects_trailing_cbor() {
        let mut transaction = unsigned_tx_fixture(false);
        transaction.push(0);
        let error = parse_input_references(&transaction).unwrap_err();
        assert!(error.to_string().contains("trailing CBOR data"));
    }

    #[test]
    fn plaintext_kupo_is_limited_to_loopback() {
        for endpoint in [
            "http://localhost:1442",
            "http://LOCALHOST.:1442",
            "http://127.0.0.1:1442",
            "http://127.42.0.9:1442",
            "http://[::1]:1442",
        ] {
            assert!(!validate_kupo_endpoint(endpoint).unwrap().1);
        }

        for endpoint in [
            "http://kupo:1442",
            "http://0.0.0.0:1442",
            "http://192.168.1.2:1442",
            "http://localhost.example:1442",
        ] {
            let error = validate_kupo_endpoint(endpoint).unwrap_err();
            assert!(error.to_string().contains("refusing plaintext"));
        }
        assert!(validate_kupo_endpoint("https://kupo.example").unwrap().1);
    }

    #[test]
    fn malformed_kupo_values_are_rejected() {
        let malformed = KupoMatch {
            transaction_id: "11".repeat(32),
            output_index: 0,
            address: format!("60{}", "aa".repeat(28)),
            value: KupoValue {
                coins: KupoQuantity::String("-1".to_string()),
                assets: BTreeMap::new(),
            },
        };
        assert!(parse_kupo_output(malformed)
            .unwrap_err()
            .to_string()
            .contains("unsigned decimal"));
    }

    #[test]
    fn api_key_header_is_sensitive_and_rejects_control_characters() {
        let header = api_key_header(" secret\n").unwrap();
        assert_eq!(header, "secret");
        assert!(header.is_sensitive());
        assert!(api_key_header("key\nwith-newline").is_err());
    }
}
