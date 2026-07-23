use std::str::FromStr;

use bytes::Bytes;
use ibc_proto::cosmos::tx::v1beta1::{
    service_client::ServiceClient, BroadcastMode, BroadcastTxRequest, Fee,
};
use ibc_proto::google::protobuf::Any;
use ibc_relayer_types::events::IbcEvent;
use tendermint::{abci::Code, Hash};
use tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use tendermint_rpc::{Client, HttpClient, Url};
use tonic::codegen::http::Uri;
use tracing::warn;

use crate::chain::cosmos::encode::sign_and_encode_tx;
use crate::chain::cosmos::estimate::estimate_tx_fees;
use crate::chain::cosmos::query::account::query_account;
use crate::chain::cosmos::query::tx::all_ibc_events_from_tx_search_response;
use crate::chain::cosmos::types::account::Account;
use crate::chain::cosmos::types::config::TxConfig;
use crate::chain::cosmos::wait::wait_tx_succeed;
use crate::config::types::Memo;
use crate::error::Error;
use crate::event::IbcEventWithHeight;
use crate::keyring::{Secp256k1KeyPair, SigningKeyPair};
use crate::util::create_grpc_client;

use super::batch::send_batched_messages_and_wait_commit;
use super::estimate::EstimatedGas;

const LARGE_TX_GRPC_FALLBACK_MIN_BYTES: usize = 512 * 1024;

pub async fn estimate_fee_and_send_tx(
    rpc_client: &HttpClient,
    config: &TxConfig,
    key_pair: &Secp256k1KeyPair,
    account: &Account,
    tx_memo: &Memo,
    messages: &[Any],
) -> Result<(Response, EstimatedGas), Error> {
    let (fee, estimated_gas) =
        estimate_tx_fees(config, key_pair, account, tx_memo, messages).await?;

    let tx_result = send_tx_with_fee(
        rpc_client, config, key_pair, account, tx_memo, messages, &fee,
    )
    .await?;

    Ok((tx_result, estimated_gas))
}

async fn send_tx_with_fee(
    rpc_client: &HttpClient,
    config: &TxConfig,
    key_pair: &Secp256k1KeyPair,
    account: &Account,
    tx_memo: &Memo,
    messages: &[Any],
    fee: &Fee,
) -> Result<Response, Error> {
    let tx_bytes = sign_and_encode_tx(config, key_pair, account, tx_memo, messages, fee)?;

    let response = match broadcast_tx_sync(rpc_client, &config.rpc_address, tx_bytes.clone()).await
    {
        Ok(response) => response,
        Err(error) if should_fallback_to_grpc_broadcast(&error, tx_bytes.len()) => {
            warn!(
                chain = %config.chain_id,
                tx_bytes = tx_bytes.len(),
                error = %error,
                "JSON-RPC rejected a large transaction request; retrying broadcast over gRPC"
            );
            broadcast_tx_sync_grpc(&config.grpc_address, tx_bytes).await?
        }
        Err(error) => return Err(error),
    };

    Ok(response)
}

fn should_fallback_to_grpc_broadcast(error: &Error, tx_len: usize) -> bool {
    should_fallback_to_grpc_broadcast_message(error.to_string().as_str(), tx_len)
}

fn should_fallback_to_grpc_broadcast_message(message: &str, tx_len: usize) -> bool {
    let normalized = message.to_ascii_lowercase();
    let explicitly_too_large = normalized.contains("payload too large")
        || normalized.contains("request body too large")
        || normalized.contains("body size is too large")
        || normalized.contains("request entity too large")
        || normalized.contains("status code: 413");

    explicitly_too_large
        || (tx_len >= LARGE_TX_GRPC_FALLBACK_MIN_BYTES
            && (normalized.contains("400 bad request") || normalized.contains("status code: 400")))
}

/// Broadcast a transaction through the Cosmos SDK Tx service in synchronous
/// mode. This avoids JSON/base64 request expansion at HTTP RPC proxies while
/// preserving the CheckTx semantics expected by the normal Tendermint path.
async fn broadcast_tx_sync_grpc(grpc_address: &Uri, tx_bytes: Vec<u8>) -> Result<Response, Error> {
    let request = BroadcastTxRequest {
        tx_bytes,
        mode: BroadcastMode::Sync as i32,
    };
    let mut client = create_grpc_client(grpc_address, ServiceClient::new).await?;
    let tx_response = client
        .broadcast_tx(tonic::Request::new(request))
        .await
        .map_err(|error| Error::grpc_status(error, "broadcast_tx_sync_grpc".to_owned()))?
        .into_inner()
        .tx_response
        .ok_or_else(|| {
            Error::send_tx(
                "Cosmos gRPC BroadcastTx returned no synchronous transaction response".to_owned(),
            )
        })?;

    let hash =
        Hash::from_str(tx_response.txhash.to_ascii_uppercase().as_str()).map_err(|error| {
            Error::send_tx(format!(
                "Cosmos gRPC BroadcastTx returned invalid transaction hash '{}': {error}",
                tx_response.txhash
            ))
        })?;

    Ok(Response {
        codespace: tx_response.codespace,
        code: Code::from(tx_response.code),
        data: Bytes::new(),
        log: tx_response.raw_log,
        hash,
    })
}

/// Perform a `broadcast_tx_sync`, and return the corresponding deserialized response data.
pub async fn broadcast_tx_sync(
    rpc_client: &HttpClient,
    rpc_address: &Url,
    data: Vec<u8>,
) -> Result<Response, Error> {
    let response = rpc_client
        .broadcast_tx_sync(data)
        .await
        .map_err(|e| Error::rpc(rpc_address.clone(), e))?;

    Ok(response)
}

/**
 A simplified version of send_tx that does not depend on `ChainHandle`.

 This allows different wallet ([`Secp256k1KeyPair`]) to be used for
 submitting transactions. The simple behavior as follows:

 - Query the account information on the fly. This may introduce more
   overhead in production, but does not matter in testing.
 - Do not split the provided messages into smaller batches.
 - Wait for TX sync result, and error if any result contains
   error event.
*/
pub async fn simple_send_tx(
    rpc_client: &HttpClient,
    config: &TxConfig,
    key_pair: &Secp256k1KeyPair,
    messages: Vec<Any>,
) -> Result<Vec<IbcEventWithHeight>, Error> {
    let key_account = key_pair.account();
    let account = query_account(&config.grpc_address, &key_account)
        .await?
        .into();

    let (response, _) = estimate_fee_and_send_tx(
        rpc_client,
        config,
        key_pair,
        &account,
        &Memo::default(),
        &messages,
    )
    .await?;

    if response.code.is_err() {
        return Err(Error::check_tx(response));
    }

    let response = wait_tx_succeed(
        rpc_client,
        &config.rpc_address,
        &config.rpc_timeout,
        &response.hash,
    )
    .await?;

    let events = all_ibc_events_from_tx_search_response(&config.chain_id, response);

    Ok(events)
}

pub async fn batched_send_tx(
    rpc_client: &HttpClient,
    config: &TxConfig,
    key_pair: &Secp256k1KeyPair,
    messages: Vec<Any>,
) -> Result<Vec<IbcEventWithHeight>, Error> {
    let key_account = key_pair.account();
    let mut account = query_account(&config.grpc_address, &key_account)
        .await?
        .into();

    let events = send_batched_messages_and_wait_commit(
        rpc_client,
        config,
        key_pair,
        &mut account,
        &Memo::default(),
        messages,
    )
    .await?;

    for event in &events {
        if let IbcEvent::ChainError(ref e) = event.event {
            return Err(Error::send_tx(e.clone()));
        }
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::{should_fallback_to_grpc_broadcast_message, LARGE_TX_GRPC_FALLBACK_MIN_BYTES};

    #[test]
    fn oversized_http_responses_use_grpc_fallback() {
        assert!(should_fallback_to_grpc_broadcast_message(
            "HTTP request failed with non-200 status code: 413 Payload Too Large",
            1,
        ));
        assert!(should_fallback_to_grpc_broadcast_message(
            "Invalid Request: error reading request body: http: request body too large",
            1,
        ));
    }

    #[test]
    fn large_proxy_bad_requests_use_grpc_fallback() {
        assert!(should_fallback_to_grpc_broadcast_message(
            "HTTP request failed with non-200 status code: 400 Bad Request",
            LARGE_TX_GRPC_FALLBACK_MIN_BYTES,
        ));
        assert!(!should_fallback_to_grpc_broadcast_message(
            "HTTP request failed with non-200 status code: 400 Bad Request",
            LARGE_TX_GRPC_FALLBACK_MIN_BYTES - 1,
        ));
    }

    #[test]
    fn unrelated_rpc_errors_do_not_use_grpc_fallback() {
        assert!(!should_fallback_to_grpc_broadcast_message(
            "RPC endpoint timed out",
            LARGE_TX_GRPC_FALLBACK_MIN_BYTES * 2,
        ));
    }
}
