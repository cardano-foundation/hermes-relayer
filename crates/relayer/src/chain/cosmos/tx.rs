use ibc_proto::cosmos::tx::v1beta1::Fee;
use ibc_proto::google::protobuf::Any;
use ibc_relayer_types::events::IbcEvent;
use tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use tendermint_rpc::{Client, HttpClient, Url};

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

use super::batch::send_batched_messages_and_wait_commit;
use super::estimate::EstimatedGas;

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
    if tx_bytes.len() > config.max_tx_size.to_usize() {
        return Err(Error::message_too_big_for_tx(tx_bytes.len()));
    }

    let response = broadcast_tx_sync(rpc_client, &config.rpc_address, tx_bytes).await?;

    Ok(response)
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
    use super::*;
    use crate::chain::cosmos::types::account::{AccountAddress, AccountNumber, AccountSequence};
    use crate::config::types::MaxTxSize;
    use crate::config::ChainConfig;
    use crate::error::ErrorDetail;

    #[tokio::test]
    async fn oversized_signed_transaction_is_rejected_before_broadcast() {
        let config = crate::config::load(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/config/fixtures/relayer_conf_example.toml"
        ))
        .unwrap();
        let chain_id = "chain_A".parse().unwrap();
        let ChainConfig::CosmosSdk(chain) = config.find_chain(&chain_id).unwrap() else {
            panic!("expected Cosmos config")
        };
        let mut config = TxConfig::try_from(chain).unwrap();
        config.max_tx_size = MaxTxSize::new(1024).unwrap();
        let seed = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/config/fixtures/relayer-seed.json"
        ))
        .unwrap();
        let key =
            Secp256k1KeyPair::from_seed_file(&seed, &"m/44'/118'/0'/0/0".parse().unwrap()).unwrap();
        let account = Account {
            address: AccountAddress::new(key.account()),
            number: AccountNumber::new(0),
            sequence: AccountSequence::new(0),
        };
        let client = HttpClient::new("http://127.0.0.1:1").unwrap();
        let error = send_tx_with_fee(
            &client,
            &config,
            &key,
            &account,
            &Memo::default(),
            &[Any {
                type_url: "/test".into(),
                value: vec![0; 2048],
            }],
            &config.gas_config.max_fee,
        )
        .await
        .unwrap_err();
        assert!(matches!(error.detail(), ErrorDetail::MessageTooBigForTx(_)));
    }
}
