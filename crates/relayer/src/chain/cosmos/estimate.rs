use ibc_proto::cosmos::tx::v1beta1::{Fee, Tx};
use ibc_proto::google::protobuf::Any;
use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use prost::Message;
use tendermint_rpc::Url;
use tonic::codegen::http::Uri;
use tracing::{debug, error, span, warn, Level};

use crate::chain::cosmos::encode::sign_tx;
use crate::chain::cosmos::gas::gas_amount_to_fee;
use crate::chain::cosmos::simulate::send_tx_simulate;
use crate::chain::cosmos::types::account::Account;
use crate::chain::cosmos::types::config::TxConfig;
use crate::chain::cosmos::types::gas::GasConfig;
use crate::config::types::Memo;
use crate::error::Error;
use crate::keyring::Secp256k1KeyPair;
use crate::telemetry;
use crate::util::pretty::PrettyFee;

pub enum EstimatedGas {
    Simulated(u64),
    Default(u64),
}

impl EstimatedGas {
    pub fn get_amount(&self) -> u64 {
        match self {
            Self::Simulated(amount) | Self::Default(amount) => *amount,
        }
    }
}

pub async fn estimate_tx_fees(
    config: &TxConfig,
    key_pair: &Secp256k1KeyPair,
    account: &Account,
    tx_memo: &Memo,
    messages: &[Any],
) -> Result<(Fee, EstimatedGas), Error> {
    let gas_config = &config.gas_config;

    debug!(
        "max fee, for use in tx simulation: {}",
        PrettyFee(&gas_config.max_fee)
    );

    let signed_tx = sign_tx(
        config,
        key_pair,
        account,
        tx_memo,
        messages,
        &gas_config.max_fee,
    )?;

    let tx = Tx {
        body: Some(signed_tx.body),
        auth_info: Some(signed_tx.auth_info),
        signatures: signed_tx.signatures,
    };

    let estimated_fee_and_gas = estimate_fee_with_tx(
        gas_config,
        &config.grpc_address,
        &config.rpc_address,
        &config.chain_id,
        tx,
        account,
    )
    .await?;

    Ok(estimated_fee_and_gas)
}

async fn estimate_fee_with_tx(
    gas_config: &GasConfig,
    grpc_address: &Uri,
    rpc_address: &Url,
    chain_id: &ChainId,
    tx: Tx,
    account: &Account,
) -> Result<(Fee, EstimatedGas), Error> {
    let estimated_gas = {
        crate::time!(
            "estimate_gas_with_tx",
            {
                "src_chain": chain_id,
            }

        );
        estimate_gas_with_tx(gas_config, grpc_address, tx, account).await
    }?;

    let estimated_gas_amount = estimated_gas.get_amount();

    if estimated_gas_amount > gas_config.max_gas {
        debug!(
            id = %chain_id, estimated = ?estimated_gas_amount, max = ?gas_config.max_gas,
            "send_tx: estimated gas is higher than max gas"
        );

        return Err(Error::tx_simulate_gas_estimate_exceeded(
            chain_id.clone(),
            estimated_gas_amount,
            gas_config.max_gas,
        ));
    }

    let adjusted_fee =
        gas_amount_to_fee(gas_config, estimated_gas_amount, chain_id, rpc_address).await;

    debug!(
        id = %chain_id,
        "send_tx: using {} gas, fee {}",
        estimated_gas_amount,
        PrettyFee(&adjusted_fee)
    );

    Ok((adjusted_fee, estimated_gas))
}

/// Try to simulate the given tx in order to estimate how much gas will be needed to submit it.
///
/// It is possible that a batch of messages are fragmented by the caller (`send_msgs`) such that
/// they do not individually verify. For example for the following batch:
/// [`MsgUpdateClient`, `MsgRecvPacket`, ..., `MsgRecvPacket`]
///
/// If the batch is split in two TX-es, the second one will fail the simulation in `deliverTx` check.
/// In this case we use the `default_gas` param.
async fn estimate_gas_with_tx(
    gas_config: &GasConfig,
    grpc_address: &Uri,
    tx: Tx,
    _account: &Account,
) -> Result<EstimatedGas, Error> {
    let require_simulation = requires_observation_simulation(&tx);
    let simulated_gas = send_tx_simulate(grpc_address, tx)
        .await
        .map(|sr| sr.gas_info);

    let _span = span!(Level::ERROR, "estimate_gas").entered();

    match simulated_gas {
        Ok(Some(gas_info)) => {
            debug!(
                "tx simulation successful, gas amount used: {:?}",
                gas_info.gas_used
            );

            Ok(EstimatedGas::Simulated(gas_info.gas_used))
        }

        Ok(None) if require_simulation => {
            Err(Error::grpc_response_param("simulation gas_info".to_owned()))
        }

        Ok(None) => {
            warn!(
                "tx simulation successful but no gas amount used was returned, falling back on default gas: {}",
                gas_config.default_gas
            );

            Ok(EstimatedGas::Default(gas_config.default_gas))
        }

        // If there is a chance that the tx will be accepted once actually submitted, we fall
        // back on the default gas and will attempt to send it anyway.
        // See `can_recover_from_simulation_failure` for more info.
        Err(e) if can_recover_from_simulation_failure(&e, require_simulation) => {
            warn!(
                "failed to simulate tx, falling back on default gas because the error is potentially recoverable: {}",
                e.detail()
            );

            telemetry!(
                simulate_errors,
                &_account.address.to_string(),
                true,
                get_error_text(&e),
            );

            Ok(EstimatedGas::Default(gas_config.default_gas))
        }

        Err(e) => {
            error!(
                "failed to simulate tx. propagating error to caller: {}",
                e.detail()
            );

            telemetry!(
                simulate_errors,
                &_account.address.to_string(),
                false,
                get_error_text(&e),
            );

            // Propagate the error, the retrying mechanism at caller may catch & retry.
            Err(e)
        }
    }
}

// Packed block evidence must fit using a real simulation. The generic fallback
// for dependent packet batches cannot establish a safe observation chunk size.
fn requires_observation_simulation(tx: &Tx) -> bool {
    use ibc_proto::ibc::core::client::v1::MsgUpdateClient;
    use ibc_relayer_types::clients::ics08_cardano_probabilistic::{
        header::PROBABILISTIC_HEADER_TYPE_URL, raw,
    };
    tx.body
        .iter()
        .flat_map(|body| &body.messages)
        .any(|message| {
            if message.type_url != "/ibc.core.client.v1.MsgUpdateClient" {
                return false;
            }
            let Ok(update) = MsgUpdateClient::decode(message.value.as_slice()) else {
                return false;
            };
            let Some(header) = update
                .client_message
                .filter(|header| header.type_url == PROBABILISTIC_HEADER_TYPE_URL)
            else {
                return false;
            };
            raw::ProbabilisticHeader::decode(header.value.as_slice())
                .ok()
                .and_then(|header| header.observation_chunk)
                .is_some_and(|chunk| chunk.operation == 4)
        })
}

/// Determine whether the given error yielded by `tx_simulate`
/// can be recovered from by submitting the tx anyway.
fn can_recover_from_simulation_failure(e: &Error, require_simulation: bool) -> bool {
    use crate::error::ErrorDetail::*;

    if require_simulation {
        return false;
    }
    match e.detail() {
        GrpcStatus(detail) => {
            detail.is_client_state_height_too_low()
                || detail.is_account_sequence_mismatch_that_can_be_ignored()
                || detail.is_out_of_order_packet_sequence_error()
                || detail.is_empty_tx_error()
        }
        _ => false,
    }
}

fn get_error_text(e: &Error) -> String {
    use crate::error::ErrorDetail::*;

    match e.detail() {
        GrpcStatus(detail) => detail.status.code().to_string(),
        detail => detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibc_proto::cosmos::tx::v1beta1::TxBody;
    use ibc_proto::ibc::core::client::v1::MsgUpdateClient;
    use ibc_relayer_types::clients::ics08_cardano_probabilistic::{
        header::PROBABILISTIC_HEADER_TYPE_URL, raw,
    };

    #[test]
    fn block_updates_require_simulation_even_after_reducing_to_one_block() {
        for count in 1..=4 {
            for operation in [1, 2, 4, 5, 6, 7] {
                let header = raw::ProbabilisticHeader {
                    observation_chunk: Some(raw::ObservationChunk {
                        operation,
                        blocks: vec![raw::ProbabilisticBlock::default(); count],
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                let update = MsgUpdateClient {
                    client_id: "08-cardano-probabilistic-0".into(),
                    signer: "inj1relayer".into(),
                    client_message: Some(Any {
                        type_url: PROBABILISTIC_HEADER_TYPE_URL.into(),
                        value: header.encode_to_vec(),
                    }),
                };
                let tx = Tx {
                    body: Some(TxBody {
                        messages: vec![Any {
                            type_url: "/ibc.core.client.v1.MsgUpdateClient".into(),
                            value: update.encode_to_vec(),
                        }],
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                assert_eq!(requires_observation_simulation(&tx), operation == 4);
            }
        }
        assert!(!requires_observation_simulation(&Tx::default()));
    }

    #[test]
    fn block_evidence_does_not_use_default_gas_after_recoverable_simulation_errors() {
        for message in [
            "account sequence mismatch, expected 1, got 2: incorrect account sequence",
            "packet sequence is out of order",
            "invalid empty tx",
            "verification failed: client state height < proof height",
        ] {
            let error =
                Error::grpc_status(tonic::Status::unknown(message), "send_tx_simulate".into());
            assert!(can_recover_from_simulation_failure(&error, false));
            assert!(!can_recover_from_simulation_failure(&error, true));
        }
    }
}
