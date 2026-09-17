use abscissa_core::clap::Parser;
use ibc_relayer::chain::{endpoint::HostStateHeartbeatOutcome, handle::ChainHandle};
use ibc_relayer_types::core::ics24_host::identifier::ChainId;

use crate::cli_utils::spawn_chain_runtime;
use crate::conclude::Output;
use crate::prelude::*;

/// This uses the same intent, independent UTxO checks and authority binding as
/// the proactive heartbeat worker. It can recover an epoch anchor without
/// starting packet workers or requiring an already accepted current root.
#[derive(Command, Debug, Parser)]
pub struct TxHostStateHeartbeatCmd {
    #[clap(long = "chain", required = true)]
    chain_id: ChainId,
}

impl Runnable for TxHostStateHeartbeatCmd {
    fn run(&self) {
        let chain = match spawn_chain_runtime(&app_config(), &self.chain_id) {
            Ok(chain) => chain,
            Err(error) => Output::error(error).exit(),
        };
        match chain.submit_host_state_heartbeat() {
            Ok(HostStateHeartbeatOutcome::Unsupported) =>
                Output::error("Selected chain does not support Cardano HostState heartbeats").exit(),
            Ok(HostStateHeartbeatOutcome::NotRequired { current_epoch, host_state_epoch }) =>
                Output::success(serde_json::json!({ "required": false, "current_epoch": current_epoch, "host_state_epoch": host_state_epoch })).exit(),
            Ok(HostStateHeartbeatOutcome::Submitted { tx_hash, height, current_epoch, previous_host_state_epoch }) =>
                Output::success(serde_json::json!({ "required": true, "tx_hash": tx_hash, "height": height, "current_epoch": current_epoch, "previous_host_state_epoch": previous_host_state_epoch })).exit(),
            Err(error) => Output::error(error).exit(),
        }
    }
}
