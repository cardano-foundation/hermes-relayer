use std::sync::Arc;

use abscissa_core::clap::Parser;
use abscissa_core::{Command, Runnable};

use ibc_relayer::chain::handle::{BaseChainHandle, ChainHandle};
use ibc_relayer::worker::stellar_packet::{
    spawn_stellar_packet_worker, PacketProofSource, PacketRelayDestination,
};
use ibc_relayer::worker::stellar_packet_adapters::{
    ChainHandleDestination, ChainHandleProofSource,
};
use ibc_relayer_types::core::ics24_host::identifier::ChainId;

use crate::cli_utils::spawn_chain_runtime_generic;
use crate::conclude::Output;
use crate::prelude::*;

#[derive(Clone, Command, Debug, Parser, PartialEq, Eq)]
pub struct StartStellarPacketRelayCmd {
    #[clap(
        long = "src-chain",
        required = true,
        value_name = "SRC_CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the Stellar source chain (must match a [[chains]] block with type='Stellar')"
    )]
    src_chain_id: ChainId,

    #[clap(
        long = "dst-chain",
        required = true,
        value_name = "DST_CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the destination Cosmos chain"
    )]
    dst_chain_id: ChainId,

    #[clap(
        long = "signer",
        value_name = "SIGNER",
        help = "Signer address to embed in MsgRecvPacket (default: derived from destination chain's key)"
    )]
    signer: Option<String>,
}

impl Runnable for StartStellarPacketRelayCmd {
    fn run(&self) {
        let config = (*app_config()).clone();

        let src: BaseChainHandle =
            match spawn_chain_runtime_generic::<BaseChainHandle>(&config, &self.src_chain_id) {
                Ok(h) => h,
                Err(e) => Output::error(format!(
                    "spawn source chain runtime ({}) failed: {e}",
                    self.src_chain_id
                ))
                .exit(),
            };

        let dst: BaseChainHandle =
            match spawn_chain_runtime_generic::<BaseChainHandle>(&config, &self.dst_chain_id) {
                Ok(h) => h,
                Err(e) => Output::error(format!(
                    "spawn destination chain runtime ({}) failed: {e}",
                    self.dst_chain_id
                ))
                .exit(),
            };

        let subscription = match src.subscribe() {
            Ok(s) => s,
            Err(e) => Output::error(format!("{}: subscribe failed: {e}", self.src_chain_id)).exit(),
        };

        let signer = match self.signer.clone() {
            Some(s) => s,
            None => match dst.get_signer() {
                Ok(s) => s.to_string(),
                Err(e) => {
                    Output::error(format!("{}: get_signer failed: {e}", self.dst_chain_id)).exit()
                }
            },
        };

        let proof_source: Arc<dyn PacketProofSource> =
            Arc::new(ChainHandleProofSource::new(Arc::new(src.clone())));
        let destination: Arc<dyn PacketRelayDestination> =
            Arc::new(ChainHandleDestination::new(Arc::new(dst.clone())));

        info!(
            "stellar packet relay starting: src={} dst={} signer={}",
            self.src_chain_id, self.dst_chain_id, signer
        );

        let handle = spawn_stellar_packet_worker(
            self.src_chain_id.clone(),
            subscription,
            Some(proof_source),
            Some(destination),
            signer,
        );

        info!("worker spawned; blocking until interrupted (Ctrl-C)");
        handle.join();
    }
}
