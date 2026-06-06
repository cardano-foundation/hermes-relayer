use std::sync::Arc;

use abscissa_core::clap::Parser;
use abscissa_core::{Command, Runnable};

use ibc_relayer::chain::handle::{BaseChainHandle, ChainHandle};
use ibc_relayer::worker::stellar_packet::{
    spawn_stellar_packet_worker, ClientUpdater, PacketProofSource, PacketRelayDestination,
    StellarPacketDeps,
};
use ibc_relayer::worker::stellar_packet_adapters::{
    ChainHandleDestination, ChainHandleProofSource, ForeignClientUpdater,
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

        let src_arc = Arc::new(src.clone());
        let dst_arc = Arc::new(dst.clone());

        let proof_source: Arc<dyn PacketProofSource> =
            Arc::new(ChainHandleProofSource::new(src_arc.clone()));
        let destination: Arc<dyn PacketRelayDestination> =
            Arc::new(ChainHandleDestination::new(dst_arc));

        let absence_source: Option<
            Arc<dyn ibc_relayer::worker::stellar_packet::PacketAbsenceProofSource>,
        > = Some(Arc::new(ChainHandleProofSource::new(Arc::new(dst.clone()))));
        let source_submitter: Option<Arc<dyn PacketRelayDestination>> =
            Some(Arc::new(ChainHandleDestination::new(src_arc)));
        let source_signer = match src.get_signer() {
            Ok(s) => s.to_string(),
            Err(_) => signer.clone(),
        };

        info!(
            "stellar packet relay starting: src={} dst={} signer={} source_signer={}",
            self.src_chain_id, self.dst_chain_id, signer, source_signer
        );

        let client_updater: Option<Arc<dyn ClientUpdater>> = Some(Arc::new(
            ForeignClientUpdater::new(Arc::new(dst.clone()), Arc::new(src.clone())),
        ));

        let handle = spawn_stellar_packet_worker(
            self.src_chain_id.clone(),
            subscription,
            StellarPacketDeps {
                proof_source: Some(proof_source),
                destination: Some(destination),
                absence_source,
                source_submitter,
                client_updater,
                ack_source: None,
                source_client_updater: None,
                signer,
                source_signer,
            },
        );

        info!("worker spawned; blocking until interrupted (Ctrl-C)");
        handle.join();
    }
}
