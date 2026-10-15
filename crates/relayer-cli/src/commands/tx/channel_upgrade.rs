//! Cardano channel-upgrade steps without an ibc-go relayer counterpart.
//!
//! On Cosmos chains, governance proposes channel upgrades. On Cardano the
//! deployment authority proposes them, so INIT is signed by the chain's key,
//! which must be the HostState deployer. FLUSH certifies that packet lanes of a
//! flushing Cardano channel are drained, which ibc-go does implicitly.

use abscissa_core::clap::Parser;
use abscissa_core::Command;
use ibc_proto::google::protobuf::Any;
use prost::Message;

use ibc_relayer::chain::cardano::gateway_client::CHANNEL_UPGRADE_FLUSH_TYPE_URL;
use ibc_relayer::chain::cardano::generated::ibc::core::channel::v1::{
    MsgChannelUpgradeCancel, MsgChannelUpgradeFlush, MsgChannelUpgradeInit, UpgradeFields,
};
use ibc_relayer::chain::handle::ChainHandle;
use ibc_relayer::chain::requests::{IncludeProof, QueryChannelRequest, QueryHeight};
use ibc_relayer::chain::tracking::TrackedMsgs;
use ibc_relayer::config::ChainConfig;
use ibc_relayer_types::core::ics04_channel::msgs::{chan_upgrade_cancel, chan_upgrade_init};
use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ChannelId, ConnectionId, PortId};

use crate::cli_utils::spawn_chain_runtime;
use crate::conclude::Output;
use crate::prelude::*;

/// Propose that a Cardano transfer channel move to a replacement connection
/// (ChannelUpgradeInit). The channel keeps its ordering and version.
#[derive(Clone, Command, Debug, Parser, PartialEq, Eq)]
pub struct TxChanUpgradeInitCmd {
    #[clap(
        long = "chain",
        required = true,
        value_name = "CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the Cardano chain"
    )]
    chain_id: ChainId,

    #[clap(
        long = "channel",
        visible_alias = "chan",
        required = true,
        value_name = "CHANNEL_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the Cardano channel"
    )]
    channel_id: ChannelId,

    #[clap(
        long = "connection",
        visible_alias = "conn",
        required = true,
        value_name = "CONNECTION_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the open replacement connection on Cardano"
    )]
    connection_id: ConnectionId,

    #[clap(
        long = "port",
        default_value = "transfer",
        value_name = "PORT_ID",
        help = "Identifier of the channel's port"
    )]
    port_id: PortId,

    #[clap(
        long = "timeout-period-ms",
        default_value = "86400000",
        value_name = "MILLISECONDS",
        help = "How long the counterparty has to open once Cardano starts flushing, from one hour to 30 days"
    )]
    timeout_period_ms: u64,
}

impl Runnable for TxChanUpgradeInitCmd {
    fn run(&self) {
        let chain = cardano_chain(&self.chain_id);
        let (channel, _) = match chain.query_channel(
            QueryChannelRequest {
                port_id: self.port_id.clone(),
                channel_id: self.channel_id.clone(),
                height: QueryHeight::Latest,
            },
            IncludeProof::No,
        ) {
            Ok(channel) => channel,
            Err(e) => Output::error(e).exit(),
        };
        let signer = match chain.get_signer() {
            Ok(signer) => signer,
            Err(e) => Output::error(e).exit(),
        };
        let msg = MsgChannelUpgradeInit {
            port_id: self.port_id.to_string(),
            channel_id: self.channel_id.to_string(),
            fields: Some(UpgradeFields {
                ordering: channel.ordering as i32,
                connection_hops: vec![self.connection_id.to_string()],
                version: channel.version.to_string(),
            }),
            signer: signer.to_string(),
            timeout_period_ms: self.timeout_period_ms,
            expected_upgrade_sequence: Some(channel.upgrade_sequence.into()),
        };
        info!("message ChanUpgradeInit: {:?}", msg);
        send(
            chain,
            chan_upgrade_init::TYPE_URL,
            msg.encode_to_vec(),
            "ChannelUpgradeInit",
        );
    }
}

/// Certify the next drained packet lanes of a flushing Cardano channel
/// (ChannelUpgradeFlush). Repeat until the channel reaches FLUSHCOMPLETE.
#[derive(Clone, Command, Debug, Parser, PartialEq, Eq)]
pub struct TxChanUpgradeFlushCmd {
    #[clap(
        long = "chain",
        required = true,
        value_name = "CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the Cardano chain"
    )]
    chain_id: ChainId,

    #[clap(
        long = "channel",
        visible_alias = "chan",
        required = true,
        value_name = "CHANNEL_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the Cardano channel"
    )]
    channel_id: ChannelId,

    #[clap(
        long = "port",
        default_value = "transfer",
        value_name = "PORT_ID",
        help = "Identifier of the channel's port"
    )]
    port_id: PortId,
}

impl Runnable for TxChanUpgradeFlushCmd {
    fn run(&self) {
        let chain = cardano_chain(&self.chain_id);
        let signer = match chain.get_signer() {
            Ok(signer) => signer,
            Err(e) => Output::error(e).exit(),
        };
        let msg = MsgChannelUpgradeFlush {
            port_id: self.port_id.to_string(),
            channel_id: self.channel_id.to_string(),
            signer: signer.to_string(),
        };
        send(
            chain,
            CHANNEL_UPGRADE_FLUSH_TYPE_URL,
            msg.encode_to_vec(),
            "ChannelUpgradeFlush",
        );
    }
}

/// Cancel a Cardano channel upgrade as the deployment authority, before the
/// channel finishes flushing (ChannelUpgradeCancel without an error receipt).
/// The relayer's `chan-upgrade-cancel` instead proves the counterparty's receipt.
#[derive(Clone, Command, Debug, Parser, PartialEq, Eq)]
pub struct TxChanUpgradeAuthorityCancelCmd {
    #[clap(
        long = "chain",
        required = true,
        value_name = "CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the Cardano chain"
    )]
    chain_id: ChainId,

    #[clap(
        long = "channel",
        visible_alias = "chan",
        required = true,
        value_name = "CHANNEL_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the Cardano channel"
    )]
    channel_id: ChannelId,

    #[clap(
        long = "port",
        default_value = "transfer",
        value_name = "PORT_ID",
        help = "Identifier of the channel's port"
    )]
    port_id: PortId,
}

impl Runnable for TxChanUpgradeAuthorityCancelCmd {
    fn run(&self) {
        let chain = cardano_chain(&self.chain_id);
        let signer = match chain.get_signer() {
            Ok(signer) => signer,
            Err(e) => Output::error(e).exit(),
        };
        let msg = MsgChannelUpgradeCancel {
            port_id: self.port_id.to_string(),
            channel_id: self.channel_id.to_string(),
            error_receipt: None,
            proof_error_receipt: vec![],
            proof_height: None,
            signer: signer.to_string(),
        };
        send(
            chain,
            chan_upgrade_cancel::TYPE_URL,
            msg.encode_to_vec(),
            "ChannelUpgradeCancel",
        );
    }
}

fn cardano_chain(chain_id: &ChainId) -> impl ChainHandle {
    let config = app_config();
    if !matches!(config.find_chain(chain_id), Some(ChainConfig::Cardano(_))) {
        Output::error(format!("{chain_id} is not a Cardano chain")).exit()
    }
    match spawn_chain_runtime(&config, chain_id) {
        Ok(chain) => chain,
        Err(e) => Output::error(e).exit(),
    }
}

fn send(chain: impl ChainHandle, type_url: &str, value: Vec<u8>, name: &'static str) {
    let msgs = TrackedMsgs::new_static(
        vec![Any {
            type_url: type_url.to_string(),
            value,
        }],
        name,
    );
    match chain.send_messages_and_wait_commit(msgs) {
        Ok(events) => Output::success(events).exit(),
        Err(e) => Output::error(e).exit(),
    }
}
