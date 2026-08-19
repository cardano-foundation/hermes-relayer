use abscissa_core::clap::Parser;
use ibc_proto::google::protobuf::Any;
use ibc_relayer::chain::cardano::generated::ibc::cardano::v1::MsgPrunePacketHistory;
use ibc_relayer::chain::cardano::generated::ibc::core::client::v1::Height as RawHeight;
use ibc_relayer_types::core::ics02_client::height::Height;
use prost::Message;
use std::ops::RangeInclusive;

use ibc_relayer::chain::handle::ChainHandle;
use ibc_relayer::chain::requests::{
    IncludeProof, QueryClientStateRequest, QueryHeight, QueryPacketCommitmentRequest,
};
use ibc_relayer::chain::tracking::TrackedMsgs;
use ibc_relayer::config::ChainConfig;
use ibc_relayer::event::IbcEventWithHeight;
use ibc_relayer::link::{Link, LinkParameters};
use ibc_relayer::util::seq_range::parse_seq_range;
use ibc_relayer_types::core::ics04_channel::packet::Sequence;
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentProofBytes;
use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ChannelId, PortId};
use ibc_relayer_types::events::IbcEvent;

use crate::cli_utils::ChainHandlePair;
use crate::conclude::Output;
use crate::error::Error;
use crate::prelude::*;

#[derive(Clone, Command, Debug, Parser, PartialEq, Eq)]
pub struct TxPacketRecvCmd {
    #[clap(
        long = "dst-chain",
        required = true,
        value_name = "DST_CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the destination chain"
    )]
    dst_chain_id: ChainId,

    #[clap(
        long = "src-chain",
        required = true,
        value_name = "SRC_CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the source chain"
    )]
    src_chain_id: ChainId,

    #[clap(
        long = "src-port",
        required = true,
        value_name = "SRC_PORT_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the source port"
    )]
    src_port_id: PortId,

    #[clap(
        long = "src-channel",
        visible_alias = "src-chan",
        required = true,
        value_name = "SRC_CHANNEL_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the source channel"
    )]
    src_channel_id: ChannelId,

    #[clap(
    long = "packet-sequences",
    help = "Sequences of packets to be cleared on `dst-chain`. \
            Either a single sequence or a range of sequences can be specified. \
            If not provided, all pending recv or timeout packets will be cleared. \
            Each element of the comma-separated list must be either a single \
            sequence or a range of sequences. \
            Example: `1,10..20` will clear packets with sequences 1, 10, 11, ..., 20",
    value_delimiter = ',',
    value_parser = parse_seq_range
    )]
    packet_sequences: Vec<RangeInclusive<Sequence>>,

    #[clap(
        long = "packet-data-query-height",
        help = "Exact height at which the packet data is queried via block_results RPC"
    )]
    packet_data_query_height: Option<u64>,
}

impl Runnable for TxPacketRecvCmd {
    fn run(&self) {
        let config = app_config();

        let chains = match ChainHandlePair::spawn(&config, &self.src_chain_id, &self.dst_chain_id) {
            Ok(chains) => chains,
            Err(e) => Output::error(e).exit(),
        };

        let opts = LinkParameters {
            src_port_id: self.src_port_id.clone(),
            src_channel_id: self.src_channel_id.clone(),
            max_memo_size: config.mode.packets.ics20_max_memo_size,
            max_receiver_size: config.mode.packets.ics20_max_receiver_size,

            // Packets are only excluded when clearing
            exclude_src_sequences: vec![],
        };

        let link = match Link::new_from_opts(chains.src, chains.dst, opts, false, false) {
            Ok(link) => link,
            Err(e) => Output::error(e).exit(),
        };

        let packet_data_query_height = self
            .packet_data_query_height
            .map(|height| Height::new(link.a_to_b.src_chain().id().version(), height).unwrap());

        let res: Result<Vec<IbcEvent>, Error> = link
            .relay_recv_packet_and_timeout_messages_with_packet_data_query_height(
                self.packet_sequences.clone(),
                packet_data_query_height,
            )
            .map_err(Error::link);

        match res {
            Ok(ev) => Output::success(ev).exit(),
            Err(e) => Output::error(e).exit(),
        }
    }
}

#[derive(Clone, Command, Debug, Parser, PartialEq, Eq)]
pub struct TxPacketAckCmd {
    #[clap(
        long = "dst-chain",
        required = true,
        value_name = "DST_CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the destination chain"
    )]
    dst_chain_id: ChainId,

    #[clap(
        long = "src-chain",
        required = true,
        value_name = "SRC_CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the source chain"
    )]
    src_chain_id: ChainId,

    #[clap(
        long = "src-port",
        required = true,
        value_name = "SRC_PORT_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the source port"
    )]
    src_port_id: PortId,

    #[clap(
        long = "src-channel",
        visible_alias = "src-chan",
        required = true,
        value_name = "SRC_CHANNEL_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the source channel"
    )]
    src_channel_id: ChannelId,

    #[clap(
        long = "packet-sequences",
        help = "Sequences of packets to be cleared on `dst-chain`. \
                Either a single sequence or a range of sequences can be specified. \
                If not provided, all pending ack packets will be cleared. \
                Each element of the comma-separated list must be either a single \
                sequence or a range of sequences. \
                Example: `1,10..20` will clear packets with sequences 1, 10, 11, ..., 20",
        value_delimiter = ',',
        value_parser = parse_seq_range
    )]
    packet_sequences: Vec<RangeInclusive<Sequence>>,

    #[clap(
        long = "packet-data-query-height",
        help = "Exact height at which the packet data is queried via block_results RPC"
    )]
    packet_data_query_height: Option<u64>,
}

impl Runnable for TxPacketAckCmd {
    fn run(&self) {
        let config = app_config();

        let chains = match ChainHandlePair::spawn(&config, &self.src_chain_id, &self.dst_chain_id) {
            Ok(chains) => chains,
            Err(e) => Output::error(e).exit(),
        };

        let opts = LinkParameters {
            src_port_id: self.src_port_id.clone(),
            src_channel_id: self.src_channel_id.clone(),
            max_memo_size: config.mode.packets.ics20_max_memo_size,
            max_receiver_size: config.mode.packets.ics20_max_receiver_size,

            // Packets are only excluded when clearing
            exclude_src_sequences: vec![],
        };

        let link = match Link::new_from_opts(chains.src, chains.dst, opts, false, false) {
            Ok(link) => link,
            Err(e) => Output::error(e).exit(),
        };

        let packet_data_query_height = self
            .packet_data_query_height
            .map(|height| Height::new(link.a_to_b.src_chain().id().version(), height).unwrap());

        let res: Result<Vec<IbcEvent>, Error> = link
            .relay_ack_packet_messages_with_packet_data_query_height(
                self.packet_sequences.clone(),
                packet_data_query_height,
            )
            .map_err(Error::link);

        match res {
            Ok(ev) => Output::success(ev).exit(),
            Err(e) => Output::error(e).exit(),
        }
    }
}

const PRUNE_PACKET_HISTORY_TYPE_URL: &str = "/ibc.cardano.v1.MsgPrunePacketHistory";

#[derive(Clone, Command, Debug, Parser, PartialEq, Eq)]
pub struct TxPacketPruneCmd {
    #[clap(
        long = "dst-chain",
        required = true,
        value_name = "DST_CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the Cardano destination chain"
    )]
    dst_chain_id: ChainId,

    #[clap(
        long = "src-chain",
        required = true,
        value_name = "SRC_CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the source chain"
    )]
    src_chain_id: ChainId,

    #[clap(
        long = "src-port",
        required = true,
        value_name = "SRC_PORT_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the source port"
    )]
    src_port_id: PortId,

    #[clap(
        long = "src-channel",
        visible_alias = "src-chan",
        required = true,
        value_name = "SRC_CHANNEL_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the source channel"
    )]
    src_channel_id: ChannelId,

    #[clap(
        long = "sequence",
        required = true,
        value_name = "SEQUENCE",
        help_heading = "REQUIRED",
        help = "Sequence of the destination receipt and acknowledgement pair to prune"
    )]
    sequence: Sequence,

    #[clap(
        long = "proof-height",
        value_name = "REVISION-HEIGHT",
        help = "IBC height at which to prove source commitment absence (defaults to the destination client's latest verified height; for a nonzero connection delay, select an older matured client height that is still at or above the channel receive high-water mark and pruning floor)"
    )]
    proof_height: Option<Height>,
}

impl TxPacketPruneCmd {
    fn execute(&self) -> Result<Vec<IbcEventWithHeight>, Error> {
        let config = app_config();
        let chains = ChainHandlePair::spawn(&config, &self.src_chain_id, &self.dst_chain_id)?;
        let opts = LinkParameters {
            src_port_id: self.src_port_id.clone(),
            src_channel_id: self.src_channel_id.clone(),
            max_memo_size: config.mode.packets.ics20_max_memo_size,
            max_receiver_size: config.mode.packets.ics20_max_receiver_size,
            exclude_src_sequences: vec![],
        };
        let link =
            Link::new_from_opts(chains.src, chains.dst, opts, false, false).map_err(Error::link)?;
        let path = &link.a_to_b;

        let destination_config = path.dst_chain().config().map_err(Error::relayer)?;
        if !matches!(destination_config, ChainConfig::Cardano(_)) {
            return Err(Error::cli_arg(format!(
                "packet history pruning is only supported when --dst-chain '{}' is Cardano",
                self.dst_chain_id
            )));
        }

        let (destination_client_state, _) = path
            .dst_chain()
            .query_client_state(
                QueryClientStateRequest {
                    client_id: path.dst_client_id().clone(),
                    height: QueryHeight::Latest,
                },
                IncludeProof::No,
            )
            .map_err(Error::relayer)?;
        let latest_verified_height = destination_client_state.latest_verified_height();
        let proof_height = self.proof_height.unwrap_or(latest_verified_height);
        if proof_height > latest_verified_height {
            return Err(Error::cli_arg(format!(
                "proof height {} is ahead of destination client {} latest verified height {}",
                proof_height,
                path.dst_client_id(),
                latest_verified_height
            )));
        }

        let source_config = path.src_chain().config().map_err(Error::relayer)?;
        let source_query_height = source_query_height_for_proof(
            proof_height,
            matches!(source_config, ChainConfig::Cardano(_)),
        )?;
        let (commitment, maybe_proof) = path
            .src_chain()
            .query_packet_commitment(
                QueryPacketCommitmentRequest {
                    port_id: path.src_port_id().clone(),
                    channel_id: path.src_channel_id().clone(),
                    sequence: self.sequence,
                    height: QueryHeight::Specific(source_query_height),
                },
                IncludeProof::Yes,
            )
            .map_err(Error::relayer)?;

        if !commitment.is_empty() {
            return Err(Error::cli_arg(format!(
                "source packet commitment still exists for {}/{}/{} at proof height {}; acknowledge or time out the packet before pruning",
                path.src_port_id(),
                path.src_channel_id(),
                self.sequence,
                proof_height
            )));
        }

        let proof = maybe_proof.ok_or_else(|| {
            Error::cli_arg(format!(
                "source chain returned no non-membership proof for {}/{}/{} at proof height {}",
                path.src_port_id(),
                path.src_channel_id(),
                self.sequence,
                proof_height
            ))
        })?;
        let proof_bytes = CommitmentProofBytes::try_from(proof)
            .map_err(|e| Error::cli_arg(format!("invalid source non-membership proof: {e}")))?
            .into_bytes();
        let signer = path.dst_chain().get_signer().map_err(Error::relayer)?;
        let message = prune_packet_history_any(
            signer.to_string(),
            path.dst_port_id().to_string(),
            path.dst_channel_id().to_string(),
            self.sequence.into(),
            proof_bytes,
            proof_height,
        );

        path.dst_chain()
            .send_messages_and_wait_commit(TrackedMsgs::new_single(message, "packet history prune"))
            .map_err(Error::relayer)
    }
}

impl Runnable for TxPacketPruneCmd {
    fn run(&self) {
        match self.execute() {
            Ok(events) => Output::success(events).exit(),
            Err(error) => Output::error(error).exit(),
        }
    }
}

fn source_query_height_for_proof(
    proof_height: Height,
    source_is_cardano: bool,
) -> Result<Height, Error> {
    if source_is_cardano {
        Ok(proof_height)
    } else {
        proof_height.decrement().map_err(|_| {
            Error::cli_arg(format!(
                "proof height {} has no preceding source query height",
                proof_height
            ))
        })
    }
}

fn prune_packet_history_any(
    signer: String,
    port_id: String,
    channel_id: String,
    sequence: u64,
    proof_commitment_absence: Vec<u8>,
    proof_height: Height,
) -> Any {
    let message = MsgPrunePacketHistory {
        signer,
        port_id,
        channel_id,
        sequence,
        proof_commitment_absence,
        proof_height: Some(RawHeight {
            revision_number: proof_height.revision_number(),
            revision_height: proof_height.revision_height(),
        }),
    };

    Any {
        type_url: PRUNE_PACKET_HISTORY_TYPE_URL.to_string(),
        value: message.encode_to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        prune_packet_history_any, source_query_height_for_proof, TxPacketAckCmd, TxPacketPruneCmd,
        TxPacketRecvCmd, PRUNE_PACKET_HISTORY_TYPE_URL,
    };

    use std::str::FromStr;

    use abscissa_core::clap::Parser;
    use ibc_relayer::chain::cardano::generated::ibc::cardano::v1::MsgPrunePacketHistory;
    use ibc_relayer_types::core::ics02_client::height::Height;
    use ibc_relayer_types::core::ics04_channel::packet::Sequence;
    use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ChannelId, PortId};
    use prost::Message;

    #[test]
    fn test_packet_recv_required_only() {
        assert_eq!(
            TxPacketRecvCmd {
                dst_chain_id: ChainId::from_string("chain_receiver"),
                src_chain_id: ChainId::from_string("chain_sender"),
                src_port_id: PortId::from_str("port_sender").unwrap(),
                src_channel_id: ChannelId::from_str("channel_sender").unwrap(),
                packet_sequences: vec![],
                packet_data_query_height: None
            },
            TxPacketRecvCmd::parse_from([
                "test",
                "--dst-chain",
                "chain_receiver",
                "--src-chain",
                "chain_sender",
                "--src-port",
                "port_sender",
                "--src-channel",
                "channel_sender"
            ])
        )
    }

    #[test]
    fn test_packet_recv_aliases() {
        assert_eq!(
            TxPacketRecvCmd {
                dst_chain_id: ChainId::from_string("chain_receiver"),
                src_chain_id: ChainId::from_string("chain_sender"),
                src_port_id: PortId::from_str("port_sender").unwrap(),
                src_channel_id: ChannelId::from_str("channel_sender").unwrap(),
                packet_sequences: vec![],
                packet_data_query_height: None
            },
            TxPacketRecvCmd::parse_from([
                "test",
                "--dst-chain",
                "chain_receiver",
                "--src-chain",
                "chain_sender",
                "--src-port",
                "port_sender",
                "--src-chan",
                "channel_sender"
            ])
        )
    }
    #[test]
    fn test_packet_recv_packet_data_query_height() {
        assert_eq!(
            TxPacketRecvCmd {
                dst_chain_id: ChainId::from_string("chain_receiver"),
                src_chain_id: ChainId::from_string("chain_sender"),
                src_port_id: PortId::from_str("port_sender").unwrap(),
                src_channel_id: ChannelId::from_str("channel_sender").unwrap(),
                packet_sequences: vec![],
                packet_data_query_height: Some(5),
            },
            TxPacketRecvCmd::parse_from([
                "test",
                "--dst-chain",
                "chain_receiver",
                "--src-chain",
                "chain_sender",
                "--src-port",
                "port_sender",
                "--src-channel",
                "channel_sender",
                "--packet-data-query-height",
                "5"
            ])
        )
    }

    #[test]
    fn test_packet_recv_no_sender_channel() {
        assert!(TxPacketRecvCmd::try_parse_from([
            "test",
            "--dst-chain",
            "chain_receiver",
            "--src-chain",
            "chain_sender",
            "--src-port",
            "port_sender"
        ])
        .is_err())
    }

    #[test]
    fn test_packet_recv_no_sender_port() {
        assert!(TxPacketRecvCmd::try_parse_from([
            "test",
            "--dst-chain",
            "chain_receiver",
            "--src-chain",
            "chain_sender",
            "--src-channel",
            "channel_sender"
        ])
        .is_err())
    }

    #[test]
    fn test_packet_recv_no_sender_chain() {
        assert!(TxPacketRecvCmd::try_parse_from([
            "test",
            "--dst-chain",
            "chain_receiver",
            "--src-port",
            "port_sender",
            "--src-channel",
            "channel_sender"
        ])
        .is_err())
    }

    #[test]
    fn test_packet_recv_no_receiver_chain() {
        assert!(TxPacketRecvCmd::try_parse_from([
            "test",
            "--src-chain",
            "chain_sender",
            "--src-port",
            "port_sender",
            "--src-channel",
            "channel_sender"
        ])
        .is_err())
    }

    #[test]
    fn test_packet_ack() {
        assert_eq!(
            TxPacketAckCmd {
                dst_chain_id: ChainId::from_string("chain_receiver"),
                src_chain_id: ChainId::from_string("chain_sender"),
                src_port_id: PortId::from_str("port_sender").unwrap(),
                src_channel_id: ChannelId::from_str("channel_sender").unwrap(),
                packet_sequences: vec![],
                packet_data_query_height: None
            },
            TxPacketAckCmd::parse_from([
                "test",
                "--dst-chain",
                "chain_receiver",
                "--src-chain",
                "chain_sender",
                "--src-port",
                "port_sender",
                "--src-channel",
                "channel_sender"
            ])
        )
    }

    #[test]
    fn test_packet_ack_aliases() {
        assert_eq!(
            TxPacketAckCmd {
                dst_chain_id: ChainId::from_string("chain_receiver"),
                src_chain_id: ChainId::from_string("chain_sender"),
                src_port_id: PortId::from_str("port_sender").unwrap(),
                src_channel_id: ChannelId::from_str("channel_sender").unwrap(),
                packet_sequences: vec![],
                packet_data_query_height: None
            },
            TxPacketAckCmd::parse_from([
                "test",
                "--dst-chain",
                "chain_receiver",
                "--src-chain",
                "chain_sender",
                "--src-port",
                "port_sender",
                "--src-chan",
                "channel_sender"
            ])
        )
    }

    #[test]
    fn test_packet_ack_no_sender_channel() {
        assert!(TxPacketAckCmd::try_parse_from([
            "test",
            "--dst-chain",
            "chain_receiver",
            "--src-chain",
            "chain_sender",
            "--src-port",
            "port_sender"
        ])
        .is_err())
    }

    #[test]
    fn test_packet_ack_no_sender_port() {
        assert!(TxPacketAckCmd::try_parse_from([
            "test",
            "--dst-chain",
            "chain_receiver",
            "--src-chain",
            "chain_sender",
            "--src-channel",
            "channel_sender"
        ])
        .is_err())
    }

    #[test]
    fn test_packet_ack_no_sender_chain() {
        assert!(TxPacketAckCmd::try_parse_from([
            "test",
            "--dst-chain",
            "chain_receiver",
            "--src-port",
            "port_sender",
            "--src-channel",
            "channel_sender"
        ])
        .is_err())
    }

    #[test]
    fn test_packet_ack_no_receiver_chain() {
        assert!(TxPacketAckCmd::try_parse_from([
            "test",
            "--src-chain",
            "chain_sender",
            "--src-port",
            "port_sender",
            "--src-channel",
            "channel_sender"
        ])
        .is_err())
    }

    #[test]
    fn test_packet_prune_required_arguments() {
        assert_eq!(
            TxPacketPruneCmd {
                dst_chain_id: ChainId::from_string("cardano-preview"),
                src_chain_id: ChainId::from_string("injective-888"),
                src_port_id: PortId::from_str("transfer").unwrap(),
                src_channel_id: ChannelId::from_str("channel-7").unwrap(),
                sequence: Sequence::from(12),
                proof_height: None,
            },
            TxPacketPruneCmd::parse_from([
                "test",
                "--dst-chain",
                "cardano-preview",
                "--src-chain",
                "injective-888",
                "--src-port",
                "transfer",
                "--src-channel",
                "channel-7",
                "--sequence",
                "12",
            ])
        );
    }

    #[test]
    fn test_packet_prune_accepts_explicit_proof_height_and_channel_alias() {
        assert_eq!(
            TxPacketPruneCmd {
                dst_chain_id: ChainId::from_string("cardano-preview"),
                src_chain_id: ChainId::from_string("injective-888"),
                src_port_id: PortId::from_str("transfer").unwrap(),
                src_channel_id: ChannelId::from_str("channel-7").unwrap(),
                sequence: Sequence::from(12),
                proof_height: Some(Height::new(888, 42).unwrap()),
            },
            TxPacketPruneCmd::parse_from([
                "test",
                "--dst-chain",
                "cardano-preview",
                "--src-chain",
                "injective-888",
                "--src-port",
                "transfer",
                "--src-chan",
                "channel-7",
                "--sequence",
                "12",
                "--proof-height",
                "888-42",
            ])
        );
    }

    #[test]
    fn test_packet_prune_requires_exactly_one_sequence() {
        assert!(TxPacketPruneCmd::try_parse_from([
            "test",
            "--dst-chain",
            "cardano-preview",
            "--src-chain",
            "injective-888",
            "--src-port",
            "transfer",
            "--src-channel",
            "channel-7",
        ])
        .is_err());
    }

    #[test]
    fn packet_prune_uses_chain_specific_source_query_height() {
        let proof_height = Height::new(7, 42).unwrap();

        assert_eq!(
            source_query_height_for_proof(proof_height, true).unwrap(),
            proof_height
        );
        assert_eq!(
            source_query_height_for_proof(proof_height, false).unwrap(),
            Height::new(7, 41).unwrap()
        );
        assert!(source_query_height_for_proof(Height::new(7, 1).unwrap(), false).is_err());
    }

    #[test]
    fn packet_prune_any_uses_cardano_wire_contract() {
        let any = prune_packet_history_any(
            "addr_test1signer".to_string(),
            "transfer".to_string(),
            "channel-3".to_string(),
            12,
            vec![1, 2, 3],
            Height::new(888, 42).unwrap(),
        );

        assert_eq!(any.type_url, PRUNE_PACKET_HISTORY_TYPE_URL);
        let message = MsgPrunePacketHistory::decode(any.value.as_slice()).unwrap();
        assert_eq!(message.signer, "addr_test1signer");
        assert_eq!(message.port_id, "transfer");
        assert_eq!(message.channel_id, "channel-3");
        assert_eq!(message.sequence, 12);
        assert_eq!(message.proof_commitment_absence, vec![1, 2, 3]);
        let height = message.proof_height.unwrap();
        assert_eq!(height.revision_number, 888);
        assert_eq!(height.revision_height, 42);
    }
}
