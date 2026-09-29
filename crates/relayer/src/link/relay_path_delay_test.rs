//! Runtime-boundary regression for the delayed scheduling path. Only request
//! replies are fixtures: schedule_operational_data and proof preparation are real.
use super::*;
use std::thread;

use ibc_relayer_types::clients::ics08_cardano_probabilistic::{
    client_state::ClientState as ProbabilisticClientState,
    consensus_state::ConsensusState as ProbabilisticConsensusState,
};
use ibc_relayer_types::core::ics04_channel::timeout::TimeoutHeight;
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentRoot;
use ibc_relayer_types::core::ics24_host::identifier::ChainId;

use crate::chain::handle::{BaseChainHandle, ChainRequest};
use crate::channel::ChannelSide;
use crate::client_state::AnyClientState;
use crate::consensus_state::AnyConsensusState;
use crate::error::Error as RelayerError;

fn height(n: u64) -> Height {
    Height::new(0, n).unwrap()
}

fn cardano_client() -> AnyClientState {
    AnyClientState::Probabilistic(ProbabilisticClientState {
        chain_id: ChainId::from_string("cardano-0"),
        latest_height: height(33),
        frozen_height: None,
        current_epoch: 0,
        trusting_period: Duration::from_secs(60),
        upgrade_path: vec![],
        host_state_nft_policy_id: vec![1; 28],
        host_state_nft_token_name: b"hostState".to_vec(),
        epoch_stake_distribution: vec![],
        epoch_nonce: vec![0; 32],
        slots_per_kes_period: 100,
        current_epoch_start_slot: 1,
        current_epoch_end_slot_exclusive: 1_000,
        system_start_unix_ns: 1,
        slot_length_ns: 1_000_000_000,
        epoch_contexts: vec![],
        latest_checkpoint_height: Some(height(50)),
        latest_checkpoint_block_hash: "02".repeat(32),
        latest_checkpoint_epoch: 0,
        max_kes_evolutions: 62,
        latest_checkpoint_operational_certificate_counters: vec![],
        operational_certificate_counter_history_start_height: Some(height(10)),
        active_slot_coefficient_numerator: 1,
        active_slot_coefficient_denominator: 20,
        max_clock_drift: Duration::from_secs(10),
        latest_checkpoint_slot: 50,
        latest_checkpoint_timestamp: 100_000_000_000,
    })
}

fn runtime(config: ChainConfig) -> (BaseChainHandle, thread::JoinHandle<Vec<Height>>) {
    let (sender, receiver) = crossbeam_channel::unbounded();
    let handle = BaseChainHandle::new(config.id().clone(), sender);
    let worker = thread::spawn(move || {
        let mut consensus_queries = vec![];
        for (_, request) in receiver {
            match request {
                ChainRequest::Config { reply_to } => reply_to.send(Ok(config.clone())).unwrap(),
                ChainRequest::QueryApplicationStatus { reply_to } => {
                    reply_to
                        .send(Ok(ChainStatus {
                            height: height(60),
                            timestamp: Timestamp::from_nanoseconds(110_000_000_000).unwrap(),
                        }))
                        .unwrap();
                }
                ChainRequest::QueryClientState { reply_to, .. } => {
                    reply_to.send(Ok((cardano_client(), None))).unwrap();
                }
                ChainRequest::QueryConsensusState {
                    request, reply_to, ..
                } => {
                    consensus_queries.push(request.consensus_height);
                    let answer = if request.consensus_height == height(33) {
                        Ok((
                            AnyConsensusState::Probabilistic(ProbabilisticConsensusState {
                                root: CommitmentRoot::from_bytes(&[1; 32]),
                                timestamp: 100_000_000_000,
                                accepted_block_hash: "01".repeat(32),
                                accepted_epoch: 0,
                                unique_pools_count: 1,
                                unique_stake_bps: 10_000,
                                security_score_bps: 10_000,
                            }),
                            None,
                        ))
                    } else {
                        Err(RelayerError::query(
                            "only the exact packet root at 33 exists".into(),
                        ))
                    };
                    reply_to.send(answer).unwrap();
                }
                ChainRequest::SendMessagesAndWaitCommit {
                    tracked_msgs,
                    reply_to,
                } => {
                    assert!(
                        tracked_msgs.messages().is_empty(),
                        "existing root needs no client update"
                    );
                    reply_to
                        .send(Err(RelayerError::query(
                            "reached delayed scheduling after exact-root verification".into(),
                        )))
                        .unwrap();
                }
                unexpected => panic!("unexpected request in delayed scheduling: {unexpected:?}"),
            }
        }
        consensus_queries
    });
    (handle, worker)
}

#[test]
fn delayed_cardano_schedule_uses_exact_proof_height_in_both_directions() {
    for target in [
        OperationalDataTarget::Source,
        OperationalDataTarget::Destination,
    ] {
        let cosmos: crate::config::Config = toml::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config.toml"
        )))
        .unwrap();
        let cardano: ChainConfig = serde_json::from_value(serde_json::json!({
            "type": "Cardano", "id": "cardano-0", "gateway_url": "http://127.0.0.1:1",
            "network_id": 0, "key_name": "unused-test-key"
        }))
        .unwrap();
        let (cardano, cardano_runtime) = runtime(cardano);
        let (cosmos, cosmos_runtime) = runtime(cosmos.chains[0].clone());
        let cardano_side = ChannelSide::new(
            cardano,
            "07-tendermint-0".parse().unwrap(),
            "connection-0".parse().unwrap(),
            PortId::transfer(),
            Some(ChannelId::new(0)),
            None,
        );
        let cosmos_side = ChannelSide::new(
            cosmos,
            "08-cardano-probabilistic-0".parse().unwrap(),
            "connection-0".parse().unwrap(),
            PortId::transfer(),
            Some(ChannelId::new(7)),
            None,
        );
        let (a_side, b_side) = match target {
            OperationalDataTarget::Source => (cosmos_side, cardano_side),
            OperationalDataTarget::Destination => (cardano_side, cosmos_side),
        };
        let limits =
            serde_json::from_value(serde_json::json!({"enabled": false, "size": "32768 B"}))
                .unwrap();
        let path = RelayPath::new(
            Channel {
                ordering: Ordering::Unordered,
                a_side,
                b_side,
                connection_delay: Duration::from_secs(10),
            },
            false,
            LinkParameters {
                src_port_id: PortId::transfer(),
                src_channel_id: ChannelId::new(0),
                max_memo_size: limits,
                max_receiver_size: limits,
                exclude_src_sequences: vec![],
            },
        )
        .unwrap();
        let mut operation = OperationalData::new(
            height(33),
            target,
            TrackingId::new_static("migration-delayed-height-regression"),
            Duration::from_secs(10),
        );
        operation.push(TransitMessage {
            event_with_height: IbcEventWithHeight::new(
                IbcEvent::SendPacket(SendPacket {
                    packet: Packet {
                        sequence: Sequence::from(1),
                        source_port: PortId::transfer(),
                        source_channel: ChannelId::new(0),
                        destination_port: PortId::transfer(),
                        destination_channel: ChannelId::new(7),
                        data: b"pending transfer".to_vec(),
                        timeout_height: TimeoutHeight::Never,
                        timeout_timestamp: Timestamp::from_nanoseconds(200_000_000_000).unwrap(),
                    },
                }),
                height(33),
            ),
            msg: Any {
                type_url: "/test/unused-packet".into(),
                value: vec![],
            },
        });
        let result = path.schedule_operational_data(operation);
        drop(path);
        let cardano_queries = cardano_runtime.join().unwrap();
        let cosmos_queries = cosmos_runtime.join().unwrap();
        assert!(cardano_queries.is_empty());
        assert!(
            !cosmos_queries.is_empty(),
            "scheduler exited before proof lookup: {result:?}"
        );
        assert!(
            cosmos_queries.iter().all(|h| *h == height(33)),
            "delayed scheduling requested {cosmos_queries:?}"
        );
        let error = result
            .expect_err("fixture stops before submission")
            .to_string();
        assert!(
            error.contains("reached delayed scheduling after exact-root verification"),
            "unexpected failure: {error}"
        );
    }
}
