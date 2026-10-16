//! Real proof preparation and staging with deterministic runtime replies. These
//! tests stop an unrelated wait with an error instead of waiting six hours.
use super::*;
use crate::chain::{
    endpoint::ChainStatus,
    handle::{BaseChainHandle, ChainRequest},
};
use crate::channel::{Channel, ChannelSide};
use crate::connection::{Connection, ConnectionSide};
use ibc_relayer_types::clients::ics08_cardano_probabilistic::{
    consensus_state::ConsensusState, raw,
};
use ibc_relayer_types::core::ics04_channel::channel::Ordering as ChannelOrdering;
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentRoot;
use ibc_relayer_types::core::ics24_host::identifier::{ChannelId, PortId};
use ibc_relayer_types::signer::Signer;
use prost::Message;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};

const NOW: u64 = 110_000_000_000;
const DEADLINE: u64 = 220_000_000_000;
const AFTER_DEADLINE: u64 = DEADLINE + 11_000_000_000;
const UNRELATED_DEADLINE: u64 = 400_000_000_000;

#[derive(Clone, Copy, Debug)]
enum ProofPath {
    Packet,
    Connection,
    Channel,
}

#[derive(Default)]
struct Requests {
    consensus_heights: Vec<Height>,
    host_times: Vec<u64>,
    operations: Vec<u32>,
    activation_times: Vec<u64>,
}

struct Harness {
    source: BaseChainHandle,
    destination: BaseChainHandle,
    requests: Arc<Mutex<Requests>>,
    threads: Vec<thread::JoinHandle<()>>,
}

fn height(n: u64) -> Height {
    Height::new(0, n).unwrap()
}

fn observation(table_epoch: Option<u64>) -> raw::ProbabilisticHeader {
    use bech32::ToBase32;
    let block = |n: u64, epoch| raw::ProbabilisticBlock {
        height: Some(height(n).into()),
        slot: n + 22,
        epoch,
        timestamp: (n + 72) * 1_000_000_000,
        hash: format!("{n:064x}"),
        header_cbor: vec![0x80],
        ..Default::default()
    };
    raw::ProbabilisticHeader {
        trusted_height: Some(height(10).into()),
        anchor_block: Some(block(33, 7)),
        descendant_blocks: table_epoch
            .map(|epoch| block(34, epoch))
            .into_iter()
            .collect(),
        new_epoch_context: table_epoch.map(|epoch| raw::EpochContext {
            epoch,
            stake_distribution: vec![raw::StakeDistributionEntry {
                pool_id: bech32::encode("pool", vec![1; 28].to_base32(), bech32::Variant::Bech32)
                    .unwrap(),
                stake: 1,
                ..Default::default()
            }],
            epoch_nonce: vec![1; 32],
            slots_per_kes_period: 100,
            epoch_start_slot: 1_000,
            epoch_end_slot_exclusive: 2_000,
        }),
        ..Default::default()
    }
}

impl Harness {
    fn new(root_epoch: Option<u64>, table_epoch: Option<u64>, pending_base: bool) -> Self {
        let AnyClientState::Probabilistic(mut client) =
            super::tests::checkpoint_test_client_state(root_epoch.is_some())
        else {
            unreachable!()
        };
        client.current_epoch = root_epoch.unwrap_or(7);
        client.latest_checkpoint_epoch = client.current_epoch;
        client.latest_checkpoint_height = Some(if root_epoch.is_some() {
            height(50)
        } else {
            height(10)
        });
        client.verification_generation = 1;
        client.storage_namespace = vec![1; 32];
        client.checkpoint_reference = vec![2; 32];
        client.trusting_period = Duration::from_secs(48 * 3_600);
        client.epoch_context_challenges = vec![
            raw::EpochContextChallenge {
                epoch: 7,
                usable_after_unix_ns: if pending_base {
                    DEADLINE
                } else {
                    90_000_000_000
                },
            },
            raw::EpochContextChallenge {
                epoch: 8,
                usable_after_unix_ns: DEADLINE,
            },
            raw::EpochContextChallenge {
                epoch: 9,
                usable_after_unix_ns: UNRELATED_DEADLINE,
            },
        ];
        let state = Arc::new(Mutex::new(client));
        let requests = Arc::new(Mutex::new(Requests::default()));
        let built = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = crossbeam_channel::unbounded();
        let source = BaseChainHandle::new(ChainId::from_string("cardano-0"), sender);
        let header_built = built.clone();
        let source_thread = thread::spawn(move || {
            for (_, request) in receiver {
                match request {
                    ChainRequest::QueryApplicationStatus { reply_to } => {
                        reply_to
                            .send(Ok(ChainStatus {
                                height: height(60),
                                timestamp: Timestamp::from_nanoseconds(NOW).unwrap(),
                            }))
                            .unwrap();
                    }
                    ChainRequest::BuildHeader {
                        trusted_height,
                        target_height,
                        reply_to,
                        ..
                    } => {
                        assert_eq!(trusted_height, height(10));
                        assert_eq!(target_height, height(33));
                        header_built.store(true, Ordering::SeqCst);
                        let header = observation(table_epoch).try_into().unwrap();
                        reply_to
                            .send(Ok((AnyHeader::Probabilistic(header), vec![])))
                            .unwrap();
                    }
                    unexpected => panic!("unexpected source request: {unexpected:?}"),
                }
            }
        });
        let (sender, receiver) = crossbeam_channel::unbounded();
        let destination = BaseChainHandle::new(ChainId::from_string("cosmos-0"), sender);
        let recorded = requests.clone();
        let destination_thread = thread::spawn(move || {
            let mut now = NOW;
            let advance = pending_base || table_epoch.is_some() || root_epoch == Some(8);
            let mut session = json!({"Sequence":0,"RowsRead":0,"CreditReady":true,"ProcessedBlocks":0,"Complete":false,"Receipt":vec![3;32]});
            for (_, request) in receiver {
                match request {
                    ChainRequest::QueryClientState { reply_to, .. } => {
                        reply_to
                            .send(Ok((
                                AnyClientState::Probabilistic(state.lock().unwrap().clone()),
                                None,
                            )))
                            .unwrap();
                    }
                    ChainRequest::QueryClientStatus { reply_to, .. } => {
                        reply_to.send(Ok(Some("Active".into()))).unwrap();
                    }
                    ChainRequest::QueryApplicationStatus { reply_to } => {
                        let mut calls = recorded.lock().unwrap();
                        let reads = calls.host_times.len() + 1;
                        // A retained root must be looked up before any challenge wait.
                        // New updates must be built before selecting their dependencies.
                        if (root_epoch.is_some() && calls.consensus_heights.is_empty())
                            || (root_epoch.is_none() && !built.load(Ordering::SeqCst) && reads > 2)
                            || reads > 8
                        {
                            reply_to
                                .send(Err(RelayerError::query(
                                    "waited for an unrelated epoch proposal".into(),
                                )))
                                .unwrap();
                            continue;
                        }
                        // Let the relevant deadline pass while epoch 9 stays pending.
                        if advance && reads >= if root_epoch.is_some() { 4 } else { 5 } {
                            now = AFTER_DEADLINE;
                        }
                        calls.host_times.push(now);
                        reply_to
                            .send(Ok(ChainStatus {
                                height: height(60),
                                timestamp: Timestamp::from_nanoseconds(now).unwrap(),
                            }))
                            .unwrap();
                    }
                    ChainRequest::QueryConsensusState {
                        request, reply_to, ..
                    } => {
                        recorded
                            .lock()
                            .unwrap()
                            .consensus_heights
                            .push(request.consensus_height);
                        let client = state.lock().unwrap();
                        let answer = if request.consensus_height == height(33)
                            && client.latest_height == height(33)
                        {
                            Ok((
                                AnyConsensusState::Probabilistic(ConsensusState {
                                    verification_generation: 1,
                                    checkpoint_reference: vec![2; 32],
                                    packet_state_reference: vec![3; 32],
                                    root: CommitmentRoot::from_bytes(&[1; 32]),
                                    timestamp: 100_000_000_000,
                                    accepted_block_hash: "01".repeat(32),
                                    accepted_epoch: root_epoch.unwrap_or(7),
                                    unique_pools_count: 1,
                                    unique_stake_bps: 10_000,
                                    security_score_bps: 10_000,
                                }),
                                None,
                            ))
                        } else {
                            Err(RelayerError::query("missing exact consensus root".into()))
                        };
                        reply_to.send(answer).unwrap();
                    }
                    ChainRequest::QueryCardanoChallengeContext { reply_to, .. } => {
                        let raw: raw::ClientState = state.lock().unwrap().clone().into();
                        reply_to.send(Ok(raw.encode_to_vec())).unwrap();
                    }
                    ChainRequest::Signer { reply_to } => {
                        reply_to.send(Ok(Signer::dummy())).unwrap();
                    }
                    ChainRequest::QueryProbabilisticVerification {
                        request, reply_to, ..
                    } => {
                        assert_eq!(request.kind, 8);
                        reply_to
                            .send(Ok(serde_json::to_vec(&session).unwrap()))
                            .unwrap();
                    }
                    ChainRequest::SendMessagesAndWaitCommit {
                        tracked_msgs,
                        reply_to,
                    } => {
                        assert_eq!(tracked_msgs.msgs.len(), 1);
                        let update = ibc_proto::ibc::core::client::v1::MsgUpdateClient::decode(
                            tracked_msgs.msgs[0].value.as_slice(),
                        )
                        .unwrap();
                        let header = raw::ProbabilisticHeader::decode(
                            update.client_message.unwrap().value.as_slice(),
                        )
                        .unwrap();
                        let chunk = header.observation_chunk.unwrap();
                        recorded.lock().unwrap().operations.push(chunk.operation);
                        session["Sequence"] = chunk.sequence.into();
                        match chunk.operation {
                            1 => {}
                            2 => session["RowsRead"] = (chunk.stake_rows.len() / 36).into(),
                            4 => {
                                let count = session["ProcessedBlocks"].as_u64().unwrap();
                                session["ProcessedBlocks"] =
                                    (count + chunk.blocks.len() as u64).into();
                            }
                            6 => session["Complete"] = true.into(),
                            7 => {
                                recorded.lock().unwrap().activation_times.push(now);
                                let anchor = observation(table_epoch).anchor_block.unwrap();
                                let mut client = state.lock().unwrap();
                                client.latest_height = height(33);
                                client.latest_checkpoint_height = Some(height(33));
                                client.latest_checkpoint_timestamp = anchor.timestamp;
                                client.latest_checkpoint_slot = anchor.slot;
                            }
                            _ => panic!("unexpected observation operation"),
                        }
                        reply_to.send(Ok(vec![])).unwrap();
                    }
                    unexpected => panic!("unexpected destination request: {unexpected:?}"),
                }
            }
        });
        Self {
            source,
            destination,
            requests,
            threads: vec![source_thread, destination_thread],
        }
    }

    fn prepare(&self, path: ProofPath) -> Result<Vec<Any>, String> {
        let client_id = "08-cardano-probabilistic-0".parse().unwrap();
        match path {
            ProofPath::Packet => {
                ForeignClient::restore(client_id, self.destination.clone(), self.source.clone())
                    .wait_and_build_update_client_for_proof(height(33))
                    .map_err(|error| error.to_string())
            }
            ProofPath::Connection => Connection {
                delay_period: Duration::ZERO,
                a_side: ConnectionSide::new(
                    self.source.clone(),
                    "07-tendermint-0".parse().unwrap(),
                    None,
                ),
                b_side: ConnectionSide::new(self.destination.clone(), client_id, None),
            }
            .build_update_client_on_dst(height(33))
            .map_err(|error| error.to_string()),
            ProofPath::Channel => Channel {
                ordering: ChannelOrdering::Unordered,
                a_side: ChannelSide::new(
                    self.source.clone(),
                    "07-tendermint-0".parse().unwrap(),
                    "connection-0".parse().unwrap(),
                    PortId::transfer(),
                    Some(ChannelId::new(0)),
                    None,
                ),
                b_side: ChannelSide::new(
                    self.destination.clone(),
                    client_id,
                    "connection-0".parse().unwrap(),
                    PortId::transfer(),
                    Some(ChannelId::new(1)),
                    None,
                ),
                connection_delay: Duration::ZERO,
            }
            .build_update_client_on_dst(height(33))
            .map_err(|error| error.to_string()),
        }
    }

    fn close(self) {
        drop(self.source);
        drop(self.destination);
        for thread in self.threads {
            thread.join().unwrap();
        }
    }
}

#[test]
fn retained_root_proofs_ignore_future_epoch_proposals() {
    for path in [ProofPath::Packet, ProofPath::Connection, ProofPath::Channel] {
        let h = Harness::new(Some(7), None, false);
        assert!(h
            .prepare(path)
            .unwrap_or_else(|error| panic!("{path:?}: {error}"))
            .is_empty());
        {
            let calls = h.requests.lock().unwrap();
            assert!(calls.operations.is_empty());
            assert_eq!(calls.consensus_heights, vec![height(33); 2]);
            assert!(
                !calls.host_times.is_empty(),
                "committed freshness must still be checked"
            );
            assert!(calls.host_times.iter().all(|time| *time == NOW));
        }
        h.close();
    }
}

#[test]
fn retained_root_still_waits_for_its_own_epoch() {
    let h = Harness::new(Some(8), None, false);
    assert!(h.prepare(ProofPath::Packet).unwrap().is_empty());
    {
        let calls = h.requests.lock().unwrap();
        assert!(calls.operations.is_empty());
        assert_eq!(calls.host_times.first(), Some(&NOW));
        assert_eq!(calls.host_times.last(), Some(&AFTER_DEADLINE));
        assert!(calls
            .host_times
            .iter()
            .all(|time| *time < UNRELATED_DEADLINE));
    }
    h.close();
}

#[test]
fn new_updates_wait_only_for_the_base_and_used_table() {
    for (table_epoch, pending_base) in [(None, false), (None, true), (Some(8), false)] {
        let h = Harness::new(None, table_epoch, pending_base);
        assert!(h.prepare(ProofPath::Connection).unwrap().is_empty());
        {
            let calls = h.requests.lock().unwrap();
            assert_eq!(calls.operations.first(), Some(&1));
            assert_eq!(calls.operations.last(), Some(&7));
            let expected = if pending_base || table_epoch.is_some() {
                AFTER_DEADLINE
            } else {
                NOW
            };
            assert_eq!(calls.activation_times, vec![expected]);
            assert!(calls.activation_times[0] < UNRELATED_DEADLINE);
        }
        h.close();
    }
}
