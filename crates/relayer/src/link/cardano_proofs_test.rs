//! Drive proof selection and dispatch through real ChainHandle requests.
use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
    Arc, Mutex,
};
use std::thread;

use ibc_relayer_types::clients::ics07_tendermint::{
    client_state::{AllowUpdate, ClientState as TmClientState},
    consensus_state::ConsensusState as TmConsensusState,
    header::Header as TmHeader,
};
use ibc_relayer_types::core::ics02_client::{
    events::{Attributes, NewBlock, UpdateClient},
    header::AnyHeader,
    trust_threshold::TrustThreshold,
};
use ibc_relayer_types::core::ics04_channel::timeout::TimeoutHeight;
use ibc_relayer_types::core::ics23_commitment::{
    commitment::CommitmentRoot, merkle::MerkleProof, specs::ProofSpecs,
};
use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use prost::Message;

use crate::chain::handle::{BaseChainHandle, ChainRequest};
use crate::chain::requests::QueryTxRequest;
use crate::client_state::AnyClientState;
use crate::consensus_state::AnyConsensusState;
use crate::error::Error;

fn height(n: u64) -> Height {
    Height::new(0, n).unwrap()
}
fn time(seconds: u64) -> Timestamp {
    Timestamp::from_nanoseconds(seconds * 1_000_000_000).unwrap()
}

fn packet(sequence: u64) -> Packet {
    Packet {
        sequence: sequence.into(),
        source_port: PortId::transfer(),
        source_channel: ChannelId::new(0),
        destination_port: PortId::transfer(),
        destination_channel: ChannelId::new(7),
        data: br#"{"denom":"inj","amount":"1","sender":"sender","receiver":"receiver"}"#.to_vec(),
        timeout_height: TimeoutHeight::Never,
        timeout_timestamp: time(300),
    }
}

fn operation(sequence: u64, event_height: u64, ack: bool, delay: Duration) -> OperationalData {
    let event = if ack {
        IbcEvent::WriteAcknowledgement(WriteAcknowledgement {
            packet: packet(sequence),
            ack: b"{\"result\":\"AQ==\"}".to_vec(),
        })
    } else {
        IbcEvent::SendPacket(SendPacket {
            packet: packet(sequence),
        })
    };
    let mut data = OperationalData::new(
        height(event_height),
        OperationalDataTarget::Destination,
        TrackingId::new_static("ready-proof-test"),
        delay,
    );
    data.push(TransitMessage {
        event_with_height: IbcEventWithHeight::new(event, height(event_height)),
        msg: Any {
            type_url: "/original/proof".into(),
            value: vec![sequence as u8],
        },
    });
    data
}

struct State {
    retained: BTreeMap<Height, u64>,
    missing: BTreeSet<(u64, u64)>,
    unavailable_proofs: bool,
    wrong_leaf: bool,
    discovery_fails: bool,
    frozen: bool,
    source_height: u64,
    queries: Vec<(Height, Sequence)>,
    updates: Vec<Height>,
    packets: Vec<Vec<Any>>,
    processed_time: u64,
    processed_height: u64,
    pause_header: Option<(
        crossbeam_channel::Sender<Height>,
        crossbeam_channel::Receiver<()>,
    )>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            retained: BTreeMap::from([(height(5), 90)]),
            missing: BTreeSet::new(),
            unavailable_proofs: false,
            wrong_leaf: false,
            discovery_fails: false,
            frozen: false,
            source_height: 40,
            queries: vec![],
            updates: vec![],
            packets: vec![],
            processed_time: 99,
            processed_height: 99,
            pause_header: None,
        }
    }
}

fn runtime(
    config: ChainConfig,
    source_id: ChainId,
    state: Arc<Mutex<State>>,
) -> (BaseChainHandle, thread::JoinHandle<()>) {
    let (sender, receiver) = crossbeam_channel::unbounded();
    let handle = BaseChainHandle::new(config.id().clone(), sender);
    let source = matches!(config, ChainConfig::CosmosSdk(_));
    let worker = thread::spawn(move || {
        for (_, request) in receiver {
            let mut state = state.lock().unwrap();
            let latest = *state.retained.keys().next_back().unwrap();
            match request {
                ChainRequest::Config { reply_to } => {
                    reply_to.send(Ok(config.clone())).unwrap();
                }
                ChainRequest::QueryApplicationStatus { reply_to } => {
                    reply_to
                        .send(Ok(ChainStatus {
                            height: height(if source { state.source_height } else { 100 }),
                            timestamp: time(100),
                        }))
                        .unwrap();
                }
                ChainRequest::Signer { reply_to } => {
                    reply_to.send(Ok("relayer".parse().unwrap())).unwrap();
                }
                ChainRequest::QueryClientState { reply_to, .. } => {
                    let mut client = TmClientState::new(
                        source_id.clone(),
                        TrustThreshold::ONE_THIRD,
                        Duration::from_secs(60),
                        Duration::from_secs(120),
                        Duration::from_secs(5),
                        latest,
                        ProofSpecs::cosmos(),
                        vec![],
                        AllowUpdate {
                            after_expiry: false,
                            after_misbehaviour: false,
                        },
                    )
                    .unwrap();
                    if state.frozen {
                        client.frozen_height = Some(height(1));
                    }
                    reply_to
                        .send(Ok((AnyClientState::Tendermint(client), None)))
                        .unwrap();
                }
                ChainRequest::QueryConsensusStateHeights { reply_to, .. } => {
                    reply_to
                        .send(if state.discovery_fails {
                            Err(Error::query("discovery unavailable".into()))
                        } else {
                            Ok(state.retained.keys().copied().collect())
                        })
                        .unwrap();
                }
                ChainRequest::QueryConsensusState {
                    request, reply_to, ..
                } => {
                    let result = state
                        .retained
                        .get(&request.consensus_height)
                        .map(|timestamp| {
                            (
                                AnyConsensusState::Tendermint(TmConsensusState::new(
                                    CommitmentRoot::from_bytes(&[1; 32]),
                                    tendermint::Time::from_unix_timestamp(*timestamp as i64, 0)
                                        .unwrap(),
                                    tendermint::Hash::Sha256([2; 32]),
                                )),
                                None,
                            )
                        });
                    reply_to
                        .send(result.ok_or_else(|| Error::query("missing root".into())))
                        .unwrap();
                }
                ChainRequest::QueryUnreceivedPackets { request, reply_to } => {
                    reply_to
                        .send(Ok(request.packet_commitment_sequences))
                        .unwrap();
                }
                ChainRequest::QueryUnreceivedAcknowledgement { request, reply_to } => {
                    reply_to.send(Ok(request.packet_ack_sequences)).unwrap();
                }
                ChainRequest::QueryPacketCommitment {
                    request,
                    include_proof,
                    reply_to,
                } => {
                    // Fixed Cosmos commitment for packet(), independent of the
                    // implementation that checks the queried leaf.
                    let value = hex::decode(
                        "b95cce9c191f4bbbfbdcd9d465f83805bcd2dbacd07a44cd20f4f9ddff39dfe0",
                    )
                    .unwrap();
                    reply_to
                        .send(leaf_reply(
                            &mut state,
                            request.height,
                            request.sequence,
                            include_proof,
                            value,
                        ))
                        .unwrap();
                }
                ChainRequest::QueryPacketAcknowledgement {
                    request,
                    include_proof,
                    reply_to,
                } => {
                    let value = Sha256::digest(b"{\"result\":\"AQ==\"}").to_vec();
                    reply_to
                        .send(leaf_reply(
                            &mut state,
                            request.height,
                            request.sequence,
                            include_proof,
                            value,
                        ))
                        .unwrap();
                }
                ChainRequest::BuildHeader {
                    trusted_height,
                    target_height,
                    reply_to,
                    ..
                } => {
                    let mut signed: tendermint::block::signed_header::SignedHeader =
                        serde_json::from_str(include_str!(
                            "../../../relayer-types/tests/support/signed_header.json"
                        ))
                        .unwrap();
                    signed.header.height = target_height.revision_height().try_into().unwrap();
                    signed.header.chain_id = source_id.as_str().parse().unwrap();
                    signed.header.time = tendermint::Time::from_unix_timestamp(100, 0).unwrap();
                    let built = (
                        AnyHeader::Tendermint(TmHeader {
                            signed_header: signed,
                            validator_set: tendermint::validator::Set::without_proposer(vec![]),
                            trusted_height,
                            trusted_validator_set: tendermint::validator::Set::without_proposer(
                                vec![],
                            ),
                        }),
                        vec![],
                    );
                    if let Some((started, release)) = state.pause_header.take() {
                        started.send(target_height).unwrap();
                        thread::spawn(move || {
                            release.recv().unwrap();
                            reply_to.send(Ok(built)).unwrap();
                        });
                    } else {
                        reply_to.send(Ok(built)).unwrap();
                    }
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
                    let header = ibc_proto::ibc::lightclients::tendermint::v1::Header::decode(
                        update.client_message.unwrap().value.as_slice(),
                    )
                    .unwrap();
                    let target =
                        height(header.signed_header.unwrap().header.unwrap().height as u64);
                    state.updates.push(target);
                    state.retained.insert(target, 100);
                    reply_to
                        .send(Ok(vec![IbcEventWithHeight::new(
                            IbcEvent::NewBlock(NewBlock::new(height(100))),
                            height(100),
                        )]))
                        .unwrap();
                }
                ChainRequest::SendMessagesAndWaitCheckTx {
                    tracked_msgs,
                    reply_to,
                } => {
                    state.packets.push(tracked_msgs.msgs);
                    reply_to.send(Ok(vec![])).unwrap();
                }
                ChainRequest::QueryPacketEventDataFromTxs {
                    request: QueryTxRequest::Client(request),
                    reply_to,
                } => {
                    reply_to
                        .send(Ok(vec![IbcEventWithHeight::new(
                            IbcEvent::UpdateClient(UpdateClient::from(Attributes {
                                client_id: request.client_id,
                                client_type: ClientType::Tendermint,
                                consensus_height: request.consensus_height,
                            })),
                            height(state.processed_height),
                        )]))
                        .unwrap();
                }
                ChainRequest::QueryHostConsensusState { request, reply_to } => {
                    let seconds = match request.height {
                        QueryHeight::Specific(h) if h == height(state.processed_height) => {
                            state.processed_time
                        }
                        _ => 100,
                    };
                    reply_to
                        .send(Ok(AnyConsensusState::Tendermint(TmConsensusState::new(
                            CommitmentRoot::from_bytes(&[1; 32]),
                            tendermint::Time::from_unix_timestamp(seconds as i64, 0).unwrap(),
                            tendermint::Hash::Sha256([2; 32]),
                        ))))
                        .unwrap();
                }
                unexpected => panic!("unexpected proof-selection request: {unexpected:?}"),
            }
        }
    });
    (handle, worker)
}

fn leaf_reply(
    state: &mut State,
    query: QueryHeight,
    sequence: Sequence,
    proof: IncludeProof,
    mut value: Vec<u8>,
) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
    if let QueryHeight::Specific(height) = query {
        state.queries.push((height, sequence));
        if state.unavailable_proofs {
            return Err(Error::query("pruned source state".into()));
        }
        if state
            .missing
            .contains(&(height.revision_height(), sequence.as_u64()))
        {
            value.clear();
        }
        if state.wrong_leaf {
            value = vec![0; 32];
        }
    }
    Ok((
        value,
        matches!(proof, IncludeProof::Yes).then(|| MerkleProof {
            proofs: vec![Default::default()],
        }),
    ))
}

struct Fixture {
    path: RelayPath<BaseChainHandle, BaseChainHandle>,
    state: Arc<Mutex<State>>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, AtomicOrdering::Relaxed);
        let config: crate::config::Config = toml::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config.toml"
        )))
        .unwrap();
        let mut cosmos = config.chains[0].clone();
        let ChainConfig::CosmosSdk(ref mut config) = cosmos else {
            panic!("Cosmos fixture")
        };
        config.id = ChainId::from_string(&format!("proof-reuse-{n}-0"));
        let source_id = config.id.clone();
        let cardano: ChainConfig = serde_json::from_value(serde_json::json!({
            "type": "Cardano", "id": format!("cardano-proof-reuse-{n}"), "gateway_url": "http://127.0.0.1:1",
            "network_id": 0, "key_name": "unused-test-key"
        })).unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let (source, a) = runtime(cosmos, source_id.clone(), state.clone());
        let (destination, b) = runtime(cardano, source_id, state.clone());
        let limits =
            serde_json::from_value(serde_json::json!({"enabled": false, "size": "32768 B"}))
                .unwrap();
        let path = RelayPath::new(
            Channel {
                ordering: Ordering::Unordered,
                a_side: ChannelSide::new(
                    source,
                    "08-cardano-probabilistic-0".parse().unwrap(),
                    ConnectionId::new(0),
                    PortId::transfer(),
                    Some(ChannelId::new(0)),
                    Some("ics20-1".parse().unwrap()),
                ),
                b_side: ChannelSide::new(
                    destination,
                    "07-tendermint-0".parse().unwrap(),
                    ConnectionId::new(0),
                    PortId::transfer(),
                    Some(ChannelId::new(7)),
                    Some("ics20-1".parse().unwrap()),
                ),
                connection_delay: Duration::ZERO,
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
        Self {
            path,
            state,
            workers: vec![a, b],
        }
    }

    fn finish(self) {
        drop(self.path);
        for worker in self.workers {
            worker.join().unwrap();
        }
    }
}

#[test]
fn mixed_receives_and_acks_at_different_event_heights_share_one_update() {
    let mut fixture = Fixture::new();
    fixture
        .path
        .dst_operational_data
        .push_back(operation(1, 8, false, Duration::ZERO));
    fixture
        .path
        .dst_operational_data
        .push_back(operation(2, 12, true, Duration::ZERO));
    fixture.path.execute_schedule().unwrap();
    {
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.updates, vec![height(40)]);
        assert_eq!(state.packets.len(), 2);
        let receive = ibc_proto::ibc::core::channel::v1::MsgRecvPacket::decode(
            state.packets[0][0].value.as_slice(),
        )
        .unwrap();
        let ack = ibc_proto::ibc::core::channel::v1::MsgAcknowledgement::decode(
            state.packets[1][0].value.as_slice(),
        )
        .unwrap();
        assert_eq!(receive.proof_height, Some(height(40).into()));
        assert_eq!(ack.proof_height, Some(height(40).into()));
        assert!(state.queries.iter().all(|(h, _)| *h == height(39)));
    }
    fixture.finish();
}

#[test]
fn retained_roots_win_over_a_new_update_and_proofs_are_requeried() {
    let fixture = Fixture::new();
    fixture
        .state
        .lock()
        .unwrap()
        .retained
        .insert(height(25), 95);
    let original = operation(1, 8, false, Duration::ZERO);
    let mut ready = VecDeque::from([original.clone(), operation(2, 12, true, Duration::ZERO)]);
    fixture.path.reuse_cardano_proof_heights(&mut ready);
    assert!(ready.iter().all(|op| op.proofs_height == height(24)));
    assert_eq!(
        ready[0].batch[0].event_with_height,
        original.batch[0].event_with_height
    );
    assert_ne!(ready[0].batch[0].msg, original.batch[0].msg);
    assert!(fixture.state.lock().unwrap().updates.is_empty());
    fixture.finish();
}

#[test]
fn missing_or_changed_leaves_and_pruned_proofs_preserve_original_messages() {
    for failure in 0..3 {
        let fixture = Fixture::new();
        let original = operation(1, 8, false, Duration::ZERO);
        {
            let mut state = fixture.state.lock().unwrap();
            state.missing.insert((39, 1));
            state.wrong_leaf = failure == 1;
            state.unavailable_proofs = failure == 2;
        }
        let mut ready = VecDeque::from([original.clone()]);
        fixture.path.reuse_cardano_proof_heights(&mut ready);
        assert_eq!(ready[0].proofs_height, original.proofs_height);
        assert_eq!(ready[0].batch[0].msg, original.batch[0].msg);
        fixture.finish();
    }
}

#[test]
fn leaf_unavailable_for_one_packet_does_not_prevent_other_ready_work() {
    let fixture = Fixture::new();
    fixture.state.lock().unwrap().missing.insert((39, 1));
    let mut ready = VecDeque::from([
        operation(1, 8, false, Duration::ZERO),
        operation(2, 12, true, Duration::ZERO),
    ]);
    fixture.path.reuse_cardano_proof_heights(&mut ready);
    assert_eq!(ready[0].proofs_height, height(8));
    assert_eq!(ready[1].proofs_height, height(39));
    fixture.finish();
}

#[test]
fn stale_roots_frozen_clients_discovery_failures_and_future_events_are_not_reused() {
    for case in 0..4 {
        let fixture = Fixture::new();
        {
            let mut state = fixture.state.lock().unwrap();
            state
                .retained
                .insert(height(25), if case == 0 { 1 } else { 95 });
            // Keep the client itself fresh while the older candidate is stale.
            if case == 0 {
                state.retained.insert(height(35), 99);
                state.missing.insert((34, 1));
            }
            state.frozen = case == 1;
            state.discovery_fails = case == 2;
        }
        let original = operation(1, if case == 3 { 40 } else { 8 }, false, Duration::ZERO);
        let mut ready = VecDeque::from([original.clone()]);
        fixture.path.reuse_cardano_proof_heights(&mut ready);
        if case == 0 {
            assert_eq!(ready[0].proofs_height, height(39));
        } else {
            assert_eq!(ready[0].batch[0].msg, original.batch[0].msg);
        }
        fixture.finish();
    }
}

#[test]
fn delayed_work_cannot_borrow_another_roots_elapsed_delay() {
    let fixture = Fixture::new();
    fixture
        .state
        .lock()
        .unwrap()
        .retained
        .insert(height(25), 95);
    let mut original = operation(1, 8, false, Duration::from_secs(10));
    original.set_update_height(height(1));
    original.set_scheduled_time(fixture.path.dst_time_latest().unwrap() - Duration::from_secs(20));
    let mut ready = VecDeque::from([original.clone()]);
    fixture.path.reuse_cardano_proof_heights(&mut ready);
    assert_eq!(ready[0].proofs_height, original.proofs_height);
    assert_eq!(ready[0].batch[0].msg, original.batch[0].msg);
    {
        let mut state = fixture.state.lock().unwrap();
        state.processed_time = 70;
        state.processed_height = 100;
    }
    fixture.path.reuse_cardano_proof_heights(&mut ready);
    assert_eq!(ready[0].proofs_height, original.proofs_height);
    fixture.state.lock().unwrap().processed_height = 90;
    fixture.path.reuse_cardano_proof_heights(&mut ready);
    assert_eq!(ready[0].proofs_height, height(24));
    fixture.finish();
}

#[test]
fn acknowledgement_entries_are_packed_after_reproving_to_a_common_height() {
    let fixture = Fixture::new();
    let mut ready = VecDeque::from([
        operation(1, 8, true, Duration::ZERO),
        operation(2, 12, false, Duration::ZERO),
        operation(3, 13, true, Duration::ZERO),
        operation(4, 14, true, Duration::ZERO),
    ]);
    fixture.path.reuse_cardano_proof_heights(&mut ready);
    let packed = fixture.path.pack_cardano_acknowledgements(ready);
    assert_eq!(packed.len(), 2);
    assert_eq!(packed[0].batch.len(), 3);
    assert_eq!(packed[1].batch.len(), 1);
    assert!(packed[0].batch.iter().all(|transit| matches!(
        transit.event_with_height.event,
        IbcEvent::WriteAcknowledgement(_)
    )));
    fixture.finish();
}

#[test]
fn an_update_in_progress_is_preferred_to_a_newer_available_state() {
    let fixture = Fixture::new();
    let (started_tx, started_rx) = crossbeam_channel::bounded(1);
    let (release_tx, release_rx) = crossbeam_channel::bounded(1);
    fixture.state.lock().unwrap().pause_header = Some((started_tx, release_rx));
    let client = ForeignClient::restore(
        fixture.path.dst_client_id().clone(),
        fixture.path.dst_chain().clone(),
        fixture.path.src_chain().clone(),
    );
    let updater = thread::spawn(move || client.wait_and_build_update_client_for_proof(height(30)));
    assert_eq!(
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        height(30)
    );
    let mut ready = VecDeque::from([
        operation(1, 8, false, Duration::ZERO),
        operation(2, 12, true, Duration::ZERO),
    ]);
    fixture.path.reuse_cardano_proof_heights(&mut ready);
    assert!(ready
        .iter()
        .all(|operation| operation.proofs_height == height(29)));
    release_tx.send(()).unwrap();
    assert!(updater.join().unwrap().unwrap().is_empty());
    assert_eq!(fixture.state.lock().unwrap().updates, vec![height(30)]);
    // Once the worker finishes, its root is discovered from chain state rather
    // than from a permanent successful-update cache.
    fixture.finish();
}

#[test]
fn rolled_back_roots_are_not_reused_on_the_next_dispatch() {
    let fixture = Fixture::new();
    fixture
        .state
        .lock()
        .unwrap()
        .retained
        .insert(height(25), 95);
    let original = operation(1, 8, false, Duration::ZERO);
    let mut first = VecDeque::from([original.clone()]);
    fixture.path.reuse_cardano_proof_heights(&mut first);
    assert_eq!(first[0].proofs_height, height(24));
    fixture.state.lock().unwrap().retained.remove(&height(25));
    let mut second = VecDeque::from([original]);
    fixture.path.reuse_cardano_proof_heights(&mut second);
    assert_eq!(second[0].proofs_height, height(39));
    fixture.finish();
}

#[test]
fn expired_receives_and_missing_acknowledgement_leaves_keep_their_original_proofs() {
    let fixture = Fixture::new();
    let mut receive = operation(1, 8, false, Duration::ZERO);
    let IbcEvent::SendPacket(ref mut event) = receive.batch[0].event_with_height.event else {
        unreachable!()
    };
    event.packet.timeout_timestamp = time(50);
    fixture.state.lock().unwrap().missing.insert((39, 2));
    let ack = operation(2, 12, true, Duration::ZERO);
    let mut ready = VecDeque::from([receive.clone(), ack.clone()]);
    fixture.path.reuse_cardano_proof_heights(&mut ready);
    assert_eq!(ready[0].batch[0].msg, receive.batch[0].msg);
    assert_eq!(ready[1].batch[0].msg, ack.batch[0].msg);
    assert!(!fixture
        .state
        .lock()
        .unwrap()
        .queries
        .iter()
        .any(|(_, sequence)| *sequence == Sequence::from(1)));
    fixture.finish();
}

#[test]
fn acknowledgement_packing_preserves_incompatible_heights_errors_and_ordered_channels() {
    let mut fixture = Fixture::new();
    let mut failed = operation(3, 8, true, Duration::ZERO);
    let IbcEvent::WriteAcknowledgement(ref mut event) = failed.batch[0].event_with_height.event
    else {
        unreachable!()
    };
    event.ack = b"{\"error\":\"failed\"}".to_vec();
    let ready = VecDeque::from([
        operation(1, 8, true, Duration::ZERO),
        operation(2, 12, true, Duration::ZERO),
        failed,
    ]);
    assert_eq!(fixture.path.pack_cardano_acknowledgements(ready).len(), 3);
    fixture.path.channel.ordering = Ordering::Ordered;
    let ready = VecDeque::from([
        operation(1, 8, true, Duration::ZERO),
        operation(2, 8, true, Duration::ZERO),
    ]);
    assert_eq!(fixture.path.pack_cardano_acknowledgements(ready).len(), 2);
    fixture.finish();
}

#[test]
fn packet_commitments_include_both_timeout_height_components() {
    let mut bounded = packet(1);
    bounded.timeout_height = TimeoutHeight::At(Height::new(1, 200).unwrap());
    assert_eq!(
        hex::encode(packet_commitment(&bounded)),
        "fdab2eec51c0ba0fff1d7d3d96b1974bb35d6e94090564d9a2a0eec59c83c78c"
    );
}
