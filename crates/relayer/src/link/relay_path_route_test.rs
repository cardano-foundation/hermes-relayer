//! Keep the worker's real route and queues across cutover and query failures.
//! Only chain-runtime replies are fixtures.
use super::*;
use std::sync::{Arc, Mutex};
use std::thread;

use ibc_relayer_types::core::ics03_connection::connection::{ConnectionEnd, Counterparty};
use ibc_relayer_types::core::ics04_channel::channel::Counterparty as ChannelCounterparty;
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentPrefix;

use crate::chain::handle::{BaseChainHandle, ChainRequest};
use crate::error::Error as RelayerError;

#[derive(Default)]
struct Replies {
    switched: [bool; 2],
    unavailable: bool,
    mismatched: bool,
    packet_query_fails: bool,
    height: u64,
    status_queries: usize,
    channel_queries: usize,
    submitted_packets: usize,
}

fn height(n: u64) -> Height {
    Height::new(0, n).unwrap()
}

fn client(side: usize, replacement: bool) -> ClientId {
    let kind = ["07-tendermint", "08-cardano-probabilistic"][side];
    format!("{kind}-{}", u8::from(replacement)).parse().unwrap()
}

fn hop(side: usize, replacement: bool) -> ConnectionId {
    ConnectionId::new(if replacement { [1, 7][side] } else { 0 })
}

fn runtime(
    config: ChainConfig,
    side: usize,
    replies: Arc<Mutex<Replies>>,
) -> (BaseChainHandle, thread::JoinHandle<()>) {
    let (sender, receiver) = crossbeam_channel::unbounded();
    let handle = BaseChainHandle::new(config.id().clone(), sender);
    let worker = thread::spawn(move || {
        for (_, request) in receiver {
            let mut state = replies.lock().unwrap();
            match request {
                ChainRequest::Config { reply_to } => reply_to.send(Ok(config.clone())).unwrap(),
                ChainRequest::QueryApplicationStatus { reply_to } => {
                    state.status_queries += 1;
                    let answer = if state.packet_query_fails && state.status_queries > 2 {
                        Err(RelayerError::query(
                            "packet regeneration unavailable".into(),
                        ))
                    } else {
                        Ok(ChainStatus {
                            height: height(state.height),
                            timestamp: Timestamp::from_nanoseconds(110_000_000_000).unwrap(),
                        })
                    };
                    reply_to.send(answer).unwrap();
                }
                ChainRequest::QueryChannel {
                    request, reply_to, ..
                } => {
                    assert!(
                        matches!(request.height, QueryHeight::Specific(h) if h == height(state.height))
                    );
                    assert_eq!(request.channel_id, ChannelId::new([0, 7][side]));
                    state.channel_queries += 1;
                    let answer = if state.unavailable {
                        Err(RelayerError::query("channel query unavailable".into()))
                    } else {
                        Ok((
                            ChannelEnd::new(
                                ChannelState::Open(ibc_relayer_types::core::ics04_channel::channel::UpgradeState::NotUpgrading),
                                if state.mismatched { Ordering::Ordered } else { Ordering::Unordered },
                                ChannelCounterparty::new(
                                    if state.mismatched { "wrong-port".parse().unwrap() } else { PortId::transfer() },
                                    if state.mismatched { None } else { Some(ChannelId::new([7, 0][side])) },
                                ),
                                vec![hop(side, state.switched[side])],
                                if state.mismatched && side == 1 { "wrong-version" } else { "ics20-1" }.parse().unwrap(),
                                Sequence::from(1),
                            ),
                            None,
                        ))
                    };
                    reply_to.send(answer).unwrap();
                }
                ChainRequest::QueryConnection {
                    request, reply_to, ..
                } => {
                    let switched = state.switched[side];
                    assert!(
                        matches!(request.height, QueryHeight::Specific(h) if h == height(state.height))
                    );
                    assert_eq!(request.connection_id, hop(side, switched));
                    reply_to
                        .send(Ok((
                            ConnectionEnd::new(
                                ConnectionState::Open,
                                client(side, switched),
                                Counterparty::new(
                                    client(1 - side, switched),
                                    Some(hop(1 - side, switched)),
                                    CommitmentPrefix::try_from(b"ibc".to_vec()).unwrap(),
                                ),
                                vec![],
                                Duration::ZERO,
                            ),
                            None,
                        )))
                        .unwrap();
                }
                ChainRequest::QueryUnreceivedPackets { request, reply_to } => {
                    reply_to
                        .send(Ok(request.packet_commitment_sequences))
                        .unwrap();
                }
                ChainRequest::QueryPacketCommitment { reply_to, .. } => {
                    reply_to.send(Ok((vec![1; 32], None))).unwrap();
                }
                ChainRequest::BuildPacketProofs {
                    height: proof_height,
                    reply_to,
                    ..
                } => {
                    assert_eq!(proof_height, height(33));
                    reply_to
                        .send(Ok(ibc_relayer_types::proofs::Proofs::new(
                            vec![9, 8, 7].try_into().unwrap(),
                            None,
                            None,
                            None,
                            None,
                            proof_height,
                        )
                        .unwrap()))
                        .unwrap();
                }
                ChainRequest::Signer { reply_to } => {
                    reply_to
                        .send(Ok("fixture-signer".parse().unwrap()))
                        .unwrap();
                }
                ChainRequest::QueryClientState { reply_to, .. } => {
                    reply_to
                        .send(Ok((super::delayed_height_tests::cardano_client(), None)))
                        .unwrap();
                }
                ChainRequest::SendMessagesAndWaitCheckTx {
                    tracked_msgs,
                    reply_to,
                } => {
                    assert_eq!(side, 1, "fresh receives must target the destination");
                    state.submitted_packets += tracked_msgs.msgs.len();
                    reply_to.send(Ok(vec![])).unwrap();
                }
                unexpected => panic!("unexpected route request: {unexpected:?}"),
            }
        }
    });
    (handle, worker)
}

struct Fixture {
    path: RelayPath<BaseChainHandle, BaseChainHandle>,
    replies: Arc<Mutex<Replies>>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl Fixture {
    fn new(reverse: bool) -> Self {
        let cosmos: crate::config::Config = toml::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config.toml"
        )))
        .unwrap();
        let cardano = serde_json::from_value(serde_json::json!({
            "type": "Cardano", "id": "cardano-0", "gateway_url": "http://127.0.0.1:1",
            "network_id": 0, "key_name": "unused-test-key"
        }))
        .unwrap();
        let replies = Arc::new(Mutex::new(Replies {
            height: 60,
            ..Replies::default()
        }));
        let (cardano, cardano_runtime) = runtime(cardano, 0, replies.clone());
        let (cosmos, cosmos_runtime) = runtime(cosmos.chains[0].clone(), 1, replies.clone());
        let sides = [cardano, cosmos]
            .into_iter()
            .enumerate()
            .map(|(side, chain)| {
                ChannelSide::new(
                    chain,
                    client(side, false),
                    hop(side, false),
                    PortId::transfer(),
                    Some(ChannelId::new([0, 7][side])),
                    Some("ics20-1".parse().unwrap()),
                )
            })
            .collect::<Vec<_>>();
        let mut sides = sides.into_iter();
        let (cardano, cosmos) = (sides.next().unwrap(), sides.next().unwrap());
        let (a_side, b_side) = if reverse {
            (cosmos, cardano)
        } else {
            (cardano, cosmos)
        };
        let limits =
            serde_json::from_value(serde_json::json!({"enabled": false, "size": "32768 B"}))
                .unwrap();
        let path = RelayPath::new(
            Channel {
                ordering: Ordering::Unordered,
                a_side,
                b_side,
                connection_delay: Duration::ZERO,
            },
            false,
            LinkParameters {
                src_port_id: PortId::transfer(),
                src_channel_id: ChannelId::new(if reverse { 7 } else { 0 }),
                max_memo_size: limits,
                max_receiver_size: limits,
                exclude_src_sequences: vec![],
            },
        )
        .unwrap();
        Self {
            path,
            replies,
            workers: vec![cardano_runtime, cosmos_runtime],
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
fn existing_packet_path_adopts_both_replacement_connections_and_clients() {
    for reverse in [false, true] {
        let mut fixture = Fixture::new(reverse);
        fixture.replies.lock().unwrap().switched = [true, true];
        fixture.path.refresh_channel_route().unwrap();
        let (source, destination) = if reverse { (1, 0) } else { (0, 1) };
        assert_eq!(fixture.path.src_connection_id(), &hop(source, true));
        assert_eq!(fixture.path.dst_connection_id(), &hop(destination, true));
        assert_eq!(fixture.path.src_client_id(), &client(source, true));
        assert_eq!(fixture.path.dst_client_id(), &client(destination, true));
        assert_eq!(
            fixture.path.src_channel_id(),
            &ChannelId::new([0, 7][source])
        );
        fixture.path.refresh_channel_route().unwrap();
        assert_eq!(fixture.replies.lock().unwrap().channel_queries, 2);
        fixture.finish();
    }
}

#[test]
fn partial_cutover_and_outage_retry_without_reverting_the_open_endpoint() {
    let mut fixture = Fixture::new(false);
    fixture.replies.lock().unwrap().switched = [true, false];
    assert!(fixture.path.refresh_channel_route().is_err());
    assert_eq!(fixture.path.src_connection_id(), &hop(0, false));
    fixture.replies.lock().unwrap().unavailable = true;
    assert!(fixture.path.refresh_channel_route().is_err());
    {
        let mut replies = fixture.replies.lock().unwrap();
        replies.unavailable = false;
        replies.switched = [true, true];
    }
    // Retry at the same heights. Failed observations must never be cached.
    fixture.path.refresh_channel_route().unwrap();
    assert_eq!(fixture.path.src_connection_id(), &hop(0, true));
    fixture.finish();
}

#[test]
fn queued_messages_survive_failed_rebuild_on_the_replacement_route() {
    let mut fixture = Fixture::new(false);
    let mut data = OperationalData::new(
        height(33),
        OperationalDataTarget::Destination,
        TrackingId::new_static("queued-before-upgrade"),
        Duration::ZERO,
    );
    data.push(TransitMessage {
        event_with_height: IbcEventWithHeight::new(
            IbcEvent::SendPacket(SendPacket {
                packet: Packet {
                    sequence: Sequence::from(1),
                    source_port: PortId::transfer(),
                    source_channel: ChannelId::new(0),
                    destination_port: PortId::transfer(),
                    destination_channel: ChannelId::new(7),
                    data: b"retained work".to_vec(),
                    timeout_height:
                        ibc_relayer_types::core::ics04_channel::timeout::TimeoutHeight::Never,
                    timeout_timestamp: Timestamp::from_nanoseconds(200_000_000_000).unwrap(),
                },
            }),
            height(33),
        ),
        msg: Any {
            type_url: "/test/retained-packet".into(),
            value: vec![1, 2, 3],
        },
    });
    fixture.path.dst_operational_data.push_back(data.clone());
    // First cache unchanged heights. Then fail only the query used to rebuild
    // packet messages, after both new connections have been authenticated.
    fixture.path.refresh_channel_route().unwrap();
    {
        let mut replies = fixture.replies.lock().unwrap();
        replies.switched = [true, true];
        replies.height += 1;
        replies.status_queries = 0;
    }
    // Fail the third status query, after both latest heights and connection
    // replies. The original bytes and proof height must survive regeneration.
    fixture.replies.lock().unwrap().packet_query_fails = true;
    assert!(fixture.path.refresh_channel_route().is_err());
    assert_eq!(fixture.path.src_connection_id(), &hop(0, false));
    let retained = fixture.path.dst_operational_data.clone_vec();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].batch[0].msg, data.batch[0].msg);
    assert_eq!(retained[0].proofs_height, height(33));
    assert_eq!(
        retained[0].tracking_id.to_string(),
        data.tracking_id.to_string()
    );
    assert_eq!(fixture.replies.lock().unwrap().channel_queries, 4);
    fixture.replies.lock().unwrap().packet_query_fails = false;
    fixture.path.refresh_channel_route().unwrap();
    assert_eq!(fixture.path.src_connection_id(), &hop(0, true));
    let rebuilt = fixture.path.dst_operational_data.clone_vec();
    assert_eq!(rebuilt.len(), 1);
    assert_eq!(rebuilt[0].batch.len(), 1);
    assert_eq!(
        rebuilt[0].batch[0].event_with_height,
        data.batch[0].event_with_height
    );
    assert_eq!(
        rebuilt[0].batch[0].msg.type_url,
        "/ibc.core.channel.v1.MsgRecvPacket"
    );
    assert_eq!(rebuilt[0].proofs_height, height(33));
    assert_eq!(
        rebuilt[0].tracking_id.to_string(),
        data.tracking_id.to_string()
    );
    fixture.finish();
}

#[test]
fn route_rejection_identifies_every_mismatch_and_retries_same_heights() {
    for reverse in [false, true] {
        let mut fixture = Fixture::new(reverse);
        fixture.replies.lock().unwrap().mismatched = true;
        let error = fixture
            .path
            .refresh_channel_route()
            .unwrap_err()
            .to_string();
        for side in ["source", "destination"] {
            for field in [
                "counterparty.port_id",
                "counterparty.channel_id",
                "ordering",
            ] {
                assert!(
                    error.contains(&format!("{side}.{field} expected=")),
                    "{error}"
                );
            }
        }
        assert!(error.contains("destination.version expected="), "{error}");
        assert!(error.contains("actual=None"), "{error}");
        assert!(error.contains("wrong-port"), "{error}");
        assert!(error.contains("wrong-version"), "{error}");
        assert_eq!(error.matches(" at 0-60").count(), 2, "{error}");
        assert!(fixture.path.route_heights.is_none());
        fixture.replies.lock().unwrap().mismatched = false;
        fixture.path.refresh_channel_route().unwrap();
        assert_eq!(fixture.replies.lock().unwrap().channel_queries, 4);
        fixture.finish();
    }
}

#[test]
fn fresh_receives_progress_while_a_cardano_refund_is_pending_or_failed() {
    let mut fixture = Fixture::new(false);
    let refund = OperationalData::new(
        height(33),
        OperationalDataTarget::Source,
        TrackingId::new_static("older-refund"),
        Duration::ZERO,
    );
    let (sender, reply) = crossbeam_channel::bounded(1);
    fixture.path.source_submission = Some(SourceSubmission {
        operation: refund,
        reply,
    });
    fixture
        .path
        .src_operational_data
        .push_back(OperationalData::new(
            height(33),
            OperationalDataTarget::Source,
            TrackingId::new_static("next-refund"),
            Duration::ZERO,
        ));
    for sequence in 22..=24 {
        // The update and connection delay for this receive are already satisfied.
        let mut receive = OperationalData::new(
            height(33),
            OperationalDataTarget::Destination,
            TrackingId::new_static("fresh-receive"),
            Duration::from_nanos(1),
        );
        receive.set_update_height(height(33));
        receive
            .set_scheduled_time(fixture.path.dst_time_latest().unwrap() - Duration::from_secs(1));
        receive.push(TransitMessage {
            event_with_height: IbcEventWithHeight::new(
                IbcEvent::SendPacket(SendPacket {
                    packet: Packet {
                        sequence: Sequence::from(sequence),
                        source_port: PortId::transfer(),
                        source_channel: ChannelId::new(0),
                        destination_port: PortId::transfer(),
                        destination_channel: ChannelId::new(7),
                        data: vec![],
                        timeout_height:
                            ibc_relayer_types::core::ics04_channel::timeout::TimeoutHeight::Never,
                        timeout_timestamp: Timestamp::from_nanoseconds(200_000_000_000).unwrap(),
                    },
                }),
                height(33),
            ),
            msg: Any {
                type_url: "/ibc.core.channel.v1.MsgRecvPacket".into(),
                value: vec![],
            },
        });
        if sequence == 24 {
            sender
                .send(Err(LinkError::relayer(RelayerError::send_tx(
                    "refund signing rejected".into(),
                ))))
                .unwrap();
        }
        fixture.path.dst_operational_data.push_back(receive);
        fixture.path.execute_schedule().unwrap();
        assert_eq!(
            fixture.replies.lock().unwrap().submitted_packets,
            (sequence - 21) as usize
        );
        assert_eq!(fixture.path.source_submission.is_some(), sequence < 24);
        assert_eq!(
            fixture.path.src_operational_data.len(),
            1,
            "only one refund can be in flight"
        );
    }
    fixture.finish();
}

#[test]
fn idle_schedule_does_not_query_an_unavailable_route() {
    let Fixture {
        path,
        replies,
        workers,
    } = Fixture::new(false);
    replies.lock().unwrap().unavailable = true;
    let packet = crate::object::Packet {
        src_chain_id: path.src_chain().id(),
        dst_chain_id: path.dst_chain().id(),
        src_channel_id: path.src_channel_id().clone(),
        src_port_id: path.src_port_id().clone(),
    };
    let mut link = crate::link::Link { a_to_b: path };
    assert!(crate::worker::packet::handle_execute_schedule(
        &mut link,
        &packet,
        crate::link::Resubmit::from_clear_interval(100),
    )
    .is_ok());
    assert_eq!(replies.lock().unwrap().status_queries, 0);
    assert_eq!(replies.lock().unwrap().channel_queries, 0);

    // Real queued work must still authenticate the route before submitting.
    link.a_to_b
        .src_operational_data
        .push_back(OperationalData::new(
            height(33),
            OperationalDataTarget::Source,
            TrackingId::new_static("refund"),
            Duration::ZERO,
        ));
    assert!(crate::worker::packet::handle_execute_schedule(
        &mut link,
        &packet,
        crate::link::Resubmit::from_clear_interval(100),
    )
    .is_err());
    assert!(link.a_to_b.has_pending_work());
    assert!(replies.lock().unwrap().channel_queries > 0);
    assert_eq!(replies.lock().unwrap().submitted_packets, 0);
    drop(link);
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn non_clearing_blocks_are_forwarded_even_when_the_route_is_unavailable() {
    let Fixture {
        path,
        replies,
        workers,
    } = Fixture::new(false);
    replies.lock().unwrap().unavailable = true;
    let link = Arc::new(Mutex::new(crate::link::Link { a_to_b: path }));
    let (sender, receiver) = crossbeam_channel::unbounded();
    let (forward, forwarded) = crossbeam_channel::unbounded();
    let task = crate::worker::packet::spawn_clear_cmd_worker(
        receiver,
        link.clone(),
        false,
        100,
        100,
        forward,
    );
    for n in 61..65 {
        sender
            .send(crate::worker::WorkerCmd::NewBlock {
                height: height(n),
                new_block: ibc_relayer_types::core::ics02_client::events::NewBlock::new(height(n)),
            })
            .unwrap();
        assert!(
            matches!(forwarded.recv_timeout(Duration::from_secs(3)).unwrap(),
            crate::worker::WorkerCmd::NewBlock { height: h, .. } if h == height(n))
        );
    }
    task.shutdown_and_wait();
    assert_eq!(replies.lock().unwrap().status_queries, 0);
    assert_eq!(replies.lock().unwrap().channel_queries, 0);
    drop(link);
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn in_flight_refunds_and_confirmations_keep_the_schedule_active() {
    let mut fixture = Fixture::new(false);
    assert!(!fixture.path.has_pending_work());
    let refund = OperationalData::new(
        height(33),
        OperationalDataTarget::Source,
        TrackingId::new_static("refund"),
        Duration::ZERO,
    );
    let (_sender, reply) = crossbeam_channel::bounded(1);
    fixture.path.source_submission = Some(SourceSubmission {
        operation: refund.clone(),
        reply,
    });
    assert!(fixture.path.has_pending_work());
    fixture.path.source_submission = None;
    fixture.path.confirm_txes = true;
    for pending in [
        &fixture.path.pending_txs_src.pending_queue,
        &fixture.path.pending_txs_dst.pending_queue,
    ] {
        pending.push_back(crate::link::pending::PendingData {
            original_od: refund.clone(),
            tx_hashes: crate::link::TxHashes(vec![]),
            submit_time: std::time::Instant::now(),
            error_events: vec![],
        });
        assert!(fixture.path.has_pending_work());
        pending.take();
        assert!(!fixture.path.has_pending_work());
    }
    fixture.finish();
}

#[test]
fn waiting_for_a_refund_polls_completion_without_competing_route_queries() {
    let Fixture {
        path,
        replies,
        workers,
    } = Fixture::new(false);
    let packet = crate::object::Packet {
        src_chain_id: path.src_chain().id(),
        dst_chain_id: path.dst_chain().id(),
        src_channel_id: path.src_channel_id().clone(),
        src_port_id: path.src_port_id().clone(),
    };
    let mut link = crate::link::Link { a_to_b: path };
    let (sender, reply) = crossbeam_channel::bounded(1);
    link.a_to_b.source_submission = Some(SourceSubmission {
        operation: OperationalData::new(
            height(33),
            OperationalDataTarget::Source,
            TrackingId::new_static("refund"),
            Duration::ZERO,
        ),
        reply,
    });
    replies.lock().unwrap().unavailable = true;
    assert!(crate::worker::packet::handle_execute_schedule(
        &mut link,
        &packet,
        crate::link::Resubmit::from_clear_interval(100),
    )
    .is_ok());
    assert!(link.a_to_b.source_submission.is_some());
    sender
        .send(Ok(relay_sender::AsyncReply { responses: vec![] }))
        .unwrap();
    assert!(crate::worker::packet::handle_execute_schedule(
        &mut link,
        &packet,
        crate::link::Resubmit::from_clear_interval(100),
    )
    .is_ok());
    assert!(link.a_to_b.source_submission.is_none());
    assert_eq!(replies.lock().unwrap().status_queries, 0);
    assert_eq!(replies.lock().unwrap().channel_queries, 0);
    // Destination work still needs route authentication even during a refund.
    let (_sender, reply) = crossbeam_channel::bounded(1);
    link.a_to_b.source_submission = Some(SourceSubmission {
        operation: OperationalData::new(
            height(33),
            OperationalDataTarget::Source,
            TrackingId::new_static("another-refund"),
            Duration::ZERO,
        ),
        reply,
    });
    link.a_to_b
        .dst_operational_data
        .push_back(OperationalData::new(
            height(33),
            OperationalDataTarget::Destination,
            TrackingId::new_static("receive"),
            Duration::ZERO,
        ));
    assert!(crate::worker::packet::handle_execute_schedule(
        &mut link,
        &packet,
        crate::link::Resubmit::from_clear_interval(100),
    )
    .is_err());
    assert!(replies.lock().unwrap().channel_queries > 0);
    assert_eq!(replies.lock().unwrap().submitted_packets, 0);
    drop(link);
    for worker in workers {
        worker.join().unwrap();
    }
}
