use super::*;
use crate::chain::{
    cardano::config::CardanoConfig,
    endpoint::ClientInitialization,
    handle::{BaseChainHandle, ChainRequest},
};
use ibc_relayer_types::clients::ics08_cardano_probabilistic::{
    client_state::ClientState, consensus_state::ConsensusState, raw,
};
use ibc_relayer_types::core::{
    ics02_client::events::{Attributes, CreateClient},
    ics23_commitment::commitment::CommitmentRoot,
};
use ibc_relayer_types::signer::Signer;
use prost::Message;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

struct Harness {
    source: BaseChainHandle,
    destination: BaseChainHandle,
    requests: Arc<Mutex<Vec<(u64, u32)>>>,
    interrupted: Arc<AtomicBool>,
    wrong_point: Arc<AtomicBool>,
    committed: Arc<Mutex<u32>>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Harness {
    fn new() -> Self {
        let AnyClientState::Probabilistic(mut client) =
            super::tests::checkpoint_test_client_state(false)
        else {
            unreachable!()
        };
        client.bootstrap_pending = true;
        client.verification_generation = 1;
        client.checkpoint_reference = vec![1; 32];
        client.storage_namespace = vec![0; 32];
        client.latest_checkpoint_height = Some(client.latest_height);
        client.trusting_period = Duration::from_secs(48 * 60 * 60);
        let consensus = AnyConsensusState::Probabilistic(ConsensusState {
            verification_generation: 1,
            checkpoint_reference: vec![1; 32],
            packet_state_reference: vec![2; 32],
            root: CommitmentRoot::from_bytes(&[3; 32]),
            timestamp: client.latest_checkpoint_timestamp,
            accepted_block_hash: client.latest_checkpoint_block_hash.clone(),
            accepted_epoch: client.current_epoch,
            unique_pools_count: 0,
            unique_stake_bps: 0,
            security_score_bps: 0,
        });
        let requests = Arc::new(Mutex::new(Vec::new()));
        let interrupted = Arc::new(AtomicBool::new(false));
        let wrong_point = Arc::new(AtomicBool::new(false));
        let committed = Arc::new(Mutex::new(0));
        let state = Arc::new(Mutex::new(None::<ClientState>));
        let id: ClientId = "08-cardano-probabilistic-0".parse().unwrap();
        let (tx, rx) = crossbeam_channel::unbounded();
        let source = BaseChainHandle::new(client.chain_id.clone(), tx);
        let (calls, wrong, initial) = (requests.clone(), wrong_point.clone(), client.clone());
        let source_thread = thread::spawn(move || {
            for (_, request) in rx {
                match request {
                    ChainRequest::Config { reply_to } => {
                        reply_to
                            .send(Ok(ChainConfig::Cardano(CardanoConfig {
                                id: initial.chain_id.clone(),
                                ..CardanoConfig::default()
                            })))
                            .unwrap();
                    }
                    ChainRequest::QueryClientInitialization {
                        height,
                        sequence,
                        reply_to,
                    } => {
                        assert_eq!(
                            height,
                            if sequence == 0 {
                                0
                            } else {
                                initial.latest_height.revision_height()
                            }
                        );
                        calls.lock().unwrap().push((height, sequence));
                        let mut prepared = initial.clone();
                        if sequence > 0 && wrong.load(Ordering::SeqCst) {
                            prepared.checkpoint_reference = vec![9; 32];
                        }
                        let message = if sequence == 0 {
                            None
                        } else {
                            let header = raw::ProbabilisticHeader {
                                observation_chunk: Some(raw::ObservationChunk {
                                    operation: if sequence == 1 { 10 } else { 11 },
                                    sequence,
                                    ..Default::default()
                                }),
                                ..Default::default()
                            };
                            Some(AnyHeader::Probabilistic(header.try_into().unwrap()))
                        };
                        reply_to
                            .send(Ok(ClientInitialization {
                                client_state: AnyClientState::Probabilistic(prepared),
                                consensus_state: consensus.clone(),
                                message,
                            }))
                            .unwrap();
                    }
                    other => panic!("Creation unexpectedly queried the source: {other:?}"),
                }
            }
        });
        let (tx, rx) = crossbeam_channel::unbounded();
        let destination = BaseChainHandle::new(ChainId::from_string("cosmos-0"), tx);
        let (stored, cursor, fail, client_id) =
            (state.clone(), committed.clone(), interrupted.clone(), id);
        let destination_thread = thread::spawn(move || {
            for (_, request) in rx {
                match request {
                    ChainRequest::QueryApplicationStatus { reply_to } => {
                        reply_to
                            .send(Ok(crate::chain::endpoint::ChainStatus {
                                height: Height::new(0, 1).unwrap(),
                                timestamp:
                                    ibc_relayer_types::timestamp::Timestamp::from_nanoseconds(
                                        101_000_000_000,
                                    )
                                    .unwrap(),
                            }))
                            .unwrap();
                    }
                    ChainRequest::QueryClientStatus { reply_to, .. } => {
                        reply_to.send(Ok(Some("Active".into()))).unwrap();
                    }
                    ChainRequest::Signer { reply_to } => {
                        reply_to
                            .send(Ok("cosmos1operator".parse::<Signer>().unwrap()))
                            .unwrap();
                    }
                    ChainRequest::QueryClientState { reply_to, .. } => {
                        reply_to
                            .send(Ok((
                                AnyClientState::Probabilistic(
                                    stored.lock().unwrap().clone().unwrap(),
                                ),
                                None,
                            )))
                            .unwrap();
                    }
                    ChainRequest::QueryProbabilisticVerification {
                        request, reply_to, ..
                    } => {
                        assert_eq!(request.kind, 11);
                        reply_to
                            .send(Ok(serde_json::to_vec(
                                &serde_json::json!({"Sequence": *cursor.lock().unwrap()}),
                            )
                            .unwrap()))
                            .unwrap();
                    }
                    ChainRequest::SendMessagesAndWaitCommit {
                        tracked_msgs,
                        reply_to,
                    } => {
                        assert_eq!(tracked_msgs.msgs.len(), 1);
                        let message = &tracked_msgs.msgs[0];
                        if message.type_url == "/ibc.core.client.v1.MsgCreateClient" {
                            let create = ibc_proto::ibc::core::client::v1::MsgCreateClient::decode(
                                message.value.as_slice(),
                            )
                            .unwrap();
                            let raw = raw::ClientState::decode(
                                create.client_state.unwrap().value.as_slice(),
                            )
                            .unwrap();
                            assert_eq!(raw.storage_version, 2);
                            assert!(raw.epoch_stake_distribution.is_empty());
                            let mut installed: ClientState = raw.try_into().unwrap();
                            installed.storage_namespace = vec![7; 32];
                            *stored.lock().unwrap() = Some(installed);
                            reply_to
                                .send(Ok(vec![IbcEventWithHeight {
                                    height: Height::new(0, 1).unwrap(),
                                    event: IbcEvent::CreateClient(CreateClient(Attributes {
                                        client_id: client_id.clone(),
                                        client_type: ClientType::CardanoProbabilistic,
                                        consensus_height: client.latest_height,
                                    })),
                                }]))
                                .unwrap();
                        } else {
                            assert_eq!(message.type_url, "/ibc.core.client.v1.MsgUpdateClient");
                            let update = ibc_proto::ibc::core::client::v1::MsgUpdateClient::decode(
                                message.value.as_slice(),
                            )
                            .unwrap();
                            let chunk = raw::ProbabilisticHeader::decode(
                                update.client_message.unwrap().value.as_slice(),
                            )
                            .unwrap()
                            .observation_chunk
                            .unwrap();
                            if fail.load(Ordering::SeqCst) && chunk.sequence == 2 {
                                reply_to
                                    .send(Err(RelayerError::query(
                                        "interrupted initialization".into(),
                                    )))
                                    .unwrap();
                                continue;
                            }
                            assert_eq!(chunk.sequence, *cursor.lock().unwrap() + 1);
                            *cursor.lock().unwrap() = chunk.sequence;
                            if chunk.operation == 11 {
                                stored.lock().unwrap().as_mut().unwrap().bootstrap_pending = false;
                            }
                            reply_to.send(Ok(vec![])).unwrap();
                        }
                    }
                    other => panic!("Unexpected destination request: {other:?}"),
                }
            }
        });
        Self {
            source,
            destination,
            requests,
            interrupted,
            wrong_point,
            committed,
            threads: vec![source_thread, destination_thread],
        }
    }
    fn client(&self) -> ForeignClient<BaseChainHandle, BaseChainHandle> {
        ForeignClient::restore(
            "08-cardano-probabilistic-0".parse().unwrap(),
            self.destination.clone(),
            self.source.clone(),
        )
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
fn ordinary_cardano_creation_initializes_without_file_or_settlement_query() {
    let harness = Harness::new();
    harness
        .client()
        .build_create_client_and_send(CreateOptions::default())
        .unwrap();
    assert_eq!(
        *harness.requests.lock().unwrap(),
        vec![(0, 0), (10, 1), (10, 2)]
    );
    assert_eq!(*harness.committed.lock().unwrap(), 2);
    harness.client().complete_bootstrap().unwrap();
    assert_eq!(harness.requests.lock().unwrap().len(), 3);
    harness.close();
}

#[test]
fn creation_resumes_from_committed_import_after_interruption() {
    let harness = Harness::new();
    harness.interrupted.store(true, Ordering::SeqCst);
    assert!(harness
        .client()
        .build_create_client_and_send(CreateOptions::default())
        .is_err());
    assert_eq!(*harness.committed.lock().unwrap(), 1);
    harness.interrupted.store(false, Ordering::SeqCst);
    harness.client().complete_bootstrap().unwrap();
    assert_eq!(
        *harness.requests.lock().unwrap(),
        vec![(0, 0), (10, 1), (10, 2), (10, 2)]
    );
    assert_eq!(*harness.committed.lock().unwrap(), 2);
    harness.close();
}

#[test]
fn resumed_creation_rejects_a_different_initial_checkpoint() {
    let harness = Harness::new();
    harness.interrupted.store(true, Ordering::SeqCst);
    assert!(harness
        .client()
        .build_create_client_and_send(CreateOptions::default())
        .is_err());
    harness.interrupted.store(false, Ordering::SeqCst);
    harness.wrong_point.store(true, Ordering::SeqCst);
    assert!(harness
        .client()
        .complete_bootstrap()
        .unwrap_err()
        .to_string()
        .contains("different starting checkpoint"));
    assert_eq!(*harness.committed.lock().unwrap(), 1);
    harness.wrong_point.store(false, Ordering::SeqCst);
    harness.client().complete_bootstrap().unwrap();
    harness.close();
}

#[test]
fn refresh_resumes_creation_before_waiting_for_maintenance_or_source_settlement() {
    let harness = Harness::new();
    harness.interrupted.store(true, Ordering::SeqCst);
    assert!(harness
        .client()
        .build_create_client_and_send(CreateOptions::default())
        .is_err());
    assert_eq!(*harness.committed.lock().unwrap(), 1);
    harness.interrupted.store(false, Ordering::SeqCst);
    assert!(harness.client().refresh().unwrap().is_some());
    assert_eq!(*harness.committed.lock().unwrap(), 2);
    harness.close();
}
