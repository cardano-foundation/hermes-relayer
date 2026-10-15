//! Request-level coverage of the real refresh worker. The destination runtime
//! here is deterministic. Signed keeper and application acceptance are separate.
use super::*;
use crate::chain::{
    endpoint::ChainStatus,
    handle::{BaseChainHandle, ChainRequest},
};
use ibc_relayer_types::clients::ics08_cardano_probabilistic::{
    client_state::ClientState, consensus_state::ConsensusState, raw,
};
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentRoot;
use ibc_relayer_types::signer::Signer;
use prost::Message;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};

struct Harness {
    source: BaseChainHandle,
    destination: BaseChainHandle,
    state: Arc<Mutex<ClientState>>,
    now: Arc<AtomicU64>,
    commits: Arc<AtomicU64>,
    source_ready: Arc<AtomicBool>,
    reject_submission: Arc<AtomicBool>,
    submissions: Arc<AtomicU64>,
    proof_queries: Arc<AtomicU64>,
    source_queries: Arc<AtomicU64>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Harness {
    fn new(authoritative: bool, commit_progress: bool) -> Self {
        let AnyClientState::Probabilistic(mut client) =
            super::tests::checkpoint_test_client_state(false)
        else {
            unreachable!()
        };
        client.storage_version = 2;
        client.verification_generation = 1;
        client.checkpoint_reference = vec![1; 32];
        client.storage_namespace = vec![2; 32];
        client.system_start_unix_ns = 950_000_000_000;
        client.latest_checkpoint_timestamp = 1_000_000_000_000;
        client.trusting_period = Duration::from_secs(60);
        client.latest_checkpoint_height = Some(client.latest_height.increment());
        client.epoch_context_challenges.clear();
        let state = Arc::new(Mutex::new(client));
        let now = Arc::new(AtomicU64::new(
            state.lock().unwrap().latest_checkpoint_timestamp + 30_000_000_000,
        ));
        let proof_time = state.lock().unwrap().latest_checkpoint_timestamp - 120_000_000_000;
        let commits = Arc::new(AtomicU64::new(0));
        let source_ready = Arc::new(AtomicBool::new(true));
        let reject_submission = Arc::new(AtomicBool::new(false));
        let submissions = Arc::new(AtomicU64::new(0));
        let available = source_ready.clone();
        let proof_queries = Arc::new(AtomicU64::new(0));
        let source_queries = Arc::new(AtomicU64::new(0));
        let (tx, rx) = crossbeam_channel::unbounded();
        let source = BaseChainHandle::new(state.lock().unwrap().chain_id.clone(), tx);
        let (current, clock, source_calls) = (state.clone(), now.clone(), source_queries.clone());
        let source_thread = thread::spawn(move || {
            for (_, request) in rx {
                match request {
                    ChainRequest::Config { reply_to } => {
                        let config: ChainConfig = serde_json::from_value(serde_json::json!({
                            "type":"CosmosSdk", "id":"cardano-0", "rpc_addr":"http://127.0.0.1:26657", "grpc_addr":"http://127.0.0.1:9090",
                            "event_source":{"mode":"pull","interval":"100ms"}, "account_prefix":"cosmos", "key_name":"test", "store_prefix":"ibc", "gas_price":{"price":0.0025,"denom":"stake"}
                        })).unwrap();
                        reply_to.send(Ok(config)).unwrap();
                    }
                    ChainRequest::BuildClientMaintenanceHeader {
                        client_state,
                        reply_to,
                    } => {
                        if !available.load(Ordering::SeqCst) {
                            reply_to.send(Ok(None)).unwrap();
                            continue;
                        }
                        let AnyClientState::Probabilistic(client) = client_state else {
                            panic!("wrong client type")
                        };
                        let timestamp = clock.load(Ordering::SeqCst);
                        if timestamp <= client.latest_checkpoint_timestamp {
                            reply_to.send(Ok(None)).unwrap();
                            continue;
                        }
                        let height = client.latest_verified_height().increment();
                        let raw = raw::ProbabilisticHeader {
                            trusted_height: Some(client.latest_verified_height().into()),
                            anchor_block: Some(raw::ProbabilisticBlock {
                                height: Some(height.into()),
                                timestamp,
                                slot: (timestamp - client.system_start_unix_ns)
                                    / client.slot_length_ns,
                                epoch: client.current_epoch,
                                hash: format!("{:064x}", height.revision_height()),
                                block_cbor: vec![0x80],
                                ..Default::default()
                            }),
                            is_checkpoint: true,
                            ..Default::default()
                        };
                        let header = raw.try_into().map(ibc_relayer_types::core::ics02_client::header::AnyHeader::Probabilistic).unwrap();
                        reply_to.send(Ok(Some(header))).unwrap();
                    }
                    ChainRequest::QueryApplicationStatus { reply_to } => {
                        source_calls.fetch_add(1, Ordering::SeqCst);
                        reply_to
                            .send(Ok(ChainStatus {
                                height: current.lock().unwrap().latest_height,
                                timestamp: Timestamp::from_nanoseconds(proof_time).unwrap(),
                            }))
                            .unwrap();
                    }
                    unexpected => panic!("unexpected source request: {unexpected:?}"),
                }
            }
        });
        let (tx, rx) = crossbeam_channel::unbounded();
        let destination = BaseChainHandle::new(ChainId::from_string("cosmos-0"), tx);
        let (current, clock, committed, queries) = (
            state.clone(),
            now.clone(),
            commits.clone(),
            proof_queries.clone(),
        );
        let (reject, attempts) = (reject_submission.clone(), submissions.clone());
        let destination_thread = thread::spawn(move || {
            let mut session = serde_json::json!({"Sequence":0,"RowsRead":0,"CreditReady":true,"ProcessedBlocks":0,"Complete":false,"Receipt":vec![3u8;32]});
            let mut staged_anchor: Option<raw::ProbabilisticBlock> = None;
            for (_, request) in rx {
                match request {
                    ChainRequest::QueryCardanoChallengeContext { reply_to, .. } => {
                        let raw: raw::ClientState = current.lock().unwrap().clone().into();
                        reply_to.send(Ok(raw.encode_to_vec())).unwrap();
                    }
                    ChainRequest::QueryProbabilisticVerification {
                        request, reply_to, ..
                    } => {
                        assert_eq!(request.kind, 8);
                        reply_to
                            .send(Ok(serde_json::to_vec(&session).unwrap()))
                            .unwrap();
                    }
                    ChainRequest::QueryClientState { reply_to, .. } => {
                        reply_to
                            .send(Ok((
                                AnyClientState::Probabilistic(current.lock().unwrap().clone()),
                                None,
                            )))
                            .unwrap();
                    }
                    ChainRequest::QueryApplicationStatus { reply_to } => {
                        reply_to
                            .send(Ok(ChainStatus {
                                height: Height::new(0, 100).unwrap(),
                                timestamp: Timestamp::from_nanoseconds(
                                    clock.load(Ordering::SeqCst),
                                )
                                .unwrap(),
                            }))
                            .unwrap();
                    }
                    ChainRequest::QueryClientStatus { reply_to, .. } => {
                        let client = current.lock().unwrap();
                        let timestamp = if client.latest_checkpoint_timestamp == 0 {
                            proof_time
                        } else {
                            client.latest_checkpoint_timestamp
                        };
                        let status = if clock.load(Ordering::SeqCst) >= timestamp + 60_000_000_000 {
                            "Expired"
                        } else {
                            "Active"
                        };
                        reply_to
                            .send(Ok(authoritative.then(|| status.to_owned())))
                            .unwrap();
                    }
                    ChainRequest::Signer { reply_to } => {
                        reply_to.send(Ok(Signer::dummy())).unwrap();
                    }
                    ChainRequest::SendMessagesAndWaitCommit {
                        tracked_msgs,
                        reply_to,
                    } => {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        if reject.load(Ordering::SeqCst) {
                            reply_to
                                .send(Err(RelayerError::query("host proofs pending".to_owned())))
                                .unwrap();
                            continue;
                        }
                        assert_eq!(tracked_msgs.msgs.len(), 1);
                        let update = ibc_proto::ibc::core::client::v1::MsgUpdateClient::decode(
                            tracked_msgs.msgs[0].value.as_slice(),
                        )
                        .unwrap();
                        let header = raw::ProbabilisticHeader::decode(
                            update.client_message.unwrap().value.as_slice(),
                        )
                        .unwrap();
                        let chunk = header
                            .observation_chunk
                            .expect("maintenance must use bounded operations");
                        session["Sequence"] = chunk.sequence.into();
                        match chunk.operation {
                            1 => {
                                session["ProcessedBlocks"] = 0.into();
                                session["Complete"] = false.into();
                            }
                            4 => {
                                staged_anchor = chunk.blocks.first().cloned();
                                session["ProcessedBlocks"] = chunk.blocks.len().into();
                            }
                            6 => session["Complete"] = true.into(),
                            7 if commit_progress => {
                                let anchor = staged_anchor.take().unwrap();
                                let mut client = current.lock().unwrap();
                                client.latest_checkpoint_height =
                                    Some(anchor.height.unwrap().try_into().unwrap());
                                client.latest_checkpoint_timestamp = anchor.timestamp;
                                client.latest_checkpoint_slot = anchor.slot;
                                client.latest_checkpoint_block_hash = anchor.hash;
                                committed.fetch_add(1, Ordering::SeqCst);
                            }
                            7 => {}
                            _ => panic!("unexpected maintenance operation"),
                        }
                        reply_to.send(Ok(vec![])).unwrap();
                    }
                    ChainRequest::QueryConsensusState { reply_to, .. } => {
                        queries.fetch_add(1, Ordering::SeqCst);
                        let consensus = ConsensusState {
                            timestamp: proof_time,
                            root: CommitmentRoot::from_bytes(&[1; 32]),
                            accepted_block_hash: "01".repeat(32),
                            accepted_epoch: 7,
                            unique_pools_count: 5,
                            unique_stake_bps: 1000,
                            security_score_bps: 1000,
                            verification_generation: 1,
                            checkpoint_reference: vec![1; 32],
                            packet_state_reference: vec![2; 32],
                        };
                        reply_to
                            .send(Ok((AnyConsensusState::Probabilistic(consensus), None)))
                            .unwrap();
                    }
                    unexpected => panic!("unexpected destination request: {unexpected:?}"),
                }
            }
        });
        Self {
            source,
            destination,
            state,
            now,
            commits,
            source_ready,
            reject_submission,
            submissions,
            proof_queries,
            source_queries,
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
fn checkpoint_freshness_uses_destination_time_without_a_timestamp_fallback() {
    for authoritative in [false, true] {
        let h = Harness::new(authoritative, true);
        let client = h.client();
        assert!(client.validated_client_state().is_ok());
        assert_eq!(h.proof_queries.load(Ordering::SeqCst), 0);
        assert_eq!(h.source_queries.load(Ordering::SeqCst), 0);
        let timestamp = h.state.lock().unwrap().latest_checkpoint_timestamp;
        h.now
            .store(timestamp + 60_000_000_000 - 1, Ordering::SeqCst);
        assert!(client.validated_client_state().is_ok());
        h.now.store(timestamp + 60_000_000_000, Ordering::SeqCst);
        assert!(client
            .validated_client_state()
            .unwrap_err()
            .is_expired_error());
        assert!(client.clone().refresh().unwrap_err().is_expired_error());
        // Even a root-bearing cursor must carry its authenticated timestamp.
        {
            let mut state = h.state.lock().unwrap();
            state.latest_checkpoint_height = Some(state.latest_height);
            state.latest_checkpoint_slot = 0;
            state.latest_checkpoint_timestamp = 0;
        }
        h.now.store(
            timestamp - 120_000_000_000 + 59_000_000_000,
            Ordering::SeqCst,
        );
        assert!(client.validated_client_state().is_err());
        assert_eq!(h.proof_queries.load(Ordering::SeqCst), 0);
        h.state.lock().unwrap().latest_checkpoint_height = Some(Height::new(0, 10000).unwrap());
        assert!(client
            .validated_client_state()
            .unwrap_err()
            .to_string()
            .contains("invalid authenticated checkpoint"));
        drop(client);
        h.close();
    }
}

#[test]
fn a_transaction_without_committed_checkpoint_progress_does_not_renew_trust() {
    let h = Harness::new(true, false);
    let before = h.state.lock().unwrap().latest_checkpoint_timestamp;
    assert!(h
        .client()
        .refresh()
        .unwrap_err()
        .to_string()
        .contains("no checkpoint or proposal"));
    assert_eq!(before, h.state.lock().unwrap().latest_checkpoint_timestamp);
    h.close();
}

#[test]
fn normal_refresh_worker_keeps_an_idle_client_alive_and_resumes_after_restart() {
    let h = Harness::new(true, true);
    let initial = h.state.lock().unwrap().latest_checkpoint_timestamp;
    for restart in 0..2 {
        let worker = crate::worker::client::spawn_refresh_client(h.client()).unwrap();
        for target in restart * 3 + 1..=restart * 3 + 3 {
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            while h.commits.load(Ordering::SeqCst) < target {
                assert!(
                    std::time::Instant::now() < deadline,
                    "refresh worker did not commit maintenance"
                );
                thread::sleep(Duration::from_millis(25));
            }
            let checkpoint = h.state.lock().unwrap().latest_checkpoint_timestamp;
            h.now.store(checkpoint + 30_000_000_000, Ordering::SeqCst);
        }
        worker.shutdown_and_wait();
    }
    assert!(h.state.lock().unwrap().latest_checkpoint_timestamp > initial + 60_000_000_000);
    assert_eq!(h.proof_queries.load(Ordering::SeqCst), 0);
    assert_eq!(h.source_queries.load(Ordering::SeqCst), 0);
    h.close();
}

#[test]
fn refresh_worker_stops_when_the_checkpoint_expires() {
    let h = Harness::new(true, true);
    let worker = crate::worker::client::spawn_refresh_client(h.client()).unwrap();
    let timestamp = h.state.lock().unwrap().latest_checkpoint_timestamp;
    h.now.store(timestamp + 60_000_000_000, Ordering::SeqCst);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !worker.is_stopped() {
        assert!(
            std::time::Instant::now() < deadline,
            "expired worker kept retrying"
        );
        thread::sleep(Duration::from_millis(25));
    }
    worker.join();
    assert_eq!(h.commits.load(Ordering::SeqCst), 0);
    h.close();
}

#[test]
fn awaiting_source_settlement_is_not_a_renewal_or_a_retry_failure() {
    let h = Harness::new(true, true);
    h.source_ready.store(false, Ordering::SeqCst);
    let before = h.state.lock().unwrap().latest_checkpoint_timestamp;
    assert_eq!(h.client().refresh().unwrap(), Some(vec![]));
    assert_eq!(h.state.lock().unwrap().latest_checkpoint_timestamp, before);
    assert_eq!(h.commits.load(Ordering::SeqCst), 0);
    h.source_ready.store(true, Ordering::SeqCst);
    h.client().refresh().unwrap();
    assert_eq!(h.commits.load(Ordering::SeqCst), 1);
    h.close();
}

#[test]
fn missing_checkpoint_timestamps_fail_without_querying_proof_state() {
    let h = Harness::new(false, true);
    {
        let mut state = h.state.lock().unwrap();
        state.storage_version = 2;
        state.latest_checkpoint_timestamp = 0;
        state.latest_checkpoint_slot = 0;
        state.latest_checkpoint_height = Some(state.latest_height);
    }
    assert!(h.client().validated_client_state().is_err());
    assert_eq!(h.proof_queries.load(Ordering::SeqCst), 0);
    h.close();
}

#[test]
fn failed_maintenance_does_not_block_shutdown_or_count_as_renewal() {
    let h = Harness::new(true, true);
    let initial = h.state.lock().unwrap().latest_checkpoint_timestamp;
    h.reject_submission.store(true, Ordering::SeqCst);
    let worker = crate::worker::client::spawn_refresh_client(h.client()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(25);
    while h.submissions.load(Ordering::SeqCst) < 3 && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(25));
    }
    let attempts = h.submissions.load(Ordering::SeqCst);
    assert_eq!(h.commits.load(Ordering::SeqCst), 0);
    assert_eq!(h.state.lock().unwrap().latest_checkpoint_timestamp, initial);
    worker.shutdown();
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    while !worker.is_stopped() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(25));
    }
    let stopped = worker.is_stopped();
    // Let a regressed worker leave its inner retry loop before the assertion.
    h.reject_submission.store(false, Ordering::SeqCst);
    worker.shutdown_and_wait();
    assert!(attempts >= 3, "maintenance did not retry on normal polls");
    assert!(
        stopped,
        "maintenance shutdown waited for the inner retry loop"
    );
    let worker = crate::worker::client::spawn_refresh_client(h.client()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while h.commits.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(25));
    }
    worker.shutdown_and_wait();
    assert_eq!(h.commits.load(Ordering::SeqCst), 1);
    assert!(h.state.lock().unwrap().latest_checkpoint_timestamp > initial);
    h.close();
}
