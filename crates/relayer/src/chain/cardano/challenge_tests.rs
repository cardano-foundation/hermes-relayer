use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw;
use ibc_relayer_types::core::ics02_client::header::Header;
use ibc_relayer_types::Height;
use prost::Message;
use tonic::codegen::{http, Body, BoxFuture, Service, StdError};

use super::challenge::context_from_store;
use super::gateway_client::GatewayClient;
use super::generated::ibc::core::types::v1::{QueryIbcHeaderRequest, QueryIbcHeaderResponse};

#[derive(Clone)]
struct WitnessService(Arc<Mutex<Option<QueryIbcHeaderRequest>>>);

impl tonic::server::NamedService for WitnessService {
    const NAME: &'static str = "ibc.core.types.v1.Query";
}

impl tonic::server::UnaryService<QueryIbcHeaderRequest> for WitnessService {
    type Response = QueryIbcHeaderResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<QueryIbcHeaderRequest>) -> Self::Future {
        *self.0.lock().unwrap() = Some(request.into_inner());
        Box::pin(async {
            let header = raw::ProbabilisticHeader {
                trusted_height: Some(raw::Height {
                    revision_number: 0,
                    revision_height: 99,
                }),
                anchor_block: Some(raw::ProbabilisticBlock {
                    height: Some(raw::Height {
                        revision_number: 0,
                        revision_height: 100,
                    }),
                    timestamp: 1_700_001_000_000_000_000,
                    ..Default::default()
                }),
                is_checkpoint: true,
                ..Default::default()
            };
            Ok(tonic::Response::new(QueryIbcHeaderResponse {
                header: Some(prost_types::Any {
                    type_url: ibc_relayer_types::clients::ics08_cardano_probabilistic::header::PROBABILISTIC_HEADER_TYPE_URL.to_owned(),
                    value: header.encode_to_vec(),
                }),
            }))
        })
    }
}

impl<B> Service<http::Request<B>> for WitnessService
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        assert_eq!(request.uri().path(), "/ibc.core.types.v1.Query/IBCHeader");
        let service = self.clone();
        Box::pin(async move {
            Ok(
                tonic::server::Grpc::new(tonic::codec::ProstCodec::default())
                    .unary(service, request)
                    .await,
            )
        })
    }
}

#[tokio::test]
async fn independent_challenge_request_carries_pre_proposal_context_on_the_wire() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/challenge-settlement.json")).unwrap();
    let snapshot = raw::ClientState::decode(
        hex::decode(fixture["snapshot_hex"].as_str().unwrap())
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let mut latest = snapshot.clone();
    latest
        .latest_checkpoint_height
        .as_mut()
        .unwrap()
        .revision_height = 110;
    latest.latest_checkpoint_epoch = 8;
    latest.current_epoch = 8;
    latest.latest_checkpoint_pool_production = Some(raw::PoolProductionHistory {
        epoch: 8,
        pools: vec![],
    });
    latest.latest_checkpoint_settlement_credit = Some(raw::SettlementCreditState {
        epoch: 8,
        reference: vec![raw::PoolSettlementCredit {
            pool_id: "pool-a".into(),
            numerator: vec![1],
            denominator: vec![100],
        }],
    });
    latest.epoch_context_challenges = vec![raw::EpochContextChallenge {
        epoch: 8,
        usable_after_unix_ns: 1,
    }];
    let context = context_from_store(latest, Height::new(0, 99).unwrap(), |_| {
        Ok(snapshot.encode_to_vec())
    })
    .unwrap();

    let received = Arc::new(Mutex::new(None));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = async_stream::stream! {
        loop { yield listener.accept().await.map(|(stream, _)| stream); }
    };
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(WitnessService(received.clone()))
            .serve_with_incoming(incoming),
    );
    let gateway = GatewayClient::new(format!("http://{address}"))
        .await
        .unwrap();
    let target = Height::new(0, 100).unwrap();
    let submitted: ibc_relayer_types::core::ics02_client::header::AnyHeader =
        raw::ProbabilisticHeader {
            trusted_height: Some(raw::Height {
                revision_number: 0,
                revision_height: 99,
            }),
            anchor_block: Some(raw::ProbabilisticBlock {
                height: Some(raw::Height {
                    revision_number: 0,
                    revision_height: 100,
                }),
                timestamp: 1,
                ..Default::default()
            }),
            ..Default::default()
        }
        .try_into()
        .map(ibc_relayer_types::core::ics02_client::header::AnyHeader::Probabilistic)
        .unwrap();
    assert!(
        super::endpoint::query_cardano_witness_header(&gateway, &submitted, None)
            .await
            .is_err()
    );
    assert!(received.lock().unwrap().is_none());
    let header = super::endpoint::query_cardano_witness_header(&gateway, &submitted, Some(context))
        .await
        .unwrap();
    assert_eq!(header.height(), target);
    let request = received.lock().unwrap().take().unwrap();
    assert!(request.checkpoint_only);
    // Gateway and the Go core exercise this fixture with five producers at
    // 250 bps, then eleven at 550 bps. The shorter evidence must not settle.
    assert_eq!(
        hex::encode(request.encode_to_vec()),
        fixture["request_hex"].as_str().unwrap()
    );
    server.abort();
}

#[test]
fn foreign_client_retrieves_trusted_checkpoint_context_before_the_witness_request() {
    use crate::chain::handle::{BaseChainHandle, ChainRequest};
    use crate::client_state::AnyClientState;
    use crate::foreign_client::ForeignClient;
    use ibc_relayer_types::clients::ics08_cardano_probabilistic::client_state::ClientState;
    use ibc_relayer_types::core::ics02_client::client_type::ClientType;
    use ibc_relayer_types::core::ics02_client::events::{Attributes, UpdateClient};
    use ibc_relayer_types::core::ics02_client::header::AnyHeader;
    use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ClientId};

    for unavailable in [false, true] {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/challenge-settlement.json")).unwrap();
        let request = QueryIbcHeaderRequest::decode(
            hex::decode(fixture["request_hex"].as_str().unwrap())
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let expected_context = request.probabilistic_client_state;
        let mut latest = raw::ClientState::decode(expected_context.as_slice()).unwrap();
        latest.chain_id = "cardano-0".into();
        latest.latest_height = Some(raw::Height {
            revision_number: 0,
            revision_height: 100,
        });
        latest
            .latest_checkpoint_height
            .as_mut()
            .unwrap()
            .revision_height = 110;
        latest.current_epoch = 8;
        latest.latest_checkpoint_epoch = 8;
        latest.trusting_period = Some(ibc_proto::google::protobuf::Duration {
            seconds: 60,
            nanos: 0,
        });
        latest.max_clock_drift = Some(ibc_proto::google::protobuf::Duration {
            seconds: 10,
            nanos: 0,
        });
        latest.packet_lane_policy_id = vec![1; 28];
        latest.host_state_nft_policy_id = vec![2; 28];
        latest.epoch_nonce = vec![3; 32];
        latest.slots_per_kes_period = 129600;
        latest.current_epoch_start_slot = 3000;
        latest.current_epoch_end_slot_exclusive = 5100;
        latest.system_start_unix_ns = 1_700_000_000_000_000_000;
        latest.slot_length_ns = 1_000_000_000;
        latest.max_kes_evolutions = 62;
        latest.active_slot_coefficient_numerator = 1;
        latest.active_slot_coefficient_denominator = 20;
        latest.operational_certificate_counter_history_start_height =
            latest.latest_checkpoint_height.clone();
        latest.latest_checkpoint_pool_production = Some(raw::PoolProductionHistory {
            epoch: 8,
            pools: vec![],
        });
        let latest = AnyClientState::Probabilistic(ClientState::try_from(latest).unwrap());
        let client_id: ClientId = "08-cardano-probabilistic-0".parse().unwrap();
        let submitted: AnyHeader = raw::ProbabilisticHeader {
            trusted_height: Some(raw::Height {
                revision_number: 0,
                revision_height: 99,
            }),
            anchor_block: Some(raw::ProbabilisticBlock {
                height: Some(raw::Height {
                    revision_number: 0,
                    revision_height: 100,
                }),
                timestamp: 1,
                ..Default::default()
            }),
            is_checkpoint: true,
            ..Default::default()
        }
        .try_into()
        .map(AnyHeader::Probabilistic)
        .unwrap();
        let update = UpdateClient {
            common: Attributes {
                client_id: client_id.clone(),
                client_type: ClientType::CardanoProbabilistic,
                consensus_height: Height::new(0, 100).unwrap(),
            },
            header: Some(submitted),
        };
        let (source_sender, source_receiver) = crossbeam_channel::unbounded();
        let source = BaseChainHandle::new(ChainId::from_string("cardano-0"), source_sender);
        let source_context = expected_context.clone();
        let source_runtime = std::thread::spawn(move || {
            let mut calls = 0;
            for (_, request) in source_receiver {
                match request {
                    ChainRequest::BuildMisbehaviour {
                        challenge_context,
                        reply_to,
                        ..
                    } => {
                        calls += 1;
                        assert_eq!(challenge_context.unwrap(), source_context);
                        reply_to.send(Ok(None)).unwrap();
                    }
                    other => panic!("unexpected source request: {other:?}"),
                }
            }
            calls
        });
        let (destination_sender, destination_receiver) = crossbeam_channel::unbounded();
        let destination =
            BaseChainHandle::new(ChainId::from_string("cosmos-0"), destination_sender);
        let destination_id = client_id.clone();
        let destination_runtime = std::thread::spawn(move || {
            let mut calls = 0;
            for (_, request) in destination_receiver {
                match request {
                    ChainRequest::QueryClientState { reply_to, .. } => {
                        reply_to.send(Ok((latest.clone(), None))).unwrap()
                    }
                    ChainRequest::QueryCardanoChallengeContext {
                        client_id,
                        trusted_height,
                        reply_to,
                    } => {
                        calls += 1;
                        assert_eq!(client_id, destination_id);
                        assert_eq!(trusted_height, Height::new(0, 99).unwrap());
                        if unavailable {
                            reply_to
                                .send(Err(crate::error::Error::query(
                                    "missing saved checkpoint".into(),
                                )))
                                .unwrap();
                        } else {
                            reply_to.send(Ok(expected_context.clone())).unwrap();
                        }
                    }
                    other => panic!("unexpected destination request: {other:?}"),
                }
            }
            calls
        });
        let client = ForeignClient::restore(client_id, destination, source);
        let result = client.detect_misbehaviour(Some(&update));
        if unavailable {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("failed querying Cardano challenge checkpoint 0-99"));
        } else {
            assert!(result.unwrap().is_none());
        }
        drop(client);
        assert_eq!(destination_runtime.join().unwrap(), 1);
        assert_eq!(source_runtime.join().unwrap(), usize::from(!unavailable));
    }
}

#[test]
fn sdk_events_reach_independent_challenge_submission() {
    use crate::chain::handle::{BaseChainHandle, ChainRequest};
    use crate::client_state::AnyClientState;
    use crate::foreign_client::{ForeignClient, MisbehaviourResults};
    use ibc_relayer_types::clients::ics08_cardano_probabilistic::client_state::ClientState;
    use ibc_relayer_types::core::ics02_client::header::AnyHeader;
    use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ClientId};
    use ibc_relayer_types::events::IbcEvent;

    for (name, data) in [
        (
            "root-bearing",
            include_str!("fixtures/watcher-v8-root-bearing.json"),
        ),
        (
            "rootless",
            include_str!("fixtures/watcher-v8-rootless.json"),
        ),
        (
            "root-bearing",
            include_str!("fixtures/watcher-v10-root-bearing.json"),
        ),
        (
            "rootless",
            include_str!("fixtures/watcher-v10-rootless.json"),
        ),
    ] {
        let fixture: serde_json::Value = serde_json::from_str(data).unwrap();
        let events: Vec<tendermint::abci::Event> =
            serde_json::from_value(fixture["events"].clone()).unwrap();
        let tx = hex::decode(fixture["tx"].as_str().unwrap()).unwrap();
        let hydrated = crate::event::tx::hydrate_client_updates(&tx, &events).unwrap();
        let mut recovered = crate::event::source::rpc::extract::extract_events(
            &ChainId::from_string("cosmos-1"),
            Height::new(1, 100).unwrap(),
            &hydrated,
        )
        .unwrap()
        .into_iter()
        .filter_map(|event| match event.event {
            IbcEvent::UpdateClient(update) => Some(update),
            _ => None,
        });
        let update = recovered.next().unwrap();
        assert!(recovered.next().is_none());
        assert!(update.header.is_some());
        assert_eq!(update.consensus_height(), Height::new(0, 11).unwrap());
        let latest_raw = raw::ClientState::decode(
            hex::decode(fixture["client"].as_str().unwrap())
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let mut context = raw::ClientState::decode(
            hex::decode(fixture["context"].as_str().unwrap())
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        context.current_epoch = context.latest_checkpoint_epoch;
        let snapshot = context.clone();
        let context = context.encode_to_vec();
        let witness = raw::ProbabilisticHeader::decode(
            hex::decode(fixture["witness"].as_str().unwrap())
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let witness = AnyHeader::Probabilistic(witness.try_into().unwrap());
        for (startup, proposal_only) in [(false, false), (true, false), (true, true)] {
            let mut restored = latest_raw.clone();
            if proposal_only {
                restored.current_epoch = snapshot.current_epoch;
                restored.latest_checkpoint_epoch = snapshot.latest_checkpoint_epoch;
                restored.latest_checkpoint_height = snapshot.latest_checkpoint_height.clone();
                restored.latest_height = snapshot.latest_checkpoint_height.clone();
                assert_eq!(restored.current_epoch, 7);
                assert!(restored
                    .epoch_context_challenges
                    .iter()
                    .any(|row| row.epoch == 8));
            }
            let latest = AnyClientState::Probabilistic(ClientState::try_from(restored).unwrap());
            let (source_sender, source_receiver) = crossbeam_channel::unbounded();
            let source = BaseChainHandle::new(ChainId::from_string("cardano-0"), source_sender);
            let expected_context = context.clone();
            let witness = witness.clone();
            let source_runtime = std::thread::spawn(move || {
                for (_, request) in source_receiver {
                    match request {
                        ChainRequest::BuildMisbehaviour {
                            update_event,
                            client_state,
                            challenge_context,
                            reply_to,
                        } => {
                            assert_eq!(challenge_context.unwrap(), expected_context);
                            let submitted = update_event.header.as_ref().unwrap();
                            reply_to
                                .send(super::endpoint::cardano_misbehaviour_evidence(
                                    &update_event,
                                    submitted,
                                    witness.clone(),
                                    &client_state,
                                ))
                                .unwrap();
                        }
                        ChainRequest::Config { reply_to } => {
                            let config: crate::config::Config = toml::from_str(include_str!(
                                "../../../tests/config/fixtures/relayer_conf_example.toml"
                            ))
                            .unwrap();
                            reply_to.send(Ok(config.chains[0].clone())).unwrap();
                        }
                        other => panic!("unexpected source request: {other:?}"),
                    }
                }
            });
            let (destination_sender, destination_receiver) = crossbeam_channel::unbounded();
            let destination =
                BaseChainHandle::new(ChainId::from_string("cosmos-1"), destination_sender);
            let latest = latest.clone();
            let expected_context = context.clone();
            let restored_update = update.clone();
            let output_name = name.to_owned();
            let destination_runtime = std::thread::spawn(move || {
                let mut submissions = 0;
                for (_, request) in destination_receiver {
                    match request {
                        ChainRequest::QueryClientState { reply_to, .. } => {
                            reply_to.send(Ok((latest.clone(), None))).unwrap();
                        }
                        ChainRequest::QueryCardanoChallengeContext {
                            trusted_height,
                            reply_to,
                            ..
                        } => {
                            assert_eq!(trusted_height, Height::new(0, 10).unwrap());
                            reply_to.send(Ok(expected_context.clone())).unwrap();
                        }
                        ChainRequest::QueryPacketEventDataFromTxs { request, reply_to } => {
                            assert!(
                                matches!(request,crate::chain::requests::QueryTxRequest::Client(request) if request.probabilistic_epoch == Some(8))
                            );
                            reply_to
                                .send(Ok(vec![crate::event::IbcEventWithHeight::new(
                                    IbcEvent::UpdateClient(restored_update.clone()),
                                    Height::new(1, 100).unwrap(),
                                )]))
                                .unwrap();
                        }
                        ChainRequest::Signer { reply_to } => {
                            reply_to
                                .send(Ok("cosmos1pyysjzgfpyysjzgfpyysjzgfpyysjzgfam50we"
                                    .parse()
                                    .unwrap()))
                                .unwrap();
                        }
                        ChainRequest::SendMessagesAndWaitCommit {
                            tracked_msgs,
                            reply_to,
                        } => {
                            assert_eq!(tracked_msgs.msgs.len(), 1);
                            let wire = hex::encode(&tracked_msgs.msgs[0].value);
                            let file = format!(
                                "{}/src/chain/cardano/fixtures/watcher-challenge-{output_name}.hex",
                                env!("CARGO_MANIFEST_DIR")
                            );
                            if std::env::var_os("UPDATE_WATCHER_FIXTURES").is_some() {
                                std::fs::write(&file, format!("{wire}\n")).unwrap();
                            }
                            assert_eq!(std::fs::read_to_string(&file).unwrap().trim(), wire);
                            submissions += 1;
                            reply_to
                                .send(Ok(vec![crate::event::IbcEventWithHeight::new(
                                    IbcEvent::ClientMisbehaviour(ibc_relayer_types::core::ics02_client::events::ClientMisbehaviour::from(restored_update.common.clone())),
                                    Height::new(1, 101).unwrap(),
                                )]))
                                .unwrap();
                        }
                        other => panic!("unexpected destination request: {other:?}"),
                    }
                }
                submissions
            });
            let client = ForeignClient::restore(
                "08-cardano-probabilistic-0".parse::<ClientId>().unwrap(),
                destination,
                source,
            );
            assert!(matches!(
                client.detect_misbehaviour_and_submit_evidence(if startup {
                    None
                } else {
                    Some(update.clone())
                }),
                MisbehaviourResults::EvidenceSubmitted(_)
            ));
            drop(client);
            source_runtime.join().unwrap();
            assert_eq!(destination_runtime.join().unwrap(), 1);
        }
    }
}

#[test]
fn startup_scans_stored_challenge_epochs_once_with_the_newest_first() {
    use crate::chain::handle::{BaseChainHandle, ChainRequest};
    use crate::client_state::AnyClientState;
    use crate::foreign_client::ForeignClient;
    use ibc_relayer_types::clients::ics08_cardano_probabilistic::client_state::ClientState;
    use ibc_relayer_types::core::ics24_host::identifier::ChainId;

    for (stored, expected) in [(vec![7, 8, 8, 9], vec![9, 8, 7]), (vec![], vec![8])] {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/watcher-v8-rootless.json")).unwrap();
        let mut latest = raw::ClientState::decode(
            hex::decode(fixture["client"].as_str().unwrap())
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        assert_eq!(latest.current_epoch, 8);
        latest.epoch_context_challenges = stored
            .into_iter()
            .map(|epoch| raw::EpochContextChallenge {
                epoch,
                usable_after_unix_ns: 1,
            })
            .collect();
        let latest = AnyClientState::Probabilistic(ClientState::try_from(latest).unwrap());
        let (source_sender, _source_receiver) = crossbeam_channel::unbounded();
        let source = BaseChainHandle::new(ChainId::from_string("cardano-0"), source_sender);
        let (sender, receiver) = crossbeam_channel::unbounded();
        let destination = BaseChainHandle::new(ChainId::from_string("cosmos-1"), sender);
        let thread = std::thread::spawn(move || {
            let mut epochs = vec![];
            for (_, request) in receiver {
                match request {
                    ChainRequest::QueryClientState { reply_to, .. } => {
                        reply_to.send(Ok((latest.clone(), None))).unwrap();
                    }
                    ChainRequest::QueryPacketEventDataFromTxs { request, reply_to } => {
                        let crate::chain::requests::QueryTxRequest::Client(query) = request else {
                            panic!("expected an epoch proposal lookup");
                        };
                        epochs.push(query.probabilistic_epoch.unwrap());
                        reply_to.send(Ok(vec![])).unwrap();
                    }
                    ChainRequest::QueryConsensusStateHeights { reply_to, .. } => {
                        reply_to.send(Ok(vec![])).unwrap();
                    }
                    other => panic!("unexpected startup request: {other:?}"),
                }
            }
            epochs
        });
        let client = ForeignClient::restore(
            "08-cardano-probabilistic-0".parse().unwrap(),
            destination,
            source,
        );
        assert!(client.detect_misbehaviour(None).unwrap().is_none());
        drop(client);
        assert_eq!(thread.join().unwrap(), expected);
    }
}
