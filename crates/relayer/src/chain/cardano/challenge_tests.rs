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
