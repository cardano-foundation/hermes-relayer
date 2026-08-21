use tonic::transport::Channel;

use super::error::StellarError;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/stellar.gateway.v1.rs"));
}

pub use proto::*;

pub struct GatewayQueryClient {
    inner: tonic::client::Grpc<Channel>,
}

impl GatewayQueryClient {
    pub async fn connect(url: String) -> Result<Self, StellarError> {
        let channel = url
            .parse::<tonic::transport::Endpoint>()
            .map_err(|e| StellarError::GatewayClient(e.to_string()))?
            .connect()
            .await
            .map_err(StellarError::from)?;
        Ok(Self {
            inner: tonic::client::Grpc::new(channel),
        })
    }

    async fn ready(&mut self) -> Result<(), StellarError> {
        self.inner
            .ready()
            .await
            .map_err(|e| StellarError::GatewayClient(e.to_string()))
    }

    pub async fn latest_height(&mut self) -> Result<LatestHeightResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayQuery/LatestHeight",
        );
        self.inner
            .unary(
                tonic::Request::new(LatestHeightRequest {}),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn query_client_state(
        &mut self,
        request: QueryClientStateRequest,
    ) -> Result<QueryClientStateResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayQuery/QueryClientState",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn query_client_states(
        &mut self,
        request: QueryClientStatesRequest,
    ) -> Result<QueryClientStatesResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayQuery/QueryClientStates",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn query_consensus_state(
        &mut self,
        request: QueryConsensusStateRequest,
    ) -> Result<QueryConsensusStateResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayQuery/QueryConsensusState",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn query_packet_commitment(
        &mut self,
        request: QueryPacketCommitmentRequest,
    ) -> Result<QueryPacketCommitmentResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayQuery/QueryPacketCommitment",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn query_packet_receipt(
        &mut self,
        request: QueryPacketReceiptRequest,
    ) -> Result<QueryPacketReceiptResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayQuery/QueryPacketReceipt",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn query_acknowledgement(
        &mut self,
        request: QueryAcknowledgementRequest,
    ) -> Result<QueryAcknowledgementResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayQuery/QueryAcknowledgement",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn query_next_seq_recv(
        &mut self,
        request: QueryNextSeqRecvRequest,
    ) -> Result<QueryNextSeqRecvResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayQuery/QueryNextSeqRecv",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    /// The parameters needed to build a Stellar client state.
    ///
    /// The quorum sets this returns are a convenience, not an authority: the
    /// caller pins their fingerprints before trusting them.
    pub async fn query_stellar_client_params(
        &mut self,
        request: QueryStellarClientParamsRequest,
    ) -> Result<QueryStellarClientParamsResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayQuery/QueryStellarClientParams",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn query_ibc_header(
        &mut self,
        request: QueryIbcHeaderRequest,
    ) -> Result<QueryIbcHeaderResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayQuery/QueryIbcHeader",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn events(&mut self, request: EventsRequest) -> Result<EventsResponse, StellarError> {
        self.ready().await?;
        let path =
            http::uri::PathAndQuery::from_static("/stellar.gateway.v1.StellarGatewayQuery/Events");
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }
}

pub struct GatewayMsgClient {
    inner: tonic::client::Grpc<Channel>,
}

impl GatewayMsgClient {
    pub async fn connect(url: String) -> Result<Self, StellarError> {
        let channel = url
            .parse::<tonic::transport::Endpoint>()
            .map_err(|e| StellarError::GatewayClient(e.to_string()))?
            .connect()
            .await
            .map_err(StellarError::from)?;
        Ok(Self {
            inner: tonic::client::Grpc::new(channel),
        })
    }

    async fn ready(&mut self) -> Result<(), StellarError> {
        self.inner
            .ready()
            .await
            .map_err(|e| StellarError::GatewayClient(e.to_string()))
    }

    pub async fn submit_signed_tx(
        &mut self,
        request: SubmitSignedTxRequest,
    ) -> Result<SubmitSignedTxResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayMsg/SubmitSignedTx",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn create_client(
        &mut self,
        request: MsgCreateClientRequest,
    ) -> Result<MsgCreateClientResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayMsg/CreateClient",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn update_client(
        &mut self,
        request: MsgUpdateClientRequest,
    ) -> Result<MsgUpdateClientResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayMsg/UpdateClient",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn register_counterparty(
        &mut self,
        request: MsgRegisterCounterpartyRequest,
    ) -> Result<MsgRegisterCounterpartyResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayMsg/RegisterCounterparty",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    /// Prepare an unsigned `commit_root()` transaction.
    ///
    /// The gateway holds no key, so this only builds; the caller signs it and
    /// sends it back through [`GatewayMsgClient::submit_signed_tx`].
    pub async fn commit_root(
        &mut self,
        request: MsgCommitRootRequest,
    ) -> Result<MsgCommitRootResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayMsg/CommitRoot",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn recv_packet(
        &mut self,
        request: MsgRecvPacketRequest,
    ) -> Result<MsgRecvPacketResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayMsg/RecvPacket",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn ack_packet(
        &mut self,
        request: MsgAckPacketRequest,
    ) -> Result<MsgAckPacketResponse, StellarError> {
        self.ready().await?;
        let path =
            http::uri::PathAndQuery::from_static("/stellar.gateway.v1.StellarGatewayMsg/AckPacket");
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn timeout_packet(
        &mut self,
        request: MsgTimeoutPacketRequest,
    ) -> Result<MsgTimeoutPacketResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayMsg/TimeoutPacket",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }

    pub async fn submit_misbehaviour(
        &mut self,
        request: MsgSubmitMisbehaviourRequest,
    ) -> Result<MsgSubmitMisbehaviourResponse, StellarError> {
        self.ready().await?;
        let path = http::uri::PathAndQuery::from_static(
            "/stellar.gateway.v1.StellarGatewayMsg/SubmitMisbehaviour",
        );
        self.inner
            .unary(
                tonic::Request::new(request),
                path,
                tonic::codec::ProstCodec::default(),
            )
            .await
            .map(|r| r.into_inner())
            .map_err(StellarError::from)
    }
}
