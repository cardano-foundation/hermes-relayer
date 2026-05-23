use prost::Message;
use tonic::transport::Channel;

use super::error::StellarError;

#[derive(Clone, Message)]
pub struct LatestHeightRequest {}

#[derive(Clone, Message)]
pub struct LatestHeightResponse {
    #[prost(uint64, tag = "1")]
    pub revision_number: u64,
    #[prost(uint64, tag = "2")]
    pub revision_height: u64,
}

#[derive(Clone, Message)]
pub struct QueryClientStateRequest {
    #[prost(string, tag = "1")]
    pub client_id: String,
    #[prost(uint64, tag = "2")]
    pub height: u64,
}

#[derive(Clone, Message)]
pub struct QueryClientStateResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub client_state: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub proof_height: u64,
}

#[derive(Clone, Message)]
pub struct QueryConsensusStateRequest {
    #[prost(string, tag = "1")]
    pub client_id: String,
    #[prost(uint64, tag = "2")]
    pub revision_number: u64,
    #[prost(uint64, tag = "3")]
    pub revision_height: u64,
}

#[derive(Clone, Message)]
pub struct QueryConsensusStateResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub consensus_state: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub proof_height: u64,
}

#[derive(Clone, Message)]
pub struct QueryPacketCommitmentRequest {
    #[prost(string, tag = "1")]
    pub client_id: String,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(uint64, tag = "3")]
    pub height: u64,
}

#[derive(Clone, Message)]
pub struct QueryPacketCommitmentResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub commitment: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub proof_height: u64,
}

#[derive(Clone, Message)]
pub struct QueryPacketReceiptRequest {
    #[prost(string, tag = "1")]
    pub client_id: String,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(uint64, tag = "3")]
    pub height: u64,
}

#[derive(Clone, Message)]
pub struct QueryPacketReceiptResponse {
    #[prost(bool, tag = "1")]
    pub received: bool,
    #[prost(bytes = "vec", tag = "2")]
    pub proof: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub proof_height: u64,
}

#[derive(Clone, Message)]
pub struct QueryAcknowledgementRequest {
    #[prost(string, tag = "1")]
    pub client_id: String,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(uint64, tag = "3")]
    pub height: u64,
}

#[derive(Clone, Message)]
pub struct QueryAcknowledgementResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub acknowledgement: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub proof_height: u64,
}

#[derive(Clone, Message)]
pub struct QueryNextSeqRecvRequest {
    #[prost(string, tag = "1")]
    pub client_id: String,
}

#[derive(Clone, Message)]
pub struct QueryNextSeqRecvResponse {
    #[prost(uint64, tag = "1")]
    pub next_seq_recv: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub proof: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub proof_height: u64,
}

#[derive(Clone, Message)]
pub struct QueryIbcHeaderRequest {
    #[prost(uint64, tag = "1")]
    pub height: u64,
}

#[derive(Clone, Message)]
pub struct QueryIbcHeaderResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub header: Vec<u8>,
}

#[derive(Clone, Message)]
pub struct SubmitSignedTxRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub tx_xdr: Vec<u8>,
}

#[derive(Clone, Message)]
pub struct SubmitSignedTxResponse {
    #[prost(string, tag = "1")]
    pub tx_hash: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub events: Vec<Vec<u8>>,
}

#[derive(Clone, Message)]
pub struct MsgCreateClientRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub client_state: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub consensus_state: Vec<u8>,
    #[prost(string, tag = "3")]
    pub signer: String,
    #[prost(string, tag = "4")]
    pub client_type: String,
    #[prost(uint64, tag = "5")]
    pub height: u64,
}

#[derive(Clone, Message)]
pub struct MsgCreateClientResponse {
    #[prost(string, tag = "1")]
    pub client_id: String,
}

#[derive(Clone, Message)]
pub struct MsgUpdateClientRequest {
    #[prost(string, tag = "1")]
    pub client_id: String,
    #[prost(bytes = "vec", tag = "2")]
    pub header: Vec<u8>,
    #[prost(string, tag = "3")]
    pub signer: String,
}

#[derive(Clone, Message)]
pub struct MsgUpdateClientResponse {}

#[derive(Clone, Message)]
pub struct MsgRegisterCounterpartyRequest {
    #[prost(string, tag = "1")]
    pub client_id: String,
    #[prost(string, tag = "2")]
    pub counterparty_client_id: String,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub counterparty_commitment_prefix: Vec<Vec<u8>>,
}

#[derive(Clone, Message)]
pub struct MsgRegisterCounterpartyResponse {}

#[derive(Clone, Message)]
pub struct MsgRecvPacketRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub packet: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub proof_height: u64,
    #[prost(string, tag = "4")]
    pub signer: String,
}

#[derive(Clone, Message)]
pub struct MsgRecvPacketResponse {}

#[derive(Clone, Message)]
pub struct MsgAckPacketRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub packet: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub acknowledgement: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub proof: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub proof_height: u64,
    #[prost(string, tag = "5")]
    pub signer: String,
}

#[derive(Clone, Message)]
pub struct MsgAckPacketResponse {}

#[derive(Clone, Message)]
pub struct MsgTimeoutPacketRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub packet: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub proof_height: u64,
    #[prost(string, tag = "4")]
    pub signer: String,
}

#[derive(Clone, Message)]
pub struct MsgTimeoutPacketResponse {}

#[derive(Clone, Message)]
pub struct StellarHeader {
    #[prost(uint32, tag = "1")]
    pub ledger_seq: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub ledger_header_xdr: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub ibc_state_root: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub scp_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub scp_signature: Vec<u8>,
}

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
}
