//! gRPC client for Cardano Gateway
//!
//! This module provides a client for interacting with the Cardano Gateway service,
//! which handles Cardano blockchain queries, transaction building, and submission.

use super::error::Error;
use super::generated::ibc::cardano::v1::{
    cardano_msg_client::CardanoMsgClient, BuildHostStateHeartbeatRequest,
    BuildHostStateHeartbeatResponse, MsgPrunePacketHistory, ObserveTxRequest, ObserveTxResponse,
    SubmitSignedTxRequest, SubmitSignedTxResponse,
};
use super::generated::ibc::core::channel::v1::msg_client::MsgClient as GenChannelMsgClient;
use super::generated::ibc::core::client::v1::msg_client::MsgClient as GenClientMsgClient;
use super::generated::ibc::core::connection::v1::msg_client::MsgClient as GenConnectionMsgClient;
use ibc_proto::google::protobuf::Any as ProtoAny;
use ibc_proto::ibc::core::channel::v1::query_client::QueryClient as ChannelQueryClient;
use ibc_proto::ibc::core::channel::v1::{
    QueryChannelClientStateRequest, QueryChannelClientStateResponse, QueryChannelRequest,
    QueryChannelsRequest, QueryConnectionChannelsRequest, QueryNextSequenceReceiveRequest,
    QueryPacketAcknowledgementRequest, QueryPacketAcknowledgementsRequest,
    QueryPacketCommitmentRequest, QueryPacketCommitmentsRequest, QueryPacketReceiptRequest,
    QueryUnreceivedAcksRequest, QueryUnreceivedPacketsRequest,
};
use ibc_proto::ibc::core::client::v1::query_client::QueryClient as ClientQueryClient;
use ibc_proto::ibc::core::client::v1::{
    QueryClientStateRequest, QueryClientStateResponse, QueryClientStatesRequest,
    QueryConsensusStateHeightsRequest, QueryConsensusStateHeightsResponse,
    QueryConsensusStateRequest, QueryConsensusStateResponse, QueryConsensusStatesRequest,
    QueryConsensusStatesResponse,
};
use ibc_proto::ibc::core::connection::v1::query_client::QueryClient as ConnectionQueryClient;
use ibc_proto::ibc::core::connection::v1::{
    QueryClientConnectionsRequest, QueryConnectionRequest, QueryConnectionsRequest,
};
use ibc_relayer_types::clients::{
    ics07_tendermint::{
        header::TENDERMINT_HEADER_TYPE_URL, misbehaviour::TENDERMINT_MISBEHAVIOR_TYPE_URL,
    },
    ics08_cardano::{header::MITHRIL_HEADER_TYPE_URL, misbehaviour::MITHRIL_MISBEHAVIOUR_TYPE_URL},
    ics08_cardano_probabilistic::{
        header::PROBABILISTIC_HEADER_TYPE_URL, misbehaviour::PROBABILISTIC_MISBEHAVIOUR_TYPE_URL,
    },
};
use ibc_relayer_types::core::ics02_client::header::AnyHeader;
use ibc_relayer_types::Height;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tonic::metadata::AsciiMetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Uri};
use tonic::{Request, Status};

const GATEWAY_HEADER_GRPC_MESSAGE_LIMIT: usize = 64 * 1024 * 1024;
const CARDANO_NATIVE_ASSET_MAX_QUANTITY: u64 = u64::MAX;
const PRUNE_PACKET_HISTORY_TYPE_URL: &str = "/ibc.cardano.v1.MsgPrunePacketHistory";

/// Unsigned transaction response from Gateway
#[derive(Debug, Clone)]
pub struct UnsignedTx {
    pub cbor_hex: String,
    pub description: String,
}

/// Transaction submission response from Gateway
#[derive(Debug, Clone)]
pub struct TxSubmitResponse {
    pub tx_hash: String,
    pub height: Option<Height>,
    pub events: Vec<IbcEvent>,
}

#[derive(Debug, Clone)]
pub struct HostStateHeartbeatBuild {
    pub heartbeat_required: bool,
    pub current_epoch: u64,
    pub host_state_epoch: u64,
    pub unsigned_tx: Option<UnsignedTx>,
}

/// A denomination trace returned by the ibc-go v10 `Query/Denom` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDenom {
    pub path: String,
    pub base_denom: String,
}

impl ResolvedDenom {
    pub fn full_denom(&self) -> String {
        if self.path.is_empty() {
            self.base_denom.clone()
        } else {
            format!("{}/{}", self.path, self.base_denom)
        }
    }
}

// ibc-proto 0.51 still exposes the pre-v10 Query/DenomTrace messages. These
// small prost types are the wire-compatible ibc-go v10 Query/Denom messages
// served by the Cardano Gateway. Keeping them private avoids exposing a second
// protobuf API while Hermes remains on ibc-proto 0.51.
#[derive(Clone, PartialEq, prost::Message)]
struct QueryDenomRequest {
    #[prost(string, tag = "1")]
    hash: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct QueryDenomResponse {
    #[prost(message, optional, tag = "1")]
    denom: Option<GatewayDenom>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GatewayDenom {
    #[prost(string, tag = "1")]
    base: String,
    #[prost(message, repeated, tag = "3")]
    trace: Vec<GatewayDenomHop>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GatewayDenomHop {
    #[prost(string, tag = "1")]
    port_id: String,
    #[prost(string, tag = "2")]
    channel_id: String,
}

/// Simplified IBC event structure for Gateway responses
#[derive(Debug, Clone)]
pub struct IbcEvent {
    pub event_type: String,
    pub attributes: Vec<(String, String)>,
}

fn describe_update_client_message(type_url: Option<&str>) -> String {
    match type_url {
        Some(TENDERMINT_HEADER_TYPE_URL) => "MsgUpdateClient<TendermintHeader>".to_string(),
        Some(TENDERMINT_MISBEHAVIOR_TYPE_URL) => {
            "MsgUpdateClient<TendermintMisbehaviour>".to_string()
        }
        Some(MITHRIL_HEADER_TYPE_URL) => "MsgUpdateClient<CardanoHeader>".to_string(),
        Some(MITHRIL_MISBEHAVIOUR_TYPE_URL) => "MsgUpdateClient<CardanoMisbehaviour>".to_string(),
        Some(PROBABILISTIC_HEADER_TYPE_URL) => "MsgUpdateClient<ProbabilisticHeader>".to_string(),
        Some(PROBABILISTIC_MISBEHAVIOUR_TYPE_URL) => {
            "MsgUpdateClient<ProbabilisticMisbehaviour>".to_string()
        }
        Some(other) => format!("MsgUpdateClient<{}>", other),
        None => "MsgUpdateClient<missing-client-message>".to_string(),
    }
}

/// Client for communicating with Cardano Gateway
#[derive(Clone)]
pub struct GatewayClient {
    endpoint: String,
    channel: InterceptedService<Channel, GatewayAuthInterceptor>,
}

#[derive(Clone)]
struct GatewayAuthInterceptor {
    authorization: Option<AsciiMetadataValue>,
}

impl Interceptor for GatewayAuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(authorization) = &self.authorization {
            request
                .metadata_mut()
                .insert("authorization", authorization.clone());
        }

        Ok(request)
    }
}

impl GatewayClient {
    /// Create a new Gateway client and establish a gRPC connection
    pub async fn new(endpoint: String) -> Result<Self, Error> {
        Self::new_with_security(endpoint, None, None).await
    }

    /// Create a Gateway client with optional private-CA trust and bearer authentication.
    pub async fn new_with_security(
        endpoint: String,
        tls_ca_file: Option<PathBuf>,
        auth_token_file: Option<PathBuf>,
    ) -> Result<Self, Error> {
        tracing::info!("Connecting to Cardano Gateway at {}", endpoint);

        let channel_endpoint = Channel::from_shared(endpoint.clone())
            .map_err(|e| Error::GatewayClient(format!("invalid Gateway endpoint: {e}")))?;
        let use_tls = validate_gateway_endpoint(channel_endpoint.uri())?;

        let channel_endpoint = if use_tls {
            let mut tls_config = ClientTlsConfig::new().with_native_roots();
            if let Some(ca_file) = tls_ca_file.as_deref() {
                let ca_pem = read_gateway_file(ca_file, "TLS CA certificate")?;
                tls_config = tls_config.ca_certificate(Certificate::from_pem(ca_pem));
            }
            channel_endpoint.tls_config(tls_config).map_err(|e| {
                Error::GatewayClient(format!("invalid Gateway TLS configuration: {e}"))
            })?
        } else {
            if tls_ca_file.is_some() {
                return Err(Error::GatewayClient(
                    "gateway_tls_ca_file requires an https:// Gateway endpoint".to_string(),
                ));
            }
            tracing::warn!(
                "Using plaintext gRPC for loopback Cardano Gateway endpoint {}; do not expose this connection to an untrusted network",
                endpoint
            );
            channel_endpoint
        };

        let authorization = auth_token_file
            .as_deref()
            .map(read_gateway_auth_token)
            .transpose()?;
        let channel = channel_endpoint.connect().await?;
        let channel = InterceptedService::new(channel, GatewayAuthInterceptor { authorization });

        Ok(Self { endpoint, channel })
    }

    fn request_with_query_height<T>(
        message: T,
        query_height: Option<Height>,
    ) -> Result<tonic::Request<T>, Error> {
        let mut request = tonic::Request::new(message);
        if let Some(height) = query_height {
            let metadata_height: AsciiMetadataValue =
                height.revision_height().to_string().parse().map_err(|e| {
                    Error::GatewayClient(format!("invalid query height metadata: {e}"))
                })?;
            request
                .metadata_mut()
                .insert("x-cosmos-block-height", metadata_height);
        }
        Ok(request)
    }

    /// Query the latest block height from the Gateway
    pub async fn query_latest_height(&self) -> Result<Height, Error> {
        use super::generated::ibc::core::client::v1::{
            query_client::QueryClient, QueryLatestHeightRequest,
        };

        let mut client = QueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryLatestHeightRequest {});

        let response = client.latest_height(request).await?.into_inner();

        tracing::debug!("Queried latest height: {}", response.height);

        // Height format: revision_number-revision_height
        // For Cardano, we use revision_number = 0
        Height::new(0, response.height)
            .map_err(|e| Error::Query(format!("Invalid height {}: {}", response.height, e)))
    }

    /// Query the canonical Cardano client state/consensus state for creating a new client.
    pub async fn query_new_client(
        &self,
        height: u64,
    ) -> Result<super::generated::ibc::core::client::v1::QueryNewClientResponse, Error> {
        use super::generated::ibc::core::client::v1::{
            query_client::QueryClient, QueryNewClientRequest,
        };

        let mut client = QueryClient::new(self.channel.clone());
        let request = tonic::Request::new(QueryNewClientRequest { height });
        let response = client.new_client(request).await?.into_inner();

        Ok(response)
    }

    /// Query client state for a specific client ID
    pub async fn query_client_state(
        &self,
        client_id: &str,
        query_height: Option<Height>,
    ) -> Result<QueryClientStateResponse, Error> {
        let mut client = ClientQueryClient::new(self.channel.clone());

        let request = Self::request_with_query_height(
            QueryClientStateRequest {
                client_id: client_id.to_string(),
            },
            query_height,
        )?;

        let response = client.client_state(request).await?.into_inner();

        Ok(response)
    }

    /// Query consensus state for a specific client ID and height
    pub async fn query_consensus_state(
        &self,
        client_id: &str,
        height: Height,
        query_height: Option<Height>,
    ) -> Result<QueryConsensusStateResponse, Error> {
        let mut client = ClientQueryClient::new(self.channel.clone());

        let request = Self::request_with_query_height(
            QueryConsensusStateRequest {
                client_id: client_id.to_string(),
                revision_number: height.revision_number(),
                revision_height: height.revision_height(),
                latest_height: false,
            },
            query_height,
        )?;

        let response = client.consensus_state(request).await?.into_inner();

        Ok(response)
    }

    /// Query consensus state heights for a specific client ID.
    pub async fn query_consensus_state_heights(
        &self,
        request: QueryConsensusStateHeightsRequest,
    ) -> Result<QueryConsensusStateHeightsResponse, Error> {
        let mut client = ClientQueryClient::new(self.channel.clone());
        let request = tonic::Request::new(request);
        let response = client.consensus_state_heights(request).await?.into_inner();
        Ok(response)
    }

    /// Query all consensus states for a specific client ID.
    pub async fn query_consensus_states(
        &self,
        request: QueryConsensusStatesRequest,
    ) -> Result<QueryConsensusStatesResponse, Error> {
        let mut client = ClientQueryClient::new(self.channel.clone());
        let request = tonic::Request::new(request);
        let response = client.consensus_states(request).await?.into_inner();
        Ok(response)
    }

    /// Query header at a specific height
    ///
    /// This is required for building headers used in `MsgUpdateClient`.
    pub async fn query_header(
        &self,
        trusted_height: Height,
        height: Height,
    ) -> Result<AnyHeader, Error> {
        use super::generated::ibc::core::types::v1::query_client::QueryClient as TypesQueryClient;
        use super::generated::ibc::core::types::v1::QueryIbcHeaderRequest;

        // Cardano headers include proof data and can exceed tonic's 4 MiB default.
        let mut client = TypesQueryClient::new(self.channel.clone())
            .max_decoding_message_size(GATEWAY_HEADER_GRPC_MESSAGE_LIMIT);

        let effective_trusted_height = if trusted_height < height {
            trusted_height
        } else {
            height
                .decrement()
                .map_err(|_| {
                    Error::Query(format!(
                        "invalid Cardano header query heights: trusted height {} must be less than target height {}",
                        trusted_height, height
                    ))
                })?
        };

        let request = tonic::Request::new(QueryIbcHeaderRequest {
            trusted_height: effective_trusted_height.revision_height(),
            height: height.revision_height(),
        });

        let response = client.ibc_header(request).await?.into_inner();

        let header_any = response
            .header
            .ok_or_else(|| Error::Query("No header in response".to_string()))?;

        let header_any = ProtoAny {
            type_url: header_any.type_url,
            value: header_any.value,
        };

        header_any
            .try_into()
            .map_err(|e: ibc_relayer_types::core::ics02_client::error::Error| {
                Error::Ibc(e.to_string())
            })
    }

    /// Query block results at a specific height.
    pub async fn query_block_results(
        &self,
        height: u64,
    ) -> Result<super::generated::ibc::core::types::v1::QueryBlockResultsResponse, Error> {
        use super::generated::ibc::core::types::v1::query_client::QueryClient as TypesQueryClient;
        use super::generated::ibc::core::types::v1::QueryBlockResultsRequest;

        let mut client = TypesQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryBlockResultsRequest { height });
        let response = client.block_results(request).await?.into_inner();

        Ok(response)
    }

    /// Search for blocks containing packet-related events.
    pub async fn query_block_search(
        &self,
        packet_src_channel: String,
        packet_dst_channel: String,
        packet_sequence: String,
        limit: u64,
    ) -> Result<super::generated::ibc::core::types::v1::QueryBlockSearchResponse, Error> {
        self.query_block_search_page(
            packet_src_channel,
            packet_dst_channel,
            packet_sequence,
            limit,
            1,
        )
        .await
    }

    /// Search for blocks containing packet-related events, returning all pages.
    pub async fn query_block_search_all(
        &self,
        packet_src_channel: String,
        packet_dst_channel: String,
        packet_sequence: String,
        limit: u64,
    ) -> Result<super::generated::ibc::core::types::v1::QueryBlockSearchResponse, Error> {
        let mut page = 1u64;
        let mut blocks = Vec::new();
        let mut total_count = None;

        loop {
            let response = self
                .query_block_search_page(
                    packet_src_channel.clone(),
                    packet_dst_channel.clone(),
                    packet_sequence.clone(),
                    limit,
                    page,
                )
                .await?;

            if total_count.is_none() {
                total_count = Some(response.total_count);
            }

            let page_is_empty = response.blocks.is_empty();
            blocks.extend(response.blocks);

            let total = total_count.unwrap_or(0);
            if total == 0 || blocks.len() as u64 >= total {
                break;
            }

            // Defensive: avoid infinite pagination if server returns empty pages.
            if page > 1 && page_is_empty {
                break;
            }

            page = page.saturating_add(1);
        }

        Ok(
            super::generated::ibc::core::types::v1::QueryBlockSearchResponse {
                total_count: total_count.unwrap_or(blocks.len() as u64),
                blocks,
            },
        )
    }

    async fn query_block_search_page(
        &self,
        packet_src_channel: String,
        packet_dst_channel: String,
        packet_sequence: String,
        limit: u64,
        page: u64,
    ) -> Result<super::generated::ibc::core::types::v1::QueryBlockSearchResponse, Error> {
        use super::generated::ibc::core::types::v1::query_client::QueryClient as TypesQueryClient;
        use super::generated::ibc::core::types::v1::QueryBlockSearchRequest;

        let mut client = TypesQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryBlockSearchRequest {
            packet_src_channel,
            packet_dst_channel,
            packet_sequence,
            limit,
            page,
        });

        let response = client.block_search(request).await?.into_inner();
        Ok(response)
    }

    /// Query a transaction by hash.
    pub async fn query_transaction_by_hash(
        &self,
        hash: String,
    ) -> Result<super::generated::ibc::core::types::v1::QueryTransactionByHashResponse, Error> {
        use super::generated::ibc::core::types::v1::query_client::QueryClient as TypesQueryClient;
        use super::generated::ibc::core::types::v1::QueryTransactionByHashRequest;

        let mut client = TypesQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryTransactionByHashRequest { hash });
        let response = client.transaction_by_hash(request).await?.into_inner();
        Ok(response)
    }

    /// Query the client state associated with a channel.
    pub async fn query_channel_client_state(
        &self,
        port_id: &str,
        channel_id: &str,
    ) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryChannelClientStateRequest {
            port_id: port_id.to_string(),
            channel_id: channel_id.to_string(),
        });

        let response: QueryChannelClientStateResponse =
            client.channel_client_state(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query connection state
    pub async fn query_connection(
        &self,
        connection_id: &str,
        query_height: Option<Height>,
    ) -> Result<Vec<u8>, Error> {
        let mut client = ConnectionQueryClient::new(self.channel.clone());

        let request = Self::request_with_query_height(
            QueryConnectionRequest {
                connection_id: connection_id.to_string(),
            },
            query_height,
        )?;

        let response = client.connection(request).await?.into_inner();

        // Return serialized connection
        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query all connections
    pub async fn query_connections(&self) -> Result<Vec<u8>, Error> {
        let mut client = ConnectionQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryConnectionsRequest { pagination: None });

        let response = client.connections(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query channel state
    pub async fn query_channel(
        &self,
        port_id: &str,
        channel_id: &str,
        query_height: Option<Height>,
    ) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());

        let request = Self::request_with_query_height(
            QueryChannelRequest {
                port_id: port_id.to_string(),
                channel_id: channel_id.to_string(),
            },
            query_height,
        )?;

        let response = client.channel(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query all channels
    pub async fn query_channels(&self) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryChannelsRequest { pagination: None });

        let response = client.channels(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query all clients
    pub async fn query_clients(&self) -> Result<Vec<u8>, Error> {
        let mut client = ClientQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryClientStatesRequest { pagination: None });

        let response = client.client_states(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Resolve an ICS-20 hash through the standard ibc-go v10 `Query/Denom`
    /// endpoint and cryptographically bind the response to the requested hash.
    ///
    /// The Gateway is not trusted to choose the full denomination used by the
    /// signing policy. A response is accepted only when its canonical full denom
    /// hashes to the exact SHA-256 value requested by Hermes.
    pub async fn query_denom(&self, hash: &str) -> Result<ResolvedDenom, Error> {
        let expected_hash = parse_ibc_denom_hash(hash)?;
        let mut client = tonic::client::Grpc::new(self.channel.clone());
        client.ready().await.map_err(|_| {
            Error::GatewayClient("Gateway denomination query service was not ready".to_string())
        })?;

        let codec = tonic::codec::ProstCodec::default();
        let path =
            http::uri::PathAndQuery::from_static("/ibc.applications.transfer.v1.Query/Denom");
        let mut request = tonic::Request::new(QueryDenomRequest {
            hash: hex::encode_upper(expected_hash),
        });
        request.extensions_mut().insert(tonic::GrpcMethod::new(
            "ibc.applications.transfer.v1.Query",
            "Denom",
        ));

        let response: tonic::Response<QueryDenomResponse> =
            client.unary(request, path, codec).await?;
        let denom = response.into_inner().denom.ok_or_else(|| {
            Error::GatewayClient(format!(
                "Gateway returned an empty denomination for hash {hash}"
            ))
        })?;

        resolve_gateway_denom(denom, expected_hash)
    }

    /// Query connections associated with a client
    pub async fn query_client_connections(&self, client_id: &str) -> Result<Vec<u8>, Error> {
        let mut client = ConnectionQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryClientConnectionsRequest {
            client_id: client_id.to_string(),
        });

        let response = client.client_connections(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query channels associated with a connection
    pub async fn query_connection_channels(&self, connection_id: &str) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryConnectionChannelsRequest {
            connection: connection_id.to_string(),
            pagination: None,
        });

        let response = client.connection_channels(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query packet commitment
    pub async fn query_packet_commitment(
        &self,
        port_id: &str,
        channel_id: &str,
        sequence: u64,
        query_height: Option<Height>,
    ) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());

        let request = Self::request_with_query_height(
            QueryPacketCommitmentRequest {
                port_id: port_id.to_string(),
                channel_id: channel_id.to_string(),
                sequence,
            },
            query_height,
        )?;

        let response = client.packet_commitment(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query all packet commitments for a channel
    pub async fn query_packet_commitments(
        &self,
        port_id: &str,
        channel_id: &str,
    ) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryPacketCommitmentsRequest {
            port_id: port_id.to_string(),
            channel_id: channel_id.to_string(),
            pagination: None,
        });

        let response = client.packet_commitments(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query packet receipt
    pub async fn query_packet_receipt(
        &self,
        port_id: &str,
        channel_id: &str,
        sequence: u64,
        query_height: Option<Height>,
    ) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());

        let request = Self::request_with_query_height(
            QueryPacketReceiptRequest {
                port_id: port_id.to_string(),
                channel_id: channel_id.to_string(),
                sequence,
            },
            query_height,
        )?;

        let response = client.packet_receipt(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query packet acknowledgement
    pub async fn query_packet_acknowledgement(
        &self,
        port_id: &str,
        channel_id: &str,
        sequence: u64,
        query_height: Option<Height>,
    ) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());

        let request = Self::request_with_query_height(
            QueryPacketAcknowledgementRequest {
                port_id: port_id.to_string(),
                channel_id: channel_id.to_string(),
                sequence,
            },
            query_height,
        )?;

        let response = client.packet_acknowledgement(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query all packet acknowledgements for a channel
    pub async fn query_packet_acknowledgements(
        &self,
        port_id: &str,
        channel_id: &str,
    ) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryPacketAcknowledgementsRequest {
            port_id: port_id.to_string(),
            channel_id: channel_id.to_string(),
            pagination: None,
            packet_commitment_sequences: vec![],
        });

        let response = client.packet_acknowledgements(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query unreceived packets
    pub async fn query_unreceived_packets(
        &self,
        port_id: &str,
        channel_id: &str,
        sequences: Vec<u64>,
    ) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryUnreceivedPacketsRequest {
            port_id: port_id.to_string(),
            channel_id: channel_id.to_string(),
            packet_commitment_sequences: sequences,
        });

        let response = client.unreceived_packets(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query unreceived acknowledgements
    pub async fn query_unreceived_acknowledgements(
        &self,
        port_id: &str,
        channel_id: &str,
        sequences: Vec<u64>,
    ) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());

        let request = tonic::Request::new(QueryUnreceivedAcksRequest {
            port_id: port_id.to_string(),
            channel_id: channel_id.to_string(),
            packet_ack_sequences: sequences,
        });

        let response = client.unreceived_acks(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query next sequence receive for a channel
    pub async fn query_next_sequence_receive(
        &self,
        port_id: &str,
        channel_id: &str,
        query_height: Option<Height>,
    ) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());

        let request = Self::request_with_query_height(
            QueryNextSequenceReceiveRequest {
                port_id: port_id.to_string(),
                channel_id: channel_id.to_string(),
            },
            query_height,
        )?;

        let response = client.next_sequence_receive(request).await?.into_inner();

        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Build unsigned transaction for IBC message via Gateway
    /// Gateway returns CBOR hex that Hermes will sign
    ///
    /// This method routes IBC messages to the appropriate Gateway Msg service based on the type_url.
    /// The type_url format is: "/ibc.core.{module}.v1.Msg{Operation}"
    pub async fn build_ibc_tx(
        &self,
        type_url: &str,
        message_data: Vec<u8>,
    ) -> Result<UnsignedTx, Error> {
        tracing::info!(
            "Building unsigned transaction for message type: {}",
            type_url
        );

        // Route based on type_url
        match type_url {
            // IBC Client messages
            "/ibc.core.client.v1.MsgCreateClient" => {
                self.build_create_client_tx(message_data).await
            }
            "/ibc.core.client.v1.MsgUpdateClient" => {
                self.build_update_client_tx(message_data).await
            }
            "/ibc.core.client.v1.MsgRecoverClient" => {
                self.build_recover_client_tx(message_data).await
            }

            // IBC Connection messages
            "/ibc.core.connection.v1.MsgConnectionOpenInit" => {
                self.build_connection_open_init_tx(message_data).await
            }
            "/ibc.core.connection.v1.MsgConnectionOpenTry" => {
                self.build_connection_open_try_tx(message_data).await
            }
            "/ibc.core.connection.v1.MsgConnectionOpenAck" => {
                self.build_connection_open_ack_tx(message_data).await
            }
            "/ibc.core.connection.v1.MsgConnectionOpenConfirm" => {
                self.build_connection_open_confirm_tx(message_data).await
            }

            // IBC Channel messages
            "/ibc.core.channel.v1.MsgChannelOpenInit" => {
                self.build_channel_open_init_tx(message_data).await
            }
            "/ibc.core.channel.v1.MsgChannelOpenTry" => {
                self.build_channel_open_try_tx(message_data).await
            }
            "/ibc.core.channel.v1.MsgChannelOpenAck" => {
                self.build_channel_open_ack_tx(message_data).await
            }
            "/ibc.core.channel.v1.MsgChannelOpenConfirm" => {
                self.build_channel_open_confirm_tx(message_data).await
            }
            "/ibc.core.channel.v1.MsgChannelCloseInit" => {
                self.build_channel_close_init_tx(message_data).await
            }
            "/ibc.core.channel.v1.MsgChannelCloseConfirm" => {
                self.build_channel_close_confirm_tx(message_data).await
            }

            // IBC Packet messages
            "/ibc.core.channel.v1.MsgRecvPacket" => self.build_recv_packet_tx(message_data).await,
            "/ibc.core.channel.v1.MsgAcknowledgement" => {
                self.build_acknowledgement_tx(message_data).await
            }
            "/ibc.core.channel.v1.MsgTimeout" => self.build_timeout_tx(message_data).await,
            "/ibc.core.channel.v1.MsgTimeoutOnClose" => {
                self.build_timeout_on_close_tx(message_data).await
            }
            PRUNE_PACKET_HISTORY_TYPE_URL => self.build_prune_packet_history_tx(message_data).await,

            // IBC Transfer messages
            "/ibc.applications.transfer.v1.MsgTransfer" => {
                self.build_transfer_tx(message_data).await
            }

            // Unknown message type
            _ => {
                tracing::error!("Unsupported message type: {}", type_url);
                Err(Error::Transaction(format!(
                    "Unsupported message type: {}",
                    type_url
                )))
            }
        }
    }

    //
    // Helper methods for building each message type
    //

    async fn build_create_client_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::client::v1::MsgCreateClient;
        use prost::Message;

        let msg = MsgCreateClient::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgCreateClient: {}", e)))?;

        let mut client = GenClientMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.create_client(request).await?.into_inner();

        // Extract unsigned CBOR from response
        // Gateway returns unsigned_tx as google.protobuf.Any with CBOR hex in the value field
        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in CreateClient response".to_string())
        })?;

        // The value field contains the CBOR hex string
        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "CreateClient: received unsigned CBOR (length: {}), client_id: {}",
            cbor_hex.len(),
            response.client_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!("MsgCreateClient (client_id: {})", response.client_id),
        })
    }

    async fn build_update_client_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::client::v1::MsgUpdateClient;
        use prost::Message;

        let msg = MsgUpdateClient::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgUpdateClient: {}", e)))?;

        let client_id = msg.client_id.clone();
        let message_description = describe_update_client_message(
            msg.client_message
                .as_ref()
                .map(|client_message| client_message.type_url.as_str()),
        );

        let mut client = GenClientMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.update_client(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in UpdateClient response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "{}: received unsigned CBOR (length: {}), client_id: {}",
            message_description,
            cbor_hex.len(),
            client_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!("{message_description} (client_id: {client_id})"),
        })
    }

    async fn build_recover_client_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::client::v1::MsgRecoverClient;
        use prost::Message;

        let msg = MsgRecoverClient::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgRecoverClient: {e}")))?;

        let subject_client_id = msg.subject_client_id.clone();
        let substitute_client_id = msg.substitute_client_id.clone();

        let mut client = GenClientMsgClient::new(self.channel.clone());
        let response = client
            .recover_client(tonic::Request::new(msg))
            .await?
            .into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in RecoverClient response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {e}")))?;

        tracing::info!(
            "RecoverClient: received unsigned CBOR (length: {}), subject_client_id: {}, substitute_client_id: {}",
            cbor_hex.len(),
            subject_client_id,
            substitute_client_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!(
                "MsgRecoverClient (subject_client_id: {subject_client_id}, substitute_client_id: {substitute_client_id})"
            ),
        })
    }

    async fn build_connection_open_init_tx(
        &self,
        message_data: Vec<u8>,
    ) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::connection::v1::MsgConnectionOpenInit;
        use prost::Message;

        let msg = MsgConnectionOpenInit::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgConnectionOpenInit: {}", e))
        })?;

        let client_id = msg.client_id.clone();

        let mut client = GenConnectionMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.connection_open_init(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in ConnectionOpenInit response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "ConnectionOpenInit: received unsigned CBOR (length: {}), client_id: {}",
            cbor_hex.len(),
            client_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!("MsgConnectionOpenInit (client_id: {})", client_id),
        })
    }

    async fn build_connection_open_try_tx(
        &self,
        message_data: Vec<u8>,
    ) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::connection::v1::MsgConnectionOpenTry;
        use prost::Message;

        let msg = MsgConnectionOpenTry::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgConnectionOpenTry: {}", e))
        })?;

        let client_id = msg.client_id.clone();

        let mut client = GenConnectionMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.connection_open_try(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in ConnectionOpenTry response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "ConnectionOpenTry: received unsigned CBOR (length: {}), client_id: {}",
            cbor_hex.len(),
            client_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!("MsgConnectionOpenTry (client_id: {})", client_id),
        })
    }

    async fn build_connection_open_ack_tx(
        &self,
        message_data: Vec<u8>,
    ) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::connection::v1::MsgConnectionOpenAck;
        use prost::Message;

        let msg = MsgConnectionOpenAck::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgConnectionOpenAck: {}", e))
        })?;

        let connection_id = msg.connection_id.clone();

        let mut client = GenConnectionMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.connection_open_ack(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in ConnectionOpenAck response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "ConnectionOpenAck: received unsigned CBOR (length: {}), connection_id: {}",
            cbor_hex.len(),
            connection_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!("MsgConnectionOpenAck (connection_id: {})", connection_id),
        })
    }

    async fn build_connection_open_confirm_tx(
        &self,
        message_data: Vec<u8>,
    ) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::connection::v1::MsgConnectionOpenConfirm;
        use prost::Message;

        let msg = MsgConnectionOpenConfirm::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgConnectionOpenConfirm: {}", e))
        })?;

        let connection_id = msg.connection_id.clone();

        let mut client = GenConnectionMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.connection_open_confirm(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in ConnectionOpenConfirm response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "ConnectionOpenConfirm: received unsigned CBOR (length: {}), connection_id: {}",
            cbor_hex.len(),
            connection_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!(
                "MsgConnectionOpenConfirm (connection_id: {})",
                connection_id
            ),
        })
    }

    async fn build_channel_open_init_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::channel::v1::MsgChannelOpenInit;
        use prost::Message;

        let msg = MsgChannelOpenInit::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgChannelOpenInit: {}", e))
        })?;

        let port_id = msg.port_id.clone();

        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.channel_open_init(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in ChannelOpenInit response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "ChannelOpenInit: received unsigned CBOR (length: {}), port_id: {}, channel_id: {}",
            cbor_hex.len(),
            port_id,
            response.channel_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!(
                "MsgChannelOpenInit (port: {}, channel: {})",
                port_id, response.channel_id
            ),
        })
    }

    async fn build_channel_open_try_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::channel::v1::MsgChannelOpenTry;
        use prost::Message;

        let msg = MsgChannelOpenTry::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgChannelOpenTry: {}", e))
        })?;

        let port_id = msg.port_id.clone();

        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.channel_open_try(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in ChannelOpenTry response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "ChannelOpenTry: received unsigned CBOR (length: {}), port_id: {}",
            cbor_hex.len(),
            port_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!("MsgChannelOpenTry (port: {})", port_id),
        })
    }

    async fn build_channel_open_ack_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::channel::v1::MsgChannelOpenAck;
        use prost::Message;

        let msg = MsgChannelOpenAck::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgChannelOpenAck: {}", e))
        })?;

        let port_id = msg.port_id.clone();
        let channel_id = msg.channel_id.clone();

        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.channel_open_ack(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in ChannelOpenAck response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "ChannelOpenAck: received unsigned CBOR (length: {}), port_id: {}, channel_id: {}",
            cbor_hex.len(),
            port_id,
            channel_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!(
                "MsgChannelOpenAck (port: {}, channel: {})",
                port_id, channel_id
            ),
        })
    }

    async fn build_channel_open_confirm_tx(
        &self,
        message_data: Vec<u8>,
    ) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::channel::v1::MsgChannelOpenConfirm;
        use prost::Message;

        let msg = MsgChannelOpenConfirm::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgChannelOpenConfirm: {}", e))
        })?;

        let port_id = msg.port_id.clone();
        let channel_id = msg.channel_id.clone();

        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.channel_open_confirm(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in ChannelOpenConfirm response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "ChannelOpenConfirm: received unsigned CBOR (length: {}), port_id: {}, channel_id: {}",
            cbor_hex.len(),
            port_id,
            channel_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!(
                "MsgChannelOpenConfirm (port: {}, channel: {})",
                port_id, channel_id
            ),
        })
    }

    async fn build_channel_close_init_tx(
        &self,
        message_data: Vec<u8>,
    ) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::channel::v1::MsgChannelCloseInit;
        use prost::Message;

        let msg = MsgChannelCloseInit::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgChannelCloseInit: {}", e))
        })?;

        let port_id = msg.port_id.clone();
        let channel_id = msg.channel_id.clone();

        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.channel_close_init(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in ChannelCloseInit response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "ChannelCloseInit: received unsigned CBOR (length: {}), port_id: {}, channel_id: {}",
            cbor_hex.len(),
            port_id,
            channel_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!(
                "MsgChannelCloseInit (port: {}, channel: {})",
                port_id, channel_id
            ),
        })
    }

    async fn build_channel_close_confirm_tx(
        &self,
        message_data: Vec<u8>,
    ) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::channel::v1::MsgChannelCloseConfirm;
        use prost::Message;

        let msg = MsgChannelCloseConfirm::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgChannelCloseConfirm: {}", e))
        })?;

        let port_id = msg.port_id.clone();
        let channel_id = msg.channel_id.clone();

        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.channel_close_confirm(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in ChannelCloseConfirm response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "ChannelCloseConfirm: received unsigned CBOR (length: {}), port_id: {}, channel_id: {}",
            cbor_hex.len(),
            port_id,
            channel_id
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!(
                "MsgChannelCloseConfirm (port: {}, channel: {})",
                port_id, channel_id
            ),
        })
    }

    async fn build_recv_packet_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::channel::v1::MsgRecvPacket;
        use prost::Message;

        let msg = MsgRecvPacket::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgRecvPacket: {}", e)))?;

        let sequence = msg
            .packet
            .as_ref()
            .ok_or_else(|| Error::Transaction("MsgRecvPacket missing packet".to_string()))?
            .sequence;

        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.recv_packet(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in RecvPacket response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "RecvPacket: received unsigned CBOR (length: {}), sequence: {}",
            cbor_hex.len(),
            sequence
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!("MsgRecvPacket (sequence: {})", sequence),
        })
    }

    async fn build_acknowledgement_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::channel::v1::MsgAcknowledgement;
        use prost::Message;

        let msg = MsgAcknowledgement::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgAcknowledgement: {}", e))
        })?;

        let sequence = msg
            .packet
            .as_ref()
            .ok_or_else(|| Error::Transaction("MsgAcknowledgement missing packet".to_string()))?
            .sequence;

        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.acknowledgement(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in Acknowledgement response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "Acknowledgement: received unsigned CBOR (length: {}), sequence: {}",
            cbor_hex.len(),
            sequence
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!("MsgAcknowledgement (sequence: {})", sequence),
        })
    }

    async fn build_transfer_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use ibc_proto::ibc::applications::transfer::v1::MsgTransfer;
        use prost::Message;

        let msg = MsgTransfer::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgTransfer: {}", e)))?;

        let token_info = msg
            .token
            .as_ref()
            .ok_or_else(|| Error::Transaction("MsgTransfer missing token".to_string()))?;
        let token = cardano_transfer_token_from_canonical(token_info)?;

        let timeout_height =
            msg.timeout_height
                .map(|height| super::generated::ibc::core::client::v1::Height {
                    revision_number: height.revision_number,
                    revision_height: height.revision_height,
                });

        // The Gateway expects MsgTransfer under `ibc.core.channel.v1` and includes a `signer`
        // field. In canonical IBC, the sender is the signer for MsgTransfer.
        let sender = msg.sender;

        tracing::info!(
            "Preparing transfer request for gateway: source_port={} source_channel={} receiver={} sender={} token={:?} amount={:?} timeout_height={:?} timeout_timestamp={} memo_len={}",
            msg.source_port,
            msg.source_channel,
            msg.receiver,
            sender,
            token_info.denom.as_str(),
            token.amount,
            timeout_height
                .as_ref()
                .map(|height| format!("{}-{}", height.revision_number, height.revision_height)),
            msg.timeout_timestamp,
            msg.memo.len(),
        );

        let gateway_msg = super::generated::ibc::core::channel::v1::MsgTransfer {
            source_port: msg.source_port,
            source_channel: msg.source_channel.clone(),
            token: Some(token),
            sender: sender.clone(),
            receiver: msg.receiver,
            timeout_height,
            timeout_timestamp: msg.timeout_timestamp,
            memo: msg.memo,
            signer: sender,
        };

        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(gateway_msg);

        let response = client.transfer(request).await?.into_inner();

        let unsigned_tx_any = response
            .unsigned_tx
            .ok_or_else(|| Error::Transaction("No unsigned_tx in Transfer response".to_string()))?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "Transfer: received unsigned CBOR (length: {}), source_channel: {}",
            cbor_hex.len(),
            msg.source_channel
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!("MsgTransfer (channel: {})", msg.source_channel),
        })
    }

    async fn build_timeout_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::channel::v1::MsgTimeout;
        use prost::Message;

        let msg = MsgTimeout::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgTimeout: {}", e)))?;

        let sequence = msg
            .packet
            .as_ref()
            .ok_or_else(|| Error::Transaction("MsgTimeout missing packet".to_string()))?
            .sequence;

        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.timeout(request).await?.into_inner();

        let unsigned_tx_any = response
            .unsigned_tx
            .ok_or_else(|| Error::Transaction("No unsigned_tx in Timeout response".to_string()))?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "Timeout: received unsigned CBOR (length: {}), sequence: {}",
            cbor_hex.len(),
            sequence
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!("MsgTimeout (sequence: {})", sequence),
        })
    }

    async fn build_timeout_on_close_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use super::generated::ibc::core::channel::v1::MsgTimeoutOnClose;
        use prost::Message;

        let msg = MsgTimeoutOnClose::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgTimeoutOnClose: {}", e))
        })?;

        let sequence = msg
            .packet
            .as_ref()
            .ok_or_else(|| Error::Transaction("MsgTimeoutOnClose missing packet".to_string()))?
            .sequence;

        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);

        let response = client.timeout_on_close(request).await?.into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in TimeoutOnClose response".to_string())
        })?;

        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "TimeoutOnClose: received unsigned CBOR (length: {}), sequence: {}",
            cbor_hex.len(),
            sequence
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!("MsgTimeoutOnClose (sequence: {})", sequence),
        })
    }

    async fn build_prune_packet_history_tx(
        &self,
        message_data: Vec<u8>,
    ) -> Result<UnsignedTx, Error> {
        use prost::Message;

        let msg = MsgPrunePacketHistory::decode(&message_data[..]).map_err(|e| {
            Error::Transaction(format!("Failed to decode MsgPrunePacketHistory: {}", e))
        })?;
        let port_id = msg.port_id.clone();
        let channel_id = msg.channel_id.clone();
        let sequence = msg.sequence;

        let mut client = CardanoMsgClient::new(self.channel.clone());
        let response = client
            .prune_packet_history(tonic::Request::new(msg))
            .await?
            .into_inner();

        let unsigned_tx_any = response.unsigned_tx.ok_or_else(|| {
            Error::Transaction("No unsigned_tx in PrunePacketHistory response".to_string())
        })?;
        let cbor_hex = String::from_utf8(unsigned_tx_any.value)
            .map_err(|e| Error::Transaction(format!("Invalid UTF-8 in unsigned_tx: {}", e)))?;

        tracing::info!(
            "PrunePacketHistory: received unsigned CBOR (length: {}), port_id: {}, channel_id: {}, sequence: {}",
            cbor_hex.len(),
            port_id,
            channel_id,
            sequence
        );

        Ok(UnsignedTx {
            cbor_hex,
            description: format!(
                "MsgPrunePacketHistory (port: {}, channel: {}, sequence: {})",
                port_id, channel_id, sequence
            ),
        })
    }

    /// Ask the Gateway to build a HostState heartbeat only if the current
    /// Cardano epoch does not already contain a HostState anchor.
    pub async fn build_host_state_heartbeat(
        &self,
        signer: &str,
    ) -> Result<HostStateHeartbeatBuild, Error> {
        let mut client = CardanoMsgClient::new(self.channel.clone());
        let response: BuildHostStateHeartbeatResponse = client
            .build_host_state_heartbeat(tonic::Request::new(BuildHostStateHeartbeatRequest {
                signer: signer.to_string(),
            }))
            .await?
            .into_inner();

        let unsigned_tx = response
            .unsigned_tx
            .map(|tx| {
                String::from_utf8(tx.value)
                    .map(|cbor_hex| UnsignedTx {
                        cbor_hex,
                        description: format!(
                            "HostState heartbeat for Cardano epoch {}",
                            response.current_epoch
                        ),
                    })
                    .map_err(|e| {
                        Error::Transaction(format!(
                            "Invalid UTF-8 in HostState heartbeat unsigned_tx: {e}"
                        ))
                    })
            })
            .transpose()?;

        Ok(HostStateHeartbeatBuild {
            heartbeat_required: response.heartbeat_required,
            current_epoch: response.current_epoch,
            host_state_epoch: response.host_state_epoch,
            unsigned_tx,
        })
    }

    /// Submit a signed transaction to the Cardano blockchain via Gateway
    #[deprecated(
        note = "Hermes must submit exact signed bytes through trusted Ogmios, then call observe_tx"
    )]
    pub async fn submit_signed_tx(&self, signed_tx_cbor: &str) -> Result<TxSubmitResponse, Error> {
        tracing::info!(
            "Submitting signed transaction (CBOR length: {})",
            signed_tx_cbor.len()
        );

        let mut client = CardanoMsgClient::new(self.channel.clone());

        let request = tonic::Request::new(SubmitSignedTxRequest {
            signed_tx_cbor: signed_tx_cbor.to_string(),
            description: "Hermes IBC transaction".to_string(),
        });

        let response: SubmitSignedTxResponse = client.submit_signed_tx(request).await?.into_inner();

        let height = parse_submit_signed_tx_height(&response.height)?;

        // Convert proto events to IbcEvent
        let events = response
            .events
            .into_iter()
            .map(|e| IbcEvent {
                event_type: e.r#type,
                attributes: e.attributes.into_iter().map(|a| (a.key, a.value)).collect(),
            })
            .collect();

        Ok(TxSubmitResponse {
            tx_hash: response.tx_hash,
            height,
            events,
        })
    }

    /// Wait for a transaction submitted through Hermes's trusted node path and
    /// finalize the matching pending Gateway state update by body hash only.
    pub async fn observe_tx(&self, tx_hash: &str) -> Result<TxSubmitResponse, Error> {
        let mut client = CardanoMsgClient::new(self.channel.clone());
        let response: ObserveTxResponse = client
            .observe_tx(tonic::Request::new(ObserveTxRequest {
                tx_hash: tx_hash.to_string(),
            }))
            .await?
            .into_inner();

        let height = parse_submit_signed_tx_height(&response.height)?;
        let events = response
            .events
            .into_iter()
            .map(|event| IbcEvent {
                event_type: event.r#type,
                attributes: event
                    .attributes
                    .into_iter()
                    .map(|attribute| (attribute.key, attribute.value))
                    .collect(),
            })
            .collect();

        Ok(TxSubmitResponse {
            tx_hash: response.tx_hash,
            height,
            events,
        })
    }

    /// Get the Gateway endpoint URL
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Fetch a Mithril certificate for a specific chain point
    ///
    /// This should query the Gateway's Mithril aggregator endpoint to get:
    /// 1. The latest Mithril certificate covering the requested slot/epoch
    /// 2. The certificate chain back to genesis (if needed)
    /// 3. The multi-signature proof
    ///
    /// The certificate is used by the light client to verify Cardano block headers
    /// without needing to sync the full chain.
    ///
    /// TODO: Add custom proto for Mithril certificate query
    /// TODO: Implement certificate chain verification
    /// TODO: Cache certificates to avoid redundant queries
    pub async fn fetch_mithril_certificate(&self, slot: u64, epoch: u64) -> Result<Vec<u8>, Error> {
        tracing::info!(
            "Fetching Mithril certificate for slot={}, epoch={}",
            slot,
            epoch
        );

        // Stub implementation - requires custom Mithril proto
        tracing::warn!(
            "fetch_mithril_certificate: requires custom proto for Mithril aggregator endpoint"
        );
        Ok(vec![])
    }

    /// Query block header at a specific height
    pub async fn query_block_header(&self, _height: Height) -> Result<Vec<u8>, Error> {
        // TODO: Implement block header query
        tracing::warn!("query_block_header: stub implementation");
        Ok(vec![])
    }

    /// Query IBC events since a given height
    /// Returns events grouped by block height
    pub async fn query_events(
        &self,
        since_height: Height,
    ) -> Result<super::generated::ibc::cardano::v1::QueryEventsResponse, Error> {
        use super::generated::ibc::cardano::v1::{query_client::QueryClient, QueryEventsRequest};

        tracing::debug!("Querying events since height: {}", since_height);

        let mut client = QueryClient::new(self.channel.clone());
        let request = tonic::Request::new(QueryEventsRequest {
            since_height: since_height.revision_height(),
        });

        let response = client.events(request).await?.into_inner();

        tracing::debug!(
            "Received {} block events, current height: {}",
            response.events.len(),
            response.current_height
        );

        Ok(response)
    }
}

fn parse_ibc_denom_hash(value: &str) -> Result<[u8; 32], Error> {
    let hash = value.strip_prefix("ibc/").unwrap_or(value);
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::GatewayClient(format!(
            "invalid ICS-20 denomination hash '{value}': expected 64 hexadecimal characters, optionally prefixed by 'ibc/'"
        )));
    }

    let bytes = hex::decode(hash).map_err(|_| {
        Error::GatewayClient(format!(
            "invalid ICS-20 denomination hash '{value}': expected hexadecimal characters"
        ))
    })?;
    bytes.try_into().map_err(|_| {
        Error::GatewayClient(format!(
            "invalid ICS-20 denomination hash '{value}': expected 32 bytes"
        ))
    })
}

fn resolve_gateway_denom(
    denom: GatewayDenom,
    expected_hash: [u8; 32],
) -> Result<ResolvedDenom, Error> {
    if denom.base.is_empty() {
        return Err(Error::GatewayClient(
            "Gateway returned a denomination with an empty base".to_string(),
        ));
    }

    let mut path_segments = Vec::with_capacity(denom.trace.len() * 2);
    for hop in denom.trace {
        if hop.port_id.is_empty()
            || hop.channel_id.is_empty()
            || hop.port_id.contains('/')
            || hop.channel_id.contains('/')
        {
            return Err(Error::GatewayClient(
                "Gateway returned an invalid denomination trace hop".to_string(),
            ));
        }
        path_segments.push(hop.port_id);
        path_segments.push(hop.channel_id);
    }

    let resolved = ResolvedDenom {
        path: path_segments.join("/"),
        base_denom: denom.base,
    };
    let full_denom = resolved.full_denom();
    let actual_hash: [u8; 32] = Sha256::digest(full_denom.as_bytes()).into();
    if actual_hash != expected_hash {
        return Err(Error::GatewayClient(format!(
            "Gateway denomination response does not match requested ICS-20 hash {}",
            hex::encode_upper(expected_hash)
        )));
    }

    Ok(resolved)
}

fn read_gateway_file(path: &Path, description: &str) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|error| {
        Error::GatewayClient(format!(
            "failed to read Gateway {description} file {}: {error}",
            path.display()
        ))
    })
}

fn read_gateway_auth_token(path: &Path) -> Result<AsciiMetadataValue, Error> {
    let bytes = read_gateway_file(path, "authentication token")?;
    let token = std::str::from_utf8(&bytes).map_err(|error| {
        Error::GatewayClient(format!(
            "Gateway authentication token file {} is not valid UTF-8: {error}",
            path.display()
        ))
    })?;
    authorization_metadata(token)
}

fn authorization_metadata(token: &str) -> Result<AsciiMetadataValue, Error> {
    let token = token.trim();
    if token.is_empty() {
        return Err(Error::GatewayClient(
            "Gateway authentication token must not be empty".to_string(),
        ));
    }

    let mut authorization = format!("Bearer {token}")
        .parse::<AsciiMetadataValue>()
        .map_err(|_| {
            Error::GatewayClient(
                "Gateway authentication token contains characters that are invalid in gRPC metadata"
                    .to_string(),
            )
        })?;
    authorization.set_sensitive(true);
    Ok(authorization)
}

fn validate_gateway_endpoint(uri: &Uri) -> Result<bool, Error> {
    match uri.scheme_str() {
        Some("https") => Ok(true),
        Some("http") => {
            let host = uri.host().ok_or_else(|| {
                Error::GatewayClient("Gateway endpoint must include a host".to_string())
            })?;

            if is_loopback_host(host) {
                Ok(false)
            } else {
                Err(Error::GatewayClient(format!(
                    "refusing plaintext gRPC connection to non-loopback Gateway host '{host}'; use an https:// endpoint"
                )))
            }
        }
        Some(scheme) => Err(Error::GatewayClient(format!(
            "unsupported Gateway endpoint scheme '{scheme}'; use https://, or http:// for loopback only"
        ))),
        None => Err(Error::GatewayClient(
            "Gateway endpoint must include an https:// scheme, or http:// for loopback only"
                .to_string(),
        )),
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    matches!(host.parse::<IpAddr>(), Ok(address) if address.is_loopback())
}

fn parse_submit_signed_tx_height(raw_height: &str) -> Result<Option<Height>, Error> {
    if raw_height.is_empty() {
        return Ok(None);
    }

    let (revision_number, revision_height) = raw_height
        .split_once('-')
        .ok_or_else(|| invalid_submit_signed_tx_height(raw_height))?;

    let revision_number = revision_number
        .parse::<u64>()
        .map_err(|_| invalid_submit_signed_tx_height(raw_height))?;
    let revision_height = revision_height
        .parse::<u64>()
        .map_err(|_| invalid_submit_signed_tx_height(raw_height))?;

    Height::new(revision_number, revision_height)
        .map(Some)
        .map_err(|_| invalid_submit_signed_tx_height(raw_height))
}

fn invalid_submit_signed_tx_height(raw_height: &str) -> Error {
    Error::GatewayClient(format!(
        "Gateway returned invalid height string: {}",
        raw_height
    ))
}

/// Convert canonical ICS-20 transfer token data into the Gateway's Cardano transfer token.
///
/// Canonical ICS-20 encodes amounts as decimal strings and Hermes models them as `U256`.
/// The Cardano Gateway transfer protobuf represents voucher quantities as Cardano native
/// asset quantities, which are bounded to `u64`. Validate that protocol constraint before
/// asking the Gateway to build a transfer transaction or create the packet.
fn cardano_transfer_token_from_canonical(
    coin: &ibc_proto::cosmos::base::v1beta1::Coin,
) -> Result<super::generated::ibc::core::channel::v1::Coin, Error> {
    let amount = parse_cardano_native_asset_quantity(&coin.amount, &coin.denom)?;

    Ok(super::generated::ibc::core::channel::v1::Coin {
        denom: coin.denom.clone(),
        amount,
    })
}

fn parse_cardano_native_asset_quantity(amount: &str, denom: &str) -> Result<u64, Error> {
    if amount.is_empty() || !amount.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Transaction(format!(
            "Invalid Cardano MsgTransfer amount '{}' for denom '{}': expected an unsigned base-10 integer string within the Cardano native asset quantity range 0..={} (u64)",
            amount, denom, CARDANO_NATIVE_ASSET_MAX_QUANTITY
        )));
    }

    amount.parse::<u64>().map_err(|_| {
        Error::Transaction(format!(
            "Invalid Cardano MsgTransfer amount '{}' for denom '{}': exceeds the Cardano native asset quantity range 0..={} (u64). Canonical ICS-20 amounts may be larger, but Cardano ICS-20 vouchers are limited to this range",
            amount, denom, CARDANO_NATIVE_ASSET_MAX_QUANTITY
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibc_proto::cosmos::base::v1beta1::Coin as ProtoCoin;
    use ibc_proto::ibc::core::client::v1::MsgRecoverClient as CanonicalMsgRecoverClient;
    use prost::Message;

    fn gateway_uri(value: &str) -> Uri {
        value.parse().expect("valid test URI")
    }

    fn denom_hash(full_denom: &str) -> [u8; 32] {
        Sha256::digest(full_denom.as_bytes()).into()
    }

    #[test]
    fn gateway_recover_client_request_matches_canonical_wire_format() {
        let canonical = CanonicalMsgRecoverClient {
            subject_client_id: "07-tendermint-0".to_string(),
            substitute_client_id: "07-tendermint-1".to_string(),
            signer: "addr_test1_recovery_authority".to_string(),
        };

        let decoded = super::super::generated::ibc::core::client::v1::MsgRecoverClient::decode(
            canonical.encode_to_vec().as_slice(),
        )
        .unwrap();

        assert_eq!(decoded.subject_client_id, canonical.subject_client_id);
        assert_eq!(decoded.substitute_client_id, canonical.substitute_client_id);
        assert_eq!(decoded.signer, canonical.signer);
    }

    #[test]
    fn gateway_denom_is_bound_to_requested_sha256_hash() {
        let full_denom = "transfer/channel-7/uatom";
        let resolved = resolve_gateway_denom(
            GatewayDenom {
                base: "uatom".to_string(),
                trace: vec![GatewayDenomHop {
                    port_id: "transfer".to_string(),
                    channel_id: "channel-7".to_string(),
                }],
            },
            denom_hash(full_denom),
        )
        .unwrap();

        assert_eq!(resolved.path, "transfer/channel-7");
        assert_eq!(resolved.base_denom, "uatom");
        assert_eq!(resolved.full_denom(), full_denom);
    }

    #[test]
    fn gateway_denom_rejects_a_response_for_another_hash() {
        let error = resolve_gateway_denom(
            GatewayDenom {
                base: "uosmo".to_string(),
                trace: vec![GatewayDenomHop {
                    port_id: "transfer".to_string(),
                    channel_id: "channel-7".to_string(),
                }],
            },
            denom_hash("transfer/channel-7/uatom"),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("does not match requested ICS-20 hash"));
    }

    #[test]
    fn gateway_denom_hash_accepts_raw_and_prefixed_hex_only() {
        let hash = "AB".repeat(32);
        assert_eq!(
            parse_ibc_denom_hash(&hash).unwrap(),
            parse_ibc_denom_hash(&format!("ibc/{hash}")).unwrap()
        );

        let non_hex = "gg".repeat(32);
        for malformed in ["ibc/1234", "xyz", non_hex.as_str()] {
            assert!(parse_ibc_denom_hash(malformed).is_err());
        }
    }

    #[test]
    fn plaintext_gateway_is_limited_to_loopback_hosts() {
        for endpoint in [
            "http://localhost:5001",
            "http://LOCALHOST.:5001",
            "http://127.0.0.1:5001",
            "http://127.42.0.9:5001",
            "http://[::1]:5001",
        ] {
            assert!(
                !validate_gateway_endpoint(&gateway_uri(endpoint)).unwrap(),
                "{endpoint} should be accepted as loopback plaintext"
            );
        }
    }

    #[test]
    fn plaintext_gateway_rejects_non_loopback_hosts() {
        for endpoint in [
            "http://gateway:5001",
            "http://0.0.0.0:5001",
            "http://192.168.1.2:5001",
            "http://10.0.0.2:5001",
            "http://localhost.example:5001",
        ] {
            let error = validate_gateway_endpoint(&gateway_uri(endpoint)).unwrap_err();
            assert!(
                error.to_string().contains("refusing plaintext"),
                "unexpected error for {endpoint}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn gateway_client_rejects_remote_plaintext_before_connecting() {
        let error = GatewayClient::new("http://gateway.example:5001".to_string())
            .await
            .err()
            .expect("remote plaintext must fail");

        assert!(error.to_string().contains("refusing plaintext"));
    }

    #[tokio::test]
    async fn gateway_client_rejects_tls_ca_for_plaintext() {
        let error = GatewayClient::new_with_security(
            "http://localhost:5001".to_string(),
            Some(PathBuf::from("/does/not/need/to/exist.pem")),
            None,
        )
        .await
        .err()
        .expect("TLS CA with plaintext must fail");

        assert!(error
            .to_string()
            .contains("gateway_tls_ca_file requires an https://"));
    }

    #[test]
    fn secure_gateway_requires_https_scheme() {
        assert!(validate_gateway_endpoint(&gateway_uri("https://gateway.example:5001")).unwrap());

        for endpoint in ["ftp://gateway.example:5001", "gateway.example:5001"] {
            let error = validate_gateway_endpoint(&gateway_uri(endpoint)).unwrap_err();
            assert!(
                error.to_string().contains("Gateway endpoint"),
                "unexpected error for {endpoint}: {error}"
            );
        }
    }

    #[test]
    fn gateway_auth_interceptor_adds_sensitive_bearer_metadata() {
        let authorization = authorization_metadata("  test-secret\n").unwrap();
        assert_eq!(authorization, "Bearer test-secret");
        assert!(authorization.is_sensitive());

        let mut interceptor = GatewayAuthInterceptor {
            authorization: Some(authorization),
        };
        let request = interceptor.call(Request::new(())).unwrap();
        let actual = request
            .metadata()
            .get("authorization")
            .expect("authorization metadata");
        assert_eq!(actual, "Bearer test-secret");
        assert!(actual.is_sensitive());
    }

    #[test]
    fn gateway_auth_interceptor_is_optional_and_rejects_invalid_tokens() {
        let mut interceptor = GatewayAuthInterceptor {
            authorization: None,
        };
        let request = interceptor.call(Request::new(())).unwrap();
        assert!(request.metadata().get("authorization").is_none());

        assert!(authorization_metadata(" \n\t").is_err());
        let error = authorization_metadata("token\nwith-newline").unwrap_err();
        assert!(error.to_string().contains("invalid in gRPC metadata"));
        assert!(!error.to_string().contains("token\nwith-newline"));
    }

    fn transfer_coin(amount: &str) -> ProtoCoin {
        ProtoCoin {
            denom: "lovelace".to_string(),
            amount: amount.to_string(),
        }
    }

    #[test]
    fn cardano_transfer_amount_accepts_u64_max() {
        let coin = transfer_coin(&u64::MAX.to_string());

        let gateway_coin = cardano_transfer_token_from_canonical(&coin).unwrap();

        assert_eq!(gateway_coin.denom, "lovelace");
        assert_eq!(gateway_coin.amount, u64::MAX);
    }

    #[test]
    fn cardano_transfer_amount_rejects_u64_overflow() {
        let coin = transfer_coin("18446744073709551616");

        let err = cardano_transfer_token_from_canonical(&coin).unwrap_err();

        match err {
            Error::Transaction(msg) => {
                assert!(msg.contains("exceeds the Cardano native asset quantity range"));
                assert!(msg.contains("u64"));
                assert!(msg.contains("18446744073709551616"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn request_with_query_height_sets_cosmos_block_height_metadata() {
        // Gateway query methods route requested heights through Cosmos-compatible
        // metadata; packet proof tests rely on this height being sent unchanged.
        let request = GatewayClient::request_with_query_height(
            (),
            Some(Height::new(0, 42).expect("valid height")),
        )
        .expect("request with query height");

        assert_eq!(
            request
                .metadata()
                .get("x-cosmos-block-height")
                .expect("height metadata"),
            "42"
        );
    }

    #[test]
    fn cardano_transfer_amount_rejects_non_integer_string() {
        let coin = transfer_coin("1.5");

        let err = cardano_transfer_token_from_canonical(&coin).unwrap_err();

        match err {
            Error::Transaction(msg) => {
                assert!(msg.contains("expected an unsigned base-10 integer string"));
                assert!(msg.contains("1.5"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn submit_signed_tx_height_accepts_empty_height() {
        assert_eq!(parse_submit_signed_tx_height("").unwrap(), None);
    }

    #[test]
    fn submit_signed_tx_height_accepts_valid_revision_height() {
        assert_eq!(
            parse_submit_signed_tx_height("0-123").unwrap(),
            Some(Height::new(0, 123).unwrap())
        );
    }

    #[test]
    fn submit_signed_tx_height_rejects_malformed_height() {
        for raw_height in ["123", "0-not-a-height", "0-0", "0-1-2"] {
            let err = parse_submit_signed_tx_height(raw_height).unwrap_err();

            match err {
                Error::GatewayClient(msg) => {
                    assert!(msg.contains("Gateway returned invalid height string"));
                    assert!(msg.contains(raw_height));
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }
}
