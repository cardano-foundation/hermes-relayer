//! gRPC client for Cardano Gateway
//!
//! This module provides a client for interacting with the Cardano Gateway service,
//! which handles Cardano blockchain queries, transaction building, and submission.

use super::error::Error;
use super::generated::ibc::cardano::v1::{cardano_msg_client::CardanoMsgClient, SubmitSignedTxRequest, SubmitSignedTxResponse};
use super::generated::ibc::core::client::v1::msg_client::MsgClient as GenClientMsgClient;
use super::generated::ibc::core::connection::v1::msg_client::MsgClient as GenConnectionMsgClient;
use super::generated::ibc::core::channel::v1::msg_client::MsgClient as GenChannelMsgClient;
use super::types::{CardanoClientState, CardanoConsensusState};
use ibc_proto::ibc::core::client::v1::query_client::QueryClient as ClientQueryClient;
use ibc_proto::ibc::core::client::v1::{QueryClientStateRequest, QueryConsensusStateRequest};
use ibc_proto::ibc::core::connection::v1::query_client::QueryClient as ConnectionQueryClient;
use ibc_proto::ibc::core::connection::v1::{QueryConnectionRequest, QueryConnectionsRequest};
use ibc_proto::ibc::core::channel::v1::query_client::QueryClient as ChannelQueryClient;
use ibc_proto::ibc::core::channel::v1::{QueryChannelRequest, QueryChannelsRequest, QueryPacketCommitmentRequest};
use ibc_relayer_types::clients::ics08_cardano::CardanoHeader;
use ibc_relayer_types::Height;
use tonic::transport::Channel;

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

/// Simplified IBC event structure for Gateway responses
#[derive(Debug, Clone)]
pub struct IbcEvent {
    pub event_type: String,
    pub attributes: Vec<(String, String)>,
}

/// Client for communicating with Cardano Gateway
#[derive(Clone)]
pub struct GatewayClient {
    endpoint: String,
    channel: Channel,
}

impl GatewayClient {
    /// Create a new Gateway client and establish a gRPC connection
    pub async fn new(endpoint: String) -> Result<Self, Error> {
        tracing::info!("Connecting to Cardano Gateway at {}", endpoint);
        
        let channel = Channel::from_shared(endpoint.clone())
            .map_err(|e| Error::GatewayClient(e.to_string()))?
            .connect()
            .await?;
        
        Ok(Self { endpoint, channel })
    }

    /// Query the latest block height from the Gateway
    /// This uses a stub implementation for now - real implementation would query
    /// the Gateway's custom LatestHeight endpoint
    pub async fn query_latest_height(&self) -> Result<Height, Error> {
        // TODO: Implement custom Query.LatestHeight gRPC call
        // The Gateway exposes this as a custom endpoint not in standard ibc-proto
        tracing::warn!("query_latest_height: using stub implementation - needs custom proto generation");
        Ok(Height::new(0, 1000).map_err(|e| Error::Query(e.to_string()))?)
    }

    /// Query client state for a specific client ID
    pub async fn query_client_state(&self, client_id: &str) -> Result<CardanoClientState, Error> {
        let mut client = ClientQueryClient::new(self.channel.clone());
        
        let request = tonic::Request::new(QueryClientStateRequest {
            client_id: client_id.to_string(),
        });
        
        let response = client.client_state(request)
            .await?
            .into_inner();
        
        // TODO: Parse the Any proto message and deserialize into CardanoClientState
        // For now, return a stub
        tracing::warn!("query_client_state: proto parsing not yet implemented");
        
        Ok(CardanoClientState::new(
            client_id.to_string(),
            Height::new(0, 1000).map_err(|e| Error::Query(e.to_string()))?,
            86400,
            1814400,
            vec![0u8; 32],
        ))
    }

    /// Query consensus state for a specific client ID and height
    pub async fn query_consensus_state(
        &self,
        client_id: &str,
        height: Height,
    ) -> Result<CardanoConsensusState, Error> {
        let mut client = ClientQueryClient::new(self.channel.clone());
        
        let request = tonic::Request::new(QueryConsensusStateRequest {
            client_id: client_id.to_string(),
            revision_number: height.revision_number(),
            revision_height: height.revision_height(),
            latest_height: false,
        });
        
        let response = client.consensus_state(request)
            .await?
            .into_inner();
        
        // TODO: Parse the Any proto message and deserialize into CardanoConsensusState
        // For now, return a stub with the queried height
        tracing::warn!("query_consensus_state: proto parsing not yet implemented");
        
        Ok(CardanoConsensusState::new(
            vec![0u8; 32],  // placeholder root
            0,  // timestamp - TODO: extract from proto
            0,  // slot - TODO: extract from proto
            0,  // epoch - TODO: extract from proto
        ))
    }

    /// Query header at a specific height
    /// 
    /// TODO: This requires generating custom proto for Gateway's QueryBlockData endpoint
    /// which is not in standard ibc-proto. For now, this returns stub data.
    /// 
    /// To implement fully:
    /// 1. Add ibc/core/client/v1/query.proto (with QueryBlockData) to build.rs
    /// 2. Generate the proto code
    /// 3. Call client.block_data(QueryBlockDataRequest { height })
    /// 4. Parse the BlockData proto to extract block_hash, timestamp, slot, epoch
    pub async fn query_header(&self, height: Height) -> Result<CardanoHeader, Error> {
        tracing::warn!("query_header: requires custom proto generation for Gateway's BlockData endpoint");
        
        // Stub implementation - returns header with correct height but placeholder data
        Ok(CardanoHeader::new(
            height,
            vec![0u8; 32],  // placeholder block hash
            0,  // timestamp - TODO: extract from BlockData
            0,  // slot - TODO: extract from BlockData
            0,  // epoch - TODO: extract from BlockData
        ))
    }

    /// Query connection state
    pub async fn query_connection(&self, connection_id: &str) -> Result<Vec<u8>, Error> {
        let mut client = ConnectionQueryClient::new(self.channel.clone());
        
        let request = tonic::Request::new(QueryConnectionRequest {
            connection_id: connection_id.to_string(),
        });
        
        let response = client.connection(request)
            .await?
            .into_inner();
        
        // Return serialized connection
        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query all connections
    pub async fn query_connections(&self) -> Result<Vec<u8>, Error> {
        let mut client = ConnectionQueryClient::new(self.channel.clone());
        
        let request = tonic::Request::new(QueryConnectionsRequest {
            pagination: None,
        });
        
        let response = client.connections(request)
            .await?
            .into_inner();
        
        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query channel state
    pub async fn query_channel(&self, port_id: &str, channel_id: &str) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());
        
        let request = tonic::Request::new(QueryChannelRequest {
            port_id: port_id.to_string(),
            channel_id: channel_id.to_string(),
        });
        
        let response = client.channel(request)
            .await?
            .into_inner();
        
        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query all channels
    pub async fn query_channels(&self) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());
        
        let request = tonic::Request::new(QueryChannelsRequest {
            pagination: None,
        });
        
        let response = client.channels(request)
            .await?
            .into_inner();
        
        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Query packet commitment
    pub async fn query_packet_commitment(
        &self,
        port_id: &str,
        channel_id: &str,
        sequence: u64,
    ) -> Result<Vec<u8>, Error> {
        let mut client = ChannelQueryClient::new(self.channel.clone());
        
        let request = tonic::Request::new(QueryPacketCommitmentRequest {
            port_id: port_id.to_string(),
            channel_id: channel_id.to_string(),
            sequence,
        });
        
        let response = client.packet_commitment(request)
            .await?
            .into_inner();
        
        Ok(prost::Message::encode_to_vec(&response))
    }

    /// Build unsigned transaction for IBC message via Gateway
    /// Gateway returns CBOR hex that Hermes will sign
    /// 
    /// This method routes IBC messages to the appropriate Gateway Msg service:
    /// - Client messages: CreateClient, UpdateClient
    /// - Connection messages: ConnectionOpenInit/Try/Ack/Confirm
    /// - Channel messages: ChannelOpenInit/Try/Ack/Confirm
    /// - Packet messages: RecvPacket, Acknowledgement, Timeout
    /// 
    /// The Gateway Msg services are now available via generated gRPC clients:
    /// - `GenClientMsgClient` for client operations
    /// - `GenConnectionMsgClient` for connection operations
    /// - `GenChannelMsgClient` for channel and packet operations
    /// 
    /// TODO: Implement message type routing based on message_type string
    /// TODO: Deserialize message_data into appropriate proto message
    /// TODO: Call the corresponding Msg service method
    /// TODO: Extract unsigned CBOR from response
    pub async fn build_ibc_tx(&self, message_type: &str, _message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        tracing::info!("Building unsigned transaction for message type: {}", message_type);
        
        // Create Msg service clients (now available from generated protos)
        let _client_msg_client = GenClientMsgClient::new(self.channel.clone());
        let _connection_msg_client = GenConnectionMsgClient::new(self.channel.clone());
        let _channel_msg_client = GenChannelMsgClient::new(self.channel.clone());
        
        // TODO: Route to appropriate service based on message_type
        // Example routing:
        // match message_type {
        //     "MsgCreateClient" => client_msg_client.create_client(...),
        //     "MsgUpdateClient" => client_msg_client.update_client(...),
        //     "MsgConnectionOpenInit" => connection_msg_client.connection_open_init(...),
        //     "MsgChannelOpenInit" => channel_msg_client.channel_open_init(...),
        //     "MsgRecvPacket" => channel_msg_client.recv_packet(...),
        //     _ => return Err(Error::Transaction(format!("Unknown message type: {}", message_type))),
        // }
        
        tracing::warn!("build_ibc_tx: message routing not yet implemented");
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: format!("Unsigned {} transaction", message_type),
        })
    }

    /// Submit a signed transaction to the Cardano blockchain via Gateway
    pub async fn submit_signed_tx(&self, signed_tx_cbor: &str) -> Result<TxSubmitResponse, Error> {
        tracing::info!("Submitting signed transaction (CBOR length: {})", signed_tx_cbor.len());
        
        let mut client = CardanoMsgClient::new(self.channel.clone());
        
        let request = tonic::Request::new(SubmitSignedTxRequest {
            signed_tx_cbor: signed_tx_cbor.to_string(),
            description: "Hermes IBC transaction".to_string(),
        });
        
        let response: SubmitSignedTxResponse = client.submit_signed_tx(request)
            .await?
            .into_inner();
        
        // Parse height if present
        let height = if !response.height.is_empty() {
            let parts: Vec<&str> = response.height.split('-').collect();
            if parts.len() == 2 {
                let revision_number: u64 = parts[0].parse().unwrap_or(0);
                let revision_height: u64 = parts[1].parse().unwrap_or(0);
                Height::new(revision_number, revision_height).ok()
            } else {
                None
            }
        } else {
            None
        };
        
        // Convert proto events to IbcEvent
        let events = response.events.into_iter().map(|e| IbcEvent {
            event_type: e.r#type,
            attributes: e.attributes.into_iter().map(|a| (a.key, a.value)).collect(),
        }).collect();
        
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
        tracing::info!("Fetching Mithril certificate for slot={}, epoch={}", slot, epoch);
        
        // Stub implementation - requires custom Mithril proto
        tracing::warn!("fetch_mithril_certificate: requires custom proto for Mithril aggregator endpoint");
        Ok(vec![])
    }

    /// Query block header at a specific height
    pub async fn query_block_header(&self, _height: Height) -> Result<Vec<u8>, Error> {
        // TODO: Implement block header query
        tracing::warn!("query_block_header: stub implementation");
        Ok(vec![])
    }
}
