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
    /// This method routes IBC messages to the appropriate Gateway Msg service based on the type_url.
    /// The type_url format is: "/ibc.core.{module}.v1.Msg{Operation}"
    pub async fn build_ibc_tx(&self, type_url: &str, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        tracing::info!("Building unsigned transaction for message type: {}", type_url);
        
        // Route based on type_url
        match type_url {
            // IBC Client messages
            "/ibc.core.client.v1.MsgCreateClient" => {
                self.build_create_client_tx(message_data).await
            }
            "/ibc.core.client.v1.MsgUpdateClient" => {
                self.build_update_client_tx(message_data).await
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
            
            // IBC Packet messages
            "/ibc.core.channel.v1.MsgRecvPacket" => {
                self.build_recv_packet_tx(message_data).await
            }
            "/ibc.core.channel.v1.MsgAcknowledgement" => {
                self.build_acknowledgement_tx(message_data).await
            }
            "/ibc.core.channel.v1.MsgTimeout" => {
                self.build_timeout_tx(message_data).await
            }
            
            // Unknown message type
            _ => {
                tracing::error!("Unsupported message type: {}", type_url);
                Err(Error::Transaction(format!("Unsupported message type: {}", type_url)))
            }
        }
    }

    //
    // Helper methods for building each message type
    //

    async fn build_create_client_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::client::v1::MsgCreateClient;
        
        let msg = MsgCreateClient::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgCreateClient: {}", e)))?;
        
        let mut client = GenClientMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.create_client(request).await?;
        
        // TODO: Extract unsigned CBOR from response
        // The Gateway needs to return the unsigned transaction in the response
        tracing::warn!("CreateClient response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgCreateClient transaction".to_string(),
        })
    }

    async fn build_update_client_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::client::v1::MsgUpdateClient;
        
        let msg = MsgUpdateClient::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgUpdateClient: {}", e)))?;
        
        let mut client = GenClientMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.update_client(request).await?;
        
        tracing::warn!("UpdateClient response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgUpdateClient transaction".to_string(),
        })
    }

    async fn build_connection_open_init_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::connection::v1::MsgConnectionOpenInit;
        
        let msg = MsgConnectionOpenInit::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgConnectionOpenInit: {}", e)))?;
        
        let mut client = GenConnectionMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.connection_open_init(request).await?;
        
        tracing::warn!("ConnectionOpenInit response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgConnectionOpenInit transaction".to_string(),
        })
    }

    async fn build_connection_open_try_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::connection::v1::MsgConnectionOpenTry;
        
        let msg = MsgConnectionOpenTry::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgConnectionOpenTry: {}", e)))?;
        
        let mut client = GenConnectionMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.connection_open_try(request).await?;
        
        tracing::warn!("ConnectionOpenTry response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgConnectionOpenTry transaction".to_string(),
        })
    }

    async fn build_connection_open_ack_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::connection::v1::MsgConnectionOpenAck;
        
        let msg = MsgConnectionOpenAck::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgConnectionOpenAck: {}", e)))?;
        
        let mut client = GenConnectionMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.connection_open_ack(request).await?;
        
        tracing::warn!("ConnectionOpenAck response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgConnectionOpenAck transaction".to_string(),
        })
    }

    async fn build_connection_open_confirm_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::connection::v1::MsgConnectionOpenConfirm;
        
        let msg = MsgConnectionOpenConfirm::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgConnectionOpenConfirm: {}", e)))?;
        
        let mut client = GenConnectionMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.connection_open_confirm(request).await?;
        
        tracing::warn!("ConnectionOpenConfirm response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgConnectionOpenConfirm transaction".to_string(),
        })
    }

    async fn build_channel_open_init_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::channel::v1::MsgChannelOpenInit;
        
        let msg = MsgChannelOpenInit::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgChannelOpenInit: {}", e)))?;
        
        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.channel_open_init(request).await?;
        
        tracing::warn!("ChannelOpenInit response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgChannelOpenInit transaction".to_string(),
        })
    }

    async fn build_channel_open_try_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::channel::v1::MsgChannelOpenTry;
        
        let msg = MsgChannelOpenTry::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgChannelOpenTry: {}", e)))?;
        
        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.channel_open_try(request).await?;
        
        tracing::warn!("ChannelOpenTry response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgChannelOpenTry transaction".to_string(),
        })
    }

    async fn build_channel_open_ack_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::channel::v1::MsgChannelOpenAck;
        
        let msg = MsgChannelOpenAck::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgChannelOpenAck: {}", e)))?;
        
        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.channel_open_ack(request).await?;
        
        tracing::warn!("ChannelOpenAck response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgChannelOpenAck transaction".to_string(),
        })
    }

    async fn build_channel_open_confirm_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::channel::v1::MsgChannelOpenConfirm;
        
        let msg = MsgChannelOpenConfirm::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgChannelOpenConfirm: {}", e)))?;
        
        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.channel_open_confirm(request).await?;
        
        tracing::warn!("ChannelOpenConfirm response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgChannelOpenConfirm transaction".to_string(),
        })
    }

    async fn build_recv_packet_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::channel::v1::MsgRecvPacket;
        
        let msg = MsgRecvPacket::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgRecvPacket: {}", e)))?;
        
        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.recv_packet(request).await?;
        
        tracing::warn!("RecvPacket response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgRecvPacket transaction".to_string(),
        })
    }

    async fn build_acknowledgement_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::channel::v1::MsgAcknowledgement;
        
        let msg = MsgAcknowledgement::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgAcknowledgement: {}", e)))?;
        
        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.acknowledgement(request).await?;
        
        tracing::warn!("Acknowledgement response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgAcknowledgement transaction".to_string(),
        })
    }

    async fn build_timeout_tx(&self, message_data: Vec<u8>) -> Result<UnsignedTx, Error> {
        use prost::Message;
        use super::generated::ibc::core::channel::v1::MsgTimeout;
        
        let msg = MsgTimeout::decode(&message_data[..])
            .map_err(|e| Error::Transaction(format!("Failed to decode MsgTimeout: {}", e)))?;
        
        let mut client = GenChannelMsgClient::new(self.channel.clone());
        let request = tonic::Request::new(msg);
        
        let response = client.timeout(request).await?;
        
        tracing::warn!("Timeout response received, but CBOR extraction not yet implemented");
        
        Ok(UnsignedTx {
            cbor_hex: "00".to_string(),
            description: "MsgTimeout transaction".to_string(),
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
