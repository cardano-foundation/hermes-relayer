//! Cardano ChainEndpoint implementation for Hermes
//!
//! This module implements the ChainEndpoint trait required by Hermes for custom chain support.

use super::config::CardanoConfig;
use super::error::Error as CardanoError;
use super::gateway_client::GatewayClient;
use super::keyring::CardanoKeyring;
use super::signer;
use super::signing_key_pair::CardanoSigningKeyPair;
use super::types::{CardanoClientState, CardanoConsensusState};

// Use CardanoHeader from ibc-relayer-types (where AnyHeader is defined)
use ibc_relayer_types::clients::ics08_cardano::CardanoHeader;

use std::sync::Arc;
use crate::account::Balance;
use crate::chain::client::ClientSettings;
use crate::chain::endpoint::{ChainEndpoint, ChainStatus, HealthCheck};
use crate::chain::handle::Subscription;
use crate::chain::requests::{
    CrossChainQueryRequest, IncludeProof, QueryChannelClientStateRequest,
    QueryChannelRequest, QueryChannelsRequest, QueryClientConnectionsRequest, QueryClientStateRequest,
    QueryClientStatesRequest, QueryConnectionChannelsRequest, QueryConnectionRequest, QueryConnectionsRequest,
    QueryConsensusStateHeightsRequest, QueryConsensusStateRequest, QueryHostConsensusStateRequest,
    QueryNextSequenceReceiveRequest, QueryPacketAcknowledgementRequest, QueryPacketAcknowledgementsRequest,
    QueryPacketCommitmentRequest, QueryPacketCommitmentsRequest, QueryPacketEventDataRequest,
    QueryPacketReceiptRequest, QueryTxRequest, QueryUnreceivedAcksRequest, QueryUnreceivedPacketsRequest,
    QueryUpgradedClientStateRequest, QueryUpgradedConsensusStateRequest,
};
use crate::chain::tracking::TrackedMsgs;
use crate::chain::cosmos::version::Specs as CosmosSpecs;
use crate::chain::version::Specs;
use crate::client_state::{AnyClientState, IdentifiedAnyClientState};
use crate::config::{ChainConfig, Error as ConfigError};
use crate::connection::ConnectionMsgType;
use crate::consensus_state::AnyConsensusState;
use crate::denom::DenomTrace;
use crate::error::Error;
use crate::event::IbcEventWithHeight;
use ibc_relayer_types::core::ics02_client::height::Height;
use crate::keyring::{AnySigningKeyPair, KeyRing, SigningKeyPair, SigningKeyPairSized};
use crate::misbehaviour::MisbehaviourEvidence;
use ibc_relayer_types::core::ics02_client::events::UpdateClient;
use ibc_relayer_types::core::ics02_client::header::{AnyHeader, Header};
use ibc_relayer_types::core::ics03_connection::connection::{ConnectionEnd, IdentifiedConnectionEnd};
use ibc_relayer_types::core::ics04_channel::channel::{ChannelEnd, IdentifiedChannelEnd};
use ibc_relayer_types::core::ics04_channel::packet::Sequence;
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentPrefix;
use ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof;
use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};
use ibc_relayer_types::proofs::Proofs;
use ibc_relayer_types::signer::Signer;
use std::str::FromStr;
use ibc_relayer_types::Height as ICSHeight;
use tendermint_rpc::endpoint::broadcast::tx_sync::Response as TxResponse;
use tokio::runtime::Runtime as TokioRuntime;

/// Cardano light block (placeholder)
#[derive(Debug, Clone)]
pub struct CardanoLightBlock {
    pub header: CardanoHeader,
}

// CardanoSigningKeyPair is now defined in signing_key_pair.rs
// From<CardanoSigningKeyPair> for AnySigningKeyPair is implemented in ibc-relayer/src/keyring/any_signing_key_pair.rs

/// Cardano ChainEndpoint implementation
pub struct CardanoChainEndpoint {
    config: CardanoConfig,
    rt: Arc<TokioRuntime>,
    gateway_client: GatewayClient,
    keyring: KeyRing<CardanoSigningKeyPair>,
}

impl CardanoChainEndpoint {
    /// Sign a transaction using the keyring (private helper method)
    fn sign_transaction_helper(&self, unsigned_cbor_hex: &str) -> Result<String, Error> {
        use super::signer;
        
        // Convert hex to bytes
        let unsigned_tx_bytes = hex::decode(unsigned_cbor_hex)
            .map_err(|e| Error::send_tx(format!("Failed to decode unsigned tx hex: {}", e)))?;
        
        // Get signing key from keyring
        let key = self.keyring.get_key(&self.config.key_name)
            .map_err(|e| Error::key_base(e))?;
        
        // Get the CardanoKeyring from the signing key pair
        let cardano_keyring = key.as_any().downcast_ref::<CardanoKeyring>()
            .ok_or_else(|| Error::send_tx("Failed to downcast to CardanoKeyring".to_string()))?;
        
        // Sign the transaction
        let signed_tx_bytes = signer::sign_transaction(&unsigned_tx_bytes, cardano_keyring)
            .map_err(|e| Error::send_tx(format!("Failed to sign transaction: {}", e)))?;
        
        // Convert back to hex
        Ok(hex::encode(signed_tx_bytes))
    }
}

impl ChainEndpoint for CardanoChainEndpoint {
    type LightBlock = CardanoLightBlock;
    type Header = CardanoHeader;
    type ConsensusState = CardanoConsensusState;
    type ClientState = CardanoClientState;
    type Time = i64; // Unix timestamp
    type SigningKeyPair = CardanoSigningKeyPair;

    fn id(&self) -> &ChainId {
        &self.config.id
    }

    fn config(&self) -> ChainConfig {
        ChainConfig::Cardano(self.config.clone())
    }

    fn bootstrap(config: ChainConfig, rt: Arc<TokioRuntime>) -> Result<Self, Error> {
        tracing::info!("Bootstrapping Cardano chain endpoint");
        
        // Extract Cardano-specific config
        let cardano_config: CardanoConfig = match config {
            ChainConfig::Cardano(config) => config,
            _ => {
                tracing::error!("Invalid config type provided to Cardano bootstrap");
                return Err(Error::config(ConfigError::wrong_type()));
            }
        };

        tracing::info!(
            "Initializing Cardano endpoint for chain: {}, gateway: {}",
            cardano_config.id,
            cardano_config.gateway_url
        );

        // Initialize Gateway client (async operation, so use rt.block_on)
        let gateway_client = rt
            .block_on(GatewayClient::new(cardano_config.gateway_url.clone()))
            .map_err(|e| {
                tracing::error!("Failed to initialize Gateway client: {}", e);
                Error::config(ConfigError::wrong_type())
            })?;

        tracing::info!("Gateway client initialized successfully");

        // Initialize keyring
        // Note: Cardano uses "addr" as account prefix (similar to how Cosmos uses prefixes)
        let keyring = KeyRing::new(
            cardano_config.key_store_type,
            "addr", // Cardano address prefix
            &cardano_config.id,
            &cardano_config.key_store_folder,
        )
        .map_err(Error::key_base)?;

        tracing::info!("Keyring initialized successfully");

        let endpoint = Self {
            config: cardano_config,
            rt,
            gateway_client,
            keyring,
        };

        tracing::info!("Cardano chain endpoint bootstrap complete");
        Ok(endpoint)
    }

    fn shutdown(self) -> Result<(), Error> {
        tracing::info!("Shutting down Cardano chain endpoint");
        Ok(())
    }

    fn health_check(&mut self) -> Result<HealthCheck, Error> {
        // TODO: Query Gateway health
        Ok(HealthCheck::Healthy)
    }

    fn subscribe(&mut self) -> Result<Subscription, Error> {
        // TODO: Implement event subscription via Gateway
        Err(Error::config(ConfigError::wrong_type()))
    }

    fn keybase(&self) -> &KeyRing<Self::SigningKeyPair> {
        &self.keyring
    }

    fn keybase_mut(&mut self) -> &mut KeyRing<Self::SigningKeyPair> {
        &mut self.keyring
    }

    fn get_signer(&self) -> Result<Signer, Error> {
        // Get the key from keyring and return its address as signer
        let key = self.keyring.get_key(&self.config.key_name)
            .map_err(Error::key_base)?;
        
        // Use the account (Cardano address) as the signer
        // Signer must be created from a string using FromStr
        Signer::from_str(&key.account())
            .map_err(|e| Error::key_base(crate::keyring::errors::Error::invalid_mnemonic(anyhow::anyhow!("Invalid signer address: {}", e))))
    }

    fn get_key(&self) -> Result<Self::SigningKeyPair, Error> {
        // Get the signing key pair from keyring
        self.keyring.get_key(&self.config.key_name)
            .map_err(Error::key_base)
    }

    fn version_specs(&self) -> Result<Specs, Error> {
        // TODO: Return Cardano version info
        // Return empty Cosmos specs for now (Cardano doesn't use Cosmos SDK)
        Ok(Specs::Cosmos(CosmosSpecs {
            cosmos_sdk: None,
            ibc_go: None,
            consensus: None,
        }))
    }

    fn send_messages_and_wait_commit(
        &mut self,
        tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        tracing::info!("send_messages_and_wait_commit: processing {} messages", tracked_msgs.msgs.len());
        
        // Block on async operations using the runtime
        self.rt.block_on(async {
            let mut all_events = Vec::new();
            
            for msg in tracked_msgs.msgs.iter() {
                tracing::debug!("Processing message type: {:?}", msg.type_url);
                
                // Step 1: Build unsigned transaction via Gateway
                let unsigned_tx = self.gateway_client
                    .build_ibc_tx(&msg.type_url, msg.value.clone())
                    .await
                    .map_err(|e| Error::send_tx(format!("Failed to build transaction: {}", e)))?;
                
                tracing::debug!("Built unsigned tx: {}", unsigned_tx.description);
                
                // Step 2: Sign transaction with keyring
                let signed_cbor_hex = self.sign_transaction_helper(&unsigned_tx.cbor_hex)?;
                
                tracing::debug!("Signed transaction, CBOR length: {}", signed_cbor_hex.len());
                
                // Step 3: Submit signed transaction via Gateway
                let tx_response = self.gateway_client
                    .submit_signed_tx(&signed_cbor_hex)
                    .await
                    .map_err(|e| Error::send_tx(format!("Failed to submit transaction: {}", e)))?;
                
                // Step 4: Parse events from transaction result
                let height = tx_response.height
                    .ok_or_else(|| Error::send_tx("No height in transaction response".to_string()))?;
                
                tracing::info!("Transaction submitted: {} at height {}", tx_response.tx_hash, height);
                
                // Log all events for debugging
                for event in &tx_response.events {
                    tracing::debug!("Gateway event: type={} attributes={:?}", event.event_type, event.attributes);
                }
                
                // Convert custom IbcEvent to proto Event format for parsing
                let proto_events: Vec<super::generated::ibc::cardano::v1::Event> = tx_response.events
                    .into_iter()
                    .map(|e| super::generated::ibc::cardano::v1::Event {
                        r#type: e.event_type,
                        attributes: e.attributes
                            .into_iter()
                            .map(|(k, v)| super::generated::ibc::cardano::v1::EventAttribute {
                                key: k,
                                value: v,
                            })
                            .collect(),
                    })
                    .collect();
                
                // Parse Gateway events into Hermes IbcEvent types
                let parsed_events = super::event_parser::parse_events(proto_events, height)
                    .map_err(|e| Error::send_tx(format!("Failed to parse events: {}", e)))?;
                
                tracing::info!("Parsed {} IBC events from transaction", parsed_events.len());
                
                // Wrap events with height
                let events_with_height: Vec<IbcEventWithHeight> = parsed_events
                    .into_iter()
                    .map(|event| IbcEventWithHeight::new(event, height))
                    .collect();
                
                // Add parsed events to result
                all_events.extend(events_with_height);
            }
            
            Ok(all_events)
        })
    }

    fn send_messages_and_wait_check_tx(
        &mut self,
        tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<TxResponse>, Error> {
        // Similar to send_messages_and_wait_commit but returns raw responses
        tracing::warn!("send_messages_and_wait_check_tx: stub implementation");
        Ok(vec![])
    }

    fn verify_header(
        &mut self,
        trusted: ICSHeight,
        target: ICSHeight,
        client_state: &AnyClientState,
    ) -> Result<Self::LightBlock, Error> {
        tracing::info!("Verifying Cardano header from trusted={:?} to target={:?}", trusted, target);
        
        // Block on async operations
        self.rt.block_on(async {
            // Step 1: Fetch the header for the target height
            let header = self.gateway_client
                .query_header(target)
                .await
                .map_err(|e| Error::query(format!("Failed to fetch header at {:?}: {}", target, e)))?;
            
            // Step 2: Verify the Mithril certificate if present
            // TODO: Add mithril_certificate field to CardanoHeader
            tracing::warn!("Mithril verification not yet fully implemented");
            
            // Step 3: Construct and return the light block
            let light_block = CardanoLightBlock {
                header,
            };
            
            tracing::info!("Header verification complete for height {:?}", target);
            Ok(light_block)
        })
    }

    fn check_misbehaviour(
        &mut self,
        update: &UpdateClient,
        client_state: &AnyClientState,
    ) -> Result<Option<MisbehaviourEvidence>, Error> {
        // TODO: Check for Cardano misbehaviour
        tracing::warn!("check_misbehaviour: stub implementation");
        Ok(None)
    }

    fn query_balance(&self, key_name: Option<&str>, denom: Option<&str>) -> Result<Balance, Error> {
        let key_name = key_name.unwrap_or(&self.config.key_name);
        let denom = denom.unwrap_or("lovelace"); // Cardano's base unit
        
        tracing::info!("Querying balance for key={}, denom={}", key_name, denom);
        
        // Get the address for this key
        let key = self.keyring.get_key(key_name)
            .map_err(|e| Error::key_base(e))?;
        
        let address = key.account();
        
        // Block on async operation
        self.rt.block_on(async {
            // TODO: Query actual balance via Gateway
            // For now, return a stub balance
            tracing::warn!("query_balance: using stub implementation");
            
            Ok(Balance {
                amount: "1000000000".to_string(), // 1000 ADA in lovelace
                denom: denom.to_string(),
            })
        })
    }

    fn query_all_balances(&self, key_name: Option<&str>) -> Result<Vec<Balance>, Error> {
        // TODO: Query all balances via Gateway
        tracing::warn!("query_all_balances: stub implementation");
        Ok(vec![])
    }

    fn query_denom_trace(&self, _hash: String) -> Result<DenomTrace, Error> {
        // Not applicable to Cardano (native assets)
        tracing::warn!("query_denom_trace: not applicable for Cardano");
        Err(Error::config(ConfigError::wrong_type()))
    }

    fn query_commitment_prefix(&self) -> Result<CommitmentPrefix, Error> {
        // Cardano uses "ibc" as commitment prefix
        Ok(CommitmentPrefix::try_from(b"ibc".to_vec()).unwrap())
    }

    fn query_application_status(&self) -> Result<ChainStatus, Error> {
        tracing::debug!("Querying Cardano application status via Gateway");
        
        // Query latest height from Gateway
        let height = self.rt.block_on(self.gateway_client.query_latest_height())
            .map_err(|e| {
                tracing::error!("Failed to query latest height: {}", e);
                Error::query(format!("Gateway query_latest_height failed: {}", e))
            })?;
        
        tracing::info!("Cardano chain at height: {}", height);
        
        Ok(ChainStatus {
            height,
            // Use current time as timestamp; TODO: Get actual timestamp from Gateway
            timestamp: tendermint::Time::now().into(),
        })
    }

    fn query_clients(
        &self,
        request: QueryClientStatesRequest,
    ) -> Result<Vec<IdentifiedAnyClientState>, Error> {
        // TODO: Query all clients via Gateway
        tracing::warn!("query_clients: stub implementation");
        Ok(vec![])
    }

    fn query_client_state(
        &self,
        request: QueryClientStateRequest,
        include_proof: IncludeProof,
    ) -> Result<(AnyClientState, Option<MerkleProof>), Error> {
        tracing::debug!("Querying client state for: {}", request.client_id);
        
        // Query client state from Gateway
        let client_state = self.rt.block_on(
            self.gateway_client.query_client_state(request.client_id.as_str())
        ).map_err(|e| {
            tracing::error!("Failed to query client state: {}", e);
            Error::query(format!("Gateway query_client_state failed: {}", e))
        })?;
        
        // Convert to AnyClientState using the From trait
        let any_client_state: AnyClientState = client_state.into();
        
        // TODO: Generate proof if include_proof is true
        let proof = if include_proof == IncludeProof::Yes {
            tracing::warn!("Proof generation not yet implemented");
            None
        } else {
            None
        };
        
        Ok((any_client_state, proof))
    }

    fn query_consensus_state(
        &self,
        request: QueryConsensusStateRequest,
        include_proof: IncludeProof,
    ) -> Result<(AnyConsensusState, Option<MerkleProof>), Error> {
        tracing::debug!(
            "Querying consensus state for client: {} at height: {:?}",
            request.client_id,
            request.consensus_height
        );
        
        // Query consensus state from Gateway
        let consensus_state = self.rt.block_on(
            self.gateway_client.query_consensus_state(
                request.client_id.as_str(),
                request.consensus_height
            )
        ).map_err(|e| {
            tracing::error!("Failed to query consensus state: {}", e);
            Error::query(format!("Gateway query_consensus_state failed: {}", e))
        })?;
        
        // Convert to AnyConsensusState using the From trait
        let any_consensus_state: AnyConsensusState = consensus_state.into();
        
        // TODO: Generate proof if include_proof is true
        let proof = if include_proof == IncludeProof::Yes {
            tracing::warn!("Proof generation not yet implemented");
            None
        } else {
            None
        };
        
        Ok((any_consensus_state, proof))
    }

    fn query_consensus_state_heights(
        &self,
        request: QueryConsensusStateHeightsRequest,
    ) -> Result<Vec<ICSHeight>, Error> {
        // TODO: Query consensus state heights via Gateway
        tracing::warn!("query_consensus_state_heights: stub implementation");
        Ok(vec![])
    }

    fn query_upgraded_client_state(
        &self,
        request: QueryUpgradedClientStateRequest,
    ) -> Result<(AnyClientState, MerkleProof), Error> {
        // TODO: Query upgraded client state
        tracing::warn!("query_upgraded_client_state: stub implementation");
        todo!("Implement query_upgraded_client_state()")
    }

    fn query_upgraded_consensus_state(
        &self,
        request: QueryUpgradedConsensusStateRequest,
    ) -> Result<(AnyConsensusState, MerkleProof), Error> {
        // TODO: Query upgraded consensus state
        tracing::warn!("query_upgraded_consensus_state: stub implementation");
        todo!("Implement query_upgraded_consensus_state()")
    }

    fn query_connections(
        &self,
        request: QueryConnectionsRequest,
    ) -> Result<Vec<IdentifiedConnectionEnd>, Error> {
        // TODO: Query connections via Gateway
        tracing::warn!("query_connections: stub implementation");
        Ok(vec![])
    }

    fn query_client_connections(
        &self,
        request: QueryClientConnectionsRequest,
    ) -> Result<Vec<ConnectionId>, Error> {
        // TODO: Query client connections via Gateway
        tracing::warn!("query_client_connections: stub implementation");
        Ok(vec![])
    }

    fn query_connection(
        &self,
        request: QueryConnectionRequest,
        include_proof: IncludeProof,
    ) -> Result<(ConnectionEnd, Option<MerkleProof>), Error> {
        tracing::info!("Querying connection: {:?}", request.connection_id);
        
        // Block on async operation
        self.rt.block_on(async {
            // Query connection from Gateway
            let response_bytes = self.gateway_client
                .query_connection(&request.connection_id.to_string())
                .await
                .map_err(|e| Error::query(format!("Failed to query connection: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::connection::v1::QueryConnectionResponse;
            
            let response = QueryConnectionResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode connection response: {}", e)))?;
            
            let connection_end = response.connection
                .ok_or_else(|| Error::query("No connection in response".to_string()))?;
            
            // Convert proto ConnectionEnd to domain ConnectionEnd
            let connection = ConnectionEnd::try_from(connection_end)
                .map_err(|e| Error::query(format!("Failed to parse ConnectionEnd: {}", e)))?;
            
            // Parse proof if requested
            let proof = if matches!(include_proof, IncludeProof::Yes) {
                if !response.proof.is_empty() {
                    use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
                    let raw_proof = RawMerkleProof::decode(&response.proof[..])
                        .map_err(|e| Error::query(format!("Failed to decode proof: {}", e)))?;
                    Some(MerkleProof::from(raw_proof))
                } else {
                    None
                }
            } else {
                None
            };
            
            Ok((connection, proof))
        })
    }

    fn query_connection_channels(
        &self,
        request: QueryConnectionChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        // TODO: Query connection channels via Gateway
        tracing::warn!("query_connection_channels: stub implementation");
        Ok(vec![])
    }

    fn query_channels(
        &self,
        request: QueryChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        // TODO: Query channels via Gateway
        tracing::warn!("query_channels: stub implementation");
        Ok(vec![])
    }

    fn query_channel(
        &self,
        request: QueryChannelRequest,
        include_proof: IncludeProof,
    ) -> Result<(ChannelEnd, Option<MerkleProof>), Error> {
        tracing::info!("Querying channel: port={}, channel={}", request.port_id, request.channel_id);
        
        // Block on async operation
        self.rt.block_on(async {
            // Query channel from Gateway
            let response_bytes = self.gateway_client
                .query_channel(&request.port_id.to_string(), &request.channel_id.to_string())
                .await
                .map_err(|e| Error::query(format!("Failed to query channel: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::channel::v1::QueryChannelResponse;
            
            let response = QueryChannelResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode channel response: {}", e)))?;
            
            let channel_proto = response.channel
                .ok_or_else(|| Error::query("No channel in response".to_string()))?;
            
            // Convert proto Channel to domain ChannelEnd
            let channel = ChannelEnd::try_from(channel_proto)
                .map_err(|e| Error::query(format!("Failed to parse ChannelEnd: {}", e)))?;
            
            // Parse proof if requested
            let proof = if matches!(include_proof, IncludeProof::Yes) {
                if !response.proof.is_empty() {
                    use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
                    let raw_proof = RawMerkleProof::decode(&response.proof[..])
                        .map_err(|e| Error::query(format!("Failed to decode proof: {}", e)))?;
                    Some(MerkleProof::from(raw_proof))
                } else {
                    None
                }
            } else {
                None
            };
            
            Ok((channel, proof))
        })
    }

    fn query_channel_client_state(
        &self,
        request: QueryChannelClientStateRequest,
    ) -> Result<Option<IdentifiedAnyClientState>, Error> {
        // TODO: Query channel client state via Gateway
        tracing::warn!("query_channel_client_state: stub implementation");
        Ok(None)
    }

    fn query_packet_commitment(
        &self,
        request: QueryPacketCommitmentRequest,
        include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        tracing::info!("Querying packet commitment: port={}, channel={}, sequence={}", 
            request.port_id, request.channel_id, request.sequence);
        
        // Block on async operation
        self.rt.block_on(async {
            // Query packet commitment from Gateway
            let response_bytes = self.gateway_client
                .query_packet_commitment(&request.port_id.to_string(), &request.channel_id.to_string(), request.sequence.into())
                .await
                .map_err(|e| Error::query(format!("Failed to query packet commitment: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::channel::v1::QueryPacketCommitmentResponse;
            
            let response = QueryPacketCommitmentResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode packet commitment response: {}", e)))?;
            
            // Parse proof if requested
            let proof = if matches!(include_proof, IncludeProof::Yes) {
                if !response.proof.is_empty() {
                    use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
                    let raw_proof = RawMerkleProof::decode(&response.proof[..])
                        .map_err(|e| Error::query(format!("Failed to decode proof: {}", e)))?;
                    Some(MerkleProof::from(raw_proof))
                } else {
                    None
                }
            } else {
                None
            };
            
            Ok((response.commitment, proof))
        })
    }

    fn query_packet_commitments(
        &self,
        request: QueryPacketCommitmentsRequest,
    ) -> Result<(Vec<Sequence>, ICSHeight), Error> {
        // TODO: Query packet commitments via Gateway
        tracing::warn!("query_packet_commitments: stub implementation");
        Ok((vec![], ICSHeight::new(0, 1).unwrap()))
    }

    fn query_packet_receipt(
        &self,
        request: QueryPacketReceiptRequest,
        include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        tracing::info!("Querying packet receipt: port={}, channel={}, sequence={}", 
            request.port_id, request.channel_id, request.sequence);
        
        // Block on async operation
        self.rt.block_on(async {
            // TODO: Query actual packet receipt from Gateway
            tracing::warn!("query_packet_receipt: using stub implementation");
            
            // Return error for now
            Err(Error::query(format!(
                "Packet receipt query not yet implemented for port={}, channel={}, seq={}",
                request.port_id, request.channel_id, request.sequence
            )))
        })
    }

    fn query_unreceived_packets(
        &self,
        request: QueryUnreceivedPacketsRequest,
    ) -> Result<Vec<Sequence>, Error> {
        // TODO: Query unreceived packets via Gateway
        tracing::warn!("query_unreceived_packets: stub implementation");
        Ok(vec![])
    }

    fn query_packet_acknowledgement(
        &self,
        request: QueryPacketAcknowledgementRequest,
        include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        tracing::info!("Querying packet acknowledgement: port={}, channel={}, sequence={}", 
            request.port_id, request.channel_id, request.sequence);
        
        // Block on async operation
        self.rt.block_on(async {
            // TODO: Query actual packet acknowledgement from Gateway
            tracing::warn!("query_packet_acknowledgement: using stub implementation");
            
            // Return error for now
            Err(Error::query(format!(
                "Packet acknowledgement query not yet implemented for port={}, channel={}, seq={}",
                request.port_id, request.channel_id, request.sequence
            )))
        })
    }

    fn query_packet_acknowledgements(
        &self,
        request: QueryPacketAcknowledgementsRequest,
    ) -> Result<(Vec<Sequence>, ICSHeight), Error> {
        // TODO: Query packet acknowledgements via Gateway
        tracing::warn!("query_packet_acknowledgements: stub implementation");
        Ok((vec![], ICSHeight::new(0, 1).unwrap()))
    }

    fn query_unreceived_acknowledgements(
        &self,
        request: QueryUnreceivedAcksRequest,
    ) -> Result<Vec<Sequence>, Error> {
        // TODO: Query unreceived acknowledgements via Gateway
        tracing::warn!("query_unreceived_acknowledgements: stub implementation");
        Ok(vec![])
    }

    fn query_next_sequence_receive(
        &self,
        request: QueryNextSequenceReceiveRequest,
        include_proof: IncludeProof,
    ) -> Result<(Sequence, Option<MerkleProof>), Error> {
        // TODO: Query next sequence receive via Gateway
        tracing::warn!("query_next_sequence_receive: stub implementation");
        todo!("Implement query_next_sequence_receive()")
    }

    fn query_txs(&self, request: QueryTxRequest) -> Result<Vec<IbcEventWithHeight>, Error> {
        // TODO: Query transactions via Gateway
        tracing::warn!("query_txs: stub implementation");
        Ok(vec![])
    }

    fn query_packet_events(
        &self,
        request: QueryPacketEventDataRequest,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        // TODO: Query packet events via Gateway
        tracing::warn!("query_packet_events: stub implementation");
        Ok(vec![])
    }

    fn query_host_consensus_state(
        &self,
        request: QueryHostConsensusStateRequest,
    ) -> Result<Self::ConsensusState, Error> {
        // TODO: Query host consensus state
        tracing::warn!("query_host_consensus_state: stub implementation");
        todo!("Implement query_host_consensus_state()")
    }

    fn build_client_state(
        &self,
        height: ICSHeight,
        settings: ClientSettings,
    ) -> Result<Self::ClientState, Error> {
        tracing::info!("Building Cardano client state at height {:?}", height);
        
        // Extract trusting period from settings or use defaults
        // TODO: Extract from settings when structure is available
        let trusting_period = 86400; // Default: 1 day
        
        // Cardano unbonding period - typically much longer
        let unbonding_period = 1814400; // 21 days
        
        // TODO: Fetch Mithril genesis verification key from config or Gateway
        // For now, use a placeholder
        let mithril_genesis_vkey = vec![0u8; 32];
        
        let client_state = CardanoClientState::new(
            self.config.id.to_string(),
            height,
            trusting_period,
            unbonding_period,
            mithril_genesis_vkey,
        );
        
        tracing::info!("Built Cardano client state: chain_id={}, height={:?}", 
            client_state.chain_id, client_state.latest_height);
        
        Ok(client_state)
    }

    fn build_consensus_state(
        &self,
        light_block: Self::LightBlock,
    ) -> Result<Self::ConsensusState, Error> {
        // TODO: Build consensus state from light block
        tracing::warn!("build_consensus_state: stub implementation");
        Ok(CardanoConsensusState::new(
            light_block.header.block_hash,
            light_block.header.timestamp,
            light_block.header.slot,
            light_block.header.epoch,
        ))
    }

    fn build_header(
        &mut self,
        trusted_height: ICSHeight,
        target_height: ICSHeight,
        _client_state: &AnyClientState,
    ) -> Result<(Self::Header, Vec<Self::Header>), Error> {
        tracing::info!("Building Cardano header from trusted_height={:?} to target_height={:?}", 
            trusted_height, target_height);
        
        // Block on async operations
        self.rt.block_on(async {
            // Step 1: Query the block header at target height
            let header = self.gateway_client
                .query_header(target_height)
                .await
                .map_err(|e| Error::query(format!("Failed to fetch block at {:?}: {}", target_height, e)))?;
            
            // Step 2: Fetch Mithril certificate for this block
            // TODO: Implement Mithril certificate fetching with proper slot/epoch calculation
            tracing::warn!("Mithril certificate fetching not yet implemented in build_header");
            
            tracing::info!("Built Cardano header at height {:?}", target_height);
            
            // Return target header and empty support headers vector
            // (Cardano doesn't need intermediate headers like Tendermint)
            Ok((header, vec![]))
        })
    }

    fn maybe_register_counterparty_payee(
        &mut self,
        _channel_id: &ChannelId,
        _port_id: &PortId,
        _counterparty_payee: &Signer,
    ) -> Result<(), Error> {
        // ICS-29 fee middleware - not implemented for Cardano yet
        tracing::warn!("maybe_register_counterparty_payee: not implemented for Cardano");
        Ok(())
    }

    fn cross_chain_query(
        &self,
        _requests: Vec<CrossChainQueryRequest>,
    ) -> Result<Vec<ibc_relayer_types::applications::ics31_icq::response::CrossChainQueryResponse>, Error> {
        // ICS-31 cross-chain query - not implemented for Cardano yet
        tracing::warn!("cross_chain_query: not implemented for Cardano");
        Ok(vec![])
    }

    fn query_incentivized_packet(
        &self,
        _request: ibc_proto::ibc::apps::fee::v1::QueryIncentivizedPacketRequest,
    ) -> Result<ibc_proto::ibc::apps::fee::v1::QueryIncentivizedPacketResponse, Error> {
        // ICS-29 fee middleware - not implemented for Cardano yet
        tracing::warn!("query_incentivized_packet: not implemented for Cardano");
        Err(Error::config(ConfigError::wrong_type()))
    }

    fn query_consumer_chains(&self) -> Result<Vec<ibc_relayer_types::applications::ics28_ccv::msgs::ConsumerChain>, Error> {
        // ICS-28 CCV (Cross-Chain Validation) - not applicable to Cardano
        tracing::warn!("query_consumer_chains: not applicable for Cardano");
        Ok(vec![])
    }

    fn query_upgrade(
        &self,
        _request: ibc_proto::ibc::core::channel::v1::QueryUpgradeRequest,
        _height: ibc_relayer_types::Height,
        _include_proof: IncludeProof,
    ) -> Result<(ibc_relayer_types::core::ics04_channel::upgrade::Upgrade, Option<MerkleProof>), Error> {
        // Channel upgrades - not implemented for Cardano yet
        tracing::warn!("query_upgrade: not implemented for Cardano");
        todo!("Implement query_upgrade()")
    }

    fn query_upgrade_error(
        &self,
        _request: ibc_proto::ibc::core::channel::v1::QueryUpgradeErrorRequest,
        _height: ibc_relayer_types::Height,
        _include_proof: IncludeProof,
    ) -> Result<(ibc_relayer_types::core::ics04_channel::upgrade::ErrorReceipt, Option<MerkleProof>), Error> {
        // Channel upgrades - not implemented for Cardano yet
        tracing::warn!("query_upgrade_error: not implemented for Cardano");
        todo!("Implement query_upgrade_error()")
    }

    fn query_ccv_consumer_id(
        &self,
        _client_id: ClientId,
    ) -> Result<ibc_relayer_types::applications::ics28_ccv::msgs::ConsumerId, Error> {
        // ICS-28 CCV - not applicable to Cardano
        tracing::warn!("query_ccv_consumer_id: not applicable for Cardano");
        todo!("Implement query_ccv_consumer_id()")
    }
}

// Header trait and From<CardanoHeader> for AnyHeader are now implemented
// in ibc-relayer-types/src/clients/ics08_cardano/header.rs and
// ibc-relayer-types/src/core/ics02_client/header.rs respectively

