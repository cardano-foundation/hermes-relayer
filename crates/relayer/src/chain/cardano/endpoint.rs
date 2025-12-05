//! Cardano ChainEndpoint implementation for Hermes
//!
//! This module implements the ChainEndpoint trait required by Hermes for custom chain support.

use super::config::CardanoConfig;
use super::error::Error as CardanoError;
use super::gateway_client::GatewayClient;
use super::keyring::CardanoKeyring;
use super::signer;
use super::signing_key_pair::CardanoSigningKeyPair;
use super::types::{CardanoClientState, CardanoConsensusState, CardanoHeader};

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

impl From<CardanoSigningKeyPair> for AnySigningKeyPair {
    fn from(pair: CardanoSigningKeyPair) -> Self {
        // AnySigningKeyPair is an enum with different variants for each chain type
        // Since we can't add a Cardano variant without modifying ibc-relayer,
        // we'll use a workaround for now
        tracing::debug!("Converting CardanoSigningKeyPair to AnySigningKeyPair");
        
        // For now, this conversion is not directly supported
        // In production, AnySigningKeyPair needs a Cardano variant
        // This is a limitation of the current Hermes architecture
        tracing::error!("CardanoSigningKeyPair -> AnySigningKeyPair conversion not yet supported");
        
        // Return a stub - this will need proper implementation
        // when CardanoSigningKeyPair is added to AnySigningKeyPair enum
        panic!("CardanoSigningKeyPair conversion not yet implemented - AnySigningKeyPair needs Cardano variant")
    }
}

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
                    .submit_signed_tx(signed_cbor_hex, unsigned_tx.description.clone())
                    .await
                    .map_err(|e| Error::send_tx(format!("Failed to submit transaction: {}", e)))?;
                
                tracing::info!("Transaction submitted: {} at height {:?}", tx_response.tx_hash, tx_response.height);
                
                // Step 4: Parse events from transaction result
                // TODO: Convert Gateway events to IbcEventWithHeight
                // For now, we'll create a stub event
                if let Some(height) = tx_response.height {
                    // TODO: Parse actual IBC events from tx_response.events
                    tracing::warn!("Event parsing not yet implemented, returning empty events");
                }
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
                .query_block_header(target)
                .await
                .map_err(|e| Error::query(format!("Failed to fetch header at {:?}: {}", target, e)))?;
            
            // Step 2: Verify the Mithril certificate if present
            if let Some(ref mithril_cert) = header.mithril_certificate {
                tracing::info!("Verifying Mithril certificate for height {:?}", target);
                
                // TODO: Implement actual Mithril verification
                // This should:
                // 1. Extract the Mithril certificate from the header
                // 2. Verify the certificate chain back to the genesis verification key in client_state
                // 3. Verify the certificate signatures using Mithril's multi-signature scheme
                // 4. Ensure the certificate covers the target block
                
                tracing::warn!("Mithril verification not yet fully implemented - accepting certificate");
                
                // For now, we accept any certificate as valid (stub implementation)
                // In production, this MUST verify:
                // - Certificate signature validity
                // - Certificate chain back to genesis
                // - Certificate covers the claimed block
            } else {
                tracing::warn!("No Mithril certificate present in header - this should not happen in production");
            }
            
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
            // TODO: Query actual connection from Gateway
            // Gateway should query the connection UTXO from Cardano
            tracing::warn!("query_connection: using stub implementation");
            
            // Return error for now - connection queries require proper Gateway integration
            Err(Error::query(format!(
                "Connection query not yet implemented for connection_id={}",
                request.connection_id
            )))
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
            // TODO: Query actual channel from Gateway
            // Gateway should query the channel UTXO from Cardano
            tracing::warn!("query_channel: using stub implementation");
            
            // Return error for now - channel queries require proper Gateway integration
            Err(Error::query(format!(
                "Channel query not yet implemented for port={}, channel={}",
                request.port_id, request.channel_id
            )))
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
            // TODO: Query actual packet commitment from Gateway
            tracing::warn!("query_packet_commitment: using stub implementation");
            
            // Return error for now
            Err(Error::query(format!(
                "Packet commitment query not yet implemented for port={}, channel={}, seq={}",
                request.port_id, request.channel_id, request.sequence
            )))
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
            let mut header = self.gateway_client
                .query_block_header(target_height)
                .await
                .map_err(|e| Error::query(format!("Failed to fetch block at {:?}: {}", target_height, e)))?;
            
            // Step 2: Fetch Mithril certificate for this block
            let mithril_cert = self.gateway_client
                .fetch_mithril_certificate(target_height)
                .await
                .map_err(|e| Error::query(format!("Failed to fetch Mithril certificate at {:?}: {}", target_height, e)))?;
            
            // Attach Mithril certificate to header
            header = header.with_mithril_certificate(mithril_cert);
            
            tracing::info!("Built Cardano header with Mithril certificate at height {:?}", target_height);
            
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

// Implement Header trait for CardanoHeader to satisfy ChainEndpoint requirements
impl Header for CardanoHeader {
    fn client_type(&self) -> ibc_relayer_types::core::ics02_client::client_type::ClientType {
        ibc_relayer_types::core::ics02_client::client_type::ClientType::Cardano
    }

    fn height(&self) -> ICSHeight {
        self.height
    }

    fn timestamp(&self) -> ibc_relayer_types::timestamp::Timestamp {
        ibc_relayer_types::timestamp::Timestamp::from_nanoseconds(self.timestamp as u64 * 1_000_000_000)
            .unwrap()
    }
}

// Implement conversion to AnyHeader
impl From<CardanoHeader> for AnyHeader {
    fn from(header: CardanoHeader) -> Self {
        // AnyHeader is an enum with different variants for each chain type
        // Since we can't add a Cardano variant without modifying ibc-relayer-types,
        // this is a known limitation
        tracing::debug!("Converting CardanoHeader to AnyHeader at height {:?}", header.height);
        
        // For now, this conversion is not directly supported
        // In production, AnyHeader needs a Cardano variant
        tracing::error!("CardanoHeader -> AnyHeader conversion not yet supported");
        
        // Return a stub - this will need proper implementation
        // when CardanoHeader is added to AnyHeader enum in ibc-relayer-types
        panic!("CardanoHeader conversion not yet implemented - AnyHeader needs Cardano variant")
    }
}

