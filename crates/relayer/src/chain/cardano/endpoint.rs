//! Cardano ChainEndpoint implementation for Hermes
//!
//! This module implements the ChainEndpoint trait required by Hermes for custom chain support.

use super::config::CardanoConfig;
use super::gateway_client::GatewayClient;
use super::signing_key_pair::CardanoSigningKeyPair;
use super::types::{CardanoClientState, CardanoConsensusState};

use ibc_relayer_types::clients::ics2000_mithril::header::Header as MithrilHeader;

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
use crate::consensus_state::AnyConsensusState;
use crate::denom::DenomTrace;
use crate::error::Error;
use crate::event::IbcEventWithHeight;
use crate::keyring::{KeyRing, SigningKeyPair};
use crate::misbehaviour::MisbehaviourEvidence;
use ibc_relayer_types::core::ics02_client::events::UpdateClient;
use ibc_relayer_types::core::ics03_connection::connection::{ConnectionEnd, IdentifiedConnectionEnd};
use ibc_relayer_types::core::ics04_channel::channel::{ChannelEnd, IdentifiedChannelEnd};
use ibc_relayer_types::core::ics04_channel::packet::Sequence;
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentPrefix;
use ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof;
use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};
use ibc_relayer_types::signer::Signer;
use std::str::FromStr;
use ibc_relayer_types::Height as ICSHeight;
use tendermint_rpc::endpoint::broadcast::tx_sync::Response as TxResponse;
use tokio::runtime::Runtime as TokioRuntime;

/// Cardano light block (placeholder)
#[derive(Debug, Clone)]
pub struct CardanoLightBlock {
    pub header: MithrilHeader,
}

// CardanoSigningKeyPair is now defined in signing_key_pair.rs
// From<CardanoSigningKeyPair> for AnySigningKeyPair is implemented in ibc-relayer/src/keyring/any_signing_key_pair.rs

/// Cardano ChainEndpoint implementation
pub struct CardanoChainEndpoint {
    config: CardanoConfig,
    rt: Arc<TokioRuntime>,
    gateway_client: GatewayClient,
    keyring: KeyRing<CardanoSigningKeyPair>,
    event_source_cmd: Option<crate::event::source::TxEventSourceCmd>,
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
        
        // Get the CardanoSigningKeyPair and extract the CardanoKeyring
        let signing_key_pair = key.as_any().downcast_ref::<CardanoSigningKeyPair>()
            .ok_or_else(|| Error::send_tx("Failed to downcast to CardanoSigningKeyPair".to_string()))?;
        let cardano_keyring = signing_key_pair.get_cardano_keyring()
            .map_err(|e| Error::send_tx(format!("Failed to get CardanoKeyring: {}", e)))?;
        
        // Sign the transaction
        let signed_tx_bytes = signer::sign_transaction(&unsigned_tx_bytes, &cardano_keyring)
            .map_err(|e| Error::send_tx(format!("Failed to sign transaction: {}", e)))?;
        
        // Convert back to hex
        Ok(hex::encode(signed_tx_bytes))
    }

    /// Initialize the event source for monitoring Cardano chain events
    fn init_event_source(&mut self) -> Result<crate::event::source::TxEventSourceCmd, Error> {
        use super::event_source::CardanoEventSource;
        use std::thread;
        use std::time::Duration;
        
        tracing::info!("Initializing Cardano event source with polling");
        
        // Get poll interval from config (default 5 seconds)
        let poll_interval = self.config.event_poll_interval
            .unwrap_or_else(|| Duration::from_secs(5));
        
        let (event_source, monitor_tx) = CardanoEventSource::new(
            self.config.id.clone(),
            self.gateway_client.clone(),
            poll_interval,
            self.rt.clone(),
        ).map_err(Error::event_source)?;
        
        thread::spawn(move || event_source.run());
        
        tracing::info!("Event source initialized, polling every {:?}", poll_interval);
        
        Ok(monitor_tx)
    }
}

impl ChainEndpoint for CardanoChainEndpoint {
    type LightBlock = CardanoLightBlock;
    type Header = MithrilHeader;
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
            event_source_cmd: None, // Initialized lazily on first subscribe() call
        };

        tracing::info!("Cardano chain endpoint bootstrap complete");
        Ok(endpoint)
    }

    fn shutdown(self) -> Result<(), Error> {
        tracing::info!("Shutting down Cardano chain endpoint");
        Ok(())
    }

    fn health_check(&mut self) -> Result<HealthCheck, Error> {
        match self.rt.block_on(self.gateway_client.query_latest_height()) {
            Ok(_) => Ok(HealthCheck::Healthy),
            Err(e) => Ok(HealthCheck::Unhealthy(Box::new(Error::query(format!(
                "Gateway health check failed: {e}"
            ))))),
        }
    }

    fn subscribe(&mut self) -> Result<Subscription, Error> {
        let event_source_cmd = match &self.event_source_cmd {
            Some(cmd) => cmd,
            None => {
                let cmd = self.init_event_source()?;
                self.event_source_cmd = Some(cmd);
                self.event_source_cmd.as_ref().unwrap()
            }
        };

        let subscription = event_source_cmd
            .subscribe()
            .map_err(Error::event_source)?;
        Ok(subscription)
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
        tracing::info!(
            "send_messages_and_wait_check_tx: processing {} messages",
            tracked_msgs.msgs.len()
        );

        if tracked_msgs.msgs.is_empty() {
            return Ok(vec![]);
        }

        self.rt.block_on(async {
            use bytes::Bytes;
            use tendermint::abci::Code;
            use tendermint::Hash;

            let mut responses = Vec::with_capacity(tracked_msgs.msgs.len());

            for msg in tracked_msgs.msgs.iter() {
                tracing::debug!("Processing message type: {:?}", msg.type_url);

                let unsigned_tx = self
                    .gateway_client
                    .build_ibc_tx(&msg.type_url, msg.value.clone())
                    .await
                    .map_err(|e| Error::send_tx(format!("Failed to build transaction: {e}")))?;

                let signed_cbor_hex = self.sign_transaction_helper(&unsigned_tx.cbor_hex)?;

                let tx_response = self
                    .gateway_client
                    .submit_signed_tx(&signed_cbor_hex)
                    .await
                    .map_err(|e| Error::send_tx(format!("Failed to submit transaction: {e}")))?;

                let hash = match Hash::from_str(&tx_response.tx_hash.to_ascii_uppercase()) {
                    Ok(h) => h,
                    Err(e) => {
                        tracing::warn!(
                            "failed to parse tx hash `{}` as Tendermint hash: {e}",
                            tx_response.tx_hash
                        );
                        Hash::None
                    }
                };

                responses.push(TxResponse {
                    codespace: String::new(),
                    code: Code::Ok,
                    data: Bytes::new(),
                    log: format!("submitted tx {}", tx_response.tx_hash),
                    hash,
                });
            }

            Ok(responses)
        })
    }

    fn verify_header(
        &mut self,
        _trusted: ICSHeight,
        _target: ICSHeight,
        _client_state: &AnyClientState,
    ) -> Result<Self::LightBlock, Error> {
        Err(Error::query(
            "Cardano header verification is not implemented; requires canonical decoding of /ibc.lightclients.cardano.v1.Header plus Mithril verification"
                .to_string(),
        ))
    }

    fn check_misbehaviour(
        &mut self,
        _update: &UpdateClient,
        _client_state: &AnyClientState,
    ) -> Result<Option<MisbehaviourEvidence>, Error> {
        // TODO: Check for Cardano misbehaviour
        tracing::warn!("check_misbehaviour: stub implementation");
        Ok(None)
    }

    fn query_balance(&self, key_name: Option<&str>, denom: Option<&str>) -> Result<Balance, Error> {
        let denom = denom.unwrap_or("lovelace"); // Cardano's base unit
        let key_name = key_name.unwrap_or(&self.config.key_name);

        Err(Error::query(format!(
            "Cardano balance query is not implemented (key={key_name}, denom={denom}); requires Gateway UTXO/balance query support"
        )))
    }

    fn query_all_balances(&self, key_name: Option<&str>) -> Result<Vec<Balance>, Error> {
        let key_name = key_name.unwrap_or(&self.config.key_name);
        Err(Error::query(format!(
            "Cardano all-balances query is not implemented (key={key_name}); requires Gateway UTXO/balance query support"
        )))
    }

    fn query_denom_trace(&self, _hash: String) -> Result<DenomTrace, Error> {
        // Not applicable to Cardano (native assets)
        tracing::warn!("query_denom_trace: not applicable for Cardano");
        Err(Error::config(ConfigError::wrong_type()))
    }

    fn query_commitment_prefix(&self) -> Result<CommitmentPrefix, Error> {
        // Cardano uses "ibc" as commitment prefix
        CommitmentPrefix::try_from(b"ibc".to_vec())
            .map_err(|e| Error::query(format!("invalid commitment prefix for Cardano: {e}")))
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

        let timestamp = match self.rt.block_on(self.gateway_client.query_header(height)) {
            Ok(header) => header.timestamp,
            Err(e) => {
                tracing::warn!(
                    "Failed to query header at height {height} for timestamp (falling back to local time): {e}"
                );
                tendermint::Time::now().into()
            }
        };
        
        Ok(ChainStatus {
            height,
            timestamp,
        })
    }

    fn query_clients(
        &self,
        _request: QueryClientStatesRequest,
    ) -> Result<Vec<IdentifiedAnyClientState>, Error> {
        tracing::debug!("Querying all clients");
        
        // Block on async operation
        self.rt.block_on(async {
            // Query clients from Gateway
            let response_bytes = self.gateway_client
                .query_clients()
                .await
                .map_err(|e| Error::query(format!("Failed to query clients: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::client::v1::QueryClientStatesResponse;
            
            let response = QueryClientStatesResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode clients response: {}", e)))?;
            
            // Convert proto client states to domain types, filtering out unsupported types
            let clients: Vec<IdentifiedAnyClientState> = response
                .client_states
                .into_iter()
                .filter_map(|cs| {
                    IdentifiedAnyClientState::try_from(cs.clone())
                        .map_err(|e| {
                            let (client_type, client_id) = (
                                if let Some(client_state) = &cs.client_state {
                                    client_state.type_url.clone()
                                } else {
                                    "None".to_string()
                                },
                                &cs.client_id
                            );
                            tracing::warn!(
                                "Encountered unsupported client type `{}` while scanning client `{}`, skipping the client",
                                client_type, client_id
                            );
                            tracing::debug!("Failed to parse client state. Error: {}", e);
                        })
                        .ok()
                })
                .collect();
            
            Ok(clients)
        })
    }

    fn query_client_state(
        &self,
        request: QueryClientStateRequest,
        include_proof: IncludeProof,
    ) -> Result<(AnyClientState, Option<MerkleProof>), Error> {
        tracing::debug!("Querying client state for: {}", request.client_id);
        
        let response = self
            .rt
            .block_on(self.gateway_client.query_client_state(request.client_id.as_str()))
            .map_err(|e| {
                tracing::error!("Failed to query client state: {}", e);
                Error::query(format!("Gateway query_client_state failed: {}", e))
            })?;

        let client_state_any = response
            .client_state
            .ok_or_else(|| Error::query("No client_state in response".to_string()))?;

        let any_client_state: AnyClientState = match AnyClientState::try_from(client_state_any.clone()) {
            Ok(cs) => cs,
            Err(_e) if client_state_any.type_url == "/ibc.lightclients.cardano.v1.ClientState" => {
                let prost_any = prost_types::Any {
                    type_url: client_state_any.type_url,
                    value: client_state_any.value,
                };

                let cs = super::proto_parser::parse_client_state_from_any(prost_any)
                    .map_err(|e| Error::query(format!("Failed to parse Cardano client state: {e}")))?;

                cs.into()
            }
            Err(e) => {
                return Err(Error::query(format!(
                    "Unsupported client state type_url {}: {e}",
                    client_state_any.type_url
                )))
            }
        };

        let proof = if include_proof == IncludeProof::Yes && !response.proof.is_empty() {
            use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
            use prost::Message;

            let raw_proof = RawMerkleProof::decode(&response.proof[..])
                .map_err(|e| Error::query(format!("Failed to decode proof: {e}")))?;
            Some(MerkleProof::from(raw_proof))
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
        
        let response = self
            .rt
            .block_on(self.gateway_client.query_consensus_state(
                request.client_id.as_str(),
                request.consensus_height,
            ))
            .map_err(|e| {
                tracing::error!("Failed to query consensus state: {}", e);
                Error::query(format!("Gateway query_consensus_state failed: {}", e))
            })?;

        let consensus_state_any = response
            .consensus_state
            .ok_or_else(|| Error::query("No consensus_state in response".to_string()))?;

        let any_consensus_state: AnyConsensusState = match AnyConsensusState::try_from(consensus_state_any.clone()) {
            Ok(cs) => cs,
            Err(_e) if consensus_state_any.type_url == "/ibc.lightclients.cardano.v1.ConsensusState" => {
                let prost_any = prost_types::Any {
                    type_url: consensus_state_any.type_url,
                    value: consensus_state_any.value,
                };

                let cs = super::proto_parser::parse_consensus_state_from_any(prost_any)
                    .map_err(|e| Error::query(format!("Failed to parse Cardano consensus state: {e}")))?;

                cs.into()
            }
            Err(e) => {
                return Err(Error::query(format!(
                    "Unsupported consensus state type_url {}: {e}",
                    consensus_state_any.type_url
                )))
            }
        };

        let proof = if include_proof == IncludeProof::Yes && !response.proof.is_empty() {
            use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
            use prost::Message;

            let raw_proof = RawMerkleProof::decode(&response.proof[..])
                .map_err(|e| Error::query(format!("Failed to decode proof: {e}")))?;
            Some(MerkleProof::from(raw_proof))
        } else {
            None
        };
        
        Ok((any_consensus_state, proof))
    }

    fn query_consensus_state_heights(
        &self,
        request: QueryConsensusStateHeightsRequest,
    ) -> Result<Vec<ICSHeight>, Error> {
        tracing::debug!(
            "Querying consensus state heights for client: {}",
            request.client_id
        );

        self.rt.block_on(async {
            let grpc_request: ibc_proto::ibc::core::client::v1::QueryConsensusStateHeightsRequest =
                request.clone().into();

            let heights_response = self
                .gateway_client
                .query_consensus_state_heights(grpc_request)
                .await;

            let consensus_state_heights = match heights_response {
                Ok(res) => res.consensus_state_heights,
                Err(heights_err) => {
                    // Some chains do not implement `ConsensusStateHeights`; fall back to
                    // `ConsensusStates` and extract the heights.
                    let states_request: ibc_proto::ibc::core::client::v1::QueryConsensusStatesRequest =
                        ibc_proto::ibc::core::client::v1::QueryConsensusStatesRequest {
                            client_id: request.client_id.to_string(),
                            pagination: request.pagination.map(|p| p.into()),
                        };

                    let states = self
                        .gateway_client
                        .query_consensus_states(states_request)
                        .await
                        .map_err(|states_err| {
                            Error::query(format!(
                                "Failed to query consensus state heights ({heights_err}) and fallback consensus states ({states_err})"
                            ))
                        })?;

                    states
                        .consensus_states
                        .into_iter()
                        .filter_map(|cs| cs.height)
                        .collect()
                }
            };

            let mut heights: Vec<_> = consensus_state_heights
                .into_iter()
                .filter_map(|h| {
                    ICSHeight::new(h.revision_number, h.revision_height)
                        .map_err(|e| {
                            tracing::warn!(
                                "Failed to parse consensus state height {}-{}: {}",
                                h.revision_number,
                                h.revision_height,
                                e
                            );
                        })
                        .ok()
                })
                .collect();

            heights.sort_unstable();

            Ok(heights)
        })
    }

    fn query_upgraded_client_state(
        &self,
        _request: QueryUpgradedClientStateRequest,
    ) -> Result<(AnyClientState, MerkleProof), Error> {
        Err(Error::query(
            "Cardano upgraded client state query is not implemented".to_string(),
        ))
    }

    fn query_upgraded_consensus_state(
        &self,
        _request: QueryUpgradedConsensusStateRequest,
    ) -> Result<(AnyConsensusState, MerkleProof), Error> {
        Err(Error::query(
            "Cardano upgraded consensus state query is not implemented".to_string(),
        ))
    }

    fn query_connections(
        &self,
        _request: QueryConnectionsRequest,
    ) -> Result<Vec<IdentifiedConnectionEnd>, Error> {
        tracing::debug!("Querying all connections");
        
        // Block on async operation
        self.rt.block_on(async {
            // Query connections from Gateway
            let response_bytes = self.gateway_client
                .query_connections()
                .await
                .map_err(|e| Error::query(format!("Failed to query connections: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::connection::v1::QueryConnectionsResponse;
            
            let response = QueryConnectionsResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode connections response: {}", e)))?;
            
            // Convert proto connections to domain types, filtering out parsing errors
            let connections: Vec<IdentifiedConnectionEnd> = response
                .connections
                .into_iter()
                .filter_map(|co| {
                    IdentifiedConnectionEnd::try_from(co.clone())
                        .map_err(|e| {
                            tracing::warn!(
                                "Connection with ID {} failed parsing. Error: {}",
                                co.id, e
                            );
                        })
                        .ok()
                })
                .collect();
            
            Ok(connections)
        })
    }

    fn query_client_connections(
        &self,
        request: QueryClientConnectionsRequest,
    ) -> Result<Vec<ConnectionId>, Error> {
        tracing::debug!("Querying connections for client: {}", request.client_id);
        
        // Block on async operation
        self.rt.block_on(async {
            // Query client connections from Gateway
            let response_bytes = self.gateway_client
                .query_client_connections(&request.client_id.to_string())
                .await
                .map_err(|e| {
                    // If not found, return empty list
                    if e.to_string().contains("NotFound") {
                        return Error::query("Client connections not found".to_string());
                    }
                    Error::query(format!("Failed to query client connections: {}", e))
                })?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::connection::v1::QueryClientConnectionsResponse;
            use std::str::FromStr;
            
            let response = QueryClientConnectionsResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode client connections response: {}", e)))?;
            
            // Parse connection_paths strings into ConnectionId instances
            let connection_ids: Vec<ConnectionId> = response
                .connection_paths
                .iter()
                .filter_map(|id| {
                    ConnectionId::from_str(id)
                        .map_err(|e| {
                            tracing::warn!(
                                "Connection with ID {} failed parsing. Error: {}",
                                id, e
                            );
                        })
                        .ok()
                })
                .collect();
            
            Ok(connection_ids)
        })
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
        tracing::debug!("Querying channels for connection: {}", request.connection_id);
        
        // Block on async operation
        self.rt.block_on(async {
            // Query connection channels from Gateway
            let response_bytes = self.gateway_client
                .query_connection_channels(&request.connection_id.to_string())
                .await
                .map_err(|e| Error::query(format!("Failed to query connection channels: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::channel::v1::QueryConnectionChannelsResponse;
            
            let response = QueryConnectionChannelsResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode connection channels response: {}", e)))?;
            
            // Convert proto channels to domain types, filtering out parsing errors
            let channels: Vec<IdentifiedChannelEnd> = response
                .channels
                .into_iter()
                .filter_map(|ch| {
                    IdentifiedChannelEnd::try_from(ch.clone())
                        .map_err(|e| {
                            tracing::warn!(
                                "Channel with port {} and ID {} failed parsing. Error: {}",
                                ch.port_id, ch.channel_id, e
                            );
                        })
                        .ok()
                })
                .collect();
            
            Ok(channels)
        })
    }

    fn query_channels(
        &self,
        _request: QueryChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        tracing::debug!("Querying all channels");
        
        // Block on async operation
        self.rt.block_on(async {
            // Query channels from Gateway
            let response_bytes = self.gateway_client
                .query_channels()
                .await
                .map_err(|e| Error::query(format!("Failed to query channels: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::channel::v1::QueryChannelsResponse;
            
            let response = QueryChannelsResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode channels response: {}", e)))?;
            
            // Convert proto channels to domain types, filtering out parsing errors
            let channels: Vec<IdentifiedChannelEnd> = response
                .channels
                .into_iter()
                .filter_map(|ch| {
                    IdentifiedChannelEnd::try_from(ch.clone())
                        .map_err(|e| {
                            tracing::warn!(
                                "Channel with port {} and ID {} failed parsing. Error: {}",
                                ch.port_id, ch.channel_id, e
                            );
                        })
                        .ok()
                })
                .collect();
            
            Ok(channels)
        })
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
        tracing::debug!(
            "Querying channel client state: port={}, channel={}",
            request.port_id,
            request.channel_id
        );

        self.rt.block_on(async {
            let response_bytes = self
                .gateway_client
                .query_channel_client_state(
                    &request.port_id.to_string(),
                    &request.channel_id.to_string(),
                )
                .await
                .map_err(|e| Error::query(format!("Failed to query channel client state: {e}")))?;

            use prost::Message;
            use ibc_proto::ibc::core::channel::v1::QueryChannelClientStateResponse;

            let response = QueryChannelClientStateResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode channel client state response: {e}")))?;

            let identified = response
                .identified_client_state
                .and_then(|ics| IdentifiedAnyClientState::try_from(ics).ok());

            Ok(identified)
        })
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
        tracing::info!("Querying packet commitments: port={}, channel={}", 
            request.port_id, request.channel_id);
        
        // Block on async operation
        self.rt.block_on(async {
            // Query packet commitments from Gateway
            let response_bytes = self.gateway_client
                .query_packet_commitments(&request.port_id.to_string(), &request.channel_id.to_string())
                .await
                .map_err(|e| Error::query(format!("Failed to query packet commitments: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::channel::v1::QueryPacketCommitmentsResponse;
            
            let response = QueryPacketCommitmentsResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode packet commitments response: {}", e)))?;
            
            // Extract sequences from packet_states
            let sequences: Vec<Sequence> = response.commitments
                .iter()
                .map(|state| Sequence::from(state.sequence))
                .collect();
            
            // Extract height from response
            let height = response.height
                .ok_or_else(|| Error::query("No height in packet commitments response".to_string()))?;
            
            let ics_height = ICSHeight::new(height.revision_number, height.revision_height)
                .map_err(|e| Error::query(format!("Invalid height: {}", e)))?;
            
            Ok((sequences, ics_height))
        })
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
            // Query packet receipt from Gateway
            let response_bytes = self.gateway_client
                .query_packet_receipt(&request.port_id.to_string(), &request.channel_id.to_string(), request.sequence.into())
                .await
                .map_err(|e| Error::query(format!("Failed to query packet receipt: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::channel::v1::QueryPacketReceiptResponse;
            
            let response = QueryPacketReceiptResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode packet receipt response: {}", e)))?;
            
            // The receipt is a boolean - convert to bytes
            let receipt_bytes = if response.received {
                vec![1u8]
            } else {
                vec![0u8]
            };
            
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
            
            Ok((receipt_bytes, proof))
        })
    }

    fn query_unreceived_packets(
        &self,
        request: QueryUnreceivedPacketsRequest,
    ) -> Result<Vec<Sequence>, Error> {
        tracing::info!("Querying unreceived packets: port={}, channel={}", 
            request.port_id, request.channel_id);
        
        // Block on async operation
        self.rt.block_on(async {
            // Query unreceived packets from Gateway
            let response_bytes = self.gateway_client
                .query_unreceived_packets(
                    &request.port_id.to_string(), 
                    &request.channel_id.to_string(),
                    request.packet_commitment_sequences.iter().map(|s| (*s).into()).collect()
                )
                .await
                .map_err(|e| Error::query(format!("Failed to query unreceived packets: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::channel::v1::QueryUnreceivedPacketsResponse;
            
            let response = QueryUnreceivedPacketsResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode unreceived packets response: {}", e)))?;
            
            // Extract sequences from response
            let sequences: Vec<Sequence> = response.sequences
                .iter()
                .map(|s| Sequence::from(*s))
                .collect();
            
            Ok(sequences)
        })
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
            // Query packet acknowledgement from Gateway
            let response_bytes = self.gateway_client
                .query_packet_acknowledgement(&request.port_id.to_string(), &request.channel_id.to_string(), request.sequence.into())
                .await
                .map_err(|e| Error::query(format!("Failed to query packet acknowledgement: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::channel::v1::QueryPacketAcknowledgementResponse;
            
            let response = QueryPacketAcknowledgementResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode packet acknowledgement response: {}", e)))?;
            
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
            
            Ok((response.acknowledgement, proof))
        })
    }

    fn query_packet_acknowledgements(
        &self,
        request: QueryPacketAcknowledgementsRequest,
    ) -> Result<(Vec<Sequence>, ICSHeight), Error> {
        tracing::info!("Querying packet acknowledgements: port={}, channel={}", 
            request.port_id, request.channel_id);
        
        // Block on async operation
        self.rt.block_on(async {
            // Query packet acknowledgements from Gateway
            let response_bytes = self.gateway_client
                .query_packet_acknowledgements(&request.port_id.to_string(), &request.channel_id.to_string())
                .await
                .map_err(|e| Error::query(format!("Failed to query packet acknowledgements: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::channel::v1::QueryPacketAcknowledgementsResponse;
            
            let response = QueryPacketAcknowledgementsResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode packet acknowledgements response: {}", e)))?;
            
            // Extract sequences from acknowledgements
            let sequences: Vec<Sequence> = response.acknowledgements
                .iter()
                .map(|ack| Sequence::from(ack.sequence))
                .collect();
            
            // Extract height from response
            let height = response.height
                .ok_or_else(|| Error::query("No height in packet acknowledgements response".to_string()))?;
            
            let ics_height = ICSHeight::new(height.revision_number, height.revision_height)
                .map_err(|e| Error::query(format!("Invalid height: {}", e)))?;
            
            Ok((sequences, ics_height))
        })
    }

    fn query_unreceived_acknowledgements(
        &self,
        request: QueryUnreceivedAcksRequest,
    ) -> Result<Vec<Sequence>, Error> {
        tracing::info!("Querying unreceived acknowledgements: port={}, channel={}", 
            request.port_id, request.channel_id);
        
        // Block on async operation
        self.rt.block_on(async {
            // Query unreceived acknowledgements from Gateway
            let response_bytes = self.gateway_client
                .query_unreceived_acknowledgements(
                    &request.port_id.to_string(), 
                    &request.channel_id.to_string(),
                    request.packet_ack_sequences.iter().map(|s| (*s).into()).collect()
                )
                .await
                .map_err(|e| Error::query(format!("Failed to query unreceived acknowledgements: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::channel::v1::QueryUnreceivedAcksResponse;
            
            let response = QueryUnreceivedAcksResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode unreceived acks response: {}", e)))?;
            
            // Extract sequences from response
            let sequences: Vec<Sequence> = response.sequences
                .iter()
                .map(|s| Sequence::from(*s))
                .collect();
            
            Ok(sequences)
        })
    }

    fn query_next_sequence_receive(
        &self,
        request: QueryNextSequenceReceiveRequest,
        include_proof: IncludeProof,
    ) -> Result<(Sequence, Option<MerkleProof>), Error> {
        tracing::info!("Querying next sequence receive: port={}, channel={}", 
            request.port_id, request.channel_id);
        
        // Block on async operation
        self.rt.block_on(async {
            // Query next sequence receive from Gateway
            let response_bytes = self.gateway_client
                .query_next_sequence_receive(&request.port_id.to_string(), &request.channel_id.to_string())
                .await
                .map_err(|e| Error::query(format!("Failed to query next sequence receive: {}", e)))?;
            
            // Decode the response
            use prost::Message;
            use ibc_proto::ibc::core::channel::v1::QueryNextSequenceReceiveResponse;
            
            let response = QueryNextSequenceReceiveResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode next sequence receive response: {}", e)))?;
            
            let sequence = Sequence::from(response.next_sequence_receive);
            
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
            
            Ok((sequence, proof))
        })
    }

    fn query_txs(&self, _request: QueryTxRequest) -> Result<Vec<IbcEventWithHeight>, Error> {
        use crate::chain::requests::{QueryHeight, QueryTxRequest};
        use ibc_relayer_types::events::WithBlockDataType;

        match _request {
            QueryTxRequest::Transaction(tx) => {
                self.rt.block_on(async {
                    let response = self
                        .gateway_client
                        .query_transaction_by_hash(tx.0.to_string())
                        .await
                        .map_err(|e| Error::query(format!("Failed to query transaction by hash: {e}")))?;

                    let height = ICSHeight::new(0, response.height)
                        .map_err(|e| Error::query(format!("Invalid tx height {}: {e}", response.height)))?;

                    let proto_events: Vec<super::generated::ibc::cardano::v1::Event> = response
                        .events
                        .into_iter()
                        .map(|e| super::generated::ibc::cardano::v1::Event {
                            r#type: e.r#type,
                            attributes: e
                                .event_attribute
                                .into_iter()
                                .map(|a| super::generated::ibc::cardano::v1::EventAttribute {
                                    key: a.key,
                                    value: a.value,
                                })
                                .collect(),
                        })
                        .collect();

                    let parsed_events = super::event_parser::parse_events(proto_events, height)
                        .map_err(|e| Error::query(format!("Failed to parse tx events: {e}")))?;

                    Ok(parsed_events
                        .into_iter()
                        .map(|ev| IbcEventWithHeight::new(ev, height))
                        .collect())
                })
            }

            QueryTxRequest::Client(request) => {
                self.rt.block_on(async {
                    const LOOKBACK_WINDOW: u64 = 50;

                    let filter_events = |height: ICSHeight,
                                         proto_events: Vec<super::generated::ibc::cardano::v1::Event>|
                     -> Result<Vec<IbcEventWithHeight>, Error> {
                        let parsed_events = super::event_parser::parse_events(proto_events, height)
                            .map_err(|e| Error::query(format!("Failed to parse tx events: {e}")))?;

                        Ok(parsed_events
                            .into_iter()
                            .filter(|ev| match (&request.event_id, ev) {
                                (
                                    WithBlockDataType::CreateClient,
                                    ibc_relayer_types::events::IbcEvent::CreateClient(e),
                                ) => e.client_id() == &request.client_id
                                    && e.0.consensus_height == request.consensus_height,
                                (
                                    WithBlockDataType::UpdateClient,
                                    ibc_relayer_types::events::IbcEvent::UpdateClient(e),
                                ) => e.common.client_id == request.client_id
                                    && e.common.consensus_height == request.consensus_height,
                                _ => false,
                            })
                            .map(|ev| IbcEventWithHeight::new(ev, height))
                            .collect())
                    };

                    match request.query_height {
                        QueryHeight::Specific(h) => {
                            let target_height_u64 = h.revision_height();

                            let response = self
                                .gateway_client
                                .query_block_results(target_height_u64)
                                .await
                                .map_err(|e| Error::query(format!("Failed to query block results: {e}")))?;

                            let block_results = response
                                .block_results
                                .ok_or_else(|| Error::query("No block_results in response".to_string()))?;

                            let height = block_results
                                .height
                                .map(|h| ICSHeight::new(h.revision_number, h.revision_height))
                                .transpose()
                                .map_err(|e| Error::query(format!("Invalid height in block results: {e}")))?
                                .unwrap_or_else(|| ICSHeight::new(0, target_height_u64).expect("valid height"));

                            let proto_events: Vec<super::generated::ibc::cardano::v1::Event> = block_results
                                .txs_results
                                .into_iter()
                                .flat_map(|tx| tx.events)
                                .map(|e| super::generated::ibc::cardano::v1::Event {
                                    r#type: e.r#type,
                                    attributes: e
                                        .event_attribute
                                        .into_iter()
                                        .map(|a| super::generated::ibc::cardano::v1::EventAttribute {
                                            key: a.key,
                                            value: a.value,
                                        })
                                        .collect(),
                                })
                                .collect();

                            filter_events(height, proto_events)
                        }
                        QueryHeight::Latest => {
                            let latest = self
                                .gateway_client
                                .query_latest_height()
                                .await
                                .map_err(|e| Error::query(format!("Failed to query latest height: {e}")))?;

                            let latest_h = latest.revision_height();
                            let since_h = latest_h.saturating_sub(LOOKBACK_WINDOW);
                            let since_h = since_h.max(1);
                            let since_height = ICSHeight::new(0, since_h)
                                .map_err(|e| Error::query(format!("Invalid since height {since_h}: {e}")))?;

                            let response = self
                                .gateway_client
                                .query_events(since_height)
                                .await
                                .map_err(|e| Error::query(format!("Failed to query events: {e}")))?;

                            let mut out = Vec::new();
                            for block in response.events {
                                let height = ICSHeight::new(0, block.height)
                                    .map_err(|e| Error::query(format!("Invalid block height {}: {e}", block.height)))?;

                                let proto_events: Vec<super::generated::ibc::cardano::v1::Event> = block
                                    .events
                                    .into_iter()
                                    .flat_map(|tx| tx.events)
                                    .map(|e| super::generated::ibc::cardano::v1::Event {
                                        r#type: e.r#type,
                                        attributes: e
                                            .event_attribute
                                            .into_iter()
                                            .map(|a| super::generated::ibc::cardano::v1::EventAttribute {
                                                key: a.key,
                                                value: a.value,
                                            })
                                            .collect(),
                                    })
                                    .collect();

                                out.extend(filter_events(height, proto_events)?);
                            }

                            Ok(out)
                        }
                    }
                })
            }
        }
    }

    fn query_packet_events(
        &self,
        request: QueryPacketEventDataRequest,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        use crate::chain::requests::{Qualified, QueryHeight};

        let max_height: Option<u64> = match request.height {
            Qualified::SmallerEqual(QueryHeight::Specific(h)) => Some(h.revision_height()),
            Qualified::Equal(QueryHeight::Specific(h)) => Some(h.revision_height()),
            _ => None,
        };

        let must_equal_height: Option<u64> = match request.height {
            Qualified::Equal(QueryHeight::Specific(h)) => Some(h.revision_height()),
            _ => None,
        };

        self.rt.block_on(async {
            let mut out = Vec::new();

            // If the request targets a single height, avoid block search and inspect that block only.
            if let Some(h) = must_equal_height {
                let response = self
                    .gateway_client
                    .query_block_results(h)
                    .await
                    .map_err(|e| Error::query(format!("Failed to query block results: {e}")))?;

                out.extend(filter_packet_events_from_block_results(&request, response.block_results, h)?);
                return Ok(out);
            }

                for seq in &request.sequences {
                    let search = self
                        .gateway_client
                        .query_block_search_all(
                            request.source_channel_id.to_string(),
                            request.destination_channel_id.to_string(),
                            seq.to_string(),
                            50,
                        )
                    .await
                    .map_err(|e| Error::query(format!("Failed to search blocks: {e}")))?;

                let mut heights: Vec<u64> = search
                    .blocks
                    .into_iter()
                    .filter_map(|b| b.block.map(|bi| bi.height))
                    .filter_map(|h| u64::try_from(h).ok())
                    .collect();

                heights.sort_unstable();
                heights.dedup();

                if let Some(max_h) = max_height {
                    heights.retain(|h| *h <= max_h);
                }

                for h in heights {
                    let response = self
                        .gateway_client
                        .query_block_results(h)
                        .await
                        .map_err(|e| Error::query(format!("Failed to query block results: {e}")))?;

                    out.extend(filter_packet_events_from_block_results(&request, response.block_results, h)?);
                }
            }

            Ok(out)
        })
    }

    fn query_host_consensus_state(
        &self,
        _request: QueryHostConsensusStateRequest,
    ) -> Result<Self::ConsensusState, Error> {
        Err(Error::query(
            "Cardano host consensus state query is not implemented".to_string(),
        ))
    }

    fn build_client_state(
        &self,
        height: ICSHeight,
        _settings: ClientSettings,
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
        _light_block: Self::LightBlock,
    ) -> Result<Self::ConsensusState, Error> {
        Err(Error::query(
            "Cardano consensus state construction is not implemented for Mithril headers"
                .to_string(),
        ))
    }

    fn build_header(
        &mut self,
        _trusted_height: ICSHeight,
        target_height: ICSHeight,
        _client_state: &AnyClientState,
    ) -> Result<(Self::Header, Vec<Self::Header>), Error> {
        let header = self
            .rt
            .block_on(self.gateway_client.query_header(target_height))
            .map_err(|e| Error::query(format!("Gateway query_header failed: {e}")))?;

        Ok((header, vec![]))
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
        Err(Error::query(
            "ICS-31 cross-chain queries are not supported for Cardano".to_string(),
        ))
    }

    fn query_incentivized_packet(
        &self,
        _request: ibc_proto::ibc::apps::fee::v1::QueryIncentivizedPacketRequest,
    ) -> Result<ibc_proto::ibc::apps::fee::v1::QueryIncentivizedPacketResponse, Error> {
        Err(Error::query(
            "ICS-29 fee middleware is not supported for Cardano".to_string(),
        ))
    }

    fn query_consumer_chains(&self) -> Result<Vec<ibc_relayer_types::applications::ics28_ccv::msgs::ConsumerChain>, Error> {
        Err(Error::query(
            "ICS-28 CCV (Cross-Chain Validation) is not applicable to Cardano".to_string(),
        ))
    }

    fn query_upgrade(
        &self,
        _request: ibc_proto::ibc::core::channel::v1::QueryUpgradeRequest,
        _height: ibc_relayer_types::Height,
        _include_proof: IncludeProof,
    ) -> Result<(ibc_relayer_types::core::ics04_channel::upgrade::Upgrade, Option<MerkleProof>), Error> {
        Err(Error::query(
            "IBC channel upgrades are not implemented for Cardano".to_string(),
        ))
    }

    fn query_upgrade_error(
        &self,
        _request: ibc_proto::ibc::core::channel::v1::QueryUpgradeErrorRequest,
        _height: ibc_relayer_types::Height,
        _include_proof: IncludeProof,
    ) -> Result<(ibc_relayer_types::core::ics04_channel::upgrade::ErrorReceipt, Option<MerkleProof>), Error> {
        Err(Error::query(
            "IBC channel upgrades are not implemented for Cardano".to_string(),
        ))
    }

    fn query_ccv_consumer_id(
        &self,
        _client_id: ClientId,
    ) -> Result<ibc_relayer_types::applications::ics28_ccv::msgs::ConsumerId, Error> {
        Err(Error::query(
            "ICS-28 CCV (Cross-Chain Validation) is not applicable to Cardano".to_string(),
        ))
    }
}

fn filter_packet_events_from_block_results(
    request: &QueryPacketEventDataRequest,
    block_results: Option<super::generated::ibc::core::types::v1::ResultBlockResults>,
    fallback_height: u64,
) -> Result<Vec<IbcEventWithHeight>, Error> {
    use ibc_relayer_types::events::{IbcEvent as RelayerIbcEvent, WithBlockDataType};

    let block_results = match block_results {
        Some(br) => br,
        None => return Ok(vec![]),
    };

    let height = block_results
        .height
        .map(|h| ICSHeight::new(h.revision_number, h.revision_height))
        .transpose()
        .map_err(|e| Error::query(format!("Invalid height in block results: {e}")))?
        .unwrap_or_else(|| ICSHeight::new(0, fallback_height).expect("valid height"));

    let proto_events: Vec<super::generated::ibc::cardano::v1::Event> = block_results
        .txs_results
        .into_iter()
        .flat_map(|tx| tx.events)
        .map(|e| super::generated::ibc::cardano::v1::Event {
            r#type: e.r#type,
            attributes: e
                .event_attribute
                .into_iter()
                .map(|a| super::generated::ibc::cardano::v1::EventAttribute {
                    key: a.key,
                    value: a.value,
                })
                .collect(),
        })
        .collect();

    let parsed_events = super::event_parser::parse_events(proto_events, height)
        .map_err(|e| Error::query(format!("Failed to parse block events: {e}")))?;

    let filtered: Vec<IbcEventWithHeight> = parsed_events
        .into_iter()
        .filter(|ev| match (&request.event_id, ev) {
            (WithBlockDataType::SendPacket, RelayerIbcEvent::SendPacket(e)) => {
                request.sequences.contains(&e.packet.sequence)
                    && e.src_port_id() == &request.source_port_id
                    && e.src_channel_id() == &request.source_channel_id
                    && e.dst_port_id() == &request.destination_port_id
                    && e.dst_channel_id() == &request.destination_channel_id
            }
            (WithBlockDataType::WriteAck, RelayerIbcEvent::WriteAcknowledgement(e)) => {
                request.sequences.contains(&e.packet.sequence)
                    && e.src_port_id() == &request.source_port_id
                    && e.src_channel_id() == &request.source_channel_id
                    && e.dst_port_id() == &request.destination_port_id
                    && e.dst_channel_id() == &request.destination_channel_id
            }
            _ => false,
        })
        .map(|ev| IbcEventWithHeight::new(ev, height))
        .collect();

    Ok(filtered)
}

// Mithril header is decoded from Gateway as `google.protobuf.Any`.
// in ibc-relayer-types/src/clients/ics08_cardano/header.rs and
// ibc-relayer-types/src/core/ics02_client/header.rs respectively
