//! Cardano ChainEndpoint implementation for Hermes
//!
//! This module implements the ChainEndpoint trait required by Hermes for custom chain support.

use super::config::CardanoConfig;
use super::gateway_client::GatewayClient;
use super::signing_key_pair::CardanoSigningKeyPair;

use ibc_relayer_types::clients::ics08_cardano::consensus_state::ConsensusState as MithrilConsensusState;
use ibc_relayer_types::clients::ics08_cardano::misbehaviour::Misbehaviour as MithrilMisbehaviour;
use ibc_relayer_types::clients::ics08_cardano_probabilistic::consensus_state::ConsensusState as ProbabilisticConsensusState;
use ibc_relayer_types::clients::ics08_cardano_probabilistic::misbehaviour::Misbehaviour as ProbabilisticMisbehaviour;

use crate::account::Balance;
use crate::chain::client::ClientSettings;
use crate::chain::cosmos::version::Specs as CosmosSpecs;
use crate::chain::endpoint::{ChainEndpoint, ChainStatus, HealthCheck, HostStateHeartbeatOutcome};
use crate::chain::handle::Subscription;
use crate::chain::requests::{
    CrossChainQueryRequest, IncludeProof, QueryChannelClientStateRequest, QueryChannelRequest,
    QueryChannelsRequest, QueryClientConnectionsRequest, QueryClientStateRequest,
    QueryClientStatesRequest, QueryConnectionChannelsRequest, QueryConnectionRequest,
    QueryConnectionsRequest, QueryConsensusStateHeightsRequest, QueryConsensusStateRequest,
    QueryHeight, QueryHostConsensusStateRequest, QueryNextSequenceReceiveRequest,
    QueryPacketAcknowledgementRequest, QueryPacketAcknowledgementsRequest,
    QueryPacketCommitmentRequest, QueryPacketCommitmentsRequest, QueryPacketEventDataRequest,
    QueryPacketReceiptRequest, QueryTxRequest, QueryUnreceivedAcksRequest,
    QueryUnreceivedPacketsRequest, QueryUpgradedClientStateRequest,
    QueryUpgradedConsensusStateRequest,
};
use crate::chain::tracking::TrackedMsgs;
use crate::chain::version::Specs;
use crate::client_state::{AnyClientState, IdentifiedAnyClientState};
use crate::config::{ChainConfig, Error as ConfigError};
use crate::consensus_state::AnyConsensusState;
use crate::denom::DenomTrace;
use crate::error::Error;
use crate::event::IbcEventWithHeight;
use crate::keyring::{KeyRing, SigningKeyPair};
use crate::misbehaviour::{AnyMisbehaviour, MisbehaviourEvidence};
use ibc_proto::ibc::core::channel::v1::{
    QueryNextSequenceReceiveResponse, QueryPacketAcknowledgementResponse,
    QueryPacketCommitmentResponse, QueryPacketReceiptResponse,
};
use ibc_relayer_types::core::ics02_client::events::UpdateClient;
use ibc_relayer_types::core::ics02_client::header::{AnyHeader, Header as IbcHeader};
use ibc_relayer_types::core::ics03_connection::connection::{
    ConnectionEnd, IdentifiedConnectionEnd,
};
use ibc_relayer_types::core::ics04_channel::channel::{ChannelEnd, IdentifiedChannelEnd};
use ibc_relayer_types::core::ics04_channel::packet::{PacketMsgType, Sequence};
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentRoot;
use ibc_relayer_types::core::ics23_commitment::commitment::{
    CommitmentPrefix, CommitmentProofBytes,
};
use ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof;
use ibc_relayer_types::core::ics24_host::identifier::{
    ChainId, ChannelId, ClientId, ConnectionId, PortId,
};
use ibc_relayer_types::proofs::Proofs;
use ibc_relayer_types::signer::Signer;
use ibc_relayer_types::Height as ICSHeight;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tendermint_rpc::endpoint::broadcast::tx_sync::Response as TxResponse;
use tokio::runtime::Runtime as TokioRuntime;

/// Cardano light block (placeholder)
#[derive(Debug, Clone)]
pub struct CardanoLightBlock {
    pub header: Option<AnyHeader>,
    pub height: ICSHeight,
    pub host_state_nft_policy_id: Vec<u8>,
    pub host_state_nft_token_name: Vec<u8>,
}

// CardanoSigningKeyPair is now defined in signing_key_pair.rs
// From<CardanoSigningKeyPair> for AnySigningKeyPair is implemented in ibc-relayer/src/keyring/any_signing_key_pair.rs

/// Cardano ChainEndpoint implementation
pub struct CardanoChainEndpoint {
    config: CardanoConfig,
    rt: Arc<TokioRuntime>,
    gateway_client: GatewayClient,
    witness_gateway_client: Option<GatewayClient>,
    keyring: KeyRing<CardanoSigningKeyPair>,
    event_source_cmd: Option<crate::event::source::TxEventSourceCmd>,
    pending_new_client_consensus_states: Mutex<HashMap<u64, AnyConsensusState>>,
}

fn gateway_query_height(query_height: QueryHeight) -> Option<ICSHeight> {
    match query_height {
        QueryHeight::Latest => None,
        QueryHeight::Specific(height) => Some(height),
    }
}

fn assert_gateway_proof_height(
    context: &str,
    response_proof_height: Option<ibc_proto::ibc::core::client::v1::Height>,
    expected_height: Option<ICSHeight>,
) -> Result<(), Error> {
    let Some(expected_height) = expected_height else {
        return Ok(());
    };

    let proof_height = response_proof_height.ok_or_else(|| {
        Error::query(format!(
            "Gateway {context} response missing proof_height for requested height {expected_height}"
        ))
    })?;

    if proof_height.revision_number != expected_height.revision_number()
        || proof_height.revision_height != expected_height.revision_height()
    {
        return Err(Error::query(format!(
            "Gateway {context} proof height mismatch: requested {}, got {}-{}",
            expected_height, proof_height.revision_number, proof_height.revision_height
        )));
    }

    Ok(())
}

impl CardanoChainEndpoint {
    /// Sign a transaction using the keyring (private helper method)
    fn sign_transaction_helper(&self, unsigned_cbor_hex: &str) -> Result<String, Error> {
        use super::signer;

        // Convert hex to bytes
        let unsigned_tx_bytes = hex::decode(unsigned_cbor_hex)
            .map_err(|e| Error::send_tx(format!("Failed to decode unsigned tx hex: {}", e)))?;

        // Get signing key from keyring
        let key = self
            .keyring
            .get_key(&self.config.key_name)
            .map_err(Error::key_base)?;

        // Get the CardanoSigningKeyPair and extract the CardanoKeyring
        let signing_key_pair = key
            .as_any()
            .downcast_ref::<CardanoSigningKeyPair>()
            .ok_or_else(|| {
                Error::send_tx("Failed to downcast to CardanoSigningKeyPair".to_string())
            })?;
        let cardano_keyring = signing_key_pair
            .get_cardano_keyring()
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
        let poll_interval = self
            .config
            .event_poll_interval
            .unwrap_or_else(|| Duration::from_secs(5));

        let (event_source, monitor_tx) = CardanoEventSource::new(
            self.config.id.clone(),
            self.gateway_client.clone(),
            poll_interval,
            self.config.event_replay_window,
            self.rt.clone(),
        )
        .map_err(Error::event_source)?;

        thread::spawn(move || event_source.run());

        tracing::info!(
            "Event source initialized, polling every {:?}",
            poll_interval
        );

        Ok(monitor_tx)
    }

    fn query_packet_commitment_response(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<QueryPacketCommitmentResponse, Error> {
        self.rt.block_on(async {
            let response_bytes = self
                .gateway_client
                .query_packet_commitment(
                    port_id.as_ref(),
                    channel_id.as_ref(),
                    sequence.into(),
                    None,
                )
                .await
                .map_err(|e| Error::query(format!("Failed to query packet commitment: {}", e)))?;

            prost::Message::decode(&response_bytes[..]).map_err(|e| {
                Error::query(format!(
                    "Failed to decode packet commitment response: {}",
                    e
                ))
            })
        })
    }

    fn query_packet_acknowledgement_response(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<QueryPacketAcknowledgementResponse, Error> {
        self.rt.block_on(async {
            let response_bytes = self
                .gateway_client
                .query_packet_acknowledgement(
                    port_id.as_ref(),
                    channel_id.as_ref(),
                    sequence.into(),
                    None,
                )
                .await
                .map_err(|e| {
                    Error::query(format!("Failed to query packet acknowledgement: {}", e))
                })?;

            prost::Message::decode(&response_bytes[..]).map_err(|e| {
                Error::query(format!(
                    "Failed to decode packet acknowledgement response: {}",
                    e
                ))
            })
        })
    }

    fn query_packet_receipt_response(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<QueryPacketReceiptResponse, Error> {
        self.rt.block_on(async {
            let response_bytes = self
                .gateway_client
                .query_packet_receipt(port_id.as_ref(), channel_id.as_ref(), sequence.into(), None)
                .await
                .map_err(|e| Error::query(format!("Failed to query packet receipt: {}", e)))?;

            prost::Message::decode(&response_bytes[..]).map_err(|e| {
                Error::query(format!("Failed to decode packet receipt response: {}", e))
            })
        })
    }

    fn query_next_sequence_receive_response(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<QueryNextSequenceReceiveResponse, Error> {
        self.rt.block_on(async {
            let response_bytes = self
                .gateway_client
                .query_next_sequence_receive(port_id.as_ref(), channel_id.as_ref(), None)
                .await
                .map_err(|e| {
                    Error::query(format!("Failed to query next sequence receive: {}", e))
                })?;

            prost::Message::decode(&response_bytes[..]).map_err(|e| {
                Error::query(format!(
                    "Failed to decode next sequence receive response: {}",
                    e
                ))
            })
        })
    }

    /// Wait until the Gateway's "latest height" has caught up to (or passed) a specific
    /// Cardano transaction inclusion height.
    ///
    /// Why this exists:
    /// - The Gateway returns a transaction `height` in `submit_signed_tx` based on `db-sync`'s
    ///   `block_no` for the block that included the transaction.
    /// - Separately, for Cardano↔Cosmos IBC, the Cosmos-side light client only accepts heights
    ///   that satisfy the active Gateway light-client mode. In Mithril mode this is a certified
    ///   transaction snapshot block number; in probabilistic mode it is a heuristically accepted
    ///   Cardano block number.
    ///
    /// If Hermes proceeds immediately after inclusion, it may query proofs at a height that the
    /// Cosmos-side client has not yet been updated to, or worse: it may receive proofs that are
    /// valid for a newer on-chain HostState root but are being verified against an older accepted
    /// root. That shows up as "proof does not match ibc_state_root".
    ///
    /// To avoid this class of race, we treat "commit" for Cardano transactions as "included AND
    /// accepted by the Gateway's current light-client mode".
    async fn wait_for_gateway_accepted_height(
        &self,
        included_height: ICSHeight,
    ) -> Result<ICSHeight, Error> {
        let poll_interval = self.config.mithril_poll_interval;
        let timeout = self.config.mithril_certification_timeout;
        let log_interval = self.config.mithril_wait_log_interval;
        let start = tokio::time::Instant::now();
        let mut last_logged_elapsed = std::time::Duration::from_secs(0);
        let mut last_latest_height: Option<u64> = None;

        loop {
            let latest = match self.gateway_client.query_latest_height().await {
                Ok(latest) => latest,
                Err(e) => {
                    let elapsed = start.elapsed();
                    if elapsed >= timeout {
                        return Err(Error::query(format!(
                            "timed out waiting for Gateway accepted height >= {} because \
                             query_latest_height kept failing: {}",
                            included_height, e,
                        )));
                    }

                    let should_log = elapsed.saturating_sub(last_logged_elapsed) >= log_interval;
                    if should_log {
                        let remaining = timeout.saturating_sub(elapsed);
                        tracing::warn!(
                            "Waiting for Gateway accepted height: latest-height query unavailable \
                             while waiting for >= {}: {}, elapsed={}s, remaining={}s",
                            included_height,
                            e,
                            elapsed.as_secs(),
                            remaining.as_secs(),
                        );
                        last_logged_elapsed = elapsed;
                    }

                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
            };

            if latest.revision_number() != included_height.revision_number() {
                return Err(Error::query(format!(
                    "gateway returned revision_number={} but expected revision_number={}",
                    latest.revision_number(),
                    included_height.revision_number()
                )));
            }

            if latest.revision_height() >= included_height.revision_height() {
                return Ok(latest);
            }

            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Err(Error::send_tx(format!(
                    "timed out waiting for Gateway-accepted height >= {} (latest={}). \
                     Note: for Cardano, Height.revision_height is a block-number based height in both Mithril and probabilistic modes.",
                    included_height, latest,
                )));
            }

            let latest_height = latest.revision_height();
            let required_height = included_height.revision_height();
            let missing_blocks = required_height.saturating_sub(latest_height);

            let latest_changed = last_latest_height
                .map(|prev| prev != latest_height)
                .unwrap_or(true);
            let should_log =
                latest_changed || elapsed.saturating_sub(last_logged_elapsed) >= log_interval;

            if should_log {
                let remaining = timeout.saturating_sub(elapsed);
                let log_msg = format!(
                    "Waiting for Gateway accepted height: need >= {} (missing {} blocks), have {}, elapsed={}s, remaining={}s",
                    included_height,
                    missing_blocks,
                    latest,
                    elapsed.as_secs(),
                    remaining.as_secs(),
                );

                if remaining <= log_interval {
                    tracing::warn!("{log_msg}");
                } else {
                    tracing::info!("{log_msg}");
                }

                last_logged_elapsed = elapsed;
            }

            last_latest_height = Some(latest_height);
            tokio::time::sleep(poll_interval).await;
        }
    }
}

impl ChainEndpoint for CardanoChainEndpoint {
    type LightBlock = CardanoLightBlock;
    type Header = AnyHeader;
    type ConsensusState = AnyConsensusState;
    type ClientState = AnyClientState;
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

        let witness_gateway_client =
            if let Some(witness_url) = cardano_config.misbehaviour_witness_gateway_url.as_ref() {
                tracing::info!(
                    "Initializing Cardano misbehaviour witness Gateway: {}",
                    witness_url
                );
                Some(
                    rt.block_on(GatewayClient::new(witness_url.clone()))
                        .map_err(|e| {
                            tracing::error!(
                                "Failed to initialize Cardano misbehaviour witness Gateway: {}",
                                e
                            );
                            Error::config(ConfigError::wrong_type())
                        })?,
                )
            } else {
                tracing::warn!(
                    "Cardano misbehaviour witness Gateway not configured; using primary Gateway. \
                     This only detects local inconsistencies and is not an independent witness."
                );
                None
            };

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
            witness_gateway_client,
            keyring,
            event_source_cmd: None, // Initialized lazily on first subscribe() call
            pending_new_client_consensus_states: Mutex::new(HashMap::new()),
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
            Ok(height) => {
                tracing::debug!(
                    "Cardano Gateway latest-height health probe succeeded at {}",
                    height
                );
                Ok(HealthCheck::Healthy)
            }
            Err(latest_height_error) => {
                tracing::warn!(
                    "Gateway latest-height probe failed during Cardano health-check: {}. Latest height is required for Cardano relayer operation.",
                    latest_height_error
                );

                let client_states_result = self
                    .rt
                    .block_on(self.gateway_client.query_clients())
                    .map(|_| ());

                match &client_states_result {
                    Ok(()) => {
                        tracing::warn!(
                            "Cardano Gateway client-states probe succeeded, but endpoint remains unhealthy because latest-height failed."
                        )
                    }
                    Err(client_states_error) => {
                        tracing::warn!(
                            "Cardano Gateway client-states probe also failed during health-check: {}",
                            client_states_error
                        )
                    }
                }

                Ok(HealthCheck::Unhealthy(Box::new(
                    cardano_latest_height_unhealthy_error(
                        &latest_height_error,
                        client_states_result,
                    ),
                )))
            }
        }
    }

    fn subscribe(&mut self) -> Result<Subscription, Error> {
        if self.event_source_cmd.is_none() {
            self.event_source_cmd = Some(self.init_event_source()?);
        }

        let event_source_cmd = self.event_source_cmd.as_ref().ok_or_else(|| {
            Error::event_source(crate::event::source::Error::collect_events_failed(
                "Cardano event source command missing after initialization".to_string(),
            ))
        })?;

        let subscription = event_source_cmd.subscribe().map_err(Error::event_source)?;
        Ok(subscription)
    }

    fn keybase(&self) -> &KeyRing<Self::SigningKeyPair> {
        &self.keyring
    }

    fn keybase_mut(&mut self) -> &mut KeyRing<Self::SigningKeyPair> {
        &mut self.keyring
    }

    fn get_signer(&self) -> Result<Signer, Error> {
        let key = self
            .keyring
            .get_key(&self.config.key_name)
            .map_err(Error::key_base)?;

        let cardano_keyring = key.get_cardano_keyring().map_err(Error::key_base)?;
        let address = cardano_keyring.address(self.config.network_id);

        Signer::from_str(&address).map_err(|e| {
            Error::key_base(crate::keyring::errors::Error::invalid_mnemonic(
                anyhow::anyhow!("Invalid signer address: {e}"),
            ))
        })
    }

    fn get_key(&self) -> Result<Self::SigningKeyPair, Error> {
        // Get the signing key pair from keyring
        self.keyring
            .get_key(&self.config.key_name)
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
        tracing::info!(
            "send_messages_and_wait_commit: processing {} messages",
            tracked_msgs.msgs.len()
        );

        // Block on async operations using the runtime
        self.rt.block_on(async {
            let mut all_events = Vec::new();

            for msg in tracked_msgs.msgs.iter() {
                tracing::debug!("Processing message type: {:?}", msg.type_url);

                // Step 1: Build unsigned transaction via Gateway
                let unsigned_tx = self
                    .gateway_client
                    .build_ibc_tx(&msg.type_url, msg.value.clone())
                    .await
                    .map_err(|e| Error::send_tx(format!("Failed to build transaction: {}", e)))?;

                tracing::debug!("Built unsigned tx: {}", unsigned_tx.description);

                // Step 2: Sign transaction with keyring
                let signed_cbor_hex = self.sign_transaction_helper(&unsigned_tx.cbor_hex)?;

                tracing::debug!("Signed transaction, CBOR length: {}", signed_cbor_hex.len());

                // Step 3: Submit signed transaction via Gateway
                let tx_response = self
                    .gateway_client
                    .submit_signed_tx(&signed_cbor_hex)
                    .await
                    .map_err(|e| Error::send_tx(format!("Failed to submit transaction: {}", e)))?;

                let tx_hash = tx_response.tx_hash.clone();
                let event_count = tx_response.events.len();

                if event_count == 0 {
                    tracing::warn!("Transaction {} produced no gateway events", tx_hash);
                } else {
                    tracing::info!(
                        "Transaction {} produced {} gateway events",
                        tx_hash,
                        event_count
                    );
                    tracing::debug!(
                        "Gateway events for {}: {:?}",
                        tx_hash,
                        tx_response
                            .events
                            .iter()
                            .map(|event| event.event_type.as_str())
                            .collect::<Vec<_>>()
                    );
                }

                // Step 4: Parse events from transaction result
                let included_height = tx_response.height.ok_or_else(|| {
                    Error::send_tx("No height in transaction response".to_string())
                })?;

                tracing::info!(
                    "Transaction submitted: {} at height {}",
                    tx_response.tx_hash,
                    included_height
                );

                // Ensure the transaction is also accepted by the active Cardano light-client mode
                // before we treat it as "committed" from the perspective of IBC relaying.
                let certified_height = self
                    .wait_for_gateway_accepted_height(included_height)
                    .await?;
                if certified_height.revision_height() != included_height.revision_height() {
                    tracing::info!(
                        "Transaction {} inclusion height {} is now certified at {}",
                        tx_response.tx_hash,
                        included_height,
                        certified_height
                    );
                }

                // Log all events for debugging
                for event in &tx_response.events {
                    tracing::debug!(
                        "Gateway event: type={} attributes={:?}",
                        event.event_type,
                        event.attributes
                    );
                }

                // Convert custom IbcEvent to proto Event format for parsing
                let proto_events: Vec<super::generated::ibc::cardano::v1::Event> = tx_response
                    .events
                    .into_iter()
                    .map(|e| super::generated::ibc::cardano::v1::Event {
                        r#type: e.event_type,
                        attributes: e
                            .attributes
                            .into_iter()
                            .map(
                                |(k, v)| super::generated::ibc::cardano::v1::EventAttribute {
                                    key: k,
                                    value: v,
                                },
                            )
                            .collect(),
                    })
                    .collect();

                // Parse Gateway events into Hermes IbcEvent types
                let parsed_events =
                    super::event_parser::parse_events(proto_events, certified_height).map_err(
                        |e| {
                            tracing::warn!(
                                "Failed to parse IBC events from transaction {} at {}: {}",
                                tx_hash,
                                certified_height,
                                e
                            );
                            Error::send_tx(format!("Failed to parse events: {}", e))
                        },
                    )?;

                if parsed_events.is_empty() {
                    tracing::warn!(
                        "Parsed 0 IBC events from transaction {} at {}",
                        tx_hash,
                        certified_height
                    );
                } else {
                    tracing::info!(
                        "Parsed {} IBC events from transaction {}",
                        parsed_events.len(),
                        tx_hash
                    );
                }

                // Wrap events with height
                let events_with_height: Vec<IbcEventWithHeight> = parsed_events
                    .into_iter()
                    .map(|event| IbcEventWithHeight::new(event, certified_height))
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

                let included_height = tx_response.height.ok_or_else(|| {
                    Error::send_tx(format!(
                        "No height in transaction response for {}",
                        tx_response.tx_hash
                    ))
                })?;

                let certified_height = self
                    .wait_for_gateway_accepted_height(included_height)
                    .await?;
                if certified_height.revision_height() != included_height.revision_height() {
                    tracing::info!(
                        "Transaction {} inclusion height {} is now certified at {}",
                        tx_response.tx_hash,
                        included_height,
                        certified_height
                    );
                }

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

    fn submit_host_state_heartbeat(&mut self) -> Result<HostStateHeartbeatOutcome, Error> {
        let signer = self.get_signer()?.to_string();

        self.rt.block_on(async {
            let build = self
                .gateway_client
                .build_host_state_heartbeat(&signer)
                .await
                .map_err(|e| {
                    Error::send_tx(format!("Failed to build HostState heartbeat: {e}"))
                })?;

            if !build.heartbeat_required {
                return Ok(HostStateHeartbeatOutcome::NotRequired {
                    current_epoch: build.current_epoch,
                    host_state_epoch: build.host_state_epoch,
                });
            }

            let unsigned_tx = build.unsigned_tx.ok_or_else(|| {
                Error::send_tx(format!(
                    "Gateway requires a HostState heartbeat for epoch {} but returned no unsigned transaction",
                    build.current_epoch
                ))
            })?;
            let signed_cbor_hex = self.sign_transaction_helper(&unsigned_tx.cbor_hex)?;
            let response = self
                .gateway_client
                .submit_signed_tx(&signed_cbor_hex)
                .await
                .map_err(|e| {
                    Error::send_tx(format!("Failed to submit HostState heartbeat: {e}"))
                })?;

            Ok(HostStateHeartbeatOutcome::Submitted {
                tx_hash: response.tx_hash,
                height: response.height,
                current_epoch: build.current_epoch,
                previous_host_state_epoch: build.host_state_epoch,
            })
        })
    }

    fn verify_header(
        &mut self,
        trusted: ICSHeight,
        target: ICSHeight,
        client_state: &AnyClientState,
    ) -> Result<Self::LightBlock, Error> {
        // Hermes uses `verify_header()` as part of its generic client update workflow.
        //
        // For Tendermint clients, this verifies signatures and header continuity off-chain.
        // For Cardano, we rely on on-chain verification in the Cosmos-side Cardano light client
        // implementation (the chain rejects invalid headers and proofs for the active client type).
        //
        // To keep Hermes functional without coupling it to the full Mithril verification stack
        // (which is already implemented in the on-chain client), we treat this as a best-effort
        // fetch + structural validation step:
        // - fetch the Cardano header for `target` from the Gateway
        // - return it as a CardanoLightBlock so the relayer can proceed
        //
        // TODO: Implement optional off-chain verification to avoid broadcasting invalid headers and
        // wasting fees, and to enable richer relayer-side diagnostics.
        if self
            .pending_new_client_consensus_states
            .lock()
            .expect("pending_new_client_consensus_states poisoned")
            .contains_key(&target.revision_height())
        {
            let (host_state_nft_policy_id, host_state_nft_token_name) = match client_state {
                AnyClientState::Mithril(state) => (
                    state.host_state_nft_policy_id.clone(),
                    state.host_state_nft_token_name.clone(),
                ),
                AnyClientState::Probabilistic(state) => (
                    state.host_state_nft_policy_id.clone(),
                    state.host_state_nft_token_name.clone(),
                ),
                _ => {
                    return Err(Error::query(
                        "Cardano verify_header requires a Cardano client state".to_string(),
                    ))
                }
            };

            return Ok(CardanoLightBlock {
                header: None,
                height: target,
                host_state_nft_policy_id,
                host_state_nft_token_name,
            });
        }

        let effective_trusted = normalize_header_query_trusted_height(trusted, target)?;
        tracing::info!(
            "Cardano verify_header querying Gateway header with trusted={} effective_trusted={} target={}",
            trusted,
            effective_trusted,
            target
        );
        let header = self
            .rt
            .block_on(self.gateway_client.query_header(effective_trusted, target))
            .map_err(|e| {
                Error::query(format!("failed to query Cardano header from Gateway: {e}"))
            })?;

        let (host_state_nft_policy_id, host_state_nft_token_name) = match client_state {
            AnyClientState::Mithril(state) => (
                state.host_state_nft_policy_id.clone(),
                state.host_state_nft_token_name.clone(),
            ),
            AnyClientState::Probabilistic(state) => (
                state.host_state_nft_policy_id.clone(),
                state.host_state_nft_token_name.clone(),
            ),
            _ => {
                return Err(Error::query(
                    "Cardano verify_header requires a Cardano client state".to_string(),
                ))
            }
        };

        Ok(CardanoLightBlock {
            header: Some(header),
            height: target,
            host_state_nft_policy_id,
            host_state_nft_token_name,
        })
    }

    fn check_misbehaviour(
        &mut self,
        update: &UpdateClient,
        client_state: &AnyClientState,
    ) -> Result<Option<MisbehaviourEvidence>, Error> {
        let Some(submitted_header) = submitted_cardano_update_header(
            update,
            self.config.require_update_event_headers_for_misbehaviour,
        )?
        else {
            return Ok(None);
        };

        let target_height = submitted_header.height();
        let trusted_height = independent_header_trusted_height(submitted_header)?;
        let witness_gateway_client = self
            .witness_gateway_client
            .as_ref()
            .unwrap_or(&self.gateway_client);
        if self.witness_gateway_client.is_none() {
            tracing::warn!(
                "Cardano misbehaviour witness Gateway not configured; using primary Gateway for client {} at height {}. \
                 This only detects local inconsistencies and is not an independent witness.",
                update.client_id(),
                target_height
            );
        }

        let witness_header = self
            .rt
            .block_on(witness_gateway_client.query_header(trusted_height, target_height))
            .map_err(|e| {
                Error::query(format!(
                    "failed to independently query Cardano header at {target_height}: {e}"
                ))
            })?;

        cardano_misbehaviour_evidence(update, submitted_header, witness_header, client_state)
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

        // Query the latest proof/accepted height from Gateway. In probabilistic mode this is the
        // latest accepted HostState anchor height.
        let height = self
            .rt
            .block_on(self.gateway_client.query_latest_height())
            .map_err(|e| {
                tracing::error!("Failed to query latest height: {}", e);
                Error::query(format!("Gateway query_latest_height failed: {}", e))
            })?;

        tracing::info!("Cardano chain at height: {}", height);

        // The status timestamp must match the accepted Cardano header at `height`.
        // Hermes uses this timestamp to classify a packet as recv-vs-timeout.
        // Returning local wall-clock time here can cause Hermes to build a timeout
        // even when the source chain still sees the destination client timestamp as earlier.
        let trusted_height = height.decrement().unwrap_or(height);
        let header = self
            .rt
            .block_on(self.gateway_client.query_header(trusted_height, height))
            .map_err(|e| {
                tracing::error!(
                    "Failed to query Cardano header for application status at {}: {}",
                    height,
                    e
                );
                Error::query(format!(
                    "Gateway query_header failed for application status at {height}: {e}"
                ))
            })?;
        let timestamp = header.timestamp();

        Ok(ChainStatus { height, timestamp })
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
        let gateway_height = gateway_query_height(request.height);

        let response = self
            .rt
            .block_on(
                self.gateway_client
                    .query_client_state(request.client_id.as_str(), gateway_height),
            )
            .map_err(|e| {
                tracing::error!("Failed to query client state: {}", e);
                Error::query(format!("Gateway query_client_state failed: {}", e))
            })?;

        assert_gateway_proof_height("query_client_state", response.proof_height, gateway_height)?;

        let client_state_any = response
            .client_state
            .ok_or_else(|| Error::query("No client_state in response".to_string()))?;

        let any_client_state: AnyClientState = AnyClientState::try_from(client_state_any.clone())
            .map_err(|e| {
            Error::query(format!(
                "Failed to decode client state {}: {e}",
                client_state_any.type_url
            ))
        })?;

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
        let gateway_height = gateway_query_height(request.query_height);

        let response = self
            .rt
            .block_on(self.gateway_client.query_consensus_state(
                request.client_id.as_str(),
                request.consensus_height,
                gateway_height,
            ))
            .map_err(|e| {
                tracing::error!("Failed to query consensus state: {}", e);
                Error::query(format!("Gateway query_consensus_state failed: {}", e))
            })?;

        assert_gateway_proof_height(
            "query_consensus_state",
            response.proof_height,
            gateway_height,
        )?;

        let consensus_state_any = response
            .consensus_state
            .ok_or_else(|| Error::query("No consensus_state in response".to_string()))?;

        let any_consensus_state: AnyConsensusState =
            AnyConsensusState::try_from(consensus_state_any.clone()).map_err(|e| {
                Error::query(format!(
                    "Failed to decode consensus state {}: {e}",
                    consensus_state_any.type_url
                ))
            })?;

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
            let response_bytes = self
                .gateway_client
                .query_connections()
                .await
                .map_err(|e| Error::query(format!("Failed to query connections: {}", e)))?;

            // Decode the response
            use ibc_proto::ibc::core::connection::v1::QueryConnectionsResponse;
            use prost::Message;

            let response = QueryConnectionsResponse::decode(&response_bytes[..]).map_err(|e| {
                Error::query(format!("Failed to decode connections response: {}", e))
            })?;

            // Convert proto connections to domain types, filtering out parsing errors
            let connections: Vec<IdentifiedConnectionEnd> = response
                .connections
                .into_iter()
                .filter_map(|co| {
                    IdentifiedConnectionEnd::try_from(co.clone())
                        .map_err(|e| {
                            tracing::warn!(
                                "Connection with ID {} failed parsing. Error: {}",
                                co.id,
                                e
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
            let response_bytes = self
                .gateway_client
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
            use ibc_proto::ibc::core::connection::v1::QueryClientConnectionsResponse;
            use prost::Message;
            use std::str::FromStr;

            let response =
                QueryClientConnectionsResponse::decode(&response_bytes[..]).map_err(|e| {
                    Error::query(format!(
                        "Failed to decode client connections response: {}",
                        e
                    ))
                })?;

            // Parse connection_paths strings into ConnectionId instances
            let connection_ids: Vec<ConnectionId> = response
                .connection_paths
                .iter()
                .filter_map(|id| {
                    ConnectionId::from_str(id)
                        .map_err(|e| {
                            tracing::warn!(
                                "Connection with ID {} failed parsing. Error: {}",
                                id,
                                e
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
        let gateway_height = gateway_query_height(request.height);

        // Block on async operation
        self.rt.block_on(async {
            // Query connection from Gateway
            let response_bytes = self
                .gateway_client
                .query_connection(&request.connection_id.to_string(), gateway_height)
                .await
                .map_err(|e| Error::query(format!("Failed to query connection: {}", e)))?;

            // Decode the response
            use ibc_proto::ibc::core::connection::v1::QueryConnectionResponse;
            use prost::Message;

            let response = QueryConnectionResponse::decode(&response_bytes[..]).map_err(|e| {
                Error::query(format!("Failed to decode connection response: {}", e))
            })?;
            assert_gateway_proof_height("query_connection", response.proof_height, gateway_height)?;

            let connection_end = response
                .connection
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
        tracing::debug!(
            "Querying channels for connection: {}",
            request.connection_id
        );

        // Block on async operation
        self.rt.block_on(async {
            // Query connection channels from Gateway
            let response_bytes = self
                .gateway_client
                .query_connection_channels(&request.connection_id.to_string())
                .await
                .map_err(|e| Error::query(format!("Failed to query connection channels: {}", e)))?;

            // Decode the response
            use ibc_proto::ibc::core::channel::v1::QueryConnectionChannelsResponse;
            use prost::Message;

            let response =
                QueryConnectionChannelsResponse::decode(&response_bytes[..]).map_err(|e| {
                    Error::query(format!(
                        "Failed to decode connection channels response: {}",
                        e
                    ))
                })?;

            // Convert proto channels to domain types, filtering out parsing errors
            let channels: Vec<IdentifiedChannelEnd> = response
                .channels
                .into_iter()
                .filter_map(|ch| {
                    IdentifiedChannelEnd::try_from(ch.clone())
                        .map_err(|e| {
                            tracing::warn!(
                                "Channel with port {} and ID {} failed parsing. Error: {}",
                                ch.port_id,
                                ch.channel_id,
                                e
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
            let response_bytes = self
                .gateway_client
                .query_channels()
                .await
                .map_err(|e| Error::query(format!("Failed to query channels: {}", e)))?;

            // Decode the response
            use ibc_proto::ibc::core::channel::v1::QueryChannelsResponse;
            use prost::Message;

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
                                ch.port_id,
                                ch.channel_id,
                                e
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
        tracing::info!(
            "Querying channel: port={}, channel={}",
            request.port_id,
            request.channel_id
        );
        let gateway_height = gateway_query_height(request.height);

        // Block on async operation
        self.rt.block_on(async {
            // Query channel from Gateway
            let response_bytes = self
                .gateway_client
                .query_channel(
                    request.port_id.as_ref(),
                    request.channel_id.as_ref(),
                    gateway_height,
                )
                .await
                .map_err(|e| Error::query(format!("Failed to query channel: {}", e)))?;

            // Decode the response
            use ibc_proto::ibc::core::channel::v1::QueryChannelResponse;
            use prost::Message;

            let response = QueryChannelResponse::decode(&response_bytes[..])
                .map_err(|e| Error::query(format!("Failed to decode channel response: {}", e)))?;
            assert_gateway_proof_height("query_channel", response.proof_height, gateway_height)?;

            let channel_proto = response
                .channel
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
                .query_channel_client_state(request.port_id.as_ref(), request.channel_id.as_ref())
                .await
                .map_err(|e| Error::query(format!("Failed to query channel client state: {e}")))?;

            use ibc_proto::ibc::core::channel::v1::QueryChannelClientStateResponse;
            use prost::Message;

            let response =
                QueryChannelClientStateResponse::decode(&response_bytes[..]).map_err(|e| {
                    Error::query(format!(
                        "Failed to decode channel client state response: {e}"
                    ))
                })?;

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
        tracing::info!(
            "Querying packet commitment: port={}, channel={}, sequence={}",
            request.port_id,
            request.channel_id,
            request.sequence
        );
        let gateway_height = gateway_query_height(request.height);

        // Block on async operation
        self.rt.block_on(async {
            // Query packet commitment from Gateway
            let response_bytes = self
                .gateway_client
                .query_packet_commitment(
                    request.port_id.as_ref(),
                    request.channel_id.as_ref(),
                    request.sequence.into(),
                    gateway_height,
                )
                .await
                .map_err(|e| Error::query(format!("Failed to query packet commitment: {}", e)))?;

            // Decode the response
            use ibc_proto::ibc::core::channel::v1::QueryPacketCommitmentResponse;
            use prost::Message;

            let response =
                QueryPacketCommitmentResponse::decode(&response_bytes[..]).map_err(|e| {
                    Error::query(format!(
                        "Failed to decode packet commitment response: {}",
                        e
                    ))
                })?;
            assert_gateway_proof_height(
                "query_packet_commitment",
                response.proof_height,
                gateway_height,
            )?;

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
        tracing::info!(
            "Querying packet commitments: port={}, channel={}",
            request.port_id,
            request.channel_id
        );

        // Block on async operation
        self.rt.block_on(async {
            // Query packet commitments from Gateway
            let response_bytes = self
                .gateway_client
                .query_packet_commitments(request.port_id.as_ref(), request.channel_id.as_ref())
                .await
                .map_err(|e| Error::query(format!("Failed to query packet commitments: {}", e)))?;

            // Decode the response
            use ibc_proto::ibc::core::channel::v1::QueryPacketCommitmentsResponse;
            use prost::Message;

            let response =
                QueryPacketCommitmentsResponse::decode(&response_bytes[..]).map_err(|e| {
                    Error::query(format!(
                        "Failed to decode packet commitments response: {}",
                        e
                    ))
                })?;

            // Extract sequences from packet_states
            let sequences: Vec<Sequence> = response
                .commitments
                .iter()
                .map(|state| Sequence::from(state.sequence))
                .collect();

            // Extract height from response
            let height = response.height.ok_or_else(|| {
                Error::query("No height in packet commitments response".to_string())
            })?;

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
        tracing::info!(
            "Querying packet receipt: port={}, channel={}, sequence={}",
            request.port_id,
            request.channel_id,
            request.sequence
        );
        let gateway_height = gateway_query_height(request.height);

        // Block on async operation
        self.rt.block_on(async {
            // Query packet receipt from Gateway
            let response_bytes = self
                .gateway_client
                .query_packet_receipt(
                    request.port_id.as_ref(),
                    request.channel_id.as_ref(),
                    request.sequence.into(),
                    gateway_height,
                )
                .await
                .map_err(|e| Error::query(format!("Failed to query packet receipt: {}", e)))?;

            // Decode the response
            use ibc_proto::ibc::core::channel::v1::QueryPacketReceiptResponse;
            use prost::Message;

            let response =
                QueryPacketReceiptResponse::decode(&response_bytes[..]).map_err(|e| {
                    Error::query(format!("Failed to decode packet receipt response: {}", e))
                })?;
            assert_gateway_proof_height(
                "query_packet_receipt",
                response.proof_height,
                gateway_height,
            )?;

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
        tracing::info!(
            "Querying unreceived packets: port={}, channel={}",
            request.port_id,
            request.channel_id
        );

        // Block on async operation
        self.rt.block_on(async {
            // Query unreceived packets from Gateway
            let response_bytes = self
                .gateway_client
                .query_unreceived_packets(
                    request.port_id.as_ref(),
                    request.channel_id.as_ref(),
                    request
                        .packet_commitment_sequences
                        .iter()
                        .map(|s| (*s).into())
                        .collect(),
                )
                .await
                .map_err(|e| Error::query(format!("Failed to query unreceived packets: {}", e)))?;

            // Decode the response
            use ibc_proto::ibc::core::channel::v1::QueryUnreceivedPacketsResponse;
            use prost::Message;

            let response =
                QueryUnreceivedPacketsResponse::decode(&response_bytes[..]).map_err(|e| {
                    Error::query(format!(
                        "Failed to decode unreceived packets response: {}",
                        e
                    ))
                })?;

            // Extract sequences from response
            let sequences: Vec<Sequence> = response
                .sequences
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
        tracing::info!(
            "Querying packet acknowledgement: port={}, channel={}, sequence={}",
            request.port_id,
            request.channel_id,
            request.sequence
        );
        let gateway_height = gateway_query_height(request.height);

        // Block on async operation
        self.rt.block_on(async {
            // Query packet acknowledgement from Gateway
            let response_bytes = self
                .gateway_client
                .query_packet_acknowledgement(
                    request.port_id.as_ref(),
                    request.channel_id.as_ref(),
                    request.sequence.into(),
                    gateway_height,
                )
                .await
                .map_err(|e| {
                    Error::query(format!("Failed to query packet acknowledgement: {}", e))
                })?;

            // Decode the response
            use ibc_proto::ibc::core::channel::v1::QueryPacketAcknowledgementResponse;
            use prost::Message;

            let response = QueryPacketAcknowledgementResponse::decode(&response_bytes[..])
                .map_err(|e| {
                    Error::query(format!(
                        "Failed to decode packet acknowledgement response: {}",
                        e
                    ))
                })?;
            assert_gateway_proof_height(
                "query_packet_acknowledgement",
                response.proof_height,
                gateway_height,
            )?;

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
        tracing::info!(
            "Querying packet acknowledgements: port={}, channel={}",
            request.port_id,
            request.channel_id
        );

        // Block on async operation
        self.rt.block_on(async {
            // Query packet acknowledgements from Gateway
            let response_bytes = self
                .gateway_client
                .query_packet_acknowledgements(
                    request.port_id.as_ref(),
                    request.channel_id.as_ref(),
                )
                .await
                .map_err(|e| {
                    Error::query(format!("Failed to query packet acknowledgements: {}", e))
                })?;

            // Decode the response
            use ibc_proto::ibc::core::channel::v1::QueryPacketAcknowledgementsResponse;
            use prost::Message;

            let response = QueryPacketAcknowledgementsResponse::decode(&response_bytes[..])
                .map_err(|e| {
                    Error::query(format!(
                        "Failed to decode packet acknowledgements response: {}",
                        e
                    ))
                })?;

            // Extract sequences from acknowledgements
            let sequences: Vec<Sequence> = response
                .acknowledgements
                .iter()
                .map(|ack| Sequence::from(ack.sequence))
                .collect();

            // Extract height from response
            let height = response.height.ok_or_else(|| {
                Error::query("No height in packet acknowledgements response".to_string())
            })?;

            let ics_height = ICSHeight::new(height.revision_number, height.revision_height)
                .map_err(|e| Error::query(format!("Invalid height: {}", e)))?;

            Ok((sequences, ics_height))
        })
    }

    fn query_unreceived_acknowledgements(
        &self,
        request: QueryUnreceivedAcksRequest,
    ) -> Result<Vec<Sequence>, Error> {
        tracing::info!(
            "Querying unreceived acknowledgements: port={}, channel={}",
            request.port_id,
            request.channel_id
        );

        // Block on async operation
        self.rt.block_on(async {
            // Query unreceived acknowledgements from Gateway
            let response_bytes = self
                .gateway_client
                .query_unreceived_acknowledgements(
                    request.port_id.as_ref(),
                    request.channel_id.as_ref(),
                    request
                        .packet_ack_sequences
                        .iter()
                        .map(|s| (*s).into())
                        .collect(),
                )
                .await
                .map_err(|e| {
                    Error::query(format!(
                        "Failed to query unreceived acknowledgements: {}",
                        e
                    ))
                })?;

            // Decode the response
            use ibc_proto::ibc::core::channel::v1::QueryUnreceivedAcksResponse;
            use prost::Message;

            let response =
                QueryUnreceivedAcksResponse::decode(&response_bytes[..]).map_err(|e| {
                    Error::query(format!("Failed to decode unreceived acks response: {}", e))
                })?;

            // Extract sequences from response
            let sequences: Vec<Sequence> = response
                .sequences
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
        tracing::info!(
            "Querying next sequence receive: port={}, channel={}",
            request.port_id,
            request.channel_id
        );
        let gateway_height = gateway_query_height(request.height);

        // Block on async operation
        self.rt.block_on(async {
            // Query next sequence receive from Gateway
            let response_bytes = self
                .gateway_client
                .query_next_sequence_receive(
                    request.port_id.as_ref(),
                    request.channel_id.as_ref(),
                    gateway_height,
                )
                .await
                .map_err(|e| {
                    Error::query(format!("Failed to query next sequence receive: {}", e))
                })?;

            // Decode the response
            use ibc_proto::ibc::core::channel::v1::QueryNextSequenceReceiveResponse;
            use prost::Message;

            let response =
                QueryNextSequenceReceiveResponse::decode(&response_bytes[..]).map_err(|e| {
                    Error::query(format!(
                        "Failed to decode next sequence receive response: {}",
                        e
                    ))
                })?;
            assert_gateway_proof_height(
                "query_next_sequence_receive",
                response.proof_height,
                gateway_height,
            )?;

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

                            let height = match block_results.height {
                                Some(h) => ICSHeight::new(h.revision_number, h.revision_height)
                                    .map_err(|e| {
                                        Error::query(format!("Invalid height in block results: {e}"))
                                    })?,
                                None => ICSHeight::new(0, target_height_u64).map_err(|e| {
                                    Error::query(format!(
                                        "Invalid fallback height {target_height_u64} in block results: {e}"
                                    ))
                                })?,
                            };

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

                out.extend(filter_packet_events_from_block_results(
                    &request,
                    response.block_results,
                    h,
                )?);
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

                    out.extend(filter_packet_events_from_block_results(
                        &request,
                        response.block_results,
                        h,
                    )?);
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

        let response = self
            .rt
            .block_on(
                self.gateway_client
                    .query_new_client(height.revision_height()),
            )
            .map_err(|e| Error::query(format!("Gateway query_new_client failed: {e}")))?;

        if let Some(raw_consensus_state) = response.consensus_state.clone() {
            let any = ibc_proto::google::protobuf::Any {
                type_url: raw_consensus_state.type_url,
                value: raw_consensus_state.value,
            };

            let consensus_state = AnyConsensusState::try_from(any).map_err(
                |e: ibc_relayer_types::core::ics02_client::error::Error| {
                    Error::query(format!(
                        "Failed to decode Cardano consensus state from query_new_client: {e}"
                    ))
                },
            )?;

            self.pending_new_client_consensus_states
                .lock()
                .expect("pending_new_client_consensus_states poisoned")
                .insert(height.revision_height(), consensus_state);
        }

        let raw_any = response
            .client_state
            .ok_or_else(|| Error::query("No client_state in NewClient response".to_string()))?;

        let any = ibc_proto::google::protobuf::Any {
            type_url: raw_any.type_url,
            value: raw_any.value,
        };

        any.try_into()
            .map_err(|e: ibc_relayer_types::core::ics02_client::error::Error| {
                Error::query(format!("Failed to decode Cardano client state: {e}"))
            })
    }

    fn build_packet_proofs(
        &self,
        packet_type: PacketMsgType,
        port_id: PortId,
        channel_id: ChannelId,
        sequence: Sequence,
        height: ICSHeight,
    ) -> Result<Proofs, Error> {
        let (maybe_packet_proof, channel_proof, proof_height) = match packet_type {
            PacketMsgType::Recv => {
                let response =
                    self.query_packet_commitment_response(&port_id, &channel_id, sequence)?;
                (
                    decode_optional_merkle_proof(&response.proof, "packet commitment")?,
                    None,
                    proof_height_from_response(response.proof_height, height, "packet commitment")?,
                )
            }
            PacketMsgType::Ack => {
                let response =
                    self.query_packet_acknowledgement_response(&port_id, &channel_id, sequence)?;
                (
                    decode_optional_merkle_proof(&response.proof, "packet acknowledgement")?,
                    None,
                    proof_height_from_response(
                        response.proof_height,
                        height,
                        "packet acknowledgement",
                    )?,
                )
            }
            PacketMsgType::TimeoutUnordered => {
                let response =
                    self.query_packet_receipt_response(&port_id, &channel_id, sequence)?;
                (
                    decode_optional_merkle_proof(&response.proof, "packet receipt")?,
                    None,
                    proof_height_from_response(response.proof_height, height, "packet receipt")?,
                )
            }
            PacketMsgType::TimeoutOrdered => {
                let response = self.query_next_sequence_receive_response(&port_id, &channel_id)?;
                (
                    decode_optional_merkle_proof(&response.proof, "next sequence receive")?,
                    None,
                    proof_height_from_response(
                        response.proof_height,
                        height,
                        "next sequence receive",
                    )?,
                )
            }
            PacketMsgType::TimeoutOnCloseUnordered => {
                let response =
                    self.query_packet_receipt_response(&port_id, &channel_id, sequence)?;
                let proof_height =
                    proof_height_from_response(response.proof_height, height, "packet receipt")?;
                let channel_proof = self
                    .query_channel(
                        QueryChannelRequest {
                            port_id: port_id.clone(),
                            channel_id: channel_id.clone(),
                            height: QueryHeight::Specific(proof_height),
                        },
                        IncludeProof::Yes,
                    )?
                    .1
                    .map(CommitmentProofBytes::try_from)
                    .transpose()
                    .map_err(Error::malformed_proof)?;

                (
                    decode_optional_merkle_proof(&response.proof, "packet receipt")?,
                    channel_proof,
                    proof_height,
                )
            }
            PacketMsgType::TimeoutOnCloseOrdered => {
                let response = self.query_next_sequence_receive_response(&port_id, &channel_id)?;
                let proof_height = proof_height_from_response(
                    response.proof_height,
                    height,
                    "next sequence receive",
                )?;
                let channel_proof = self
                    .query_channel(
                        QueryChannelRequest {
                            port_id: port_id.clone(),
                            channel_id: channel_id.clone(),
                            height: QueryHeight::Specific(proof_height),
                        },
                        IncludeProof::Yes,
                    )?
                    .1
                    .map(CommitmentProofBytes::try_from)
                    .transpose()
                    .map_err(Error::malformed_proof)?;

                (
                    decode_optional_merkle_proof(&response.proof, "next sequence receive")?,
                    channel_proof,
                    proof_height,
                )
            }
        };

        let Some(packet_proof) = maybe_packet_proof else {
            return Err(Error::queried_proof_not_found());
        };

        // Cardano Gateway proof heights follow accepted HostState anchors, not packet event heights.
        Proofs::new(
            CommitmentProofBytes::try_from(packet_proof).map_err(Error::malformed_proof)?,
            None,
            None,
            None,
            channel_proof,
            proof_height,
        )
        .map_err(Error::malformed_proof)
    }

    fn build_consensus_state(
        &self,
        light_block: Self::LightBlock,
    ) -> Result<Self::ConsensusState, Error> {
        let header_height = light_block.height.revision_height();
        if let Some(consensus_state) = self
            .pending_new_client_consensus_states
            .lock()
            .expect("pending_new_client_consensus_states poisoned")
            .remove(&header_height)
        {
            return Ok(consensus_state);
        }

        let header = light_block.header.ok_or_else(|| {
            Error::query("missing Cardano header while building consensus state".to_string())
        })?;

        let ibc_state_root = extract_ibc_state_root_from_host_state_tx(
            &header,
            &light_block.host_state_nft_policy_id,
            &light_block.host_state_nft_token_name,
        )?;

        match header {
            AnyHeader::Mithril(header) => Ok(AnyConsensusState::from(MithrilConsensusState::new(
                CommitmentRoot::from_bytes(&ibc_state_root),
                header.timestamp.nanoseconds(),
                header.mithril_stake_distribution_certificate,
                header.transaction_snapshot_certificate.hash,
            ))),
            AnyHeader::Probabilistic(header) => {
                Ok(AnyConsensusState::from(ProbabilisticConsensusState {
                    root: CommitmentRoot::from_bytes(&ibc_state_root),
                    timestamp: header.timestamp.nanoseconds(),
                    accepted_block_hash: header.anchor_block.hash,
                    accepted_epoch: header.anchor_block.epoch,
                    unique_pools_count: 0,
                    unique_stake_bps: 0,
                    security_score_bps: 0,
                    operational_certificate_state_initialized: true,
                }))
            }
            AnyHeader::Tendermint(_) => Err(Error::query(
                "Cardano build_consensus_state received a Tendermint header".to_string(),
            )),
        }
    }

    fn build_header(
        &mut self,
        trusted_height: ICSHeight,
        target_height: ICSHeight,
        _client_state: &AnyClientState,
    ) -> Result<(Self::Header, Vec<Self::Header>), Error> {
        // NOTE: Hermes core logic often requests a client update at `proofs_height + 1`.
        //
        // On Tendermint chains this is fine because heights are contiguous and the Tendermint
        // header builder can return intermediate "support" headers (including the proof height).
        //
        // For Cardano/Mithril, however, headers only exist at Mithril-certified transaction snapshot
        // heights (e.g. every ~15 blocks in our devnet setup). That means a height like `H + 1`
        // may not exist at all even if the chain has advanced well beyond it.
        //
        // If the exact `target_height` is not available, we still want to:
        // - install a consensus state at `target_height - 1` (the proof height), so proofs verify, and
        // - also advance the client to the latest available snapshot height.
        //
        // We do this by returning:
        // - `support` header at `target_height - 1`, and
        // - a final header at the latest snapshot height.
        let effective_trusted_height =
            normalize_header_query_trusted_height(trusted_height, target_height)?;
        tracing::info!(
            "Cardano build_header querying Gateway header with trusted={} effective_trusted={} target={}",
            trusted_height,
            effective_trusted_height,
            target_height
        );
        match self.rt.block_on(
            self.gateway_client
                .query_header(effective_trusted_height, target_height),
        ) {
            Ok(header) => Ok((header, vec![])),
            Err(e) => {
                if !is_recoverable_gateway_header_height_error(&e) {
                    return Err(Error::query(format!("Gateway query_header failed: {e}")));
                }

                let proof_height = target_height
                    .decrement()
                    .map_err(|_| Error::query(format!("invalid target height {target_height}")))?;
                let effective_proof_trusted_height =
                    normalize_header_query_trusted_height(trusted_height, proof_height)?;

                let proof_header = self
                    .rt
                    .block_on(
                        self.gateway_client
                            .query_header(effective_proof_trusted_height, proof_height),
                    )
                    .map_err(|e| {
                        Error::query(format!(
                            "Gateway query_header failed at proof height {proof_height}: {e}"
                        ))
                    })?;

                let latest_height = self
                    .rt
                    .block_on(self.gateway_client.query_latest_height())
                    .map_err(|e| {
                        Error::query(format!("Gateway query_latest_height failed: {e}"))
                    })?;

                let mut selected_header = None;
                let mut candidate_height = target_height.revision_height();
                let latest_revision_height = latest_height.revision_height();

                while candidate_height <= latest_revision_height {
                    let candidate_ics_height =
                        ICSHeight::new(target_height.revision_number(), candidate_height)
                            .map_err(|_| {
                                Error::query(format!(
                                    "invalid candidate height while searching Cardano header: {candidate_height}"
                                ))
                            })?;

                    match self.rt.block_on(
                        self.gateway_client
                            .query_header(proof_height, candidate_ics_height),
                    ) {
                        Ok(header) => {
                            selected_header = Some(header);
                            break;
                        }
                        Err(search_error) => {
                            if !is_recoverable_gateway_header_height_error(&search_error) {
                                return Err(Error::query(format!(
                                    "Gateway query_header failed while searching for a certified height at/after {target_height} (candidate {candidate_ics_height}): {search_error}"
                                )));
                            }
                        }
                    }

                    candidate_height = candidate_height.saturating_add(1);
                }

                let selected_header = if let Some(header) = selected_header {
                    header
                } else {
                    self.rt
                        .block_on(
                            self.gateway_client
                                .query_header(proof_height, latest_height),
                        )
                        .map_err(|e| {
                            Error::query(format!(
                                "Gateway query_header failed at latest height {latest_height}: {e}"
                            ))
                        })?
                };

                Ok((selected_header, vec![proof_header]))
            }
        }
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
    ) -> Result<
        Vec<ibc_relayer_types::applications::ics31_icq::response::CrossChainQueryResponse>,
        Error,
    > {
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

    fn query_consumer_chains(
        &self,
    ) -> Result<Vec<ibc_relayer_types::applications::ics28_ccv::msgs::ConsumerChain>, Error> {
        Err(Error::query(
            "ICS-28 CCV (Cross-Chain Validation) is not applicable to Cardano".to_string(),
        ))
    }

    fn query_upgrade(
        &self,
        _request: ibc_proto::ibc::core::channel::v1::QueryUpgradeRequest,
        _height: ibc_relayer_types::Height,
        _include_proof: IncludeProof,
    ) -> Result<
        (
            ibc_relayer_types::core::ics04_channel::upgrade::Upgrade,
            Option<MerkleProof>,
        ),
        Error,
    > {
        Err(Error::query(
            "IBC channel upgrades are not implemented for Cardano".to_string(),
        ))
    }

    fn query_upgrade_error(
        &self,
        _request: ibc_proto::ibc::core::channel::v1::QueryUpgradeErrorRequest,
        _height: ibc_relayer_types::Height,
        _include_proof: IncludeProof,
    ) -> Result<
        (
            ibc_relayer_types::core::ics04_channel::upgrade::ErrorReceipt,
            Option<MerkleProof>,
        ),
        Error,
    > {
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

    let height = match block_results.height {
        Some(h) => ICSHeight::new(h.revision_number, h.revision_height)
            .map_err(|e| Error::query(format!("Invalid height in block results: {e}")))?,
        None => ICSHeight::new(0, fallback_height)
            .map_err(|e| Error::query(format!("Invalid fallback height {fallback_height}: {e}")))?,
    };

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

// Mithril header is decoded from the Gateway as `google.protobuf.Any`.
// See `ibc-relayer-types/src/clients/ics08_cardano/header.rs` and
// `ibc-relayer-types/src/core/ics02_client/header.rs`.

fn independent_header_trusted_height(header: &AnyHeader) -> Result<ICSHeight, Error> {
    match header {
        AnyHeader::Mithril(header) => header.height.decrement().map_err(|_| {
            Error::query(format!(
                "cannot independently query Mithril header at {} without a prior trusted height",
                header.height
            ))
        }),
        AnyHeader::Probabilistic(header) => Ok(header.trusted_height),
        AnyHeader::Tendermint(_) => Err(Error::query(
            "Cardano misbehaviour check received a Tendermint header".to_string(),
        )),
    }
}

fn submitted_cardano_update_header(
    update: &UpdateClient,
    require_update_event_header: bool,
) -> Result<Option<&AnyHeader>, Error> {
    let Some(submitted_header) = update.header.as_ref() else {
        if require_update_event_header {
            return Err(Error::query(format!(
                "cannot check Cardano misbehaviour for client {} at consensus height {}: update-client event does not include the submitted header",
                update.client_id(),
                update.consensus_height(),
            )));
        }

        tracing::warn!(
            "skipping Cardano misbehaviour check for client {} at consensus height {}: update-client event does not include the submitted header",
            update.client_id(),
            update.consensus_height(),
        );
        return Ok(None);
    };

    let target_height = submitted_header.height();
    if target_height != update.consensus_height() {
        return Err(Error::query(format!(
            "update event consensus height {} does not match submitted Cardano header height {} for client {}",
            update.consensus_height(),
            target_height,
            update.client_id()
        )));
    }

    Ok(Some(submitted_header))
}

fn cardano_misbehaviour_evidence(
    update: &UpdateClient,
    submitted_header: &AnyHeader,
    witness_header: AnyHeader,
    client_state: &AnyClientState,
) -> Result<Option<MisbehaviourEvidence>, Error> {
    let target_height = submitted_header.height();
    if witness_header.height() != target_height {
        return Err(Error::query(format!(
            "independent Cardano header height mismatch: expected {target_height}, got {}",
            witness_header.height()
        )));
    }

    if !cardano_headers_conflict(submitted_header, &witness_header, client_state)? {
        return Ok(None);
    }

    let misbehaviour = match (submitted_header.clone(), witness_header) {
        (AnyHeader::Mithril(header1), AnyHeader::Mithril(header2)) => {
            AnyMisbehaviour::Mithril(MithrilMisbehaviour {
                client_id: update.client_id().clone(),
                header1,
                header2,
            })
        }
        (AnyHeader::Probabilistic(header1), AnyHeader::Probabilistic(header2)) => {
            AnyMisbehaviour::Probabilistic(ProbabilisticMisbehaviour {
                client_id: update.client_id().clone(),
                header1,
                header2,
            })
        }
        (AnyHeader::Tendermint(_), _) => {
            return Err(Error::query(
                "Cardano misbehaviour check received a Tendermint update header".to_string(),
            ))
        }
        (left, right) => {
            return Err(Error::query(format!(
                "Cardano misbehaviour check cannot compare different header types: submitted={:?}, witness={:?}",
                left.client_type(),
                right.client_type()
            )))
        }
    };

    Ok(Some(MisbehaviourEvidence {
        misbehaviour,
        supporting_headers: vec![],
    }))
}

fn cardano_headers_conflict(
    submitted: &AnyHeader,
    witness: &AnyHeader,
    client_state: &AnyClientState,
) -> Result<bool, Error> {
    let (host_state_nft_policy_id, host_state_nft_token_name) =
        cardano_host_state_nft(client_state)?;

    match (submitted, witness) {
        (AnyHeader::Mithril(submitted), AnyHeader::Mithril(witness)) => {
            if submitted.height != witness.height {
                return Err(Error::query(format!(
                    "cannot compare Mithril headers at different heights: {} and {}",
                    submitted.height, witness.height
                )));
            }

            let submitted_root = extract_ibc_state_root_from_host_state_tx(
                &AnyHeader::Mithril(submitted.clone()),
                host_state_nft_policy_id,
                host_state_nft_token_name,
            )?;
            let witness_root = extract_ibc_state_root_from_host_state_tx(
                &AnyHeader::Mithril(witness.clone()),
                host_state_nft_policy_id,
                host_state_nft_token_name,
            )?;

            let conflicts = submitted_root != witness_root
                || !submitted
                    .host_state_tx_hash
                    .trim()
                    .eq_ignore_ascii_case(witness.host_state_tx_hash.trim())
                || !submitted
                    .mithril_stake_distribution_certificate
                    .hash
                    .trim()
                    .eq_ignore_ascii_case(
                        witness.mithril_stake_distribution_certificate.hash.trim(),
                    )
                || !submitted
                    .transaction_snapshot_certificate
                    .hash
                    .trim()
                    .eq_ignore_ascii_case(witness.transaction_snapshot_certificate.hash.trim());

            if conflicts {
                tracing::warn!(
                    "Mithril header conflict detected at {}: submitted_root={}, witness_root={}, submitted_host_tx={}, witness_host_tx={}, submitted_tx_cert={}, witness_tx_cert={}",
                    submitted.height,
                    hex::encode(&submitted_root),
                    hex::encode(&witness_root),
                    submitted.host_state_tx_hash,
                    witness.host_state_tx_hash,
                    submitted.transaction_snapshot_certificate.hash,
                    witness.transaction_snapshot_certificate.hash,
                );
            }

            Ok(conflicts)
        }
        (AnyHeader::Probabilistic(submitted), AnyHeader::Probabilistic(witness)) => {
            if submitted.height != witness.height {
                return Err(Error::query(format!(
                    "cannot compare probabilistic headers at different heights: {} and {}",
                    submitted.height, witness.height
                )));
            }

            let cheap_conflict = !submitted
                .host_state_tx_hash
                .trim()
                .eq_ignore_ascii_case(witness.host_state_tx_hash.trim())
                || !submitted
                    .anchor_block
                    .hash
                    .trim()
                    .eq_ignore_ascii_case(witness.anchor_block.hash.trim())
                || probabilistic_windows_conflict_by_block_height(submitted, witness);
            if cheap_conflict {
                tracing::warn!(
                    "Probabilistic header conflict detected at {}: submitted_host_tx={}, witness_host_tx={}, submitted_anchor={}, witness_anchor={}",
                    submitted.height,
                    submitted.host_state_tx_hash,
                    witness.host_state_tx_hash,
                    submitted.anchor_block.hash,
                    witness.anchor_block.hash,
                );
                return Ok(true);
            }

            let submitted_root = extract_ibc_state_root_from_host_state_tx(
                &AnyHeader::Probabilistic(submitted.clone()),
                host_state_nft_policy_id,
                host_state_nft_token_name,
            )?;
            let witness_root = extract_ibc_state_root_from_host_state_tx(
                &AnyHeader::Probabilistic(witness.clone()),
                host_state_nft_policy_id,
                host_state_nft_token_name,
            )?;

            let conflicts = submitted_root != witness_root;

            if conflicts {
                tracing::warn!(
                    "Probabilistic header conflict detected at {}: submitted_root={}, witness_root={}, submitted_host_tx={}, witness_host_tx={}, submitted_anchor={}, witness_anchor={}",
                    submitted.height,
                    hex::encode(&submitted_root),
                    hex::encode(&witness_root),
                    submitted.host_state_tx_hash,
                    witness.host_state_tx_hash,
                    submitted.anchor_block.hash,
                    witness.anchor_block.hash,
                );
            }

            Ok(conflicts)
        }
        (AnyHeader::Tendermint(_), _) => Err(Error::query(
            "Cardano misbehaviour check received a Tendermint submitted header".to_string(),
        )),
        (_, AnyHeader::Tendermint(_)) => Err(Error::query(
            "Cardano misbehaviour check independently fetched a Tendermint header".to_string(),
        )),
        (submitted, witness) => Err(Error::query(format!(
            "cannot compare different Cardano header types: submitted={:?}, witness={:?}",
            submitted.client_type(),
            witness.client_type()
        ))),
    }
}

fn probabilistic_windows_conflict_by_block_height(
    submitted: &ibc_relayer_types::clients::ics08_cardano_probabilistic::header::Header,
    witness: &ibc_relayer_types::clients::ics08_cardano_probabilistic::header::Header,
) -> bool {
    let submitted_blocks = std::iter::once(&submitted.anchor_block)
        .chain(submitted.bridge_blocks.iter())
        .chain(submitted.descendant_blocks.iter());
    let witness_blocks = std::iter::once(&witness.anchor_block)
        .chain(witness.bridge_blocks.iter())
        .chain(witness.descendant_blocks.iter());

    // A shared block height with different hashes proves incompatible probabilistic windows.
    for submitted_block in submitted_blocks {
        let Some(submitted_height) = probabilistic_block_revision_height(submitted_block) else {
            continue;
        };

        for witness_block in witness_blocks.clone() {
            if probabilistic_block_revision_height(witness_block) == Some(submitted_height)
                && !submitted_block
                    .hash
                    .trim()
                    .eq_ignore_ascii_case(witness_block.hash.trim())
            {
                return true;
            }
        }
    }

    false
}

fn probabilistic_block_revision_height(
    block: &ibc_relayer_types::clients::ics08_cardano_probabilistic::raw::ProbabilisticBlock,
) -> Option<u64> {
    block.height.as_ref().map(|height| height.revision_height)
}

fn cardano_host_state_nft(client_state: &AnyClientState) -> Result<(&[u8], &[u8]), Error> {
    match client_state {
        AnyClientState::Mithril(state) => Ok((
            state.host_state_nft_policy_id.as_slice(),
            state.host_state_nft_token_name.as_slice(),
        )),
        AnyClientState::Probabilistic(state) => Ok((
            state.host_state_nft_policy_id.as_slice(),
            state.host_state_nft_token_name.as_slice(),
        )),
        _ => Err(Error::query(
            "Cardano misbehaviour check requires a Cardano client state".to_string(),
        )),
    }
}

fn extract_ibc_state_root_from_host_state_tx(
    header: &AnyHeader,
    host_state_nft_policy_id: &[u8],
    host_state_nft_token_name: &[u8],
) -> Result<Vec<u8>, Error> {
    match header {
        AnyHeader::Mithril(header) => extract_ibc_state_root_from_host_state_tx_body(
            "Mithril",
            header.host_state_tx_hash.trim(),
            header.host_state_tx_body_cbor.as_slice(),
            header.host_state_tx_output_index,
            host_state_nft_policy_id,
            host_state_nft_token_name,
        ),
        AnyHeader::Probabilistic(header) => extract_ibc_state_root_from_probabilistic_anchor_block(
            header.host_state_tx_hash.trim(),
            header.anchor_block.block_cbor.as_slice(),
            header.host_state_tx_output_index,
            host_state_nft_policy_id,
            host_state_nft_token_name,
        ),
        AnyHeader::Tendermint(_) => Err(Error::query(
            "unexpected Tendermint header in Cardano host state extraction".to_string(),
        )),
    }
}

fn extract_ibc_state_root_from_host_state_tx_body(
    header_kind: &str,
    tx_hash: &str,
    tx_body_cbor: &[u8],
    output_index: u32,
    host_state_nft_policy_id: &[u8],
    host_state_nft_token_name: &[u8],
) -> Result<Vec<u8>, Error> {
    if tx_hash.is_empty() {
        return Err(Error::query(format!(
            "missing host_state_tx_hash in {header_kind} header"
        )));
    }

    if host_state_nft_policy_id.len() != 28 {
        return Err(Error::query(format!(
            "invalid host_state_nft_policy_id length: expected 28 bytes, got {}",
            host_state_nft_policy_id.len()
        )));
    }

    if tx_body_cbor.is_empty() {
        return Err(Error::query(format!(
            "missing host_state_tx_body_cbor in {header_kind} header"
        )));
    }

    let computed = blake2b_256(tx_body_cbor);
    let computed_hex = hex::encode(computed);
    if !computed_hex.eq_ignore_ascii_case(tx_hash) {
        return Err(Error::query(format!(
            "HostState tx body hash mismatch: expected {tx_hash}, got {computed_hex}"
        )));
    }

    use pallas_codec::minicbor;
    use pallas_codec::utils::KeepRaw;
    use pallas_primitives::{babbage, conway};

    let conway_body: Result<KeepRaw<'_, conway::MintedTransactionBody<'_>>, _> =
        minicbor::decode(tx_body_cbor);
    if let Ok(body) = conway_body {
        return extract_root_from_conway_tx_body(
            &body,
            output_index,
            host_state_nft_policy_id,
            host_state_nft_token_name,
        );
    }

    let babbage_body: Result<KeepRaw<'_, babbage::MintedTransactionBody<'_>>, _> =
        minicbor::decode(tx_body_cbor);
    if let Ok(body) = babbage_body {
        return extract_root_from_babbage_tx_body(
            &body,
            output_index,
            host_state_nft_policy_id,
            host_state_nft_token_name,
        );
    }

    Err(Error::query(
        "unsupported HostState transaction body CBOR".to_string(),
    ))
}

fn extract_ibc_state_root_from_probabilistic_anchor_block(
    tx_hash: &str,
    anchor_block_cbor: &[u8],
    output_index: u32,
    host_state_nft_policy_id: &[u8],
    host_state_nft_token_name: &[u8],
) -> Result<Vec<u8>, Error> {
    use pallas_codec::minicbor;
    use pallas_codec::utils::KeepRaw;
    use pallas_primitives::{babbage, conway};

    if tx_hash.is_empty() {
        return Err(Error::query(
            "missing host_state_tx_hash in probabilistic header".to_string(),
        ));
    }

    if host_state_nft_policy_id.len() != 28 {
        return Err(Error::query(format!(
            "invalid host_state_nft_policy_id length: expected 28 bytes, got {}",
            host_state_nft_policy_id.len()
        )));
    }

    if anchor_block_cbor.is_empty() {
        return Err(Error::query(
            "missing anchor block_cbor in probabilistic header".to_string(),
        ));
    }

    let conway_block: Result<KeepRaw<'_, conway::MintedBlock<'_>>, _> =
        minicbor::decode(anchor_block_cbor);
    if let Ok(block) = conway_block {
        return extract_root_from_conway_block(
            &block,
            tx_hash,
            output_index,
            host_state_nft_policy_id,
            host_state_nft_token_name,
        );
    }

    let babbage_block: Result<KeepRaw<'_, babbage::MintedBlock<'_>>, _> =
        minicbor::decode(anchor_block_cbor);
    if let Ok(block) = babbage_block {
        return extract_root_from_babbage_block(
            &block,
            tx_hash,
            output_index,
            host_state_nft_policy_id,
            host_state_nft_token_name,
        );
    }

    Err(Error::query(
        "unsupported probabilistic anchor block CBOR".to_string(),
    ))
}

fn blake2b_256(data: &[u8]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn extract_root_from_conway_block<'a>(
    block: &pallas_codec::utils::KeepRaw<'a, pallas_primitives::conway::MintedBlock<'a>>,
    tx_hash: &str,
    output_index: u32,
    host_state_nft_policy_id: &[u8],
    host_state_nft_token_name: &[u8],
) -> Result<Vec<u8>, Error> {
    for tx_body in block.transaction_bodies.iter() {
        let computed_hex = hex::encode(blake2b_256(tx_body.raw_cbor()));
        if computed_hex.eq_ignore_ascii_case(tx_hash) {
            return extract_root_from_conway_tx_body(
                tx_body,
                output_index,
                host_state_nft_policy_id,
                host_state_nft_token_name,
            );
        }
    }

    Err(Error::query(format!(
        "HostState tx {tx_hash} not found in probabilistic anchor block"
    )))
}

fn extract_root_from_babbage_block<'a>(
    block: &pallas_codec::utils::KeepRaw<'a, pallas_primitives::babbage::MintedBlock<'a>>,
    tx_hash: &str,
    output_index: u32,
    host_state_nft_policy_id: &[u8],
    host_state_nft_token_name: &[u8],
) -> Result<Vec<u8>, Error> {
    for tx_body in block.transaction_bodies.iter() {
        let computed_hex = hex::encode(blake2b_256(tx_body.raw_cbor()));
        if computed_hex.eq_ignore_ascii_case(tx_hash) {
            return extract_root_from_babbage_tx_body(
                tx_body,
                output_index,
                host_state_nft_policy_id,
                host_state_nft_token_name,
            );
        }
    }

    Err(Error::query(format!(
        "HostState tx {tx_hash} not found in probabilistic anchor block"
    )))
}

fn extract_root_from_conway_tx_body<'a>(
    body: &pallas_codec::utils::KeepRaw<'a, pallas_primitives::conway::MintedTransactionBody<'a>>,
    output_index: u32,
    host_state_nft_policy_id: &[u8],
    host_state_nft_token_name: &[u8],
) -> Result<Vec<u8>, Error> {
    use pallas_primitives::conway::{MintedTransactionOutput, PseudoTransactionOutput};

    let idx: usize = output_index
        .try_into()
        .map_err(|_| Error::query("host_state_tx_output_index out of range".to_string()))?;

    let output: &MintedTransactionOutput<'a> = body
        .outputs
        .get(idx)
        .ok_or_else(|| Error::query("host_state_tx_output_index out of range".to_string()))?;

    let out = match output {
        PseudoTransactionOutput::PostAlonzo(out) => out,
        _ => {
            return Err(Error::query(
                "HostState output is not a post-Alonzo output".to_string(),
            ))
        }
    };

    ensure_value_contains_host_state_nft_conway(
        &out.value,
        host_state_nft_policy_id,
        host_state_nft_token_name,
    )?;

    let datum_option = out.datum_option.as_ref().ok_or_else(|| {
        Error::query("HostState output has no datum option (expected inline datum)".to_string())
    })?;

    let plutus_data = match datum_option {
        pallas_primitives::babbage::PseudoDatumOption::Data(cbor_wrap) => {
            std::ops::Deref::deref(std::ops::Deref::deref(cbor_wrap))
        }
        _ => {
            return Err(Error::query(
                "HostState output does not contain an inline datum".to_string(),
            ))
        }
    };

    extract_ibc_state_root_from_host_state_datum(plutus_data, host_state_nft_policy_id)
}

fn extract_root_from_babbage_tx_body<'a>(
    body: &pallas_codec::utils::KeepRaw<'a, pallas_primitives::babbage::MintedTransactionBody<'a>>,
    output_index: u32,
    host_state_nft_policy_id: &[u8],
    host_state_nft_token_name: &[u8],
) -> Result<Vec<u8>, Error> {
    use pallas_primitives::babbage::{MintedTransactionOutput, PseudoTransactionOutput};

    let idx: usize = output_index
        .try_into()
        .map_err(|_| Error::query("host_state_tx_output_index out of range".to_string()))?;

    let output: &MintedTransactionOutput<'a> = body
        .outputs
        .get(idx)
        .ok_or_else(|| Error::query("host_state_tx_output_index out of range".to_string()))?;

    let out = match output {
        PseudoTransactionOutput::PostAlonzo(out) => out,
        _ => {
            return Err(Error::query(
                "HostState output is not a post-Alonzo output".to_string(),
            ))
        }
    };

    ensure_value_contains_host_state_nft_alonzo(
        &out.value,
        host_state_nft_policy_id,
        host_state_nft_token_name,
    )?;

    let datum_option = out.datum_option.as_ref().ok_or_else(|| {
        Error::query("HostState output has no datum option (expected inline datum)".to_string())
    })?;

    let plutus_data = match datum_option {
        pallas_primitives::babbage::PseudoDatumOption::Data(cbor_wrap) => {
            std::ops::Deref::deref(std::ops::Deref::deref(cbor_wrap))
        }
        _ => {
            return Err(Error::query(
                "HostState output does not contain an inline datum".to_string(),
            ))
        }
    };

    extract_ibc_state_root_from_host_state_datum(plutus_data, host_state_nft_policy_id)
}

fn ensure_value_contains_host_state_nft_conway(
    value: &pallas_primitives::conway::Value,
    host_state_nft_policy_id: &[u8],
    host_state_nft_token_name: &[u8],
) -> Result<(), Error> {
    match value {
        pallas_primitives::conway::Value::Multiasset(_, multiasset) => {
            for (policy, assets) in multiasset.iter() {
                if policy.as_ref() != host_state_nft_policy_id {
                    continue;
                }

                for (asset, amount) in assets.iter() {
                    if asset.as_slice() == host_state_nft_token_name {
                        let amount_u64: u64 = amount.into();
                        if amount_u64 == 1 {
                            return Ok(());
                        }
                    }
                }
            }

            Err(Error::query(
                "HostState output does not contain the expected HostState NFT".to_string(),
            ))
        }
        _ => Err(Error::query(
            "HostState output has no multi-assets (expected HostState NFT)".to_string(),
        )),
    }
}

fn ensure_value_contains_host_state_nft_alonzo(
    value: &pallas_primitives::alonzo::Value,
    host_state_nft_policy_id: &[u8],
    host_state_nft_token_name: &[u8],
) -> Result<(), Error> {
    match value {
        pallas_primitives::alonzo::Value::Multiasset(_, multiasset) => {
            for (policy, assets) in multiasset.iter() {
                if policy.as_ref() != host_state_nft_policy_id {
                    continue;
                }

                for (asset, amount) in assets.iter() {
                    if asset.as_slice() == host_state_nft_token_name && *amount == 1 {
                        return Ok(());
                    }
                }
            }

            Err(Error::query(
                "HostState output does not contain the expected HostState NFT".to_string(),
            ))
        }
        _ => Err(Error::query(
            "HostState output has no multi-assets (expected HostState NFT)".to_string(),
        )),
    }
}

fn extract_ibc_state_root_from_host_state_datum(
    datum: &pallas_primitives::alonzo::PlutusData,
    expected_nft_policy_id: &[u8],
) -> Result<Vec<u8>, Error> {
    use pallas_primitives::alonzo::PlutusData;

    let outer = match datum {
        PlutusData::Constr(c) => c,
        _ => {
            return Err(Error::query(
                "HostState datum is not a constructor PlutusData".to_string(),
            ))
        }
    };

    if plutus_constructor_index(outer) != Some(0) || outer.fields.len() < 2 {
        return Err(Error::query(
            "HostState datum does not match expected constructor shape".to_string(),
        ));
    }

    let state = &outer.fields[0];
    let nft_policy = &outer.fields[1];

    if !expected_nft_policy_id.is_empty() {
        let nft_policy_bytes: &[u8] = match nft_policy {
            PlutusData::BoundedBytes(bytes) => bytes.as_slice(),
            _ => {
                return Err(Error::query(
                    "HostState datum nft_policy is not a byte string".to_string(),
                ))
            }
        };

        if nft_policy_bytes != expected_nft_policy_id {
            return Err(Error::query(
                "unexpected HostState nft_policy in datum".to_string(),
            ));
        }
    }

    let state = match state {
        PlutusData::Constr(c) => c,
        _ => {
            return Err(Error::query(
                "HostState state is not a constructor".to_string(),
            ))
        }
    };

    if plutus_constructor_index(state) != Some(0) || state.fields.len() < 2 {
        return Err(Error::query(
            "HostState state does not match expected constructor shape".to_string(),
        ));
    }

    let root: &[u8] = match &state.fields[1] {
        PlutusData::BoundedBytes(bytes) => bytes.as_slice(),
        _ => {
            return Err(Error::query(
                "ibc_state_root is not a byte string".to_string(),
            ))
        }
    };

    if root.len() != 32 {
        return Err(Error::query(format!(
            "invalid ibc_state_root length: expected 32 bytes, got {}",
            root.len()
        )));
    }

    Ok(root.to_vec())
}

fn normalize_header_query_trusted_height(
    trusted_height: ICSHeight,
    target_height: ICSHeight,
) -> Result<ICSHeight, Error> {
    if trusted_height < target_height {
        return Ok(trusted_height);
    }

    target_height.decrement().map_err(|_| {
        Error::query(format!(
            "invalid Cardano header query heights: trusted height {trusted_height} must be less than target height {target_height}"
        ))
    })
}

fn is_recoverable_gateway_header_height_error(error: &super::error::Error) -> bool {
    match error {
        super::error::Error::GatewayStatus { code, message } => {
            matches!(
                (*code, message.as_str()),
                (tonic::Code::NotFound, msg) if msg.contains("HEIGHT_NOT_FOUND")
            ) || matches!(
                (*code, message.as_str()),
                (tonic::Code::FailedPrecondition, msg) if msg.contains("HEIGHT_NOT_ACCEPTED")
            ) || is_legacy_gateway_header_height_not_found(message)
        }
        _ => is_legacy_gateway_header_height_not_found(&error.to_string()),
    }
}

fn is_legacy_gateway_header_height_not_found(message: &str) -> bool {
    message.contains("Not found") && message.contains("height")
}

fn decode_optional_merkle_proof(proof: &[u8], context: &str) -> Result<Option<MerkleProof>, Error> {
    if proof.is_empty() {
        return Ok(None);
    }

    let raw_proof =
        <ibc_proto::ibc::core::commitment::v1::MerkleProof as prost::Message>::decode(proof)
            .map_err(|e| {
                Error::query(format!(
                    "Failed to decode {context} proof from Gateway: {e}"
                ))
            })?;
    Ok(Some(MerkleProof::from(raw_proof)))
}

fn proof_height_from_response(
    proof_height: Option<ibc_proto::ibc::core::client::v1::Height>,
    requested_height: ICSHeight,
    context: &str,
) -> Result<ICSHeight, Error> {
    let proof_height = proof_height.ok_or_else(|| {
        Error::query(format!(
            "Cardano Gateway response for {context} omitted proof_height for requested height {requested_height}"
        ))
    })?;

    let proof_height = ICSHeight::new(proof_height.revision_number, proof_height.revision_height)
        .map_err(|e| {
        Error::query(format!(
            "Invalid {context} proof_height from Cardano Gateway: {e}"
        ))
    })?;

    if proof_height != requested_height {
        return Err(Error::query(format!(
            "Cardano Gateway {context} proof height mismatch: requested {requested_height}, got {proof_height}"
        )));
    }

    Ok(proof_height)
}

fn plutus_constructor_index(
    constr: &pallas_primitives::alonzo::Constr<pallas_primitives::alonzo::PlutusData>,
) -> Option<u64> {
    match constr.tag {
        102 => constr.any_constructor,
        121..=127 => Some(constr.tag - 121),
        1280..=1400 => Some(constr.tag - 1280 + 7),
        _ => None,
    }
}

fn cardano_latest_height_unhealthy_error(
    latest_height_error: &super::error::Error,
    client_states_result: Result<(), super::error::Error>,
) -> Error {
    match client_states_result {
        Ok(()) => Error::query(format!(
            "Cardano Gateway health check failed: latest-height probe is required for relayer operation and failed: {latest_height_error}; client-states probe succeeded, so the Gateway query API is partially reachable but latest-height/proof-serving is not ready"
        )),
        Err(client_states_error) => Error::query(format!(
            "Cardano Gateway health check failed: latest-height probe is required for relayer operation and failed: {latest_height_error}; client-states probe also failed: {client_states_error}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::cardano::error::Error as CardanoError;
    use crate::client_state::AnyClientState;
    use ibc_proto::ibc::core::client::v1::Height as RawHeight;
    use ibc_proto::Protobuf;
    use ibc_relayer_types::clients::ics08_cardano::{
        client_state::ClientState as MithrilClientState, header::Header as MithrilHeader,
        raw as mithril_raw,
    };
    use ibc_relayer_types::clients::ics08_cardano_probabilistic::{
        client_state::ClientState as ProbabilisticClientState,
        header::Header as ProbabilisticHeader, raw as probabilistic_raw,
    };
    use ibc_relayer_types::core::ics02_client::client_type::ClientType;
    use ibc_relayer_types::core::ics02_client::events::Attributes;
    use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ClientId};
    use ibc_relayer_types::timestamp::Timestamp;
    use std::time::Duration;

    const HOST_STATE_NFT_POLICY_ID: [u8; 28] = [7; 28];
    const HOST_STATE_NFT_TOKEN_NAME: &[u8] = b"host_state_nft";

    fn height(revision_height: u64) -> ICSHeight {
        ICSHeight::new(0, revision_height).expect("valid height")
    }

    fn client_id() -> ClientId {
        "08-cardano-mithril-0".parse().expect("valid client id")
    }

    fn host_state_tx_body_cbor(root: [u8; 32]) -> Vec<u8> {
        fn encode_host_state_output(
            e: &mut pallas_codec::minicbor::Encoder<&mut Vec<u8>>,
            root: [u8; 32],
        ) {
            use pallas_codec::minicbor::data::Tag;

            // Minimal post-Alonzo output map containing only the fields the
            // HostState root extractor reads: address, multiasset value, datum.
            e.map(3).unwrap();
            e.u8(0).unwrap();
            e.bytes(&[0]).unwrap();

            // Value with exactly one HostState NFT under the configured policy.
            // The extractor rejects outputs that do not carry this NFT.
            e.u8(1).unwrap();
            e.array(2).unwrap();
            e.u8(0).unwrap();
            e.map(1).unwrap();
            e.bytes(&HOST_STATE_NFT_POLICY_ID).unwrap();
            e.map(1).unwrap();
            e.bytes(HOST_STATE_NFT_TOKEN_NAME).unwrap();
            e.u8(1).unwrap();

            e.u8(2).unwrap();
            e.array(2).unwrap();
            e.u8(1).unwrap();

            // Inline datum shape expected by `extract_ibc_state_root_from_host_state_datum`:
            // HostState(state, nft_policy), where state contains the 32-byte IBC root.
            let mut datum = Vec::new();
            let mut datum_encoder = pallas_codec::minicbor::Encoder::new(&mut datum);
            datum_encoder.tag(Tag::Unassigned(121)).unwrap();
            datum_encoder.array(2).unwrap();
            datum_encoder.tag(Tag::Unassigned(121)).unwrap();
            datum_encoder.array(2).unwrap();
            datum_encoder.bytes(&[]).unwrap();
            datum_encoder.bytes(&root).unwrap();
            datum_encoder.bytes(&HOST_STATE_NFT_POLICY_ID).unwrap();

            e.tag(Tag::Cbor).unwrap();
            e.bytes(&datum).unwrap();
        }

        let mut tx_body = Vec::new();
        let mut encoder = pallas_codec::minicbor::Encoder::new(&mut tx_body);
        // Minimal transaction body: no inputs, one HostState output, zero fee.
        // This keeps the fixture small while still exercising real CBOR decoding.
        encoder.map(3).unwrap();
        encoder.u8(0).unwrap();
        encoder.array(0).unwrap();
        encoder.u8(1).unwrap();
        encoder.array(1).unwrap();
        encode_host_state_output(&mut encoder, root);
        encoder.u8(2).unwrap();
        encoder.u8(0).unwrap();
        tx_body
    }

    fn raw_protocol_parameters() -> mithril_raw::MithrilProtocolParameters {
        mithril_raw::MithrilProtocolParameters {
            k: 1,
            m: 2,
            phi_f: None,
        }
    }

    fn raw_certificate(hash: &str) -> mithril_raw::MithrilCertificate {
        mithril_raw::MithrilCertificate {
            hash: hash.to_string(),
            previous_hash: String::new(),
            epoch: 0,
            signed_entity_type: None,
            metadata: Some(mithril_raw::CertificateMetadata {
                network: "testnet".to_string(),
                protocol_version: "v1".to_string(),
                protocol_parameters: Some(raw_protocol_parameters()),
                initiated_at: "2024-01-01T00:00:00Z".to_string(),
                sealed_at: "2024-01-01T00:00:01Z".to_string(),
                signers: vec![],
            }),
            protocol_message: None,
            signed_message: String::new(),
            aggregate_verification_key: String::new(),
            multi_signature: String::new(),
            genesis_signature: String::new(),
        }
    }

    fn mithril_header(revision_height: u64, root: [u8; 32]) -> MithrilHeader {
        let tx_body = host_state_tx_body_cbor(root);

        MithrilHeader {
            height: height(revision_height),
            timestamp: Timestamp::from_nanoseconds(1).expect("valid timestamp"),
            mithril_stake_distribution: mithril_raw::MithrilStakeDistribution {
                epoch: 0,
                signers_with_stake: vec![],
                hash: "stake_distribution".to_string(),
                certificate_hash: "stake_distribution_cert".to_string(),
                created_at: 1,
                protocol_parameter: Some(raw_protocol_parameters()),
            },
            mithril_stake_distribution_certificate: raw_certificate("stake_distribution_cert"),
            transaction_snapshot: mithril_raw::CardanoTransactionSnapshot {
                merkle_root: "snapshot_root".to_string(),
                epoch: 0,
                block_number: revision_height,
                hash: "snapshot".to_string(),
                certificate_hash: "tx_snapshot_cert".to_string(),
                created_at: "2024-01-01T00:00:01Z".to_string(),
            },
            transaction_snapshot_certificate: raw_certificate("tx_snapshot_cert"),
            previous_mithril_stake_distribution_certificates: vec![],
            // Match the fixture body hash so conflicts come from the requested
            // root/certificate fields, not from malformed fixture data.
            host_state_tx_hash: hex::encode(blake2b_256(&tx_body)),
            host_state_tx_body_cbor: tx_body,
            host_state_tx_output_index: 0,
            host_state_tx_proof: vec![1],
        }
    }

    fn mithril_client_state() -> AnyClientState {
        AnyClientState::Mithril(MithrilClientState {
            chain_id: ChainId::from_string("cardano-1"),
            latest_height: height(10),
            frozen_height: None,
            current_epoch: 0,
            trusting_period: Duration::from_secs(60),
            protocol_parameters: raw_protocol_parameters(),
            upgrade_path: vec![],
            host_state_nft_policy_id: HOST_STATE_NFT_POLICY_ID.to_vec(),
            host_state_nft_token_name: HOST_STATE_NFT_TOKEN_NAME.to_vec(),
        })
    }

    fn probabilistic_client_state() -> AnyClientState {
        AnyClientState::Probabilistic(ProbabilisticClientState {
            chain_id: ChainId::from_string("cardano-1"),
            latest_height: height(10),
            frozen_height: None,
            current_epoch: 0,
            trusting_period: Duration::from_secs(60),
            upgrade_path: vec![],
            host_state_nft_policy_id: HOST_STATE_NFT_POLICY_ID.to_vec(),
            host_state_nft_token_name: HOST_STATE_NFT_TOKEN_NAME.to_vec(),
            epoch_stake_distribution: vec![],
            epoch_nonce: vec![0; 32],
            slots_per_kes_period: 1,
            current_epoch_start_slot: 1,
            current_epoch_end_slot_exclusive: 2,
            system_start_unix_ns: 1,
            slot_length_ns: 1,
            epoch_contexts: vec![],
            latest_checkpoint_height: Some(height(10)),
            latest_checkpoint_block_hash: "checkpoint-10".to_string(),
            latest_checkpoint_epoch: 0,
            max_kes_evolutions: 62,
            latest_checkpoint_operational_certificate_counters: vec![],
            operational_certificate_state_initialized: true,
            operational_certificate_counter_history_start_height: Some(height(10)),
        })
    }

    fn probabilistic_block(
        revision_height: u64,
        hash: &str,
    ) -> probabilistic_raw::ProbabilisticBlock {
        probabilistic_raw::ProbabilisticBlock {
            height: Some(probabilistic_raw::Height {
                revision_number: 0,
                revision_height,
            }),
            slot: revision_height,
            hash: hash.to_string(),
            epoch: 0,
            timestamp: 1,
            block_cbor: vec![],
        }
    }

    fn probabilistic_header(revision_height: u64, anchor_hash: &str) -> ProbabilisticHeader {
        ProbabilisticHeader {
            trusted_height: height(revision_height - 1),
            height: height(revision_height),
            timestamp: Timestamp::from_nanoseconds(1).expect("valid timestamp"),
            anchor_block: probabilistic_block(revision_height, anchor_hash),
            bridge_blocks: vec![],
            descendant_blocks: vec![],
            // Anchor/hash conflicts short-circuit before block CBOR root extraction.
            host_state_tx_hash: "host_tx".to_string(),
            host_state_tx_output_index: 0,
            new_epoch_context: None,
            is_checkpoint: false,
        }
    }

    fn update_client(header: Option<AnyHeader>, consensus_height: ICSHeight) -> UpdateClient {
        UpdateClient {
            common: Attributes {
                client_id: client_id(),
                client_type: ClientType::CardanoMithril,
                consensus_height,
            },
            header,
        }
    }

    #[test]
    fn latest_height_failure_is_unhealthy_even_when_client_states_probe_succeeds() {
        let error = cardano_latest_height_unhealthy_error(
            &CardanoError::Query("latest height unavailable".to_string()),
            Ok(()),
        );

        let message = error.to_string();
        assert!(message.contains("latest-height probe is required"));
        assert!(message.contains("client-states probe succeeded"));
        assert!(message.contains("latest-height/proof-serving is not ready"));
    }

    #[test]
    fn latest_height_failure_reports_client_states_probe_failure() {
        let error = cardano_latest_height_unhealthy_error(
            &CardanoError::Query("latest height unavailable".to_string()),
            Err(CardanoError::Query("client states unavailable".to_string())),
        );

        let message = error.to_string();
        assert!(message.contains("latest-height probe is required"));
        assert!(message.contains("client-states probe also failed"));
        assert!(message.contains("client states unavailable"));
    }

    #[test]
    fn header_height_errors_accept_typed_recoverable_statuses() {
        let height_not_found = CardanoError::from(tonic::Status::not_found(
            "HEIGHT_NOT_FOUND: no header at height 10",
        ));
        let height_not_accepted = CardanoError::from(tonic::Status::failed_precondition(
            "HEIGHT_NOT_ACCEPTED: height 10 is not an accepted Cardano header height",
        ));

        assert!(is_recoverable_gateway_header_height_error(
            &height_not_found
        ));
        assert!(is_recoverable_gateway_header_height_error(
            &height_not_accepted
        ));
    }

    #[test]
    fn header_height_errors_reject_typed_fatal_statuses() {
        let history_not_ready = CardanoError::from(tonic::Status::unavailable(
            "HISTORY_NOT_READY: Gateway has not indexed the requested range",
        ));
        let invalid_trusted_height = CardanoError::from(tonic::Status::invalid_argument(
            "INVALID_TRUSTED_HEIGHT: trusted height must be lower than target height",
        ));

        assert!(!is_recoverable_gateway_header_height_error(
            &history_not_ready
        ));
        assert!(!is_recoverable_gateway_header_height_error(
            &invalid_trusted_height
        ));
    }

    #[test]
    fn header_height_errors_keep_legacy_text_fallback() {
        let legacy = CardanoError::GatewayClient("Not found: height 10".to_string());

        assert!(is_recoverable_gateway_header_height_error(&legacy));
    }

    #[test]
    fn proof_height_accepts_exact_requested_height() {
        let requested = ICSHeight::new(0, 42).expect("valid requested height");

        // Packet proofs must be tied to the exact query height Hermes requested.
        // Returning any other height would let Gateway silently prove another state.
        let proof_height = proof_height_from_response(
            Some(RawHeight {
                revision_number: 0,
                revision_height: 42,
            }),
            requested,
            "packet commitment",
        )
        .expect("valid proof height");

        assert_eq!(proof_height, requested);
    }

    #[test]
    fn proof_height_errors_when_gateway_omits_height() {
        let requested = ICSHeight::new(0, 10).expect("valid requested height");

        // Missing proof height used to fall back to the query height. Keep this
        // strict so Gateway omissions cannot hide proof serving bugs.
        let error = proof_height_from_response(None, requested, "packet commitment")
            .expect_err("missing proof height must fail");

        assert!(error.to_string().contains("omitted proof_height"));
        assert!(error.to_string().contains("0-10"));
    }

    #[test]
    fn proof_height_errors_when_gateway_returns_wrong_height() {
        let requested = ICSHeight::new(0, 10).expect("valid requested height");

        // A proof for an adjacent height is not equivalent: packet state may have
        // changed between accepted HostState anchors.
        let error = proof_height_from_response(
            Some(RawHeight {
                revision_number: 0,
                revision_height: 11,
            }),
            requested,
            "packet commitment",
        )
        .expect_err("mismatched proof height must fail");

        assert!(error.to_string().contains("proof height mismatch"));
        assert!(error.to_string().contains("requested 0-10"));
        assert!(error.to_string().contains("got 0-11"));
    }

    #[test]
    fn missing_update_header_is_skipped_when_not_strict() {
        let update = update_client(None, height(10));

        // Non-strict mode preserves the existing operational behavior for old
        // Gateway events that do not embed the submitted client message.
        assert!(submitted_cardano_update_header(&update, false)
            .expect("non-strict missing header")
            .is_none());
    }

    #[test]
    fn missing_update_header_errors_when_strict() {
        let update = update_client(None, height(10));

        // Strict mode is the production-safe path: without the submitted header,
        // Hermes cannot compare the event payload against an independent witness.
        let error = submitted_cardano_update_header(&update, true)
            .expect_err("strict missing header must fail");

        assert!(error
            .to_string()
            .contains("does not include the submitted header"));
    }

    #[test]
    fn misbehaviour_no_conflict_returns_no_evidence() {
        let submitted = AnyHeader::Mithril(mithril_header(10, [1; 32]));
        let witness = submitted.clone();
        let update = update_client(Some(submitted.clone()), height(10));

        // Identical submitted and witness headers should be treated as a valid
        // client update, not as misbehaviour evidence.
        let evidence =
            cardano_misbehaviour_evidence(&update, &submitted, witness, &mithril_client_state())
                .expect("misbehaviour check succeeds");

        assert!(evidence.is_none());
    }

    #[test]
    fn misbehaviour_root_conflict_returns_evidence() {
        let submitted = AnyHeader::Mithril(mithril_header(10, [1; 32]));
        let witness = AnyHeader::Mithril(mithril_header(10, [2; 32]));
        let update = update_client(Some(submitted.clone()), height(10));

        // Same height plus different extracted HostState root is the core
        // fork/conflict signal for Mithril-backed Cardano headers.
        let evidence =
            cardano_misbehaviour_evidence(&update, &submitted, witness, &mithril_client_state())
                .expect("misbehaviour check succeeds")
                .expect("conflicting roots produce evidence");

        assert!(matches!(evidence.misbehaviour, AnyMisbehaviour::Mithril(_)));
    }

    #[test]
    fn misbehaviour_anchor_hash_conflict_returns_evidence() {
        let submitted = AnyHeader::Probabilistic(probabilistic_header(10, "anchor_a"));
        let witness = AnyHeader::Probabilistic(probabilistic_header(10, "anchor_b"));
        let update = UpdateClient {
            common: Attributes {
                client_id: client_id(),
                client_type: ClientType::CardanoProbabilistic,
                consensus_height: height(10),
            },
            header: Some(submitted.clone()),
        };

        // Probabilistic headers can prove conflict before root extraction when
        // the accepted anchor at the same height has a different block hash.
        let evidence = cardano_misbehaviour_evidence(
            &update,
            &submitted,
            witness,
            &probabilistic_client_state(),
        )
        .expect("misbehaviour check succeeds")
        .expect("conflicting anchors produce evidence");

        assert!(matches!(
            evidence.misbehaviour,
            AnyMisbehaviour::Probabilistic(_)
        ));
    }

    #[test]
    fn misbehaviour_witness_wrong_height_errors() {
        let submitted = AnyHeader::Mithril(mithril_header(10, [1; 32]));
        let witness = AnyHeader::Mithril(mithril_header(11, [1; 32]));
        let update = update_client(Some(submitted.clone()), height(10));

        // Evidence requires two headers at the same client height. A mismatched
        // witness height means the independent query is unusable, not conflicting.
        let error =
            cardano_misbehaviour_evidence(&update, &submitted, witness, &mithril_client_state())
                .expect_err("wrong witness height must fail");

        assert!(error
            .to_string()
            .contains("independent Cardano header height mismatch"));
    }

    #[test]
    fn mithril_evidence_is_encoded_as_msg_update_client_misbehaviour() {
        let submitted = mithril_header(10, [1; 32]);
        let witness = mithril_header(10, [2; 32]);
        let misbehaviour = AnyMisbehaviour::Mithril(MithrilMisbehaviour {
            client_id: client_id(),
            header1: submitted,
            header2: witness,
        });

        // Hermes submits Cardano evidence through MsgUpdateClient with the
        // misbehaviour Any in `client_message`, matching the Gateway contract.
        let msg = ibc_relayer_types::core::ics02_client::msgs::update_client::MsgUpdateClient {
            client_id: client_id(),
            header: misbehaviour.into(),
            signer: "cardano-signer".parse().expect("valid signer"),
        };
        let raw: ibc_proto::ibc::core::client::v1::MsgUpdateClient = msg.into();
        let header = raw.client_message.expect("client message");

        assert_eq!(
            header.type_url,
            ibc_relayer_types::clients::ics08_cardano::misbehaviour::MITHRIL_MISBEHAVIOUR_TYPE_URL
        );
        assert!(MithrilMisbehaviour::decode_vec(&header.value).is_ok());
    }
}
