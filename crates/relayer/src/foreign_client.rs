//! Queries and methods for interfacing with foreign clients.
//!
//! The term "foreign client" refers to IBC light clients that are running on-chain,
//! i.e. they are *foreign* to the relayer. In contrast, the term "local client"
//! refers to light clients running *locally* as part of the relayer.

use core::{fmt, time::Duration};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use ibc_proto::google::protobuf::Any;
use ibc_relayer_types::applications::ics28_ccv::msgs::ConsumerId;
use itertools::Itertools;
use tracing::{debug, error, info, instrument, trace, warn};

use flex_error::define_error;
use ibc_relayer_types::applications::ics28_ccv::msgs::ccv_misbehaviour::MsgSubmitIcsConsumerMisbehaviour;
use ibc_relayer_types::core::ics02_client::client_state::ClientState;
use ibc_relayer_types::core::ics02_client::client_type::ClientType;
use ibc_relayer_types::core::ics02_client::error::Error as ClientError;
use ibc_relayer_types::core::ics02_client::events::UpdateClient;
use ibc_relayer_types::core::ics02_client::header::{AnyHeader, Header};
use ibc_relayer_types::core::ics02_client::msgs::create_client::MsgCreateClient;
use ibc_relayer_types::core::ics02_client::msgs::update_client::MsgUpdateClient;
use ibc_relayer_types::core::ics02_client::msgs::upgrade_client::MsgUpgradeClient;
use ibc_relayer_types::core::ics02_client::trust_threshold::TrustThreshold;
use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ClientId};
use ibc_relayer_types::downcast;
use ibc_relayer_types::events::{IbcEvent, IbcEventType, WithBlockDataType};
use ibc_relayer_types::timestamp::{Timestamp, TimestampOverflowError};
use ibc_relayer_types::tx_msg::Msg;
use ibc_relayer_types::Height;

use crate::chain::client::ClientSettings;
use crate::chain::handle::ChainHandle;
use crate::chain::requests::*;
use crate::chain::tracking::TrackedMsgs;
use crate::client_state::AnyClientState;
use crate::config::ChainConfig;
use crate::consensus_state::AnyConsensusState;
use crate::error::Error as RelayerError;
use crate::event::IbcEventWithHeight;
use crate::misbehaviour::{AnyMisbehaviour, MisbehaviourEvidence};
use crate::telemetry;
use crate::util::collate::CollatedIterExt;
use crate::util::pretty::{PrettyDuration, PrettySlice};

const MAX_MISBEHAVIOUR_CHECK_DURATION: Duration = Duration::from_secs(120);

const MAX_RETRIES: usize = 5;
const CREATE_CLIENT_DISCOVERY_MAX_RETRIES: usize = 30;
const CREATE_CLIENT_DISCOVERY_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_PROBABILISTIC_CHECKPOINT_UPDATES: usize = 4_096;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExpiredOrFrozen {
    Expired,
    Frozen,
}

impl fmt::Display for ExpiredOrFrozen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExpiredOrFrozen::Expired => write!(f, "expired"),
            ExpiredOrFrozen::Frozen => write!(f, "frozen"),
        }
    }
}

define_error! {
    ForeignClientError {
        ClientCreate
            {
                chain_id: ChainId,
                description: String
            }
            [ RelayerError ]
            |e| {
                format_args!("error raised while creating client for chain {0}: {1}",
                    e.chain_id, e.description)
            },

        Client
            [ ClientError ]
            |_| { "ICS02 client error" },

        HeaderInTheFuture
            {
                src_chain_id: ChainId,
                src_header_height: Height,
                src_header_time: Timestamp,
                dst_chain_id: ChainId,
                dst_latest_header_height: Height,
                dst_latest_header_time: Timestamp,
                max_drift: Duration
            }
            |e| {
                format_args!("update header from {} with height {} and time {} is in the future compared with latest header on {} with height {} and time {}, adjusted with drift {:?}",
                 e.src_chain_id, e.src_header_height, e.src_header_time, e.dst_chain_id, e.dst_latest_header_height, e.dst_latest_header_time, e.max_drift)
            },

        ClientUpdate
            {
                chain_id: ChainId,
                description: String
            }
            [ RelayerError ]
            |e| {
                format_args!("error raised while updating client on chain {0}: {1}", e.chain_id, e.description)
            },

        CheckpointUpdate
            {
                chain_id: ChainId,
                description: String
            }
            |e| {
                format_args!("error while advancing probabilistic checkpoints on chain {0}: {1}", e.chain_id, e.description)
            },

        ClientUpdateTiming
            {
                chain_id: ChainId,
                clock_drift: Duration,
                description: String
            }
            [ TimestampOverflowError ]
            |e| {
                format_args!("error raised while updating client on chain {0}: {1}", e.chain_id, e.description)
            },

        ClientAlreadyUpToDate
            {
                client_id: ClientId,
                chain_id: ChainId,
                height: Height,
            }
            |e| {
                format_args!("client {} is already up-to-date with chain {} at height {}",
                    e.client_id, e.chain_id, e.height)
            },

        MissingSmallerTrustedHeight
            {
                chain_id: ChainId,
                target_height: Height,
            }
            |e| {
                format_args!("chain {} is missing trusted state smaller than target height {}",
                    e.chain_id, e.target_height)
            },

        MissingTrustedHeight
            {
                chain_id: ChainId,
                target_height: Height,
            }
            |e| {
                format_args!("chain {} is missing trusted state at target height {}",
                    e.chain_id, e.target_height)
            },

        ClientRefresh
            {
                client_id: ClientId,
                reason: String
            }
            [ RelayerError ]
            |e| {
                format_args!("error raised while trying to refresh client {0}: {1}",
                    e.client_id, e.reason)
            },

        ClientQuery
            {
                client_id: ClientId,
                chain_id: ChainId,
            }
            [ RelayerError ]
            |e| {
                format_args!("failed while querying for client {0} on chain id {1}",
                    e.client_id, e.chain_id)
            },

        ClientConsensusQuery
            {
                client_id: ClientId,
                chain_id: ChainId,
                height: Height
            }
            [ RelayerError ]
            |e| {
                format_args!("failed while querying for client consensus state {0} on chain id {1} for height {2}",
                    e.client_id, e.chain_id, e.height)
            },

        ClientUpgrade
            {
                client_id: ClientId,
                chain_id: ChainId,
                description: String,
            }
            [ RelayerError ]
            |e| {
                format_args!("failed while trying to upgrade client id {0} for chain {1}: {2}: {3}",
                    e.client_id, e.chain_id, e.description, e.source)
            },

        ClientUpgradeNoSource
        {
            client_id: ClientId,
            chain_id: ChainId,
            description: String,
        }
        |e| {
            format_args!("failed while trying to upgrade client id {0} for chain {1}: {2}",
                    e.client_id, e.chain_id, e.description)
        },

        ClientEventQuery
            {
                client_id: ClientId,
                chain_id: ChainId,
                consensus_height: Height
            }
            [ RelayerError ]
            |e| {
                format_args!("failed while querying Tx for client {0} on chain id {1} at consensus height {2}",
                    e.client_id, e.chain_id, e.consensus_height)
            },

        UnexpectedEvent
            {
                client_id: ClientId,
                chain_id: ChainId,
                event: String,
            }
            |e| {
                format_args!("failed while querying Tx for client {0} on chain id {1}: query Tx-es returned unexpected event: {2}",
                    e.client_id, e.chain_id, e.event)
            },

        MismatchChainId
            {
                client_id: ClientId,
                expected_chain_id: ChainId,
                actual_chain_id: ChainId,
            }
            |e| {
                format_args!("failed while finding client {0}: expected chain_id in client state: {1}; actual chain_id: {2}",
                    e.client_id, e.expected_chain_id, e.actual_chain_id)
            },

        ExpiredOrFrozen
            {
                status: ExpiredOrFrozen,
                client_id: ClientId,
                chain_id: ChainId,
                description: String,
            }
            |e| {
                format_args!("client {0} on chain id {1} is {2}: {3}",
                    e.client_id, e.chain_id, e.status, e.description)
            },

        ConsensusStateNotTrusted
            {
                height: Height,
                elapsed: Duration,
            }
            |e| {
                format_args!("the consensus state at height {} is outside of trusting period: elapsed {:?}",
                    e.height, e.elapsed)
            },

        Misbehaviour
            {
                description: String,
            }
            [ RelayerError ]
            |e| {
                format_args!("error raised while checking for misbehaviour evidence: {0}", e.description)
            },

        MisbehaviourDesc
            {
                description: String,
            }
            |e| {
                format_args!("error raised while checking for misbehaviour evidence: {0}", e.description)
            },

        MisbehaviourExit
            { reason: String }
            |e| {
                format_args!("cannot run misbehaviour: {0}", e.reason)
            },

        SameChainId
            {
                chain_id: ChainId
            }
            |e| {
                format_args!("the chain ID ({}) at the source and destination chains must be different", e.chain_id)
            },

        MissingClientIdFromEvent
            { event: IbcEvent }
            |e| {
                format_args!("cannot extract client_id from result: {:?}",
                    e.event)
            },

        ChainErrorEvent
            {
                chain_id: ChainId,
                event: IbcEvent
            }
            |e| {
                format_args!("failed to update client on destination {} because of error event: {}",
                    e.chain_id, e.event)
            },
    }
}

pub trait HasExpiredOrFrozenError {
    fn is_expired_error(&self) -> bool;
    fn is_frozen_error(&self) -> bool;

    fn is_expired_or_frozen_error(&self) -> bool {
        self.is_expired_error() || self.is_frozen_error()
    }
}

impl HasExpiredOrFrozenError for ForeignClientErrorDetail {
    fn is_expired_error(&self) -> bool {
        if let Self::ExpiredOrFrozen(e) = self {
            e.status == ExpiredOrFrozen::Expired
        } else {
            false
        }
    }

    fn is_frozen_error(&self) -> bool {
        if let Self::ExpiredOrFrozen(e) = self {
            e.status == ExpiredOrFrozen::Frozen
        } else {
            false
        }
    }
}

impl HasExpiredOrFrozenError for ForeignClientError {
    fn is_expired_error(&self) -> bool {
        self.detail().is_expired_error()
    }

    fn is_frozen_error(&self) -> bool {
        self.detail().is_frozen_error()
    }
}

/// User-supplied options for the [`ForeignClient::build_create_client`] operation.
///
/// Currently, the parameters are specific to the Tendermint-based chains.
/// A future revision will bring differentiated options for other chain types.
#[derive(Debug, Default)]
pub struct CreateOptions {
    pub max_clock_drift: Option<Duration>,
    pub trusting_period: Option<Duration>,
    pub trust_threshold: Option<TrustThreshold>,
}

/// Captures the diagnostic of verifying whether a certain
/// consensus state is within the trusting period (i.e., trusted)
/// or it's not within the trusting period (not trusted).
pub enum ConsensusStateTrusted {
    NotTrusted {
        elapsed: Duration,
        network_timestamp: Timestamp,
        consensus_state_timestamp: Timestamp,
    },
    Trusted {
        elapsed: Duration,
    },
}

#[derive(Debug, Default)]
struct ProbabilisticScan {
    namespace: Vec<u8>,
    generation: u64,
    after: Vec<u8>,
    retry: VecDeque<(Vec<u8>, serde_json::Value)>,
}

#[derive(Clone, Debug)]
pub struct ForeignClient<DstChain: ChainHandle, SrcChain: ChainHandle> {
    /// The identifier of this client. The host chain determines this id upon client creation,
    /// so we may be using the default value temporarily.
    pub id: ClientId,

    /// A handle to the chain hosting this client, i.e., destination chain.
    pub dst_chain: DstChain,

    /// A handle to the chain whose headers this client is verifying, aka the source chain.
    pub src_chain: SrcChain,
    probabilistic_scan: Arc<Mutex<ProbabilisticScan>>,
}

/// Used in Output messages.
/// Provides a concise description of a [`ForeignClient`],
/// using the format:
///     {CHAIN-ID}->{CHAIN-ID}:{CLIENT}
/// where the first chain identifier is for the source
/// chain, and the second chain identifier is the
/// destination (which hosts the client) chain.
impl<DstChain: ChainHandle, SrcChain: ChainHandle> fmt::Display
    for ForeignClient<DstChain, SrcChain>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}->{}:{}",
            self.src_chain.id(),
            self.dst_chain.id(),
            self.id
        )
    }
}

impl<DstChain: ChainHandle, SrcChain: ChainHandle> ForeignClient<DstChain, SrcChain> {
    /// Creates a new foreign client on `dst_chain`. Blocks until the client is created, or
    /// an error occurs.
    /// Post-condition: `dst_chain` hosts an IBC client for `src_chain`.
    pub fn new(
        dst_chain: DstChain,
        src_chain: SrcChain,
    ) -> Result<ForeignClient<DstChain, SrcChain>, ForeignClientError> {
        // Sanity check
        if src_chain.id().eq(&dst_chain.id()) {
            return Err(ForeignClientError::same_chain_id(src_chain.id()));
        }

        let mut client = ForeignClient {
            id: ClientId::default(),
            dst_chain,
            src_chain,
            probabilistic_scan: Arc::default(),
        };

        client.create()?;

        Ok(client)
    }

    pub fn restore(
        id: ClientId,
        dst_chain: DstChain,
        src_chain: SrcChain,
    ) -> ForeignClient<DstChain, SrcChain> {
        ForeignClient {
            id,
            dst_chain,
            src_chain,
            probabilistic_scan: Arc::default(),
        }
    }

    /// Queries `host_chain` to verify that a client with identifier `client_id` exists.
    /// If the client does not exist, returns an error. If the client exists, cross-checks that the
    /// identifier for the target chain of this client (i.e., the chain whose headers this client is
    /// verifying) is consistent with `expected_target_chain`, and if so, return a new
    /// `ForeignClient` representing this client.
    pub fn find(
        expected_target_chain: SrcChain,
        host_chain: DstChain,
        client_id: &ClientId,
    ) -> Result<ForeignClient<DstChain, SrcChain>, ForeignClientError> {
        match host_chain.query_client_state(
            QueryClientStateRequest {
                client_id: client_id.clone(),
                height: QueryHeight::Latest,
            },
            IncludeProof::No,
        ) {
            Ok((cs, _)) => {
                if cs.chain_id() != expected_target_chain.id() {
                    Err(ForeignClientError::mismatch_chain_id(
                        client_id.clone(),
                        expected_target_chain.id(),
                        cs.chain_id(),
                    ))
                } else {
                    // TODO: Any additional checks?
                    Ok(ForeignClient::restore(
                        client_id.clone(),
                        host_chain,
                        expected_target_chain,
                    ))
                }
            }
            Err(e) => Err(ForeignClientError::client_query(
                client_id.clone(),
                host_chain.id(),
                e,
            )),
        }
    }

    /// Create and send a transaction to perform a client upgrade.
    /// src_upgrade_height: The height on the source chain at which the chain will halt for the upgrade.
    #[instrument(
        name = "foreign_client.upgrade",
        level = "error",
        skip(self),
        fields(client = %self)
    )]
    pub fn upgrade(&self, src_upgrade_height: Height) -> Result<Vec<IbcEvent>, ForeignClientError> {
        let msgs = self
            .build_update_client_with_trusted(src_upgrade_height, None)
            .map_err(|_| {
                ForeignClientError::client_upgrade_no_source(
                    self.id.clone(),
                    self.dst_chain.id(),
                    format!(
                        "is chain {} halted at height {}?",
                        self.src_chain().id(),
                        src_upgrade_height
                    ),
                )
            })?;

        let mut msgs: Vec<Any> = msgs.into_iter().map(Msg::to_any).collect();

        // Query the host chain for the upgraded client state, consensus state & their proofs.
        let (client_state, proof_upgrade_client) = self
            .src_chain
            .query_upgraded_client_state(QueryUpgradedClientStateRequest {
                upgrade_height: src_upgrade_height,
            })
            .map_err(|e| {
                ForeignClientError::client_upgrade(
                    self.id.clone(),
                    self.src_chain.id(),
                    format!("failed while fetching from chain the upgraded client state. The upgrade height `{src_upgrade_height}` might be too low"),
                    e,
                )
            })?;

        debug!("upgraded client state {:?}", client_state);

        let (consensus_state, proof_upgrade_consensus_state) = self
            .src_chain
            .query_upgraded_consensus_state(QueryUpgradedConsensusStateRequest {
                upgrade_height: src_upgrade_height,
            })
            .map_err(|e| {
                ForeignClientError::client_upgrade(
                    self.id.clone(),
                    self.src_chain.id(),
                    "failed while fetching from chain the upgraded client consensus state"
                        .to_string(),
                    e,
                )
            })?;

        debug!("upgraded client consensus state {:?}", consensus_state);

        // Get signer
        let signer = self.dst_chain.get_signer().map_err(|e| {
            ForeignClientError::client_upgrade(
                self.id.clone(),
                self.dst_chain.id(),
                "failed while fetching the destination chain signer".to_string(),
                e,
            )
        })?;

        let msg_upgrade = MsgUpgradeClient {
            client_id: self.id.clone(),
            client_state: client_state.into(),
            consensus_state: consensus_state.into(),
            proof_upgrade_client: proof_upgrade_client.into(),
            proof_upgrade_consensus_state: proof_upgrade_consensus_state.into(),
            signer,
        }
        .to_any();

        msgs.push(msg_upgrade);

        let tm = TrackedMsgs::new_static(msgs, "upgrade client");

        let res = self
            .dst_chain
            .send_messages_and_wait_commit(tm)
            .map_err(|e| {
                ForeignClientError::client_upgrade(
                    self.id.clone(),
                    self.dst_chain.id(),
                    "failed while sending message to destination chain".to_string(),
                    e,
                )
            })?;

        Ok(res
            .into_iter()
            .map(|ev_with_height| ev_with_height.event)
            .collect())
    }

    /// Returns a handle to the chain hosting this client.
    pub fn dst_chain(&self) -> DstChain {
        self.dst_chain.clone()
    }

    /// Returns a handle to the chain whose headers this client is sourcing (the source chain).
    pub fn src_chain(&self) -> SrcChain {
        self.src_chain.clone()
    }

    pub fn id(&self) -> &ClientId {
        &self.id
    }

    /// Lower-level interface for preparing a message to create a client.
    pub fn build_create_client(
        &self,
        options: CreateOptions,
    ) -> Result<MsgCreateClient, ForeignClientError> {
        // Get signer
        let signer = self.dst_chain.get_signer().map_err(|e| {
            ForeignClientError::client_create(
                self.src_chain.id(),
                format!(
                    "failed while fetching the dst chain ({}) signer",
                    self.dst_chain.id()
                ),
                e,
            )
        })?;

        let src_config = self.src_chain.config().map_err(|e| {
            ForeignClientError::client_create(
                self.src_chain.id(),
                "failed while querying the source chain for configuration".to_string(),
                e,
            )
        })?;

        if matches!(src_config, crate::config::ChainConfig::Cardano(_)) {
            let initial = self
                .src_chain
                .query_client_initialization(0, 0)
                .map_err(|e| {
                    ForeignClientError::checkpoint_update(self.dst_chain.id(), e.to_string())
                })?;
            if let AnyClientState::Probabilistic(client) = &initial.client_state {
                if client.trusting_period <= crate::chain::cardano::checkpoint::maintenance_budget()
                {
                    return Err(ForeignClientError::checkpoint_update(self.dst_chain.id(), "probabilistic trusting period must exceed the bounded maintenance and response-window budget, use at least 48 hours".to_owned()));
                }
            }
            return MsgCreateClient::new(
                initial.client_state.into(),
                initial.consensus_state.into(),
                signer,
            )
            .map_err(ForeignClientError::client);
        }

        let latest_height = self.src_chain.query_latest_height().map_err(|e| {
            ForeignClientError::client_create(
                self.src_chain.id(),
                "failed while querying src chain for latest height".to_string(),
                e,
            )
        })?;

        let dst_config = self.dst_chain.config().map_err(|e| {
            ForeignClientError::client_create(
                self.dst_chain.id(),
                "failed while querying the destination chain for configuration".to_string(),
                e,
            )
        })?;

        let settings = ClientSettings::for_create_command(options, &src_config, &dst_config);

        let client_state: AnyClientState = self
            .src_chain
            .build_client_state(latest_height, settings)
            .map_err(|e| {
                ForeignClientError::client_create(
                    self.src_chain.id(),
                    "failed when building client state".to_string(),
                    e,
                )
            })?;

        let consensus_state = self
            .src_chain
            .build_consensus_state(
                client_state.latest_height(),
                latest_height,
                client_state.clone(),
            )
            .map_err(|e| {
                ForeignClientError::client_create(
                    self.src_chain.id(),
                    "failed while building client consensus state from src chain".to_string(),
                    e,
                )
            })?;

        //TODO Get acct_prefix
        let msg = MsgCreateClient::new(client_state.into(), consensus_state.into(), signer)
            .map_err(ForeignClientError::client)?;

        Ok(msg)
    }

    /// Returns the identifier of the newly created client.
    pub fn build_create_client_and_send(
        &self,
        options: CreateOptions,
    ) -> Result<IbcEventWithHeight, ForeignClientError> {
        let new_msg = self.build_create_client(options)?;

        let res = self
            .dst_chain
            .send_messages_and_wait_commit(TrackedMsgs::new_single(
                new_msg.to_any(),
                "create client",
            ))
            .map_err(|e| {
                ForeignClientError::client_create(
                    self.dst_chain.id(),
                    "failed sending message to dst chain ".to_string(),
                    e,
                )
            })?;

        if res.is_empty() {
            return Err(ForeignClientError::client_create(
                self.dst_chain.id(),
                "create client transaction committed but returned no IBC events".to_string(),
                RelayerError::event(),
            ));
        }
        let mut created = self.clone();
        created.id = extract_client_id(&res[0].event)?.clone();
        created.complete_bootstrap()?;
        Ok(res[0].clone())
    }

    /// Sends the client creation transaction & subsequently sets the id of this ForeignClient
    #[instrument(
        name = "foreign_client.create",
        level = "error",
        skip(self),
        fields(client = %self)
    )]
    fn create(&mut self) -> Result<(), ForeignClientError> {
        let existing_client_ids = match self.query_destination_clients_for_source_chain() {
            Ok(client_ids) => Some(client_ids),
            Err(error) => {
                debug!(
                    "destination client pre-scan unavailable, falling back to event-only client creation path: {}",
                    error
                );
                None
            }
        };
        let new_msg = self.build_create_client(CreateOptions::default())?;

        let res = self
            .dst_chain
            .send_messages_and_wait_commit(TrackedMsgs::new_single(
                new_msg.to_any(),
                "create client",
            ))
            .map_err(|e| {
                ForeignClientError::client_create(
                    self.dst_chain.id(),
                    "failed sending message to dst chain ".to_string(),
                    e,
                )
            })
            .map_err(|e| {
                error!("failed to create client: {}", e);
                e
            })?;

        if let Some(event_with_height) = res.first() {
            self.id = extract_client_id(&event_with_height.event)?.clone();
            info!(id = %self.id, "client was created successfully");
            debug!(id = %self.id, ?event_with_height.event, "event emitted after creation");
            self.complete_bootstrap()?;
            return Ok(());
        }

        let Some(existing_client_ids) = existing_client_ids.as_deref() else {
            return Err(ForeignClientError::client_create(
                self.dst_chain.id(),
                "create client transaction committed but returned no IBC events, and destination chain does not support client discovery fallback".to_string(),
                RelayerError::event(),
            ));
        };

        self.id = self.infer_latest_created_client_id(existing_client_ids)?;
        warn!(
            id = %self.id,
            "create client emitted no parsable IBC event, inferred client id from destination chain state"
        );
        info!(id = %self.id, "client was created successfully");
        self.complete_bootstrap()?;
        Ok(())
    }

    fn query_destination_clients_for_source_chain(
        &self,
    ) -> Result<Vec<ClientId>, ForeignClientError> {
        let src_chain_id = self.src_chain.id();
        self.dst_chain
            .query_clients(QueryClientStatesRequest { pagination: None })
            .map_err(|e| {
                ForeignClientError::client_create(
                    self.dst_chain.id(),
                    "failed to query destination clients after create client".to_string(),
                    e,
                )
            })
            .map(|clients| {
                clients
                    .into_iter()
                    .filter(|client| client.client_state.chain_id() == src_chain_id)
                    .map(|client| client.client_id)
                    .collect()
            })
    }

    fn infer_latest_created_client_id(
        &self,
        previous_client_ids: &[ClientId],
    ) -> Result<ClientId, ForeignClientError> {
        let previous_client_ids: Vec<String> = previous_client_ids
            .iter()
            .map(|client_id| client_id.to_string())
            .collect();

        for attempt in 0..CREATE_CLIENT_DISCOVERY_MAX_RETRIES {
            let newest_observed = self
                .query_destination_clients_for_source_chain()?
                .into_iter()
                .filter(|client_id| {
                    !previous_client_ids
                        .iter()
                        .any(|previous_id| previous_id == client_id.as_str())
                })
                .max_by_key(|client_id| parse_client_counter(client_id.as_str()));

            if let Some(client_id) = newest_observed {
                return Ok(client_id);
            }

            if attempt + 1 < CREATE_CLIENT_DISCOVERY_MAX_RETRIES {
                debug!(
                    retries_remaining = CREATE_CLIENT_DISCOVERY_MAX_RETRIES - attempt - 1,
                    "create client emitted no parsable event, waiting for destination chain indexers"
                );
                thread::sleep(CREATE_CLIENT_DISCOVERY_RETRY_DELAY);
            }
        }

        let latest_known_client = self
            .query_destination_clients_for_source_chain()?
            .into_iter()
            .max_by_key(|client_id| parse_client_counter(client_id.as_str()));

        if let Some(client_id) = latest_known_client {
            return Err(ForeignClientError::client_create(
                self.dst_chain.id(),
                format!(
                    "create client returned no events and no new matching client id appeared on destination chain (latest observed: {})",
                    client_id
                ),
                RelayerError::event(),
            ));
        }

        Err(ForeignClientError::client_create(
            self.dst_chain.id(),
            "create client returned no events and no matching client id was found on destination chain".to_string(),
            RelayerError::event(),
        ))
    }

    #[instrument(
        name = "foreign_client.validated_client_state",
        level = "error",
        skip(self),
        fields(client = %self)
    )]
    pub fn validated_client_state(
        &self,
    ) -> Result<(AnyClientState, Option<Duration>), ForeignClientError> {
        let (client_state, _) = {
            self.dst_chain
                .query_client_state(
                    QueryClientStateRequest {
                        client_id: self.id().clone(),
                        height: QueryHeight::Latest,
                    },
                    IncludeProof::No,
                )
                .map_err(|e| {
                    ForeignClientError::client_refresh(
                        self.id().clone(),
                        "failed querying client state on dst chain".to_string(),
                        e,
                    )
                })?
        };

        if client_state.is_frozen() {
            return Err(ForeignClientError::expired_or_frozen(
                ExpiredOrFrozen::Frozen,
                self.id().clone(),
                self.dst_chain.id(),
                "client state reports that client is frozen".into(),
            ));
        }

        if matches!(client_state, AnyClientState::Probabilistic(_)) {
            return self.validated_probabilistic_client_state();
        }

        match self
            .check_consensus_state_trusting_period(&client_state, &client_state.latest_height())?
        {
            ConsensusStateTrusted::NotTrusted {
                elapsed,
                network_timestamp,
                consensus_state_timestamp,
            } => {
                error!(
                    latest_height = %client_state.latest_height(),
                    network_timestamp = %network_timestamp,
                    consensus_state_timestamp = %consensus_state_timestamp,
                    elapsed = ?elapsed,
                    "client state is not valid: latest height is outside of trusting period!",
                );
                Err(ForeignClientError::expired_or_frozen(
                    ExpiredOrFrozen::Expired,
                    self.id().clone(),
                    self.dst_chain.id(),
                    format!("time elapsed since last client update: {elapsed:?}"),
                ))
            }
            ConsensusStateTrusted::Trusted { elapsed } => Ok((client_state, Some(elapsed))),
        }
    }

    fn validated_probabilistic_client_state(
        &self,
    ) -> Result<(AnyClientState, Option<Duration>), ForeignClientError> {
        let query_error = |error| {
            ForeignClientError::client_refresh(
                self.id.clone(),
                "failed querying committed destination freshness".to_owned(),
                error,
            )
        };
        let committed = self
            .dst_chain
            .query_application_status()
            .map_err(query_error)?;
        let (client, _) = self
            .dst_chain
            .query_client_state(
                QueryClientStateRequest {
                    client_id: self.id.clone(),
                    height: QueryHeight::Specific(committed.height),
                },
                IncludeProof::No,
            )
            .map_err(query_error)?;
        let AnyClientState::Probabilistic(state) = &client else {
            return Err(query_error(RelayerError::query(
                "destination changed client type".to_owned(),
            )));
        };
        let derived = state
            .latest_checkpoint_slot
            .checked_mul(state.slot_length_ns)
            .and_then(|offset| state.system_start_unix_ns.checked_add(offset));
        if state.storage_version != 2
            || state.latest_checkpoint_height.is_none()
            || state.latest_checkpoint_timestamp == 0
            || derived != Some(state.latest_checkpoint_timestamp)
        {
            return Err(query_error(RelayerError::query(
                "invalid authenticated checkpoint timestamp or storage format".to_owned(),
            )));
        }
        let checkpoint_time = Timestamp::from_nanoseconds(state.latest_checkpoint_timestamp)
            .map_err(|error| query_error(RelayerError::query(error.to_string())))?;
        let elapsed = committed
            .timestamp
            .duration_since(&checkpoint_time)
            .unwrap_or_default();
        let status = self
            .dst_chain
            .query_client_status(self.id.clone(), QueryHeight::Specific(committed.height))
            .map_err(query_error)?;
        let frozen = state.frozen_height.is_some() || status.as_deref() == Some("Frozen");
        let active = match status.as_deref() {
            Some("Active") => true,
            None => !client.expired(elapsed),
            Some(_) => false,
        };
        if frozen || !active {
            return Err(ForeignClientError::expired_or_frozen(
                if frozen {
                    ExpiredOrFrozen::Frozen
                } else {
                    ExpiredOrFrozen::Expired
                },
                self.id.clone(),
                self.dst_chain.id(),
                format!(
                    "destination client status {:?}, checkpoint elapsed {elapsed:?}",
                    status
                ),
            ));
        }
        Ok((client, Some(elapsed)))
    }

    /// Verifies if the consensus state at given [`Height`]
    /// is within or outside of the client's trusting period.
    #[instrument(
        name = "foreign_client.check_consensus_state_trusting_period",
        level = "error",
        skip_all,
        fields(client = %self, %height)
    )]
    fn check_consensus_state_trusting_period(
        &self,
        client_state: &AnyClientState,
        height: &Height,
    ) -> Result<ConsensusStateTrusted, ForeignClientError> {
        // Safety check
        if client_state.chain_id() != self.src_chain.id() {
            warn!("the chain id in the client state ('{}') is inconsistent with the client's source chain id ('{}')",
            client_state.chain_id(), self.src_chain.id());
        }

        let consensus_state_timestamp = self.fetch_consensus_state(*height)?.timestamp();

        let network_status = if matches!(client_state, AnyClientState::Probabilistic(_)) {
            self.dst_chain.query_application_status()
        } else {
            self.src_chain.query_application_status()
        };
        let current_src_network_time = network_status
            .map_err(|e| {
                ForeignClientError::client_refresh(
                    self.id().clone(),
                    "failed querying the application status of source chain".to_string(),
                    e,
                )
            })?
            .timestamp;

        // Compute the duration of time elapsed since this consensus state was installed
        let elapsed = current_src_network_time
            .duration_since(&consensus_state_timestamp)
            .unwrap_or_default();

        if client_state.expired(elapsed) {
            Ok(ConsensusStateTrusted::NotTrusted {
                elapsed,
                network_timestamp: current_src_network_time,
                consensus_state_timestamp,
            })
        } else {
            Ok(ConsensusStateTrusted::Trusted { elapsed })
        }
    }

    pub fn is_frozen(&self) -> bool {
        match self.validated_client_state() {
            Ok(_) => false,
            Err(e) => e.is_frozen_error(),
        }
    }

    pub fn is_expired(&self) -> bool {
        match self.validated_client_state() {
            Ok(_) => false,
            Err(e) => e.is_expired_error(),
        }
    }

    pub fn is_expired_or_frozen(&self) -> bool {
        match self.validated_client_state() {
            Ok(_) => false,
            Err(e) => e.is_expired_or_frozen_error(),
        }
    }

    #[instrument(
        name = "foreign_client.refresh",
        level = "error",
        skip_all,
        fields(client = %self)
    )]
    pub fn refresh(&mut self) -> Result<Option<Vec<IbcEvent>>, ForeignClientError> {
        fn check_no_errors(
            ibc_events: &[IbcEvent],
            dst_chain_id: ChainId,
        ) -> Result<(), ForeignClientError> {
            // The assumption is that only one IbcEventType::ChainError will be
            // in the resulting Vec<IbcEvent> if an error occurred.
            let chain_error = ibc_events
                .iter()
                .find(|&e| e.event_type() == IbcEventType::ChainError);

            match chain_error {
                None => Ok(()),
                Some(ev) => Err(ForeignClientError::chain_error_event(
                    dst_chain_id,
                    ev.to_owned(),
                )),
            }
        }

        // If elapsed < refresh_window for the client, `try_refresh()` will
        // be successful with an empty vector.
        if let Some(events) = self.try_refresh()? {
            check_no_errors(&events, self.dst_chain().id())?;
            Ok(Some(events))
        } else {
            Ok(None)
        }
    }

    fn try_refresh(&mut self) -> Result<Option<Vec<IbcEvent>>, ForeignClientError> {
        let (client_state, elapsed) = self.validated_client_state()?;
        if matches!(&client_state, AnyClientState::Probabilistic(client) if client.bootstrap_pending)
        {
            self.complete_bootstrap()?;
            return Ok(Some(vec![]));
        }
        self.record_mithril_stake(&client_state);

        let src_config = self.src_chain.config().map_err(|e| {
            ForeignClientError::client_create(
                self.src_chain.id(),
                "failed while querying the source chain for configuration".to_string(),
                e,
            )
        })?;

        let refresh_rate = match src_config {
            ChainConfig::CosmosSdk(config) => config.client_refresh_rate,
            #[cfg(feature = "namada")]
            ChainConfig::Namada(config) => config.client_refresh_rate,
            #[cfg(feature = "penumbra")]
            ChainConfig::Penumbra(config) => config.client_refresh_rate,
            ChainConfig::Cardano(config) => config.client_refresh_rate,
        };

        let refresh_period = client_state
            .trusting_period()
            .mul_f64(refresh_rate.as_f64());

        match (elapsed, refresh_period) {
            (None, _) => Ok(None),
            (Some(elapsed), refresh_period) => {
                let refresh_period =
                    if matches!(client_state, AnyClientState::Probabilistic(_)) {
                        // Start well before expiry to leave room for bounded history,
                        // epoch response windows, retries and destination inclusion.
                        {
                            let AnyClientState::Probabilistic(state) = &client_state else {
                                unreachable!()
                            };
                            refresh_period.min(state.trusting_period.saturating_sub(
                                crate::chain::cardano::checkpoint::maintenance_budget(),
                            ))
                        }
                    } else {
                        refresh_period
                    };
                if elapsed >= refresh_period {
                    info!(?elapsed, ?refresh_period, "client needs to be refreshed");

                    if matches!(client_state, AnyClientState::Probabilistic(_)) {
                        self.refresh_probabilistic_checkpoint().map(Some)
                    } else {
                        self.build_latest_update_client_and_send().map(Some)
                    }
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Submits the Mithril certificates that extend an anchored probabilistic
    /// client. Mithril publishes an epoch's distribution at least an epoch
    /// before the rollover it covers, so refresh records it well in advance.
    /// Failures leave the challenge period in place and are only logged.
    fn record_mithril_stake(&self, state: &AnyClientState) {
        let AnyClientState::Probabilistic(client) = state else {
            return;
        };
        // A pending bootstrap's own certificate moves its anchor first.
        if client.mithril_epoch == 0 || client.frozen_height.is_some() || client.bootstrap_pending {
            return;
        }
        let message = match self
            .src_chain
            .query_mithril_stake_certificates(client.mithril_epoch)
        {
            Ok(Some(message)) => message,
            Ok(None) => return,
            Err(error) => {
                warn!(
                    mithril_epoch = client.mithril_epoch,
                    "Mithril stake certificates are unavailable: {error}"
                );
                return;
            }
        };
        let signer = match self.dst_chain.get_signer() {
            Ok(signer) => signer,
            Err(error) => {
                warn!("cannot sign Mithril stake certificates: {error}");
                return;
            }
        };
        let message = MsgUpdateClient {
            client_id: self.id.clone(),
            header: message,
            signer,
        }
        .to_any();
        match self
            .dst_chain
            .send_messages_and_wait_commit(TrackedMsgs::new_single(
                message,
                "Mithril-certified stake",
            )) {
            Ok(events)
                if events
                    .iter()
                    .any(|event| event.event.event_type() == IbcEventType::ChainError) =>
            {
                warn!(
                    mithril_epoch = client.mithril_epoch,
                    "Mithril stake certificates were rejected: {events:?}"
                )
            }
            Ok(_) => info!(
                mithril_epoch = client.mithril_epoch,
                "recorded Mithril-certified stake"
            ),
            Err(error) => warn!(
                mithril_epoch = client.mithril_epoch,
                "Mithril stake certificates were not committed: {error}"
            ),
        }
    }

    fn maintenance_evidence_client(
        &self,
        state: &AnyClientState,
    ) -> Result<AnyClientState, ForeignClientError> {
        let AnyClientState::Probabilistic(client) = state else {
            return Ok(state.clone());
        };
        use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw;
        use prost::Message;
        let bytes = self
            .dst_chain
            .query_cardano_challenge_context(self.id.clone(), client.latest_verified_height(), None)
            .map_err(|error| {
                ForeignClientError::checkpoint_update(self.dst_chain.id(), error.to_string())
            })?;
        let raw = raw::ClientState::decode(bytes.as_slice()).map_err(|error| {
            ForeignClientError::checkpoint_update(self.dst_chain.id(), error.to_string())
        })?;
        raw.try_into()
            .map(AnyClientState::Probabilistic)
            .map_err(|error| {
                ForeignClientError::checkpoint_update(
                    self.dst_chain.id(),
                    format!("invalid maintenance checkpoint context: {error}"),
                )
            })
    }

    fn refresh_probabilistic_checkpoint(&self) -> Result<Vec<IbcEvent>, ForeignClientError> {
        let before = self.validated_client_state()?.0;
        let evidence = self.maintenance_evidence_client(&before)?;
        let committed = self.dst_chain.query_application_status().map_err(|error| {
            ForeignClientError::checkpoint_update(self.dst_chain.id(), error.to_string())
        })?;
        if let AnyClientState::Probabilistic(state) = &before {
            if state.epoch_context_challenges.iter().any(|challenge| {
                challenge.usable_after_unix_ns >= committed.timestamp.nanoseconds()
            }) {
                return Ok(vec![]);
            }
        }
        let header = self
            .src_chain
            .build_client_maintenance_header(&evidence)
            .map_err(|error| {
                ForeignClientError::checkpoint_update(self.dst_chain.id(), error.to_string())
            })?;
        let Some(header) = header else {
            // Source settlement may not yet have produced a newer checkpoint.
            // Keep the normal polling cadence without counting this as renewal.
            return Ok(vec![]);
        };
        let (AnyClientState::Probabilistic(client), AnyHeader::Probabilistic(checkpoint)) =
            (&before, header)
        else {
            return Err(ForeignClientError::checkpoint_update(
                self.dst_chain.id(),
                "maintenance requires a probabilistic checkpoint".to_owned(),
            ));
        };
        if !checkpoint.is_checkpoint {
            return Err(ForeignClientError::checkpoint_update(
                self.dst_chain.id(),
                "maintenance requires a rootless checkpoint".to_owned(),
            ));
        }
        self.stage_forward_observation(client, checkpoint)?;
        let after = self.validated_client_state()?.0;
        if after.latest_verified_height() <= before.latest_verified_height() {
            let AnyClientState::Probabilistic(updated) = after else {
                unreachable!()
            };
            if updated.epoch_context_challenges == client.epoch_context_challenges {
                return Err(ForeignClientError::checkpoint_update(
                    self.dst_chain.id(),
                    "staged maintenance committed no checkpoint or proposal".to_owned(),
                ));
            }
        }
        Ok(vec![])
    }

    /// Wrapper for build_update_client_with_trusted.
    pub fn wait_and_build_update_client(
        &self,
        target_height: Height,
    ) -> Result<Vec<Any>, ForeignClientError> {
        for _ in 0..MAX_PROBABILISTIC_CHECKPOINT_UPDATES {
            self.wait_for_probabilistic_epoch_challenge()?;
            let messages = self.wait_and_build_update_client_with_trusted(target_height, None)?;
            let (state, _) = self.validated_client_state()?;
            if matches!(&state, AnyClientState::Probabilistic(state) if state.latest_verified_height() < target_height)
            {
                continue;
            }
            return Ok(messages);
        }
        Err(ForeignClientError::checkpoint_update(
            self.dst_chain.id(),
            "too many observations while preparing packet proofs".to_owned(),
        ))
    }

    /// Returns a trusted height that is lower than the target height, so
    /// that the relayer can update the client to the target height based
    /// on the returned trusted height.
    #[instrument(
        name = "foreign_client.solve_trusted_height",
        level = "error",
        skip_all,
        fields(client = %self, %target_height)
    )]
    fn solve_trusted_height(
        &self,
        target_height: Height,
        client_state: &AnyClientState,
    ) -> Result<Height, ForeignClientError> {
        let client_latest_height = client_state.latest_verified_height();

        if client_latest_height < target_height {
            // If the latest height of the client is already lower than the
            // target height, we can simply use it.
            Ok(client_latest_height)
        } else {
            // The only time when the above is false is when for some reason,
            // the command line user wants to submit a client update at an
            // older height even when the relayer already have an up-to-date
            // client at a newer height.

            // In production, this should rarely happen unless there is another
            // relayer racing to update the client state, and that we so happen
            // to get the latest client state that was updated between
            // the time the target height was determined, and the time
            // the client state was fetched.

            warn!(
                "resolving trusted height from the full list of consensus state \
                 heights for target height {}; this may take a while",
                target_height
            );

            // Potential optimization: cache the list of consensus heights
            // so that subsequent fetches can be fast.
            let cs_heights = self.fetch_consensus_state_heights()?;

            // Iterate through the available consensus heights and find one
            // that is lower than the target height.
            cs_heights
                .into_iter()
                .find(|h| h < &target_height)
                .ok_or_else(|| {
                    ForeignClientError::missing_smaller_trusted_height(
                        self.dst_chain().id(),
                        target_height,
                    )
                })
        }
    }

    /// Validate a non-zero trusted height to make sure that there is a corresponding
    /// consensus state at the given trusted height on the destination chain's client.
    #[instrument(
        name = "foreign_client.validate_trusted_height",
        level = "error",
        skip_all,
        fields(client = %self, %trusted_height)
    )]
    fn validate_trusted_height(
        &self,
        trusted_height: Height,
        client_state: &AnyClientState,
    ) -> Result<(), ForeignClientError> {
        if client_state.latest_verified_height() != trusted_height {
            // There should be no need to validate a trusted height in production,
            // Since it is always fetched from some client state. The only use is
            // from the command line when the trusted height is manually specified.
            // We should consider skipping the validation entirely and only validate
            // it from the command line itself.
            self.fetch_consensus_state(trusted_height)?;
        }

        Ok(())
    }

    /// Given a client state and header it adds, if required, a delay such that the header will
    /// not be considered in the future when submitted in an update client:
    /// - determine the `dst_timestamp` as the time of the latest block on destination chain
    /// - return if `header.timestamp <= dst_timestamp + client_state.max_clock_drift`
    /// - wait for the destination chain to reach `dst_timestamp + 1`
    ///    Note: This is mostly to help with existing clients where the `max_clock_drift` did
    ///    not take into account the block time.
    /// - return error if header.timestamp < dst_timestamp + client_state.max_clock_drift
    ///
    /// Ref: https://github.com/informalsystems/hermes/issues/1445.
    #[instrument(
        name = "foreign_client.wait_for_header_validation_delay",
        level = "error",
        skip_all,
        fields(client = %self)
    )]
    fn wait_for_header_validation_delay(
        &self,
        client_state: &AnyClientState,
        header: &AnyHeader,
    ) -> Result<(), ForeignClientError> {
        crate::time!(
            "wait_for_header_validation_delay",
            {
                "src_chain": self.src_chain().id(),
                "dst_chain": self.dst_chain().id(),
                "header_height": header.height(),
                "header_timestamp": header.timestamp()
            }
        );

        // Get latest height and time on destination chain
        let mut status = self.dst_chain().query_application_status().map_err(|e| {
            ForeignClientError::client_update(
                self.dst_chain.id(),
                "failed querying latest status of the destination chain".to_string(),
                e,
            )
        })?;

        let ts_adjusted = (status.timestamp + client_state.max_clock_drift()).map_err(|e| {
            ForeignClientError::client_update_timing(
                self.dst_chain.id(),
                client_state.max_clock_drift(),
                "failed to adjust timestamp of destination chain with clock drift".to_string(),
                e,
            )
        })?;

        let local_ts_adjusted = || {
            (Timestamp::now() + client_state.max_clock_drift()).map_err(|e| {
                ForeignClientError::client_update_timing(
                    self.dst_chain.id(),
                    client_state.max_clock_drift(),
                    "failed to adjust local clock with clock drift".to_string(),
                    e,
                )
            })
        };

        if header.timestamp().after(&ts_adjusted) {
            // Header would be considered in the future, wait for destination chain to
            // advance to the next height. For Cardano/probabilistic mode, the accepted proof height
            // can legitimately stay flat while wall-clock time keeps advancing, so also allow
            // the local clock to satisfy the delay bound.
            warn!(
                "src header {} is after dst latest header {} + client state drift {},\
                 wait for next height on {} or for local time to catch up",
                header.timestamp(),
                status.timestamp,
                PrettyDuration(&client_state.max_clock_drift()),
                self.dst_chain().id()
            );

            let target_dst_height = status.height.increment();
            loop {
                if !header.timestamp().after(&local_ts_adjusted()?) {
                    break;
                }

                thread::sleep(Duration::from_millis(300));
                status = self.dst_chain().query_application_status().map_err(|e| {
                    ForeignClientError::client_update(
                        self.dst_chain.id(),
                        "failed querying latest status of the destination chain".to_string(),
                        e,
                    )
                })?;

                if status.height >= target_dst_height {
                    break;
                }
            }
        }

        let next_ts_adjusted =
            (status.timestamp + client_state.max_clock_drift()).map_err(|e| {
                ForeignClientError::client_update_timing(
                    self.dst_chain.id(),
                    client_state.max_clock_drift(),
                    "failed to adjust timestamp of destination chain with clock drift".to_string(),
                    e,
                )
            })?;

        let next_local_ts_adjusted = local_ts_adjusted()?;

        if header.timestamp().after(&next_ts_adjusted)
            && header.timestamp().after(&next_local_ts_adjusted)
        {
            // The header is still in the future
            Err(ForeignClientError::header_in_the_future(
                self.src_chain.id(),
                header.height(),
                header.timestamp(),
                self.dst_chain.id(),
                status.height,
                status.timestamp,
                client_state.max_clock_drift(),
            ))
        } else {
            Ok(())
        }
    }

    /// Pending proposals are checked before historical pagination. A failed
    /// observation leaves coverage incomplete without starving other proposals.
    fn detect_probabilistic_misbehaviour(
        &self,
        client: &ibc_relayer_types::clients::ics08_cardano_probabilistic::client_state::ClientState,
        update: Option<&UpdateClient>,
    ) -> Result<Option<MisbehaviourEvidence>, ForeignClientError> {
        use crate::chain::cardano::staging;
        use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw;
        let fail =
            |error: String| ForeignClientError::checkpoint_update(self.dst_chain.id(), error);
        let mut scan = self
            .probabilistic_scan
            .lock()
            .map_err(|_| fail("Watcher progress lock is poisoned".into()))?;
        if scan.namespace != client.storage_namespace
            || scan.generation != client.verification_generation
        {
            *scan = ProbabilisticScan {
                namespace: client.storage_namespace.clone(),
                generation: client.verification_generation,
                ..Default::default()
            };
        }
        let retries = scan.retry.len().min(8);
        let mut incomplete = None;
        let mut checked = std::collections::BTreeSet::new();
        let mut failed = std::collections::BTreeSet::new();
        let mut check =
            |id: Vec<u8>,
             receipt: serde_json::Value,
             incomplete: &mut Option<ForeignClientError>,
             retry: &mut VecDeque<(Vec<u8>, serde_json::Value)>| {
                if !checked.insert(id.clone()) {
                    if failed.contains(&id) && !retry.iter().any(|(other, _)| other == &id) {
                        retry.push_back((id, receipt));
                    }
                    return None;
                }
                match self.check_probabilistic_receipt(client, id.clone(), receipt.clone()) {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        warn!(receipt_id = %hex::encode(&id), %error, "observation check incomplete, will retry");
                        *incomplete = Some(error);
                        failed.insert(id.clone());
                        if !retry.iter().any(|(other, _)| other == &id) {
                            retry.push_back((id, receipt));
                        }
                        None
                    }
                }
            };
        match self.verification_query(client, 10, vec![], vec![]) {
            Ok(pending) => {
                let proposals = pending
                    .as_array()
                    .ok_or_else(|| fail("Invalid pending proposal response".into()))?;
                for proposal in proposals {
                    let result = staging::decode_bytes(proposal, "Receipt").and_then(|id| {
                        if id.len() != 32 {
                            return Err("Invalid proposal receipt identifier".into());
                        }
                        self.verification_query(client, 9, vec![], id.clone())
                            .map(|receipt| (id, receipt))
                    });
                    match result {
                        Ok((id, receipt)) => {
                            if let Some(evidence) =
                                check(id, receipt, &mut incomplete, &mut scan.retry)
                            {
                                return Ok(Some(evidence));
                            }
                        }
                        Err(error) => {
                            incomplete = Some(fail(error));
                        }
                    }
                }
            }
            Err(error) => {
                incomplete = Some(fail(error));
            }
        }
        // Newly committed proof updates take priority too. Their activation
        // header identifies the session even if old history still needs work.
        if let Some(AnyHeader::Probabilistic(header)) =
            update.and_then(|event| event.header.as_ref())
        {
            if let Some(chunk) = &header.observation_chunk {
                let result = self
                    .verification_query(client, 8, chunk.session_id.clone(), vec![])
                    .and_then(|session| staging::decode_bytes(&session, "Receipt"))
                    .and_then(|id| {
                        self.verification_query(client, 9, vec![], id.clone())
                            .map(|receipt| (id, receipt))
                    });
                match result {
                    Ok((id, receipt)) => {
                        if let Some(evidence) = check(id, receipt, &mut incomplete, &mut scan.retry)
                        {
                            return Ok(Some(evidence));
                        }
                    }
                    Err(error) => incomplete = Some(fail(error)),
                }
            }
        }
        for _ in 0..retries {
            let (id, receipt) = scan.retry.pop_front().expect("queued historical check");
            if let Some(evidence) = check(id, receipt, &mut incomplete, &mut scan.retry) {
                return Ok(Some(evidence));
            }
        }
        let after = scan.after.clone();
        // One page per poll bounds old-history work. Failed observations and
        // the committed page cursor survive the next worker poll.
        let mut malformed = false;
        let response = self
            .dst_chain
            .query_probabilistic_verification(
                raw::QueryVerificationRequest {
                    namespace: client.storage_namespace.clone(),
                    generation: client.verification_generation,
                    kind: 12,
                    after: after.clone(),
                    limit: 8,
                    ..Default::default()
                },
                QueryHeight::Latest,
            )
            .map_err(|error| fail(error.to_string()))?;
        let page: serde_json::Value =
            serde_json::from_slice(&response).map_err(|error| fail(error.to_string()))?;
        let records = page
            .get("records")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| fail("Invalid historical receipt page".into()))?;
        for record in records {
            let entry = staging::decode_bytes(record, "ID").and_then(|id| {
                if id.len() != 32 {
                    return Err("Invalid historical receipt identifier".into());
                }
                record
                    .get("Receipt")
                    .cloned()
                    .map(|receipt| (id, receipt))
                    .ok_or_else(|| "Missing historical receipt".to_owned())
            });
            match entry {
                Ok((id, receipt)) => {
                    if let Some(evidence) = check(id, receipt, &mut incomplete, &mut scan.retry) {
                        return Ok(Some(evidence));
                    }
                }
                Err(error) => {
                    malformed = true;
                    incomplete = Some(fail(error));
                }
            }
        }
        let next = staging::decode_bytes(&page, "next").map_err(fail)?;
        if !next.is_empty() && next <= after {
            return Err(fail("Receipt index did not advance".into()));
        }
        if !malformed {
            scan.after = next.clone();
        }
        if let Some(error) = incomplete {
            return Err(error);
        }
        if !next.is_empty() || !scan.retry.is_empty() {
            return Err(fail(
                "Historical verification has pending pages or observations".into(),
            ));
        }
        Ok(None)
    }

    fn check_probabilistic_receipt(
        &self,
        client: &ibc_relayer_types::clients::ics08_cardano_probabilistic::client_state::ClientState,
        id: Vec<u8>,
        receipt: serde_json::Value,
    ) -> Result<Option<MisbehaviourEvidence>, ForeignClientError> {
        use crate::chain::cardano::staging;
        use ibc_relayer_types::clients::ics08_cardano_probabilistic::{
            header::Header as ProbabilisticHeader,
            misbehaviour::Misbehaviour as ProbabilisticMisbehaviour, raw,
        };
        use ibc_relayer_types::core::ics02_client::client_type::ClientType;
        use ibc_relayer_types::core::ics02_client::events::Attributes;
        use prost::Message;
        let fail =
            |error: String| ForeignClientError::checkpoint_update(self.dst_chain.id(), error);
        let base = staging::decode_bytes(&receipt, "BaseReference").map_err(fail)?;
        let height = Height::new(0, staging::integer(&receipt, "AnchorHeight").map_err(fail)?)
            .map_err(|error| fail(error.to_string()))?;
        // Recover the original verification base and capped history from
        // destination storage, not the latest state or observer counts.
        let metadata = self
            .dst_chain
            .query_probabilistic_verification(
                raw::QueryVerificationRequest {
                    namespace: client.storage_namespace.clone(),
                    generation: client.verification_generation,
                    checkpoint_reference: base.clone(),
                    receipt_id: id.clone(),
                    kind: 0,
                    ..Default::default()
                },
                QueryHeight::Latest,
            )
            .map_err(|error| fail(error.to_string()))?;
        let metadata: serde_json::Value =
            serde_json::from_slice(&metadata).map_err(|error| fail(error.to_string()))?;
        let trusted = Height::new(0, staging::integer(&metadata, "Height").map_err(fail)?)
            .map_err(|error| fail(error.to_string()))?;
        let context = self
            .dst_chain
            .query_cardano_challenge_context(self.id.clone(), trusted, Some(id.clone()))
            .map_err(|error| fail(error.to_string()))?;
        let historical = raw::ClientState::decode(context.as_slice())
            .map_err(|error| fail(error.to_string()))?;
        let hash = hex::encode(staging::decode_bytes(&receipt, "AnchorHash").map_err(fail)?);
        let placeholder = ProbabilisticHeader {
            trusted_height: trusted,
            height,
            timestamp: ibc_relayer_types::timestamp::Timestamp::none(),
            anchor_block: raw::ProbabilisticBlock {
                height: Some(height.into()),
                hash,
                ..Default::default()
            },
            bridge_blocks: vec![],
            descendant_blocks: vec![],
            host_state_tx_hash: String::new(),
            host_state_tx_output_index: 0,
            new_epoch_context: None,
            is_checkpoint: true,
            observation_chunk: None,
        };
        let event = UpdateClient {
            common: Attributes {
                client_id: self.id.clone(),
                client_type: ClientType::CardanoProbabilistic,
                consensus_height: height,
            },
            header: Some(AnyHeader::Probabilistic(placeholder)),
        };
        let evidence = self
            .src_chain
            .check_misbehaviour(
                event,
                AnyClientState::Probabilistic(client.clone()),
                Some(context),
            )
            .map_err(|error| fail(error.to_string()))?;
        let Some(evidence) = evidence else {
            return Ok(None);
        };
        let crate::misbehaviour::AnyMisbehaviour::Probabilistic(evidence) = evidence.misbehaviour
        else {
            return Err(fail("Unexpected probabilistic challenge type".into()));
        };
        let alternative: raw::ProbabilisticHeader = evidence.header2.into();
        let plan = staging::plan(&historical, &alternative, id.clone()).map_err(fail)?;
        let other = staging::submit(
            &plan,
            |session| self.verification_query(client, 8, session.to_vec(), vec![]),
            |chunk| self.send_observation_step(chunk),
        )
        .map_err(fail)?;
        let receipt_challenge = raw::Misbehaviour {
            client_id: self.id.to_string(),
            verified_observation_1: id,
            verified_observation_2: other,
            ..Default::default()
        };
        let misbehaviour = ProbabilisticMisbehaviour::try_from(receipt_challenge)
            .map_err(|error| fail(error.to_string()))?;
        Ok(Some(MisbehaviourEvidence {
            misbehaviour: crate::misbehaviour::AnyMisbehaviour::Probabilistic(misbehaviour),
            supporting_headers: vec![],
        }))
    }

    fn complete_bootstrap(&self) -> Result<(), ForeignClientError> {
        use crate::chain::cardano::staging;
        let fail =
            |error: String| ForeignClientError::checkpoint_update(self.dst_chain.id(), error);
        // Re-read committed progress so another uploader or an interrupted
        // process never makes us silently skip unfinished imports.
        for _ in 0..=4096 {
            let (state, _) = self
                .dst_chain
                .query_client_state(
                    QueryClientStateRequest {
                        client_id: self.id.clone(),
                        height: QueryHeight::Latest,
                    },
                    IncludeProof::No,
                )
                .map_err(|e| fail(e.to_string()))?;
            let AnyClientState::Probabilistic(client) = state else {
                return Ok(());
            };
            if !client.bootstrap_pending {
                return Ok(());
            }
            let progress = self
                .verification_query(&client, 11, vec![], vec![])
                .map_err(fail)?;
            let sequence = u32::try_from(staging::integer(&progress, "Sequence").map_err(fail)?)
                .map_err(|e| fail(e.to_string()))?
                .checked_add(1)
                .ok_or_else(|| fail("Initialization sequence overflow".into()))?;
            let initial = self
                .src_chain
                .query_client_initialization(client.latest_height.revision_height(), sequence)
                .map_err(|e| fail(e.to_string()))?;
            let AnyClientState::Probabilistic(prepared) = initial.client_state else {
                return Err(fail("Initial client has the wrong type".into()));
            };
            if prepared.checkpoint_reference != client.checkpoint_reference
                || prepared.chain_id != client.chain_id
            {
                return Err(fail(
                    "Initialization data belongs to a different starting checkpoint".into(),
                ));
            }
            let Some(AnyHeader::Probabilistic(header)) = initial.message else {
                return Err(fail(
                    "Missing probabilistic client initialization import".into(),
                ));
            };
            let chunk = header
                .observation_chunk
                .ok_or_else(|| fail("Missing client initialization operation".into()))?;
            if ![10, 11].contains(&chunk.operation) || chunk.sequence != sequence {
                return Err(fail(
                    "Invalid client initialization operation or sequence".into(),
                ));
            }
            self.send_observation_step(chunk).map_err(fail)?;
        }
        Err(fail(
            "Client initialization exceeds its import allowance".into(),
        ))
    }

    fn verification_query(
        &self,
        client: &ibc_relayer_types::clients::ics08_cardano_probabilistic::client_state::ClientState,
        kind: u32,
        session: Vec<u8>,
        receipt: Vec<u8>,
    ) -> Result<serde_json::Value, String> {
        use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw;
        let bytes = self
            .dst_chain
            .query_probabilistic_verification(
                raw::QueryVerificationRequest {
                    namespace: client.storage_namespace.clone(),
                    generation: client.verification_generation,
                    kind,
                    session_id: session,
                    receipt_id: receipt,
                    ..Default::default()
                },
                QueryHeight::Latest,
            )
            .map_err(|error| error.to_string())?;
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())
    }
    fn send_observation_step(
        &self,
        chunk: ibc_relayer_types::clients::ics08_cardano_probabilistic::raw::ObservationChunk,
    ) -> Result<(), String> {
        use ibc_relayer_types::clients::ics08_cardano_probabilistic::{
            header::PROBABILISTIC_HEADER_TYPE_URL, raw,
        };
        use prost::Message;
        let signer = self
            .dst_chain
            .get_signer()
            .map_err(|error| error.to_string())?;
        let header = raw::ProbabilisticHeader {
            observation_chunk: Some(chunk),
            ..Default::default()
        };
        let update = ibc_proto::ibc::core::client::v1::MsgUpdateClient {
            client_id: self.id.to_string(),
            client_message: Some(Any {
                type_url: PROBABILISTIC_HEADER_TYPE_URL.into(),
                value: header.encode_to_vec(),
            }),
            signer: signer.to_string(),
        };
        let message = Any {
            type_url: "/ibc.core.client.v1.MsgUpdateClient".into(),
            value: update.encode_to_vec(),
        };
        let events = self
            .dst_chain
            .send_messages_and_wait_commit(TrackedMsgs::new_single(
                message,
                "bounded Cardano verification",
            ))
            .map_err(|error| error.to_string())?;
        for event in events {
            if let IbcEvent::ChainError(error) = event.event {
                return Err(error);
            }
        }
        Ok(())
    }
    fn stage_forward_observation(
        &self,
        client: &ibc_relayer_types::clients::ics08_cardano_probabilistic::client_state::ClientState,
        header: ibc_relayer_types::clients::ics08_cardano_probabilistic::header::Header,
    ) -> Result<(), ForeignClientError> {
        use crate::chain::cardano::staging;
        use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw;
        if header.new_epoch_context.is_some() {
            // A table Mithril has certified activates without a response window.
            self.record_mithril_stake(&AnyClientState::Probabilistic(client.clone()));
        }
        let plan = staging::plan(&client.clone().into(), &header.into(), vec![])
            .map_err(|error| ForeignClientError::checkpoint_update(self.dst_chain.id(), error))?;
        staging::submit(
            &plan,
            |id| self.verification_query(client, 8, id.to_vec(), vec![]),
            |chunk| self.send_observation_step(chunk),
        )
        .map_err(|error| ForeignClientError::checkpoint_update(self.dst_chain.id(), error))?;
        let session = self
            .verification_query(client, 8, plan.id.clone(), vec![])
            .map_err(|error| ForeignClientError::checkpoint_update(self.dst_chain.id(), error))?;
        let sequence = staging::integer(&session, "Sequence")
            .map_err(|error| ForeignClientError::checkpoint_update(self.dst_chain.id(), error))?;
        self.send_observation_step(raw::ObservationChunk {
            operation: 7,
            session_id: plan.id,
            sequence: u32::try_from(sequence)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    ForeignClientError::checkpoint_update(
                        self.dst_chain.id(),
                        "Observation sequence overflow".into(),
                    )
                })?,
            ..Default::default()
        })
        .map_err(|error| ForeignClientError::checkpoint_update(self.dst_chain.id(), error))
    }

    fn wait_for_probabilistic_epoch_challenge(&self) -> Result<(), ForeignClientError> {
        loop {
            let (state, _) = self.validated_client_state()?;
            let AnyClientState::Probabilistic(state) = state else {
                return Ok(());
            };
            let deadline = state
                .epoch_context_challenges
                .iter()
                .map(|challenge| challenge.usable_after_unix_ns)
                .max()
                .unwrap_or(0);
            if deadline == 0 {
                return Ok(());
            }
            let status = self
                .dst_chain()
                .query_application_status()
                .map_err(|error| {
                    ForeignClientError::client_update(
                        self.dst_chain.id(),
                        "failed querying epoch challenge host time".to_string(),
                        error,
                    )
                })?;
            if status.timestamp.nanoseconds() > deadline.saturating_add(10_000_000_000) {
                return Ok(());
            }
            debug!(client_id = %self.id, deadline, "waiting for epoch context challenge window");
            thread::sleep(Duration::from_secs(1));
        }
    }

    /// Wait for the source chain application to reach height `target_height`
    /// before building the update client messages.
    ///
    /// Returns a vector with a message for updating the client to height
    /// `target_height`. If the client already stores a consensus state for this
    /// height, returns an empty vector.
    #[instrument(
        name = "foreign_client.wait_and_build_update_client_with_trusted",
        level = "error",
        skip_all,
        fields(client = %self, %target_height)
    )]
    pub fn wait_and_build_update_client_with_trusted(
        &self,
        target_height: Height,
        trusted_height: Option<Height>,
    ) -> Result<Vec<Any>, ForeignClientError> {
        crate::time!(
            "wait_and_build_update_client_with_trusted",
            {
                "src_chain": self.src_chain().id(),
                "dst_chain": self.dst_chain().id(),
            }
        );

        let consensus_state = self.dst_chain().query_consensus_state(
            QueryConsensusStateRequest {
                client_id: self.id().clone(),
                consensus_height: target_height,
                query_height: QueryHeight::Latest,
            },
            IncludeProof::No,
        );

        if let Ok((consensus_state, _)) = consensus_state {
            debug!("consensus state already exists at height {target_height}, skipping update");
            trace!(?consensus_state, "consensus state");

            // If the client already stores a consensus state for the target height,
            // there is no need to update the client
            telemetry!(
                client_updates_skipped,
                &self.src_chain.id(),
                &self.dst_chain.id(),
                &self.id,
                1,
            );
            return Ok(vec![]);
        }

        let src_application_latest_height = || {
            self.src_chain().query_latest_height().map_err(|e| {
                ForeignClientError::client_create(
                    self.src_chain.id(),
                    "failed fetching src network latest height with error".to_string(),
                    e,
                )
            })
        };

        {
            crate::time!(
                "wait_and_build_update_client_with_trusted_sleep",
                {
                    "src_chain": self.src_chain().id(),
                    "dst_chain": self.dst_chain().id(),
                }
            );

            // Wait for the source network to produce block(s) & reach `target_height`.
            while src_application_latest_height()? < target_height {
                thread::sleep(Duration::from_millis(100));
            }
        }

        let messages = self.build_update_client_with_trusted(target_height, trusted_height)?;

        let (state, _) = self
            .dst_chain
            .query_client_state(
                QueryClientStateRequest {
                    client_id: self.id.clone(),
                    height: QueryHeight::Latest,
                },
                IncludeProof::No,
            )
            .map_err(|e| {
                ForeignClientError::checkpoint_update(self.dst_chain.id(), e.to_string())
            })?;
        if let AnyClientState::Probabilistic(client) = &state {
            for message in messages {
                let header: AnyHeader = message.header.try_into().map_err(|error| {
                    ForeignClientError::checkpoint_update(
                        self.dst_chain.id(),
                        format!("Invalid observation header: {error}"),
                    )
                })?;
                if let AnyHeader::Probabilistic(header) = header {
                    self.stage_forward_observation(client, header)?;
                } else {
                    return Err(ForeignClientError::checkpoint_update(
                        self.dst_chain.id(),
                        "Cardano probabilistic client received a different header type".into(),
                    ));
                }
            }
            return Ok(vec![]);
        }
        let encoded_messages = messages.into_iter().map(Msg::to_any).collect();

        Ok(encoded_messages)
    }

    #[instrument(
        name = "foreign_client.build_update_client_with_trusted",
        level = "error",
        skip_all,
        fields(client = %self, %target_height)
    )]
    pub fn build_update_client_with_trusted(
        &self,
        target_height: Height,
        maybe_trusted_height: Option<Height>,
    ) -> Result<Vec<MsgUpdateClient>, ForeignClientError> {
        crate::time!(
            "build_update_client_with_trusted",
            {
                "src_chain": self.src_chain().id(),
                "dst_chain": self.dst_chain().id(),
            }
        );
        // Get the latest client state on destination.
        let (client_state, _) = self.validated_client_state()?;
        if matches!(&client_state, AnyClientState::Probabilistic(client) if client.bootstrap_pending)
        {
            self.complete_bootstrap()?;
            return self.build_update_client_with_trusted(target_height, maybe_trusted_height);
        }

        // Tendermint clients can backfill a missing consensus state at a skipped
        // historical height, which light-client evidence may need as its trusted
        // height. Cardano clients use sparse accepted proof anchors, so retain the
        // at-or-below-latest guard for them.
        if should_skip_client_update(
            client_state.client_type(),
            client_state.latest_verified_height(),
            target_height,
        ) {
            debug!(
                latest_height = %client_state.latest_height(),
                %target_height,
                "client already at or above target height, skipping update"
            );

            telemetry!(
                client_updates_skipped,
                &self.src_chain.id(),
                &self.dst_chain.id(),
                &self.id,
                1,
            );

            return Ok(vec![]);
        }

        let trusted_height = match maybe_trusted_height {
            Some(trusted_height) => {
                self.validate_trusted_height(trusted_height, &client_state)?;
                trusted_height
            }
            None => self.solve_trusted_height(target_height, &client_state)?,
        };

        if trusted_height != client_state.latest_height()
            && trusted_height != client_state.latest_verified_height()
        {
            // If we're using a trusted height that is different from the client latest height,
            // then check if the consensus state at `trusted_height` is within trusting period
            if let ConsensusStateTrusted::NotTrusted {
                elapsed,
                consensus_state_timestamp,
                network_timestamp,
            } = self.check_consensus_state_trusting_period(&client_state, &trusted_height)?
            {
                error!(
                    %trusted_height,
                    %network_timestamp,
                    %consensus_state_timestamp,
                    ?elapsed,
                    "cannot build client update message because the provided trusted height is outside of trusting period!",
                );

                return Err(ForeignClientError::consensus_state_not_trusted(
                    trusted_height,
                    elapsed,
                ));
            }
        }

        if trusted_height >= target_height {
            warn!(
                "skipping update: trusted height ({}) >= chain target height ({})",
                trusted_height, target_height
            );

            return Ok(vec![]);
        }

        let evidence_client = if matches!(&client_state, AnyClientState::Probabilistic(_)) {
            use prost::Message;
            let bytes = self
                .dst_chain
                .query_cardano_challenge_context(self.id.clone(), trusted_height, None)
                .map_err(|error| {
                    ForeignClientError::client_update(
                        self.dst_chain.id(),
                        "querying verification checkpoint".to_owned(),
                        error,
                    )
                })?;
            let raw =
                ibc_relayer_types::clients::ics08_cardano_probabilistic::raw::ClientState::decode(
                    bytes.as_slice(),
                )
                .map_err(|error| {
                    ForeignClientError::checkpoint_update(self.dst_chain.id(), error.to_string())
                })?;
            AnyClientState::Probabilistic(raw.try_into().map_err(|error| {
                ForeignClientError::checkpoint_update(
                    self.dst_chain.id(),
                    format!("Invalid checkpoint context: {error}"),
                )
            })?)
        } else {
            client_state.clone()
        };
        let (header, support) = self
            .src_chain()
            .build_header(trusted_height, target_height, evidence_client)
            .map_err(|e| {
                ForeignClientError::client_update(
                    self.dst_chain.id(),
                    "failed building header with error".to_string(),
                    e,
                )
            })?;

        let signer = self.dst_chain().get_signer().map_err(|e| {
            ForeignClientError::client_update(
                self.dst_chain.id(),
                "failed getting signer for dst chain".to_string(),
                e,
            )
        })?;

        self.wait_for_header_validation_delay(&client_state, &header)?;

        let mut msgs = vec![];

        for header in support {
            debug!(
                "building a MsgUpdateAnyClient for intermediate height {}",
                header.height(),
            );

            msgs.push(MsgUpdateClient {
                header: header.into(),
                client_id: self.id.clone(),
                signer: signer.clone(),
            });
        }

        debug!(
            "building a MsgUpdateAnyClient from trusted height {} to target height {}",
            trusted_height,
            header.height(),
        );

        msgs.push(MsgUpdateClient {
            header: header.into(),
            signer,
            client_id: self.id.clone(),
        });

        telemetry!(
            client_updates_submitted,
            &self.src_chain.id(),
            &self.dst_chain.id(),
            &self.id,
            msgs.len() as u64
        );

        Ok(msgs)
    }

    pub fn build_latest_update_client_and_send(&self) -> Result<Vec<IbcEvent>, ForeignClientError> {
        self.build_update_client_and_send(QueryHeight::Latest, None)
    }

    /// Build proof-bearing updates, or establish that the exact proof root is
    /// already retained. A later checkpoint cursor alone cannot satisfy this.
    /// Packet scheduling handles checkpoint submission separately.
    pub fn wait_and_build_update_client_for_proof(
        &self,
        height: Height,
    ) -> Result<Vec<Any>, ForeignClientError> {
        let messages = self.wait_and_build_update_client(height)?;
        if messages.is_empty() {
            self.require_consensus_state_for_proof(height)?;
        }
        Ok(messages)
    }

    /// Prepare updates that can be followed by a membership proof at `height`.
    /// A Cardano checkpoint advances authenticated header continuity but installs
    /// no state root/processed-time entry. Commit checkpoint catch-up separately
    /// before a handshake; batching it with the handshake cannot verify its proof.
    pub fn prepare_update_client_for_proof(
        &self,
        height: Height,
    ) -> Result<Vec<Any>, ForeignClientError> {
        self.wait_and_build_update_client_for_proof(height)
    }

    fn require_consensus_state_for_proof(&self, height: Height) -> Result<(), ForeignClientError> {
        self.dst_chain().query_consensus_state(
            QueryConsensusStateRequest {
                client_id: self.id().clone(),
                consensus_height: height,
                query_height: QueryHeight::Latest,
            },
            IncludeProof::No,
        ).map_err(|error| ForeignClientError::client_update(
            self.dst_chain.id(),
            format!("proof consensus state at {height} is unavailable; rebuild proofs at a retained root-bearing anchor (a checkpoint cursor is insufficient)"),
            error,
        ))?;
        Ok(())
    }

    #[instrument(
        name = "foreign_client.build_update_client_and_send",
        level = "error",
        skip_all,
        fields(client = %self, %target_query_height)
    )]
    pub fn build_update_client_and_send(
        &self,
        target_query_height: QueryHeight,
        trusted_height: Option<Height>,
    ) -> Result<Vec<IbcEvent>, ForeignClientError> {
        let target_height = match target_query_height {
            QueryHeight::Latest => self.src_chain.query_latest_height().map_err(|e| {
                ForeignClientError::client_update(
                    self.src_chain.id(),
                    "failed while querying src chain ({}) for latest height".to_string(),
                    e,
                )
            })?,
            QueryHeight::Specific(height) => height,
        };

        let mut next_trusted_height = trusted_height;
        for _ in 0..MAX_PROBABILISTIC_CHECKPOINT_UPDATES {
            self.wait_for_probabilistic_epoch_challenge()?;
            let messages =
                self.wait_and_build_update_client_with_trusted(target_height, next_trusted_height)?;
            if messages.is_empty() {
                if let AnyClientState::Probabilistic(state) = self.validated_client_state()?.0 {
                    if state.latest_verified_height() < target_height {
                        next_trusted_height = None;
                        continue;
                    }
                    return Ok(vec![]);
                }
                return Err(ForeignClientError::client_already_up_to_date(
                    self.id.clone(),
                    self.src_chain.id(),
                    target_height,
                ));
            }
            let events = self
                .dst_chain()
                .send_messages_and_wait_commit(TrackedMsgs::new_static(messages, "update client"))
                .map_err(|error| {
                    ForeignClientError::client_update(
                        self.dst_chain.id(),
                        "failed sending message to dst chain".to_owned(),
                        error,
                    )
                })?;
            return Ok(events.into_iter().map(|event| event.event).collect());
        }
        Err(ForeignClientError::checkpoint_update(self.dst_chain.id(), format!("exceeded {MAX_PROBABILISTIC_CHECKPOINT_UPDATES} observations while catching up to {target_height}")))
    }

    /// Attempts to update a client using header from the latest height of its source chain.
    #[instrument(
        name = "foreign_client.update",
        level = "error",
        skip_all,
        fields(client = %self)
    )]
    pub fn update(&self) -> Result<(), ForeignClientError> {
        let events = self.build_latest_update_client_and_send()?;

        debug!(?events, "client updated");

        Ok(())
    }

    /// Retrieves the client update event that was emitted when a consensus state at the
    /// specified height was created on chain.
    /// It is possible that the event cannot be retrieved if the information is not yet available
    /// on the full node. To handle this the query is retried a few times.
    #[instrument(
        name = "foreign_client.fetch_update_client_event",
        level = "error",
        skip_all,
        fields(client = %self, %consensus_height)
    )]
    pub fn fetch_update_client_event(
        &self,
        consensus_height: Height,
    ) -> Result<Option<UpdateClient>, ForeignClientError> {
        crate::time!(
            "fetch_update_client_event",
            {
                "src_chain": self.src_chain().id(),
                "dst_chain": self.dst_chain().id(),
            }
        );

        let mut events_with_heights = vec![];
        for i in 0..MAX_RETRIES {
            thread::sleep(Duration::from_millis(200));

            let result = self
                .dst_chain
                .query_txs(QueryTxRequest::Client(QueryClientEventRequest {
                    probabilistic_epoch: None,
                    query_height: QueryHeight::Latest,
                    event_id: WithBlockDataType::UpdateClient,
                    client_id: self.id.clone(),
                    consensus_height,
                }))
                .map_err(|e| {
                    ForeignClientError::client_event_query(
                        self.id().clone(),
                        self.dst_chain.id(),
                        consensus_height,
                        e,
                    )
                });

            match result {
                Err(e) => {
                    error!(
                        "query_tx failed with error {}, retry {}/{}",
                        e,
                        i + 1,
                        MAX_RETRIES
                    );

                    continue;
                }
                Ok(result) => {
                    events_with_heights = result;

                    // Should break to prevent retrying uselessly.
                    break;
                }
            }
        }

        if events_with_heights.is_empty() {
            return Ok(None);
        }

        // It is possible in theory that `query_txs` returns multiple client update events for the
        // same consensus height. This could happen when multiple client updates with same header
        // were submitted to chain. However this is not what it's observed during testing.
        // Regardless, just take the event from the first update.
        let event = &events_with_heights[0].event;
        let update = downcast!(event.clone() => IbcEvent::UpdateClient).ok_or_else(|| {
            ForeignClientError::unexpected_event(
                self.id().clone(),
                self.dst_chain.id(),
                event.to_json(),
            )
        })?;

        Ok(Some(update))
    }

    /// Returns the consensus state at `height` or error if not found.
    #[instrument(
        name = "foreign_client.fetch_consensus_state",
        level = "error",
        skip_all,
        fields(client = %self, %height)
    )]
    fn fetch_consensus_state(
        &self,
        height: Height,
    ) -> Result<AnyConsensusState, ForeignClientError> {
        let (consensus_state, _) = self
            .dst_chain
            .query_consensus_state(
                QueryConsensusStateRequest {
                    client_id: self.id.clone(),
                    consensus_height: height,
                    query_height: QueryHeight::Latest,
                },
                IncludeProof::No,
            )
            .map_err(|e| {
                ForeignClientError::client_consensus_query(
                    self.id.clone(),
                    self.dst_chain.id(),
                    height,
                    e,
                )
            })?;

        Ok(consensus_state)
    }

    /// Retrieves all consensus heights for this client sorted in descending order.
    #[instrument(
        name = "foreign_client.fetch_consensus_state_heights",
        level = "error",
        skip_all,
        fields(client = %self)
    )]
    fn fetch_consensus_state_heights(&self) -> Result<Vec<Height>, ForeignClientError> {
        let mut heights = self
            .dst_chain
            .query_consensus_state_heights(QueryConsensusStateHeightsRequest {
                client_id: self.id.clone(),
                pagination: Some(PageRequest::all()),
            })
            .map_err(|e| {
                ForeignClientError::client_query(self.id().clone(), self.src_chain.id(), e)
            })?;

        // This is necessary because the results are sorted in lexicographic order instead of
        // numeric order, and we cannot therefore rely on setting the `reverse = true` in the
        // `PageRequest` setting. Since we are asking for all heights anyway, we can sort them
        // ourselves.
        //
        // For more context, see:
        // - https://github.com/informalsystems/hermes/pull/2950#issuecomment-1373733744
        // - https://github.com/cosmos/ibc-go/issues/1399
        heights.sort_by_key(|&h| core::cmp::Reverse(h));

        Ok(heights)
    }

    /// Checks for evidence of misbehaviour.
    /// The check starts with and `update_event` emitted by chain B (`dst_chain`) for a client update
    /// with a header from chain A (`src_chain`). The algorithm goes backwards through the headers
    /// until it gets to the first misbehaviour.
    ///
    /// The following cases are covered:
    /// 1 - fork:
    /// Assumes at least one consensus state before the fork point exists.
    /// Let existing consensus states on chain B be: [Sn,.., Sf, Sf-1, S0] with `Sf-1` being
    /// the most recent state before fork.
    /// Chain A is queried for a header `Hf'` at `Sf.height` and if it is different than the `Hf`
    /// in the event for the client update (the one that has generated `Sf` on chain), then the two
    /// headers are included in the evidence and submitted.
    /// Note that in this case the headers are different but have the same height.
    ///
    /// 2 - BFT time violation for unavailable header (a.k.a. Future Lunatic Attack or FLA):
    /// Some header with a height that is higher than the latest
    /// height on A has been accepted and a consensus state was created on B. Note that this implies
    /// that the timestamp of this header must be within the `clock_drift` of the client.
    /// Assume the client on B has been updated with `h2`(not present on/ produced by chain A)
    /// and it has a timestamp of `t2` that is at most `clock_drift` in the future.
    /// Then the latest header from A is fetched, let it be `h1`, with a timestamp of `t1`.
    /// If `t1 >= t2` then evidence of misbehavior is submitted to A.
    ///
    /// 3 - BFT time violation for existing headers (TODO):
    /// Ensure that consensus state times are monotonically increasing with height.
    ///
    /// Other notes:
    /// - the algorithm builds misbehavior at each consensus height, starting with the
    /// highest height assuming the previous one is trusted. It submits the first constructed
    /// evidence (the one with the highest height)
    /// - a lot of the logic here is derived from the behavior of the only implemented client
    /// (ics07-tendermint) and might not be general enough.
    ///
    #[instrument(
        name = "foreign_client.detect_misbehaviour",
        level = "error",
        skip_all,
        fields(client = %self)
    )]
    pub fn detect_misbehaviour(
        &self,
        mut update: Option<&UpdateClient>,
    ) -> Result<Option<MisbehaviourEvidence>, ForeignClientError> {
        // FIXME(romac): Why do we need this, and shouldn't we wait somewhere else up the call stack?
        thread::sleep(Duration::from_millis(200));

        // Get the latest client state on destination.
        let (client_state, _) = {
            self.dst_chain()
                .query_client_state(
                    QueryClientStateRequest {
                        client_id: self.id().clone(),
                        height: QueryHeight::Latest,
                    },
                    IncludeProof::No,
                )
                .map_err(|e| {
                    ForeignClientError::misbehaviour(
                        format!("failed querying client state on dst chain {}", self.id),
                        e,
                    )
                })?
        };

        if let AnyClientState::Probabilistic(state) = &client_state {
            return self.detect_probabilistic_misbehaviour(state, update);
        }

        let consensus_state_heights = if let Some(event) = update {
            vec![event.consensus_height()]
        } else {
            // Get the list of consensus state heights in descending order.
            // Note: If chain does not prune consensus states then the last consensus state is
            // the one installed by the `CreateClient` which does not include a header.
            // For chains that do support pruning, it is possible that the last consensus state
            // was installed by an `UpdateClient` and an event and header will be found.
            self.fetch_consensus_state_heights()?
        };

        trace!(
            total = %consensus_state_heights.len(),
            heights = %consensus_state_heights.iter().copied().collated().format(", "),
            "checking misbehaviour for consensus state heights",
        );

        let start_time = Instant::now();

        for target_height in consensus_state_heights {
            // Start with specified update event or the one for latest consensus height
            let update_event = if let Some(event) = update {
                // we are here only on the first iteration when called with `Some` update event
                event.clone()
            } else if let Some(event) = self.fetch_update_client_event(target_height)? {
                // we are here either on the first iteration with `None` initial update event or
                // subsequent iterations
                event
            } else {
                // we are here if the consensus state was installed on-chain when client was
                // created, therefore there will be no update client event
                break;
            };

            // Skip over heights higher than the update event one.
            // This can happen if a client update happened with a lower height than latest.
            if target_height > update_event.consensus_height() {
                continue;
            }

            // Ensure consensus height of the event is same as target height. This should be the
            // case as we either
            // - got the `update_event` from the `target_height` above, or
            // - an `update_event` was specified and we should eventually find a consensus state
            //   at that height
            // We break here in case we got a bogus event.
            if target_height < update_event.consensus_height() {
                break;
            }

            // No header in events, cannot run misbehavior. Cardano update-client
            // events do not currently carry the submitted client message, so the
            // Cardano chain-specific checker is allowed to skip cleanly.
            if update_event.header.is_none()
                && !client_type_allows_missing_update_header(update_event.client_type())
            {
                return Err(ForeignClientError::misbehaviour_exit(format!(
                    "could not extract header from update client event {:?} emitted by chain {}",
                    update_event,
                    self.dst_chain.id()
                )));
            }

            let result =
                self.src_chain
                    .check_misbehaviour(update_event.clone(), client_state.clone(), None);

            let misbehavior = match result {
                // Misbehavior check passed.
                Ok(evidence_opt) => evidence_opt,

                // Predictable error occurred which we'll wrap.
                // This error means we cannot check for misbehavior with the provided `target_height`
                Err(e) if e.is_trusted_state_outside_trusting_period_error() => {
                    debug!(
                        target = %target_height,
                        "exhausted checking trusted consensus states for this client; no evidence found"
                    );

                    // It's safe to stop checking for misbehavior past this `target_height`.
                    break;
                }

                // Unknown error occurred in the light client `check_misbehaviour` method.
                // Propagate.
                Err(e) => {
                    return Err(ForeignClientError::misbehaviour(
                        format!(
                            "failed to check misbehaviour for {} at consensus height {}",
                            update_event.client_id(),
                            update_event.consensus_height(),
                        ),
                        e,
                    ))
                }
            };

            if misbehavior.is_some() {
                return Ok(misbehavior);
            }

            // Exit the loop if more than MAX_MISBEHAVIOUR_CHECK_DURATION was spent here.
            if start_time.elapsed() > MAX_MISBEHAVIOUR_CHECK_DURATION {
                trace!(
                    "finished misbehaviour verification after {:?}",
                    start_time.elapsed()
                );

                return Err(ForeignClientError::misbehaviour(
                    "historical verification did not complete".to_owned(),
                    RelayerError::query("misbehaviour scan exceeded its time budget".to_owned()),
                ));
            }

            // Clear the update
            update = None;

            // slight backoff
            thread::sleep(Duration::from_millis(100));
        }

        trace!(
            "finished misbehaviour verification after {:?}",
            start_time.elapsed()
        );

        Ok(None)
    }

    #[instrument(
        name = "foreign_client.submit_evidence",
        level = "error",
        skip_all,
        fields(client = %self)
    )]
    fn submit_evidence(
        &self,
        evidence: MisbehaviourEvidence,
    ) -> Result<Vec<IbcEvent>, ForeignClientError> {
        let signer = self.dst_chain().get_signer().map_err(|e| {
            ForeignClientError::misbehaviour(
                format!(
                    "failed getting signer for destination chain ({})",
                    self.dst_chain.id()
                ),
                e,
            )
        })?;

        let chain_config = self.src_chain().config().map_err(|e| {
            ForeignClientError::misbehaviour(
                format!("failed querying configuration of src chain {}", self.id),
                e,
            )
        })?;

        let is_ccv_consumer_chain = match chain_config {
            ChainConfig::CosmosSdk(config) => config.ccv_consumer_chain,
            #[cfg(feature = "namada")]
            ChainConfig::Namada(config) => config.ccv_consumer_chain,
            #[cfg(feature = "penumbra")]
            ChainConfig::Penumbra(_) => false,
            ChainConfig::Cardano(_) => false,
        };

        let mut msgs = vec![];

        for header in evidence.supporting_headers {
            msgs.push(
                MsgUpdateClient {
                    header: header.into(),
                    client_id: self.id.clone(),
                    signer: signer.clone(),
                }
                .to_any(),
            );
        }

        // If the misbehaving chain is a CCV consumer chain, we need to add
        // the corresponding CCV message for the provider.
        if is_ccv_consumer_chain {
            if let AnyMisbehaviour::Tendermint(tm_misbehaviour) = &evidence.misbehaviour {
                match fetch_ccv_consumer_id(&self.dst_chain(), &self.id) {
                    Ok(consumer_id) => {
                        msgs.push(
                            MsgSubmitIcsConsumerMisbehaviour {
                                submitter: signer.clone(),
                                misbehaviour: tm_misbehaviour.clone(),
                                consumer_id,
                            }
                            .to_any(),
                        );
                    }
                    Err(e) => {
                        error!(
                            "cannot build CCV misbehaviour evidence: failed to fetch CCV consumer id for client {}: {}",
                            self.id, e
                        );
                    }
                }
            } else {
                warn!(
                    "skipping CCV misbehaviour evidence for non-Tendermint client message {}",
                    evidence.misbehaviour
                );
            }
        }

        msgs.push(
            MsgUpdateClient {
                header: evidence.misbehaviour.into(),
                client_id: self.id.clone(),
                signer,
            }
            .to_any(),
        );

        let tm = TrackedMsgs::new_static(msgs, "evidence");

        let events = self
            .dst_chain()
            .send_messages_and_wait_commit(tm)
            .map_err(|e| {
                ForeignClientError::misbehaviour(
                    format!(
                        "failed sending evidence to destination chain ({})",
                        self.dst_chain.id(),
                    ),
                    e,
                )
            })?;

        if events.is_empty() {
            return Err(ForeignClientError::misbehaviour(
                "evidence submission did not return a committed result".to_owned(),
                RelayerError::query("missing evidence confirmation".to_owned()),
            ));
        }
        for event in &events {
            if matches!(event.event, IbcEvent::ChainError(_)) {
                return Err(ForeignClientError::chain_error_event(
                    self.dst_chain.id(),
                    event.event.clone(),
                ));
            }
        }
        Ok(events.into_iter().map(|ev| ev.event).collect())
    }

    #[instrument(
        name = "foreign_client.detect_misbehaviour_and_submit_evidence",
        level = "error",
        skip_all,
        fields(client = %self)
    )]
    pub fn detect_misbehaviour_and_submit_evidence(
        &self,
        update_event: Option<UpdateClient>,
    ) -> MisbehaviourResults {
        // check evidence of misbehaviour for all updates or one
        let result = match self.detect_misbehaviour(update_event.as_ref()) {
            Err(e) => Err(e),
            Ok(None) => Ok(vec![]), // no evidence found
            Ok(Some(detected)) => {
                error!(
                    misbehaviour = %detected.misbehaviour,
                    "misbehaviour detected, sending evidence"
                );

                telemetry!(
                    client_misbehaviours_submitted,
                    &self.src_chain.id(),
                    &self.dst_chain.id(),
                    &self.id,
                    1
                );

                self.submit_evidence(detected)
            }
        };

        // Incomplete verification is retryable for both startup and update
        // checks. Only unsupported checking and expired/frozen clients stop it.
        match result {
            Ok(events) => {
                if !events.is_empty() {
                    info!("Evidence successfully submitted: {}", PrettySlice(&events));

                    MisbehaviourResults::EvidenceSubmitted(events)
                } else {
                    info!("client is valid");

                    MisbehaviourResults::ValidClient
                }
            }

            Err(e) => match e.detail() {
                ForeignClientErrorDetail::MisbehaviourExit(s) => {
                    error!("misbehaviour checking is being disabled, reason: {s}");

                    MisbehaviourResults::CannotExecute
                }

                ForeignClientErrorDetail::ExpiredOrFrozen(_) => {
                    error!("cannot check misbehavior on frozen or expired client");

                    MisbehaviourResults::CannotExecute
                }

                _ => {
                    warn!(%e, "misbehaviour verification incomplete, retry required");
                    MisbehaviourResults::VerificationError
                }
            },
        }
    }

    pub fn map_chain<DstChain2: ChainHandle, SrcChain2: ChainHandle>(
        self,
        map_dst: impl Fn(DstChain) -> DstChain2,
        map_src: impl Fn(SrcChain) -> SrcChain2,
    ) -> ForeignClient<DstChain2, SrcChain2> {
        ForeignClient {
            id: self.id,
            dst_chain: map_dst(self.dst_chain),
            src_chain: map_src(self.src_chain),
            probabilistic_scan: self.probabilistic_scan,
        }
    }
}

#[derive(Clone, Debug)]
pub enum MisbehaviourResults {
    CannotExecute,
    EvidenceSubmitted(Vec<IbcEvent>),
    ValidClient,
    VerificationError,
}

pub fn extract_client_id(event: &IbcEvent) -> Result<&ClientId, ForeignClientError> {
    match event {
        IbcEvent::CreateClient(ev) => Ok(ev.client_id()),
        IbcEvent::UpdateClient(ev) => Ok(ev.client_id()),
        _ => Err(ForeignClientError::missing_client_id_from_event(
            event.clone(),
        )),
    }
}

fn parse_client_counter(client_id: &str) -> u64 {
    client_id
        .rsplit('-')
        .next()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or_default()
}

fn client_type_allows_missing_update_header(client_type: ClientType) -> bool {
    is_cardano_client_type(client_type)
}

fn should_skip_client_update(
    client_type: ClientType,
    latest_height: Height,
    target_height: Height,
) -> bool {
    latest_height == target_height
        || (is_cardano_client_type(client_type) && latest_height > target_height)
}

fn is_cardano_client_type(client_type: ClientType) -> bool {
    matches!(client_type, ClientType::CardanoProbabilistic)
}

pub fn fetch_ccv_consumer_id(
    provider: &impl ChainHandle,
    client_id: &ClientId,
) -> Result<ConsumerId, ForeignClientError> {
    let consumer_id = provider.query_ccv_consumer_id(client_id).map_err(|e| {
        ForeignClientError::misbehaviour(
            format!(
                "failed to query CCV consumer id corresponding to client {} from provider {}",
                client_id,
                provider.id()
            ),
            e,
        )
    })?;

    Ok(consumer_id)
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::{Duration, Instant};

    use ibc_proto::google::protobuf::Any;
    use ibc_relayer_types::clients::ics08_cardano_probabilistic::{
        client_state::ClientState as ProbabilisticClientState,
        consensus_state::ConsensusState as ProbabilisticConsensusState,
    };
    use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentRoot;
    use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ClientId};
    use ibc_relayer_types::timestamp::Timestamp;

    use crate::chain::endpoint::ChainStatus;
    use crate::chain::handle::{BaseChainHandle, ChainRequest};
    use crate::client_state::AnyClientState;
    use crate::consensus_state::AnyConsensusState;
    use crate::error::Error as RelayerError;

    use super::{
        client_type_allows_missing_update_header, should_skip_client_update, ClientType,
        ForeignClient, ForeignClientError, Height,
    };

    fn height(revision_height: u64) -> Height {
        Height::new(0, revision_height).expect("valid test height")
    }

    #[test]
    fn cardano_clients_may_skip_misbehaviour_without_update_header() {
        assert!(client_type_allows_missing_update_header(
            ClientType::CardanoProbabilistic
        ));
        assert!(!client_type_allows_missing_update_header(
            ClientType::Tendermint
        ));
    }

    #[test]
    fn tendermint_clients_can_fill_missing_historical_consensus_states() {
        assert!(!should_skip_client_update(
            ClientType::Tendermint,
            height(33),
            height(4),
        ));
    }

    #[test]
    fn tendermint_clients_skip_updates_at_the_latest_height() {
        assert!(should_skip_client_update(
            ClientType::Tendermint,
            height(33),
            height(33),
        ));
    }

    #[test]
    fn cardano_clients_skip_updates_at_or_below_the_latest_height() {
        assert!(should_skip_client_update(
            ClientType::CardanoProbabilistic,
            height(33),
            height(4),
        ));
        assert!(should_skip_client_update(
            ClientType::CardanoProbabilistic,
            height(33),
            height(33),
        ));
    }

    #[test]
    fn cardano_clients_still_update_to_newer_heights() {
        assert!(!should_skip_client_update(
            ClientType::CardanoProbabilistic,
            height(4),
            height(33),
        ));
    }

    #[derive(Default)]
    struct ProofPreparationRequests {
        consensus_heights: Vec<Height>,
        client_state_queries: usize,
        application_status_queries: usize,
        submissions: usize,
    }

    pub(super) fn checkpoint_test_client_state(exact_root_exists: bool) -> AnyClientState {
        let source_id = ChainId::from_string("cardano-0");
        AnyClientState::Probabilistic(ProbabilisticClientState {
            storage_version: 2,
            verification_generation: 0,
            checkpoint_reference: vec![],
            storage_namespace: vec![],
            bootstrap_objects: vec![],
            bootstrap_pending: false,
            mithril_epoch: 0,
            mithril_aggregate_verification_key: String::new(),
            mithril_protocol_parameters_hash: String::new(),
            packet_lane_policy_id: vec![0x55; 28],
            epoch_context_challenges: vec![],
            latest_checkpoint_nonce_state: None,
            latest_checkpoint_pool_registry: None,
            latest_checkpoint_settlement_credit: None,
            latest_checkpoint_pool_production: None,
            randomness_stabilisation_window_slots: 0,
            chain_id: source_id.clone(),
            latest_height: height(if exact_root_exists { 33 } else { 10 }),
            frozen_height: None,
            current_epoch: 0,
            trusting_period: Duration::from_secs(60),
            upgrade_path: vec![],
            host_state_nft_policy_id: vec![1; 28],
            host_state_nft_token_name: b"hostState".to_vec(),
            epoch_stake_distribution: vec![],
            epoch_nonce: vec![0; 32],
            slots_per_kes_period: 100,
            current_epoch_start_slot: 1,
            current_epoch_end_slot_exclusive: 1_000,
            system_start_unix_ns: 50_000_000_000,
            slot_length_ns: 1_000_000_000,
            epoch_contexts: vec![],
            latest_checkpoint_height: Some(height(50)),
            latest_checkpoint_block_hash: "02".repeat(32),
            latest_checkpoint_epoch: 0,
            max_kes_evolutions: 62,
            latest_checkpoint_operational_certificate_counters: vec![],
            operational_certificate_counter_history_start_height: Some(height(10)),
            active_slot_coefficient_numerator: 1,
            active_slot_coefficient_denominator: 20,
            max_clock_drift: Duration::from_secs(10),
            latest_checkpoint_slot: 50,
            latest_checkpoint_timestamp: 100_000_000_000,
        })
    }

    // Exercise the real helper through the runtime request/reply boundary. The
    // cursor at 50 authenticates headers, while only the listed heights have
    // roots that can verify a handshake proof.
    fn prepare_proof_with_checkpoint_cursor(
        exact_root_exists: bool,
        packet_path: bool,
    ) -> (
        Result<Vec<Any>, ForeignClientError>,
        ProofPreparationRequests,
        ProofPreparationRequests,
    ) {
        let source_id = ChainId::from_string("cardano-0");
        let client_id: ClientId = "08-cardano-probabilistic-0".parse().unwrap();
        let client_state = checkpoint_test_client_state(exact_root_exists);
        let consensus_state = AnyConsensusState::Probabilistic(ProbabilisticConsensusState {
            verification_generation: 0,
            checkpoint_reference: vec![],
            packet_state_reference: vec![],

            root: CommitmentRoot::from_bytes(&[1; 32]),
            timestamp: 100_000_000_000,
            accepted_block_hash: "01".repeat(32),
            accepted_epoch: 0,
            unique_pools_count: 1,
            unique_stake_bps: 10_000,
            security_score_bps: 10_000,
        });

        let (source_sender, source_receiver) = crossbeam_channel::unbounded();
        let source = BaseChainHandle::new(source_id, source_sender);
        let source_runtime = thread::spawn(move || {
            let mut requests = ProofPreparationRequests::default();
            for (_, request) in source_receiver {
                match request {
                    ChainRequest::QueryApplicationStatus { reply_to } => {
                        requests.application_status_queries += 1;
                        reply_to
                            .send(Ok(ChainStatus {
                                height: height(60),
                                timestamp: Timestamp::from_nanoseconds(110_000_000_000).unwrap(),
                            }))
                            .unwrap();
                    }
                    ChainRequest::SendMessagesAndWaitCommit { reply_to, .. } => {
                        requests.submissions += 1;
                        reply_to
                            .send(Err(RelayerError::query("unexpected submission".into())))
                            .unwrap();
                    }
                    ChainRequest::SendMessagesAndWaitCheckTx { reply_to, .. } => {
                        requests.submissions += 1;
                        reply_to
                            .send(Err(RelayerError::query("unexpected submission".into())))
                            .unwrap();
                    }
                    unexpected => panic!("unexpected source request: {unexpected:?}"),
                }
            }
            requests
        });

        let (destination_sender, destination_receiver) = crossbeam_channel::unbounded();
        let destination =
            BaseChainHandle::new(ChainId::from_string("cosmos-0"), destination_sender);
        let expected_client_id = client_id.clone();
        let destination_runtime = thread::spawn(move || {
            let mut requests = ProofPreparationRequests::default();
            for (_, request) in destination_receiver {
                match request {
                    ChainRequest::QueryApplicationStatus { reply_to } => {
                        requests.application_status_queries += 1;
                        reply_to
                            .send(Ok(ChainStatus {
                                height: height(60),
                                timestamp: Timestamp::from_nanoseconds(110_000_000_000).unwrap(),
                            }))
                            .unwrap();
                    }
                    ChainRequest::QueryClientStatus { reply_to, .. } => {
                        reply_to.send(Ok(Some("Active".to_owned()))).unwrap();
                    }
                    ChainRequest::QueryConsensusState {
                        request, reply_to, ..
                    } => {
                        assert_eq!(request.client_id, expected_client_id);
                        requests.consensus_heights.push(request.consensus_height);
                        let available = request.consensus_height == height(10)
                            || (exact_root_exists && request.consensus_height == height(33));
                        let response = if available {
                            Ok((consensus_state.clone(), None))
                        } else {
                            Err(RelayerError::query("missing exact consensus root".into()))
                        };
                        reply_to.send(response).unwrap();
                    }
                    ChainRequest::QueryClientState {
                        request, reply_to, ..
                    } => {
                        assert_eq!(request.client_id, expected_client_id);
                        requests.client_state_queries += 1;
                        reply_to.send(Ok((client_state.clone(), None))).unwrap();
                    }
                    ChainRequest::SendMessagesAndWaitCommit { reply_to, .. } => {
                        requests.submissions += 1;
                        reply_to
                            .send(Err(RelayerError::query("unexpected submission".into())))
                            .unwrap();
                    }
                    ChainRequest::SendMessagesAndWaitCheckTx { reply_to, .. } => {
                        requests.submissions += 1;
                        reply_to
                            .send(Err(RelayerError::query("unexpected submission".into())))
                            .unwrap();
                    }
                    unexpected => panic!("unexpected destination request: {unexpected:?}"),
                }
            }
            requests
        });

        let client = ForeignClient::restore(client_id, destination, source);
        let result = if packet_path {
            client.wait_and_build_update_client_for_proof(height(33))
        } else {
            client.prepare_update_client_for_proof(height(33))
        };
        drop(client);
        (
            result,
            source_runtime.join().unwrap(),
            destination_runtime.join().unwrap(),
        )
    }

    #[test]
    fn prepare_update_client_for_proof_accepts_existing_exact_root_without_sending() {
        let (result, source, destination) = prepare_proof_with_checkpoint_cursor(true, false);

        assert!(result.expect("the exact proof root exists").is_empty());
        // Challenge checks also revalidate the client before and after preparing updates.
        assert_eq!(destination.consensus_heights, vec![height(33); 2]);
        assert_eq!(destination.client_state_queries, 4);
        assert_eq!(source.application_status_queries, 0);
        assert_eq!(source.submissions + destination.submissions, 0);
    }

    #[test]
    fn prepare_update_client_for_proof_rejects_missing_root_behind_checkpoint_without_sending() {
        let (result, source, destination) = prepare_proof_with_checkpoint_cursor(false, false);

        let error = result.expect_err("a later checkpoint cannot supply the missing proof root");
        assert!(error
            .to_string()
            .contains("proof consensus state at 0-33 is unavailable"));
        assert!(error
            .to_string()
            .contains("a checkpoint cursor is insufficient"));
        assert_eq!(destination.consensus_heights, vec![height(33), height(33)]);
        assert!(destination.client_state_queries >= 6);
        assert!(source.application_status_queries <= 1);
        assert_eq!(source.submissions + destination.submissions, 0);
    }

    #[test]
    fn packet_update_requires_the_exact_root_when_cursor_is_a_later_checkpoint() {
        for present in [false, true] {
            let (result, source, destination) = prepare_proof_with_checkpoint_cursor(present, true);
            if present {
                assert!(result.expect("packet root is retained").is_empty());
            } else {
                assert!(result
                    .expect_err("checkpoint cannot authenticate this packet proof")
                    .to_string()
                    .contains("proof consensus state at 0-33 is unavailable"));
            }
            assert_eq!(destination.consensus_heights.last(), Some(&height(33)));
            assert_eq!(source.submissions + destination.submissions, 0);
        }
    }
    #[test]
    fn snapshot_restart_discovers_future_proposal_at_its_saved_checkpoint() {
        run_snapshot_startup_check(None, false);
    }

    #[test]
    fn startup_retries_failed_history_without_events_or_restart() {
        run_snapshot_startup_check(Some(true), false);
        run_snapshot_startup_check(Some(false), false);
    }

    #[test]
    fn startup_resumes_bounded_history_while_rechecking_pending_proposals() {
        run_snapshot_startup_check(None, true);
    }

    fn run_snapshot_startup_check(fail_history_page: Option<bool>, paged_history: bool) {
        use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw;
        use ibc_relayer_types::core::ics02_client::header::AnyHeader;
        use prost::Message;
        use serde_json::json;
        let historical = raw::ClientState {
            chain_id: "cardano-0".into(),
            latest_height: Some(height(966).into()),
            latest_checkpoint_height: Some(height(966).into()),
            latest_checkpoint_block_hash: "01".repeat(32),
            latest_checkpoint_epoch: 7,
            latest_checkpoint_slot: 966,
            latest_checkpoint_timestamp: 966_000_000_001,
            current_epoch: 7,
            trusting_period: Some(ibc_proto::google::protobuf::Duration {
                seconds: 604800,
                nanos: 0,
            }),
            max_clock_drift: Some(ibc_proto::google::protobuf::Duration {
                seconds: 10,
                nanos: 0,
            }),
            host_state_nft_policy_id: vec![1; 28],
            packet_lane_policy_id: vec![2; 28],
            epoch_nonce: vec![3; 32],
            slots_per_kes_period: 129600,
            current_epoch_start_slot: 1,
            current_epoch_end_slot_exclusive: 432001,
            system_start_unix_ns: 1,
            slot_length_ns: 1000000000,
            max_kes_evolutions: 62,
            operational_certificate_counter_history_start_height: Some(height(966).into()),
            active_slot_coefficient_numerator: 1,
            active_slot_coefficient_denominator: 20,
            storage_version: 2,
            verification_generation: 1,
            storage_namespace: vec![1; 32],
            checkpoint_reference: vec![2; 32],
            latest_checkpoint_pool_production: Some(raw::PoolProductionHistory {
                epoch: 7,
                pools: vec![raw::PoolProductionRecord {
                    pool_id: "pool-a".into(),
                    completed_epochs_bitmap: 1,
                    produced_current_epoch: false,
                }],
            }),
            latest_checkpoint_settlement_credit: Some(raw::SettlementCreditState {
                epoch: 7,
                reference: vec![raw::PoolSettlementCredit {
                    pool_id: "pool-a".into(),
                    numerator: vec![1],
                    denominator: vec![5],
                }],
            }),
            ..Default::default()
        };
        let mut latest = historical.clone();
        latest.latest_checkpoint_height = Some(height(990).into());
        latest.latest_checkpoint_slot = 990;
        latest.latest_checkpoint_timestamp = 990_000_000_001;
        latest.checkpoint_reference = vec![4; 32];
        latest.epoch_context_challenges = vec![raw::EpochContextChallenge {
            epoch: 8,
            usable_after_unix_ns: 300_000_000_000,
        }];
        let latest =
            AnyClientState::Probabilistic(ProbabilisticClientState::try_from(latest).unwrap());
        let (sender, receiver) = crossbeam_channel::unbounded();
        let source = BaseChainHandle::new(ChainId::from_string("cardano-0"), sender);
        let source_runtime = thread::spawn(move || {
            let mut found = Vec::new();
            for (_, request) in receiver {
                match request {
                    ChainRequest::BuildMisbehaviour {
                        update_event,
                        challenge_context,
                        reply_to,
                        ..
                    } => {
                        let Some(AnyHeader::Probabilistic(header)) = update_event.header else {
                            panic!("missing receipt observation")
                        };
                        assert_eq!(header.trusted_height, height(966));
                        assert!(header.height == height(1001) || header.height == height(990));
                        let context =
                            raw::ClientState::decode(challenge_context.unwrap().as_slice())
                                .unwrap();
                        assert_eq!(context.current_epoch, 7);
                        assert_eq!(context.latest_checkpoint_height, Some(height(966).into()));
                        assert_eq!(
                            context.latest_checkpoint_pool_production.unwrap().pools[0]
                                .completed_epochs_bitmap,
                            1
                        );
                        assert_eq!(
                            context
                                .latest_checkpoint_settlement_credit
                                .unwrap()
                                .reference[0]
                                .numerator,
                            vec![1]
                        );
                        found.push(header.height.revision_height());
                        reply_to.send(Ok(None)).unwrap();
                    }
                    request => panic!("unexpected source request: {request:?}"),
                }
            }
            found
        });
        let (sender, receiver) = crossbeam_channel::unbounded();
        let destination = BaseChainHandle::new(ChainId::from_string("cosmos-0"), sender);
        let destination_runtime = thread::spawn(move || {
            let mut requested = vec![];
            let mut page_cursors = vec![];
            let mut failed = false;
            for (_, request) in receiver {
                match request {
                    ChainRequest::QueryClientState { reply_to, .. } => {
                        reply_to.send(Ok((latest.clone(), None))).unwrap()
                    }
                    ChainRequest::QueryProbabilisticVerification {
                        request, reply_to, ..
                    } => {
                        requested.push(request.kind);
                        let fail = match fail_history_page {
                            Some(true) => request.kind == 12,
                            Some(false) => request.kind == 0 && request.receipt_id == vec![9; 32],
                            None => false,
                        };
                        if fail && !failed {
                            failed = true;
                            reply_to
                                .send(Err(RelayerError::query(
                                    "temporary historical query failure".into(),
                                )))
                                .unwrap();
                            continue;
                        }
                        let response = match request.kind {
                            10 => json!([{"Receipt":vec![7;32],"Table":{"Epoch":8}}]),
                            9 => {
                                json!({"BaseReference":vec![2;32],"AnchorHeight":1001,"AnchorHash":vec![8;32]})
                            }
                            12 if paged_history => {
                                page_cursors.push(request.after.clone());
                                if request.after.is_empty() {
                                    json!({"records":[{"ID":vec![9;32],"Receipt":{"BaseReference":vec![2;32],"AnchorHeight":990,"AnchorHash":vec![9;32]}}],"next":vec![9;32]})
                                } else {
                                    assert_eq!(request.after, vec![9; 32]);
                                    json!({"records":[],"next":[]})
                                }
                            }
                            12 if fail_history_page.is_some() => {
                                json!({"records":[{"ID":vec![9;32],"Receipt":{"BaseReference":vec![2;32],"AnchorHeight":990,"AnchorHash":vec![9;32]}}],"next":[]})
                            }
                            12 => json!({"records":[],"next":[]}),
                            0 => {
                                assert_eq!(request.checkpoint_reference, vec![2; 32]);
                                assert!(
                                    request.receipt_id == vec![7; 32]
                                        || request.receipt_id == vec![9; 32]
                                );
                                json!({"Height":966})
                            }
                            other => panic!("unexpected verification query {other}"),
                        };
                        reply_to
                            .send(Ok(serde_json::to_vec(&response).unwrap()))
                            .unwrap();
                    }
                    ChainRequest::QueryCardanoChallengeContext {
                        trusted_height,
                        receipt_id,
                        reply_to,
                        ..
                    } => {
                        assert_eq!(trusted_height, height(966));
                        assert!(receipt_id == Some(vec![7; 32]) || receipt_id == Some(vec![9; 32]));
                        reply_to.send(Ok(historical.encode_to_vec())).unwrap();
                    }
                    request => panic!("unexpected destination request: {request:?}"),
                }
            }
            (requested, page_cursors)
        });
        let client = ForeignClient::restore(
            "08-cardano-probabilistic-0".parse().unwrap(),
            destination,
            source,
        );
        let mut monitor = crate::worker::client::MisbehaviourMonitor::new(true);
        let now = Instant::now();
        assert!(monitor.incomplete());
        assert!(matches!(
            monitor.tick(now, [], |update| client
                .detect_misbehaviour_and_submit_evidence(update)),
            crate::util::task::Next::Continue
        ));
        if fail_history_page.is_some() || paged_history {
            assert!(
                monitor.incomplete(),
                "a failed scan must expose incomplete coverage"
            );
            monitor.tick(now + Duration::from_secs(1), [], |_| {
                panic!("must respect retry backoff")
            });
            assert!(matches!(
                monitor.tick(now + Duration::from_secs(6), [], |update| client
                    .detect_misbehaviour_and_submit_evidence(update)),
                crate::util::task::Next::Continue
            ));
        }
        assert!(
            !monitor.incomplete(),
            "coverage recovers without new update events"
        );
        drop(client);
        let checked = source_runtime.join().unwrap();
        let (requested, page_cursors) = destination_runtime.join().unwrap();
        if paged_history {
            assert_eq!(checked, vec![1001, 990, 1001]);
            assert_eq!(page_cursors, vec![vec![], vec![9; 32]]);
        } else if fail_history_page.is_some() {
            assert_eq!(
                checked,
                vec![1001, 1001, 990],
                "pending proposal is checked even while historical queries fail"
            );
        } else {
            assert_eq!(checked, vec![1001]);
            assert_eq!(requested, vec![10, 9, 0, 12]);
        }
    }
}

#[cfg(test)]
#[path = "foreign_client/freshness_tests.rs"]
mod freshness_tests;

#[cfg(test)]
#[path = "foreign_client/initialization_tests.rs"]
mod initialization_tests;

#[cfg(test)]
#[path = "foreign_client/mithril_stake_tests.rs"]
mod mithril_stake_tests;
