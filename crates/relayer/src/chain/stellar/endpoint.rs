use alloc::sync::Arc;
use core::str::FromStr;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use ibc_proto::ibc::apps::fee::v1::{
    QueryIncentivizedPacketRequest, QueryIncentivizedPacketResponse,
};
use ibc_proto::ibc::core::channel::v1::{QueryUpgradeErrorRequest, QueryUpgradeRequest};
use ibc_relayer_types::applications::ics28_ccv::msgs::{ConsumerChain, ConsumerId};
use ibc_relayer_types::applications::ics31_icq::response::CrossChainQueryResponse;
use ibc_relayer_types::clients::ics10_stellar::client_state::ClientState as StellarClientState;
use ibc_relayer_types::clients::ics10_stellar::consensus_state::ConsensusState as StellarConsensusState;
use ibc_relayer_types::clients::ics10_stellar::header::Header as StellarHeader;
use ibc_relayer_types::clients::ics10_stellar::misbehaviour::Misbehaviour as StellarMisbehaviour;
use ibc_relayer_types::clients::ics10_stellar::raw as stellar_raw;
use ibc_relayer_types::core::ics02_client::events::UpdateClient;
use ibc_relayer_types::core::ics02_client::header::{AnyHeader, Header as IbcHeader};
use ibc_relayer_types::core::ics02_client::height::Height;
use ibc_relayer_types::core::ics03_connection::connection::{
    ConnectionEnd, IdentifiedConnectionEnd,
};
use ibc_relayer_types::core::ics04_channel::channel::{ChannelEnd, IdentifiedChannelEnd};
use ibc_relayer_types::core::ics04_channel::packet::Sequence;
use ibc_relayer_types::core::ics04_channel::upgrade::{ErrorReceipt, Upgrade};
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentPrefix;
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentRoot;
use ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof;
use ibc_relayer_types::core::ics24_host::identifier::{
    ChainId, ChannelId, ClientId, ConnectionId, PortId,
};
use ibc_relayer_types::events::{IbcEvent, ModuleEvent, ModuleEventAttribute, ModuleId};
use ibc_relayer_types::signer::Signer;
use ibc_relayer_types::timestamp::Timestamp;
use ibc_relayer_types::Height as ICSHeight;
use prost::Message as _;
use tendermint_rpc::endpoint::broadcast::tx_sync::Response as TxResponse;
use tokio::runtime::Runtime as TokioRuntime;

use crate::account::Balance;
use crate::chain::client::ClientSettings;
use crate::chain::cosmos::version::Specs as CosmosSpecs;
use crate::chain::endpoint::{ChainEndpoint, ChainStatus, HealthCheck};
use crate::chain::handle::Subscription;
use crate::chain::requests::*;
use crate::chain::tracking::{TrackedMsgs, TrackingId};
use crate::chain::version::Specs;
use crate::client_state::{AnyClientState, IdentifiedAnyClientState};
use crate::config::{ChainConfig, Error as ConfigError};
use crate::consensus_state::AnyConsensusState;
use crate::denom::DenomTrace;
use crate::error::Error;
use crate::event::source::{Error as SourceError, EventBatch};
use crate::event::IbcEventWithHeight;
use crate::keyring::{KeyRing, SigningKeyPair, Store};
use crate::misbehaviour::{AnyMisbehaviour, MisbehaviourEvidence};

use super::config::StellarConfig;
use super::gateway_client::{
    self, EventsRequest, GatewayMsgClient, GatewayQueryClient, QueryIbcHeaderRequest,
};
use super::signing_key_pair::StellarSigningKeyPair;
use ibc_relayer_types::clients::ics10_stellar as stellar_types;

/// One verified-on-chain Stellar ledger, as hermes carries it internally.
///
/// It holds the SCP *evidence* — envelopes, quorum-set preimages, the next
/// slot's tx set — not a conclusion. Hermes does not verify any of it; the
/// light client on the counterparty chain does. Previously this carried an
/// `ibc_state_root` the gateway had computed off-chain, which meant trusting
/// that service for the one value the whole bridge rests on.
pub struct StellarLightBlock {
    pub slot_index: u64,
    pub ledger_hash: Vec<u8>,
    pub timestamp: Timestamp,
    pub close_time_secs: u64,
    pub ledger_header_xdr: Vec<u8>,
    pub scp_envelopes: Vec<Vec<u8>>,
    pub quorum_sets_xdr: Vec<Vec<u8>>,
    pub next_scp_envelopes: Vec<Vec<u8>>,
    pub next_tx_set_xdr: Vec<u8>,
    pub state_root_proof: Option<stellar_raw::StateRootProof>,
}

pub struct StellarChainEndpoint {
    pub config: StellarConfig,
    pub keyring: KeyRing<StellarSigningKeyPair>,
    pub gateway_query: StdMutex<GatewayQueryClient>,
    pub gateway_msg: StdMutex<GatewayMsgClient>,
    pub rt: Arc<TokioRuntime>,
    pub event_sender: StdMutex<
        Option<
            crossbeam_channel::Sender<
                Arc<crate::event::source::Result<crate::event::source::EventBatch>>,
            >,
        >,
    >,
}

impl ChainEndpoint for StellarChainEndpoint {
    type LightBlock = StellarLightBlock;
    type Header = AnyHeader;
    type ConsensusState = AnyConsensusState;
    type ClientState = AnyClientState;
    type Time = Timestamp;
    type SigningKeyPair = StellarSigningKeyPair;

    fn id(&self) -> &ChainId {
        &self.config.id
    }

    fn config(&self) -> ChainConfig {
        ChainConfig::Stellar(self.config.clone())
    }

    fn bootstrap(config: ChainConfig, rt: Arc<TokioRuntime>) -> Result<Self, Error> {
        let stellar_config = match config {
            ChainConfig::Stellar(c) => c,
            _ => {
                tracing::error!("invalid config type provided to stellar bootstrap");

                return Err(Error::config(ConfigError::wrong_type()));
            }
        };

        tracing::info!(
            "[stellar] connecting endpoint id={} gateway={}",
            stellar_config.id,
            stellar_config.gateway_url,
        );

        let gateway_query = rt
            .block_on(GatewayQueryClient::connect(
                stellar_config.gateway_url.clone(),
            ))
            .map_err(|e| {
                tracing::error!("Stellar gateway query connect failed: {e}");
                Error::config(ConfigError::wrong_type())
            })?;

        tracing::debug!(
            "[stellar] gateway query client connected id={} gateway={}",
            stellar_config.id,
            stellar_config.gateway_url,
        );

        let gateway_msg = rt
            .block_on(GatewayMsgClient::connect(
                stellar_config.gateway_url.clone(),
            ))
            .map_err(|e| {
                tracing::error!("Stellar gateway msg connect failed: {e}");
                Error::config(ConfigError::wrong_type())
            })?;

        tracing::debug!(
            "[stellar] gateway message client connected id={} gateway={}",
            stellar_config.id,
            stellar_config.gateway_url,
        );

        let keyring = KeyRing::new(Store::Test, "stellar", &stellar_config.id, &None)
            .map_err(Error::key_base)?;

        tracing::info!(
            "[stellar] endpoint ready id={} gateway={}",
            stellar_config.id,
            stellar_config.gateway_url,
        );

        // todo: check for misbehaviour config

        Ok(Self {
            config: stellar_config,
            keyring,
            gateway_query: StdMutex::new(gateway_query),
            gateway_msg: StdMutex::new(gateway_msg),
            rt,
            event_sender: StdMutex::new(None),
        })
    }

    fn shutdown(self) -> Result<(), Error> {
        tracing::info!("[stellar] endpoint shutting down");

        Ok(())
    }

    fn health_check(&mut self) -> Result<HealthCheck, Error> {
        let resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();

                guard.latest_height().await
            })
            .map_err(|e| Error::query(format!("Stellar gateway latest height failed: {e}")))?;

        if resp.revision_height == 0 {
            return Err(Error::query(
                "Stellar gateway reported revision_height=0".to_string(),
            ));
        }

        tracing::info!("[stellar] health ok — height {}", resp.revision_height);

        Ok(HealthCheck::Healthy)
    }

    fn subscribe(&mut self) -> Result<Subscription, Error> {
        let (tx, rx) = crossbeam_channel::unbounded();
        {
            let mut guard = self.event_sender.lock().unwrap();
            *guard = Some(tx.clone());
        }

        let chain_id = self.config.id.clone();
        let gateway_url = self.config.gateway_url.clone();
        let poll_interval = Duration::from_secs(2);

        self.rt.spawn(async move {
            run_event_polling(chain_id, gateway_url, tx, poll_interval).await;
        });

        Ok(rx)
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

        tracing::debug!("getting stellar signer from keyring");

        let signer = Signer::from_str(&key.account_id()).map_err(|e| {
            Error::key_base(crate::keyring::errors::Error::invalid_mnemonic(
                anyhow::anyhow!("Invalid Stellar signer address: {e}"),
            ))
        });

        tracing::debug!("stellar signer from keyring: {}", key.account_id());

        signer
    }

    fn get_key(&self) -> Result<Self::SigningKeyPair, Error> {
        self.keyring
            .get_key(&self.config.key_name)
            .map_err(Error::key_base)
    }

    fn version_specs(&self) -> Result<Specs, Error> {
        // todo: return stellar protocol version info

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
        tracing::debug!(
            "send_messages_and_wait_commit: processing {} messages",
            tracked_msgs.msgs.len()
        );

        let signer = self.get_signer()?.to_string();
        let signing_key = self.get_key()?;
        let network_passphrase = self.config.network_passphrase.clone();

        self.rt.block_on(async {
            let mut events = Vec::new();

            for msg in tracked_msgs.msgs.iter() {
                let msg_events = dispatch_msg(
                    &self.gateway_msg,
                    &msg.type_url,
                    msg.value.clone(),
                    &signer,
                    &signing_key,
                    &network_passphrase,
                )
                .await?;

                // todo: get events from tx response

                // todo: check if stellar verified the tx height

                events.extend(msg_events);
            }

            // todo: parse events using event parser + events with height

            Ok::<Vec<IbcEventWithHeight>, Error>(events)
        })
    }

    fn send_messages_and_wait_check_tx(
        &mut self,
        tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<TxResponse>, Error> {
        tracing::debug!(
            "send_messages_and_wait_check_tx: processing {} messages",
            tracked_msgs.msgs.len()
        );

        // todo: adjust this method so it is non blocking as the commit one

        self.send_messages_and_wait_commit(tracked_msgs)?;

        Ok(Vec::new())
    }

    fn verify_header(
        &mut self,
        trusted: ICSHeight,
        target: ICSHeight,
        _client_state: &AnyClientState,
    ) -> Result<Self::LightBlock, Error> {
        // todo: verify proof header

        let height = if trusted < target { trusted } else { target };

        tracing::debug!(
            "stellar verify header with trusted height {}, target height {} and query height {}",
            trusted,
            target,
            height
        );

        let resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();

                guard
                    .query_ibc_header(QueryIbcHeaderRequest {
                        height: height.revision_height(),
                    })
                    .await
            })
            .map_err(|e| {
                Error::query(format!(
                    "Stellar gateway query_ibc_header failed at {target}: {e}"
                ))
            })?;

        let wire = gateway_client::StellarHeader::decode(resp.header.as_slice())
            .map_err(|e| Error::query(format!("StellarHeader decode failed: {e}")))?;

        let close_time = ledger_close_time_secs(&wire.ledger_header_xdr)?;

        let timestamp = Timestamp::from_nanoseconds(close_time.saturating_mul(1_000_000_000))
            .map_err(|e| Error::query(format!("invalid Stellar close_time: {e}")))?;

        let ledger_hash = ledger_previous_hash(&wire.ledger_header_xdr)?;

        tracing::debug!(
            "verified stellar header with trusted height {}, target height {} and query height {}",
            trusted,
            target,
            height
        );

        if wire.state_root_proof.is_none() {
            // Legitimate for a ledger the bridge did not touch, but such a
            // header binds no state root, so packet proofs against it will not
            // verify.
            tracing::debug!(
                slot = wire.slot_index,
                "stellar header carries no state-root proof"
            );
        }

        Ok(StellarLightBlock {
            slot_index: wire.slot_index,
            ledger_hash,
            timestamp,
            close_time_secs: close_time,
            ledger_header_xdr: wire.ledger_header_xdr,
            scp_envelopes: wire.scp_envelopes,
            quorum_sets_xdr: wire.quorum_sets_xdr,
            next_scp_envelopes: wire.next_scp_envelopes,
            next_tx_set_xdr: wire.next_tx_set_xdr,
            state_root_proof: wire.state_root_proof.map(|p| stellar_raw::StateRootProof {
                result_pairs: p.result_pairs,
                result_index: p.result_index,
                success_preimage_xdr: p.success_preimage_xdr,
            }),
        })
    }

    fn check_misbehaviour(
        &mut self,
        update: &UpdateClient,
        client_state: &AnyClientState,
    ) -> Result<Option<MisbehaviourEvidence>, Error> {
        let Some(submitted_header) = submitted_stellar_update_header(update)? else {
            return Ok(None);
        };

        let target_height = submitted_header.height;
        let trusted_height = submitted_header.trusted_height;

        tracing::warn!(
            client = %update.client_id(),
            target_height = %target_height,
            "Stellar misbehaviour witness Gateway not configured; reusing the primary Gateway. \
             This only catches local inconsistencies — it is not an independent witness."
        );

        let witness_resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard
                    .query_ibc_header(QueryIbcHeaderRequest {
                        height: target_height.revision_height(),
                    })
                    .await
            })
            .map_err(|e| {
                Error::query(format!(
                    "failed to independently query Stellar header at {target_height}: {e}"
                ))
            })?;

        let wire = gateway_client::StellarHeader::decode(witness_resp.header.as_slice())
            .map_err(|e| Error::query(format!("witness StellarHeader decode failed: {e}")))?;

        let witness_raw = stellar_raw::StellarHeader {
            slot_index: wire.slot_index,
            ledger_header_xdr: wire.ledger_header_xdr,
            scp_envelopes: wire.scp_envelopes,
            quorum_sets_xdr: wire.quorum_sets_xdr,
            next_scp_envelopes: wire.next_scp_envelopes,
            next_tx_set_xdr: wire.next_tx_set_xdr,
            state_root_proof: wire.state_root_proof.map(|p| stellar_raw::StateRootProof {
                result_pairs: p.result_pairs,
                result_index: p.result_index,
                success_preimage_xdr: p.success_preimage_xdr,
            }),
        };
        let mut witness_header: StellarHeader = witness_raw
            .try_into()
            .map_err(|e| Error::query(format!("witness StellarHeader try_into failed: {e}")))?;
        // The wire format carries no trusted height — SCP verifies each header
        // independently — so restore the one this update claimed.
        witness_header.trusted_height = trusted_height;

        stellar_misbehaviour_evidence(update, submitted_header, witness_header, client_state)
    }

    fn query_balance(
        &self,
        _key_name: Option<&str>,
        denom: Option<&str>,
    ) -> Result<Balance, Error> {
        // todo: add gateway query balance

        Ok(Balance {
            amount: "0".to_string(),
            denom: denom.unwrap_or("XLM").to_string(),
        })
    }

    fn query_all_balances(&self, _key_name: Option<&str>) -> Result<Vec<Balance>, Error> {
        // todo: add gateway query balance

        Ok(Vec::new())
    }

    fn query_denom_trace(&self, _hash: String) -> Result<DenomTrace, Error> {
        tracing::warn!("query_denom_trace: not applicable for Stellar");
        Err(Error::config(ConfigError::wrong_type()))
    }

    fn query_commitment_prefix(&self) -> Result<CommitmentPrefix, Error> {
        CommitmentPrefix::try_from(b"ibc".to_vec())
            .map_err(|e| Error::query(format!("invalid commitment prefix for Stellar: {e}")))
    }

    fn query_application_status(&self) -> Result<ChainStatus, Error> {
        tracing::debug!("querying stellar application status via gateway");

        let latest = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard.latest_height().await
            })
            .map_err(|e| Error::query(format!("Stellar gateway latest_height failed: {e}")))?;

        let height = ICSHeight::new(latest.revision_number, latest.revision_height)
            .map_err(|e| Error::query(format!("invalid Stellar height from gateway: {e}")))?;

        tracing::debug!("stellar chain at height {}", height);

        let header_resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard
                    .query_ibc_header(super::gateway_client::QueryIbcHeaderRequest {
                        height: height.revision_height(),
                    })
                    .await
            })
            .map_err(|e| {
                Error::query(format!(
                    "Stellar gateway query_ibc_header failed at {height}: {e}"
                ))
            })?;

        let wire_header = gateway_client::StellarHeader::decode(header_resp.header.as_slice())
            .map_err(|e| Error::query(format!("StellarHeader decode failed: {e}")))?;

        let close_time_secs = ledger_close_time_secs(&wire_header.ledger_header_xdr)?;
        let timestamp = Timestamp::from_nanoseconds(close_time_secs.saturating_mul(1_000_000_000))
            .map_err(|e| Error::query(format!("invalid Stellar close_time: {e}")))?;

        tracing::debug!(
            "stellar chain at height {} and timestamp {}",
            height,
            timestamp
        );

        Ok(ChainStatus { height, timestamp })
    }

    fn query_clients(
        &self,
        _request: QueryClientStatesRequest,
    ) -> Result<Vec<IdentifiedAnyClientState>, Error> {
        tracing::debug!("querying all clients on the Stellar router");

        let resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard
                    .query_client_states(super::gateway_client::QueryClientStatesRequest {})
                    .await
            })
            .map_err(|e| {
                Error::query(format!("Stellar gateway query_client_states failed: {e}"))
            })?;

        let mut clients = Vec::new();
        for entry in resp.client_states {
            let client_id = match entry.client_id.parse::<ClientId>() {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!(client_id = %entry.client_id, %e, "skipping client: bad id");
                    continue;
                }
            };
            let any = match ibc_proto::google::protobuf::Any::decode(entry.client_state.as_slice())
            {
                Ok(any) => any,
                Err(e) => {
                    tracing::warn!(%client_id, %e, "skipping client: Any decode failed");
                    continue;
                }
            };
            match AnyClientState::try_from(any) {
                Ok(client_state) => clients.push(IdentifiedAnyClientState {
                    client_id,
                    client_state,
                }),
                Err(e) => {
                    tracing::warn!(%client_id, %e, "skipping client: AnyClientState decode failed")
                }
            }
        }

        Ok(clients)
    }

    fn query_client_state(
        &self,
        request: QueryClientStateRequest,
        _include_proof: IncludeProof,
    ) -> Result<(AnyClientState, Option<MerkleProof>), Error> {
        tracing::debug!(client_id = %request.client_id, "querying client state");

        let height = match request.height {
            QueryHeight::Latest => self.query_application_status()?.height.revision_height(),
            QueryHeight::Specific(h) => h.revision_height(),
        };

        let resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard
                    .query_client_state(super::gateway_client::QueryClientStateRequest {
                        client_id: request.client_id.to_string(),
                        height,
                    })
                    .await
            })
            .map_err(|e| Error::query(format!("Stellar gateway query_client_state failed: {e}")))?;
        let any = ibc_proto::google::protobuf::Any::decode(resp.client_state.as_slice())
            .map_err(|e| Error::query(format!("client_state Any decode failed: {e}")))?;
        let cs = AnyClientState::try_from(any)
            .map_err(|e| Error::query(format!("AnyClientState decode failed: {e}")))?;
        Ok((cs, None))
    }

    fn query_consensus_state(
        &self,
        request: QueryConsensusStateRequest,
        _include_proof: IncludeProof,
    ) -> Result<(AnyConsensusState, Option<MerkleProof>), Error> {
        let resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard
                    .query_consensus_state(super::gateway_client::QueryConsensusStateRequest {
                        client_id: request.client_id.to_string(),
                        revision_number: request.consensus_height.revision_number(),
                        revision_height: request.consensus_height.revision_height(),
                    })
                    .await
            })
            .map_err(|e| {
                Error::query(format!("Stellar gateway query_consensus_state failed: {e}"))
            })?;
        let any = ibc_proto::google::protobuf::Any::decode(resp.consensus_state.as_slice())
            .map_err(|e| Error::query(format!("consensus_state Any decode failed: {e}")))?;
        let cs = AnyConsensusState::try_from(any)
            .map_err(|e| Error::query(format!("AnyConsensusState decode failed: {e}")))?;
        Ok((cs, None))
    }

    fn query_consensus_state_heights(
        &self,
        _request: QueryConsensusStateHeightsRequest,
    ) -> Result<Vec<ICSHeight>, Error> {
        Ok(Vec::new())
    }

    fn query_upgraded_client_state(
        &self,
        _request: QueryUpgradedClientStateRequest,
    ) -> Result<(AnyClientState, MerkleProof), Error> {
        Err(Error::query(
            "Stellar does not support client upgrades via IBC".to_string(),
        ))
    }

    fn query_upgraded_consensus_state(
        &self,
        _request: QueryUpgradedConsensusStateRequest,
    ) -> Result<(AnyConsensusState, MerkleProof), Error> {
        Err(Error::query(
            "Stellar does not support client upgrades via IBC".to_string(),
        ))
    }

    fn query_connections(
        &self,
        _request: QueryConnectionsRequest,
    ) -> Result<Vec<IdentifiedConnectionEnd>, Error> {
        Ok(Vec::new())
    }

    fn query_client_connections(
        &self,
        _request: QueryClientConnectionsRequest,
    ) -> Result<Vec<ConnectionId>, Error> {
        Ok(Vec::new())
    }

    fn query_connection(
        &self,
        _request: QueryConnectionRequest,
        _include_proof: IncludeProof,
    ) -> Result<(ConnectionEnd, Option<MerkleProof>), Error> {
        Err(Error::query(
            "Connection queries are not part of IBC v2".to_string(),
        ))
    }

    fn query_connection_channels(
        &self,
        _request: QueryConnectionChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        Ok(Vec::new())
    }

    fn query_channels(
        &self,
        _request: QueryChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        Ok(Vec::new())
    }

    fn query_channel(
        &self,
        _request: QueryChannelRequest,
        _include_proof: IncludeProof,
    ) -> Result<(ChannelEnd, Option<MerkleProof>), Error> {
        Err(Error::query(
            "Channel queries are not part of IBC v2".to_string(),
        ))
    }

    fn query_channel_client_state(
        &self,
        _request: QueryChannelClientStateRequest,
    ) -> Result<Option<IdentifiedAnyClientState>, Error> {
        Ok(None)
    }

    fn query_packet_commitment(
        &self,
        request: QueryPacketCommitmentRequest,
        _include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        let height = match request.height {
            QueryHeight::Latest => self.query_application_status()?.height.revision_height(),
            QueryHeight::Specific(h) => h.revision_height(),
        };
        let resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard
                    .query_packet_commitment(super::gateway_client::QueryPacketCommitmentRequest {
                        client_id: request.channel_id.to_string(),
                        sequence: request.sequence.into(),
                        height,
                    })
                    .await
            })
            .map_err(|e| {
                Error::query(format!(
                    "Stellar gateway query_packet_commitment failed: {e}"
                ))
            })?;
        let proof = decode_merkle_proof(&resp.proof)?;
        Ok((resp.commitment, proof))
    }

    fn query_packet_commitments(
        &self,
        _request: QueryPacketCommitmentsRequest,
    ) -> Result<(Vec<Sequence>, ICSHeight), Error> {
        let h = self.query_application_status()?.height;
        Ok((Vec::new(), h))
    }

    fn query_packet_receipt(
        &self,
        request: QueryPacketReceiptRequest,
        _include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        let height = match request.height {
            QueryHeight::Latest => self.query_application_status()?.height.revision_height(),
            QueryHeight::Specific(h) => h.revision_height(),
        };
        let resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard
                    .query_packet_receipt(super::gateway_client::QueryPacketReceiptRequest {
                        client_id: request.channel_id.to_string(),
                        sequence: request.sequence.into(),
                        height,
                    })
                    .await
            })
            .map_err(|e| {
                Error::query(format!("Stellar gateway query_packet_receipt failed: {e}"))
            })?;
        let proof = decode_merkle_proof(&resp.proof)?;
        let value = if resp.received {
            vec![0x01]
        } else {
            Vec::new()
        };
        Ok((value, proof))
    }

    fn query_unreceived_packets(
        &self,
        _request: QueryUnreceivedPacketsRequest,
    ) -> Result<Vec<Sequence>, Error> {
        Ok(Vec::new())
    }

    fn query_packet_acknowledgement(
        &self,
        request: QueryPacketAcknowledgementRequest,
        _include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        let height = match request.height {
            QueryHeight::Latest => self.query_application_status()?.height.revision_height(),
            QueryHeight::Specific(h) => h.revision_height(),
        };
        let resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard
                    .query_acknowledgement(super::gateway_client::QueryAcknowledgementRequest {
                        client_id: request.channel_id.to_string(),
                        sequence: request.sequence.into(),
                        height,
                    })
                    .await
            })
            .map_err(|e| {
                Error::query(format!("Stellar gateway query_acknowledgement failed: {e}"))
            })?;
        let proof = decode_merkle_proof(&resp.proof)?;
        Ok((resp.acknowledgement, proof))
    }

    fn query_packet_acknowledgements(
        &self,
        _request: QueryPacketAcknowledgementsRequest,
    ) -> Result<(Vec<Sequence>, ICSHeight), Error> {
        let h = self.query_application_status()?.height;
        Ok((Vec::new(), h))
    }

    fn query_unreceived_acknowledgements(
        &self,
        _request: QueryUnreceivedAcksRequest,
    ) -> Result<Vec<Sequence>, Error> {
        Ok(Vec::new())
    }

    fn query_next_sequence_receive(
        &self,
        _request: QueryNextSequenceReceiveRequest,
        _include_proof: IncludeProof,
    ) -> Result<(Sequence, Option<MerkleProof>), Error> {
        Err(Error::query(
            "nextSequenceSend path was removed in IBC v2".to_string(),
        ))
    }

    fn query_txs(&self, _request: QueryTxRequest) -> Result<Vec<IbcEventWithHeight>, Error> {
        Ok(Vec::new())
    }

    fn query_packet_events(
        &self,
        _request: QueryPacketEventDataRequest,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        Ok(Vec::new())
    }

    fn query_host_consensus_state(
        &self,
        _request: QueryHostConsensusStateRequest,
    ) -> Result<Self::ConsensusState, Error> {
        let status = self.query_application_status()?;
        let target = ICSHeight::new(0, status.height.revision_height())
            .map_err(|e| Error::query(format!("invalid Stellar height: {e}")))?;
        let lb = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard
                    .query_ibc_header(QueryIbcHeaderRequest {
                        height: target.revision_height(),
                    })
                    .await
            })
            .map_err(|e| Error::query(format!("query_ibc_header failed: {e}")))?;
        let wire = gateway_client::StellarHeader::decode(lb.header.as_slice())
            .map_err(|e| Error::query(format!("StellarHeader decode failed: {e}")))?;
        let close_time = ledger_close_time_secs(&wire.ledger_header_xdr)?;
        let ledger_hash = ledger_previous_hash(&wire.ledger_header_xdr)?;
        Ok(AnyConsensusState::Stellar(StellarConsensusState {
            root: CommitmentRoot::from_bytes(&[]),
            timestamp: close_time,
            ledger_hash,
            wrap_as_wasm: self.is_wasm_wrapped(),
        }))
    }

    fn build_client_state(
        &self,
        height: ICSHeight,
        _settings: ClientSettings,
    ) -> Result<Self::ClientState, Error> {
        tracing::info!(%height, "[stellar] building client state");

        let params = self.stellar_client_params(height)?;
        let wasm_checksum = self.wasm_checksum_bytes()?;

        // Derived locally from our own configured passphrase, not taken from
        // the gateway. The network id decides which network's signatures the
        // light client will accept, so it belongs to the same class of input as
        // the quorum set: something the operator states, not something a
        // service supplies.
        let network_id = network_id_from_passphrase(&self.config.network_passphrase);
        if !params.network_id.is_empty() && params.network_id != network_id {
            return Err(Error::query(format!(
                "gateway reports network id {} but this relayer is configured for {} — \
                 the gateway is pointed at a different Stellar network",
                hex_encode(&params.network_id),
                hex_encode(&network_id),
            )));
        }

        let client_state = StellarClientState {
            chain_id: self.config.id.clone(),
            latest_height: height,
            frozen_height: None,
            quorum_configs: params
                .quorum_configs
                .into_iter()
                .map(|c| stellar_types::QuorumConfig {
                    quorum_set_xdr: c.quorum_set_xdr,
                    valid_from: c.valid_from,
                })
                .collect(),
            proof_specs: Vec::new(),
            network_id,
            max_consensus_age: self.trusting_period_secs(),
            router_contract_id: params.router_contract_id,
            root_event_topic: params.root_event_topic,
            wasm_checksum,
        };

        // The one input that cannot be delegated. Everything downstream — every
        // signature check, every packet proof — is only as good as this set, and
        // it arrived over untrusted transport.
        let pinned = self.pinned_quorum_fingerprints()?;
        client_state
            .verify_quorum_fingerprints(&pinned)
            .map_err(|e| {
                Error::query(format!(
                    "refusing to create a Stellar client: {e}. The quorum set came from the \
                     gateway, which is untrusted transport; add its fingerprint to \
                     `pinned_quorum_set_hashes` only after verifying it independently \
                     (for example with `interstellar verify --ledger <n>`)."
                ))
            })?;

        tracing::info!(
            %height,
            quorum_configs = client_state.quorum_configs.len(),
            wasm_wrapped = self.is_wasm_wrapped(),
            "[stellar] client state built — quorum sets checked against pinned fingerprints",
        );

        Ok(AnyClientState::Stellar(client_state))
    }

    fn build_consensus_state(
        &self,
        light_block: Self::LightBlock,
    ) -> Result<Self::ConsensusState, Error> {
        tracing::debug!(
            timestamp = light_block.close_time_secs,
            wasm_wrapped = self.is_wasm_wrapped(),
            "built stellar consensus state",
        );

        // No root. The light client derives it from the state-root proof it
        // verifies; anything hermes put here would be an unverified assertion,
        // which is exactly the design that was removed. Proofs at the creation
        // height therefore fail until the first update binds a real root.
        Ok(AnyConsensusState::Stellar(StellarConsensusState {
            root: CommitmentRoot::from_bytes(&[]),
            timestamp: light_block.close_time_secs,
            ledger_hash: light_block.ledger_hash,
            wrap_as_wasm: self.is_wasm_wrapped(),
        }))
    }

    fn build_header(
        &mut self,
        trusted_height: ICSHeight,
        target_height: ICSHeight,
        _client_state: &AnyClientState,
    ) -> Result<(Self::Header, Vec<Self::Header>), Error> {
        let resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard
                    .query_ibc_header(QueryIbcHeaderRequest {
                        height: target_height.revision_height(),
                    })
                    .await
            })
            .map_err(|e| {
                Error::query(format!(
                    "Stellar gateway query_ibc_header failed at {target_height}: {e}"
                ))
            })?;

        let wire = gateway_client::StellarHeader::decode(resp.header.as_slice())
            .map_err(|e| Error::query(format!("StellarHeader decode failed: {e}")))?;

        let raw = stellar_raw::StellarHeader {
            slot_index: wire.slot_index,
            ledger_header_xdr: wire.ledger_header_xdr,
            scp_envelopes: wire.scp_envelopes,
            quorum_sets_xdr: wire.quorum_sets_xdr,
            next_scp_envelopes: wire.next_scp_envelopes,
            next_tx_set_xdr: wire.next_tx_set_xdr,
            state_root_proof: wire.state_root_proof.map(|p| stellar_raw::StateRootProof {
                result_pairs: p.result_pairs,
                result_index: p.result_index,
                success_preimage_xdr: p.success_preimage_xdr,
            }),
        };

        let mut header: StellarHeader = raw
            .try_into()
            .map_err(|e| Error::query(format!("StellarHeader try_into failed: {e}")))?;
        // Not on the wire — SCP verifies each header independently — so hermes
        // records the height this update is relative to for its own bookkeeping.
        header.trusted_height = trusted_height;

        header.wrap_as_wasm = self.is_wasm_wrapped();

        Ok((AnyHeader::Stellar(header), vec![]))
    }

    fn maybe_register_counterparty_payee(
        &mut self,
        _channel_id: &ChannelId,
        _port_id: &PortId,
        _counterparty_payee: &Signer,
    ) -> Result<(), Error> {
        tracing::warn!("maybe_register_counterparty_payee: ICS-29 fee middleware is not implemented for Stellar");
        Ok(())
    }

    fn cross_chain_query(
        &self,
        _requests: Vec<CrossChainQueryRequest>,
    ) -> Result<Vec<CrossChainQueryResponse>, Error> {
        Err(Error::query(
            "ICS-31 cross-chain queries are not supported for Stellar".to_string(),
        ))
    }

    fn query_incentivized_packet(
        &self,
        _request: QueryIncentivizedPacketRequest,
    ) -> Result<QueryIncentivizedPacketResponse, Error> {
        Err(Error::query(
            "ICS-29 fee middleware is not supported for Stellar".to_string(),
        ))
    }

    fn query_consumer_chains(&self) -> Result<Vec<ConsumerChain>, Error> {
        Err(Error::query(
            "ICS-28 CCV (Cross-Chain Validation) is not applicable to Stellar".to_string(),
        ))
    }

    fn query_upgrade(
        &self,
        _request: QueryUpgradeRequest,
        _height: Height,
        _include_proof: IncludeProof,
    ) -> Result<(Upgrade, Option<MerkleProof>), Error> {
        Err(Error::query(
            "Stellar channel upgrade query is not implemented".to_string(),
        ))
    }

    fn query_upgrade_error(
        &self,
        _request: QueryUpgradeErrorRequest,
        _height: Height,
        _include_proof: IncludeProof,
    ) -> Result<(ErrorReceipt, Option<MerkleProof>), Error> {
        Err(Error::query(
            "Stellar channel upgrade error query is not implemented".to_string(),
        ))
    }

    fn query_ccv_consumer_id(&self, _client_id: ClientId) -> Result<ConsumerId, Error> {
        Err(Error::query(
            "ICS-28 CCV (Cross-Chain Validation) is not applicable to Stellar".to_string(),
        ))
    }
}

impl StellarChainEndpoint {
    fn is_wasm_wrapped(&self) -> bool {
        self.config
            .wasm_checksum_hex
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    }

    fn wasm_checksum_bytes(&self) -> Result<Option<Vec<u8>>, Error> {
        let Some(hex) = self
            .config
            .wasm_checksum_hex
            .as_deref()
            .filter(|s| !s.is_empty())
        else {
            return Ok(None);
        };
        let bytes = hex_decode(hex).map_err(|e| {
            Error::query(format!("invalid wasm_checksum_hex on Stellar config: {e}"))
        })?;
        Ok(Some(bytes))
    }

    /// Client-state parameters from the gateway: quorum configs, network id,
    /// and the router whose root event binds Soroban state.
    ///
    /// This replaces a sampler that walked back over recent headers collecting
    /// signer keys into a flat validator list. That was never a trust root —
    /// SCP quorum sets are recursive, and a flat m-of-n check errs in *both*
    /// directions — and it took whatever the gateway happened to serve. The
    /// caller now pins what comes back.
    fn stellar_client_params(
        &self,
        height: ICSHeight,
    ) -> Result<gateway_client::QueryStellarClientParamsResponse, Error> {
        self.rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard
                    .query_stellar_client_params(gateway_client::QueryStellarClientParamsRequest {
                        height: height.revision_height(),
                    })
                    .await
            })
            .map_err(|e| {
                Error::query(format!(
                    "Stellar gateway query_stellar_client_params failed at {height}: {e}"
                ))
            })
    }

    /// How long a consensus state stays trustworthy, in seconds.
    ///
    /// Defaults to two weeks, matching the trusting period a Tendermint client
    /// would use. An earlier version derived this from `max_block_time`, which
    /// gave twelve seconds and expired every client almost immediately — block
    /// cadence and trust decay are unrelated quantities.
    fn trusting_period_secs(&self) -> u64 {
        const DEFAULT: Duration = Duration::from_secs(14 * 24 * 60 * 60);
        self.config.trusting_period.unwrap_or(DEFAULT).as_secs()
    }

    /// The quorum-set fingerprints this relayer was configured to accept.
    ///
    /// Config only, deliberately: the trust root is an operator decision, and a
    /// value compiled into the binary would be one more thing to keep current
    /// across releases. An empty list is refused by the caller rather than
    /// treated as "accept anything".
    fn pinned_quorum_fingerprints(&self) -> Result<Vec<[u8; 32]>, Error> {
        self.config
            .pinned_quorum_set_hashes
            .iter()
            .map(|hex| {
                let bytes = hex_decode(hex).map_err(|e| {
                    Error::query(format!(
                        "pinned_quorum_set_hashes entry {hex:?} is not valid hex: {e}"
                    ))
                })?;
                <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                    Error::query(format!(
                        "pinned_quorum_set_hashes entry {hex:?} is not 32 bytes"
                    ))
                })
            })
            .collect()
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {}", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = char_to_nibble(bytes[i]).ok_or_else(|| format!("invalid hex char at {i}"))?;
        let lo =
            char_to_nibble(bytes[i + 1]).ok_or_else(|| format!("invalid hex char at {}", i + 1))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn char_to_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn network_id_from_passphrase(passphrase: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(passphrase.as_bytes()).to_vec()
}

fn ledger_close_time_secs(ledger_header_xdr: &[u8]) -> Result<u64, Error> {
    use stellar_xdr::curr::{LedgerHeader, Limits, ReadXdr};

    let header = LedgerHeader::from_xdr(ledger_header_xdr, Limits::none())
        .map_err(|e| Error::query(format!("LedgerHeader XDR decode failed: {e}")))?;
    Ok(header.scp_value.close_time.0)
}

fn submitted_stellar_update_header(update: &UpdateClient) -> Result<Option<&StellarHeader>, Error> {
    let Some(any_header) = update.header.as_ref() else {
        tracing::warn!(
            "skipping Stellar misbehaviour check for client {} at consensus height {}: \
             update-client event does not include the submitted header",
            update.client_id(),
            update.consensus_height(),
        );
        return Ok(None);
    };

    match any_header {
        AnyHeader::Stellar(header) => {
            let target_height = header.height;
            if target_height != update.consensus_height() {
                return Err(Error::query(format!(
                    "update event consensus height {} does not match submitted Stellar header height {} for client {}",
                    update.consensus_height(),
                    target_height,
                    update.client_id()
                )));
            }
            Ok(Some(header))
        }
        other => Err(Error::query(format!(
            "Stellar misbehaviour check received a non-Stellar update header: {:?}",
            other.client_type()
        ))),
    }
}

fn stellar_headers_conflict(submitted: &StellarHeader, witness: &StellarHeader) -> bool {
    // The ledger header is the whole of what SCP binds, so any disagreement on
    // it is a fork. The state-root proof is derived from it and is not compared
    // separately: two headers that agree on the ledger cannot disagree on a
    // root the light client would accept.
    submitted.ledger_header_xdr != witness.ledger_header_xdr
}

fn stellar_misbehaviour_evidence(
    update: &UpdateClient,
    submitted_header: &StellarHeader,
    witness_header: StellarHeader,
    _client_state: &AnyClientState,
) -> Result<Option<MisbehaviourEvidence>, Error> {
    let target_height = submitted_header.height;
    if witness_header.height != target_height {
        return Err(Error::query(format!(
            "independent Stellar header height mismatch: expected {target_height}, got {}",
            witness_header.height
        )));
    }

    if !stellar_headers_conflict(submitted_header, &witness_header) {
        return Ok(None);
    }

    let misbehaviour = AnyMisbehaviour::Stellar(StellarMisbehaviour {
        client_id: update.client_id().clone(),
        header1: submitted_header.clone(),
        header2: witness_header,
    });
    Ok(Some(MisbehaviourEvidence {
        misbehaviour,
        supporting_headers: vec![],
    }))
}

fn sign_stellar_tx(
    tx_xdr: &[u8],
    signing_key: &StellarSigningKeyPair,
    network_passphrase: &str,
) -> Result<Vec<u8>, Error> {
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::{
        BytesM, DecoratedSignature, Hash, Limits, ReadXdr, Signature, SignatureHint,
        TransactionEnvelope, TransactionSignaturePayload,
        TransactionSignaturePayloadTaggedTransaction, WriteXdr,
    };

    let mut envelope = TransactionEnvelope::from_xdr(tx_xdr, Limits::none())
        .map_err(|e| Error::send_tx(format!("decode unsigned tx envelope: {e}")))?;

    let tx = match &envelope {
        TransactionEnvelope::Tx(env) => env.tx.clone(),
        _ => {
            return Err(Error::send_tx(
                "expected a v1 (Tx) transaction envelope from the gateway".to_string(),
            ))
        }
    };

    let network_id: [u8; 32] = Sha256::digest(network_passphrase.as_bytes()).into();
    let payload = TransactionSignaturePayload {
        network_id: Hash(network_id),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx),
    };
    let payload_xdr = payload
        .to_xdr(Limits::none())
        .map_err(|e| Error::send_tx(format!("encode signature payload: {e}")))?;
    let tx_hash: [u8; 32] = Sha256::digest(payload_xdr).into();

    let signature = signing_key
        .sign(&tx_hash)
        .map_err(|e| Error::send_tx(format!("sign tx hash with relayer key: {e}")))?;
    let signature: BytesM<64> = signature
        .try_into()
        .map_err(|_| Error::send_tx("relayer signature is not 64 bytes".to_string()))?;
    let decorated = DecoratedSignature {
        hint: SignatureHint(signing_key.key_hint()),
        signature: Signature(signature),
    };

    if let TransactionEnvelope::Tx(env) = &mut envelope {
        let mut signatures = env.signatures.to_vec();
        signatures.push(decorated);
        env.signatures = signatures
            .try_into()
            .map_err(|_| Error::send_tx("too many signatures on tx envelope".to_string()))?;
    }

    envelope
        .to_xdr(Limits::none())
        .map_err(|e| Error::send_tx(format!("encode signed tx envelope: {e}")))
}

fn scval_string_from_xdr(bytes: &[u8]) -> Option<String> {
    use stellar_xdr::curr::{Limits, ReadXdr, ScVal};
    match ScVal::from_xdr(bytes, Limits::none()).ok()? {
        ScVal::String(s) => core::str::from_utf8(s.0.as_slice())
            .ok()
            .map(|s| s.to_string()),
        ScVal::Symbol(s) => core::str::from_utf8(s.0.as_slice())
            .ok()
            .map(|s| s.to_string()),
        _ => None,
    }
}

fn packet_to_soroban_xdr(
    packet: &ibc_relayer_types::clients::ics10_stellar::v2_msgs::Packet,
) -> Result<Vec<u8>, Error> {
    use stellar_xdr::curr::{
        Limits, ScBytes, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec, StringM, VecM,
        WriteXdr,
    };

    fn sym(s: &str) -> Result<ScVal, Error> {
        let m = StringM::<32>::try_from(s.as_bytes())
            .map_err(|e| Error::send_tx(format!("invalid struct field symbol {s}: {e}")))?;
        Ok(ScVal::Symbol(ScSymbol(m)))
    }
    fn string(s: &str) -> Result<ScVal, Error> {
        let m = StringM::<{ u32::MAX }>::try_from(s.as_bytes())
            .map_err(|e| Error::send_tx(format!("invalid string for ScVal: {e}")))?;
        Ok(ScVal::String(ScString(m)))
    }
    fn bytes(b: &[u8]) -> Result<ScVal, Error> {
        let bm = b
            .to_vec()
            .try_into()
            .map_err(|e| Error::send_tx(format!("invalid bytes for ScVal: {e}")))?;
        Ok(ScVal::Bytes(ScBytes(bm)))
    }
    fn sc_struct(fields: Vec<(&str, ScVal)>) -> Result<ScVal, Error> {
        let mut entries = Vec::with_capacity(fields.len());
        for (key, val) in fields {
            entries.push(ScMapEntry {
                key: sym(key)?,
                val,
            });
        }
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        let vm = VecM::<ScMapEntry>::try_from(entries)
            .map_err(|e| Error::send_tx(format!("struct map too large: {e}")))?;
        Ok(ScVal::Map(Some(ScMap(vm))))
    }

    let mut payloads = Vec::with_capacity(packet.payloads.len());
    for pl in &packet.payloads {
        payloads.push(sc_struct(vec![
            ("source_port", string(&pl.source_port)?),
            ("dest_port", string(&pl.dest_port)?),
            ("version", string(&pl.version)?),
            ("encoding", string(&pl.encoding)?),
            ("value", bytes(&pl.value)?),
        ])?);
    }
    let payloads_vm = VecM::<ScVal>::try_from(payloads)
        .map_err(|e| Error::send_tx(format!("payloads vec too large: {e}")))?;
    let payloads_scval = ScVal::Vec(Some(ScVec(payloads_vm)));

    let packet_scval = sc_struct(vec![
        ("sequence", ScVal::U64(packet.sequence)),
        ("source_client", string(&packet.source_client)?),
        ("dest_client", string(&packet.dest_client)?),
        ("timeout_timestamp", ScVal::U64(packet.timeout_timestamp)),
        ("payloads", payloads_scval),
    ])?;

    packet_scval
        .to_xdr(Limits::none())
        .map_err(|e| Error::send_tx(format!("packet to soroban xdr: {e}")))
}

async fn dispatch_msg(
    msg_client: &StdMutex<GatewayMsgClient>,
    type_url: &str,
    value: Vec<u8>,
    signer: &str,
    signing_key: &StellarSigningKeyPair,
    network_passphrase: &str,
) -> Result<Vec<IbcEventWithHeight>, Error> {
    use ibc_proto::ibc::core::client::v1 as cosmos_client;
    use ibc_relayer_types::clients::ics10_stellar::v2_msgs;

    let mut events: Vec<IbcEventWithHeight> = Vec::new();

    match type_url {
        "/ibc.core.client.v1.MsgCreateClient" => {
            use ibc_proto::ibc::lightclients::tendermint::v1::ClientState as RawTmClientState;
            use ibc_relayer_types::clients::ics07_tendermint::client_state::TENDERMINT_CLIENT_STATE_TYPE_URL;
            use ibc_relayer_types::clients::ics10_stellar::client_state::WASM_CLIENT_STATE_TYPE_URL;

            let m = cosmos_client::MsgCreateClient::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgCreateClient decode: {e}")))?;
            let client_state_any = m.client_state.ok_or_else(|| {
                Error::send_tx("MsgCreateClient missing client_state".to_string())
            })?;
            let consensus_state = m.consensus_state.map(|a| a.value).unwrap_or_default();

            let client_type = match client_state_any.type_url.as_str() {
                TENDERMINT_CLIENT_STATE_TYPE_URL => "07-tendermint".to_string(),
                WASM_CLIENT_STATE_TYPE_URL => "08-wasm".to_string(),
                other => {
                    return Err(Error::send_tx(format!(
                        "unsupported client_state type_url for Stellar create_client: {other}"
                    )))
                }
            };

            tracing::debug!(
                client_type = %client_type,
                type_url = %client_state_any.type_url.as_str(),
                "decoding MsgCreateClient"
            );

            let height = match client_state_any.type_url.as_str() {
                TENDERMINT_CLIENT_STATE_TYPE_URL => {
                    RawTmClientState::decode(client_state_any.value.as_slice())
                        .map_err(|e| Error::send_tx(format!("tendermint ClientState decode: {e}")))?
                        .latest_height
                        .map(|h| h.revision_height)
                        .unwrap_or_default()
                }
                _ => 0,
            };

            tracing::info!(
                client_type = %client_type,
                height = %height,
                "[stellar] create_client"
            );

            let source = if m.signer.is_empty() {
                signer.to_string()
            } else {
                m.signer
            };

            let prepared = {
                let mut guard = msg_client.lock().unwrap();
                guard
                    .create_client(super::gateway_client::MsgCreateClientRequest {
                        client_state: client_state_any.value,
                        consensus_state,
                        signer: source,
                        client_type,
                        height,
                    })
                    .await
                    .map_err(|e| {
                        Error::send_tx(format!("gateway create_client (prepare) failed: {e}"))
                    })?
            };
            let signed = sign_stellar_tx(&prepared.tx_xdr, signing_key, network_passphrase)?;
            let submitted = {
                let mut guard = msg_client.lock().unwrap();
                guard
                    .submit_signed_tx(super::gateway_client::SubmitSignedTxRequest {
                        tx_xdr: signed,
                    })
                    .await
                    .map_err(|e| Error::send_tx(format!("gateway submit_signed_tx failed: {e}")))?
            };
            tracing::info!(
                tx_hash = %submitted.tx_hash,
                "[stellar] create_client tx submitted"
            );

            use ibc_relayer_types::core::ics02_client::client_type::ClientType;
            use ibc_relayer_types::core::ics02_client::events::{
                Attributes as ClientAttributes, CreateClient,
            };

            let client_id_str =
                scval_string_from_xdr(&submitted.return_value).ok_or_else(|| {
                    Error::send_tx(
                        "create_client tx returned no client id in its return value".to_string(),
                    )
                })?;
            let client_id = ClientId::from_str(&client_id_str)
                .map_err(|e| Error::send_tx(format!("invalid client id {client_id_str}: {e}")))?;
            let consensus_height = ICSHeight::new(0, height)
                .map_err(|e| Error::send_tx(format!("invalid consensus height {height}: {e}")))?;

            tracing::info!(%client_id, %consensus_height, "[stellar] client created");

            events.push(IbcEventWithHeight::new(
                IbcEvent::CreateClient(CreateClient(ClientAttributes {
                    client_id,
                    client_type: ClientType::Tendermint,
                    consensus_height,
                })),
                consensus_height,
            ));
        }
        "/ibc.core.client.v1.MsgUpdateClient" => {
            let m = cosmos_client::MsgUpdateClient::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgUpdateClient decode: {e}")))?;
            let header_bytes = m.client_message.map(|a| a.value).unwrap_or_default();
            let prepared = {
                let mut guard = msg_client.lock().unwrap();
                guard
                    .update_client(super::gateway_client::MsgUpdateClientRequest {
                        client_id: m.client_id,
                        header: header_bytes,
                        signer: if m.signer.is_empty() {
                            signer.to_string()
                        } else {
                            m.signer
                        },
                    })
                    .await
                    .map_err(|e| {
                        Error::send_tx(format!("gateway update_client (prepare) failed: {e}"))
                    })?
            };
            sign_and_submit(
                msg_client,
                &prepared.tx_xdr,
                signing_key,
                network_passphrase,
                "update_client",
            )
            .await?;
        }
        url if url == v2_msgs::TYPE_URL_REGISTER_COUNTERPARTY => {
            let m = v2_msgs::MsgRegisterCounterparty::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgRegisterCounterparty decode: {e}")))?;
            let prepared = {
                let mut guard = msg_client.lock().unwrap();
                guard
                    .register_counterparty(super::gateway_client::MsgRegisterCounterpartyRequest {
                        client_id: m.client_id,
                        counterparty_client_id: m.counterparty_client_id,
                        counterparty_commitment_prefix: m.counterparty_commitment_prefix,
                        signer: if m.signer.is_empty() {
                            signer.to_string()
                        } else {
                            m.signer
                        },
                    })
                    .await
                    .map_err(|e| {
                        Error::send_tx(format!(
                            "gateway register_counterparty (prepare) failed: {e}"
                        ))
                    })?
            };
            sign_and_submit(
                msg_client,
                &prepared.tx_xdr,
                signing_key,
                network_passphrase,
                "register_counterparty",
            )
            .await?;
        }
        url if url == v2_msgs::TYPE_URL_RECV_PACKET => {
            let m = v2_msgs::MsgRecvPacket::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgRecvPacket decode: {e}")))?;
            let packet_bytes = match m.packet.as_ref() {
                Some(p) => packet_to_soroban_xdr(p)?,
                None => Vec::new(),
            };
            let proof_height = m.proof_height.map(|h| h.revision_height).unwrap_or(0);
            let prepared = {
                let mut guard = msg_client.lock().unwrap();
                guard
                    .recv_packet(super::gateway_client::MsgRecvPacketRequest {
                        packet: packet_bytes,
                        proof: m.proof_commitment,
                        proof_height,
                        signer: if m.signer.is_empty() {
                            signer.to_string()
                        } else {
                            m.signer
                        },
                    })
                    .await
                    .map_err(|e| {
                        Error::send_tx(format!("gateway recv_packet (prepare) failed: {e}"))
                    })?
            };
            sign_and_submit(
                msg_client,
                &prepared.tx_xdr,
                signing_key,
                network_passphrase,
                "recv_packet",
            )
            .await?;
        }
        url if url == v2_msgs::TYPE_URL_ACKNOWLEDGEMENT => {
            let m = v2_msgs::MsgAcknowledgement::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgAcknowledgement decode: {e}")))?;
            let packet_bytes = match m.packet.as_ref() {
                Some(p) => packet_to_soroban_xdr(p)?,
                None => Vec::new(),
            };
            let ack_bytes = m.acknowledgements.into_iter().next().unwrap_or_default();
            let proof_height = m.proof_height.map(|h| h.revision_height).unwrap_or(0);
            let prepared = {
                let mut guard = msg_client.lock().unwrap();
                guard
                    .ack_packet(super::gateway_client::MsgAckPacketRequest {
                        packet: packet_bytes,
                        acknowledgement: ack_bytes,
                        proof: m.proof_acked,
                        proof_height,
                        signer: if m.signer.is_empty() {
                            signer.to_string()
                        } else {
                            m.signer
                        },
                    })
                    .await
                    .map_err(|e| {
                        Error::send_tx(format!("gateway ack_packet (prepare) failed: {e}"))
                    })?
            };
            sign_and_submit(
                msg_client,
                &prepared.tx_xdr,
                signing_key,
                network_passphrase,
                "ack_packet",
            )
            .await?;
        }
        url if url == v2_msgs::TYPE_URL_TIMEOUT => {
            let m = v2_msgs::MsgTimeout::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgTimeout decode: {e}")))?;
            let packet_bytes = match m.packet.as_ref() {
                Some(p) => packet_to_soroban_xdr(p)?,
                None => Vec::new(),
            };
            let proof_height = m.proof_height.map(|h| h.revision_height).unwrap_or(0);
            let prepared = {
                let mut guard = msg_client.lock().unwrap();
                guard
                    .timeout_packet(super::gateway_client::MsgTimeoutPacketRequest {
                        packet: packet_bytes,
                        proof: m.proof_unreceived,
                        proof_height,
                        signer: if m.signer.is_empty() {
                            signer.to_string()
                        } else {
                            m.signer
                        },
                    })
                    .await
                    .map_err(|e| {
                        Error::send_tx(format!("gateway timeout_packet (prepare) failed: {e}"))
                    })?
            };
            sign_and_submit(
                msg_client,
                &prepared.tx_xdr,
                signing_key,
                network_passphrase,
                "timeout_packet",
            )
            .await?;
        }
        url if url == v2_msgs::TYPE_URL_SUBMIT_MISBEHAVIOUR => {
            let m = v2_msgs::MsgSubmitMisbehaviour::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgSubmitMisbehaviour decode: {e}")))?;
            let client_message = m.misbehaviour.map(|a| a.value).unwrap_or_default();
            let prepared = {
                let mut guard = msg_client.lock().unwrap();
                guard
                    .submit_misbehaviour(super::gateway_client::MsgSubmitMisbehaviourRequest {
                        client_id: m.client_id,
                        client_message,
                        signer: if m.signer.is_empty() {
                            signer.to_string()
                        } else {
                            m.signer
                        },
                    })
                    .await
                    .map_err(|e| {
                        Error::send_tx(format!("gateway submit_misbehaviour (prepare) failed: {e}"))
                    })?
            };
            sign_and_submit(
                msg_client,
                &prepared.tx_xdr,
                signing_key,
                network_passphrase,
                "submit_misbehaviour",
            )
            .await?;
        }
        other => {
            return Err(Error::send_tx(format!(
                "Stellar endpoint does not yet encode message type {other}",
            )));
        }
    }

    Ok(events)
}

async fn sign_and_submit(
    msg_client: &StdMutex<GatewayMsgClient>,
    tx_xdr: &[u8],
    signing_key: &StellarSigningKeyPair,
    network_passphrase: &str,
    label: &str,
) -> Result<super::gateway_client::SubmitSignedTxResponse, Error> {
    let signed = sign_stellar_tx(tx_xdr, signing_key, network_passphrase)?;
    let submitted = {
        let mut guard = msg_client.lock().unwrap();
        guard
            .submit_signed_tx(super::gateway_client::SubmitSignedTxRequest { tx_xdr: signed })
            .await
            .map_err(|e| Error::send_tx(format!("gateway submit_signed_tx failed: {e}")))?
    };
    tracing::info!(
        tx_hash = %submitted.tx_hash,
        message = %label,
        "[stellar] tx submitted"
    );
    Ok(submitted)
}

fn decode_merkle_proof(bytes: &[u8]) -> Result<Option<MerkleProof>, Error> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let raw = ibc_proto::ibc::core::commitment::v1::MerkleProof::decode(bytes)
        .map_err(|e| Error::query(format!("MerkleProof decode failed: {e}")))?;
    Ok(Some(MerkleProof::from(raw)))
}

fn ledger_previous_hash(ledger_header_xdr: &[u8]) -> Result<Vec<u8>, Error> {
    use stellar_xdr::curr::{LedgerHeader, Limits, ReadXdr};

    let header = LedgerHeader::from_xdr(ledger_header_xdr, Limits::none())
        .map_err(|e| Error::query(format!("LedgerHeader XDR decode failed: {e}")))?;
    Ok(header.previous_ledger_hash.0.to_vec())
}

const POLL_RECONNECT_THRESHOLD: u32 = 5;
const POLL_MAX_BACKOFF: Duration = Duration::from_secs(60);

fn poll_backoff(base: Duration, consecutive_errors: u32) -> Duration {
    if consecutive_errors == 0 {
        return base;
    }
    let factor = 1u64
        .checked_shl(consecutive_errors)
        .unwrap_or(u64::MAX / base.as_millis().max(1) as u64);
    let ms = (base.as_millis() as u64).saturating_mul(factor);
    let candidate = Duration::from_millis(ms);
    if candidate > POLL_MAX_BACKOFF {
        POLL_MAX_BACKOFF
    } else {
        candidate
    }
}

fn attr_line<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
}

fn module_attr(key: &str, value: &str) -> ModuleEventAttribute {
    ModuleEventAttribute {
        key: key.to_string(),
        value: value.to_string(),
    }
}

async fn run_event_polling(
    chain_id: ChainId,
    gateway_url: String,
    sender: crossbeam_channel::Sender<Arc<crate::event::source::Result<EventBatch>>>,
    poll_interval: Duration,
) {
    tracing::info!("[stellar] event polling started");

    let mut client = match GatewayQueryClient::connect(gateway_url.clone()).await {
        Ok(c) => c,
        Err(e) => {
            let _ = sender.send(Arc::new(Err(SourceError::collect_events_failed(format!(
                "Stellar event polling: gateway connect failed: {e}"
            )))));
            return;
        }
    };

    let mut start_ledger: u32 = match client.latest_height().await {
        Ok(h) => h.revision_height as u32,
        Err(e) => {
            tracing::warn!(
                target: "stellar_events",
                "[stellar] latest_height failed at startup: {e}; defaulting start_ledger to 1"
            );
            1
        }
    };

    let mut cursor = String::new();
    let mut consecutive_errors: u32 = 0;

    loop {
        tokio::time::sleep(poll_backoff(poll_interval, consecutive_errors)).await;

        let req = EventsRequest {
            start_ledger: if cursor.is_empty() { start_ledger } else { 0 },
            cursor: cursor.clone(),
            limit: 200,
        };

        crate::telemetry!(stellar_polling_attempt, &chain_id);

        let resp = match client.events(req).await {
            Ok(r) => {
                if consecutive_errors > 0 {
                    tracing::info!(
                        target: "stellar_events",
                        "[stellar] gateway recovered after {consecutive_errors} consecutive errors"
                    );
                }
                consecutive_errors = 0;
                r
            }
            Err(e) => {
                consecutive_errors = consecutive_errors.saturating_add(1);
                crate::telemetry!(stellar_polling_failure, &chain_id);
                tracing::debug!(
                    target: "stellar_events",
                    "{chain_id}: gateway events poll failed (start_ledger={start_ledger}, cursor='{cursor}', consecutive={consecutive_errors}): {e}"
                );
                if consecutive_errors >= POLL_RECONNECT_THRESHOLD {
                    crate::telemetry!(stellar_polling_reconnect, &chain_id);
                    tracing::warn!(
                        target: "stellar_events",
                        "[stellar] gateway unreachable after {consecutive_errors} failures — reconnecting to {gateway_url}"
                    );
                    match GatewayQueryClient::connect(gateway_url.clone()).await {
                        Ok(c) => {
                            client = c;
                            tracing::info!(
                                target: "stellar_events",
                                "[stellar] gateway client reconnected"
                            );
                        }
                        Err(reconnect_err) => {
                            tracing::warn!(
                                target: "stellar_events",
                                "[stellar] gateway reconnect failed: {reconnect_err}"
                            );
                        }
                    }
                }
                continue;
            }
        };

        if !resp.cursor.is_empty() {
            cursor = resp.cursor;
        }
        if resp.latest_ledger as u32 > start_ledger {
            start_ledger = resp.latest_ledger as u32;
        }

        let mut ibc_events: Vec<IbcEventWithHeight> = Vec::new();
        for event in &resp.events {
            let Some(kind) = attr_line(&event.attributes, "type") else {
                continue;
            };
            if !matches!(
                kind,
                "send_packet" | "recv_packet" | "write_ack" | "ack_packet" | "timeout_packet"
            ) {
                continue;
            }

            let height = match ICSHeight::new(0, event.ledger) {
                Ok(h) => h,
                Err(e) => {
                    tracing::debug!(
                        target: "stellar_events",
                        "{chain_id}: bad event height {}: {e}", event.ledger
                    );
                    continue;
                }
            };

            let client_id = attr_line(&event.attributes, "packet_src_channel").unwrap_or("");
            let sequence = attr_line(&event.attributes, "packet_sequence").unwrap_or("0");

            let module_event = ModuleEvent {
                kind: kind.to_string(),
                module_name: ModuleId::new("stellaribcrouter".into())
                    .expect("static module id is valid"),
                attributes: vec![
                    module_attr("client_id", client_id),
                    module_attr("sequence", sequence),
                    module_attr("value_xdr_hex", &hex::encode(&event.value_xdr)),
                    module_attr("tx_hash", &event.tx_hash),
                    module_attr("event_id", &event.id),
                    module_attr("contract_id", &event.contract_id),
                ],
            };

            let arrow = if kind == "send_packet" {
                "stellar→cosmos"
            } else {
                "stellar"
            };
            tracing::info!(
                target: "stellar_events",
                "[{arrow}] {kind} seq={sequence} observed at ledger {} (client={client_id})",
                height.revision_height()
            );
            ibc_events.push(IbcEventWithHeight::new(
                IbcEvent::AppModule(module_event),
                height,
            ));
        }

        if !ibc_events.is_empty() {
            let height = ibc_events
                .iter()
                .map(|e| e.height)
                .max()
                .unwrap_or_else(|| ICSHeight::new(0, start_ledger.max(1) as u64).unwrap());
            let batch = EventBatch {
                chain_id: chain_id.clone(),
                tracking_id: TrackingId::new_uuid(),
                height,
                events: ibc_events,
            };
            let _ = sender.send(Arc::new(Ok(batch)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_backoff_zero_errors_returns_base() {
        let base = Duration::from_secs(2);
        assert_eq!(poll_backoff(base, 0), base);
    }

    #[test]
    fn poll_backoff_doubles_per_consecutive_error() {
        let base = Duration::from_secs(2);
        assert_eq!(poll_backoff(base, 1), Duration::from_secs(4));
        assert_eq!(poll_backoff(base, 2), Duration::from_secs(8));
        assert_eq!(poll_backoff(base, 3), Duration::from_secs(16));
        assert_eq!(poll_backoff(base, 4), Duration::from_secs(32));
    }

    #[test]
    fn poll_backoff_caps_at_60s() {
        let base = Duration::from_secs(2);
        assert_eq!(poll_backoff(base, 5), POLL_MAX_BACKOFF);
        assert_eq!(poll_backoff(base, 20), POLL_MAX_BACKOFF);
        assert_eq!(poll_backoff(base, u32::MAX), POLL_MAX_BACKOFF);
    }

    #[test]
    fn poll_backoff_uses_caller_base() {
        let base = Duration::from_millis(500);
        assert_eq!(poll_backoff(base, 3), Duration::from_secs(4));
        assert_eq!(poll_backoff(base, 7), POLL_MAX_BACKOFF);
    }

    #[test]
    fn poll_backoff_does_not_overflow_on_large_consecutive_counts() {
        let base = Duration::from_secs(2);
        let d = poll_backoff(base, u32::MAX);
        assert!(d <= POLL_MAX_BACKOFF);
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
