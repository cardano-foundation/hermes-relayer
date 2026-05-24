use alloc::sync::Arc;
use core::str::FromStr;
use std::borrow::Cow;
use std::collections::BTreeMap;
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
use ibc_relayer_types::clients::ics10_stellar::raw as stellar_raw;
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentRoot;
use ibc_relayer_types::core::ics02_client::events::UpdateClient;
use ibc_relayer_types::core::ics02_client::header::AnyHeader;
use ibc_relayer_types::core::ics02_client::height::Height;
use ibc_relayer_types::core::ics03_connection::connection::{ConnectionEnd, IdentifiedConnectionEnd};
use ibc_relayer_types::core::ics04_channel::channel::{ChannelEnd, IdentifiedChannelEnd};
use ibc_relayer_types::core::ics04_channel::packet::Sequence;
use ibc_relayer_types::core::ics04_channel::upgrade::{ErrorReceipt, Upgrade};
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentPrefix;
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
use crate::chain::tracking::TrackedMsgs;
use crate::chain::tracking::TrackingId;
use crate::chain::version::Specs;
use crate::client_state::{AnyClientState, IdentifiedAnyClientState};
use crate::config::{ChainConfig, Error as ConfigError};
use crate::consensus_state::AnyConsensusState;
use crate::denom::DenomTrace;
use crate::error::Error;
use crate::event::source::{Error as SourceError, EventBatch};
use crate::event::IbcEventWithHeight;
use crate::keyring::{KeyRing, Store};
use crate::misbehaviour::MisbehaviourEvidence;

use super::config::StellarConfig;
use super::gateway_client::{
    self, EventsRequest, GatewayContractEvent, GatewayMsgClient, GatewayQueryClient,
    QueryIbcHeaderRequest,
};
use super::signing_key_pair::StellarSigningKeyPair;

pub struct StellarLightBlock {
    pub ledger_seq: u64,
    pub ledger_hash: Vec<u8>,
    pub ibc_state_root: Vec<u8>,
    pub timestamp: Timestamp,
    pub close_time_secs: u64,
    pub scp_node_id: Vec<u8>,
}

pub struct StellarChainEndpoint {
    pub config: StellarConfig,
    pub keyring: KeyRing<StellarSigningKeyPair>,
    pub gateway_query: StdMutex<GatewayQueryClient>,
    pub gateway_msg: StdMutex<GatewayMsgClient>,
    pub rt: Arc<TokioRuntime>,
    pub event_sender:
        StdMutex<Option<crossbeam_channel::Sender<Arc<crate::event::source::Result<crate::event::source::EventBatch>>>>>,
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
            _ => return Err(Error::config(ConfigError::wrong_type())),
        };

        tracing::info!(
            "Bootstrapping Stellar chain endpoint id={} gateway={}",
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
        let gateway_msg = rt
            .block_on(GatewayMsgClient::connect(stellar_config.gateway_url.clone()))
            .map_err(|e| {
                tracing::error!("Stellar gateway msg connect failed: {e}");
                Error::config(ConfigError::wrong_type())
            })?;

        let keyring =
            KeyRing::new(Store::Test, "stellar", &stellar_config.id, &None).map_err(Error::key_base)?;

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
        Ok(())
    }

    fn health_check(&mut self) -> Result<HealthCheck, Error> {
        let resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard.latest_height().await
            })
            .map_err(|e| Error::query(format!("Stellar gateway latest_height failed: {e}")))?;
        if resp.revision_height == 0 {
            return Err(Error::query(
                "Stellar gateway reported revision_height=0".to_string(),
            ));
        }
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
        Signer::from_str(&key.account_id()).map_err(|e| {
            Error::key_base(crate::keyring::errors::Error::invalid_mnemonic(
                anyhow::anyhow!("Invalid Stellar signer address: {e}"),
            ))
        })
    }

    fn get_key(&self) -> Result<Self::SigningKeyPair, Error> {
        self.keyring
            .get_key(&self.config.key_name)
            .map_err(Error::key_base)
    }

    fn version_specs(&self) -> Result<Specs, Error> {
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
        let signer = self.get_signer()?.to_string();

        self.rt.block_on(async {
            for msg in tracked_msgs.msgs.iter() {
                dispatch_msg(&self.gateway_msg, &msg.type_url, msg.value.clone(), &signer)
                    .await?;
            }
            Ok::<(), Error>(())
        })?;

        Ok(Vec::new())
    }

    fn send_messages_and_wait_check_tx(
        &mut self,
        tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<TxResponse>, Error> {
        self.send_messages_and_wait_commit(tracked_msgs)?;
        Ok(Vec::new())
    }

    fn verify_header(
        &mut self,
        _trusted: ICSHeight,
        target: ICSHeight,
        _client_state: &AnyClientState,
    ) -> Result<Self::LightBlock, Error> {
        let resp = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard
                    .query_ibc_header(QueryIbcHeaderRequest {
                        height: target.revision_height(),
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

        Ok(StellarLightBlock {
            ledger_seq: wire.ledger_seq as u64,
            ledger_hash,
            ibc_state_root: wire.ibc_state_root,
            timestamp,
            close_time_secs: close_time,
            scp_node_id: wire.scp_node_id,
        })
    }

    fn check_misbehaviour(
        &mut self,
        _update: &UpdateClient,
        _client_state: &AnyClientState,
    ) -> Result<Option<MisbehaviourEvidence>, Error> {
        unimplemented!()
    }

    fn query_balance(
        &self,
        _key_name: Option<&str>,
        _denom: Option<&str>,
    ) -> Result<Balance, Error> {
        unimplemented!()
    }

    fn query_all_balances(&self, _key_name: Option<&str>) -> Result<Vec<Balance>, Error> {
        unimplemented!()
    }

    fn query_denom_trace(&self, _hash: String) -> Result<DenomTrace, Error> {
        unimplemented!()
    }

    fn query_commitment_prefix(&self) -> Result<CommitmentPrefix, Error> {
        CommitmentPrefix::try_from(b"ibc".to_vec())
            .map_err(|e| Error::query(format!("invalid commitment prefix for Stellar: {e}")))
    }

    fn query_application_status(&self) -> Result<ChainStatus, Error> {
        let latest = self
            .rt
            .block_on(async {
                let mut guard = self.gateway_query.lock().unwrap();
                guard.latest_height().await
            })
            .map_err(|e| Error::query(format!("Stellar gateway latest_height failed: {e}")))?;

        let height = ICSHeight::new(latest.revision_number, latest.revision_height)
            .map_err(|e| Error::query(format!("invalid Stellar height from gateway: {e}")))?;

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
        let timestamp =
            Timestamp::from_nanoseconds(close_time_secs.saturating_mul(1_000_000_000))
                .map_err(|e| Error::query(format!("invalid Stellar close_time: {e}")))?;

        Ok(ChainStatus { height, timestamp })
    }

    fn query_clients(
        &self,
        _request: QueryClientStatesRequest,
    ) -> Result<Vec<IdentifiedAnyClientState>, Error> {
        Ok(Vec::new())
    }

    fn query_client_state(
        &self,
        request: QueryClientStateRequest,
        _include_proof: IncludeProof,
    ) -> Result<(AnyClientState, Option<MerkleProof>), Error> {
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
            .map_err(|e| {
                Error::query(format!("Stellar gateway query_client_state failed: {e}"))
            })?;
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
                Error::query(format!(
                    "Stellar gateway query_packet_receipt failed: {e}"
                ))
            })?;
        let proof = decode_merkle_proof(&resp.proof)?;
        let value = if resp.received { vec![0x01] } else { Vec::new() };
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
                Error::query(format!(
                    "Stellar gateway query_acknowledgement failed: {e}"
                ))
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
            root: CommitmentRoot::from_bytes(&wire.ibc_state_root),
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
        let network_id = network_id_from_passphrase(&self.config.network_passphrase);
        Ok(AnyClientState::Stellar(StellarClientState {
            chain_id: self.config.id.clone(),
            latest_height: height,
            frozen_height: None,
            trusted_validators: Vec::new(),
            proof_specs: Vec::new(),
            network_id,
            wasm_checksum: self.wasm_checksum_bytes()?,
        }))
    }

    fn build_consensus_state(
        &self,
        light_block: Self::LightBlock,
    ) -> Result<Self::ConsensusState, Error> {
        Ok(AnyConsensusState::Stellar(StellarConsensusState {
            root: CommitmentRoot::from_bytes(&light_block.ibc_state_root),
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

        let envelope = stellar_raw::ScpEnvelope {
            node_id: wire.scp_node_id,
            statement_xdr: wire.signed_value_xdr,
            signature: wire.scp_signature,
        };

        let timestamp_secs = ledger_close_time_secs(&wire.ledger_header_xdr).unwrap_or(0);
        let previous_ledger_hash =
            ledger_previous_hash(&wire.ledger_header_xdr).unwrap_or_default();
        let raw = stellar_raw::StellarHeader {
            ledger_seq: wire.ledger_seq as u64,
            ledger_header_xdr: wire.ledger_header_xdr,
            ibc_state_root: wire.ibc_state_root,
            scp_envelopes: vec![envelope],
            trusted_height: Some(stellar_raw::Height {
                revision_number: trusted_height.revision_number(),
                revision_height: trusted_height.revision_height(),
            }),
            timestamp: timestamp_secs,
            ledger_hash: Vec::new(),
            previous_ledger_hash,
        };

        let header: StellarHeader = raw
            .try_into()
            .map_err(|e| Error::query(format!("StellarHeader try_into failed: {e}")))?;

        Ok((AnyHeader::Stellar(header), vec![]))
    }

    fn maybe_register_counterparty_payee(
        &mut self,
        _channel_id: &ChannelId,
        _port_id: &PortId,
        _counterparty_payee: &Signer,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    fn cross_chain_query(
        &self,
        _requests: Vec<CrossChainQueryRequest>,
    ) -> Result<Vec<CrossChainQueryResponse>, Error> {
        unimplemented!()
    }

    fn query_incentivized_packet(
        &self,
        _request: QueryIncentivizedPacketRequest,
    ) -> Result<QueryIncentivizedPacketResponse, Error> {
        unimplemented!()
    }

    fn query_consumer_chains(&self) -> Result<Vec<ConsumerChain>, Error> {
        unimplemented!()
    }

    fn query_upgrade(
        &self,
        _request: QueryUpgradeRequest,
        _height: Height,
        _include_proof: IncludeProof,
    ) -> Result<(Upgrade, Option<MerkleProof>), Error> {
        unimplemented!()
    }

    fn query_upgrade_error(
        &self,
        _request: QueryUpgradeErrorRequest,
        _height: Height,
        _include_proof: IncludeProof,
    ) -> Result<(ErrorReceipt, Option<MerkleProof>), Error> {
        unimplemented!()
    }

    fn query_ccv_consumer_id(&self, _client_id: ClientId) -> Result<ConsumerId, Error> {
        unimplemented!()
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
        let bytes = hex_decode(hex)
            .map_err(|e| Error::query(format!("invalid wasm_checksum_hex on Stellar config: {e}")))?;
        Ok(Some(bytes))
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

async fn dispatch_msg(
    msg_client: &StdMutex<GatewayMsgClient>,
    type_url: &str,
    value: Vec<u8>,
    signer: &str,
) -> Result<(), Error> {
    use ibc_proto::ibc::core::client::v1 as cosmos_client;
    use ibc_relayer_types::clients::ics10_stellar::v2_msgs;

    match type_url {
        "/ibc.core.client.v1.MsgCreateClient" => {
            let m = cosmos_client::MsgCreateClient::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgCreateClient decode: {e}")))?;
            let cs_bytes = m.client_state.map(|a| a.value).unwrap_or_default();
            let cons_bytes = m.consensus_state.map(|a| a.value).unwrap_or_default();
            let mut guard = msg_client.lock().unwrap();
            guard
                .create_client(super::gateway_client::MsgCreateClientRequest {
                    client_state: cs_bytes,
                    consensus_state: cons_bytes,
                    signer: if m.signer.is_empty() {
                        signer.to_string()
                    } else {
                        m.signer
                    },
                    client_type: String::new(),
                    height: 0,
                })
                .await
                .map_err(|e| Error::send_tx(format!("gateway create_client failed: {e}")))?;
        }
        "/ibc.core.client.v1.MsgUpdateClient" => {
            let m = cosmos_client::MsgUpdateClient::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgUpdateClient decode: {e}")))?;
            let header_bytes = m.client_message.map(|a| a.value).unwrap_or_default();
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
                .map_err(|e| Error::send_tx(format!("gateway update_client failed: {e}")))?;
        }
        url if url == v2_msgs::TYPE_URL_REGISTER_COUNTERPARTY => {
            let m = v2_msgs::MsgRegisterCounterparty::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgRegisterCounterparty decode: {e}")))?;
            let mut guard = msg_client.lock().unwrap();
            guard
                .register_counterparty(super::gateway_client::MsgRegisterCounterpartyRequest {
                    client_id: m.client_id,
                    counterparty_client_id: m.counterparty_client_id,
                    counterparty_commitment_prefix: m.counterparty_commitment_prefix,
                })
                .await
                .map_err(|e| Error::send_tx(format!("gateway register_counterparty failed: {e}")))?;
        }
        url if url == v2_msgs::TYPE_URL_RECV_PACKET => {
            let m = v2_msgs::MsgRecvPacket::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgRecvPacket decode: {e}")))?;
            let packet_bytes = m
                .packet
                .map(|p| p.encode_to_vec())
                .unwrap_or_default();
            let proof_height = m
                .proof_height
                .map(|h| h.revision_height)
                .unwrap_or(0);
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
                .map_err(|e| Error::send_tx(format!("gateway recv_packet failed: {e}")))?;
        }
        url if url == v2_msgs::TYPE_URL_ACKNOWLEDGEMENT => {
            let m = v2_msgs::MsgAcknowledgement::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgAcknowledgement decode: {e}")))?;
            let packet_bytes = m
                .packet
                .map(|p| p.encode_to_vec())
                .unwrap_or_default();
            let ack_bytes = m.acknowledgements.into_iter().next().unwrap_or_default();
            let proof_height = m
                .proof_height
                .map(|h| h.revision_height)
                .unwrap_or(0);
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
                .map_err(|e| Error::send_tx(format!("gateway ack_packet failed: {e}")))?;
        }
        url if url == v2_msgs::TYPE_URL_TIMEOUT => {
            let m = v2_msgs::MsgTimeout::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgTimeout decode: {e}")))?;
            let packet_bytes = m
                .packet
                .map(|p| p.encode_to_vec())
                .unwrap_or_default();
            let proof_height = m
                .proof_height
                .map(|h| h.revision_height)
                .unwrap_or(0);
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
                .map_err(|e| Error::send_tx(format!("gateway timeout_packet failed: {e}")))?;
        }
        url if url == v2_msgs::TYPE_URL_SUBMIT_MISBEHAVIOUR => {
            let m = v2_msgs::MsgSubmitMisbehaviour::decode(value.as_slice())
                .map_err(|e| Error::send_tx(format!("MsgSubmitMisbehaviour decode: {e}")))?;
            let client_message = m.misbehaviour.map(|a| a.value).unwrap_or_default();
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
                .map_err(|e| Error::send_tx(format!("gateway submit_misbehaviour failed: {e}")))?;
        }
        other => {
            return Err(Error::send_tx(format!(
                "Stellar endpoint does not yet encode message type {other}",
            )));
        }
    }

    Ok(())
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

const STELLAR_ROUTER_MODULE: &str = "stellaribcrouter";

async fn run_event_polling(
    chain_id: ChainId,
    gateway_url: String,
    sender: crossbeam_channel::Sender<Arc<crate::event::source::Result<EventBatch>>>,
    poll_interval: Duration,
) {
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
                "latest_height failed at startup: {e}; defaulting start_ledger to 1"
            );
            1
        }
    };
    let mut cursor = String::new();

    loop {
        tokio::time::sleep(poll_interval).await;

        let req = EventsRequest {
            start_ledger: if cursor.is_empty() { start_ledger } else { 0 },
            cursor: cursor.clone(),
            limit: 200,
        };

        let resp = match client.events(req).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    target: "stellar_events",
                    "gateway events poll failed (start_ledger={start_ledger}, cursor='{cursor}'): {e}"
                );
                continue;
            }
        };

        if !resp.cursor.is_empty() {
            cursor = resp.cursor;
        }
        if resp.latest_ledger as u32 > start_ledger {
            start_ledger = resp.latest_ledger as u32;
        }

        let mut by_ledger: BTreeMap<u64, Vec<IbcEventWithHeight>> = BTreeMap::new();
        for ev in resp.events {
            let height = match ICSHeight::new(0, ev.ledger) {
                Ok(h) => h,
                Err(_) => continue,
            };
            if let Some(ibc_ev) = translate_router_event(&ev) {
                by_ledger
                    .entry(ev.ledger)
                    .or_default()
                    .push(IbcEventWithHeight::new(ibc_ev, height));
            }
        }

        for (ledger_seq, events) in by_ledger {
            let height = match ICSHeight::new(0, ledger_seq) {
                Ok(h) => h,
                Err(_) => continue,
            };
            let batch = EventBatch {
                chain_id: chain_id.clone(),
                tracking_id: TrackingId::new_uuid(),
                height,
                events,
            };
            if sender.send(Arc::new(Ok(batch))).is_err() {
                return;
            }
        }
    }
}

fn translate_router_event(ev: &GatewayContractEvent) -> Option<IbcEvent> {
    use stellar_xdr::curr::{Limits, ReadXdr, ScVal};

    let topics: Vec<ScVal> = ev
        .topics_xdr
        .iter()
        .filter_map(|t| ScVal::from_xdr(t, Limits::none()).ok())
        .collect();

    let kind = match topics.first() {
        Some(ScVal::Symbol(sym)) => core::str::from_utf8(sym.0.as_slice()).ok()?.to_owned(),
        _ => return None,
    };

    if !matches!(
        kind.as_str(),
        "send_packet" | "recv_packet" | "write_ack" | "ack_packet" | "timeout_packet"
    ) {
        return None;
    }

    let module_name = ModuleId::new(Cow::Borrowed(STELLAR_ROUTER_MODULE)).ok()?;

    let mut attributes = Vec::with_capacity(4);
    attributes.push(ModuleEventAttribute {
        key: "tx_hash".to_string(),
        value: ev.tx_hash.clone(),
    });
    attributes.push(ModuleEventAttribute {
        key: "event_id".to_string(),
        value: ev.id.clone(),
    });
    if let Some(ScVal::String(s)) = topics.get(1) {
        if let Ok(client_id) = core::str::from_utf8(s.0.as_slice()) {
            attributes.push(ModuleEventAttribute {
                key: "client_id".to_string(),
                value: client_id.to_string(),
            });
        }
    }
    if let Some(ScVal::U64(seq)) = topics.get(2) {
        attributes.push(ModuleEventAttribute {
            key: "sequence".to_string(),
            value: seq.to_string(),
        });
    }
    if !ev.value_xdr.is_empty() {
        attributes.push(ModuleEventAttribute {
            key: "value_xdr_hex".to_string(),
            value: hex_encode_bytes(&ev.value_xdr),
        });
    }
    if !ev.contract_id.is_empty() {
        attributes.push(ModuleEventAttribute {
            key: "contract_id".to_string(),
            value: ev.contract_id.clone(),
        });
    }

    Some(IbcEvent::AppModule(ModuleEvent {
        kind,
        module_name,
        attributes,
    }))
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
