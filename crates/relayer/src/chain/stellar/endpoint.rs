use alloc::sync::Arc;
use core::str::FromStr;
use std::sync::Mutex as StdMutex;

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
use crate::chain::version::Specs;
use crate::client_state::{AnyClientState, IdentifiedAnyClientState};
use crate::config::{ChainConfig, Error as ConfigError};
use crate::consensus_state::AnyConsensusState;
use crate::denom::DenomTrace;
use crate::error::Error;
use crate::event::IbcEventWithHeight;
use crate::keyring::{KeyRing, Store};
use crate::misbehaviour::MisbehaviourEvidence;

use super::config::StellarConfig;
use super::gateway_client::{
    self, GatewayMsgClient, GatewayQueryClient, QueryIbcHeaderRequest,
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
        unimplemented!()
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
        _target: ICSHeight,
        _client_state: &AnyClientState,
    ) -> Result<Self::LightBlock, Error> {
        unimplemented!()
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
        unimplemented!()
    }

    fn query_client_state(
        &self,
        _request: QueryClientStateRequest,
        _include_proof: IncludeProof,
    ) -> Result<(AnyClientState, Option<MerkleProof>), Error> {
        unimplemented!()
    }

    fn query_consensus_state(
        &self,
        _request: QueryConsensusStateRequest,
        _include_proof: IncludeProof,
    ) -> Result<(AnyConsensusState, Option<MerkleProof>), Error> {
        unimplemented!()
    }

    fn query_consensus_state_heights(
        &self,
        _request: QueryConsensusStateHeightsRequest,
    ) -> Result<Vec<ICSHeight>, Error> {
        unimplemented!()
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
        _request: QueryPacketCommitmentRequest,
        _include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        unimplemented!()
    }

    fn query_packet_commitments(
        &self,
        _request: QueryPacketCommitmentsRequest,
    ) -> Result<(Vec<Sequence>, ICSHeight), Error> {
        unimplemented!()
    }

    fn query_packet_receipt(
        &self,
        _request: QueryPacketReceiptRequest,
        _include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        unimplemented!()
    }

    fn query_unreceived_packets(
        &self,
        _request: QueryUnreceivedPacketsRequest,
    ) -> Result<Vec<Sequence>, Error> {
        unimplemented!()
    }

    fn query_packet_acknowledgement(
        &self,
        _request: QueryPacketAcknowledgementRequest,
        _include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        unimplemented!()
    }

    fn query_packet_acknowledgements(
        &self,
        _request: QueryPacketAcknowledgementsRequest,
    ) -> Result<(Vec<Sequence>, ICSHeight), Error> {
        unimplemented!()
    }

    fn query_unreceived_acknowledgements(
        &self,
        _request: QueryUnreceivedAcksRequest,
    ) -> Result<Vec<Sequence>, Error> {
        unimplemented!()
    }

    fn query_next_sequence_receive(
        &self,
        _request: QueryNextSequenceReceiveRequest,
        _include_proof: IncludeProof,
    ) -> Result<(Sequence, Option<MerkleProof>), Error> {
        unimplemented!()
    }

    fn query_txs(&self, _request: QueryTxRequest) -> Result<Vec<IbcEventWithHeight>, Error> {
        unimplemented!()
    }

    fn query_packet_events(
        &self,
        _request: QueryPacketEventDataRequest,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        unimplemented!()
    }

    fn query_host_consensus_state(
        &self,
        _request: QueryHostConsensusStateRequest,
    ) -> Result<Self::ConsensusState, Error> {
        unimplemented!()
    }

    fn build_client_state(
        &self,
        _height: ICSHeight,
        _settings: ClientSettings,
    ) -> Result<Self::ClientState, Error> {
        unimplemented!()
    }

    fn build_consensus_state(
        &self,
        _light_block: Self::LightBlock,
    ) -> Result<Self::ConsensusState, Error> {
        unimplemented!()
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
            statement_xdr: Vec::new(),
            signature: wire.scp_signature,
        };

        let raw = stellar_raw::StellarHeader {
            ledger_seq: wire.ledger_seq as u64,
            ledger_header_xdr: wire.ledger_header_xdr,
            ibc_state_root: wire.ibc_state_root,
            scp_envelopes: vec![envelope],
            trusted_height: Some(stellar_raw::Height {
                revision_number: trusted_height.revision_number(),
                revision_height: trusted_height.revision_height(),
            }),
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

fn ledger_close_time_secs(ledger_header_xdr: &[u8]) -> Result<u64, Error> {
    use stellar_xdr::curr::{LedgerHeader, Limits, ReadXdr};

    let header = LedgerHeader::from_xdr(ledger_header_xdr, Limits::none())
        .map_err(|e| Error::query(format!("LedgerHeader XDR decode failed: {e}")))?;
    Ok(header.scp_value.close_time.0)
}
