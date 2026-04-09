use prost::Message;
use serde_derive::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;

use crate::clients::ics08_cardano_stability::error::Error;
use crate::clients::ics08_cardano_stability::raw;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::consensus_state::ConsensusState as Ics2ConsensusState;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::core::ics23_commitment::commitment::CommitmentRoot;
use crate::timestamp::Timestamp;

pub const STABILITY_CONSENSUS_STATE_TYPE_URL: &str =
    "/ibc.lightclients.stability.v1.ConsensusState";

type RawConsensusState = raw::ConsensusState;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusState {
    pub root: CommitmentRoot,
    pub timestamp: u64,
    pub accepted_block_hash: String,
    pub accepted_epoch: u64,
    pub unique_pools_count: u64,
    pub unique_stake_bps: u64,
    pub security_score_bps: u64,
}

impl Ics2ConsensusState for ConsensusState {
    fn client_type(&self) -> ClientType {
        ClientType::CardanoStability
    }

    fn root(&self) -> &CommitmentRoot {
        &self.root
    }

    fn timestamp(&self) -> Timestamp {
        Timestamp::from_nanoseconds(self.timestamp).unwrap_or_else(|_| Timestamp::none())
    }
}

impl Protobuf<RawConsensusState> for ConsensusState {}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(raw: RawConsensusState) -> Result<Self, Self::Error> {
        if raw.ibc_state_root.is_empty() {
            return Err(Error::missing_field("ibc_state_root"));
        }

        if raw.ibc_state_root.len() != 32 {
            return Err(Error::invalid_field(
                "ibc_state_root",
                format!("expected 32 bytes, got {}", raw.ibc_state_root.len()),
            ));
        }

        Ok(Self {
            root: CommitmentRoot::from_bytes(&raw.ibc_state_root),
            timestamp: raw.timestamp,
            accepted_block_hash: raw.accepted_block_hash,
            accepted_epoch: raw.accepted_epoch,
            unique_pools_count: raw.unique_pools_count,
            unique_stake_bps: raw.unique_stake_bps,
            security_score_bps: raw.security_score_bps,
        })
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        RawConsensusState {
            timestamp: value.timestamp,
            ibc_state_root: value.root.as_bytes().to_vec(),
            accepted_block_hash: value.accepted_block_hash,
            accepted_epoch: value.accepted_epoch,
            unique_pools_count: value.unique_pools_count,
            unique_stake_bps: value.unique_stake_bps,
            security_score_bps: value.security_score_bps,
        }
    }
}

impl Protobuf<Any> for ConsensusState {}

impl TryFrom<Any> for ConsensusState {
    type Error = Ics02Error;

    fn try_from(raw_any: Any) -> Result<Self, Ics02Error> {
        use core::ops::Deref;

        fn decode_state(bytes: &[u8]) -> Result<ConsensusState, Error> {
            RawConsensusState::decode(bytes)
                .map_err(Error::decode)?
                .try_into()
        }

        match raw_any.type_url.as_str() {
            STABILITY_CONSENSUS_STATE_TYPE_URL => {
                decode_state(raw_any.value.deref()).map_err(Into::into)
            }
            _ => Err(Ics02Error::unknown_consensus_state_type(raw_any.type_url)),
        }
    }
}

impl From<ConsensusState> for Any {
    fn from(value: ConsensusState) -> Self {
        Any {
            type_url: STABILITY_CONSENSUS_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawConsensusState>::encode_vec(value),
        }
    }
}
