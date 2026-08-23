use prost::Message;
use serde_derive::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;

use crate::clients::ics08_cardano_probabilistic::error::Error;
use crate::clients::ics08_cardano_probabilistic::raw;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::consensus_state::ConsensusState as Ics2ConsensusState;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::core::ics23_commitment::commitment::CommitmentRoot;
use crate::timestamp::Timestamp;

pub const PROBABILISTIC_CONSENSUS_STATE_TYPE_URL: &str =
    "/ibc.lightclients.probabilistic.v1.ConsensusState";

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
    pub operational_certificate_state_initialized: bool,
}

impl Ics2ConsensusState for ConsensusState {
    fn client_type(&self) -> ClientType {
        ClientType::CardanoProbabilistic
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
            operational_certificate_state_initialized: raw
                .operational_certificate_state_initialized,
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
            operational_certificate_state_initialized: value
                .operational_certificate_state_initialized,
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
            PROBABILISTIC_CONSENSUS_STATE_TYPE_URL => {
                decode_state(raw_any.value.deref()).map_err(Into::into)
            }
            _ => Err(Ics02Error::unknown_consensus_state_type(raw_any.type_url)),
        }
    }
}

impl From<ConsensusState> for Any {
    fn from(value: ConsensusState) -> Self {
        Any {
            type_url: PROBABILISTIC_CONSENSUS_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawConsensusState>::encode_vec(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_consensus_state() -> RawConsensusState {
        RawConsensusState {
            timestamp: 1,
            ibc_state_root: vec![3; 32],
            accepted_block_hash: "accepted-block".to_string(),
            accepted_epoch: 7,
            unique_pools_count: 15,
            unique_stake_bps: 7_000,
            security_score_bps: 8_000,
            operational_certificate_state_initialized: true,
        }
    }

    #[test]
    fn any_round_trip_preserves_operational_certificate_marker() {
        let raw = raw_consensus_state();
        let any = Any {
            type_url: PROBABILISTIC_CONSENSUS_STATE_TYPE_URL.to_string(),
            value: raw.encode_to_vec(),
        };

        let decoded = ConsensusState::try_from(any).expect("consensus state must decode");
        assert!(decoded.operational_certificate_state_initialized);

        let reencoded: Any = decoded.into();
        let round_trip = RawConsensusState::decode(reencoded.value.as_slice())
            .expect("round-trip consensus state must decode");
        assert_eq!(round_trip, raw);
    }

    #[test]
    fn legacy_consensus_state_with_default_marker_still_decodes() {
        let mut raw = raw_consensus_state();
        raw.operational_certificate_state_initialized = false;

        let decoded = ConsensusState::try_from(raw).expect("legacy consensus state must decode");
        assert!(!decoded.operational_certificate_state_initialized);
    }
}
