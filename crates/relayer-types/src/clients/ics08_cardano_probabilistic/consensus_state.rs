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
    pub verification_generation: u64,
    pub checkpoint_reference: Vec<u8>,
    pub packet_state_reference: Vec<u8>,
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
        if raw.verification_generation == 0
            || raw.checkpoint_reference.len() != 32
            || raw.packet_state_reference.len() != 32
            || raw.timestamp == 0
        {
            return Err(Error::invalid_field(
                "checkpoint_reference",
                "consensus requires authenticated snapshot references".to_owned(),
            ));
        }
        if !raw.packet_state_snapshot.is_empty()
            || raw.nonce_state.is_some()
            || raw.pool_registry.is_some()
            || raw.settlement_credit.is_some()
            || raw.pool_production.is_some()
        {
            return Err(Error::invalid_field(
                "checkpoint_reference",
                "consensus cannot embed verification collections".to_owned(),
            ));
        }

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
            verification_generation: raw.verification_generation,
            checkpoint_reference: raw.checkpoint_reference,
            packet_state_reference: raw.packet_state_reference,
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
            verification_generation: value.verification_generation,
            checkpoint_reference: value.checkpoint_reference,
            packet_state_reference: value.packet_state_reference,
            ..Default::default()
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
    #[test]
    fn only_snapshot_consensus_round_trips() {
        let raw = RawConsensusState {
            timestamp: 1,
            ibc_state_root: vec![1; 32],
            verification_generation: 1,
            checkpoint_reference: vec![2; 32],
            packet_state_reference: vec![3; 32],
            ..Default::default()
        };
        let state = ConsensusState::try_from(raw.clone()).unwrap();
        let any: Any = state.into();
        let restored: RawConsensusState = ConsensusState::try_from(any).unwrap().into();
        assert_eq!(restored, raw);
        let mut invalid = raw.clone();
        invalid.verification_generation = 0;
        assert!(ConsensusState::try_from(invalid).is_err());
        let mut invalid = raw;
        invalid.pool_registry = Some(raw::test_pool_registry());
        assert!(ConsensusState::try_from(invalid).is_err());
    }
}
