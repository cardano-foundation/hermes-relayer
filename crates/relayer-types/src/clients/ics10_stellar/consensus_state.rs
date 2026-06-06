use prost::Message;
use serde_derive::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::lightclients::wasm::v1::ConsensusState as RawWasmConsensusState;
use ibc_proto::Protobuf;

use crate::clients::ics10_stellar::error::Error;
use crate::clients::ics10_stellar::raw;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::consensus_state::ConsensusState as Ics2ConsensusState;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::core::ics23_commitment::commitment::CommitmentRoot;
use crate::timestamp::Timestamp;

pub const STELLAR_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.stellar.v1.ConsensusState";
pub const WASM_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.wasm.v1.ConsensusState";

const HASH_BYTES: usize = 32;

type RawConsensusState = raw::ConsensusState;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusState {
    pub root: CommitmentRoot,
    pub timestamp: u64,
    pub ledger_hash: Vec<u8>,
    #[serde(skip)]
    pub wrap_as_wasm: bool,
}

impl Ics2ConsensusState for ConsensusState {
    fn client_type(&self) -> ClientType {
        ClientType::Stellar
    }

    fn root(&self) -> &CommitmentRoot {
        &self.root
    }

    fn timestamp(&self) -> Timestamp {
        Timestamp::from_nanoseconds(self.timestamp.saturating_mul(1_000_000_000))
            .unwrap_or_else(|_| Timestamp::none())
    }
}

impl Protobuf<RawConsensusState> for ConsensusState {}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(raw: RawConsensusState) -> Result<Self, Self::Error> {
        if raw.root.is_empty() {
            return Err(Error::missing_field("root"));
        }
        if raw.root.len() != HASH_BYTES {
            return Err(Error::invalid_field(
                "root",
                format!("expected {HASH_BYTES} bytes, got {}", raw.root.len()),
            ));
        }
        if !raw.ledger_hash.is_empty() && raw.ledger_hash.len() != HASH_BYTES {
            return Err(Error::invalid_field(
                "ledger_hash",
                format!("expected {HASH_BYTES} bytes, got {}", raw.ledger_hash.len()),
            ));
        }

        Ok(Self {
            root: CommitmentRoot::from_bytes(&raw.root),
            timestamp: raw.timestamp,
            ledger_hash: raw.ledger_hash,
            wrap_as_wasm: false,
        })
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        RawConsensusState {
            timestamp: value.timestamp,
            ledger_hash: value.ledger_hash,
            root: value.root.as_bytes().to_vec(),
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
            STELLAR_CONSENSUS_STATE_TYPE_URL => {
                decode_state(raw_any.value.deref()).map_err(Into::into)
            }
            WASM_CONSENSUS_STATE_TYPE_URL => {
                let wasm = RawWasmConsensusState::decode(raw_any.value.deref())
                    .map_err(Error::decode)?;
                let mut inner = decode_state(&wasm.data).map_err(Into::<Ics02Error>::into)?;
                inner.wrap_as_wasm = true;
                Ok(inner)
            }
            _ => Err(Ics02Error::unknown_consensus_state_type(raw_any.type_url)),
        }
    }
}

impl From<ConsensusState> for Any {
    fn from(value: ConsensusState) -> Self {
        if value.wrap_as_wasm {
            let inner_bytes = {
                let mut without = value.clone();
                without.wrap_as_wasm = false;
                Protobuf::<RawConsensusState>::encode_vec(without)
            };
            let wasm = RawWasmConsensusState { data: inner_bytes };
            return Any {
                type_url: WASM_CONSENSUS_STATE_TYPE_URL.to_string(),
                value: wasm.encode_to_vec(),
            };
        }
        Any {
            type_url: STELLAR_CONSENSUS_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawConsensusState>::encode_vec(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(wrap_as_wasm: bool) -> ConsensusState {
        ConsensusState {
            root: CommitmentRoot::from_bytes(&[0x11; 32]),
            timestamp: 1_700_000_000,
            ledger_hash: vec![0xaa; 32],
            wrap_as_wasm,
        }
    }

    #[test]
    fn native_any_uses_stellar_type_url_and_round_trips() {
        let original = sample(false);
        let any: Any = original.clone().into();
        assert_eq!(any.type_url, STELLAR_CONSENSUS_STATE_TYPE_URL);
        let decoded: ConsensusState = any.try_into().unwrap();
        assert_eq!(decoded.timestamp, original.timestamp);
        assert_eq!(decoded.ledger_hash, original.ledger_hash);
        assert!(!decoded.wrap_as_wasm);
    }

    #[test]
    fn wasm_any_wraps_and_round_trips_marking_wasm() {
        let original = sample(true);
        let any: Any = original.clone().into();
        assert_eq!(any.type_url, WASM_CONSENSUS_STATE_TYPE_URL);
        let decoded: ConsensusState = any.try_into().unwrap();
        assert_eq!(decoded.timestamp, original.timestamp);
        assert_eq!(decoded.ledger_hash, original.ledger_hash);
        assert!(decoded.wrap_as_wasm);
    }
}
