use prost::Message;
use serde_derive::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;

use crate::clients::ics2000_mithril::error::Error;
use crate::clients::ics2000_mithril::raw as raw;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::consensus_state::ConsensusState as Ics2ConsensusState;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::core::ics23_commitment::commitment::CommitmentRoot;
use crate::timestamp::Timestamp;

pub const MITHRIL_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.clients.mithril.v1.ConsensusState";

type RawConsensusState = raw::ConsensusState;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusState {
    /// Commitment root is not carried by the Mithril client proto yet.
    /// For MVP relaying, Hermes does not perform proof verification locally.
    pub root: CommitmentRoot,
    pub timestamp: u64,
    pub first_cert_hash_latest_epoch: raw::MithrilCertificate,
    pub latest_cert_hash_tx_snapshot: String,
}

impl ConsensusState {
    pub fn new(
        timestamp: u64,
        first_cert_hash_latest_epoch: raw::MithrilCertificate,
        latest_cert_hash_tx_snapshot: String,
    ) -> Self {
        Self {
            root: CommitmentRoot::from_bytes(&[]),
            timestamp,
            first_cert_hash_latest_epoch,
            latest_cert_hash_tx_snapshot,
        }
    }
}

impl Ics2ConsensusState for ConsensusState {
    fn client_type(&self) -> ClientType {
        ClientType::CardanoMithril
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
        let first = raw
            .first_cert_hash_latest_epoch
            .ok_or_else(|| Error::missing_field("first_cert_hash_latest_epoch"))?;

        Ok(Self::new(
            raw.timestamp,
            first,
            raw.latest_cert_hash_tx_snapshot,
        ))
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        RawConsensusState {
            timestamp: value.timestamp,
            first_cert_hash_latest_epoch: Some(value.first_cert_hash_latest_epoch),
            latest_cert_hash_tx_snapshot: value.latest_cert_hash_tx_snapshot,
        }
    }
}

impl Protobuf<Any> for ConsensusState {}

impl TryFrom<Any> for ConsensusState {
    type Error = Ics02Error;

    fn try_from(raw_any: Any) -> Result<Self, Ics02Error> {
        use core::ops::Deref;

        fn decode_state(bytes: &[u8]) -> Result<ConsensusState, Error> {
            RawConsensusState::decode(bytes).map_err(Error::decode)?.try_into()
        }

        match raw_any.type_url.as_str() {
            MITHRIL_CONSENSUS_STATE_TYPE_URL => {
                decode_state(raw_any.value.deref()).map_err(Into::into)
            }
            _ => Err(Ics02Error::unknown_consensus_state_type(raw_any.type_url)),
        }
    }
}

impl From<ConsensusState> for Any {
    fn from(value: ConsensusState) -> Self {
        Any {
            type_url: MITHRIL_CONSENSUS_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawConsensusState>::encode_vec(value),
        }
    }
}

