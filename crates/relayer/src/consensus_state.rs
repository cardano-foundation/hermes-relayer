use serde::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::client::v1::ConsensusStateWithHeight;
use ibc_proto::ibc::lightclients::tendermint::v1::ConsensusState as RawConsensusState;
use ibc_proto::Protobuf;
use ibc_relayer_types::clients::ics07_tendermint::consensus_state::{
    ConsensusState as TmConsensusState, TENDERMINT_CONSENSUS_STATE_TYPE_URL,
};

#[cfg(feature = "cardano")]
use ibc_cardano_chain::types::CardanoConsensusState;

const CARDANO_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.cardano.v1.ConsensusState";
use ibc_relayer_types::core::ics02_client::client_type::ClientType;
use ibc_relayer_types::core::ics02_client::consensus_state::ConsensusState;
use ibc_relayer_types::core::ics02_client::error::Error;
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentRoot;
use ibc_relayer_types::timestamp::Timestamp;
use ibc_relayer_types::Height;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AnyConsensusState {
    Tendermint(TmConsensusState),
    #[cfg(feature = "cardano")]
    Cardano(CardanoConsensusState),
}

impl AnyConsensusState {
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Self::Tendermint(cs_state) => cs_state.timestamp.into(),
            #[cfg(feature = "cardano")]
            Self::Cardano(cs_state) => ConsensusState::timestamp(cs_state),
        }
    }

    pub fn client_type(&self) -> ClientType {
        match self {
            AnyConsensusState::Tendermint(_cs) => ClientType::Tendermint,
            #[cfg(feature = "cardano")]
            AnyConsensusState::Cardano(_cs) => ClientType::Cardano,
        }
    }
}

impl Protobuf<Any> for AnyConsensusState {}

impl TryFrom<Any> for AnyConsensusState {
    type Error = Error;

    fn try_from(value: Any) -> Result<Self, Self::Error> {
        match value.type_url.as_str() {
            "" => Err(Error::empty_consensus_state_response()),

            TENDERMINT_CONSENSUS_STATE_TYPE_URL => Ok(AnyConsensusState::Tendermint(
                Protobuf::<RawConsensusState>::decode_vec(&value.value)
                    .map_err(Error::decode_raw_client_state)?,
            )),

            #[cfg(feature = "cardano")]
            CARDANO_CONSENSUS_STATE_TYPE_URL => {
                // For now, deserialize from JSON (will need proper protobuf later)
                let cardano_state: CardanoConsensusState = serde_json::from_slice(&value.value)
                    .map_err(|e| Error::decode_raw_client_state(e.into()))?;
                Ok(AnyConsensusState::Cardano(cardano_state))
            }

            _ => Err(Error::unknown_consensus_state_type(value.type_url)),
        }
    }
}

impl From<AnyConsensusState> for Any {
    fn from(value: AnyConsensusState) -> Self {
        match value {
            AnyConsensusState::Tendermint(value) => Any {
                type_url: TENDERMINT_CONSENSUS_STATE_TYPE_URL.to_string(),
                value: Protobuf::<RawConsensusState>::encode_vec(value),
            },
            #[cfg(feature = "cardano")]
            AnyConsensusState::Cardano(value) => Any {
                type_url: CARDANO_CONSENSUS_STATE_TYPE_URL.to_string(),
                // For now, serialize to JSON (will need proper protobuf later)
                value: serde_json::to_vec(&value).unwrap_or_default(),
            },
        }
    }
}

impl From<TmConsensusState> for AnyConsensusState {
    fn from(cs: TmConsensusState) -> Self {
        Self::Tendermint(cs)
    }
}

#[cfg(feature = "cardano")]
impl From<CardanoConsensusState> for AnyConsensusState {
    fn from(cs: CardanoConsensusState) -> Self {
        Self::Cardano(cs)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AnyConsensusStateWithHeight {
    pub height: Height,
    pub consensus_state: AnyConsensusState,
}

impl Protobuf<ConsensusStateWithHeight> for AnyConsensusStateWithHeight {}

impl TryFrom<ConsensusStateWithHeight> for AnyConsensusStateWithHeight {
    type Error = Error;

    fn try_from(value: ConsensusStateWithHeight) -> Result<Self, Self::Error> {
        let state = value
            .consensus_state
            .map(AnyConsensusState::try_from)
            .transpose()?
            .ok_or_else(Error::empty_consensus_state_response)?;

        Ok(AnyConsensusStateWithHeight {
            height: value
                .height
                .and_then(|raw_height| raw_height.try_into().ok())
                .ok_or_else(Error::missing_height)?,
            consensus_state: state,
        })
    }
}

impl From<AnyConsensusStateWithHeight> for ConsensusStateWithHeight {
    fn from(value: AnyConsensusStateWithHeight) -> Self {
        ConsensusStateWithHeight {
            height: Some(value.height.into()),
            consensus_state: Some(value.consensus_state.into()),
        }
    }
}

impl ConsensusState for AnyConsensusState {
    fn client_type(&self) -> ClientType {
        self.client_type()
    }

    fn root(&self) -> &CommitmentRoot {
        match self {
            Self::Tendermint(cs_state) => cs_state.root(),
            #[cfg(feature = "cardano")]
            Self::Cardano(cs_state) => ConsensusState::root(cs_state),
        }
    }

    fn timestamp(&self) -> Timestamp {
        AnyConsensusState::timestamp(self)
    }
}
