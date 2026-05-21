use serde::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::client::v1::ConsensusStateWithHeight;
use ibc_proto::ibc::lightclients::tendermint::v1::ConsensusState as RawConsensusState;
use ibc_proto::Protobuf;
use ibc_relayer_types::clients::ics07_tendermint::consensus_state::{
    ConsensusState as TmConsensusState, TENDERMINT_CONSENSUS_STATE_TYPE_URL,
};
use ibc_relayer_types::clients::ics08_cardano::consensus_state::{
    ConsensusState as MithrilConsensusState, MITHRIL_CONSENSUS_STATE_TYPE_URL,
};
use ibc_relayer_types::clients::ics08_cardano_probabilistic::consensus_state::{
    ConsensusState as ProbabilisticConsensusState, PROBABILISTIC_CONSENSUS_STATE_TYPE_URL,
};
use ibc_relayer_types::clients::ics10_stellar::consensus_state::{
    ConsensusState as StellarConsensusState, STELLAR_CONSENSUS_STATE_TYPE_URL,
};

use ibc_relayer_types::core::ics02_client::client_type::ClientType;
use ibc_relayer_types::core::ics02_client::consensus_state::ConsensusState;
use ibc_relayer_types::core::ics02_client::error::Error;
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentRoot;
use ibc_relayer_types::timestamp::Timestamp;
use ibc_relayer_types::Height;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum AnyConsensusState {
    Tendermint(TmConsensusState),
    /// Cardano-tracking consensus state (`08-cardano-mithril`), encoded as `ibc.lightclients.mithril.v1.ConsensusState`.
    Mithril(MithrilConsensusState),
    /// Probabilistic Cardano consensus state (`08-cardano-probabilistic`), encoded as `ibc.lightclients.probabilistic.v1.ConsensusState`.
    Probabilistic(ProbabilisticConsensusState),
    /// Stellar consensus state (`10-stellar`), encoded as `ibc.lightclients.stellar.v1.ConsensusState`.
    Stellar(StellarConsensusState),
}

impl AnyConsensusState {
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Self::Tendermint(cs_state) => cs_state.timestamp.into(),
            Self::Mithril(cs_state) => ConsensusState::timestamp(cs_state),
            Self::Probabilistic(cs_state) => ConsensusState::timestamp(cs_state),
            Self::Stellar(cs_state) => ConsensusState::timestamp(cs_state),
        }
    }

    pub fn client_type(&self) -> ClientType {
        match self {
            AnyConsensusState::Tendermint(_cs) => ClientType::Tendermint,
            AnyConsensusState::Mithril(_cs) => ClientType::CardanoMithril,
            AnyConsensusState::Probabilistic(_cs) => ClientType::CardanoProbabilistic,
            AnyConsensusState::Stellar(_cs) => ClientType::Stellar,
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

            MITHRIL_CONSENSUS_STATE_TYPE_URL => Ok(AnyConsensusState::Mithril(value.try_into()?)),
            PROBABILISTIC_CONSENSUS_STATE_TYPE_URL => {
                Ok(AnyConsensusState::Probabilistic(value.try_into()?))
            }
            STELLAR_CONSENSUS_STATE_TYPE_URL => {
                Ok(AnyConsensusState::Stellar(value.try_into()?))
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
            AnyConsensusState::Mithril(value) => value.into(),
            AnyConsensusState::Probabilistic(value) => value.into(),
            AnyConsensusState::Stellar(value) => value.into(),
        }
    }
}

impl From<TmConsensusState> for AnyConsensusState {
    fn from(cs: TmConsensusState) -> Self {
        Self::Tendermint(cs)
    }
}

impl From<MithrilConsensusState> for AnyConsensusState {
    fn from(cs: MithrilConsensusState) -> Self {
        Self::Mithril(cs)
    }
}

impl From<ProbabilisticConsensusState> for AnyConsensusState {
    fn from(cs: ProbabilisticConsensusState) -> Self {
        Self::Probabilistic(cs)
    }
}

impl From<StellarConsensusState> for AnyConsensusState {
    fn from(cs: StellarConsensusState) -> Self {
        Self::Stellar(cs)
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
            Self::Mithril(cs_state) => ConsensusState::root(cs_state),
            Self::Probabilistic(cs_state) => ConsensusState::root(cs_state),
            Self::Stellar(cs_state) => ConsensusState::root(cs_state),
        }
    }

    fn timestamp(&self) -> Timestamp {
        AnyConsensusState::timestamp(self)
    }
}
