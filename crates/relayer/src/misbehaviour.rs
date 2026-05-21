use serde::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_relayer_types::clients::ics07_tendermint::misbehaviour::{
    Misbehaviour as TmMisbehaviour, TENDERMINT_MISBEHAVIOR_TYPE_URL,
};
use ibc_relayer_types::clients::ics08_cardano::misbehaviour::{
    Misbehaviour as MithrilMisbehaviour, MITHRIL_MISBEHAVIOUR_TYPE_URL,
};
use ibc_relayer_types::clients::ics08_cardano::raw as mithril_raw;
use ibc_relayer_types::clients::ics08_cardano_probabilistic::misbehaviour::{
    Misbehaviour as ProbabilisticMisbehaviour, PROBABILISTIC_MISBEHAVIOUR_TYPE_URL,
};
use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw as probabilistic_raw;
use ibc_relayer_types::clients::ics10_stellar::misbehaviour::{
    Misbehaviour as StellarMisbehaviour, STELLAR_MISBEHAVIOUR_TYPE_URL,
};
use ibc_relayer_types::clients::ics10_stellar::raw as stellar_raw;
use ibc_relayer_types::core::ics02_client::error::Error;
use ibc_relayer_types::core::ics02_client::header::AnyHeader;
use ibc_relayer_types::core::ics02_client::misbehaviour::Misbehaviour;
use ibc_relayer_types::core::ics24_host::identifier::ClientId;
use ibc_relayer_types::Height;
use prost::Message;
use tendermint_proto::Protobuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MisbehaviourEvidence {
    pub misbehaviour: AnyMisbehaviour,
    pub supporting_headers: Vec<AnyHeader>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum AnyMisbehaviour {
    Tendermint(TmMisbehaviour),
    Mithril(MithrilMisbehaviour),
    Probabilistic(ProbabilisticMisbehaviour),
    Stellar(StellarMisbehaviour),
}

impl Misbehaviour for AnyMisbehaviour {
    fn client_id(&self) -> &ClientId {
        match self {
            Self::Tendermint(misbehaviour) => misbehaviour.client_id(),
            Self::Mithril(misbehaviour) => misbehaviour.client_id(),
            Self::Probabilistic(misbehaviour) => misbehaviour.client_id(),
            Self::Stellar(misbehaviour) => misbehaviour.client_id(),
        }
    }

    fn height(&self) -> Height {
        match self {
            Self::Tendermint(misbehaviour) => misbehaviour.height(),
            Self::Mithril(misbehaviour) => misbehaviour.height(),
            Self::Probabilistic(misbehaviour) => misbehaviour.height(),
            Self::Stellar(misbehaviour) => misbehaviour.height(),
        }
    }
}

impl Protobuf<Any> for AnyMisbehaviour {}

impl TryFrom<Any> for AnyMisbehaviour {
    type Error = Error;

    fn try_from(raw: Any) -> Result<Self, Error> {
        match raw.type_url.as_str() {
            TENDERMINT_MISBEHAVIOR_TYPE_URL => Ok(AnyMisbehaviour::Tendermint(
                TmMisbehaviour::decode_vec(&raw.value).map_err(Error::decode_raw_misbehaviour)?,
            )),
            MITHRIL_MISBEHAVIOUR_TYPE_URL => {
                let value = mithril_raw::Misbehaviour::decode(raw.value.as_slice())
                    .map_err(Error::decode)?;
                Ok(AnyMisbehaviour::Mithril(value.try_into()?))
            }
            PROBABILISTIC_MISBEHAVIOUR_TYPE_URL => {
                let value = probabilistic_raw::Misbehaviour::decode(raw.value.as_slice())
                    .map_err(Error::decode)?;
                Ok(AnyMisbehaviour::Probabilistic(value.try_into()?))
            }
            STELLAR_MISBEHAVIOUR_TYPE_URL => {
                let value = stellar_raw::Misbehaviour::decode(raw.value.as_slice())
                    .map_err(Error::decode)?;
                Ok(AnyMisbehaviour::Stellar(value.try_into()?))
            }

            _ => Err(Error::unknown_misbehaviour_type(raw.type_url)),
        }
    }
}

impl From<AnyMisbehaviour> for Any {
    fn from(value: AnyMisbehaviour) -> Self {
        match value {
            AnyMisbehaviour::Tendermint(misbehaviour) => Any {
                type_url: TENDERMINT_MISBEHAVIOR_TYPE_URL.to_string(),
                value: misbehaviour.encode_vec(),
            },
            AnyMisbehaviour::Mithril(misbehaviour) => {
                let raw: mithril_raw::Misbehaviour = misbehaviour.into();
                Any {
                    type_url: MITHRIL_MISBEHAVIOUR_TYPE_URL.to_string(),
                    value: raw.encode_to_vec(),
                }
            }
            AnyMisbehaviour::Probabilistic(misbehaviour) => {
                let raw: probabilistic_raw::Misbehaviour = misbehaviour.into();
                Any {
                    type_url: PROBABILISTIC_MISBEHAVIOUR_TYPE_URL.to_string(),
                    value: raw.encode_to_vec(),
                }
            }
            AnyMisbehaviour::Stellar(misbehaviour) => {
                let raw: stellar_raw::Misbehaviour = misbehaviour.into();
                Any {
                    type_url: STELLAR_MISBEHAVIOUR_TYPE_URL.to_string(),
                    value: raw.encode_to_vec(),
                }
            }
        }
    }
}

impl core::fmt::Display for AnyMisbehaviour {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            AnyMisbehaviour::Tendermint(tm) => write!(f, "{tm}"),
            AnyMisbehaviour::Mithril(mithril) => write!(f, "{mithril}"),
            AnyMisbehaviour::Probabilistic(probabilistic) => write!(f, "{probabilistic}"),
            AnyMisbehaviour::Stellar(stellar) => write!(f, "{stellar}"),
        }
    }
}

impl From<TmMisbehaviour> for AnyMisbehaviour {
    fn from(misbehaviour: TmMisbehaviour) -> Self {
        Self::Tendermint(misbehaviour)
    }
}

impl From<MithrilMisbehaviour> for AnyMisbehaviour {
    fn from(misbehaviour: MithrilMisbehaviour) -> Self {
        Self::Mithril(misbehaviour)
    }
}

impl From<ProbabilisticMisbehaviour> for AnyMisbehaviour {
    fn from(misbehaviour: ProbabilisticMisbehaviour) -> Self {
        Self::Probabilistic(misbehaviour)
    }
}

impl From<StellarMisbehaviour> for AnyMisbehaviour {
    fn from(misbehaviour: StellarMisbehaviour) -> Self {
        Self::Stellar(misbehaviour)
    }
}
