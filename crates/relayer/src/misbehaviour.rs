use serde::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_relayer_types::clients::ics07_tendermint::misbehaviour::{
    Misbehaviour as TmMisbehaviour, TENDERMINT_MISBEHAVIOR_TYPE_URL,
};
use ibc_relayer_types::clients::ics08_cardano::misbehaviour::{
    Misbehaviour as MithrilMisbehaviour, MITHRIL_MISBEHAVIOUR_TYPE_URL,
};
use ibc_relayer_types::clients::ics08_cardano::raw as mithril_raw;
use ibc_relayer_types::clients::ics08_cardano_stability::misbehaviour::{
    Misbehaviour as StabilityMisbehaviour, STABILITY_MISBEHAVIOUR_TYPE_URL,
};
use ibc_relayer_types::clients::ics08_cardano_stability::raw as stability_raw;
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
    Stability(StabilityMisbehaviour),
}

impl Misbehaviour for AnyMisbehaviour {
    fn client_id(&self) -> &ClientId {
        match self {
            Self::Tendermint(misbehaviour) => misbehaviour.client_id(),
            Self::Mithril(misbehaviour) => misbehaviour.client_id(),
            Self::Stability(misbehaviour) => misbehaviour.client_id(),
        }
    }

    fn height(&self) -> Height {
        match self {
            Self::Tendermint(misbehaviour) => misbehaviour.height(),
            Self::Mithril(misbehaviour) => misbehaviour.height(),
            Self::Stability(misbehaviour) => misbehaviour.height(),
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
            STABILITY_MISBEHAVIOUR_TYPE_URL => {
                let value = stability_raw::Misbehaviour::decode(raw.value.as_slice())
                    .map_err(Error::decode)?;
                Ok(AnyMisbehaviour::Stability(value.try_into()?))
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
            AnyMisbehaviour::Stability(misbehaviour) => {
                let raw: stability_raw::Misbehaviour = misbehaviour.into();
                Any {
                    type_url: STABILITY_MISBEHAVIOUR_TYPE_URL.to_string(),
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
            AnyMisbehaviour::Stability(stability) => write!(f, "{stability}"),
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

impl From<StabilityMisbehaviour> for AnyMisbehaviour {
    fn from(misbehaviour: StabilityMisbehaviour) -> Self {
        Self::Stability(misbehaviour)
    }
}
