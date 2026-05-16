use ibc_proto::Protobuf;
use serde::{Deserialize, Serialize};

use crate::clients::ics08_cardano_probabilistic::error::Error;
use crate::clients::ics08_cardano_probabilistic::header::Header;
use crate::clients::ics08_cardano_probabilistic::raw;
use crate::core::ics24_host::identifier::ClientId;
use crate::tx_msg::Msg;
use crate::Height;

pub const PROBABILISTIC_MISBEHAVIOUR_TYPE_URL: &str =
    "/ibc.lightclients.probabilistic.v1.Misbehaviour";

type RawMisbehaviour = raw::Misbehaviour;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Misbehaviour {
    pub client_id: ClientId,
    pub header1: Header,
    pub header2: Header,
}

impl crate::core::ics02_client::misbehaviour::Misbehaviour for Misbehaviour {
    fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    fn height(&self) -> Height {
        self.header1.height
    }
}

impl Msg for Misbehaviour {
    type ValidationError = Error;
    type Raw = RawMisbehaviour;

    fn route(&self) -> String {
        crate::keys::ROUTER_KEY.to_string()
    }

    fn type_url(&self) -> String {
        PROBABILISTIC_MISBEHAVIOUR_TYPE_URL.to_string()
    }
}

impl Protobuf<RawMisbehaviour> for Misbehaviour {}

impl TryFrom<RawMisbehaviour> for Misbehaviour {
    type Error = Error;

    fn try_from(raw: RawMisbehaviour) -> Result<Self, Self::Error> {
        Ok(Self {
            client_id: raw
                .client_id
                .parse::<ClientId>()
                .map_err(|e| Error::invalid_field("client_id", e.to_string()))?,
            header1: raw
                .probabilistic_header_1
                .ok_or_else(|| Error::missing_field("probabilistic_header_1"))?
                .try_into()?,
            header2: raw
                .probabilistic_header_2
                .ok_or_else(|| Error::missing_field("probabilistic_header_2"))?
                .try_into()?,
        })
    }
}

impl From<Misbehaviour> for RawMisbehaviour {
    fn from(value: Misbehaviour) -> Self {
        RawMisbehaviour {
            client_id: value.client_id.to_string(),
            probabilistic_header_1: Some(value.header1.into()),
            probabilistic_header_2: Some(value.header2.into()),
        }
    }
}

impl core::fmt::Display for Misbehaviour {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "{} h1: {} trusted: {} h2: {} trusted: {}",
            self.client_id,
            self.header1.height,
            self.header1.trusted_height,
            self.header2.height,
            self.header2.trusted_height,
        )
    }
}
