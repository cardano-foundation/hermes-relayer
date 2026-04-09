use bytes::Buf;
use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;
use prost::Message;
use serde_derive::{Deserialize, Serialize};

use crate::clients::ics08_cardano_stability::error::Error;
use crate::clients::ics08_cardano_stability::raw;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::timestamp::Timestamp;
use crate::Height;

pub const STABILITY_HEADER_TYPE_URL: &str = "/ibc.lightclients.stability.v1.StabilityHeader";

type RawHeader = raw::StabilityHeader;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub trusted_height: Height,
    pub height: Height,
    pub timestamp: Timestamp,
    pub anchor_block: raw::StabilityBlock,
    pub bridge_blocks: Vec<raw::StabilityBlock>,
    pub descendant_blocks: Vec<raw::StabilityBlock>,
    pub host_state_tx_hash: String,
    pub host_state_tx_output_index: u32,
}

impl crate::core::ics02_client::header::Header for Header {
    fn client_type(&self) -> ClientType {
        ClientType::CardanoStability
    }

    fn height(&self) -> Height {
        self.height
    }

    fn timestamp(&self) -> Timestamp {
        self.timestamp
    }
}

impl Protobuf<RawHeader> for Header {}

impl TryFrom<RawHeader> for Header {
    type Error = Error;

    fn try_from(raw: RawHeader) -> Result<Self, Self::Error> {
        let trusted_height = raw
            .trusted_height
            .ok_or_else(|| Error::missing_field("trusted_height"))?
            .try_into()?;

        let anchor_block = raw
            .anchor_block
            .ok_or_else(|| Error::missing_field("anchor_block"))?;

        let anchor_height = anchor_block
            .height
            .clone()
            .ok_or_else(|| Error::missing_field("anchor_block.height"))?
            .try_into()?;

        let timestamp = Timestamp::from_nanoseconds(anchor_block.timestamp)
            .map_err(|e| Error::timestamp_conversion(e.to_string()))?;

        Ok(Self {
            trusted_height,
            height: anchor_height,
            timestamp,
            anchor_block,
            bridge_blocks: raw.bridge_blocks,
            descendant_blocks: raw.descendant_blocks,
            host_state_tx_hash: raw.host_state_tx_hash,
            host_state_tx_output_index: raw.host_state_tx_output_index,
        })
    }
}

impl From<Header> for RawHeader {
    fn from(value: Header) -> Self {
        RawHeader {
            trusted_height: Some(value.trusted_height.into()),
            anchor_block: Some(value.anchor_block),
            bridge_blocks: value.bridge_blocks,
            descendant_blocks: value.descendant_blocks,
            host_state_tx_hash: value.host_state_tx_hash,
            host_state_tx_output_index: value.host_state_tx_output_index,
        }
    }
}

impl Protobuf<Any> for Header {}

impl TryFrom<Any> for Header {
    type Error = Ics02Error;

    fn try_from(raw_any: Any) -> Result<Self, Ics02Error> {
        use core::ops::Deref;

        fn decode_header<B: Buf>(buf: B) -> Result<Header, Error> {
            RawHeader::decode(buf).map_err(Error::decode)?.try_into()
        }

        match raw_any.type_url.as_str() {
            STABILITY_HEADER_TYPE_URL => decode_header(raw_any.value.deref()).map_err(Into::into),
            _ => Err(Ics02Error::unknown_header_type(raw_any.type_url)),
        }
    }
}

impl From<Header> for Any {
    fn from(header: Header) -> Self {
        Any {
            type_url: STABILITY_HEADER_TYPE_URL.to_string(),
            value: Protobuf::<RawHeader>::encode_vec(header),
        }
    }
}
