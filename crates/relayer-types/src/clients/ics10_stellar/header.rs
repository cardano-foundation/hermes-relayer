use bytes::Buf;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::lightclients::wasm::v1::ClientMessage as RawWasmClientMessage;
use ibc_proto::Protobuf;
use prost::Message;
use serde_derive::{Deserialize, Serialize};

use crate::clients::ics10_stellar::error::Error;
use crate::clients::ics10_stellar::raw;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::timestamp::Timestamp;
use crate::Height;

pub const STELLAR_HEADER_TYPE_URL: &str = "/ibc.lightclients.stellar.v1.StellarHeader";
pub const WASM_CLIENT_MESSAGE_TYPE_URL: &str = "/ibc.lightclients.wasm.v1.ClientMessage";

const SMT_ROOT_BYTES: usize = 32;

type RawHeader = raw::StellarHeader;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub trusted_height: Height,
    pub height: Height,
    pub timestamp: Timestamp,
    pub ledger_header_xdr: Vec<u8>,
    pub ibc_state_root: Vec<u8>,
    pub scp_envelopes: Vec<ScpEnvelope>,
    pub ledger_hash: Vec<u8>,
    pub previous_ledger_hash: Vec<u8>,
    #[serde(default)]
    pub wrap_as_wasm: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScpEnvelope {
    pub node_id: Vec<u8>,
    pub statement_xdr: Vec<u8>,
    pub signature: Vec<u8>,
}

impl From<raw::ScpEnvelope> for ScpEnvelope {
    fn from(r: raw::ScpEnvelope) -> Self {
        Self {
            node_id: r.node_id,
            statement_xdr: r.statement_xdr,
            signature: r.signature,
        }
    }
}

impl From<ScpEnvelope> for raw::ScpEnvelope {
    fn from(value: ScpEnvelope) -> Self {
        Self {
            node_id: value.node_id,
            statement_xdr: value.statement_xdr,
            signature: value.signature,
        }
    }
}

impl crate::core::ics02_client::header::Header for Header {
    fn client_type(&self) -> ClientType {
        ClientType::Stellar
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
        if raw.ledger_seq == 0 {
            return Err(Error::invalid_height(raw.ledger_seq));
        }

        let trusted_height = raw
            .trusted_height
            .ok_or_else(|| Error::missing_field("trusted_height"))?
            .try_into()?;

        let height = Height::new(0, raw.ledger_seq).map_err(|e| {
            Error::height_conversion(format!(
                "failed to build height from ledger_seq={}: {e}",
                raw.ledger_seq
            ))
        })?;

        if raw.ibc_state_root.is_empty() {
            return Err(Error::missing_field("ibc_state_root"));
        }
        if raw.ibc_state_root.len() != SMT_ROOT_BYTES {
            return Err(Error::invalid_field(
                "ibc_state_root",
                format!(
                    "expected {SMT_ROOT_BYTES} bytes, got {}",
                    raw.ibc_state_root.len()
                ),
            ));
        }
        if raw.ledger_header_xdr.is_empty() {
            return Err(Error::missing_field("ledger_header_xdr"));
        }
        if raw.scp_envelopes.is_empty() {
            return Err(Error::missing_field("scp_envelopes"));
        }

        let timestamp = if raw.timestamp == 0 {
            Timestamp::none()
        } else {
            Timestamp::from_nanoseconds(raw.timestamp.saturating_mul(1_000_000_000))
                .unwrap_or_else(|_| Timestamp::none())
        };

        Ok(Self {
            trusted_height,
            height,
            timestamp,
            ledger_header_xdr: raw.ledger_header_xdr,
            ibc_state_root: raw.ibc_state_root,
            scp_envelopes: raw.scp_envelopes.into_iter().map(Into::into).collect(),
            ledger_hash: raw.ledger_hash,
            previous_ledger_hash: raw.previous_ledger_hash,
            wrap_as_wasm: false,
        })
    }
}

impl From<Header> for RawHeader {
    fn from(value: Header) -> Self {
        let timestamp_secs = value
            .timestamp
            .nanoseconds()
            .checked_div(1_000_000_000)
            .unwrap_or(0);
        RawHeader {
            ledger_seq: value.height.revision_height(),
            ledger_header_xdr: value.ledger_header_xdr,
            ibc_state_root: value.ibc_state_root,
            scp_envelopes: value.scp_envelopes.into_iter().map(Into::into).collect(),
            trusted_height: Some(value.trusted_height.into()),
            timestamp: timestamp_secs,
            ledger_hash: value.ledger_hash,
            previous_ledger_hash: value.previous_ledger_hash,
        }
    }
}

impl Protobuf<Any> for Header {}

impl TryFrom<Any> for Header {
    type Error = Ics02Error;

    fn try_from(raw_any: Any) -> Result<Self, Ics02Error> {
        use core::ops::Deref;

        fn decode_header<B: Buf>(buf: B) -> Result<Header, Error> {
            tracing::info!("converting cosmos header to stellar header",);

            RawHeader::decode(buf).map_err(Error::decode)?.try_into()
        }

        match raw_any.type_url.as_str() {
            STELLAR_HEADER_TYPE_URL => decode_header(raw_any.value.deref()).map_err(Into::into),
            WASM_CLIENT_MESSAGE_TYPE_URL => {
                let wasm = RawWasmClientMessage::decode(raw_any.value.deref())
                    .map_err(|e| Ics02Error::from(Error::decode(e)))?;
                let mut inner = decode_header(wasm.data.as_slice())?;
                inner.wrap_as_wasm = true;
                Ok(inner)
            }
            _ => Err(Ics02Error::unknown_header_type(raw_any.type_url)),
        }
    }
}

impl From<Header> for Any {
    fn from(header: Header) -> Self {
        if header.wrap_as_wasm {
            let inner_bytes = {
                let mut without = header.clone();
                without.wrap_as_wasm = false;
                Protobuf::<RawHeader>::encode_vec(without)
            };
            let wasm = RawWasmClientMessage { data: inner_bytes };
            return Any {
                type_url: WASM_CLIENT_MESSAGE_TYPE_URL.to_string(),
                value: wasm.encode_to_vec(),
            };
        }
        Any {
            type_url: STELLAR_HEADER_TYPE_URL.to_string(),
            value: Protobuf::<RawHeader>::encode_vec(header),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header(ts_secs: u64) -> Header {
        Header {
            trusted_height: Height::new(0, 100).unwrap(),
            height: Height::new(0, 105).unwrap(),
            timestamp: Timestamp::from_nanoseconds(ts_secs.saturating_mul(1_000_000_000))
                .unwrap_or_else(|_| Timestamp::none()),
            ledger_header_xdr: vec![0xCC; 16],
            ibc_state_root: vec![0x11; 32],
            scp_envelopes: vec![ScpEnvelope {
                node_id: vec![0x42; 32],
                statement_xdr: vec![1, 2, 3],
                signature: vec![0u8; 64],
            }],
            ledger_hash: vec![0xaa; 32],
            previous_ledger_hash: vec![0xbb; 32],
            wrap_as_wasm: false,
        }
    }

    #[test]
    fn raw_round_trip_carries_new_fields() {
        let original = sample_header(1_700_000_500);
        let raw: RawHeader = original.clone().into();
        assert_eq!(raw.timestamp, 1_700_000_500);
        assert_eq!(raw.ledger_hash, original.ledger_hash);
        assert_eq!(raw.previous_ledger_hash, original.previous_ledger_hash);

        let decoded: Header = raw.try_into().unwrap();
        assert_eq!(decoded.height, original.height);
        assert_eq!(decoded.ledger_hash, original.ledger_hash);
        assert_eq!(decoded.previous_ledger_hash, original.previous_ledger_hash);
    }

    #[test]
    fn timestamp_zero_decodes_as_none() {
        let mut original = sample_header(0);
        original.timestamp = Timestamp::none();
        let raw: RawHeader = original.clone().into();
        assert_eq!(raw.timestamp, 0);
        let decoded: Header = raw.try_into().unwrap();
        assert_eq!(decoded.timestamp, Timestamp::none());
    }

    #[test]
    fn any_round_trip_through_stellar_type_url() {
        let original = sample_header(1_700_000_500);
        let any: Any = original.clone().into();
        assert_eq!(any.type_url, STELLAR_HEADER_TYPE_URL);
        let decoded: Header = any.try_into().unwrap();
        assert_eq!(decoded.ledger_hash, original.ledger_hash);
        assert_eq!(decoded.previous_ledger_hash, original.previous_ledger_hash);
    }
}
