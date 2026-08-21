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

/// Byte offset of `StellarValue.closeTime` inside a `LedgerHeader`.
///
/// Everything before it is fixed width — `ledgerVersion` (4),
/// `previousLedgerHash` (32), `StellarValue.txSetHash` (32) — so the close time
/// can be read without a full XDR decode. The wire header carries no timestamp
/// of its own; taking one from anywhere but the signed header bytes would mean
/// trusting the relayer for it.
const CLOSE_TIME_OFFSET: usize = 4 + 32 + 32;

type RawHeader = raw::StellarHeader;

/// A Stellar ledger plus the SCP evidence that it was agreed on.
///
/// The last four fields are what the light client verifies; `height`,
/// `timestamp` and `trusted_height` are hermes' own bookkeeping and are not on
/// the wire. SCP has no ledger-hash continuity chain — each header is verified
/// independently against the client's pinned quorum set — so there is no
/// trusted height to transmit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub height: Height,
    pub timestamp: Timestamp,
    pub trusted_height: Height,
    pub ledger_header_xdr: Vec<u8>,
    pub scp_envelopes: Vec<Vec<u8>>,
    pub quorum_sets_xdr: Vec<Vec<u8>>,
    pub next_scp_envelopes: Vec<Vec<u8>>,
    pub next_tx_set_xdr: Vec<u8>,
    pub state_root_proof: Option<StateRootProof>,
    #[serde(default)]
    pub wrap_as_wasm: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRootProof {
    pub result_pairs: Vec<Vec<u8>>,
    pub result_index: u32,
    pub success_preimage_xdr: Vec<u8>,
}

impl From<raw::StateRootProof> for StateRootProof {
    fn from(r: raw::StateRootProof) -> Self {
        Self {
            result_pairs: r.result_pairs,
            result_index: r.result_index,
            success_preimage_xdr: r.success_preimage_xdr,
        }
    }
}

impl From<StateRootProof> for raw::StateRootProof {
    fn from(v: StateRootProof) -> Self {
        Self {
            result_pairs: v.result_pairs,
            result_index: v.result_index,
            success_preimage_xdr: v.success_preimage_xdr,
        }
    }
}

/// Read `closeTime` out of a `LedgerHeader`, big-endian.
fn close_time_secs(ledger_header_xdr: &[u8]) -> Result<u64, Error> {
    let end = CLOSE_TIME_OFFSET + 8;
    let bytes = ledger_header_xdr
        .get(CLOSE_TIME_OFFSET..end)
        .ok_or_else(|| {
            Error::invalid_field(
                "ledger_header_xdr",
                format!(
                    "too short to contain closeTime: need {end} bytes, got {}",
                    ledger_header_xdr.len()
                ),
            )
        })?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(buf))
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
        if raw.slot_index == 0 {
            return Err(Error::invalid_height(raw.slot_index));
        }
        if raw.ledger_header_xdr.is_empty() {
            return Err(Error::missing_field("ledger_header_xdr"));
        }
        if raw.scp_envelopes.is_empty() {
            return Err(Error::missing_field("scp_envelopes"));
        }
        if raw.quorum_sets_xdr.is_empty() {
            return Err(Error::missing_field("quorum_sets_xdr"));
        }
        // Slot N+1 is what binds the parts of the header SCP does not sign, so
        // a header without it cannot prove a state root and is rejected here
        // rather than on chain.
        if raw.next_scp_envelopes.is_empty() {
            return Err(Error::missing_field("next_scp_envelopes"));
        }
        if raw.next_tx_set_xdr.is_empty() {
            return Err(Error::missing_field("next_tx_set_xdr"));
        }

        let height = Height::new(0, raw.slot_index).map_err(|e| {
            Error::height_conversion(format!(
                "failed to build height from slot_index={}: {e}",
                raw.slot_index
            ))
        })?;

        let close_time = close_time_secs(&raw.ledger_header_xdr)?;
        let timestamp = if close_time == 0 {
            Timestamp::none()
        } else {
            Timestamp::from_nanoseconds(close_time.saturating_mul(1_000_000_000))
                .unwrap_or_else(|_| Timestamp::none())
        };

        Ok(Self {
            height,
            timestamp,
            // Nothing on the wire says otherwise; the endpoint overwrites this
            // when it has the real trusted height.
            trusted_height: height,
            ledger_header_xdr: raw.ledger_header_xdr,
            scp_envelopes: raw.scp_envelopes,
            quorum_sets_xdr: raw.quorum_sets_xdr,
            next_scp_envelopes: raw.next_scp_envelopes,
            next_tx_set_xdr: raw.next_tx_set_xdr,
            state_root_proof: raw.state_root_proof.map(Into::into),
            wrap_as_wasm: false,
        })
    }
}

impl From<Header> for RawHeader {
    fn from(value: Header) -> Self {
        RawHeader {
            slot_index: value.height.revision_height(),
            ledger_header_xdr: value.ledger_header_xdr,
            scp_envelopes: value.scp_envelopes,
            quorum_sets_xdr: value.quorum_sets_xdr,
            next_scp_envelopes: value.next_scp_envelopes,
            next_tx_set_xdr: value.next_tx_set_xdr,
            state_root_proof: value.state_root_proof.map(Into::into),
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

    /// A header whose ledger bytes are long enough to carry a closeTime at the
    /// fixed offset, with a recognisable value.
    fn sample_header(close_time: u64) -> Header {
        let mut ledger_header_xdr = vec![0xCCu8; CLOSE_TIME_OFFSET];
        ledger_header_xdr.extend_from_slice(&close_time.to_be_bytes());
        ledger_header_xdr.extend_from_slice(&[0xDD; 32]);

        Header {
            height: Height::new(0, 105).unwrap(),
            timestamp: Timestamp::from_nanoseconds(close_time.saturating_mul(1_000_000_000))
                .unwrap_or_else(|_| Timestamp::none()),
            trusted_height: Height::new(0, 100).unwrap(),
            ledger_header_xdr,
            scp_envelopes: vec![vec![1, 2, 3]],
            quorum_sets_xdr: vec![vec![4, 5, 6]],
            next_scp_envelopes: vec![vec![7, 8, 9]],
            next_tx_set_xdr: vec![0xEE; 40],
            state_root_proof: Some(StateRootProof {
                result_pairs: vec![vec![0xA1; 8], vec![0xA2; 8]],
                result_index: 1,
                success_preimage_xdr: vec![0xB0; 12],
            }),
            wrap_as_wasm: false,
        }
    }

    #[test]
    fn raw_round_trip_preserves_the_scp_evidence() {
        let original = sample_header(1_700_000_500);
        let raw: RawHeader = original.clone().into();

        assert_eq!(raw.slot_index, 105);
        assert_eq!(raw.scp_envelopes, original.scp_envelopes);
        assert_eq!(raw.quorum_sets_xdr, original.quorum_sets_xdr);
        assert_eq!(raw.next_scp_envelopes, original.next_scp_envelopes);
        assert_eq!(raw.next_tx_set_xdr, original.next_tx_set_xdr);

        let decoded: Header = raw.try_into().unwrap();
        assert_eq!(decoded.height, original.height);
        assert_eq!(decoded.scp_envelopes, original.scp_envelopes);
        assert_eq!(decoded.state_root_proof, original.state_root_proof);
    }

    /// The timestamp is not transmitted; it is read out of the signed ledger
    /// header, so it cannot be set independently of the bytes the validators
    /// signed.
    #[test]
    fn timestamp_is_derived_from_the_ledger_header() {
        let original = sample_header(1_700_000_500);
        let decoded: Header = RawHeader::from(original).try_into().unwrap();

        assert_eq!(
            decoded.timestamp.nanoseconds(),
            1_700_000_500u64.saturating_mul(1_000_000_000)
        );
    }

    #[test]
    fn a_header_too_short_for_a_close_time_is_rejected() {
        let mut original = sample_header(1_700_000_500);
        original.ledger_header_xdr.truncate(CLOSE_TIME_OFFSET + 4);
        let raw: RawHeader = original.into();

        assert!(Header::try_from(raw).is_err());
    }

    /// Slot N+1 carries the binding for everything SCP does not sign, so a
    /// header without it is refused before it reaches the chain.
    #[test]
    fn a_header_without_the_next_slot_is_rejected() {
        let original = sample_header(1_700_000_500);
        let mut raw: RawHeader = original.into();
        raw.next_scp_envelopes.clear();

        assert!(Header::try_from(raw).is_err());
    }

    #[test]
    fn any_round_trip_through_stellar_type_url() {
        let original = sample_header(1_700_000_500);
        let any: Any = original.clone().into();
        assert_eq!(any.type_url, STELLAR_HEADER_TYPE_URL);

        let decoded: Header = any.try_into().unwrap();
        assert_eq!(decoded.height, original.height);
        assert_eq!(decoded.next_tx_set_xdr, original.next_tx_set_xdr);
    }
}
