use bytes::Buf;
use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;
use prost::Message;
use serde_derive::{Deserialize, Serialize};

use crate::clients::ics08_cardano::error::Error;
use crate::clients::ics08_cardano::raw as raw;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::timestamp::Timestamp;
use crate::Height;

pub const MITHRIL_HEADER_TYPE_URL: &str = "/ibc.lightclients.mithril.v1.MithrilHeader";

type RawHeader = raw::MithrilHeader;

/// Cardano Mithril header (Cosmos-sidechain light client).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub height: Height,
    pub timestamp: Timestamp,
    pub mithril_stake_distribution: raw::MithrilStakeDistribution,
    pub mithril_stake_distribution_certificate: raw::MithrilCertificate,
    pub transaction_snapshot: raw::CardanoTransactionSnapshot,
    pub transaction_snapshot_certificate: raw::MithrilCertificate,
    pub previous_mithril_stake_distribution_certificates: Vec<raw::MithrilCertificate>,
    pub host_state_tx_hash: String,
    pub host_state_tx_body_cbor: Vec<u8>,
    pub host_state_tx_output_index: u32,
    pub host_state_tx_proof: Vec<u8>,
}

impl crate::core::ics02_client::header::Header for Header {
    fn client_type(&self) -> ClientType {
        ClientType::Cardano
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
        let RawHeader {
            mithril_stake_distribution,
            mithril_stake_distribution_certificate,
            transaction_snapshot,
            transaction_snapshot_certificate,
            previous_mithril_stake_distribution_certificates,
            host_state_tx_hash,
            host_state_tx_body_cbor,
            host_state_tx_output_index,
            host_state_tx_proof,
        } = raw;

        let transaction_snapshot: raw::CardanoTransactionSnapshot = transaction_snapshot
            .ok_or_else(|| Error::missing_field("transaction_snapshot"))?;

        let transaction_snapshot_certificate: raw::MithrilCertificate = transaction_snapshot_certificate
            .ok_or_else(|| Error::missing_field("transaction_snapshot_certificate"))?;

        // IBC heights are `(revision_number, revision_height)`.
        // For Cardano we use `revision_number = 0` and interpret `revision_height` as the
        // Cardano block number from the Mithril transaction snapshot (not a slot number).
        let height = Height::new(0, transaction_snapshot.block_number).map_err(|e| {
            Error::height_conversion(format!(
                "failed to construct height from block_number {}: {e}",
                transaction_snapshot.block_number
            ))
        })?;

        let timestamp = {
            let metadata = transaction_snapshot_certificate
                .metadata
                .as_ref()
                .ok_or_else(|| Error::missing_field("transaction_snapshot_certificate.metadata"))?;

            let sealed_at = metadata.sealed_at.trim();
            if sealed_at.is_empty() {
                return Err(Error::invalid_timestamp(sealed_at.to_string()));
            }

            // RFC3339 with optional sub-second precision, matching the Go client.
            let ts = time::OffsetDateTime::parse(
                sealed_at,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| Error::invalid_timestamp(sealed_at.to_string()))?;

            let nanos: i128 = ts.unix_timestamp_nanos();
            if nanos <= 0 {
                return Err(Error::invalid_timestamp(sealed_at.to_string()));
            }

            let nanos_u64: u64 = nanos
                .try_into()
                .map_err(|_| Error::timestamp_conversion("timestamp out of range".to_string()))?;

            Timestamp::from_nanoseconds(nanos_u64)
                .map_err(|e| Error::timestamp_conversion(e.to_string()))?
        };

        if host_state_tx_body_cbor.is_empty() {
            return Err(Error::missing_field("host_state_tx_body_cbor"));
        }

        if host_state_tx_proof.is_empty() {
            return Err(Error::missing_field("host_state_tx_proof"));
        }

        Ok(Self {
            height,
            timestamp,
            mithril_stake_distribution: mithril_stake_distribution
                .ok_or_else(|| Error::missing_field("mithril_stake_distribution"))?,
            mithril_stake_distribution_certificate: mithril_stake_distribution_certificate
                .ok_or_else(|| Error::missing_field("mithril_stake_distribution_certificate"))?,
            transaction_snapshot,
            transaction_snapshot_certificate,
            previous_mithril_stake_distribution_certificates,
            host_state_tx_hash,
            host_state_tx_body_cbor,
            host_state_tx_output_index,
            host_state_tx_proof,
        })
    }
}

impl From<Header> for RawHeader {
    fn from(value: Header) -> Self {
        RawHeader {
            mithril_stake_distribution: Some(value.mithril_stake_distribution),
            mithril_stake_distribution_certificate: Some(value.mithril_stake_distribution_certificate),
            transaction_snapshot: Some(value.transaction_snapshot),
            transaction_snapshot_certificate: Some(value.transaction_snapshot_certificate),
            previous_mithril_stake_distribution_certificates: value.previous_mithril_stake_distribution_certificates,
            host_state_tx_hash: value.host_state_tx_hash,
            host_state_tx_body_cbor: value.host_state_tx_body_cbor,
            host_state_tx_output_index: value.host_state_tx_output_index,
            host_state_tx_proof: value.host_state_tx_proof,
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
            MITHRIL_HEADER_TYPE_URL => decode_header(raw_any.value.deref()).map_err(Into::into),
            _ => Err(Ics02Error::unknown_header_type(raw_any.type_url)),
        }
    }
}

impl From<Header> for Any {
    fn from(header: Header) -> Self {
        Any {
            type_url: MITHRIL_HEADER_TYPE_URL.to_string(),
            value: Protobuf::<RawHeader>::encode_vec(header),
        }
    }
}
