use bytes::Buf;
use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;
use prost::Message;
use serde_derive::{Deserialize, Serialize};

use crate::clients::ics08_cardano_probabilistic::error::Error;
use crate::clients::ics08_cardano_probabilistic::raw;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::timestamp::Timestamp;
use crate::Height;

pub const PROBABILISTIC_HEADER_TYPE_URL: &str =
    "/ibc.lightclients.probabilistic.v1.ProbabilisticHeader";

type RawHeader = raw::ProbabilisticHeader;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub trusted_height: Height,
    pub height: Height,
    pub timestamp: Timestamp,
    pub anchor_block: raw::ProbabilisticBlock,
    pub bridge_blocks: Vec<raw::ProbabilisticBlock>,
    pub descendant_blocks: Vec<raw::ProbabilisticBlock>,
    pub host_state_tx_hash: String,
    pub host_state_tx_output_index: u32,
    pub new_epoch_context: Option<raw::EpochContext>,
    pub is_checkpoint: bool,
}

impl crate::core::ics02_client::header::Header for Header {
    fn client_type(&self) -> ClientType {
        ClientType::CardanoProbabilistic
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
            new_epoch_context: raw.new_epoch_context,
            is_checkpoint: raw.is_checkpoint,
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
            new_epoch_context: value.new_epoch_context,
            is_checkpoint: value.is_checkpoint,
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
            PROBABILISTIC_HEADER_TYPE_URL => {
                decode_header(raw_any.value.deref()).map_err(Into::into)
            }
            _ => Err(Ics02Error::unknown_header_type(raw_any.type_url)),
        }
    }
}

impl From<Header> for Any {
    fn from(header: Header) -> Self {
        Any {
            type_url: PROBABILISTIC_HEADER_TYPE_URL.to_string(),
            value: Protobuf::<RawHeader>::encode_vec(header),
        }
    }
}

#[cfg(test)]
mod tests {
    use ibc_proto::cosmos::base::v1beta1::Coin;
    use ibc_proto::cosmos::crypto::secp256k1::PubKey;
    use ibc_proto::cosmos::tx::v1beta1::mode_info::{Single, Sum};
    use ibc_proto::cosmos::tx::v1beta1::{AuthInfo, Fee, ModeInfo, SignerInfo, TxBody, TxRaw};
    use ibc_proto::ibc::core::client::v1::MsgUpdateClient;

    use super::*;

    const FULL_BLOCK_CBOR_BYTES: usize = 17_943;
    const HEADER_CBOR_BYTES: usize = 860;
    const DESCENDANT_BLOCKS: usize = 24;
    const CHECKPOINT_BRIDGE_BLOCKS: usize = 32;

    fn block(
        revision_height: u64,
        block_cbor: Vec<u8>,
        header_cbor: Vec<u8>,
    ) -> raw::ProbabilisticBlock {
        raw::ProbabilisticBlock {
            height: Some(raw::Height {
                revision_number: 0,
                revision_height,
            }),
            slot: revision_height,
            hash: format!("block-{revision_height}"),
            epoch: 7,
            timestamp: 1_700_000_000_000_000_000,
            block_cbor,
            header_cbor,
        }
    }

    fn header(
        anchor_block: raw::ProbabilisticBlock,
        bridge_blocks: Vec<raw::ProbabilisticBlock>,
        descendant_blocks: Vec<raw::ProbabilisticBlock>,
    ) -> RawHeader {
        RawHeader {
            trusted_height: Some(raw::Height {
                revision_number: 0,
                revision_height: 10,
            }),
            anchor_block: Some(anchor_block),
            descendant_blocks,
            host_state_tx_hash: "host-state-tx".to_string(),
            host_state_tx_output_index: 0,
            bridge_blocks,
            new_epoch_context: None,
            is_checkpoint: false,
        }
    }

    fn raw_domain_round_trip(raw_header: RawHeader) -> RawHeader {
        let decoded = RawHeader::decode(raw_header.encode_to_vec().as_slice())
            .expect("raw header should decode");
        let domain = Header::try_from(decoded).expect("raw header should convert to domain header");
        let reencoded: RawHeader = domain.into();

        RawHeader::decode(reencoded.encode_to_vec().as_slice())
            .expect("re-encoded domain header should decode")
    }

    fn sized_block(revision_height: u64, compact: bool) -> raw::ProbabilisticBlock {
        raw::ProbabilisticBlock {
            height: Some(raw::Height {
                revision_number: 0,
                revision_height,
            }),
            slot: 10_000_000 + revision_height,
            hash: format!("{revision_height:064x}"),
            epoch: 500,
            timestamp: 1_700_000_000_000_000_000 + revision_height * 1_000_000_000,
            block_cbor: if compact {
                vec![]
            } else {
                vec![0x82; FULL_BLOCK_CBOR_BYTES]
            },
            header_cbor: if compact {
                vec![0x83; HEADER_CBOR_BYTES]
            } else {
                vec![]
            },
        }
    }

    fn sized_header(checkpoint: bool, compact: bool) -> RawHeader {
        const TRUSTED_HEIGHT: u64 = 1_000;

        let mut next_height = TRUSTED_HEIGHT + 1;
        let bridge_blocks = if checkpoint {
            (0..CHECKPOINT_BRIDGE_BLOCKS)
                .map(|_| {
                    let block = sized_block(next_height, compact);
                    next_height += 1;
                    block
                })
                .collect()
        } else {
            vec![]
        };
        let anchor_block = sized_block(next_height, checkpoint && compact);
        next_height += 1;
        let descendant_blocks = (0..DESCENDANT_BLOCKS)
            .map(|_| {
                let block = sized_block(next_height, compact);
                next_height += 1;
                block
            })
            .collect();

        RawHeader {
            trusted_height: Some(raw::Height {
                revision_number: 0,
                revision_height: TRUSTED_HEIGHT,
            }),
            anchor_block: Some(anchor_block),
            bridge_blocks,
            descendant_blocks,
            host_state_tx_hash: if checkpoint {
                String::new()
            } else {
                format!("{:064x}", TRUSTED_HEIGHT + 1)
            },
            host_state_tx_output_index: u32::from(!checkpoint),
            new_epoch_context: None,
            is_checkpoint: checkpoint,
        }
    }

    fn signed_update_tx(header: RawHeader) -> Vec<u8> {
        let header = Any {
            type_url: PROBABILISTIC_HEADER_TYPE_URL.to_string(),
            value: header.encode_to_vec(),
        };
        let update = MsgUpdateClient {
            client_id: "07-cardano-probabilistic-0".to_string(),
            client_message: Some(header),
            signer: "inj1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqe2hm49".to_string(),
        };
        let body = TxBody {
            messages: vec![Any {
                type_url: "/ibc.core.client.v1.MsgUpdateClient".to_string(),
                value: update.encode_to_vec(),
            }],
            memo: String::new(),
            timeout_height: 0,
            extension_options: vec![],
            non_critical_extension_options: vec![],
        };
        let public_key = PubKey {
            key: vec![0x02; 33],
        };
        #[allow(deprecated)]
        let auth_info = AuthInfo {
            signer_infos: vec![SignerInfo {
                public_key: Some(Any {
                    type_url: "/injective.crypto.v1beta1.ethsecp256k1.PubKey".to_string(),
                    value: public_key.encode_to_vec(),
                }),
                mode_info: Some(ModeInfo {
                    sum: Some(Sum::Single(Single { mode: 1 })),
                }),
                sequence: 42,
            }],
            fee: Some(Fee {
                amount: vec![Coin {
                    denom: "inj".to_string(),
                    amount: "500000000000000".to_string(),
                }],
                gas_limit: 5_000_000,
                payer: String::new(),
                granter: String::new(),
            }),
            tip: None,
        };

        TxRaw {
            body_bytes: body.encode_to_vec(),
            auth_info_bytes: auth_info.encode_to_vec(),
            signatures: vec![vec![0x5a; 64]],
        }
        .encode_to_vec()
    }

    fn assert_complete_signed_update_tx(encoded: &[u8]) {
        let tx = TxRaw::decode(encoded).expect("signed TxRaw should decode");
        assert_eq!(tx.signatures.len(), 1);
        assert_eq!(tx.signatures[0].len(), 64);

        let body = TxBody::decode(tx.body_bytes.as_slice()).expect("TxBody should decode");
        assert_eq!(body.messages.len(), 1);
        assert_eq!(
            body.messages[0].type_url,
            "/ibc.core.client.v1.MsgUpdateClient"
        );
        let update = MsgUpdateClient::decode(body.messages[0].value.as_slice())
            .expect("MsgUpdateClient should decode");
        assert_eq!(
            update
                .client_message
                .expect("client message should be present")
                .type_url,
            PROBABILISTIC_HEADER_TYPE_URL
        );

        let auth = AuthInfo::decode(tx.auth_info_bytes.as_slice()).expect("AuthInfo should decode");
        assert_eq!(auth.signer_infos.len(), 1);
        assert!(auth.fee.is_some());
    }

    #[test]
    fn header_cbor_tag_survives_raw_and_domain_reencoding() {
        let compact_header = vec![0xaa, 0xbb, 0xcc];
        let raw_block = raw::ProbabilisticBlock {
            header_cbor: compact_header.clone(),
            ..Default::default()
        };

        // Field 10 with a length-delimited wire type is encoded as 0x52.
        assert_eq!(
            raw_block.encode_to_vec(),
            vec![0x52, 0x03, 0xaa, 0xbb, 0xcc]
        );
        assert_eq!(
            raw::ProbabilisticBlock::decode(raw_block.encode_to_vec().as_slice())
                .expect("raw block should decode")
                .header_cbor,
            compact_header
        );

        let raw_header = header(
            block(11, vec![0x01], vec![]),
            vec![block(12, vec![], vec![0xaa, 0xbb, 0xcc])],
            vec![block(13, vec![], vec![0xdd, 0xee])],
        );
        let round_tripped = raw_domain_round_trip(raw_header.clone());

        assert_eq!(round_tripped, raw_header);
        assert_eq!(
            round_tripped.bridge_blocks[0].header_cbor,
            vec![0xaa, 0xbb, 0xcc]
        );
        assert!(round_tripped.bridge_blocks[0].block_cbor.is_empty());
        assert_eq!(
            round_tripped.descendant_blocks[0].header_cbor,
            vec![0xdd, 0xee]
        );
        assert!(round_tripped.descendant_blocks[0].block_cbor.is_empty());
    }

    #[test]
    fn legacy_block_cbor_survives_raw_and_domain_reencoding() {
        let legacy_block = vec![0x82, 0x01, 0x02];
        let raw_block = raw::ProbabilisticBlock {
            block_cbor: legacy_block.clone(),
            ..Default::default()
        };

        // Field 9 with a length-delimited wire type is encoded as 0x4a.
        assert_eq!(
            raw_block.encode_to_vec(),
            vec![0x4a, 0x03, 0x82, 0x01, 0x02]
        );
        let decoded_block = raw::ProbabilisticBlock::decode(raw_block.encode_to_vec().as_slice())
            .expect("legacy raw block should decode");
        assert_eq!(decoded_block.block_cbor, legacy_block);
        assert!(decoded_block.header_cbor.is_empty());

        let raw_header = header(
            block(11, vec![0x82, 0x01, 0x02], vec![]),
            vec![block(12, vec![0x83, 0x03, 0x04], vec![])],
            vec![block(13, vec![0x84, 0x05, 0x06], vec![])],
        );
        let round_tripped = raw_domain_round_trip(raw_header.clone());

        assert_eq!(round_tripped, raw_header);
        assert_eq!(
            round_tripped
                .anchor_block
                .expect("anchor block should remain present")
                .block_cbor,
            vec![0x82, 0x01, 0x02]
        );
        assert!(round_tripped.bridge_blocks[0].header_cbor.is_empty());
        assert!(round_tripped.descendant_blocks[0].header_cbor.is_empty());
    }

    #[test]
    fn signed_update_transaction_size_regression() {
        let cases = [
            ("minimum root", false, 25, 50_000, 440_000, 10),
            ("bounded checkpoint", true, 57, 65_000, 1_000_000, 15),
        ];

        for (name, checkpoint, block_count, compact_max, legacy_min, reduction) in cases {
            let compact_header = sized_header(checkpoint, true);
            let legacy_header = sized_header(checkpoint, false);
            assert_eq!(
                compact_header.bridge_blocks.len()
                    + compact_header.descendant_blocks.len()
                    + usize::from(compact_header.anchor_block.is_some()),
                block_count
            );

            let compact_tx = signed_update_tx(compact_header);
            let legacy_tx = signed_update_tx(legacy_header);
            assert_complete_signed_update_tx(&compact_tx);
            assert_complete_signed_update_tx(&legacy_tx);

            assert!(
                compact_tx.len() <= compact_max,
                "{name} compact signed TxRaw is {} bytes, expected at most {compact_max}",
                compact_tx.len()
            );
            assert!(
                legacy_tx.len() >= legacy_min,
                "{name} legacy signed TxRaw is {} bytes, expected at least {legacy_min}",
                legacy_tx.len()
            );
            assert!(
                compact_tx.len() * reduction < legacy_tx.len(),
                "{name} compact signed TxRaw is not at least {reduction}x smaller: compact={} legacy={}",
                compact_tx.len(),
                legacy_tx.len()
            );

            eprintln!(
                "{name}: compact={} bytes, legacy-full={} bytes, reduction={:.1}x",
                compact_tx.len(),
                legacy_tx.len(),
                legacy_tx.len() as f64 / compact_tx.len() as f64
            );
        }
    }
}
