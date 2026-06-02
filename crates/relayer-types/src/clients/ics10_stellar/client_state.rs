use std::time::Duration;

use prost::Message;
use serde_derive::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::lightclients::wasm::v1::ClientState as RawWasmClientState;
use ibc_proto::Protobuf;

use crate::clients::ics10_stellar::error::Error;
use crate::clients::ics10_stellar::raw;
use crate::core::ics02_client::client_state::ClientState as Ics2ClientState;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::core::ics24_host::identifier::ChainId;
use crate::Height;

pub const STELLAR_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.stellar.v1.ClientState";
pub const WASM_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.wasm.v1.ClientState";

const ED25519_PUBLIC_KEY_BYTES: usize = 32;

type RawClientState = raw::ClientState;
type RawHeight = raw::Height;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientState {
    pub chain_id: ChainId,
    pub latest_height: Height,
    pub frozen_height: Option<Height>,
    pub trusted_validators: Vec<Vec<u8>>,
    pub proof_specs: Vec<Vec<u8>>,
    pub network_id: Vec<u8>,
    #[serde(skip)]
    pub wasm_checksum: Option<Vec<u8>>,
}

impl Ics2ClientState for ClientState {
    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn client_type(&self) -> ClientType {
        ClientType::Stellar
    }

    fn latest_height(&self) -> Height {
        self.latest_height
    }

    fn frozen_height(&self) -> Option<Height> {
        self.frozen_height
    }

    fn expired(&self, _elapsed: Duration) -> bool {
        false
    }
}

impl Protobuf<RawClientState> for ClientState {}

impl TryFrom<RawClientState> for ClientState {
    type Error = Error;

    fn try_from(raw: RawClientState) -> Result<Self, Self::Error> {
        let RawClientState {
            chain_id: raw_chain_id,
            latest_height,
            frozen_height,
            trusted_validators,
            proof_specs,
            network_id,
        } = raw;

        let chain_id = ChainId::from_string(&raw_chain_id);

        let latest_height = latest_height
            .ok_or_else(|| Error::missing_field("latest_height"))?
            .try_into()?;

        let frozen_height = frozen_height.and_then(|h| h.try_into().ok());

        for (i, v) in trusted_validators.iter().enumerate() {
            if v.len() != ED25519_PUBLIC_KEY_BYTES {
                return Err(Error::invalid_field(
                    "trusted_validators",
                    format!(
                        "entry {i}: expected {ED25519_PUBLIC_KEY_BYTES} bytes, got {}",
                        v.len()
                    ),
                ));
            }
        }

        Ok(Self {
            chain_id,
            latest_height,
            frozen_height,
            trusted_validators,
            proof_specs,
            network_id,
            wasm_checksum: None,
        })
    }
}

impl From<ClientState> for RawClientState {
    fn from(value: ClientState) -> Self {
        RawClientState {
            chain_id: value.chain_id.to_string(),
            latest_height: Some(value.latest_height.into()),
            frozen_height: value.frozen_height.map(Into::into),
            trusted_validators: value.trusted_validators,
            proof_specs: value.proof_specs,
            network_id: value.network_id,
        }
    }
}

impl TryFrom<RawHeight> for Height {
    type Error = Error;

    fn try_from(raw: RawHeight) -> Result<Self, Self::Error> {
        Height::new(raw.revision_number, raw.revision_height).map_err(|e| {
            Error::height_conversion(format!(
                "failed to construct height from revision_number={}, revision_height={}: {e}",
                raw.revision_number, raw.revision_height
            ))
        })
    }
}

impl From<Height> for RawHeight {
    fn from(value: Height) -> Self {
        RawHeight {
            revision_number: value.revision_number(),
            revision_height: value.revision_height(),
        }
    }
}

impl Protobuf<Any> for ClientState {}

impl TryFrom<Any> for ClientState {
    type Error = Ics02Error;

    fn try_from(raw_any: Any) -> Result<Self, Ics02Error> {
        use core::ops::Deref;

        fn decode_state(bytes: &[u8]) -> Result<ClientState, Error> {
            RawClientState::decode(bytes)
                .map_err(Error::decode)?
                .try_into()
        }

        match raw_any.type_url.as_str() {
            STELLAR_CLIENT_STATE_TYPE_URL => {
                decode_state(raw_any.value.deref()).map_err(Into::into)
            }
            WASM_CLIENT_STATE_TYPE_URL => {
                let wasm = RawWasmClientState::decode(raw_any.value.deref())
                    .map_err(|e| Error::decode(e))?;
                let mut inner = decode_state(&wasm.data).map_err(Into::<Ics02Error>::into)?;
                if !wasm.checksum.is_empty() {
                    inner.wasm_checksum = Some(wasm.checksum);
                }
                Ok(inner)
            }
            _ => Err(Ics02Error::unknown_client_state_type(raw_any.type_url)),
        }
    }
}

impl From<ClientState> for Any {
    fn from(value: ClientState) -> Self {
        if let Some(checksum) = value.wasm_checksum.clone() {
            let latest_height = value.latest_height;
            let inner_bytes = Protobuf::<RawClientState>::encode_vec(value);
            let wasm = RawWasmClientState {
                data: inner_bytes,
                checksum,
                latest_height: Some(ibc_proto::ibc::core::client::v1::Height {
                    revision_number: latest_height.revision_number(),
                    revision_height: latest_height.revision_height(),
                }),
            };
            return Any {
                type_url: WASM_CLIENT_STATE_TYPE_URL.to_string(),
                value: wasm.encode_to_vec(),
            };
        }
        Any {
            type_url: STELLAR_CLIENT_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawClientState>::encode_vec(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state(wasm_checksum: Option<Vec<u8>>) -> ClientState {
        ClientState {
            chain_id: ChainId::from_string("stellar-testnet"),
            latest_height: Height::new(0, 100).unwrap(),
            frozen_height: None,
            trusted_validators: vec![vec![0x42; 32]],
            proof_specs: vec![],
            network_id: vec![0x33; 32],
            wasm_checksum,
        }
    }

    #[test]
    fn native_any_uses_stellar_type_url_and_round_trips() {
        let original = sample_state(None);
        let any: Any = original.clone().into();
        assert_eq!(any.type_url, STELLAR_CLIENT_STATE_TYPE_URL);
        let decoded: ClientState = any.try_into().unwrap();
        assert_eq!(decoded, original);
        assert!(decoded.wasm_checksum.is_none());
    }

    #[test]
    fn wasm_any_uses_wasm_type_url_and_round_trips_with_checksum() {
        let checksum = vec![0xAB; 32];
        let original = sample_state(Some(checksum.clone()));
        let any: Any = original.clone().into();
        assert_eq!(any.type_url, WASM_CLIENT_STATE_TYPE_URL);
        let decoded: ClientState = any.try_into().unwrap();
        assert_eq!(decoded.chain_id, original.chain_id);
        assert_eq!(decoded.latest_height, original.latest_height);
        assert_eq!(decoded.network_id, original.network_id);
        assert_eq!(decoded.wasm_checksum, Some(checksum));
    }

    #[test]
    fn network_id_is_carried_through_native_round_trip() {
        let original = sample_state(None);
        let raw: RawClientState = original.clone().into();
        assert_eq!(raw.network_id, original.network_id);
        let decoded: ClientState = raw.try_into().unwrap();
        assert_eq!(decoded.network_id, original.network_id);
    }
}
