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

/// `sha256(network passphrase)`.
const NETWORK_ID_BYTES: usize = 32;
/// A Soroban contract id.
const CONTRACT_ID_BYTES: usize = 32;

type RawClientState = raw::ClientState;
type RawHeight = raw::Height;

/// A trust root that applies from `valid_from` onward.
///
/// Stellar validator sets rotate, and a header for an old slot must still be
/// verifiable against the set that was live then — hence a list rather than a
/// single set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumConfig {
    pub quorum_set_xdr: Vec<u8>,
    pub valid_from: u64,
}

impl QuorumConfig {
    /// `sha256(quorum_set_xdr)` — the identity a deployment pins.
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(&self.quorum_set_xdr).into()
    }
}

impl From<raw::QuorumConfig> for QuorumConfig {
    fn from(r: raw::QuorumConfig) -> Self {
        Self {
            quorum_set_xdr: r.quorum_set_xdr,
            valid_from: r.valid_from,
        }
    }
}

impl From<QuorumConfig> for raw::QuorumConfig {
    fn from(v: QuorumConfig) -> Self {
        Self {
            quorum_set_xdr: v.quorum_set_xdr,
            valid_from: v.valid_from,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientState {
    pub chain_id: ChainId,
    pub latest_height: Height,
    pub frozen_height: Option<Height>,
    /// The trust root. Everything the light client will ever accept is decided
    /// here — see [`ClientState::verify_quorum_fingerprints`].
    pub quorum_configs: Vec<QuorumConfig>,
    pub proof_specs: Vec<Vec<u8>>,
    pub network_id: Vec<u8>,
    /// Seconds after which a consensus state is too old to be trusted. Zero
    /// disables expiry, which is only appropriate for a devnet.
    pub max_consensus_age: u64,
    /// The router whose `ibc_root` event binds the IBC state root.
    pub router_contract_id: Vec<u8>,
    /// The symbol that event is topic-tagged with.
    pub root_event_topic: Vec<u8>,
    #[serde(skip)]
    pub wasm_checksum: Option<Vec<u8>>,
}

impl ClientState {
    /// Check the quorum sets against fingerprints this deployment ships with.
    ///
    /// The trust root is the one input that cannot be delegated. Quorum sets
    /// reach the relayer over the gateway, which is untrusted transport — a
    /// compromised or merely wrong gateway could otherwise seed a client with a
    /// validator set of its choosing, and every subsequent proof would verify
    /// happily against it.
    ///
    /// Pinning the sha256 makes that substitution a startup failure instead of
    /// a silent compromise. Rotating the real set is then a deliberate,
    /// reviewable change to the pinned constant.
    pub fn verify_quorum_fingerprints(&self, expected: &[[u8; 32]]) -> Result<(), Error> {
        if self.quorum_configs.is_empty() {
            return Err(Error::missing_field("quorum_configs"));
        }
        if expected.is_empty() {
            return Err(Error::invalid_field(
                "quorum_configs",
                "no pinned fingerprints to check against; refusing to trust an \
                 unverified validator set"
                    .to_string(),
            ));
        }

        for (i, config) in self.quorum_configs.iter().enumerate() {
            let actual = config.fingerprint();
            if !expected.contains(&actual) {
                return Err(Error::invalid_field(
                    "quorum_configs",
                    format!(
                        "entry {i} has fingerprint {} which is not pinned for this network",
                        hex_encode(&actual)
                    ),
                ));
            }
        }
        Ok(())
    }

    /// The quorum set that governs `slot`: the one with the greatest
    /// `valid_from` that does not postdate it.
    pub fn quorum_config_for(&self, slot: u64) -> Option<&QuorumConfig> {
        self.quorum_configs
            .iter()
            .filter(|c| c.valid_from <= slot)
            .max_by_key(|c| c.valid_from)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
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
            quorum_configs,
            proof_specs,
            network_id,
            max_consensus_age,
            router_contract_id,
            root_event_topic,
        } = raw;

        let chain_id = ChainId::from_string(&raw_chain_id);

        let latest_height = latest_height
            .ok_or_else(|| Error::missing_field("latest_height"))?
            .try_into()?;

        let frozen_height = frozen_height.and_then(|h| h.try_into().ok());

        if network_id.len() != NETWORK_ID_BYTES {
            return Err(Error::invalid_field(
                "network_id",
                format!(
                    "expected {NETWORK_ID_BYTES} bytes, got {}",
                    network_id.len()
                ),
            ));
        }

        // An empty router id means no state root can ever be bound, so the
        // client would verify consensus and prove nothing about Soroban state.
        // Allowed, because a consensus-only client is a legitimate
        // intermediate, but a wrong-length one is a configuration error.
        if !router_contract_id.is_empty() && router_contract_id.len() != CONTRACT_ID_BYTES {
            return Err(Error::invalid_field(
                "router_contract_id",
                format!(
                    "expected {CONTRACT_ID_BYTES} bytes, got {}",
                    router_contract_id.len()
                ),
            ));
        }

        Ok(Self {
            chain_id,
            latest_height,
            frozen_height,
            quorum_configs: quorum_configs.into_iter().map(Into::into).collect(),
            proof_specs,
            network_id,
            max_consensus_age,
            router_contract_id,
            root_event_topic,
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
            quorum_configs: value.quorum_configs.into_iter().map(Into::into).collect(),
            proof_specs: value.proof_specs,
            network_id: value.network_id,
            max_consensus_age: value.max_consensus_age,
            router_contract_id: value.router_contract_id,
            root_event_topic: value.root_event_topic,
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
                let wasm =
                    RawWasmClientState::decode(raw_any.value.deref()).map_err(Error::decode)?;
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

    fn quorum_set(seed: u8) -> Vec<u8> {
        let mut out = 3u32.to_be_bytes().to_vec(); // threshold
        out.extend_from_slice(&1u32.to_be_bytes()); // one validator
        out.extend_from_slice(&0u32.to_be_bytes()); // PUBLIC_KEY_TYPE_ED25519
        out.extend_from_slice(&[seed; 32]);
        out.extend_from_slice(&0u32.to_be_bytes()); // no inner sets
        out
    }

    fn sample_state(wasm_checksum: Option<Vec<u8>>) -> ClientState {
        ClientState {
            chain_id: ChainId::from_string("stellar-testnet"),
            latest_height: Height::new(0, 100).unwrap(),
            frozen_height: None,
            quorum_configs: vec![QuorumConfig {
                quorum_set_xdr: quorum_set(0x42),
                valid_from: 0,
            }],
            proof_specs: vec![],
            network_id: vec![0x33; 32],
            max_consensus_age: 1_209_600,
            router_contract_id: vec![0x5a; 32],
            root_event_topic: b"ibc_root".to_vec(),
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
    }

    #[test]
    fn wasm_any_uses_wasm_type_url_and_round_trips_with_checksum() {
        let checksum = vec![0xAB; 32];
        let original = sample_state(Some(checksum.clone()));
        let any: Any = original.clone().into();
        assert_eq!(any.type_url, WASM_CLIENT_STATE_TYPE_URL);
        let decoded: ClientState = any.try_into().unwrap();
        assert_eq!(decoded.quorum_configs, original.quorum_configs);
        assert_eq!(decoded.wasm_checksum, Some(checksum));
    }

    #[test]
    fn the_trust_root_survives_a_round_trip_byte_for_byte() {
        let original = sample_state(None);
        let raw: RawClientState = original.clone().into();
        let decoded: ClientState = raw.try_into().unwrap();

        // The quorum set is hashed by the light client to match each signer's
        // commitQuorumSetHash, so a single byte of drift breaks every update.
        assert_eq!(
            decoded.quorum_configs[0].quorum_set_xdr,
            original.quorum_configs[0].quorum_set_xdr
        );
        assert_eq!(decoded.router_contract_id, original.router_contract_id);
        assert_eq!(decoded.root_event_topic, original.root_event_topic);
        assert_eq!(decoded.max_consensus_age, original.max_consensus_age);
    }

    // --- the pinned trust root -------------------------------------------

    #[test]
    fn a_pinned_quorum_set_is_accepted() {
        let state = sample_state(None);
        let pinned = [state.quorum_configs[0].fingerprint()];
        assert!(state.verify_quorum_fingerprints(&pinned).is_ok());
    }

    /// The substitution the pin exists to catch: the gateway is untrusted
    /// transport, so a validator set it supplies must match something the
    /// operator shipped.
    #[test]
    fn an_unpinned_quorum_set_is_refused() {
        let mut state = sample_state(None);
        let pinned = [state.quorum_configs[0].fingerprint()];

        state.quorum_configs[0].quorum_set_xdr = quorum_set(0xEE);
        let err = state.verify_quorum_fingerprints(&pinned).unwrap_err();
        assert!(
            err.to_string().contains("not pinned"),
            "unexpected error: {err}"
        );
    }

    /// Failing open here would defeat the whole mechanism.
    #[test]
    fn an_empty_pin_list_refuses_rather_than_permits() {
        let state = sample_state(None);
        assert!(state.verify_quorum_fingerprints(&[]).is_err());
    }

    #[test]
    fn a_client_state_with_no_quorum_config_is_refused() {
        let mut state = sample_state(None);
        state.quorum_configs.clear();
        assert!(state.verify_quorum_fingerprints(&[[0u8; 32]]).is_err());
    }

    // --- rotation ---------------------------------------------------------

    /// A header for an old slot must still resolve to the set that was live
    /// then, or rotating validators would invalidate history.
    #[test]
    fn the_quorum_config_for_a_slot_is_the_latest_one_not_after_it() {
        let mut state = sample_state(None);
        state.quorum_configs = vec![
            QuorumConfig {
                quorum_set_xdr: quorum_set(0x01),
                valid_from: 0,
            },
            QuorumConfig {
                quorum_set_xdr: quorum_set(0x02),
                valid_from: 500,
            },
        ];

        assert_eq!(state.quorum_config_for(499).unwrap().valid_from, 0);
        assert_eq!(state.quorum_config_for(500).unwrap().valid_from, 500);
        assert_eq!(state.quorum_config_for(10_000).unwrap().valid_from, 500);
    }

    #[test]
    fn a_slot_before_every_config_has_none() {
        let mut state = sample_state(None);
        state.quorum_configs = vec![QuorumConfig {
            quorum_set_xdr: quorum_set(0x01),
            valid_from: 500,
        }];
        assert!(state.quorum_config_for(499).is_none());
    }

    #[test]
    fn a_wrong_length_network_id_is_refused() {
        let mut state = sample_state(None);
        state.network_id = vec![0x33; 16];
        let raw: RawClientState = state.into();
        assert!(ClientState::try_from(raw).is_err());
    }
}
