use std::time::Duration;

use prost::Message;
use serde_derive::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;

use crate::clients::ics08_cardano_probabilistic::error::Error;
use crate::clients::ics08_cardano_probabilistic::raw;
use crate::core::ics02_client::client_state::ClientState as Ics2ClientState;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::core::ics24_host::identifier::ChainId;
use crate::Height;

pub const PROBABILISTIC_CLIENT_STATE_TYPE_URL: &str =
    "/ibc.lightclients.probabilistic.v1.ClientState";

type RawClientState = raw::ClientState;
type RawHeight = raw::Height;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientState {
    pub chain_id: ChainId,
    pub latest_height: Height,
    pub frozen_height: Option<Height>,
    pub current_epoch: u64,
    pub trusting_period: Duration,
    pub upgrade_path: Vec<String>,
    pub host_state_nft_policy_id: Vec<u8>,
    pub host_state_nft_token_name: Vec<u8>,
    pub epoch_stake_distribution: Vec<raw::StakeDistributionEntry>,
    pub epoch_nonce: Vec<u8>,
    pub slots_per_kes_period: u64,
    pub current_epoch_start_slot: u64,
    pub current_epoch_end_slot_exclusive: u64,
    pub system_start_unix_ns: u64,
    pub slot_length_ns: u64,
    pub epoch_contexts: Vec<raw::EpochContext>,
}

impl Ics2ClientState for ClientState {
    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn client_type(&self) -> ClientType {
        ClientType::CardanoProbabilistic
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
            current_epoch,
            trusting_period,
            upgrade_path,
            host_state_nft_policy_id,
            host_state_nft_token_name,
            epoch_stake_distribution,
            epoch_nonce,
            slots_per_kes_period,
            current_epoch_start_slot,
            current_epoch_end_slot_exclusive,
            system_start_unix_ns,
            slot_length_ns,
            epoch_contexts,
        } = raw;

        let chain_id = ChainId::from_string(&raw_chain_id);

        let latest_height = latest_height
            .ok_or_else(|| Error::missing_field("latest_height"))?
            .try_into()?;

        let frozen_height = frozen_height.and_then(|h| h.try_into().ok());

        let trusting_period = trusting_period
            .and_then(|d| duration_from_proto(d).ok())
            .ok_or_else(|| Error::missing_field("trusting_period"))?;

        if host_state_nft_policy_id.is_empty() {
            return Err(Error::missing_field("host_state_nft_policy_id"));
        }

        if host_state_nft_policy_id.len() != 28 {
            return Err(Error::invalid_field(
                "host_state_nft_policy_id",
                format!("expected 28 bytes, got {}", host_state_nft_policy_id.len()),
            ));
        }
        if epoch_nonce.len() != 32 {
            return Err(Error::invalid_field(
                "epoch_nonce",
                format!("expected 32 bytes, got {}", epoch_nonce.len()),
            ));
        }
        if slots_per_kes_period == 0 {
            return Err(Error::invalid_field(
                "slots_per_kes_period",
                "must be greater than zero".to_string(),
            ));
        }
        if current_epoch_end_slot_exclusive <= current_epoch_start_slot {
            return Err(Error::invalid_field(
                "current_epoch_end_slot_exclusive",
                "must be greater than current_epoch_start_slot".to_string(),
            ));
        }
        if system_start_unix_ns == 0 {
            return Err(Error::invalid_field(
                "system_start_unix_ns",
                "must be greater than zero".to_string(),
            ));
        }
        if slot_length_ns == 0 {
            return Err(Error::invalid_field(
                "slot_length_ns",
                "must be greater than zero".to_string(),
            ));
        }

        Ok(Self {
            chain_id,
            latest_height,
            frozen_height,
            current_epoch,
            trusting_period,
            upgrade_path,
            host_state_nft_policy_id,
            host_state_nft_token_name,
            epoch_stake_distribution,
            epoch_nonce,
            slots_per_kes_period,
            current_epoch_start_slot,
            current_epoch_end_slot_exclusive,
            system_start_unix_ns,
            slot_length_ns,
            epoch_contexts,
        })
    }
}

impl From<ClientState> for RawClientState {
    fn from(value: ClientState) -> Self {
        RawClientState {
            chain_id: value.chain_id.to_string(),
            latest_height: Some(value.latest_height.into()),
            frozen_height: value.frozen_height.map(Into::into),
            current_epoch: value.current_epoch,
            trusting_period: Some(duration_to_proto(value.trusting_period)),
            upgrade_path: value.upgrade_path,
            host_state_nft_policy_id: value.host_state_nft_policy_id,
            host_state_nft_token_name: value.host_state_nft_token_name,
            epoch_stake_distribution: value.epoch_stake_distribution,
            epoch_nonce: value.epoch_nonce,
            slots_per_kes_period: value.slots_per_kes_period,
            current_epoch_start_slot: value.current_epoch_start_slot,
            current_epoch_end_slot_exclusive: value.current_epoch_end_slot_exclusive,
            system_start_unix_ns: value.system_start_unix_ns,
            slot_length_ns: value.slot_length_ns,
            epoch_contexts: value.epoch_contexts,
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

fn duration_from_proto(d: ibc_proto::google::protobuf::Duration) -> Result<Duration, Error> {
    let secs = u64::try_from(d.seconds)
        .map_err(|_| Error::timestamp_conversion("negative duration seconds".to_string()))?;

    let nanos = u32::try_from(d.nanos)
        .map_err(|_| Error::timestamp_conversion("negative duration nanos".to_string()))?;

    Ok(Duration::new(secs, nanos))
}

fn duration_to_proto(d: Duration) -> ibc_proto::google::protobuf::Duration {
    ibc_proto::google::protobuf::Duration {
        seconds: d.as_secs() as i64,
        nanos: d.subsec_nanos() as i32,
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
            PROBABILISTIC_CLIENT_STATE_TYPE_URL => {
                decode_state(raw_any.value.deref()).map_err(Into::into)
            }
            _ => Err(Ics02Error::unknown_client_state_type(raw_any.type_url)),
        }
    }
}

impl From<ClientState> for Any {
    fn from(value: ClientState) -> Self {
        Any {
            type_url: PROBABILISTIC_CLIENT_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawClientState>::encode_vec(value),
        }
    }
}
