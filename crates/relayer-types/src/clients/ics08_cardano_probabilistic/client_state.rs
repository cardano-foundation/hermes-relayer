use std::time::Duration;

use prost::Message;
use serde_derive::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;

use crate::clients::ics08_cardano_probabilistic::error::Error;
use crate::clients::ics08_cardano_probabilistic::raw;
use crate::clients::ics08_cardano_probabilistic::validate_operational_certificate_counters;
use crate::core::ics02_client::client_state::ClientState as Ics2ClientState;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::core::ics24_host::identifier::ChainId;
use crate::Height;

pub const PROBABILISTIC_CLIENT_STATE_TYPE_URL: &str =
    "/ibc.lightclients.probabilistic.v1.ClientState";
const MAX_SUPPORTED_KES_EVOLUTIONS: u64 = 64;

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
    pub latest_checkpoint_height: Option<Height>,
    pub latest_checkpoint_block_hash: String,
    pub latest_checkpoint_epoch: u64,
    pub max_kes_evolutions: u64,
    pub latest_checkpoint_operational_certificate_counters: Vec<raw::OperationalCertificateCounter>,
    pub operational_certificate_state_initialized: bool,
    pub operational_certificate_counter_history_start_height: Option<Height>,
}

impl ClientState {
    /// Latest Cardano block whose chain progression has been authenticated.
    /// This can be ahead of `latest_height`, but it has no IBC commitment root.
    pub fn latest_verified_height(&self) -> Height {
        self.latest_checkpoint_height.unwrap_or(self.latest_height)
    }
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
            latest_checkpoint_height,
            latest_checkpoint_block_hash,
            latest_checkpoint_epoch,
            max_kes_evolutions,
            latest_checkpoint_operational_certificate_counters,
            operational_certificate_state_initialized,
            operational_certificate_counter_history_start_height,
        } = raw;

        let chain_id = ChainId::from_string(&raw_chain_id);

        let latest_height = latest_height
            .ok_or_else(|| Error::missing_field("latest_height"))?
            .try_into()?;

        let frozen_height = frozen_height.and_then(|h| h.try_into().ok());

        let latest_checkpoint_height = latest_checkpoint_height
            .map(TryInto::try_into)
            .transpose()?;

        let operational_certificate_counter_history_start_height =
            operational_certificate_counter_history_start_height
                .map(TryInto::try_into)
                .transpose()?;

        if let Some(checkpoint_height) = latest_checkpoint_height {
            if checkpoint_height < latest_height {
                return Err(Error::invalid_field(
                    "latest_checkpoint_height",
                    format!(
                        "must not be older than latest_height ({latest_height}), got {checkpoint_height}"
                    ),
                ));
            }
            if latest_checkpoint_block_hash.trim().is_empty() {
                return Err(Error::missing_field("latest_checkpoint_block_hash"));
            }
        } else if !latest_checkpoint_block_hash.is_empty() || latest_checkpoint_epoch != 0 {
            return Err(Error::invalid_field(
                "latest_checkpoint_height",
                "checkpoint hash and epoch require a checkpoint height".to_string(),
            ));
        }

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
        let is_legacy_operational_certificate_state = !operational_certificate_state_initialized
            && max_kes_evolutions == 0
            && latest_checkpoint_operational_certificate_counters.is_empty()
            && operational_certificate_counter_history_start_height.is_none();

        if !is_legacy_operational_certificate_state {
            if !operational_certificate_state_initialized {
                return Err(Error::invalid_field(
                    "operational_certificate_state_initialized",
                    "must be true unless all operational-certificate fields have their legacy defaults"
                        .to_string(),
                ));
            }
            if max_kes_evolutions == 0 || max_kes_evolutions > MAX_SUPPORTED_KES_EVOLUTIONS {
                return Err(Error::invalid_field(
                    "max_kes_evolutions",
                    format!("must be between 1 and {MAX_SUPPORTED_KES_EVOLUTIONS}"),
                ));
            }
            validate_operational_certificate_counters(
                &latest_checkpoint_operational_certificate_counters,
                "latest_checkpoint_operational_certificate_counters",
            )?;

            let history_start_height = operational_certificate_counter_history_start_height
                .ok_or_else(|| {
                    Error::missing_field("operational_certificate_counter_history_start_height")
                })?;
            let latest_counter_height = latest_checkpoint_height.unwrap_or(latest_height);
            if history_start_height > latest_counter_height {
                return Err(Error::invalid_field(
                    "operational_certificate_counter_history_start_height",
                    format!(
                        "must not be newer than the latest counter height ({latest_counter_height}), got {history_start_height}"
                    ),
                ));
            }
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
            latest_checkpoint_height,
            latest_checkpoint_block_hash,
            latest_checkpoint_epoch,
            max_kes_evolutions,
            latest_checkpoint_operational_certificate_counters,
            operational_certificate_state_initialized,
            operational_certificate_counter_history_start_height,
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
            latest_checkpoint_height: value.latest_checkpoint_height.map(Into::into),
            latest_checkpoint_block_hash: value.latest_checkpoint_block_hash,
            latest_checkpoint_epoch: value.latest_checkpoint_epoch,
            max_kes_evolutions: value.max_kes_evolutions,
            latest_checkpoint_operational_certificate_counters: value
                .latest_checkpoint_operational_certificate_counters,
            operational_certificate_state_initialized: value
                .operational_certificate_state_initialized,
            operational_certificate_counter_history_start_height: value
                .operational_certificate_counter_history_start_height
                .map(Into::into),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn counter(pool_byte: u8, sequence_number: u64) -> raw::OperationalCertificateCounter {
        raw::OperationalCertificateCounter {
            pool_id: vec![pool_byte; 28],
            sequence_number,
        }
    }

    fn raw_client_state() -> RawClientState {
        RawClientState {
            chain_id: "cardano-preprod".to_string(),
            latest_height: Some(RawHeight {
                revision_number: 0,
                revision_height: 10,
            }),
            trusting_period: Some(ibc_proto::google::protobuf::Duration {
                seconds: 86_400,
                nanos: 0,
            }),
            host_state_nft_policy_id: vec![1; 28],
            epoch_nonce: vec![2; 32],
            slots_per_kes_period: 129_600,
            current_epoch_start_slot: 1,
            current_epoch_end_slot_exclusive: 2,
            system_start_unix_ns: 1,
            slot_length_ns: 1,
            max_kes_evolutions: 62,
            operational_certificate_state_initialized: true,
            operational_certificate_counter_history_start_height: Some(RawHeight {
                revision_number: 0,
                revision_height: 10,
            }),
            ..Default::default()
        }
    }

    fn legacy_raw_client_state() -> RawClientState {
        let mut raw = raw_client_state();
        raw.max_kes_evolutions = 0;
        raw.latest_checkpoint_operational_certificate_counters
            .clear();
        raw.operational_certificate_state_initialized = false;
        raw.operational_certificate_counter_history_start_height = None;
        raw
    }

    #[test]
    fn legacy_state_uses_latest_consensus_height_as_verified_height() {
        let state = ClientState::try_from(legacy_raw_client_state())
            .expect("all-default legacy state must decode");
        assert_eq!(state.latest_verified_height(), state.latest_height);
        assert!(!state.operational_certificate_state_initialized);
    }

    #[test]
    fn checkpoint_state_uses_newer_verified_height_without_changing_latest_height() {
        let mut raw = raw_client_state();
        raw.latest_checkpoint_height = Some(RawHeight {
            revision_number: 0,
            revision_height: 20,
        });
        raw.latest_checkpoint_block_hash = "checkpoint-20".to_string();
        raw.latest_checkpoint_epoch = 8;

        let state = ClientState::try_from(raw).unwrap();
        assert_eq!(state.latest_height.revision_height(), 10);
        assert_eq!(state.latest_verified_height().revision_height(), 20);
    }

    #[test]
    fn any_round_trip_preserves_operational_certificate_state() {
        let sequence_above_u32 = u64::from(u32::MAX) + 1;
        let mut raw = raw_client_state();
        raw.latest_checkpoint_height = Some(RawHeight {
            revision_number: 0,
            revision_height: 10,
        });
        raw.latest_checkpoint_block_hash = "checkpoint-10".to_string();
        raw.latest_checkpoint_epoch = 7;
        raw.max_kes_evolutions = 62;
        raw.latest_checkpoint_operational_certificate_counters =
            vec![counter(1, 3), counter(2, sequence_above_u32)];

        let any = Any {
            type_url: PROBABILISTIC_CLIENT_STATE_TYPE_URL.to_string(),
            value: raw.encode_to_vec(),
        };
        let decoded = ClientState::try_from(any).expect("client state must decode");
        assert_eq!(decoded.max_kes_evolutions, 62);
        assert!(decoded.operational_certificate_state_initialized);
        assert_eq!(
            decoded.operational_certificate_counter_history_start_height,
            Some(Height::new(0, 10).unwrap())
        );
        assert_eq!(
            decoded.latest_checkpoint_operational_certificate_counters,
            vec![counter(1, 3), counter(2, sequence_above_u32)]
        );

        let reencoded: Any = decoded.into();
        let round_trip = RawClientState::decode(reencoded.value.as_slice())
            .expect("round-trip client state must decode");
        assert_eq!(round_trip, raw);
    }

    #[test]
    fn rejects_unsupported_max_kes_evolutions() {
        for value in [0, MAX_SUPPORTED_KES_EVOLUTIONS + 1] {
            let mut raw = raw_client_state();
            raw.max_kes_evolutions = value;
            assert!(ClientState::try_from(raw).is_err());
        }
    }

    #[test]
    fn rejects_noncanonical_operational_certificate_counters() {
        let cases = [
            vec![raw::OperationalCertificateCounter {
                pool_id: vec![1; 27],
                sequence_number: 1,
            }],
            vec![counter(1, 0)],
            vec![counter(1, 1), counter(1, 2)],
            vec![counter(2, 1), counter(1, 2)],
        ];

        for counters in cases {
            let mut raw = raw_client_state();
            raw.latest_checkpoint_operational_certificate_counters = counters;
            assert!(ClientState::try_from(raw).is_err());
        }
    }

    #[test]
    fn rejects_partially_initialized_operational_certificate_state() {
        let legacy = legacy_raw_client_state();

        let mut nonzero_max = legacy.clone();
        nonzero_max.max_kes_evolutions = 62;

        let mut counters = legacy.clone();
        counters.latest_checkpoint_operational_certificate_counters = vec![counter(1, 1)];

        let mut history_start = legacy;
        history_start.operational_certificate_counter_history_start_height = Some(RawHeight {
            revision_number: 0,
            revision_height: 10,
        });

        for raw in [nonzero_max, counters, history_start] {
            assert!(ClientState::try_from(raw).is_err());
        }
    }

    #[test]
    fn rejects_initialized_state_without_usable_history_start() {
        let mut missing = raw_client_state();
        missing.operational_certificate_counter_history_start_height = None;
        assert!(ClientState::try_from(missing).is_err());

        let mut newer_than_latest = raw_client_state();
        newer_than_latest.operational_certificate_counter_history_start_height = Some(RawHeight {
            revision_number: 0,
            revision_height: 11,
        });
        assert!(ClientState::try_from(newer_than_latest).is_err());
    }
}
