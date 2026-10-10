//! Destination-owned history for independent probabilistic challenge queries.

use ibc_proto::google::protobuf::Any;
use ibc_relayer_types::clients::ics08_cardano_probabilistic::{
    consensus_state::PROBABILISTIC_CONSENSUS_STATE_TYPE_URL, raw,
};
use ibc_relayer_types::Height;
use prost::Message;

use crate::error::Error;

/// Mirror the core's trusted-height selection. These bytes are an evidence
/// selection hint, not a client state to install or an IBC commitment root.
pub(crate) fn context_from_store(
    latest: raw::ClientState,
    trusted_height: Height,
    mut read: impl FnMut(&[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    for challenge in &latest.epoch_context_challenges {
        let mut key = b"epochChallengeCheckpoint/".to_vec();
        key.extend_from_slice(&challenge.epoch.to_be_bytes());
        let bytes = read(&key)?;
        if bytes.is_empty() {
            continue;
        }
        // Private snapshots contain a bare ClientState, not protobuf Any.
        let snapshot = raw::ClientState::decode(bytes.as_slice())
            .map_err(|error| Error::query(format!("Invalid challenge snapshot: {error}")))?;
        let height = snapshot.latest_checkpoint_height.as_ref().ok_or_else(|| {
            Error::query("Challenge snapshot has no checkpoint height".to_owned())
        })?;
        if height.revision_number == trusted_height.revision_number()
            && height.revision_height == trusted_height.revision_height()
        {
            return encode_context(snapshot);
        }
    }

    let latest_height = latest
        .latest_checkpoint_height
        .as_ref()
        .or(latest.latest_height.as_ref());
    if latest_height.is_some_and(|height| {
        height.revision_number == trusted_height.revision_number()
            && height.revision_height == trusted_height.revision_height()
    }) {
        return encode_context(latest);
    }

    let key = format!("consensusStates/{trusted_height}");
    let bytes = read(key.as_bytes())?;
    let any = Any::decode(bytes.as_slice()).map_err(|error| {
        Error::query(format!(
            "Historical challenge consensus state is unavailable: {error}"
        ))
    })?;
    if any.type_url != PROBABILISTIC_CONSENSUS_STATE_TYPE_URL {
        return Err(Error::query(
            "Historical challenge consensus state has the wrong type".to_owned(),
        ));
    }
    let consensus = raw::ConsensusState::decode(any.value.as_slice())
        .map_err(|error| Error::query(format!("Invalid challenge consensus state: {error}")))?;
    let timestamp_offset = consensus
        .timestamp
        .checked_sub(latest.system_start_unix_ns)
        .filter(|offset| latest.slot_length_ns != 0 && offset % latest.slot_length_ns == 0)
        .ok_or_else(|| {
            Error::query("Historical challenge timestamp is not a Cardano slot time".to_owned())
        })?;
    let context = raw::ClientState {
        latest_checkpoint_height: Some(raw::Height {
            revision_number: trusted_height.revision_number(),
            revision_height: trusted_height.revision_height(),
        }),
        latest_checkpoint_block_hash: consensus.accepted_block_hash,
        latest_checkpoint_epoch: consensus.accepted_epoch,
        latest_checkpoint_slot: timestamp_offset / latest.slot_length_ns,
        latest_checkpoint_timestamp: consensus.timestamp,
        latest_checkpoint_settlement_credit: consensus.settlement_credit,
        latest_checkpoint_pool_production: consensus.pool_production,
        epoch_contexts: latest.epoch_contexts,
        ..Default::default()
    };
    encode_context(context)
}

fn encode_context(mut snapshot: raw::ClientState) -> Result<Vec<u8>, Error> {
    let epoch = snapshot.latest_checkpoint_epoch;
    // Private snapshots deliberately omit the flattened current client view.
    // Gateway uses current_epoch to position both the bitmap and credit state.
    snapshot.current_epoch = epoch;
    let production = snapshot
        .latest_checkpoint_pool_production
        .as_ref()
        .ok_or_else(|| {
            Error::query("Historical challenge production history is unavailable".to_owned())
        })?;
    let credit = snapshot
        .latest_checkpoint_settlement_credit
        .as_ref()
        .ok_or_else(|| {
            Error::query("Historical challenge settlement credit is unavailable".to_owned())
        })?;
    if production.epoch != epoch || credit.epoch != epoch {
        return Err(Error::query(
            "Historical challenge history has the wrong epoch".to_owned(),
        ));
    }
    snapshot
        .epoch_contexts
        .retain(|context| context.epoch == epoch);
    if snapshot.epoch_contexts.len() != 1 {
        return Err(Error::query(
            "Historical challenge epoch stake context is unavailable".to_owned(),
        ));
    }
    snapshot.epoch_context_challenges.clear();
    Ok(snapshot.encode_to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_snapshot() -> raw::ClientState {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/challenge-settlement.json")).unwrap();
        raw::ClientState::decode(
            hex::decode(fixture["snapshot_hex"].as_str().unwrap())
                .unwrap()
                .as_slice(),
        )
        .unwrap()
    }

    #[test]
    fn rootless_pre_proposal_snapshot_restores_epoch_and_history() {
        let snapshot = fixture_snapshot();
        assert_eq!(snapshot.current_epoch, 0); // Private core snapshots omit it.
        let mut latest = snapshot.clone();
        latest.current_epoch = 8;
        latest
            .latest_checkpoint_height
            .as_mut()
            .unwrap()
            .revision_height = 110;
        latest.latest_checkpoint_epoch = 8;
        latest.latest_checkpoint_pool_production = Some(raw::PoolProductionHistory {
            epoch: 8,
            pools: vec![],
        });
        latest.latest_checkpoint_settlement_credit = Some(raw::SettlementCreditState {
            epoch: 8,
            reference: vec![],
        });
        latest.epoch_context_challenges = vec![raw::EpochContextChallenge {
            epoch: 8,
            usable_after_unix_ns: 1,
        }];
        let bytes = context_from_store(latest, Height::new(0, 99).unwrap(), |key| {
            assert_eq!(
                key,
                [b"epochChallengeCheckpoint/".as_slice(), &8u64.to_be_bytes()].concat()
            );
            Ok(snapshot.encode_to_vec())
        })
        .unwrap();
        let restored = raw::ClientState::decode(bytes.as_slice()).unwrap();
        assert_eq!(restored.current_epoch, 7);
        assert_eq!(
            restored.latest_checkpoint_pool_production,
            snapshot.latest_checkpoint_pool_production
        );
        assert_eq!(
            restored.latest_checkpoint_settlement_credit,
            snapshot.latest_checkpoint_settlement_credit
        );
        assert_eq!(
            restored.latest_checkpoint_height,
            snapshot.latest_checkpoint_height
        );
        assert_eq!(restored.epoch_contexts, snapshot.epoch_contexts);
    }

    #[test]
    fn ordinary_consensus_checkpoint_restores_its_history() {
        let snapshot = fixture_snapshot();
        let mut latest = snapshot.clone();
        latest
            .latest_checkpoint_height
            .as_mut()
            .unwrap()
            .revision_height = 110;
        latest.system_start_unix_ns = 1_700_000_000_000_000_000;
        latest.slot_length_ns = 1_000_000_000;
        let consensus = raw::ConsensusState {
            accepted_block_hash: "hash-99".into(),
            accepted_epoch: 7,
            timestamp: snapshot.latest_checkpoint_timestamp,
            settlement_credit: snapshot.latest_checkpoint_settlement_credit.clone(),
            pool_production: snapshot.latest_checkpoint_pool_production.clone(),
            ..Default::default()
        };
        let bytes = context_from_store(latest, Height::new(0, 99).unwrap(), |key| {
            assert_eq!(key, b"consensusStates/0-99");
            Ok(Any {
                type_url: PROBABILISTIC_CONSENSUS_STATE_TYPE_URL.into(),
                value: consensus.encode_to_vec(),
            }
            .encode_to_vec())
        })
        .unwrap();
        let restored = raw::ClientState::decode(bytes.as_slice()).unwrap();
        assert_eq!(restored.current_epoch, 7);
        assert_eq!(restored.latest_checkpoint_slot, 990);
        assert_eq!(
            restored.latest_checkpoint_settlement_credit,
            snapshot.latest_checkpoint_settlement_credit
        );
        assert_eq!(
            restored.latest_checkpoint_pool_production,
            snapshot.latest_checkpoint_pool_production
        );
    }

    #[test]
    fn matching_current_checkpoint_needs_no_historical_read() {
        let snapshot = fixture_snapshot();
        let bytes = context_from_store(snapshot, Height::new(0, 99).unwrap(), |_| {
            panic!("no store query expected")
        })
        .unwrap();
        assert_eq!(
            raw::ClientState::decode(bytes.as_slice())
                .unwrap()
                .current_epoch,
            7
        );
    }

    #[test]
    fn mismatched_snapshot_does_not_replace_requested_checkpoint() {
        let mut latest = fixture_snapshot();
        latest.epoch_context_challenges = vec![raw::EpochContextChallenge {
            epoch: 8,
            usable_after_unix_ns: 1,
        }];
        let mut other = latest.clone();
        other
            .latest_checkpoint_height
            .as_mut()
            .unwrap()
            .revision_height = 88;
        let bytes = context_from_store(latest, Height::new(0, 99).unwrap(), |_| {
            Ok(other.encode_to_vec())
        })
        .unwrap();
        assert_eq!(
            raw::ClientState::decode(bytes.as_slice())
                .unwrap()
                .latest_checkpoint_height
                .unwrap()
                .revision_height,
            99
        );
    }

    #[test]
    fn missing_or_wrongly_positioned_history_fails_without_observer_fallback() {
        for missing_production in [true, false] {
            let mut snapshot = fixture_snapshot();
            if missing_production {
                snapshot.latest_checkpoint_pool_production = None;
            } else {
                snapshot
                    .latest_checkpoint_settlement_credit
                    .as_mut()
                    .unwrap()
                    .epoch = 8;
            }
            assert!(
                context_from_store(snapshot, Height::new(0, 99).unwrap(), |_| panic!(
                    "no fallback read expected"
                ))
                .is_err()
            );
        }
        let mut latest = fixture_snapshot();
        latest
            .latest_checkpoint_height
            .as_mut()
            .unwrap()
            .revision_height = 110;
        assert!(context_from_store(latest, Height::new(0, 99).unwrap(), |_| Ok(vec![])).is_err());
    }
}
