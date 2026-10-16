//! Readiness belongs to the destination verifier, including its paused clock.
use serde::Deserialize;

use crate::chain::endpoint::ChainStatus;

pub(crate) const QUERY_EPOCH_USABILITY: u32 = 13;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EpochUsabilityStatus {
    Usable,
    Pending,
    Unproposed,
    Frozen,
    Expired,
    Unsupported,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EpochUsability {
    pub status: EpochUsabilityStatus,
    pub epoch: u64,
    pub generation: u64,
    pub revision: u64,
    pub height: u64,
    pub timestamp: u64,
    #[serde(default)]
    pub reason: String,
}

impl EpochUsability {
    pub fn validate_at(
        &self,
        epoch: u64,
        generation: u64,
        committed: &ChainStatus,
    ) -> Result<(), String> {
        if self.epoch != epoch
            || self.generation != generation
            || self.revision != committed.height.revision_number()
            || self.height != committed.height.revision_height()
            || self.timestamp != committed.timestamp.nanoseconds()
        {
            return Err(
                "Epoch usability belongs to a different epoch, generation or committed height"
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibc_relayer_types::{timestamp::Timestamp, Height};

    #[test]
    fn query_matches_the_go_wire_encoding() {
        use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw;
        use prost::Message;
        let request = raw::QueryVerificationRequest {
            namespace: vec![0xaa, 0xbb],
            generation: 7,
            kind: QUERY_EPOCH_USABILITY,
            epoch: 8,
            client_id: "08-cardano-probabilistic-0".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            hex::encode(request.encode_to_vec()),
            "0a02aabb1007200d4808521a30382d63617264616e6f2d70726f626162696c69737469632d30"
        );
    }

    #[test]
    fn usability_must_match_the_queried_snapshot() {
        let committed = ChainStatus {
            height: Height::new(2, 17).unwrap(),
            timestamp: Timestamp::from_nanoseconds(100).unwrap(),
        };
        let response = serde_json::json!({
            "status":"usable", "epoch":8, "generation":3,
            "revision":2, "height":17, "timestamp":100,
        });
        let readiness: EpochUsability = serde_json::from_value(response.clone()).unwrap();
        assert!(readiness.validate_at(8, 3, &committed).is_ok());
        for field in ["epoch", "generation", "revision", "height", "timestamp"] {
            let mut stale = response.clone();
            stale[field] = 99.into();
            let readiness: EpochUsability = serde_json::from_value(stale).unwrap();
            assert!(readiness.validate_at(8, 3, &committed).is_err(), "{field}");
        }
        let mut unknown = response;
        unknown["status"] = "future_policy".into();
        assert!(serde_json::from_value::<EpochUsability>(unknown).is_err());
    }
}
