//! Mithril-certified stake for anchored probabilistic clients.
//!
//! Mithril certifies the Cardano stake distribution of epoch N early in epoch
//! N+1, and that distribution elects the leaders of epoch N+2. Once a client
//! records it, the epoch's stake table must equal it and needs no challenge
//! period, so certificates are submitted as soon as Mithril publishes them.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ibc_proto::google::protobuf::Any;
use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw::MithrilStakeCertificates;
use prost::Message;

pub const MITHRIL_STAKE_CERTIFICATES_TYPE_URL: &str =
    "/ibc.lightclients.probabilistic.v1.MithrilStakeCertificates";

/// Refresh runs every few seconds. After an empty answer for an anchor epoch,
/// that epoch is not queried again for this long.
const EMPTY_ANSWER_RETRY: Duration = Duration::from_secs(10 * 60);
/// A committed submission moves the anchor on. This bounds resubmission of
/// certificates the destination rejected.
const SERVED_ANSWER_RETRY: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub struct MithrilStakePolls {
    next: HashMap<u64, Instant>,
}

impl MithrilStakePolls {
    pub fn due(&self, mithril_epoch: u64, now: Instant) -> bool {
        self.next
            .get(&mithril_epoch)
            .is_none_or(|next| now >= *next)
    }

    pub fn record(&mut self, mithril_epoch: u64, now: Instant, served: bool) {
        self.next.retain(|_, next| now < *next);
        let retry = if served {
            SERVED_ANSWER_RETRY
        } else {
            EMPTY_ANSWER_RETRY
        };
        self.next.insert(mithril_epoch, now + retry);
    }
}

/// Checks a Gateway answer before it is submitted as a client message.
pub fn validate_client_message(message: Any) -> Result<Any, String> {
    if message.type_url != MITHRIL_STAKE_CERTIFICATES_TYPE_URL {
        return Err(format!(
            "expected {MITHRIL_STAKE_CERTIFICATES_TYPE_URL}, got {}",
            message.type_url
        ));
    }
    let decoded = MithrilStakeCertificates::decode(message.value.as_slice())
        .map_err(|error| format!("undecodable certificates: {error}"))?;
    if decoded.certificates.is_empty() {
        return Err("the message carries no certificates".to_owned());
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_defers_only_that_epoch() {
        let start = Instant::now();
        let mut polls = MithrilStakePolls::default();
        assert!(polls.due(7, start));
        polls.record(7, start, false);
        assert!(!polls.due(7, start + Duration::from_secs(5)));
        assert!(polls.due(8, start + Duration::from_secs(5)));
        assert!(polls.due(7, start + EMPTY_ANSWER_RETRY));

        // Certificates the destination rejected are offered again sooner.
        polls.record(8, start + EMPTY_ANSWER_RETRY, true);
        assert_eq!(polls.next.len(), 1);
        assert!(!polls.due(8, start + EMPTY_ANSWER_RETRY));
        assert!(polls.due(8, start + EMPTY_ANSWER_RETRY + SERVED_ANSWER_RETRY));
    }

    #[test]
    fn only_certificate_messages_are_submitted() {
        let certificates = MithrilStakeCertificates {
            certificates: vec!["{}".to_owned()],
        };
        let message = Any {
            type_url: MITHRIL_STAKE_CERTIFICATES_TYPE_URL.to_owned(),
            value: certificates.encode_to_vec(),
        };
        assert_eq!(
            validate_client_message(message.clone()),
            Ok(message.clone())
        );

        let header = Any {
            type_url: "/ibc.lightclients.probabilistic.v1.ProbabilisticHeader".to_owned(),
            ..message.clone()
        };
        assert!(validate_client_message(header).is_err());
        let empty = Any {
            value: MithrilStakeCertificates::default().encode_to_vec(),
            ..message
        };
        assert!(validate_client_message(empty).is_err());
    }
}
