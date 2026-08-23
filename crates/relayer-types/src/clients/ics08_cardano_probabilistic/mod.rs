//! Cardano probabilistic light client types (`08-cardano-probabilistic`)
//!
//! Domain types for the Cosmos-side `08-cardano-probabilistic` light client.
//! Protobuf messages live under `ibc.lightclients.probabilistic.v1.*`.

pub mod client_state;
pub mod consensus_state;
pub mod error;
pub mod header;
pub mod misbehaviour;
pub mod raw;

pub use client_state::ClientState;
pub use consensus_state::ConsensusState;
pub use header::Header;
pub use misbehaviour::Misbehaviour;

pub(crate) fn validate_operational_certificate_counters(
    counters: &[raw::OperationalCertificateCounter],
    field: &'static str,
) -> Result<(), error::Error> {
    let mut previous_pool_id: Option<&[u8]> = None;
    for (index, counter) in counters.iter().enumerate() {
        if counter.pool_id.len() != 28 {
            return Err(error::Error::invalid_field(
                field,
                format!(
                    "entry {index} pool_id must be 28 bytes, got {}",
                    counter.pool_id.len()
                ),
            ));
        }
        if counter.sequence_number == 0 {
            return Err(error::Error::invalid_field(
                field,
                format!("entry {index} has a zero sequence_number; zero entries must be omitted"),
            ));
        }
        if previous_pool_id.is_some_and(|previous| previous >= counter.pool_id.as_slice()) {
            return Err(error::Error::invalid_field(
                field,
                format!(
                    "entry {index} is not in strictly increasing pool_id order; counters must be sorted and unique"
                ),
            ));
        }
        previous_pool_id = Some(counter.pool_id.as_slice());
    }

    Ok(())
}
