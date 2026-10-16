use std::time::Duration;

/// Reserve the maximum 2,427 observation transactions at eight seconds per inclusion, source
/// settlement lookahead and a retry allowance before the checkpoint expires.
/// Activation needs its full six-hour response window.
/// A shorter configured lifetime makes maintenance immediately due.
pub(crate) fn maintenance_budget() -> Duration {
    Duration::from_secs(2427 * 8 + 128 * 20 + 30 * 60 + 6 * 60 * 60 + 10)
}
