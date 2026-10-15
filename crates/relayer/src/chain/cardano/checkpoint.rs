use std::time::Duration;

/// Reserve the enforced maximum work at ten seconds per inclusion, source
/// settlement lookahead and a retry allowance before the checkpoint expires.
/// Activation needs its full twelve-hour response window.
/// A shorter configured lifetime makes maintenance immediately due.
pub(crate) fn maintenance_budget() -> Duration {
    Duration::from_secs(4096 * 10 + 128 * 20 + 30 * 60 + 12 * 60 * 60 + 10)
}
