use core::time::Duration;
use std::time::Instant;

use tracing::{debug, error_span, info};

use crate::{
    chain::{endpoint::HostStateHeartbeatOutcome, handle::ChainHandle},
    util::task::{spawn_background_task, Next, TaskError, TaskHandle},
};

pub fn spawn_host_state_heartbeat_worker<Chain: ChainHandle>(
    chain: Chain,
    interval: Duration,
) -> TaskHandle {
    let span = error_span!("worker.cardano.host_state_heartbeat", chain = %chain.id());
    let interval = interval.max(Duration::from_secs(1));
    let shutdown_poll_interval = interval.min(Duration::from_secs(5));
    let max_idle_check_interval = Duration::from_secs(60 * 60);
    let mut next_check = Instant::now();

    spawn_background_task(
        span,
        Some(shutdown_poll_interval),
        move || -> Result<Next, TaskError<String>> {
            let now = Instant::now();
            if now < next_check {
                return Ok(Next::Continue);
            }
            next_check = now + interval;

            match chain.submit_host_state_heartbeat() {
                Ok(HostStateHeartbeatOutcome::NotRequired {
                    current_epoch,
                    host_state_epoch,
                    next_check_delay_ms,
                }) => {
                    next_check = Instant::now()
                        + suggested_delay(next_check_delay_ms, interval, max_idle_check_interval);
                    debug!(
                        current_epoch,
                        host_state_epoch, "Cardano HostState heartbeat is not required"
                    );
                }
                Ok(HostStateHeartbeatOutcome::Submitted {
                    tx_hash,
                    height,
                    current_epoch,
                    previous_host_state_epoch,
                    next_check_delay_ms,
                }) => {
                    next_check = Instant::now()
                        + suggested_delay(next_check_delay_ms, interval, max_idle_check_interval);
                    info!(
                        %tx_hash,
                        ?height,
                        current_epoch,
                        previous_host_state_epoch,
                        "submitted Cardano HostState epoch heartbeat"
                    );
                }
                Ok(HostStateHeartbeatOutcome::Unsupported) => {
                    return Err(TaskError::Fatal(Box::new(format!(
                        "chain {} does not support HostState heartbeats",
                        chain.id()
                    ))));
                }
                Err(error) => {
                    // A concurrent relayer may have consumed the HostState UTxO after
                    // this relayer built its transaction. Treat every failed attempt as
                    // retryable; the next poll asks the Gateway for fresh epoch state.
                    next_check = Instant::now() + interval;
                    return Err(TaskError::Ignore(Box::new(format!(
                        "HostState heartbeat attempt failed: {error}"
                    ))));
                }
            }

            Ok(Next::Continue)
        },
    )
}

fn suggested_delay(
    delay_ms: u64,
    retry_interval: Duration,
    max_idle_interval: Duration,
) -> Duration {
    if delay_ms == 0 {
        retry_interval
    } else {
        Duration::from_millis(delay_ms)
            .min(max_idle_interval)
            .max(Duration::from_secs(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_delay_replaces_minute_poll_and_is_capped_for_rollback_checks() {
        let retry = Duration::from_secs(60);
        let max_idle = Duration::from_secs(60 * 60);

        assert_eq!(suggested_delay(0, retry, max_idle), retry);
        assert_eq!(
            suggested_delay(30 * 60 * 1000, retry, max_idle),
            Duration::from_secs(30 * 60)
        );
        assert_eq!(
            suggested_delay(5 * 24 * 60 * 60 * 1000, retry, max_idle),
            max_idle
        );
    }
}
