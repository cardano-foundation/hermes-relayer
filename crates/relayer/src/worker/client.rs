use core::convert::Infallible;
use core::time::Duration;
use crossbeam_channel::Receiver;
use retry::delay::Fibonacci;
use retry::{retry_with_index, OperationResult};
use std::{collections::VecDeque, time::Instant};
use tracing::{debug, error_span, trace, warn};

use ibc_relayer_types::core::ics02_client::client_type::ClientType;
use ibc_relayer_types::core::ics02_client::events::UpdateClient;
use ibc_relayer_types::core::ics24_host::identifier::ClientId;
use ibc_relayer_types::events::IbcEvent;

use crate::telemetry;
use crate::util::retry::clamp_total;
use crate::util::task::{spawn_background_task, Next, TaskError, TaskHandle};
use crate::{
    chain::handle::ChainHandle,
    foreign_client::{ForeignClient, HasExpiredOrFrozenError, MisbehaviourResults},
};

use super::WorkerCmd;

const REFRESH_CHECK_INTERVAL: Duration = Duration::from_secs(5); // 5 seconds
const INITIAL_BACKOFF: Duration = Duration::from_secs(5); // 5 seconds
const MAX_REFRESH_DELAY: Duration = Duration::from_secs(60 * 60); // 1 hour
const MAX_REFRESH_TOTAL_DELAY: Duration = Duration::from_secs(60 * 60 * 24); // 1 day

pub fn spawn_refresh_client<ChainA: ChainHandle, ChainB: ChainHandle>(
    mut client: ForeignClient<ChainA, ChainB>,
) -> Option<TaskHandle> {
    if client.is_expired_or_frozen() {
        warn!(
            client = %client.id,
            "skipping refresh client task on frozen client",
        );

        return None;
    }

    let checkpoint_maintenance = client.id().as_str().starts_with(&format!(
        "{}-",
        ClientId::prefix(ClientType::CardanoProbabilistic)
    ));

    Some(spawn_background_task(
        error_span!(
            "worker.client.refresh",
            client = %client.id,
            src_chain = %client.src_chain.id(),
            dst_chain = %client.dst_chain.id(),
        ),
        Some(REFRESH_CHECK_INTERVAL),
        move || {
            // Try to refresh the client, but only if the refresh window has expired.
            // If the refresh fails, retry according to the given strategy.
            // Checkpoint maintenance must return between attempts so shutdown
            // and committed freshness are checked on every normal poll.
            let delays = refresh_strategy().take(if checkpoint_maintenance {
                0
            } else {
                usize::MAX
            });
            let res = retry_with_index(delays, |_| match client.refresh() {
                Ok(events) => OperationResult::Ok(events),
                Err(error) if error.is_expired_or_frozen_error() => OperationResult::Err(error),
                Err(error) => OperationResult::Retry(error),
            });

            match res {
                // If `client.refresh()` was successful, continue
                Ok(_) => Ok(Next::Continue),

                Err(e) if checkpoint_maintenance && !e.error.is_expired_or_frozen_error() => {
                    Err(TaskError::Ignore(Box::new(e)))
                }

                // If `client.refresh()` failed and the retry mechanism
                // exceeded the maximum delay, return a fatal error.
                Err(e) => Err(TaskError::Fatal(Box::new(e))),
            }
        },
    ))
}

pub fn detect_misbehavior_task<ChainA: ChainHandle, ChainB: ChainHandle>(
    receiver: Receiver<WorkerCmd>,
    client: ForeignClient<ChainB, ChainA>,
) -> Option<TaskHandle> {
    if client.is_expired_or_frozen() {
        warn!(
            client = %client.id(),
            src_chain = %client.src_chain.id(),
            dst_chain = %client.dst_chain.id(),
            "skipping detect misbehavior task on frozen client",
        );

        return None;
    }

    let probabilistic = client.id().as_str().starts_with(&format!(
        "{}-",
        ClientId::prefix(ClientType::CardanoProbabilistic)
    ));
    let mut monitor = MisbehaviourMonitor::new(probabilistic);
    telemetry!(
        client_misbehaviour_check_incomplete,
        &client.src_chain.id(),
        &client.dst_chain.id(),
        client.id(),
        true
    );

    let handle = spawn_background_task(
        error_span!(
            "worker.client.misbehaviour",
            client = %client.id,
            src_chain = %client.src_chain.id(),
            dst_chain = %client.dst_chain.id(),
        ),
        Some(Duration::from_millis(600)),
        move || -> Result<Next, TaskError<Infallible>> {
            let mut updates = Vec::new();
            if let Ok(WorkerCmd::IbcEvents { batch }) = receiver.try_recv() {
                trace!("received batch: {:?}", batch);
                for event in batch.events {
                    if let IbcEvent::UpdateClient(update) = event.event {
                        updates.push(update);
                    }
                }
            }
            if !updates.is_empty() || monitor.incomplete() {
                telemetry!(
                    client_misbehaviour_check_incomplete,
                    &client.src_chain.id(),
                    &client.dst_chain.id(),
                    client.id(),
                    true
                );
            }
            let next = monitor.tick(Instant::now(), updates, |update| {
                client.detect_misbehaviour_and_submit_evidence(update)
            });
            telemetry!(
                client_misbehaviour_check_incomplete,
                &client.src_chain.id(),
                &client.dst_chain.id(),
                client.id(),
                monitor.incomplete()
            );
            Ok(next)
        },
    );

    Some(handle)
}

const MISBEHAVIOUR_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const MAX_UPDATE_CHECKS_PER_POLL: usize = 16;

struct PendingUpdate {
    update: UpdateClient,
    retry_at: Instant,
}

/// Work survives a transient query or verification failure. Probabilistic checks
/// reconstruct the retained work from the destination, including staged cursors.
pub(crate) struct MisbehaviourMonitor {
    probabilistic: bool,
    initial_check_done: bool,
    retry_at: Instant,
    updates: VecDeque<PendingUpdate>,
}

impl MisbehaviourMonitor {
    pub(crate) fn new(probabilistic: bool) -> Self {
        Self {
            probabilistic,
            initial_check_done: false,
            retry_at: Instant::now(),
            updates: VecDeque::new(),
        }
    }

    pub(crate) fn incomplete(&self) -> bool {
        !self.initial_check_done || !self.updates.is_empty()
    }

    pub(crate) fn tick(
        &mut self,
        now: Instant,
        updates: impl IntoIterator<Item = UpdateClient>,
        mut check: impl FnMut(Option<UpdateClient>) -> MisbehaviourResults,
    ) -> Next {
        for update in updates {
            self.updates.push_back(PendingUpdate {
                update,
                retry_at: now,
            });
        }
        // Proposals and rootless checkpoints do not need to emit an IBC
        // UpdateClient event. Poll committed pending work even on idle routes.
        if self.probabilistic && now >= self.retry_at {
            self.initial_check_done = false;
        }
        if !self.initial_check_done && now >= self.retry_at {
            debug!("checking retained misbehaviour coverage");
            match check(None) {
                MisbehaviourResults::ValidClient => {
                    self.initial_check_done = true;
                    self.retry_at = now + MISBEHAVIOUR_RETRY_INTERVAL;
                }
                MisbehaviourResults::VerificationError => {
                    warn!("misbehaviour coverage incomplete, retrying without restarting");
                    self.retry_at = now + MISBEHAVIOUR_RETRY_INTERVAL;
                }
                MisbehaviourResults::EvidenceSubmitted(_) => {
                    self.initial_check_done = true;
                    self.updates.clear();
                    return Next::Abort;
                }
                MisbehaviourResults::CannotExecute => return Next::Abort,
            }
        }
        // A failing old update cannot starve newly received updates. Each failed
        // item goes to the back with its own bounded retry delay.
        for _ in 0..self.updates.len().min(MAX_UPDATE_CHECKS_PER_POLL) {
            let mut pending = self.updates.pop_front().expect("queued update");
            if now < pending.retry_at {
                self.updates.push_back(pending);
                continue;
            }
            match check(Some(pending.update.clone())) {
                MisbehaviourResults::ValidClient => {}
                MisbehaviourResults::VerificationError => {
                    pending.retry_at = now + MISBEHAVIOUR_RETRY_INTERVAL;
                    self.updates.push_back(pending);
                }
                MisbehaviourResults::EvidenceSubmitted(_) => {
                    self.initial_check_done = true;
                    self.updates.clear();
                    return Next::Abort;
                }
                MisbehaviourResults::CannotExecute => {
                    self.initial_check_done = false;
                    return Next::Abort;
                }
            }
        }
        Next::Continue
    }
}

fn refresh_strategy() -> impl Iterator<Item = Duration> {
    clamp_total(
        Fibonacci::from(INITIAL_BACKOFF),
        MAX_REFRESH_DELAY,
        MAX_REFRESH_TOTAL_DELAY,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibc_relayer_types::core::ics02_client::events::Attributes;
    use ibc_relayer_types::Height;

    fn update(height: u64) -> UpdateClient {
        UpdateClient {
            common: Attributes {
                client_id: "07-tendermint-0".parse().unwrap(),
                client_type: ClientType::Tendermint,
                consensus_height: Height::new(0, height).unwrap(),
            },
            header: None,
        }
    }

    #[test]
    fn transient_update_is_retained_without_starving_later_updates() {
        let mut monitor = MisbehaviourMonitor::new(false);
        let now = Instant::now();
        let mut checked = Vec::new();
        monitor.tick(now, [update(1), update(2)], |event| {
            let Some(event) = event else {
                return MisbehaviourResults::ValidClient;
            };
            checked.push(event.consensus_height().revision_height());
            if event.consensus_height().revision_height() == 1 {
                MisbehaviourResults::VerificationError
            } else {
                MisbehaviourResults::ValidClient
            }
        });
        assert_eq!(checked, vec![1, 2]);
        assert!(monitor.incomplete());
        monitor.tick(now + Duration::from_secs(1), [], |_| {
            panic!("retry must wait")
        });
        monitor.tick(now + Duration::from_secs(6), [], |event| {
            assert_eq!(event.unwrap().consensus_height().revision_height(), 1);
            MisbehaviourResults::ValidClient
        });
        assert!(!monitor.incomplete());
    }

    #[test]
    fn probabilistic_monitor_polls_without_update_events_after_success() {
        let mut monitor = MisbehaviourMonitor::new(true);
        let now = Instant::now();
        let mut checks = 0;
        monitor.tick(now, [], |event| {
            assert!(event.is_none());
            checks += 1;
            MisbehaviourResults::ValidClient
        });
        assert!(!monitor.incomplete());
        monitor.tick(now + Duration::from_secs(1), [], |_| {
            panic!("poll must wait")
        });
        monitor.tick(now + Duration::from_secs(6), [], |event| {
            assert!(event.is_none());
            checks += 1;
            MisbehaviourResults::ValidClient
        });
        assert_eq!(checks, 2);
        assert!(!monitor.incomplete());
    }

    #[test]
    fn initial_evidence_or_unsupported_check_stops_the_worker() {
        for result in [
            MisbehaviourResults::EvidenceSubmitted(vec![]),
            MisbehaviourResults::CannotExecute,
        ] {
            let mut monitor = MisbehaviourMonitor::new(true);
            assert!(matches!(
                monitor.tick(Instant::now(), [], |_| result.clone()),
                Next::Abort
            ));
        }
    }
}
