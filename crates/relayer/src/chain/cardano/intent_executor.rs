use futures::{stream, StreamExt};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

const RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(super) struct ExecutorSchedule {
    retry_after: HashMap<String, Instant>,
    progressed: bool,
}

impl ExecutorSchedule {
    pub fn begin_pass(&mut self, now: Instant) {
        self.progressed = false;
        self.retry_after.retain(|_, deadline| *deadline > now);
    }

    pub fn ready(&self, channel: &str, now: Instant) -> bool {
        self.retry_after
            .get(channel)
            .is_none_or(|deadline| *deadline <= now)
    }

    pub fn succeeded(&mut self, channel: &str, sent: bool) {
        self.progressed |= sent;
        self.retry_after.remove(channel);
    }

    pub fn failed(&mut self, channel: String, now: Instant) {
        self.retry_after.insert(channel, now + RETRY_DELAY);
    }

    /// Drain one batch per eligible channel without letting a slow inclusion
    /// hold up other channels. A pass finishes before the next one starts.
    pub async fn execute<E, F, Fut>(
        &mut self,
        channels: impl IntoIterator<Item = String>,
        concurrency: NonZeroUsize,
        execute: F,
    ) -> Vec<(String, E)>
    where
        F: Fn(String) -> Fut,
        Fut: Future<Output = Result<bool, E>>,
    {
        let now = Instant::now();
        let mut seen = HashSet::new();
        let eligible: Vec<_> = channels
            .into_iter()
            .filter(|channel| self.ready(channel, now) && seen.insert(channel.clone()))
            .collect();
        let jobs = stream::iter(eligible).map(|channel| {
            let job = execute(channel.clone());
            async move { (channel, job.await) }
        });
        let mut pending = jobs.buffer_unordered(concurrency.get());
        let mut failures = Vec::new();
        while let Some((channel, result)) = pending.next().await {
            match result {
                Ok(sent) => self.succeeded(&channel, sent),
                Err(error) => {
                    self.failed(channel.clone(), Instant::now());
                    failures.push((channel, error));
                }
            }
        }
        failures
    }

    pub fn delay(&self) -> Duration {
        if self.progressed {
            Duration::ZERO
        } else {
            RETRY_DELAY
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounds_in_flight_batches_and_drains_after_a_failure() {
        use std::cell::{Cell, RefCell};
        use std::rc::Rc;
        use tokio::sync::mpsc;

        let mut schedule = ExecutorSchedule::default();
        schedule.begin_pass(Instant::now());
        let active = Rc::new(Cell::new(0));
        let peak = Rc::new(Cell::new(0));
        let started = Rc::new(RefCell::new(Vec::new()));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let jobs = schedule.execute(
            ["slow", "busy", "healthy", "healthy", "last"].map(String::from),
            NonZeroUsize::new(2).unwrap(),
            |channel| {
                let (release, included) = tokio::sync::oneshot::channel();
                started.borrow_mut().push(channel.clone());
                active.set(active.get() + 1);
                peak.set(peak.get().max(active.get()));
                tx.send((channel.clone(), release)).unwrap();
                let active = active.clone();
                async move {
                    included.await.unwrap();
                    active.set(active.get() - 1);
                    if channel == "busy" {
                        Err("reserved inputs")
                    } else {
                        Ok(true)
                    }
                }
            },
        );
        let releases = async {
            let (first, hold) = rx.recv().await.unwrap();
            let (second, release) = rx.recv().await.unwrap();
            assert_eq!((first.as_str(), second.as_str()), ("slow", "busy"));
            assert!(rx.try_recv().is_err());
            release.send(()).unwrap();
            // Other channels finish while the first is still awaiting inclusion.
            for expected in ["healthy", "last"] {
                let (channel, release) = rx.recv().await.unwrap();
                assert_eq!(channel, expected);
                release.send(()).unwrap();
            }
            hold.send(()).unwrap();
        };
        let (failures, ()) = tokio::join!(jobs, releases);
        assert_eq!(peak.get(), 2);
        assert_eq!(active.get(), 0);
        assert_eq!(started.borrow().len(), 4);
        assert_eq!(failures, vec![("busy".into(), "reserved inputs")]);
        assert!(!schedule.ready("busy", Instant::now()));
        assert!(schedule.ready("healthy", Instant::now()));
        assert_eq!(schedule.delay(), Duration::ZERO);
    }

    #[tokio::test]
    async fn one_worker_preserves_serial_execution_and_skips_backoff() {
        let mut schedule = ExecutorSchedule::default();
        let now = Instant::now();
        schedule.begin_pass(now);
        schedule.failed("busy".into(), now);
        let started = std::cell::RefCell::new(Vec::new());
        let finished = std::cell::RefCell::new(Vec::new());
        let failures = schedule
            .execute(
                ["first", "busy", "second", "first"].map(String::from),
                NonZeroUsize::new(1).unwrap(),
                |channel| {
                    assert_eq!(started.borrow().len(), finished.borrow().len());
                    started.borrow_mut().push(channel.clone());
                    let finished = &finished;
                    async move {
                        tokio::task::yield_now().await;
                        finished.borrow_mut().push(channel);
                        Ok::<_, ()>(true)
                    }
                },
            )
            .await;
        assert!(failures.is_empty());
        assert_eq!(*finished.borrow(), ["first", "second"]);
        assert!(!schedule.ready("busy", Instant::now()));
    }

    #[test]
    fn drains_a_healthy_backlog_while_a_failed_channel_backs_off() {
        let mut scheduler = ExecutorSchedule::default();
        let start = Instant::now();
        scheduler.begin_pass(start);
        scheduler.failed("failed".into(), start);
        scheduler.succeeded("healthy", true);
        assert_eq!(scheduler.delay(), Duration::ZERO);
        for second in 1..5 {
            let now = start + Duration::from_secs(second);
            scheduler.begin_pass(now);
            assert!(!scheduler.ready("failed", now));
            assert!(scheduler.ready("healthy", now));
            scheduler.succeeded("healthy", true);
            assert_eq!(scheduler.delay(), Duration::ZERO);
        }
        let retry = start + RETRY_DELAY;
        scheduler.begin_pass(retry);
        assert!(scheduler.ready("failed", retry));
        scheduler.succeeded("failed", false);
        scheduler.succeeded("healthy", false);
        assert_eq!(scheduler.delay(), RETRY_DELAY);
    }

    #[test]
    fn unavailable_inputs_and_discovery_failures_do_not_spin() {
        let mut scheduler = ExecutorSchedule::default();
        let now = Instant::now();
        scheduler.begin_pass(now);
        assert_eq!(scheduler.delay(), RETRY_DELAY);
        scheduler.failed("busy-lane".into(), now);
        assert!(!scheduler.ready("busy-lane", now));
        assert_eq!(scheduler.delay(), RETRY_DELAY);
        scheduler.begin_pass(now + RETRY_DELAY);
        scheduler.succeeded("busy-lane", true);
        assert_eq!(scheduler.delay(), Duration::ZERO);
    }
}
