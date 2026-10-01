use std::collections::HashMap;
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
