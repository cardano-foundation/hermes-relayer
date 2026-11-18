use crate::config::filter::ChannelPolicy;
use futures::{stream::FuturesUnordered, StreamExt};
use ibc_proto::ibc::core::channel::v1::IdentifiedChannel;
use ibc_relayer_types::core::ics24_host::identifier::{ChannelId, PortId};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

const RETRY_DELAY: Duration = Duration::from_secs(5);

/// Operator authorization for autonomous funded-intent work.
#[derive(Clone)]
pub(super) struct ExecutorPolicy {
    enabled: bool,
    channels: ChannelPolicy,
}

impl ExecutorPolicy {
    pub fn new(enabled: bool, channels: ChannelPolicy) -> Self {
        Self { enabled, channels }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    fn allows(&self, channel: &IdentifiedChannel) -> bool {
        if !self.enabled || channel.port_id != "transfer" || channel.state != 3 {
            return false;
        }
        let (Ok(port), Ok(channel)) = (
            channel.port_id.parse::<PortId>(),
            channel.channel_id.parse::<ChannelId>(),
        ) else {
            return false;
        };
        self.channels.is_allowed(&port, &channel)
    }

    /// Keep a fair queue of channels, with only one unresolved attempt per channel.
    /// Discovery is polled alongside execution so it cannot stall active batches.
    pub async fn run<E, D, DFut, F, Fut>(
        &self,
        concurrency: NonZeroUsize,
        mut discover: D,
        execute: F,
        report: impl Fn(Option<&str>, E),
        stopped: impl Fn() -> bool,
    ) where
        D: FnMut() -> DFut,
        DFut: Future<Output = Result<Vec<IdentifiedChannel>, E>>,
        F: Fn(String) -> Fut,
        Fut: Future<Output = Result<bool, E>>,
    {
        if !self.enabled {
            return;
        }
        let mut ready: VecDeque<String> = VecDeque::new();
        let mut eligible = HashSet::new();
        let mut active = HashSet::new();
        let mut retry_after = HashMap::new();
        let mut jobs = FuturesUnordered::new();
        let mut queries: FuturesUnordered<DFut> = FuturesUnordered::new();
        let mut tick = tokio::time::interval(RETRY_DELAY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let stopping = stopped();
            if stopping && jobs.is_empty() {
                return;
            }
            if !stopping {
                // Rotate delayed channels instead of letting one block the queue.
                for _ in 0..ready.len() {
                    if stopped() || jobs.len() >= concurrency.get() {
                        break;
                    }
                    let channel = ready.pop_front().expect("nonempty ready queue");
                    if !eligible.contains(&channel) {
                        retry_after.remove(&channel);
                        continue;
                    }
                    if retry_after
                        .get(&channel)
                        .is_some_and(|deadline| *deadline > Instant::now())
                    {
                        ready.push_back(channel);
                        continue;
                    }
                    active.insert(channel.clone());
                    let job = execute(channel.clone());
                    jobs.push(async move { (channel, job.await) });
                }
            }
            let next_retry = ready
                .iter()
                .filter_map(|channel| retry_after.get(channel))
                .copied()
                .filter(|deadline| *deadline > Instant::now())
                .min();
            let retry_wakeup = next_retry
                .map(tokio::time::Instant::from_std)
                .unwrap_or_else(|| tokio::time::Instant::now() + RETRY_DELAY);
            tokio::select! {
                _ = tokio::time::sleep_until(retry_wakeup), if !stopping && jobs.len() < concurrency.get() && next_retry.is_some() => {}
                Some((channel, result)) = jobs.next(), if !jobs.is_empty() => {
                    active.remove(&channel);
                    match result {
                        Ok(true) => { retry_after.remove(&channel); }
                        result => {
                            retry_after.insert(channel.clone(), Instant::now() + RETRY_DELAY);
                            if let Err(error) = result { report(Some(&channel), error); }
                        }
                    }
                    if eligible.contains(&channel) { ready.push_back(channel); }
                }
                Some(result) = queries.next(), if !queries.is_empty() && !stopping => {
                    match result {
                        Ok(channels) => {
                            eligible.clear();
                            for channel in channels.into_iter().filter(|channel| self.allows(channel)) {
                                let channel = channel.channel_id;
                                if eligible.insert(channel.clone()) && !active.contains(&channel) && !ready.contains(&channel) {
                                    ready.push_back(channel);
                                }
                            }
                            ready.retain(|channel| eligible.contains(channel));
                            retry_after.retain(|channel, _| eligible.contains(channel));
                        }
                        Err(error) => report(None, error),
                    }
                }
                _ = tick.tick() => {
                    if !stopped() && queries.is_empty() { queries.push(discover()); }
                }
            }
        }
    }
}

/// Retain the exact signed bytes before the first submission attempt. Only an
/// observed inclusion or a trusted proof of expiry may release the channel.
#[derive(Default)]
pub(super) struct PendingBatches(
    std::sync::Mutex<HashMap<String, super::signer::SignedTransaction>>,
);

impl PendingBatches {
    pub async fn execute<E, B, BFut, R, RFut>(
        &self,
        channel: &str,
        build: B,
        reconcile: R,
    ) -> Result<bool, E>
    where
        B: FnOnce() -> BFut,
        BFut: Future<Output = Result<Option<super::signer::SignedTransaction>, E>>,
        R: FnOnce(super::signer::SignedTransaction) -> RFut,
        RFut: Future<Output = Result<bool, E>>,
    {
        let pending = self
            .0
            .lock()
            .expect("pending batches poisoned")
            .get(channel)
            .cloned();
        let signed = match pending {
            Some(signed) => signed,
            None => {
                let Some(signed) = build().await? else {
                    return Ok(false);
                };
                self.0
                    .lock()
                    .expect("pending batches poisoned")
                    .insert(channel.to_string(), signed.clone());
                signed
            }
        };
        let included = reconcile(signed).await?;
        self.0
            .lock()
            .expect("pending batches poisoned")
            .remove(channel);
        Ok(included)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[tokio::test]
    async fn ambiguous_submission_reuses_signed_bytes_until_reconciled() {
        let pending = PendingBatches::default();
        let builds = Cell::new(0);
        let signed = super::super::signer::SignedTransaction {
            cbor: vec![1, 2, 3],
            tx_hash: "same-hash".into(),
        };
        for outcome in [
            Err("submission response lost"),
            Err("observation timed out"),
            Ok(true),
            Ok(false),
        ] {
            let result = pending
                .execute(
                    "channel-0",
                    || async {
                        builds.set(builds.get() + 1);
                        Ok(Some(signed.clone()))
                    },
                    |actual| {
                        assert_eq!(actual, signed);
                        async move { outcome }
                    },
                )
                .await;
            assert_eq!(result, outcome);
        }
        // Only confirmation permits the fourth attempt to build and sign again.
        assert_eq!(builds.get(), 2);
    }

    #[tokio::test]
    async fn cancelled_observation_retains_signed_transaction() {
        let pending = PendingBatches::default();
        let signed = super::super::signer::SignedTransaction {
            cbor: vec![4],
            tx_hash: "pending-hash".into(),
        };
        let attempt = pending.execute(
            "channel-0",
            || async { Ok::<_, ()>(Some(signed.clone())) },
            |_| std::future::pending(),
        );
        assert!(tokio::time::timeout(Duration::from_millis(10), attempt)
            .await
            .is_err());
        pending
            .execute(
                "channel-0",
                || async {
                    panic!("must not build or sign again");
                    #[allow(unreachable_code)]
                    Ok::<_, ()>(None)
                },
                |actual| {
                    assert_eq!(actual, signed);
                    async { Ok(true) }
                },
            )
            .await
            .unwrap();
    }

    fn open_channel(id: &str) -> IdentifiedChannel {
        IdentifiedChannel {
            port_id: "transfer".into(),
            channel_id: id.into(),
            state: 3,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn healthy_channel_finishes_multiple_batches_while_slow_channel_waits() {
        let policy = ExecutorPolicy::new(true, toml::from_str("policy = 'allowall'").unwrap());
        let stopped = Cell::new(false);
        let active = RefCell::new(HashSet::new());
        let peak = Cell::new(0);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let run = policy.run(
            NonZeroUsize::new(2).unwrap(),
            || async {
                Ok::<_, ()>(vec![
                    open_channel("channel-0"),
                    open_channel("channel-1"),
                    open_channel("channel-1"),
                    open_channel("channel-2"),
                ])
            },
            |channel| {
                assert!(
                    active.borrow_mut().insert(channel.clone()),
                    "duplicate in-flight channel"
                );
                peak.set(peak.get().max(active.borrow().len()));
                let (release, included) = tokio::sync::oneshot::channel();
                tx.send((channel.clone(), release)).unwrap();
                let active = &active;
                async move {
                    included.await.unwrap();
                    active.borrow_mut().remove(&channel);
                    Ok(true)
                }
            },
            |_, ()| panic!("unexpected failure"),
            || stopped.get(),
        );
        let releases = async {
            let (slow, hold) = rx.recv().await.unwrap();
            assert_eq!(slow, "channel-0");
            for expected in [
                "channel-1",
                "channel-2",
                "channel-1",
                "channel-2",
                "channel-1",
            ] {
                let (channel, release) = rx.recv().await.unwrap();
                assert_eq!(channel, expected);
                assert!(rx.try_recv().is_err());
                if expected == "channel-1" && peak.get() != 2 {
                    panic!("unbounded execution");
                }
                release.send(()).unwrap();
            }
            stopped.set(true);
            hold.send(()).unwrap();
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(run, releases);
        })
        .await
        .unwrap();
        assert_eq!(peak.get(), 2);
        assert!(active.borrow().is_empty());
    }

    #[tokio::test]
    async fn discovers_new_channels_while_an_existing_batch_is_pending() {
        let policy = ExecutorPolicy::new(true, toml::from_str("policy = 'allowall'").unwrap());
        let stopped = Cell::new(false);
        let queries = Cell::new(0);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let run = policy.run(
            NonZeroUsize::new(2).unwrap(),
            || {
                queries.set(queries.get() + 1);
                let channels = if queries.get() == 1 {
                    vec![open_channel("channel-0")]
                } else {
                    vec![open_channel("channel-0"), open_channel("channel-1")]
                };
                async { Ok::<_, ()>(channels) }
            },
            |channel| {
                let (release, included) = tokio::sync::oneshot::channel();
                tx.send((channel, release)).unwrap();
                async {
                    included.await.unwrap();
                    Ok(true)
                }
            },
            |_, ()| panic!("unexpected failure"),
            || stopped.get(),
        );
        let releases = async {
            let (first, hold) = rx.recv().await.unwrap();
            assert_eq!(first, "channel-0");
            let (second, release) = rx.recv().await.unwrap();
            assert_eq!(second, "channel-1");
            stopped.set(true);
            release.send(()).unwrap();
            hold.send(()).unwrap();
        };
        tokio::time::timeout(RETRY_DELAY * 2, async {
            tokio::join!(run, releases);
        })
        .await
        .unwrap();
        assert_eq!(queries.get(), 2);
    }

    #[tokio::test]
    async fn disabled_packets_never_discover_or_execute() {
        let policy = ExecutorPolicy::new(false, toml::from_str("policy = 'allowall'").unwrap());
        policy
            .run(
                NonZeroUsize::new(2).unwrap(),
                || async {
                    panic!("disabled discovery");
                    #[allow(unreachable_code)]
                    Ok::<_, ()>(vec![])
                },
                |_| async {
                    panic!("disabled build/sign/submit");
                    #[allow(unreachable_code)]
                    Ok(true)
                },
                |_, ()| panic!("unexpected failure"),
                || false,
            )
            .await;
    }

    #[tokio::test]
    async fn channel_policy_is_applied_before_build_sign_and_submit() {
        for config in [
            "policy = 'allow'\nlist = [['transfer', 'channel-0']]",
            "policy = 'deny'\nlist = [['transfer', 'channel-1']]",
        ] {
            let policy = ExecutorPolicy::new(true, toml::from_str(config).unwrap());
            let stopped = Cell::new(false);
            let calls = RefCell::new(Vec::new());
            let mut closed = open_channel("channel-2");
            closed.state = 4;
            let mut wrong_port = open_channel("channel-3");
            wrong_port.port_id = "other".into();
            let channels = vec![
                open_channel("channel-1"),
                open_channel("channel-0"),
                closed,
                wrong_port,
                open_channel("invalid"),
            ];
            policy
                .run(
                    NonZeroUsize::new(4).unwrap(),
                    || async { Ok::<_, ()>(channels.clone()) },
                    |channel| {
                        calls.borrow_mut().push(channel);
                        stopped.set(true);
                        async { Ok(true) }
                    },
                    |_, ()| panic!("unexpected failure"),
                    || stopped.get(),
                )
                .await;
            assert_eq!(*calls.borrow(), ["channel-0"]);
        }
    }

    #[tokio::test]
    async fn idle_and_failed_channels_back_off_without_delaying_healthy_work() {
        let policy = ExecutorPolicy::new(true, toml::from_str("policy = 'allowall'").unwrap());
        let stopped = Cell::new(false);
        let calls = RefCell::new(HashMap::<String, usize>::new());
        let errors = RefCell::new(Vec::new());
        policy
            .run(
                NonZeroUsize::new(1).unwrap(),
                || async {
                    Ok(vec![
                        open_channel("channel-0"),
                        open_channel("channel-1"),
                        open_channel("channel-2"),
                    ])
                },
                |channel| {
                    let count = {
                        let mut calls = calls.borrow_mut();
                        let count = calls.entry(channel.clone()).or_default();
                        *count += 1;
                        *count
                    };
                    if count == 3 {
                        stopped.set(true);
                    }
                    async move {
                        match channel.as_str() {
                            "channel-0" => Ok(false),
                            "channel-1" => Err("busy"),
                            _ => Ok(true),
                        }
                    }
                },
                |channel, error| {
                    errors
                        .borrow_mut()
                        .push((channel.unwrap().to_string(), error))
                },
                || stopped.get(),
            )
            .await;
        assert_eq!(calls.borrow()["channel-0"], 1);
        assert_eq!(calls.borrow()["channel-1"], 1);
        assert_eq!(calls.borrow()["channel-2"], 3);
        assert_eq!(*errors.borrow(), [("channel-1".into(), "busy")]);
    }
}
