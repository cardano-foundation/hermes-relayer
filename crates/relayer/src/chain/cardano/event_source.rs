//! Event source for Cardano chain
//!
//! Polls the Gateway for IBC events and broadcasts them to subscribers.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crossbeam_channel as channel;
use futures::future::BoxFuture;
use tokio::{
    runtime::Runtime as TokioRuntime,
    time::{sleep, Duration, Instant},
};
use tracing::{debug, error, error_span, trace, warn};

use ibc_relayer_types::{
    core::{
        ics02_client::events::NewBlock, ics02_client::height::Height,
        ics24_host::identifier::ChainId,
    },
    events::IbcEvent,
};

use crate::{
    chain::tracking::TrackingId,
    event::{bus::EventBus, source::Error, IbcEventWithHeight},
    telemetry,
};

use super::{
    event_parser, gateway_client::GatewayClient, generated::ibc::cardano::v1::QueryEventsResponse,
};

use crate::event::source::{EventBatch, EventSourceCmd, TxEventSourceCmd};

pub type Result<T> = core::result::Result<T, Error>;

trait EventSourceGateway: Send + Sync {
    fn query_latest_height(
        &self,
    ) -> BoxFuture<'_, core::result::Result<Height, super::error::Error>>;

    fn query_events(
        &self,
        since_height: Height,
    ) -> BoxFuture<'_, core::result::Result<QueryEventsResponse, super::error::Error>>;
}

impl EventSourceGateway for GatewayClient {
    fn query_latest_height(
        &self,
    ) -> BoxFuture<'_, core::result::Result<Height, super::error::Error>> {
        Box::pin(GatewayClient::query_latest_height(self))
    }

    fn query_events(
        &self,
        since_height: Height,
    ) -> BoxFuture<'_, core::result::Result<QueryEventsResponse, super::error::Error>> {
        Box::pin(GatewayClient::query_events(self, since_height))
    }
}

#[derive(Debug, Copy, Clone)]
enum Next {
    Continue,
    Abort,
}

/// An event source that polls the Cardano Gateway for IBC events
pub struct CardanoEventSource {
    /// Chain identifier
    chain_id: ChainId,

    /// Gateway client for querying events
    gateway_client: Arc<dyn EventSourceGateway>,

    /// Poll interval
    poll_interval: Duration,

    /// Number of recent Gateway-scanned blocks to replay on startup
    event_replay_window: u64,

    /// Event bus for broadcasting events
    event_bus: EventBus<Arc<Result<EventBatch>>>,

    /// Channel where to receive commands
    rx_cmd: channel::Receiver<EventSourceCmd>,

    /// Tokio runtime
    rt: Arc<TokioRuntime>,

    /// Last fetched block height
    last_fetched_height: Height,

    /// Gateway events already emitted while polling the replay overlap
    seen_event_keys: BTreeSet<EventCursorKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EventCursorKey {
    height: u64,
    event_type: String,
    attributes: Vec<(String, String)>,
}

impl EventCursorKey {
    fn from_core_event(height: u64, event: &super::generated::ibc::core::types::v1::Event) -> Self {
        let mut attributes = event
            .event_attribute
            .iter()
            .map(|attr| (attr.key.clone(), attr.value.clone()))
            .collect::<Vec<_>>();
        attributes.sort();

        Self {
            height,
            event_type: event.r#type.clone(),
            attributes,
        }
    }
}

impl CardanoEventSource {
    pub fn new(
        chain_id: ChainId,
        gateway_client: GatewayClient,
        poll_interval: Duration,
        event_replay_window: u64,
        rt: Arc<TokioRuntime>,
    ) -> Result<(Self, TxEventSourceCmd)> {
        Self::new_with_gateway(
            chain_id,
            Arc::new(gateway_client),
            poll_interval,
            event_replay_window,
            rt,
        )
    }

    fn new_with_gateway(
        chain_id: ChainId,
        gateway_client: Arc<dyn EventSourceGateway>,
        poll_interval: Duration,
        event_replay_window: u64,
        rt: Arc<TokioRuntime>,
    ) -> Result<(Self, TxEventSourceCmd)> {
        let event_bus = EventBus::new();
        let (tx_cmd, rx_cmd) = channel::unbounded();

        let source = Self {
            rt,
            chain_id,
            gateway_client,
            poll_interval,
            event_replay_window,
            event_bus,
            rx_cmd,
            // Start at a valid (non-zero) height; `run()` will initialize this
            // from the Gateway latest height and configured replay window.
            last_fetched_height: Height::new(0, 1).map_err(|e| {
                Error::collect_events_failed(format!("Failed to create initial height: {}", e))
            })?,
            seen_event_keys: BTreeSet::new(),
        };

        Ok((source, TxEventSourceCmd::new(tx_cmd)))
    }

    pub fn run(mut self) {
        let _span = error_span!("event_source.cardano", chain.id = %self.chain_id).entered();

        debug!("starting Cardano event source");

        let rt = self.rt.clone();

        rt.block_on(async {
            // Initialize the latest fetched height
            if let Ok(latest_height) = self.fetch_latest_height().await {
                match startup_replay_height(latest_height, self.event_replay_window) {
                    Ok(replay_height) => {
                        self.last_fetched_height = replay_height;
                        debug!(
                            latest_height = %latest_height,
                            event_replay_window = self.event_replay_window,
                            last_fetched_height = %self.last_fetched_height,
                            "initialized Cardano event source replay cursor"
                        );
                    }
                    Err(e) => error!("failed to initialize replay height: {e}"),
                }
            }

            // Continuously run the event loop
            loop {
                let before_step = Instant::now();

                match self.step().await {
                    Ok(Next::Abort) => break,

                    Ok(Next::Continue) => {
                        // Check if we need to wait before the next iteration
                        let delay = self.poll_interval.checked_sub(before_step.elapsed());

                        if let Some(delay_remaining) = delay {
                            sleep(delay_remaining).await;
                        }

                        continue;
                    }

                    Err(e) => {
                        error!("event source encountered an error: {e}");
                        // Wait before retrying
                        sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });

        debug!("shutting down Cardano event source");
    }

    async fn step(&mut self) -> Result<Next> {
        // Process any shutdown or subscription commands before we start doing any work
        if let Next::Abort = self.try_process_cmd() {
            return Ok(Next::Abort);
        }

        let poll_since_height = replay_height(self.last_fetched_height, self.event_replay_window)?;

        // Query Gateway for events since the replay cursor. The overlap handles Gateway
        // event-indexing lag for events whose block height was already scanned.
        let response = self
            .gateway_client
            .query_events(poll_since_height)
            .await
            .map_err(|e| {
                Error::collect_events_failed(format!("Failed to query Gateway events: {}", e))
            })?;

        let current_height = Height::new(0, response.current_height).map_err(|e| {
            Error::collect_events_failed(format!("Invalid height from Gateway: {}", e))
        })?;

        let scanned_to_height = Height::new(0, response.scanned_to_height).map_err(|e| {
            Error::collect_events_failed(format!("Invalid scanned height from Gateway: {}", e))
        })?;

        if scanned_to_height < self.last_fetched_height {
            return Err(Error::collect_events_failed(format!(
                "Gateway scanned height {} regressed behind last fetched height {}",
                scanned_to_height, self.last_fetched_height
            )));
        }

        let overlap_start_height = poll_since_height.revision_height().saturating_add(1);
        let new_start_height = self.last_fetched_height.revision_height().saturating_add(1);
        let end_height = scanned_to_height.revision_height();

        self.seen_event_keys
            .retain(|key| key.height >= overlap_start_height);

        if overlap_start_height <= end_height {
            trace!(
                "received {} block(s) with IBC events from height {} to {}, gateway current height {}",
                response.events.len(),
                poll_since_height,
                scanned_to_height,
                current_height
            );

            let mut events_by_height = response
                .events
                .into_iter()
                .map(|block_events| (block_events.height, block_events))
                .collect::<BTreeMap<_, _>>();

            for height in overlap_start_height..=end_height {
                let block_events = events_by_height.remove(&height);
                let include_new_block = height >= new_start_height;

                if block_events.is_none() && !include_new_block {
                    continue;
                }

                let batch = process_block_events(
                    &self.chain_id,
                    &mut self.seen_event_keys,
                    height,
                    block_events,
                    include_new_block,
                )?;

                if batch.events.is_empty() {
                    continue;
                }

                // Check for commands before broadcasting
                if let Next::Abort = self.try_process_cmd() {
                    return Ok(Next::Abort);
                }

                self.broadcast_batch(batch);
            }
        } else {
            trace!(
                "no new blocks, scanned to {}, current height: {}, last fetched: {}",
                scanned_to_height,
                current_height,
                self.last_fetched_height
            );
        }

        // Gateway event queries are windowed; advance to the scanned height even when
        // the window has no IBC events so polling eventually catches later packets.
        self.last_fetched_height = scanned_to_height;

        Ok(Next::Continue)
    }

    /// Process any pending commands, if any.
    fn try_process_cmd(&mut self) -> Next {
        if let Ok(cmd) = self.rx_cmd.try_recv() {
            match cmd {
                EventSourceCmd::Shutdown => return Next::Abort,

                EventSourceCmd::Subscribe(tx) => {
                    if let Err(e) = tx.send(self.event_bus.subscribe()) {
                        error!("failed to send back subscription: {e}");
                    }
                }
            }
        }

        Next::Continue
    }

    /// Broadcast an event batch to all subscribers
    fn broadcast_batch(&mut self, batch: EventBatch) {
        telemetry!(ws_events, &batch.chain_id, batch.events.len() as u64);

        trace!(
            chain = %batch.chain_id,
            count = %batch.events.len(),
            height = %batch.height,
            "broadcasting batch of {} events at height {}",
            batch.events.len(),
            batch.height
        );

        self.event_bus.broadcast(Arc::new(Ok(batch)));
    }

    /// Fetch the current chain height from Gateway
    async fn fetch_latest_height(&self) -> Result<Height> {
        self.gateway_client
            .query_latest_height()
            .await
            .map_err(|e| {
                Error::collect_events_failed(format!("Failed to fetch latest height: {}", e))
            })
    }
}

fn startup_replay_height(latest_height: Height, event_replay_window: u64) -> Result<Height> {
    replay_height(latest_height, event_replay_window)
}

fn replay_height(latest_height: Height, event_replay_window: u64) -> Result<Height> {
    let replay_height = latest_height
        .revision_height()
        .saturating_sub(event_replay_window)
        .max(1);

    Height::new(latest_height.revision_number(), replay_height).map_err(|e| {
        Error::collect_events_failed(format!("Invalid replay height from Gateway: {}", e))
    })
}

/// Process events from a single block.
fn process_block_events(
    chain_id: &ChainId,
    seen_event_keys: &mut BTreeSet<EventCursorKey>,
    raw_height: u64,
    block_events: Option<super::generated::ibc::cardano::v1::BlockEvents>,
    include_new_block: bool,
) -> Result<EventBatch> {
    let height = Height::new(0, raw_height)
        .map_err(|e| Error::collect_events_failed(format!("Invalid block height: {}", e)))?;

    let mut events_with_height = if include_new_block {
        vec![IbcEventWithHeight::new(
            IbcEvent::NewBlock(NewBlock::new(height)),
            height,
        )]
    } else {
        vec![]
    };

    if let Some(block_events) = block_events {
        let mut keyed_gateway_events = Vec::new();

        for tx_result in block_events.events {
            for core_event in tx_result.events {
                let key = EventCursorKey::from_core_event(raw_height, &core_event);

                if seen_event_keys.contains(&key) {
                    continue;
                }

                // Convert ibc.core.types.v1.Event to ibc.cardano.v1.Event
                let event = super::generated::ibc::cardano::v1::Event {
                    r#type: core_event.r#type,
                    attributes: core_event
                        .event_attribute
                        .into_iter()
                        .map(|attr| super::generated::ibc::cardano::v1::EventAttribute {
                            key: attr.key,
                            value: attr.value,
                        })
                        .collect(),
                };

                keyed_gateway_events.push((key, event));
            }
        }

        if !keyed_gateway_events.is_empty() {
            for (key, gateway_event) in keyed_gateway_events {
                match event_parser::parse_events(vec![gateway_event], height) {
                    Ok(ibc_events) => {
                        events_with_height.extend(
                            ibc_events
                                .into_iter()
                                .map(|event| IbcEventWithHeight::new(event, height)),
                        );
                    }
                    Err(error) => {
                        warn!(
                            chain = %chain_id,
                            height = %height,
                            event_type = %key.event_type,
                            %error,
                            "skipping malformed Cardano Gateway event"
                        );
                    }
                }

                // A malformed event cannot become parseable on the next overlapping poll.
                // Remember it so one bad Gateway response is not retried indefinitely.
                seen_event_keys.insert(key);
            }
        }
    }

    debug!(
        chain = %chain_id,
        height = %height,
        count = events_with_height.len(),
        "parsed {} Cardano events at height {}",
        events_with_height.len(),
        height
    );

    Ok(EventBatch {
        chain_id: chain_id.clone(),
        tracking_id: TrackingId::new_uuid(),
        height,
        events: events_with_height,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, VecDeque},
        sync::{Arc, Mutex},
    };

    use futures::future::BoxFuture;
    use ibc_relayer_types::{
        core::{ics02_client::height::Height, ics24_host::identifier::ChainId},
        events::IbcEvent,
    };
    use tokio::{runtime::Runtime as TokioRuntime, time::Duration};

    use crate::chain::cardano::{
        error::Error as CardanoError,
        generated::ibc::{
            cardano::v1::{BlockEvents, QueryEventsResponse},
            core::types::v1::{
                Event as CoreEvent, EventAttribute as CoreEventAttribute, ResponseDeliverTx,
            },
        },
    };

    use super::{
        process_block_events, startup_replay_height, CardanoEventSource, EventSourceGateway, Next,
    };

    struct ScriptedGateway {
        responses: Mutex<VecDeque<QueryEventsResponse>>,
        requested_heights: Arc<Mutex<Vec<Height>>>,
    }

    impl EventSourceGateway for ScriptedGateway {
        fn query_latest_height(&self) -> BoxFuture<'_, core::result::Result<Height, CardanoError>> {
            Box::pin(async { Ok(Height::new(0, 1).unwrap()) })
        }

        fn query_events(
            &self,
            since_height: Height,
        ) -> BoxFuture<'_, core::result::Result<QueryEventsResponse, CardanoError>> {
            Box::pin(async move {
                self.requested_heights.lock().unwrap().push(since_height);

                self.responses.lock().unwrap().pop_front().ok_or_else(|| {
                    CardanoError::GatewayClient("scripted response missing".to_string())
                })
            })
        }
    }

    #[test]
    fn startup_replay_height_subtracts_window() {
        let latest = Height::new(0, 1000).unwrap();

        assert_eq!(
            startup_replay_height(latest, 100).unwrap(),
            Height::new(0, 900).unwrap()
        );
    }

    #[test]
    fn startup_replay_height_preserves_latest_when_window_is_zero() {
        let latest = Height::new(0, 1000).unwrap();

        assert_eq!(
            startup_replay_height(latest, 0).unwrap(),
            Height::new(0, 1000).unwrap()
        );
    }

    #[test]
    fn startup_replay_height_clamps_to_one() {
        let latest = Height::new(0, 50).unwrap();

        assert_eq!(
            startup_replay_height(latest, 100).unwrap(),
            Height::new(0, 1).unwrap()
        );
    }

    #[test]
    fn process_block_events_can_emit_late_overlap_packet_without_new_block() {
        let chain_id = chain_id();
        let mut seen_event_keys = BTreeSet::new();

        let batch = process_block_events(
            &chain_id,
            &mut seen_event_keys,
            42,
            Some(block_with_send_packet()),
            false,
        )
        .unwrap();

        assert_eq!(batch.events.len(), 1);
        assert!(matches!(batch.events[0].event, IbcEvent::SendPacket(_)));
    }

    #[test]
    fn process_block_events_deduplicates_replayed_overlap_events() {
        let chain_id = chain_id();
        let mut seen_event_keys = BTreeSet::new();

        let first = process_block_events(
            &chain_id,
            &mut seen_event_keys,
            42,
            Some(block_with_send_packet()),
            false,
        )
        .unwrap();
        let second = process_block_events(
            &chain_id,
            &mut seen_event_keys,
            42,
            Some(block_with_send_packet()),
            false,
        )
        .unwrap();

        assert_eq!(first.events.len(), 1);
        assert!(second.events.is_empty());
    }

    #[test]
    fn process_block_events_keeps_new_block_for_new_scanned_height() {
        let chain_id = chain_id();
        let mut seen_event_keys = BTreeSet::new();

        let batch = process_block_events(&chain_id, &mut seen_event_keys, 42, None, true).unwrap();

        assert_eq!(batch.events.len(), 1);
        assert!(matches!(batch.events[0].event, IbcEvent::NewBlock(_)));
    }

    #[test]
    fn event_source_advances_past_malformed_gateway_event() {
        let requested_heights = Arc::new(Mutex::new(Vec::new()));
        let gateway = Arc::new(ScriptedGateway {
            responses: Mutex::new(VecDeque::from([
                QueryEventsResponse {
                    current_height: 43,
                    scanned_to_height: 43,
                    events: vec![block_with_malformed_and_valid_send_packets()],
                },
                QueryEventsResponse {
                    current_height: 44,
                    scanned_to_height: 44,
                    events: vec![],
                },
            ])),
            requested_heights: Arc::clone(&requested_heights),
        });
        let rt = Arc::new(TokioRuntime::new().unwrap());
        let (mut source, _tx_cmd) = CardanoEventSource::new_with_gateway(
            chain_id(),
            gateway,
            Duration::ZERO,
            0,
            Arc::clone(&rt),
        )
        .unwrap();
        source.last_fetched_height = Height::new(0, 41).unwrap();
        let event_rx = source.event_bus.subscribe();

        rt.block_on(async {
            assert!(matches!(source.step().await.unwrap(), Next::Continue));
            assert_eq!(source.last_fetched_height, Height::new(0, 43).unwrap());

            let block_42 = event_rx.try_recv().unwrap();
            let block_42 = block_42.as_ref().as_ref().unwrap();
            assert_eq!(block_42.height, Height::new(0, 42).unwrap());
            assert!(block_42
                .events
                .iter()
                .any(|event| matches!(event.event, IbcEvent::SendPacket(_))));

            assert!(matches!(source.step().await.unwrap(), Next::Continue));
            assert_eq!(source.last_fetched_height, Height::new(0, 44).unwrap());
        });

        assert_eq!(
            *requested_heights.lock().unwrap(),
            vec![Height::new(0, 41).unwrap(), Height::new(0, 43).unwrap()]
        );
    }

    fn chain_id() -> ChainId {
        "cardano-preprod".parse().unwrap()
    }

    fn block_with_send_packet() -> BlockEvents {
        BlockEvents {
            height: 42,
            events: vec![ResponseDeliverTx {
                code: 0,
                events: vec![send_packet_event("7")],
            }],
        }
    }

    fn block_with_malformed_and_valid_send_packets() -> BlockEvents {
        BlockEvents {
            height: 42,
            events: vec![ResponseDeliverTx {
                code: 0,
                events: vec![send_packet_event("not-a-number"), send_packet_event("7")],
            }],
        }
    }

    fn send_packet_event(sequence: &str) -> CoreEvent {
        CoreEvent {
            r#type: "send_packet".to_string(),
            event_attribute: attrs(&[
                ("packet_sequence", sequence),
                ("packet_src_port", "transfer"),
                ("packet_src_channel", "channel-2"),
                ("packet_dst_port", "transfer"),
                ("packet_dst_channel", "channel-0"),
                ("packet_data", "deadbeef"),
                ("packet_timeout_height", "0-0"),
                ("packet_timeout_timestamp", "1000"),
            ]),
        }
    }

    fn attrs(kvs: &[(&str, &str)]) -> Vec<CoreEventAttribute> {
        kvs.iter()
            .map(|(key, value)| CoreEventAttribute {
                key: (*key).to_string(),
                value: (*value).to_string(),
                index: true,
            })
            .collect()
    }
}
