//! Event source for Cardano chain
//!
//! Polls the Gateway for IBC events and broadcasts them to subscribers.

use std::{collections::BTreeMap, sync::Arc};

use crossbeam_channel as channel;
use tokio::{
    runtime::Runtime as TokioRuntime,
    time::{sleep, Duration, Instant},
};
use tracing::{debug, error, error_span, trace};

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

use super::{event_parser, gateway_client::GatewayClient};

use crate::event::source::{EventBatch, EventSourceCmd, TxEventSourceCmd};

pub type Result<T> = core::result::Result<T, Error>;

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
    gateway_client: GatewayClient,

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
}

impl CardanoEventSource {
    pub fn new(
        chain_id: ChainId,
        gateway_client: GatewayClient,
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

        // Query Gateway for events since last height
        let response = self
            .gateway_client
            .query_events(self.last_fetched_height)
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

        let start_height = self.last_fetched_height.revision_height().saturating_add(1);
        let end_height = scanned_to_height.revision_height();

        if start_height <= end_height {
            trace!(
                "received {} block(s) with IBC events from height {} to {}, gateway current height {}",
                response.events.len(),
                self.last_fetched_height,
                scanned_to_height,
                current_height
            );

            let mut events_by_height = response
                .events
                .into_iter()
                .map(|block_events| (block_events.height, block_events))
                .collect::<BTreeMap<_, _>>();

            // Emit NewBlock for every scanned height so clear_interval can recover
            // packets whose original Cardano event was missed or temporarily unrelayable.
            for height in start_height..=end_height {
                let batch = self.process_block_events(height, events_by_height.remove(&height))?;

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

    /// Process events from a single block
    fn process_block_events(
        &self,
        raw_height: u64,
        block_events: Option<super::generated::ibc::cardano::v1::BlockEvents>,
    ) -> Result<EventBatch> {
        let height = Height::new(0, raw_height)
            .map_err(|e| Error::collect_events_failed(format!("Invalid block height: {}", e)))?;

        let mut events_with_height = vec![IbcEventWithHeight::new(
            IbcEvent::NewBlock(NewBlock::new(height)),
            height,
        )];

        if let Some(block_events) = block_events {
            // Flatten all events from all ResponseDeliverTx items and convert to cardano Event type
            let gateway_events: Vec<_> = block_events
                .events
                .into_iter()
                .flat_map(|tx_result| {
                    tx_result.events.into_iter().map(|core_event| {
                        // Convert ibc.core.types.v1.Event to ibc.cardano.v1.Event
                        super::generated::ibc::cardano::v1::Event {
                            r#type: core_event.r#type,
                            attributes: core_event
                                .event_attribute
                                .into_iter()
                                .map(|attr| super::generated::ibc::cardano::v1::EventAttribute {
                                    key: attr.key,
                                    value: attr.value,
                                })
                                .collect(),
                        }
                    })
                })
                .collect();

            if !gateway_events.is_empty() {
                let ibc_events =
                    event_parser::parse_events(gateway_events, height).map_err(|e| {
                        Error::collect_events_failed(format!("Failed to parse events: {}", e))
                    })?;

                events_with_height.extend(
                    ibc_events
                        .into_iter()
                        .map(|event| IbcEventWithHeight::new(event, height)),
                );
            }
        }

        debug!(
            chain = %self.chain_id,
            height = %height,
            count = events_with_height.len(),
            "parsed {} Cardano events at height {}",
            events_with_height.len(),
            height
        );

        let batch = EventBatch {
            chain_id: self.chain_id.clone(),
            tracking_id: TrackingId::new_uuid(),
            height,
            events: events_with_height,
        };

        Ok(batch)
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
    let replay_height = latest_height
        .revision_height()
        .saturating_sub(event_replay_window)
        .max(1);

    Height::new(latest_height.revision_number(), replay_height).map_err(|e| {
        Error::collect_events_failed(format!("Invalid replay height from Gateway: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use ibc_relayer_types::core::ics02_client::height::Height;

    use super::startup_replay_height;

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
}
