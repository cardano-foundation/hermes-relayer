use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel as channel;
use tokio::runtime::Runtime as TokioRuntime;
use tokio::time::sleep;
use tracing::{debug, error, error_span};

use ibc_relayer_types::core::ics02_client::events::NewBlock;
use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use ibc_relayer_types::events::IbcEvent;
use ibc_relayer_types::Height;

use crate::chain::tracking::TrackingId;
use crate::event::bus::EventBus;
use crate::event::source::{EventBatch, EventSourceCmd, TxEventSourceCmd};
use crate::event::IbcEventWithHeight;

use super::gateway_client::GatewayQueryClient;

pub type Result<T> = core::result::Result<T, crate::event::error::Error>;

pub struct StellarEventSource {
    chain_id: ChainId,
    gateway_url: String,
    poll_interval: Duration,
    event_bus: EventBus<Arc<Result<EventBatch>>>,
    rx_cmd: channel::Receiver<EventSourceCmd>,
    rt: Arc<TokioRuntime>,
    last_height: u64,
}

impl StellarEventSource {
    pub fn new(
        chain_id: ChainId,
        gateway_url: String,
        poll_interval: Duration,
        rt: Arc<TokioRuntime>,
    ) -> (Self, TxEventSourceCmd) {
        let event_bus = EventBus::new();
        let (tx_cmd, rx_cmd) = channel::unbounded();

        let source = Self {
            chain_id,
            gateway_url,
            poll_interval,
            event_bus,
            rx_cmd,
            rt,
            last_height: 0,
        };

        (source, TxEventSourceCmd::new(tx_cmd))
    }

    pub fn run(mut self) {
        let _span = error_span!("event_source.stellar", chain.id = %self.chain_id).entered();

        debug!("collecting stellar events");

        let rt = self.rt.clone();

        rt.block_on(async {
            loop {
                if let Ok(cmd) = self.rx_cmd.try_recv() {
                    match cmd {
                        EventSourceCmd::Shutdown => break,
                        EventSourceCmd::Subscribe(tx) => {
                            let _ = tx.send(self.event_bus.subscribe());
                        }
                    }
                }

                match self.poll_once().await {
                    Ok(batches) => {
                        for batch in batches {
                            self.event_bus.broadcast(Arc::new(Ok(batch)));
                        }
                    }
                    Err(e) => {
                        error!("stellar event poll error: {e}");
                    }
                }

                sleep(self.poll_interval).await;
            }
        });
    }

    async fn poll_once(&mut self) -> core::result::Result<Vec<EventBatch>, String> {
        let mut client = GatewayQueryClient::connect(self.gateway_url.clone())
            .await
            .map_err(|e| e.to_string())?;

        let resp = client.latest_height().await.map_err(|e| e.to_string())?;
        let latest = resp.revision_height;

        if latest <= self.last_height {
            return Ok(vec![]);
        }

        let mut batches = Vec::new();

        for seq in (self.last_height + 1)..=latest {
            let height = Height::new(resp.revision_number, seq)
                .map_err(|e| e.to_string())?;
            let new_block = IbcEventWithHeight::new(
                IbcEvent::NewBlock(NewBlock::new(height)),
                height,
            );
            batches.push(EventBatch {
                chain_id: self.chain_id.clone(),
                tracking_id: TrackingId::new_uuid(),
                height,
                events: vec![new_block],
            });
        }

        self.last_height = latest;
        Ok(batches)
    }
}
