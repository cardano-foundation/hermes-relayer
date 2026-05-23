use core::time::Duration;

use tracing::{debug, error_span, info, warn};

use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use ibc_relayer_types::events::{IbcEvent, ModuleEvent};

use crate::chain::handle::Subscription;
use crate::event::source::EventBatch;
use crate::util::task::{spawn_background_task, Next, TaskError, TaskHandle};

use super::error::RunError;

const ROUTER_MODULE: &str = "stellaribcrouter";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StellarPacketEvent {
    pub kind: String,
    pub client_id: String,
    pub sequence: u64,
    pub tx_hash: String,
    pub event_id: String,
}

pub fn extract_router_event(ev: &ModuleEvent) -> Option<StellarPacketEvent> {
    if ev.module_name.to_string() != ROUTER_MODULE {
        return None;
    }
    if !matches!(
        ev.kind.as_str(),
        "send_packet" | "recv_packet" | "write_ack" | "ack_packet" | "timeout_packet"
    ) {
        return None;
    }
    let mut out = StellarPacketEvent {
        kind: ev.kind.clone(),
        client_id: String::new(),
        sequence: 0,
        tx_hash: String::new(),
        event_id: String::new(),
    };
    for attr in &ev.attributes {
        match attr.key.as_str() {
            "client_id" => out.client_id = attr.value.clone(),
            "sequence" => {
                if let Ok(n) = attr.value.parse::<u64>() {
                    out.sequence = n;
                }
            }
            "tx_hash" => out.tx_hash = attr.value.clone(),
            "event_id" => out.event_id = attr.value.clone(),
            _ => {}
        }
    }
    Some(out)
}

pub fn spawn_stellar_packet_worker(chain_id: ChainId, subscription: Subscription) -> TaskHandle {
    let span = error_span!("worker.stellar_packet", chain.id = %chain_id);

    spawn_background_task(
        span,
        Some(Duration::from_millis(100)),
        move || match subscription.recv() {
            Ok(arc_batch) => match arc_batch.as_ref() {
                Ok(batch) => {
                    process_batch(&chain_id, batch);
                    Ok(Next::Continue)
                }
                Err(err) => {
                    warn!("stellar packet worker received error from subscription: {err}");
                    Ok(Next::Continue)
                }
            },
            Err(_) => {
                debug!("stellar packet worker: subscription closed, exiting");
                Ok::<Next, TaskError<RunError>>(Next::Abort)
            }
        },
    )
}

fn process_batch(chain_id: &ChainId, batch: &EventBatch) {
    let height = batch.height;
    for ev in &batch.events {
        if let IbcEvent::AppModule(m) = &ev.event {
            if let Some(packet_ev) = extract_router_event(m) {
                info!(
                    target: "stellar_packet",
                    chain = %chain_id,
                    kind = %packet_ev.kind,
                    client_id = %packet_ev.client_id,
                    sequence = packet_ev.sequence,
                    tx_hash = %packet_ev.tx_hash,
                    event_id = %packet_ev.event_id,
                    ledger = height.revision_height(),
                    "observed stellar router event"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    use ibc_relayer_types::events::{ModuleEventAttribute, ModuleId};

    fn build_event(kind: &str, module: &str, attrs: &[(&str, &str)]) -> ModuleEvent {
        ModuleEvent {
            kind: kind.to_string(),
            module_name: ModuleId::new(Cow::Borrowed(module)).unwrap(),
            attributes: attrs
                .iter()
                .map(|(k, v)| ModuleEventAttribute {
                    key: (*k).to_string(),
                    value: (*v).to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn extracts_send_packet_attributes() {
        let ev = build_event(
            "send_packet",
            "stellaribcrouter",
            &[
                ("client_id", "10-stellar-0"),
                ("sequence", "42"),
                ("tx_hash", "deadbeef"),
                ("event_id", "1234-1"),
            ],
        );
        let out = extract_router_event(&ev).unwrap();
        assert_eq!(out.kind, "send_packet");
        assert_eq!(out.client_id, "10-stellar-0");
        assert_eq!(out.sequence, 42);
        assert_eq!(out.tx_hash, "deadbeef");
        assert_eq!(out.event_id, "1234-1");
    }

    #[test]
    fn rejects_other_module() {
        let ev = build_event(
            "send_packet",
            "someothermodule",
            &[("client_id", "10-stellar-0"), ("sequence", "1")],
        );
        assert!(extract_router_event(&ev).is_none());
    }

    #[test]
    fn rejects_unknown_kind() {
        let ev = build_event(
            "random_event",
            "stellaribcrouter",
            &[("client_id", "10-stellar-0"), ("sequence", "1")],
        );
        assert!(extract_router_event(&ev).is_none());
    }

    #[test]
    fn ignores_unknown_attributes() {
        let ev = build_event(
            "write_ack",
            "stellaribcrouter",
            &[
                ("client_id", "10-stellar-3"),
                ("sequence", "7"),
                ("foo", "bar"),
                ("tx_hash", "abc"),
            ],
        );
        let out = extract_router_event(&ev).unwrap();
        assert_eq!(out.client_id, "10-stellar-3");
        assert_eq!(out.sequence, 7);
        assert_eq!(out.tx_hash, "abc");
        assert_eq!(out.event_id, "");
    }

    #[test]
    fn malformed_sequence_falls_back_to_zero() {
        let ev = build_event(
            "send_packet",
            "stellaribcrouter",
            &[("client_id", "c"), ("sequence", "not-a-number")],
        );
        let out = extract_router_event(&ev).unwrap();
        assert_eq!(out.sequence, 0);
    }

    #[test]
    fn accepts_all_five_router_kinds() {
        for kind in [
            "send_packet",
            "recv_packet",
            "write_ack",
            "ack_packet",
            "timeout_packet",
        ] {
            let ev = build_event(
                kind,
                "stellaribcrouter",
                &[("client_id", "c"), ("sequence", "1")],
            );
            assert!(
                extract_router_event(&ev).is_some(),
                "kind {kind} should be accepted"
            );
        }
    }
}
