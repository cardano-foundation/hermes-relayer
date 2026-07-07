use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use tracing::{debug, error_span, info, instrument, warn};

use ibc_proto::google::protobuf::Any;
use ibc_relayer_types::clients::ics10_stellar::v2_msgs::Packet;
use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use ibc_relayer_types::events::{IbcEvent, ModuleEvent};

use crate::chain::handle::Subscription;
use crate::event::source::EventBatch;
use crate::util::task::{spawn_background_task, Next, TaskError, TaskHandle};

use super::error::RunError;
use super::stellar_packet::{
    build_msg_recv_packet, decode_hex, extract_ack_app_bytes, relay_ack_packet, StellarPacketDeps,
};

const SEND_PACKET_EVENT: &str = "send_packet";
const ATTR_ENCODED_PACKET: &str = "encoded_packet_hex";

pub fn spawn_cosmos_packet_worker(
    chain_id: ChainId,
    subscription: Subscription,
    deps: StellarPacketDeps,
) -> TaskHandle {
    let span = error_span!("worker.cosmos_packet", chain.id = %chain_id);

    spawn_background_task(
        span,
        Some(Duration::from_millis(100)),
        move || match subscription.recv() {
            Ok(arc_batch) => match arc_batch.as_ref() {
                Ok(batch) => {
                    process_batch(&chain_id, batch, &deps);
                    Ok(Next::Continue)
                }
                Err(err) => {
                    warn!("[cosmos] packet worker: subscription error: {err}");
                    Ok(Next::Continue)
                }
            },
            Err(_) => {
                debug!("cosmos packet worker: subscription closed, exiting");
                Ok::<Next, TaskError<RunError>>(Next::Abort)
            }
        },
    )
}

fn process_batch(chain_id: &ChainId, batch: &EventBatch, deps: &StellarPacketDeps) {
    let height = batch.height;
    for ev in &batch.events {
        if let IbcEvent::AppModule(m) = &ev.event {
            if m.kind != SEND_PACKET_EVENT {
                continue;
            }
            let Some(packet) = decode_send_packet(m) else {
                debug!("cosmos packet worker: send_packet event without decodable packet");
                continue;
            };
            let status = relay_recv_packet(chain_id, &packet, deps);
            debug!(
                target: "cosmos_packet",
                chain = %chain_id,
                sequence = packet.sequence,
                source_client = %packet.source_client,
                dest_client = %packet.dest_client,
                ledger = height.revision_height(),
                relay = %status,
                "cosmos v2 send_packet processed"
            );
        }
    }
}

fn decode_send_packet(m: &ModuleEvent) -> Option<Packet> {
    let hex = &m
        .attributes
        .iter()
        .find(|a| a.key == ATTR_ENCODED_PACKET)?
        .value;
    let bytes = decode_hex(hex)?;

    Packet::decode(bytes.as_slice()).ok()
}

#[instrument(level = "debug", skip(packet, deps), fields(
    chain = %chain_id,
    source_client = %packet.source_client,
    dest_client = %packet.dest_client,
    sequence = packet.sequence,
))]
fn relay_recv_packet(chain_id: &ChainId, packet: &Packet, deps: &StellarPacketDeps) -> String {
    let now = now_unix_secs();
    if packet.timeout_timestamp > 0 && now > packet.timeout_timestamp {
        info!(
            timeout_ts = packet.timeout_timestamp,
            now, "send_packet already expired, skipping recv relay"
        );
        return format!("expired timeout_ts={} now={now}", packet.timeout_timestamp);
    }

    let signer = deps.signer.as_str();

    let Some(src) = deps.proof_source.as_deref() else {
        debug!("recv relay skipped: no proof source configured");
        return "no_proof_source".to_string();
    };

    let (proof_commitment, proof_height) =
        match src.packet_commitment_proof(&packet.source_client, packet.sequence) {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "recv relay: commitment proof failed");
                return format!("build_failed: {e}");
            }
        };

    let mut msgs: Vec<Any> = Vec::new();

    if let Some(updater) = deps.client_updater.as_deref() {
        match updater.build_update(&packet.dest_client, proof_height) {
            Ok(update_msgs) => {
                debug!(
                    count = update_msgs.len(),
                    dest_client = %packet.dest_client,
                    target_height = %proof_height,
                    "built client update for destination (stellar)"
                );
                msgs.extend(update_msgs);
            }
            Err(e) => {
                warn!(error = %e, "recv relay: client update build failed");
                return format!("client_update_failed: {e}");
            }
        }
    }

    let recv = build_msg_recv_packet(
        packet.clone(),
        proof_commitment,
        proof_height,
        signer.to_string(),
    );
    let recv_summary = format!("recv bytes={} type_url={}", recv.value.len(), recv.type_url);
    msgs.push(recv);

    info!(
        sequence = packet.sequence,
        dest_client = %packet.dest_client,
        "[cosmos→stellar] 1/3  relaying recv packet to stellar"
    );

    let Some(dst) = deps.destination.as_deref() else {
        debug!("recv relay: no destination submitter (observer-only mode)");
        return format!("{recv_summary} submit=no_destination");
    };

    match dst.submit(msgs) {
        Ok(events) => {
            info!(
                sequence = packet.sequence,
                "[cosmos→stellar] 2/3  recv accepted — 07-tendermint verified the proof on-chain"
            );
            let acks = extract_ack_app_bytes(&events, packet.sequence);
            let ack_status = relay_ack_packet(chain_id, packet, acks, deps);
            format!("{recv_summary} submit=ok {ack_status}")
        }
        Err(e) => {
            warn!(error = %e, sequence = packet.sequence, "[cosmos→stellar] recv rejected by stellar");
            format!("{recv_summary} submit=failed: {e}")
        }
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
