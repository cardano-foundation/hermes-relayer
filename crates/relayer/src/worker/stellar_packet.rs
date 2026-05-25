use core::time::Duration;
use std::sync::Arc;

use prost::Message;
use stellar_xdr::curr::{Limits, ReadXdr, ScVal};
use tracing::{debug, error_span, info, warn};

use ibc_proto::google::protobuf::Any;
use ibc_relayer_types::clients::ics10_stellar::v2_msgs::{
    Height as V2Height, MsgRecvPacket, MsgTimeout, Packet, Payload, TYPE_URL_RECV_PACKET,
    TYPE_URL_TIMEOUT,
};
use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use ibc_relayer_types::events::{IbcEvent, ModuleEvent};
use ibc_relayer_types::Height as ICSHeight;

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
    pub value_xdr: Vec<u8>,
    pub contract_id: String,
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
        value_xdr: Vec::new(),
        contract_id: String::new(),
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
            "value_xdr_hex" => {
                if let Some(bytes) = decode_hex(&attr.value) {
                    out.value_xdr = bytes;
                }
            }
            "contract_id" => out.contract_id = attr.value.clone(),
            _ => {}
        }
    }
    Some(out)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PacketDecodeError {
    #[error("event body XDR decode failed: {0}")]
    Xdr(String),
    #[error("event body is not a struct map (got ScVal variant: {0})")]
    NotAStruct(&'static str),
    #[error("missing field {0} in event body")]
    MissingField(&'static str),
    #[error("field {field} has unexpected type ({reason})")]
    WrongFieldType { field: &'static str, reason: String },
}

pub fn decode_packet_from_event_body(value_xdr: &[u8]) -> Result<Packet, PacketDecodeError> {
    let body = ScVal::from_xdr(value_xdr, Limits::none())
        .map_err(|e| PacketDecodeError::Xdr(e.to_string()))?;
    decode_packet_scval(&body)
}

fn decode_packet_scval(value: &ScVal) -> Result<Packet, PacketDecodeError> {
    let entries = struct_entries(value)?;

    let sequence = u64_field(entries, "sequence")?;
    let source_client = string_field(entries, "source_client")?;
    let dest_client = string_field(entries, "dest_client")?;
    let timeout_timestamp = u64_field(entries, "timeout_timestamp")?;
    let payloads_scval = lookup(entries, "payloads")?;
    let payloads = decode_payloads(payloads_scval)?;

    Ok(Packet {
        sequence,
        source_client,
        dest_client,
        timeout_timestamp,
        payloads,
    })
}

fn decode_payloads(value: &ScVal) -> Result<Vec<Payload>, PacketDecodeError> {
    let vec = match value {
        ScVal::Vec(Some(v)) => v,
        ScVal::Vec(None) => {
            return Ok(Vec::new());
        }
        other => {
            return Err(PacketDecodeError::WrongFieldType {
                field: "payloads",
                reason: format!("expected Vec, got {}", scval_variant_name(other)),
            });
        }
    };
    vec.0.iter().map(decode_payload).collect()
}

fn decode_payload(value: &ScVal) -> Result<Payload, PacketDecodeError> {
    let entries = struct_entries(value)?;
    let source_port = string_field(entries, "source_port")?;
    let dest_port = string_field(entries, "dest_port")?;
    let version = string_field(entries, "version")?;
    let encoding = string_field(entries, "encoding")?;
    let value_bytes = match lookup(entries, "value")? {
        ScVal::Bytes(b) => b.0.to_vec(),
        other => {
            return Err(PacketDecodeError::WrongFieldType {
                field: "value",
                reason: format!("expected Bytes, got {}", scval_variant_name(other)),
            });
        }
    };
    Ok(Payload {
        source_port,
        dest_port,
        version,
        encoding,
        value: value_bytes,
    })
}

fn struct_entries(value: &ScVal) -> Result<&[stellar_xdr::curr::ScMapEntry], PacketDecodeError> {
    match value {
        ScVal::Map(Some(m)) => Ok(m.0.as_slice()),
        other => Err(PacketDecodeError::NotAStruct(scval_variant_name(other))),
    }
}

fn lookup<'a>(
    entries: &'a [stellar_xdr::curr::ScMapEntry],
    name: &'static str,
) -> Result<&'a ScVal, PacketDecodeError> {
    for entry in entries {
        if let ScVal::Symbol(sym) = &entry.key {
            if sym.0.as_slice() == name.as_bytes() {
                return Ok(&entry.val);
            }
        }
    }
    Err(PacketDecodeError::MissingField(name))
}

fn u64_field(
    entries: &[stellar_xdr::curr::ScMapEntry],
    name: &'static str,
) -> Result<u64, PacketDecodeError> {
    match lookup(entries, name)? {
        ScVal::U64(n) => Ok(*n),
        other => Err(PacketDecodeError::WrongFieldType {
            field: name,
            reason: format!("expected U64, got {}", scval_variant_name(other)),
        }),
    }
}

fn string_field(
    entries: &[stellar_xdr::curr::ScMapEntry],
    name: &'static str,
) -> Result<String, PacketDecodeError> {
    match lookup(entries, name)? {
        ScVal::String(s) => core::str::from_utf8(s.0.as_slice())
            .map(|s| s.to_owned())
            .map_err(|e| PacketDecodeError::WrongFieldType {
                field: name,
                reason: format!("String not UTF-8: {e}"),
            }),
        other => Err(PacketDecodeError::WrongFieldType {
            field: name,
            reason: format!("expected String, got {}", scval_variant_name(other)),
        }),
    }
}

fn scval_variant_name(value: &ScVal) -> &'static str {
    match value {
        ScVal::Bool(_) => "Bool",
        ScVal::Void => "Void",
        ScVal::Error(_) => "Error",
        ScVal::U32(_) => "U32",
        ScVal::I32(_) => "I32",
        ScVal::U64(_) => "U64",
        ScVal::I64(_) => "I64",
        ScVal::Timepoint(_) => "Timepoint",
        ScVal::Duration(_) => "Duration",
        ScVal::U128(_) => "U128",
        ScVal::I128(_) => "I128",
        ScVal::U256(_) => "U256",
        ScVal::I256(_) => "I256",
        ScVal::Bytes(_) => "Bytes",
        ScVal::String(_) => "String",
        ScVal::Symbol(_) => "Symbol",
        ScVal::Vec(_) => "Vec",
        ScVal::Map(_) => "Map",
        ScVal::Address(_) => "Address",
        ScVal::ContractInstance(_) => "ContractInstance",
        ScVal::LedgerKeyContractInstance => "LedgerKeyContractInstance",
        ScVal::LedgerKeyNonce(_) => "LedgerKeyNonce",
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = char_to_nibble(bytes[i])?;
        let lo = char_to_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn char_to_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PacketProofError {
    #[error("proof source failed: {0}")]
    QueryFailed(String),
    #[error("no commitment for client_id={client_id} sequence={sequence} at height={height}")]
    CommitmentAbsent {
        client_id: String,
        sequence: u64,
        height: u64,
    },
}

pub trait PacketProofSource: Send + Sync {
    fn packet_commitment_proof(
        &self,
        client_id: &str,
        sequence: u64,
    ) -> Result<(Vec<u8>, ICSHeight), PacketProofError>;
}

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("destination submit failed: {0}")]
    SubmitFailed(String),
}

pub trait PacketRelayDestination: Send + Sync {
    fn submit(&self, msgs: Vec<Any>) -> Result<String, SubmitError>;
}

pub trait PacketAbsenceProofSource: Send + Sync {
    fn packet_receipt_absence_proof(
        &self,
        dest_client_id: &str,
        sequence: u64,
    ) -> Result<(Vec<u8>, ICSHeight), PacketProofError>;
}

#[derive(Debug, thiserror::Error)]
pub enum BuildTimeoutError {
    #[error(transparent)]
    Decode(#[from] PacketDecodeError),
    #[error("source chain has no body bytes for this send_packet event")]
    MissingValueXdr,
    #[error(transparent)]
    Proof(#[from] PacketProofError),
    #[error("packet sequence in event ({event}) disagrees with decoded packet ({decoded})")]
    SequenceMismatch { event: u64, decoded: u64 },
}

pub fn build_msg_timeout(
    packet: Packet,
    proof_unreceived: Vec<u8>,
    proof_height: ICSHeight,
    signer: String,
) -> Any {
    let msg = MsgTimeout {
        packet: Some(packet),
        proof_unreceived,
        proof_height: Some(V2Height {
            revision_number: proof_height.revision_number(),
            revision_height: proof_height.revision_height(),
        }),
        signer,
    };
    Any {
        type_url: TYPE_URL_TIMEOUT.to_string(),
        value: msg.encode_to_vec(),
    }
}

pub fn build_msg_timeout_from_event<S: PacketAbsenceProofSource + ?Sized>(
    event: &StellarPacketEvent,
    absence: &S,
    signer: String,
) -> Result<Any, BuildTimeoutError> {
    if event.value_xdr.is_empty() {
        return Err(BuildTimeoutError::MissingValueXdr);
    }
    let packet = decode_packet_from_event_body(&event.value_xdr)?;
    if packet.sequence != event.sequence {
        return Err(BuildTimeoutError::SequenceMismatch {
            event: event.sequence,
            decoded: packet.sequence,
        });
    }
    let (proof_unreceived, proof_height) =
        absence.packet_receipt_absence_proof(&packet.dest_client, packet.sequence)?;
    Ok(build_msg_timeout(
        packet,
        proof_unreceived,
        proof_height,
        signer,
    ))
}

#[derive(Debug, thiserror::Error)]
pub enum BuildMsgError {
    #[error(transparent)]
    Decode(#[from] PacketDecodeError),
    #[error("source chain has no body bytes for this send_packet event")]
    MissingValueXdr,
    #[error(transparent)]
    Proof(#[from] PacketProofError),
    #[error("packet sequence in event ({event}) disagrees with decoded packet ({decoded})")]
    SequenceMismatch { event: u64, decoded: u64 },
}

pub fn build_msg_recv_packet(
    packet: Packet,
    proof_commitment: Vec<u8>,
    proof_height: ICSHeight,
    signer: String,
) -> Any {
    let msg = MsgRecvPacket {
        packet: Some(packet),
        proof_commitment,
        proof_height: Some(V2Height {
            revision_number: proof_height.revision_number(),
            revision_height: proof_height.revision_height(),
        }),
        signer,
    };
    Any {
        type_url: TYPE_URL_RECV_PACKET.to_string(),
        value: msg.encode_to_vec(),
    }
}

pub fn build_msg_recv_packet_from_event<S: PacketProofSource + ?Sized>(
    event: &StellarPacketEvent,
    source: &S,
    signer: String,
) -> Result<Any, BuildMsgError> {
    if event.value_xdr.is_empty() {
        return Err(BuildMsgError::MissingValueXdr);
    }
    let packet = decode_packet_from_event_body(&event.value_xdr)?;
    if packet.sequence != event.sequence {
        return Err(BuildMsgError::SequenceMismatch {
            event: event.sequence,
            decoded: packet.sequence,
        });
    }
    let (proof_commitment, proof_height) =
        source.packet_commitment_proof(&event.client_id, event.sequence)?;
    Ok(build_msg_recv_packet(
        packet,
        proof_commitment,
        proof_height,
        signer,
    ))
}

pub struct StellarPacketDeps {
    pub proof_source: Option<Arc<dyn PacketProofSource>>,
    pub destination: Option<Arc<dyn PacketRelayDestination>>,
    pub absence_source: Option<Arc<dyn PacketAbsenceProofSource>>,
    pub source_submitter: Option<Arc<dyn PacketRelayDestination>>,
    pub signer: String,
    pub source_signer: String,
}

impl StellarPacketDeps {
    pub fn observer_only() -> Self {
        Self {
            proof_source: None,
            destination: None,
            absence_source: None,
            source_submitter: None,
            signer: String::new(),
            source_signer: String::new(),
        }
    }
}

pub fn spawn_stellar_packet_worker(
    chain_id: ChainId,
    subscription: Subscription,
    deps: StellarPacketDeps,
) -> TaskHandle {
    let span = error_span!("worker.stellar_packet", chain.id = %chain_id);

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

fn process_batch(chain_id: &ChainId, batch: &EventBatch, deps: &StellarPacketDeps) {
    let height = batch.height;
    for ev in &batch.events {
        if let IbcEvent::AppModule(m) = &ev.event {
            if let Some(packet_ev) = extract_router_event(m) {
                crate::telemetry!(stellar_router_event_observed, chain_id, &packet_ev.kind);
                let decoded = if packet_ev.value_xdr.is_empty() {
                    None
                } else {
                    decode_packet_from_event_body(&packet_ev.value_xdr).ok()
                };
                let payload_summary = match (&packet_ev.value_xdr.is_empty(), &decoded) {
                    (true, _) => "none".to_string(),
                    (false, Some(p)) => format!(
                        "src={} dst={} payloads={}",
                        p.source_client,
                        p.dest_client,
                        p.payloads.len()
                    ),
                    (false, None) => "decode_failed".to_string(),
                };
                let relay_status = if packet_ev.kind == "send_packet" {
                    dispatch_send_packet(chain_id, &packet_ev, decoded.as_ref(), deps)
                } else {
                    "n/a".to_string()
                };
                info!(
                    target: "stellar_packet",
                    chain = %chain_id,
                    kind = %packet_ev.kind,
                    client_id = %packet_ev.client_id,
                    sequence = packet_ev.sequence,
                    tx_hash = %packet_ev.tx_hash,
                    event_id = %packet_ev.event_id,
                    ledger = height.revision_height(),
                    payload = %payload_summary,
                    relay = %relay_status,
                    "observed stellar router event"
                );
            }
        }
    }
}

fn dispatch_send_packet(
    chain_id: &ChainId,
    packet_ev: &StellarPacketEvent,
    decoded: Option<&Packet>,
    deps: &StellarPacketDeps,
) -> String {
    let now = now_unix_secs();
    if let Some(packet) = decoded {
        if packet.timeout_timestamp > 0 && now > packet.timeout_timestamp {
            return relay_timeout(
                chain_id,
                packet_ev,
                deps.absence_source.as_deref(),
                deps.source_submitter.as_deref(),
                &deps.source_signer,
                packet.timeout_timestamp,
                now,
            );
        }
    }
    relay_send_packet(
        chain_id,
        packet_ev,
        deps.proof_source.as_deref(),
        deps.destination.as_deref(),
        &deps.signer,
    )
}

fn relay_send_packet(
    chain_id: &ChainId,
    packet_ev: &StellarPacketEvent,
    proof_source: Option<&dyn PacketProofSource>,
    destination: Option<&dyn PacketRelayDestination>,
    signer: &str,
) -> String {
    let Some(src) = proof_source else {
        return "no_proof_source".to_string();
    };
    let any = match build_msg_recv_packet_from_event(packet_ev, src, signer.to_string()) {
        Ok(a) => a,
        Err(e) => {
            crate::telemetry!(stellar_relay_build_failure, chain_id, "recv");
            return format!("build_failed: {e}");
        }
    };
    let any_summary = format!(
        "built_msg_recv_packet bytes={} type_url={}",
        any.value.len(),
        any.type_url
    );
    let Some(dst) = destination else {
        return format!("{any_summary} submit=no_destination");
    };
    match dst.submit(vec![any]) {
        Ok(tx_hash) => {
            crate::telemetry!(stellar_relay_success, chain_id, "recv");
            format!("{any_summary} submit=ok tx={tx_hash}")
        }
        Err(e) => {
            crate::telemetry!(stellar_relay_submit_failure, chain_id, "recv");
            format!("{any_summary} submit=failed: {e}")
        }
    }
}

fn relay_timeout(
    chain_id: &ChainId,
    packet_ev: &StellarPacketEvent,
    absence_source: Option<&dyn PacketAbsenceProofSource>,
    source_submitter: Option<&dyn PacketRelayDestination>,
    source_signer: &str,
    timeout_ts: u64,
    now: u64,
) -> String {
    let prefix = format!("timeout(timeout_ts={timeout_ts} now={now})");
    let Some(absence) = absence_source else {
        return format!("{prefix} skip=no_absence_source");
    };
    let any = match build_msg_timeout_from_event(packet_ev, absence, source_signer.to_string()) {
        Ok(a) => a,
        Err(e) => {
            crate::telemetry!(stellar_relay_build_failure, chain_id, "timeout");
            return format!("{prefix} build_failed: {e}");
        }
    };
    let any_summary = format!(
        "built_msg_timeout bytes={} type_url={}",
        any.value.len(),
        any.type_url
    );
    let Some(submitter) = source_submitter else {
        return format!("{prefix} {any_summary} submit=no_source_submitter");
    };
    match submitter.submit(vec![any]) {
        Ok(tx_hash) => {
            crate::telemetry!(stellar_relay_success, chain_id, "timeout");
            format!("{prefix} {any_summary} submit=ok tx={tx_hash}")
        }
        Err(e) => {
            crate::telemetry!(stellar_relay_submit_failure, chain_id, "timeout");
            format!("{prefix} {any_summary} submit=failed: {e}")
        }
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    #[test]
    fn value_xdr_hex_attribute_round_trips() {
        let raw_bytes = vec![0x00, 0xAB, 0xCD, 0xFF];
        let hex = "00abcdff";
        let ev = build_event(
            "send_packet",
            "stellaribcrouter",
            &[
                ("client_id", "10-stellar-0"),
                ("sequence", "1"),
                ("value_xdr_hex", hex),
                ("contract_id", "CABC"),
            ],
        );
        let out = extract_router_event(&ev).unwrap();
        assert_eq!(out.value_xdr, raw_bytes);
        assert_eq!(out.contract_id, "CABC");
    }

    #[test]
    fn malformed_value_xdr_hex_falls_back_to_empty() {
        let ev = build_event(
            "send_packet",
            "stellaribcrouter",
            &[
                ("client_id", "c"),
                ("sequence", "1"),
                ("value_xdr_hex", "zz"),
            ],
        );
        let out = extract_router_event(&ev).unwrap();
        assert!(out.value_xdr.is_empty());
    }
}

#[cfg(test)]
mod decoder_tests {
    use super::*;
    use stellar_xdr::curr::{
        BytesM, Limits, ScBytes, ScMap, ScMapEntry, ScString, ScSymbol, ScVec, StringM, VecM,
        WriteXdr,
    };

    fn sym(s: &str) -> ScVal {
        ScVal::Symbol(ScSymbol(
            StringM::<32>::try_from(s.as_bytes().to_vec()).unwrap(),
        ))
    }

    fn string_val(s: &str) -> ScVal {
        ScVal::String(ScString(StringM::try_from(s.as_bytes().to_vec()).unwrap()))
    }

    fn bytes_val(b: &[u8]) -> ScVal {
        ScVal::Bytes(ScBytes(BytesM::try_from(b.to_vec()).unwrap()))
    }

    fn struct_val(entries: Vec<(&str, ScVal)>) -> ScVal {
        let mapped: Vec<ScMapEntry> = entries
            .into_iter()
            .map(|(k, v)| ScMapEntry {
                key: sym(k),
                val: v,
            })
            .collect();
        ScVal::Map(Some(ScMap(VecM::try_from(mapped).unwrap())))
    }

    fn vec_val(items: Vec<ScVal>) -> ScVal {
        ScVal::Vec(Some(ScVec(VecM::try_from(items).unwrap())))
    }

    fn sample_payload() -> ScVal {
        struct_val(vec![
            ("source_port", string_val("transfer")),
            ("dest_port", string_val("transfer")),
            ("version", string_val("ics20-2")),
            ("encoding", string_val("json")),
            ("value", bytes_val(b"app-data")),
        ])
    }

    fn sample_packet_scval() -> ScVal {
        struct_val(vec![
            ("sequence", ScVal::U64(42)),
            ("source_client", string_val("10-stellar-0")),
            ("dest_client", string_val("07-tendermint-0")),
            ("timeout_timestamp", ScVal::U64(1_700_000_500)),
            ("payloads", vec_val(vec![sample_payload()])),
        ])
    }

    #[test]
    fn decode_single_payload_packet() {
        let xdr = sample_packet_scval().to_xdr(Limits::none()).unwrap();
        let packet = decode_packet_from_event_body(&xdr).unwrap();
        assert_eq!(packet.sequence, 42);
        assert_eq!(packet.source_client, "10-stellar-0");
        assert_eq!(packet.dest_client, "07-tendermint-0");
        assert_eq!(packet.timeout_timestamp, 1_700_000_500);
        assert_eq!(packet.payloads.len(), 1);
        let p = &packet.payloads[0];
        assert_eq!(p.source_port, "transfer");
        assert_eq!(p.dest_port, "transfer");
        assert_eq!(p.version, "ics20-2");
        assert_eq!(p.encoding, "json");
        assert_eq!(p.value, b"app-data");
    }

    #[test]
    fn decode_empty_payloads_vec_is_ok() {
        let body = struct_val(vec![
            ("sequence", ScVal::U64(1)),
            ("source_client", string_val("a")),
            ("dest_client", string_val("b")),
            ("timeout_timestamp", ScVal::U64(0)),
            ("payloads", vec_val(vec![])),
        ]);
        let xdr = body.to_xdr(Limits::none()).unwrap();
        let packet = decode_packet_from_event_body(&xdr).unwrap();
        assert!(packet.payloads.is_empty());
    }

    #[test]
    fn decode_rejects_non_struct_body() {
        let xdr = ScVal::U64(99).to_xdr(Limits::none()).unwrap();
        let err = decode_packet_from_event_body(&xdr).unwrap_err();
        assert!(matches!(err, PacketDecodeError::NotAStruct(_)));
    }

    #[test]
    fn decode_rejects_missing_required_field() {
        let body = struct_val(vec![
            ("sequence", ScVal::U64(1)),
            ("source_client", string_val("a")),
            ("dest_client", string_val("b")),
            ("payloads", vec_val(vec![])),
        ]);
        let xdr = body.to_xdr(Limits::none()).unwrap();
        let err = decode_packet_from_event_body(&xdr).unwrap_err();
        assert_eq!(err, PacketDecodeError::MissingField("timeout_timestamp"));
    }

    #[test]
    fn decode_rejects_wrong_field_type() {
        let body = struct_val(vec![
            ("sequence", string_val("not-a-u64")),
            ("source_client", string_val("a")),
            ("dest_client", string_val("b")),
            ("timeout_timestamp", ScVal::U64(0)),
            ("payloads", vec_val(vec![])),
        ]);
        let xdr = body.to_xdr(Limits::none()).unwrap();
        let err = decode_packet_from_event_body(&xdr).unwrap_err();
        assert!(matches!(
            err,
            PacketDecodeError::WrongFieldType {
                field: "sequence",
                ..
            }
        ));
    }

    #[test]
    fn decode_rejects_garbage_xdr() {
        let err = decode_packet_from_event_body(b"not xdr").unwrap_err();
        assert!(matches!(err, PacketDecodeError::Xdr(_)));
    }

    fn test_chain_id() -> ChainId {
        ChainId::from_string("stellar-testnet")
    }

    struct FakeProofSource {
        proof: Vec<u8>,
        height: ICSHeight,
    }
    impl PacketProofSource for FakeProofSource {
        fn packet_commitment_proof(
            &self,
            _client_id: &str,
            _sequence: u64,
        ) -> Result<(Vec<u8>, ICSHeight), PacketProofError> {
            Ok((self.proof.clone(), self.height))
        }
    }
    struct FailingProofSource;
    impl PacketProofSource for FailingProofSource {
        fn packet_commitment_proof(
            &self,
            client_id: &str,
            sequence: u64,
        ) -> Result<(Vec<u8>, ICSHeight), PacketProofError> {
            Err(PacketProofError::CommitmentAbsent {
                client_id: client_id.to_string(),
                sequence,
                height: 0,
            })
        }
    }

    fn packet_body_with_sequence(sequence: u64) -> Vec<u8> {
        struct_val(vec![
            ("sequence", ScVal::U64(sequence)),
            ("source_client", string_val("10-stellar-0")),
            ("dest_client", string_val("07-tendermint-0")),
            ("timeout_timestamp", ScVal::U64(1_700_000_500)),
            ("payloads", vec_val(vec![sample_payload()])),
        ])
        .to_xdr(Limits::none())
        .unwrap()
    }

    fn synthetic_event(sequence: u64) -> StellarPacketEvent {
        StellarPacketEvent {
            kind: "send_packet".to_string(),
            client_id: "10-stellar-0".to_string(),
            sequence,
            tx_hash: "tx-hash".to_string(),
            event_id: "ev-1".to_string(),
            value_xdr: packet_body_with_sequence(sequence),
            contract_id: "CABC".to_string(),
        }
    }

    #[test]
    fn build_msg_recv_packet_produces_well_formed_any() {
        let decoded = decode_packet_scval(&sample_packet_scval()).unwrap();
        let proof_height = ICSHeight::new(0, 105).unwrap();
        let any = build_msg_recv_packet(
            decoded.clone(),
            vec![0xAB, 0xCD],
            proof_height,
            "stellar1signer".to_string(),
        );
        assert_eq!(any.type_url, TYPE_URL_RECV_PACKET);

        let parsed = MsgRecvPacket::decode(any.value.as_slice()).unwrap();
        assert_eq!(parsed.signer, "stellar1signer");
        assert_eq!(parsed.proof_commitment, vec![0xAB, 0xCD]);
        let h = parsed.proof_height.unwrap();
        assert_eq!(h.revision_number, 0);
        assert_eq!(h.revision_height, 105);
        let p = parsed.packet.unwrap();
        assert_eq!(p.sequence, decoded.sequence);
        assert_eq!(p.source_client, decoded.source_client);
        assert_eq!(p.payloads.len(), decoded.payloads.len());
    }

    #[test]
    fn build_from_event_happy_path() {
        let event = synthetic_event(42);
        let src = FakeProofSource {
            proof: vec![0x11, 0x22, 0x33],
            height: ICSHeight::new(0, 200).unwrap(),
        };
        let any = build_msg_recv_packet_from_event(&event, &src, "signer".to_string()).unwrap();
        let parsed = MsgRecvPacket::decode(any.value.as_slice()).unwrap();
        assert_eq!(parsed.signer, "signer");
        assert_eq!(parsed.proof_commitment, vec![0x11, 0x22, 0x33]);
        assert_eq!(parsed.proof_height.unwrap().revision_height, 200);
        assert_eq!(parsed.packet.unwrap().sequence, 42);
    }

    #[test]
    fn build_from_event_missing_value_xdr_errors() {
        let mut event = synthetic_event(1);
        event.value_xdr.clear();
        let src = FakeProofSource {
            proof: vec![],
            height: ICSHeight::new(0, 1).unwrap(),
        };
        let err = build_msg_recv_packet_from_event(&event, &src, "s".into()).unwrap_err();
        assert!(matches!(err, BuildMsgError::MissingValueXdr));
    }

    #[test]
    fn build_from_event_sequence_mismatch_errors() {
        let mut event = synthetic_event(42);
        event.sequence = 999;
        let src = FakeProofSource {
            proof: vec![],
            height: ICSHeight::new(0, 1).unwrap(),
        };
        let err = build_msg_recv_packet_from_event(&event, &src, "s".into()).unwrap_err();
        assert!(matches!(
            err,
            BuildMsgError::SequenceMismatch {
                event: 999,
                decoded: 42
            }
        ));
    }

    #[test]
    fn build_from_event_propagates_proof_query_failure() {
        let event = synthetic_event(7);
        let err =
            build_msg_recv_packet_from_event(&event, &FailingProofSource, "s".into()).unwrap_err();
        assert!(matches!(err, BuildMsgError::Proof(_)));
    }

    #[test]
    fn build_from_event_propagates_decode_failure() {
        let mut event = synthetic_event(1);
        event.value_xdr = b"not xdr".to_vec();
        let src = FakeProofSource {
            proof: vec![],
            height: ICSHeight::new(0, 1).unwrap(),
        };
        let err = build_msg_recv_packet_from_event(&event, &src, "s".into()).unwrap_err();
        assert!(matches!(err, BuildMsgError::Decode(_)));
    }

    struct RecordingDestination {
        submitted: std::sync::Mutex<Vec<Vec<Any>>>,
        tx_hash: String,
    }
    impl PacketRelayDestination for RecordingDestination {
        fn submit(&self, msgs: Vec<Any>) -> Result<String, SubmitError> {
            self.submitted.lock().unwrap().push(msgs);
            Ok(self.tx_hash.clone())
        }
    }

    struct FailingDestination;
    impl PacketRelayDestination for FailingDestination {
        fn submit(&self, _msgs: Vec<Any>) -> Result<String, SubmitError> {
            Err(SubmitError::SubmitFailed("nack from chain".to_string()))
        }
    }

    #[test]
    fn relay_send_packet_submits_built_any_to_destination() {
        let event = synthetic_event(11);
        let src = FakeProofSource {
            proof: vec![0xAA],
            height: ICSHeight::new(0, 50).unwrap(),
        };
        let dst = RecordingDestination {
            submitted: std::sync::Mutex::new(Vec::new()),
            tx_hash: "ABC123".to_string(),
        };

        let status = relay_send_packet(&test_chain_id(), &event, Some(&src), Some(&dst), "signer");
        assert!(
            status.contains("submit=ok") && status.contains("tx=ABC123"),
            "unexpected status: {status}"
        );

        let recorded = dst.submitted.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let msgs = &recorded[0];
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].type_url, TYPE_URL_RECV_PACKET);
        let parsed = MsgRecvPacket::decode(msgs[0].value.as_slice()).unwrap();
        assert_eq!(parsed.packet.unwrap().sequence, 11);
        assert_eq!(parsed.signer, "signer");
    }

    #[test]
    fn relay_send_packet_reports_no_destination_when_unset() {
        let event = synthetic_event(1);
        let src = FakeProofSource {
            proof: vec![],
            height: ICSHeight::new(0, 1).unwrap(),
        };
        let status = relay_send_packet(&test_chain_id(), &event, Some(&src), None, "s");
        assert!(
            status.contains("submit=no_destination"),
            "unexpected status: {status}"
        );
    }

    #[test]
    fn relay_send_packet_reports_submit_failure() {
        let event = synthetic_event(1);
        let src = FakeProofSource {
            proof: vec![],
            height: ICSHeight::new(0, 1).unwrap(),
        };
        let status = relay_send_packet(
            &test_chain_id(),
            &event,
            Some(&src),
            Some(&FailingDestination),
            "s",
        );
        assert!(
            status.contains("submit=failed: destination submit failed: nack from chain"),
            "unexpected status: {status}"
        );
    }

    #[test]
    fn relay_send_packet_skips_when_no_proof_source() {
        let event = synthetic_event(1);
        let dst = RecordingDestination {
            submitted: std::sync::Mutex::new(Vec::new()),
            tx_hash: "tx".to_string(),
        };
        let status = relay_send_packet(&test_chain_id(), &event, None, Some(&dst), "s");
        assert_eq!(status, "no_proof_source");
        assert!(dst.submitted.lock().unwrap().is_empty());
    }

    struct FakeAbsenceSource {
        proof: Vec<u8>,
        height: ICSHeight,
    }
    impl PacketAbsenceProofSource for FakeAbsenceSource {
        fn packet_receipt_absence_proof(
            &self,
            _dest_client_id: &str,
            _sequence: u64,
        ) -> Result<(Vec<u8>, ICSHeight), PacketProofError> {
            Ok((self.proof.clone(), self.height))
        }
    }
    struct FailingAbsenceSource;
    impl PacketAbsenceProofSource for FailingAbsenceSource {
        fn packet_receipt_absence_proof(
            &self,
            dest_client_id: &str,
            sequence: u64,
        ) -> Result<(Vec<u8>, ICSHeight), PacketProofError> {
            Err(PacketProofError::QueryFailed(format!(
                "receipt present for {dest_client_id}/{sequence}"
            )))
        }
    }

    #[test]
    fn build_msg_timeout_produces_well_formed_any() {
        let packet = decode_packet_scval(&sample_packet_scval()).unwrap();
        let any = build_msg_timeout(
            packet.clone(),
            vec![0xDE, 0xAD],
            ICSHeight::new(0, 321).unwrap(),
            "signer".to_string(),
        );
        assert_eq!(any.type_url, TYPE_URL_TIMEOUT);
        let parsed = MsgTimeout::decode(any.value.as_slice()).unwrap();
        assert_eq!(parsed.signer, "signer");
        assert_eq!(parsed.proof_unreceived, vec![0xDE, 0xAD]);
        let h = parsed.proof_height.unwrap();
        assert_eq!(h.revision_height, 321);
        let p = parsed.packet.unwrap();
        assert_eq!(p.sequence, packet.sequence);
        assert_eq!(p.dest_client, packet.dest_client);
    }

    #[test]
    fn build_timeout_from_event_happy_path() {
        let event = synthetic_event(42);
        let src = FakeAbsenceSource {
            proof: vec![0x11, 0x22],
            height: ICSHeight::new(0, 500).unwrap(),
        };
        let any = build_msg_timeout_from_event(&event, &src, "signer".to_string()).unwrap();
        let parsed = MsgTimeout::decode(any.value.as_slice()).unwrap();
        assert_eq!(parsed.packet.unwrap().sequence, 42);
        assert_eq!(parsed.proof_unreceived, vec![0x11, 0x22]);
        assert_eq!(parsed.proof_height.unwrap().revision_height, 500);
    }

    #[test]
    fn build_timeout_from_event_missing_value_xdr_errors() {
        let mut event = synthetic_event(1);
        event.value_xdr.clear();
        let src = FakeAbsenceSource {
            proof: vec![],
            height: ICSHeight::new(0, 1).unwrap(),
        };
        let err = build_msg_timeout_from_event(&event, &src, "s".into()).unwrap_err();
        assert!(matches!(err, BuildTimeoutError::MissingValueXdr));
    }

    #[test]
    fn build_timeout_from_event_sequence_mismatch_errors() {
        let mut event = synthetic_event(42);
        event.sequence = 999;
        let src = FakeAbsenceSource {
            proof: vec![],
            height: ICSHeight::new(0, 1).unwrap(),
        };
        let err = build_msg_timeout_from_event(&event, &src, "s".into()).unwrap_err();
        assert!(matches!(
            err,
            BuildTimeoutError::SequenceMismatch {
                event: 999,
                decoded: 42
            }
        ));
    }

    #[test]
    fn build_timeout_from_event_propagates_absence_query_failure() {
        let event = synthetic_event(7);
        let err =
            build_msg_timeout_from_event(&event, &FailingAbsenceSource, "s".into()).unwrap_err();
        assert!(matches!(err, BuildTimeoutError::Proof(_)));
    }

    #[test]
    fn build_timeout_from_event_propagates_decode_failure() {
        let mut event = synthetic_event(1);
        event.value_xdr = b"not xdr".to_vec();
        let src = FakeAbsenceSource {
            proof: vec![],
            height: ICSHeight::new(0, 1).unwrap(),
        };
        let err = build_msg_timeout_from_event(&event, &src, "s".into()).unwrap_err();
        assert!(matches!(err, BuildTimeoutError::Decode(_)));
    }

    #[test]
    fn build_timeout_uses_dest_client_from_packet_not_event_client_id() {
        struct AssertingSource;
        impl PacketAbsenceProofSource for AssertingSource {
            fn packet_receipt_absence_proof(
                &self,
                dest_client_id: &str,
                _sequence: u64,
            ) -> Result<(Vec<u8>, ICSHeight), PacketProofError> {
                assert_eq!(
                    dest_client_id, "07-tendermint-0",
                    "must query against packet.dest_client, not event.client_id"
                );
                Ok((vec![], ICSHeight::new(0, 1).unwrap()))
            }
        }
        let event = synthetic_event(1);
        assert_ne!(event.client_id, "07-tendermint-0");
        build_msg_timeout_from_event(&event, &AssertingSource, "s".into()).unwrap();
    }

    #[test]
    fn relay_timeout_happy_path_submits_msg_timeout_to_source() {
        let event = synthetic_event(5);
        let absence = FakeAbsenceSource {
            proof: vec![0x77, 0x88],
            height: ICSHeight::new(0, 300).unwrap(),
        };
        let src_submitter = RecordingDestination {
            submitted: std::sync::Mutex::new(Vec::new()),
            tx_hash: "TX-TIMEOUT".to_string(),
        };
        let status = relay_timeout(
            &test_chain_id(),
            &event,
            Some(&absence),
            Some(&src_submitter),
            "source-signer",
            1_700_000_000,
            1_700_000_500,
        );
        assert!(
            status.contains("submit=ok") && status.contains("tx=TX-TIMEOUT"),
            "unexpected status: {status}"
        );
        let recorded = src_submitter.submitted.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0][0].type_url, TYPE_URL_TIMEOUT);
        let parsed = MsgTimeout::decode(recorded[0][0].value.as_slice()).unwrap();
        assert_eq!(parsed.signer, "source-signer");
        assert_eq!(parsed.proof_unreceived, vec![0x77, 0x88]);
    }

    #[test]
    fn relay_timeout_no_absence_source_skips() {
        let event = synthetic_event(1);
        let status = relay_timeout(&test_chain_id(), &event, None, None, "s", 100, 200);
        assert!(status.contains("skip=no_absence_source"), "got: {status}");
    }

    #[test]
    fn relay_timeout_no_source_submitter_skips_after_build() {
        let event = synthetic_event(1);
        let absence = FakeAbsenceSource {
            proof: vec![],
            height: ICSHeight::new(0, 1).unwrap(),
        };
        let status = relay_timeout(&test_chain_id(), &event, Some(&absence), None, "s", 100, 200);
        assert!(
            status.contains("submit=no_source_submitter"),
            "got: {status}"
        );
    }

    #[test]
    fn relay_timeout_propagates_build_failure() {
        let mut event = synthetic_event(1);
        event.value_xdr = b"junk".to_vec();
        let absence = FakeAbsenceSource {
            proof: vec![],
            height: ICSHeight::new(0, 1).unwrap(),
        };
        let dst = RecordingDestination {
            submitted: std::sync::Mutex::new(Vec::new()),
            tx_hash: "tx".to_string(),
        };
        let status = relay_timeout(&test_chain_id(), &event, Some(&absence), Some(&dst), "s", 100, 200);
        assert!(status.contains("build_failed:"), "got: {status}");
        assert!(dst.submitted.lock().unwrap().is_empty());
    }

    #[test]
    fn dispatch_routes_unexpired_packet_to_send_path() {
        let event = synthetic_event(1);
        let deps = StellarPacketDeps {
            proof_source: Some(Arc::new(FakeProofSource {
                proof: vec![0xAB],
                height: ICSHeight::new(0, 50).unwrap(),
            })),
            destination: Some(Arc::new(RecordingDestination {
                submitted: std::sync::Mutex::new(Vec::new()),
                tx_hash: "TX-RECV".to_string(),
            })),
            absence_source: Some(Arc::new(FakeAbsenceSource {
                proof: vec![0xCD],
                height: ICSHeight::new(0, 60).unwrap(),
            })),
            source_submitter: Some(Arc::new(RecordingDestination {
                submitted: std::sync::Mutex::new(Vec::new()),
                tx_hash: "TX-TIMEOUT".to_string(),
            })),
            signer: "dst-signer".to_string(),
            source_signer: "src-signer".to_string(),
        };

        let body_xdr = struct_val(vec![
            ("sequence", ScVal::U64(1)),
            ("source_client", string_val("10-stellar-0")),
            ("dest_client", string_val("07-tendermint-0")),
            ("timeout_timestamp", ScVal::U64(u64::MAX / 2)),
            ("payloads", vec_val(vec![sample_payload()])),
        ])
        .to_xdr(Limits::none())
        .unwrap();
        let mut event = event;
        event.value_xdr = body_xdr;
        let decoded = decode_packet_from_event_body(&event.value_xdr).unwrap();
        let status = dispatch_send_packet(&test_chain_id(), &event, Some(&decoded), &deps);
        assert!(
            status.contains("built_msg_recv_packet"),
            "expected send-path status, got: {status}"
        );
        assert!(!status.contains("built_msg_timeout"), "got: {status}");
    }

    #[test]
    fn dispatch_routes_expired_packet_to_timeout_path() {
        let event = synthetic_event(2);
        let body_xdr = struct_val(vec![
            ("sequence", ScVal::U64(2)),
            ("source_client", string_val("10-stellar-0")),
            ("dest_client", string_val("07-tendermint-0")),
            ("timeout_timestamp", ScVal::U64(1)),
            ("payloads", vec_val(vec![sample_payload()])),
        ])
        .to_xdr(Limits::none())
        .unwrap();
        let mut event = event;
        event.value_xdr = body_xdr;
        let decoded = decode_packet_from_event_body(&event.value_xdr).unwrap();

        let recv_dst = RecordingDestination {
            submitted: std::sync::Mutex::new(Vec::new()),
            tx_hash: "TX-RECV".to_string(),
        };
        let timeout_dst = RecordingDestination {
            submitted: std::sync::Mutex::new(Vec::new()),
            tx_hash: "TX-TIMEOUT".to_string(),
        };
        let deps = StellarPacketDeps {
            proof_source: Some(Arc::new(FakeProofSource {
                proof: vec![0xAB],
                height: ICSHeight::new(0, 50).unwrap(),
            })),
            destination: Some(Arc::new(recv_dst)),
            absence_source: Some(Arc::new(FakeAbsenceSource {
                proof: vec![0xCD, 0xEF],
                height: ICSHeight::new(0, 75).unwrap(),
            })),
            source_submitter: Some(Arc::new(timeout_dst)),
            signer: "dst-signer".to_string(),
            source_signer: "src-signer".to_string(),
        };
        let status = dispatch_send_packet(&test_chain_id(), &event, Some(&decoded), &deps);
        assert!(
            status.contains("built_msg_timeout"),
            "expected timeout-path status, got: {status}"
        );
        assert!(!status.contains("built_msg_recv_packet"), "got: {status}");
    }

    #[test]
    fn dispatch_routes_to_send_path_when_packet_timeout_is_zero() {
        let event = synthetic_event(3);
        let body_xdr = struct_val(vec![
            ("sequence", ScVal::U64(3)),
            ("source_client", string_val("10-stellar-0")),
            ("dest_client", string_val("07-tendermint-0")),
            ("timeout_timestamp", ScVal::U64(0)),
            ("payloads", vec_val(vec![sample_payload()])),
        ])
        .to_xdr(Limits::none())
        .unwrap();
        let mut event = event;
        event.value_xdr = body_xdr;
        let decoded = decode_packet_from_event_body(&event.value_xdr).unwrap();

        let deps = StellarPacketDeps {
            proof_source: Some(Arc::new(FakeProofSource {
                proof: vec![],
                height: ICSHeight::new(0, 1).unwrap(),
            })),
            destination: None,
            absence_source: Some(Arc::new(FakeAbsenceSource {
                proof: vec![],
                height: ICSHeight::new(0, 1).unwrap(),
            })),
            source_submitter: None,
            signer: "s".to_string(),
            source_signer: "s".to_string(),
        };
        let status = dispatch_send_packet(&test_chain_id(), &event, Some(&decoded), &deps);
        assert!(status.contains("built_msg_recv_packet"), "got: {status}");
    }

    #[test]
    fn relay_send_packet_does_not_submit_when_build_fails() {
        let mut event = synthetic_event(1);
        event.value_xdr = b"garbage".to_vec();
        let src = FakeProofSource {
            proof: vec![],
            height: ICSHeight::new(0, 1).unwrap(),
        };
        let dst = RecordingDestination {
            submitted: std::sync::Mutex::new(Vec::new()),
            tx_hash: "tx".to_string(),
        };
        let status = relay_send_packet(&test_chain_id(), &event, Some(&src), Some(&dst), "s");
        assert!(status.starts_with("build_failed:"), "got: {status}");
        assert!(dst.submitted.lock().unwrap().is_empty());
    }

    #[test]
    fn decode_multi_payload_packet_preserves_order() {
        let p1 = struct_val(vec![
            ("source_port", string_val("transfer")),
            ("dest_port", string_val("transfer")),
            ("version", string_val("v1")),
            ("encoding", string_val("json")),
            ("value", bytes_val(b"first")),
        ]);
        let p2 = struct_val(vec![
            ("source_port", string_val("erroring")),
            ("dest_port", string_val("erroring")),
            ("version", string_val("v1")),
            ("encoding", string_val("cbor")),
            ("value", bytes_val(b"second")),
        ]);
        let body = struct_val(vec![
            ("sequence", ScVal::U64(2)),
            ("source_client", string_val("src")),
            ("dest_client", string_val("dst")),
            ("timeout_timestamp", ScVal::U64(999)),
            ("payloads", vec_val(vec![p1, p2])),
        ]);
        let xdr = body.to_xdr(Limits::none()).unwrap();
        let packet = decode_packet_from_event_body(&xdr).unwrap();
        assert_eq!(packet.payloads.len(), 2);
        assert_eq!(packet.payloads[0].value, b"first");
        assert_eq!(packet.payloads[1].value, b"second");
        assert_eq!(packet.payloads[1].encoding, "cbor");
    }
}
