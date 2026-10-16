//! Bind successful transaction events to their submitted client messages.
use ibc_proto::cosmos::tx::v1beta1::{TxBody, TxRaw};
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::client::v1::MsgUpdateClient;
use ibc_relayer_types::clients::ics08_cardano_probabilistic::{
    header::PROBABILISTIC_HEADER_TYPE_URL, raw,
};
use ibc_relayer_types::core::ics02_client::header::{AnyHeader, Header};
use prost::Message;
use tendermint::abci::Event;

use crate::chain::cardano::mithril_stake::MITHRIL_STAKE_CERTIFICATES_TYPE_URL;

fn attribute<'a>(event: &'a Event, key: &str) -> Result<Option<&'a str>, String> {
    let mut values = event
        .attributes
        .iter()
        .filter(|a| a.key_bytes() == key.as_bytes());
    let value = values
        .next()
        .map(|a| a.value_str().map_err(|e| e.to_string()))
        .transpose()?;
    if values.next().is_some() {
        return Err(format!("duplicate update event attribute: {key}"));
    }
    Ok(value)
}

fn required<'a>(event: &'a Event, key: &str) -> Result<&'a str, String> {
    attribute(event, key)?.ok_or_else(|| format!("update event has no {key}"))
}

fn message_position(event: &Event) -> Result<Option<usize>, String> {
    attribute(event, "msg_index")?
        .map(|s| s.parse().map_err(|_| "invalid message index".to_owned()))
        .transpose()
}

fn same_message(emitted: &Any, submitted: &Any) -> Result<bool, String> {
    if emitted.type_url != submitted.type_url {
        return Ok(false);
    }
    // The SDK re-encodes its decoded message for the event. Compare protobuf
    // contents so another valid field order is not mistaken for another message.
    match submitted.type_url.as_str() {
        PROBABILISTIC_HEADER_TYPE_URL => {
            Ok(raw::ProbabilisticHeader::decode(emitted.value.as_slice())
                .map_err(|e| e.to_string())?
                == raw::ProbabilisticHeader::decode(submitted.value.as_slice())
                    .map_err(|e| e.to_string())?)
        }
        MITHRIL_STAKE_CERTIFICATES_TYPE_URL => Ok(raw::MithrilStakeCertificates::decode(
            emitted.value.as_slice(),
        )
        .map_err(|e| e.to_string())?
            == raw::MithrilStakeCertificates::decode(submitted.value.as_slice())
                .map_err(|e| e.to_string())?),
        _ => Ok(emitted == submitted),
    }
}

// Some adapters implement exported.Height.String using the protobuf debug
// format. Only accept that spelling of the same height, never another height.
fn check_height(event: &Event, expected: &str) -> Result<(), String> {
    for key in ["consensus_height", "consensus_heights"] {
        if let Some(claimed) = attribute(event, key)? {
            let legacy = expected
                .strip_prefix("0-")
                .map(|n| format!("revision_height:{n} "));
            if claimed != expected && legacy.as_deref() != Some(claimed) {
                return Err(
                    "update event height disagrees with submitted header or activation result"
                        .to_owned(),
                );
            }
        }
    }
    Ok(())
}

fn activation_result<'a>(
    events: &'a [Event],
    chunk: &raw::ObservationChunk,
    position: Option<usize>,
) -> Result<&'a Event, String> {
    let mut results = events
        .iter()
        .filter(|e| e.kind == "probabilistic_activation_result");
    let result = results.next().ok_or("activation has no committed result")?;
    if results.next().is_some()
        || required(result, "session_id")? != hex::encode(&chunk.session_id)
        || required(result, "sequence")? != chunk.sequence.to_string()
        || message_position(result)?
            .zip(position)
            .is_some_and(|(a, b)| a != b)
    {
        return Err("activation result does not match submitted session step".to_owned());
    }
    let receipt = hex::decode(required(result, "receipt_id")?).map_err(|e| e.to_string())?;
    if receipt.len() != 32 || chunk.session_id.len() != 32 {
        return Err("activation result has invalid session or receipt".to_owned());
    }
    let anchor: u64 = required(result, "anchor_height")?
        .parse()
        .map_err(|_| "invalid activation anchor")?;
    let height = required(result, "consensus_height")?;
    if anchor == 0 || (!height.is_empty() && height != format!("0-{anchor}")) {
        return Err("activation result height disagrees with its anchor".to_owned());
    }
    let mut activations = events
        .iter()
        .filter(|e| e.kind == "probabilistic_observation_activated");
    if let Some(activated) = activations.next() {
        if activations.next().is_some()
            || required(activated, "receipt_id")? != required(result, "receipt_id")?
            || required(activated, "anchor_height")? != required(result, "anchor_height")?
        {
            return Err("activation result disagrees with activated receipt".to_owned());
        }
    } else if !height.is_empty() {
        return Err("consensus update has no activated receipt".to_owned());
    }
    Ok(result)
}

pub fn hydrate_client_updates(tx: &[u8], events: &[Event]) -> Result<Vec<Event>, String> {
    let is_probabilistic = |event: &Event| {
        event.kind == "update_client"
            && event.attributes.iter().any(|a| {
                a.key_bytes() == b"client_id"
                    && a.value_str()
                        .is_ok_and(|id| id.starts_with("08-cardano-probabilistic-"))
            })
    };
    if !events.iter().any(is_probabilistic) {
        return Ok(events.to_vec());
    }
    let raw = TxRaw::decode(tx).map_err(|e| format!("decode update transaction: {e}"))?;
    let body = TxBody::decode(raw.body_bytes.as_slice())
        .map_err(|e| format!("decode update transaction body: {e}"))?;
    let mut messages = Vec::new();
    for (position, message) in body.messages.into_iter().enumerate() {
        if message.type_url == "/ibc.core.client.v1.MsgUpdateClient" {
            let update =
                MsgUpdateClient::decode(message.value.as_slice()).map_err(|e| e.to_string())?;
            if let Some(message) = update.client_message {
                messages.push((position, update.client_id, message));
            }
        }
    }
    let mut used = vec![false; messages.len()];
    let mut result = Vec::with_capacity(events.len());
    let mut boundary = 0;
    for (event_index, event) in events.iter().enumerate() {
        let start = boundary;
        if event.kind == "update_client" {
            boundary = event_index + 1;
        }
        if !is_probabilistic(event) {
            result.push(event.clone());
            continue;
        }
        let client = required(event, "client_id")?;
        let position = message_position(event)?;
        // SDK event order follows message order. Require msg_index too when
        // present, then compare the keeper's encoded message with the actual tx.
        let index = messages
            .iter()
            .enumerate()
            .find(|(i, (p, id, _))| {
                !used[*i] && id == client && position.is_none_or(|wanted| wanted == *p)
            })
            .map(|(i, _)| i)
            .ok_or("update event does not match a submitted message")?;
        used[index] = true;
        let message = &messages[index].2;
        let enclosed = attribute(event, "header")?.filter(|s| !s.is_empty());
        if let Some(encoded) = enclosed {
            let bytes = hex::decode(encoded).map_err(|e| e.to_string())?;
            let emitted = Any::decode(bytes.as_slice()).map_err(|e| e.to_string())?;
            if !same_message(&emitted, message)? {
                return Err("update event message disagrees with submitted message".to_owned());
            }
        }
        let mut hydrated = event.clone();
        match message.type_url.as_str() {
            PROBABILISTIC_HEADER_TYPE_URL => {
                let header = raw::ProbabilisticHeader::decode(message.value.as_slice())
                    .map_err(|e| e.to_string())?;
                if let Some(chunk) = header.observation_chunk {
                    if enclosed.is_none() {
                        return Err("bounded update event has no submitted message".to_owned());
                    }
                    required(event, "consensus_height")?;
                    let height = if chunk.operation == 7 {
                        let committed =
                            activation_result(&events[start..event_index], &chunk, position)?;
                        for key in ["session_id", "sequence", "receipt_id", "anchor_height"] {
                            hydrated
                                .attributes
                                .push((key, required(committed, key)?).into());
                        }
                        required(committed, "consensus_height")?.to_owned()
                    } else {
                        String::new()
                    };
                    check_height(event, &height)?;
                    // Bootstrap, verification, rootless activation, proposals and
                    // retries create no consensus state. Keep their module events,
                    // but do not invent an IBC consensus update at height 0-1.
                    if height.is_empty() {
                        continue;
                    }
                    // A session reference is not a self-contained evidence header.
                    hydrated.attributes.retain(|a| {
                        a.key_bytes() != b"header" && a.key_bytes() != b"consensus_height"
                    });
                    hydrated
                        .attributes
                        .push(("consensus_height", height).into());
                } else {
                    let header = AnyHeader::try_from(message.clone()).map_err(|e| e.to_string())?;
                    let height = header.height().to_string();
                    // Historical full-header events sometimes omitted the height.
                    if attribute(event, "consensus_height")?.is_some_and(|s| !s.is_empty()) {
                        check_height(event, &height)?;
                    }
                    hydrated.attributes.retain(|a| {
                        a.key_bytes() != b"header" && a.key_bytes() != b"consensus_height"
                    });
                    hydrated
                        .attributes
                        .push(("consensus_height", height).into());
                    hydrated
                        .attributes
                        .push(("header", hex::encode(message.encode_to_vec())).into());
                }
            }
            MITHRIL_STAKE_CERTIFICATES_TYPE_URL => {
                let certificates = raw::MithrilStakeCertificates::decode(message.value.as_slice())
                    .map_err(|e| e.to_string())?;
                if enclosed.is_none() || certificates.certificates.is_empty() {
                    return Err("certificate update event has no submitted certificates".to_owned());
                }
                required(event, "consensus_height")?;
                check_height(event, "")?;
                // mithril_stake_certified remains a certificate event. It cannot
                // be represented by UpdateClient, which requires a consensus height.
                continue;
            }
            _ => return Err("unsupported probabilistic update message".to_owned()),
        }
        result.push(hydrated);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vec<u8>, Vec<Event>) {
        let data: serde_json::Value = serde_json::from_str(include_str!(
            "../chain/cardano/fixtures/watcher-v10-rootless.json"
        ))
        .unwrap();
        (
            hex::decode(data["tx"].as_str().unwrap()).unwrap(),
            serde_json::from_value(data["events"].clone()).unwrap(),
        )
    }

    #[test]
    fn header_recovery_requires_matching_client_and_height() {
        let (tx, mut events) = fixture();
        let update = events
            .iter_mut()
            .find(|e| e.kind == "update_client")
            .unwrap();
        // Replace rather than append the existing empty height.
        update
            .attributes
            .retain(|a| a.key_bytes() != b"consensus_height");
        update.attributes.push(("consensus_height", "0-12").into());
        assert!(hydrate_client_updates(&tx, &events)
            .unwrap_err()
            .contains("height disagrees"));
        let (tx, mut events) = fixture();
        let update = events
            .iter_mut()
            .find(|e| e.kind == "update_client")
            .unwrap();
        update.attributes.retain(|a| a.key_bytes() != b"client_id");
        update
            .attributes
            .push(("client_id", "08-cardano-probabilistic-9").into());
        assert!(hydrate_client_updates(&tx, &events)
            .unwrap_err()
            .contains("does not match"));
    }

    #[test]
    fn repeated_client_updates_follow_message_positions() {
        let (tx, events) = fixture();
        let mut raw = TxRaw::decode(tx.as_slice()).unwrap();
        let mut body = TxBody::decode(raw.body_bytes.as_slice()).unwrap();
        let mut second = MsgUpdateClient::decode(body.messages[0].value.as_slice()).unwrap();
        let mut header=ibc_relayer_types::clients::ics08_cardano_probabilistic::raw::ProbabilisticHeader::decode(second.client_message.as_ref().unwrap().value.as_slice()).unwrap();
        header
            .anchor_block
            .as_mut()
            .unwrap()
            .height
            .as_mut()
            .unwrap()
            .revision_height = 12;
        second.client_message.as_mut().unwrap().value = header.encode_to_vec();
        let mut message = body.messages[0].clone();
        message.value = second.encode_to_vec();
        body.messages.push(message);
        raw.body_bytes = body.encode_to_vec();
        let first = events
            .iter()
            .find(|e| e.kind == "update_client")
            .unwrap()
            .clone();
        let mut second_event = first.clone();
        second_event.attributes.push(("msg_index", "1").into());
        let mut first_event = first;
        first_event.attributes.push(("msg_index", "0").into());
        let recovered =
            hydrate_client_updates(&raw.encode_to_vec(), &[second_event, first_event]).unwrap();
        assert_eq!(
            crate::event::extract_header_from_tx(&recovered[0])
                .unwrap()
                .height()
                .revision_height(),
            12
        );
        assert_eq!(
            crate::event::extract_header_from_tx(&recovered[1])
                .unwrap()
                .height()
                .revision_height(),
            11
        );
    }
}

#[cfg(test)]
pub(crate) mod operation_fixtures {
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use tendermint::abci::Event;
    use tendermint_rpc::endpoint::tx::Response;

    #[derive(Clone, Deserialize)]
    pub(crate) struct Record {
        pub name: String,
        pub tx: String,
        pub height: u64,
        pub events: Vec<Event>,
        pub consensus_heights: Option<Vec<String>>,
    }

    impl Record {
        pub fn response(&self) -> Response {
            let tx = hex::decode(&self.tx).unwrap();
            Response {
                hash: tendermint::Hash::Sha256(Sha256::digest(&tx).into()),
                height: self.height.try_into().unwrap(),
                index: 0,
                tx_result: tendermint::abci::types::ExecTxResult {
                    events: self.events.clone(),
                    ..Default::default()
                },
                tx,
                proof: None,
            }
        }
    }

    pub(crate) fn records() -> Vec<Record> {
        let data = std::env::var("RELAYER_OPERATION_EVENTS")
            .map(|path| std::fs::read_to_string(path).unwrap())
            .unwrap_or_else(|_| include_str!("fixtures/probabilistic-operations.json").to_owned());
        serde_json::from_str(&data).unwrap()
    }
}

#[cfg(test)]
mod operation_tests {
    use super::{operation_fixtures::records, *};
    use ibc_relayer_types::{core::ics24_host::identifier::ChainId, events::IbcEvent};

    #[test]
    fn committed_keeper_operations_have_only_real_consensus_heights() {
        let chain = ChainId::from_string("relayer-events-1");
        for record in records() {
            let response = record.response();
            let hydrated = hydrate_client_updates(&response.tx, &record.events).unwrap();
            if record.name == "certificate" {
                assert!(hydrated.iter().any(|e| e.kind == "mithril_stake_certified"));
            }
            if record.name == "mixed" {
                assert!(hydrated.iter().any(|e| e.kind == "transfer"));
            }
            let recovered = crate::chain::cosmos::query::tx::all_ibc_events_from_tx_search_response(
                &chain, response,
            );
            assert!(
                !recovered
                    .iter()
                    .any(|e| matches!(e.event, IbcEvent::ChainError(_))),
                "{}: {recovered:?}",
                record.name
            );
            let heights: Vec<_> = recovered
                .iter()
                .filter_map(|e| match &e.event {
                    IbcEvent::UpdateClient(update) => {
                        // Staged references must not become placeholder evidence headers.
                        assert!(update.header.is_none());
                        Some(update.consensus_height().to_string())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                heights,
                record.consensus_heights.unwrap_or_default(),
                "{}",
                record.name
            );
        }
    }

    fn replace(event: &mut Event, key: &str, value: &str) {
        event.attributes.retain(|a| a.key_bytes() != key.as_bytes());
        event.attributes.push((key, value).into());
    }

    #[test]
    fn activation_result_and_keeper_message_bindings_are_required() {
        let record = records()
            .into_iter()
            .find(|r| r.name == "root-activation")
            .unwrap();
        for (kind, key, value) in [
            ("probabilistic_activation_result", "session_id", "00"),
            ("probabilistic_activation_result", "sequence", "9999"),
            ("probabilistic_activation_result", "receipt_id", "00"),
            ("probabilistic_activation_result", "anchor_height", "968"),
            (
                "probabilistic_activation_result",
                "consensus_height",
                "0-968",
            ),
            ("update_client", "client_id", "08-cardano-probabilistic-9"),
            ("update_client", "consensus_height", "0-968"),
            ("update_client", "consensus_heights", "0-968"),
            ("update_client", "msg_index", "9"),
            ("update_client", "header", "00"),
        ] {
            let mut events = record.events.clone();
            replace(
                events.iter_mut().find(|e| e.kind == kind).unwrap(),
                key,
                value,
            );
            assert!(
                hydrate_client_updates(&hex::decode(&record.tx).unwrap(), &events).is_err(),
                "accepted altered {kind}.{key}"
            );
        }
        let mut events = record.events.clone();
        events.retain(|e| e.kind != "probabilistic_activation_result");
        assert!(
            hydrate_client_updates(&hex::decode(&record.tx).unwrap(), &events)
                .unwrap_err()
                .contains("no committed result")
        );
        let mut events = record.events.clone();
        replace(
            events
                .iter_mut()
                .find(|e| e.kind == "probabilistic_activation_result")
                .unwrap(),
            "receipt_id",
            &"11".repeat(32),
        );
        assert!(
            hydrate_client_updates(&hex::decode(&record.tx).unwrap(), &events)
                .unwrap_err()
                .contains("activated receipt")
        );
        let result = record
            .events
            .iter()
            .find(|e| e.kind == "probabilistic_activation_result")
            .unwrap()
            .clone();
        let mut events = record.events.clone();
        events.insert(0, result);
        assert!(hydrate_client_updates(&hex::decode(&record.tx).unwrap(), &events).is_err());
    }

    #[test]
    fn certificate_events_cannot_claim_a_consensus_height_or_another_message() {
        let record = records()
            .into_iter()
            .find(|r| r.name == "certificate")
            .unwrap();
        for (key, value) in [
            ("consensus_height", "0-1"),
            ("consensus_heights", "0-1"),
            ("header", "00"),
        ] {
            let mut events = record.events.clone();
            replace(
                events
                    .iter_mut()
                    .find(|e| e.kind == "update_client")
                    .unwrap(),
                key,
                value,
            );
            assert!(hydrate_client_updates(&hex::decode(&record.tx).unwrap(), &events).is_err());
        }
    }

    #[test]
    fn mixed_operations_are_bound_in_order_without_message_indices() {
        let mut record = records().into_iter().find(|r| r.name == "mixed").unwrap();
        for event in &mut record.events {
            event.attributes.retain(|a| a.key_bytes() != b"msg_index");
        }
        let hydrated =
            hydrate_client_updates(&hex::decode(&record.tx).unwrap(), &record.events).unwrap();
        let updates: Vec<_> = hydrated
            .iter()
            .filter(|e| e.kind == "update_client")
            .collect();
        assert_eq!(updates.len(), 1);
        assert_eq!(required(updates[0], "consensus_height").unwrap(), "0-969");
    }

    #[test]
    fn message_binding_accepts_equivalent_protobuf_encodings() {
        let header = raw::ProbabilisticHeader {
            observation_chunk: Some(raw::ObservationChunk {
                operation: 7,
                session_id: vec![1; 32],
                sequence: 10,
                ..Default::default()
            }),
            ..Default::default()
        };
        let submitted = Any {
            type_url: PROBABILISTIC_HEADER_TYPE_URL.to_owned(),
            value: header.encode_to_vec(),
        };
        let mut emitted = submitted.clone();
        // An explicitly encoded zero output index is equivalent to its absence.
        // The keeper's protobuf encoder omits it again.
        emitted.value.extend_from_slice(&[0x30, 0]);
        assert!(same_message(&emitted, &submitted).unwrap());
        emitted.type_url = MITHRIL_STAKE_CERTIFICATES_TYPE_URL.to_owned();
        assert!(!same_message(&emitted, &submitted).unwrap());
    }
}
