//! Bind successful transaction events to their submitted client messages.
use ibc_proto::cosmos::tx::v1beta1::{TxBody, TxRaw};
use ibc_proto::ibc::core::client::v1::MsgUpdateClient;
use ibc_relayer_types::clients::ics08_cardano_probabilistic::header::PROBABILISTIC_HEADER_TYPE_URL;
use ibc_relayer_types::core::ics02_client::header::{AnyHeader, Header};
use prost::Message;
use tendermint::abci::Event;

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
        if message.type_url != "/ibc.core.client.v1.MsgUpdateClient" {
            continue;
        }
        let update =
            MsgUpdateClient::decode(message.value.as_slice()).map_err(|e| e.to_string())?;
        if let Some(header) = update.client_message {
            if header.type_url == PROBABILISTIC_HEADER_TYPE_URL {
                messages.push((position, update.client_id, header));
            }
        }
    }
    let mut result = events.to_vec();
    let mut used = vec![false; messages.len()];
    for event in result.iter_mut().filter(|e| is_probabilistic(e)) {
        let client = event
            .attributes
            .iter()
            .find(|a| a.key_bytes() == b"client_id")
            .and_then(|a| a.value_str().ok())
            .ok_or("update event has no client id")?
            .to_owned();
        let position = event
            .attributes
            .iter()
            .find(|a| a.key_bytes() == b"msg_index")
            .map(|a| {
                a.value_str()
                    .map_err(|_| "invalid message index")
                    .and_then(|s| s.parse::<usize>().map_err(|_| "invalid message index"))
            })
            .transpose()?;
        // SDK event order follows message order. Where msg_index is available
        // require it too. This binds repeated updates to the same client safely.
        let index = messages
            .iter()
            .enumerate()
            .find(|(i, (p, id, _))| {
                !used[*i] && id == &client && position.is_none_or(|wanted| wanted == *p)
            })
            .map(|(i, _)| i)
            .ok_or("update event does not match a submitted message")?;
        used[index] = true;
        let raw_header = messages[index].2.clone();
        let header = AnyHeader::try_from(raw_header.clone()).map_err(|e| e.to_string())?;
        let height = header.height().to_string();
        if let Some(claimed) = event
            .attributes
            .iter()
            .find(|a| a.key_bytes() == b"consensus_height")
            .and_then(|a| a.value_str().ok())
        {
            let legacy = format!("revision_height:{} ", header.height().revision_height());
            if !claimed.is_empty() && claimed != height && claimed != legacy {
                return Err("update event height disagrees with submitted header".to_owned());
            }
        }
        // A rootless update has an empty consensus_height. Its anchor remains
        // challengeable even though it creates no proof-bearing consensus state.
        event
            .attributes
            .retain(|a| a.key_bytes() != b"header" && a.key_bytes() != b"consensus_height");
        event.attributes.push(("consensus_height", height).into());
        event
            .attributes
            .push(("header", hex::encode(raw_header.encode_to_vec())).into());
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
