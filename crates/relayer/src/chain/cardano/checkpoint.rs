use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::client::v1::MsgUpdateClient as RawMsgUpdateClient;
use ibc_relayer_types::clients::ics08_cardano_probabilistic::header::PROBABILISTIC_HEADER_TYPE_URL;
use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw::ProbabilisticHeader;
use ibc_relayer_types::core::ics02_client::msgs::update_client::TYPE_URL as UPDATE_CLIENT_TYPE_URL;
use prost::Message;

pub(crate) fn is_probabilistic_checkpoint_header(header: &Any) -> Result<bool, String> {
    if header.type_url != PROBABILISTIC_HEADER_TYPE_URL {
        return Ok(false);
    }

    ProbabilisticHeader::decode(header.value.as_slice())
        .map(|header| header.is_checkpoint)
        .map_err(|error| format!("failed to decode probabilistic checkpoint header: {error}"))
}

pub(crate) fn is_probabilistic_checkpoint_update(message: &Any) -> Result<bool, String> {
    if message.type_url != UPDATE_CLIENT_TYPE_URL {
        return Ok(false);
    }

    let update = RawMsgUpdateClient::decode(message.value.as_slice())
        .map_err(|error| format!("failed to decode MsgUpdateClient: {error}"))?;
    match update.client_message {
        Some(header) => is_probabilistic_checkpoint_header(&header),
        None => Err("probabilistic MsgUpdateClient is missing its client message".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw;

    #[test]
    fn detects_checkpoint_update_messages() {
        let header = raw::ProbabilisticHeader {
            is_checkpoint: true,
            ..Default::default()
        };
        let update = RawMsgUpdateClient {
            client_id: "08-cardano-probabilistic-0".to_string(),
            client_message: Some(Any {
                type_url: PROBABILISTIC_HEADER_TYPE_URL.to_string(),
                value: header.encode_to_vec(),
            }),
            signer: "inj1signer".to_string(),
        };
        let message = Any {
            type_url: UPDATE_CLIENT_TYPE_URL.to_string(),
            value: update.encode_to_vec(),
        };

        assert!(is_probabilistic_checkpoint_update(&message).unwrap());
    }
}
