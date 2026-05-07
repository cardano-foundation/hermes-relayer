//! Event parsing for Cardano Gateway events -> Hermes `IbcEvent` conversion.
//!
//! The Gateway returns events in the format:
//! `Event { type: "create_client", attributes: [{ key: "client_id", value: "08-cardano-0" }, ...] }`
//!
//! This module converts them into Hermes' `IbcEvent` enum variants.

use ibc_proto::google::protobuf::Any as ProtoAny;
use ibc_relayer_types::{
    clients::{
        ics07_tendermint::{
            header::TENDERMINT_HEADER_TYPE_URL, misbehaviour::TENDERMINT_MISBEHAVIOR_TYPE_URL,
        },
        ics08_cardano::{
            header::MITHRIL_HEADER_TYPE_URL, misbehaviour::MITHRIL_MISBEHAVIOUR_TYPE_URL,
        },
        ics08_cardano_stability::{
            header::STABILITY_HEADER_TYPE_URL, misbehaviour::STABILITY_MISBEHAVIOUR_TYPE_URL,
        },
    },
    core::{
        ics02_client::{
            events as ClientEvents,
            header::AnyHeader,
            height::{Height, HeightErrorDetail},
        },
        ics03_connection::events as ConnectionEvents,
        ics04_channel::{events as ChannelEvents, packet::Packet, timeout::TimeoutHeight},
        ics24_host::identifier::{ChannelId, ClientId, ConnectionId, PortId},
    },
    events::IbcEvent,
    timestamp::Timestamp,
};
use prost::Message;
use std::collections::HashMap;
use std::str::FromStr;

use super::error::Error;
use super::generated::ibc::cardano::v1::{Event, EventAttribute};

const ATTR_CLIENT_MESSAGE_ANY_HEX: &str = "client_message_any_hex";
const ATTR_LEGACY_HEADER: &str = "header";

/// Parse a list of Gateway events into Hermes IbcEvent types
pub fn parse_events(gateway_events: Vec<Event>, _height: Height) -> Result<Vec<IbcEvent>, Error> {
    let event_count = gateway_events.len();
    tracing::debug!("Parsing {} gateway events", event_count);

    let mut ibc_events = Vec::new();
    let mut parsed_type_counts: HashMap<String, usize> = HashMap::new();
    let mut unknown_event_count = 0usize;

    for event in gateway_events {
        let event_type = event.r#type.clone();
        let attribute_count = event.attributes.len();
        let attributes = event.attributes.clone();
        let attrs = attributes_to_map(event.attributes);

        tracing::debug!(
            "Parsing event type: {} ({} attributes)",
            event_type,
            attribute_count
        );

        // Parse event based on type
        let ibc_event = match event_type.as_str() {
            // Client events
            "create_client" => parse_event_with_context(
                "create_client",
                &attributes,
                attrs,
                parse_create_client_event,
            )?,
            "update_client" => parse_event_with_context(
                "update_client",
                &attributes,
                attrs,
                parse_update_client_event,
            )?,
            "upgrade_client" => parse_event_with_context(
                "upgrade_client",
                &attributes,
                attrs,
                parse_upgrade_client_event,
            )?,
            "client_misbehaviour" => parse_event_with_context(
                "client_misbehaviour",
                &attributes,
                attrs,
                parse_client_misbehaviour_event,
            )?,

            // Connection events
            "connection_open_init" => parse_event_with_context(
                "connection_open_init",
                &attributes,
                attrs,
                parse_connection_open_init_event,
            )?,
            "connection_open_try" => parse_event_with_context(
                "connection_open_try",
                &attributes,
                attrs,
                parse_connection_open_try_event,
            )?,
            "connection_open_ack" => parse_event_with_context(
                "connection_open_ack",
                &attributes,
                attrs,
                parse_connection_open_ack_event,
            )?,
            "connection_open_confirm" => parse_event_with_context(
                "connection_open_confirm",
                &attributes,
                attrs,
                parse_connection_open_confirm_event,
            )?,

            // Channel events
            "channel_open_init" => parse_event_with_context(
                "channel_open_init",
                &attributes,
                attrs,
                parse_channel_open_init_event,
            )?,
            "channel_open_try" => parse_event_with_context(
                "channel_open_try",
                &attributes,
                attrs,
                parse_channel_open_try_event,
            )?,
            "channel_open_ack" => parse_event_with_context(
                "channel_open_ack",
                &attributes,
                attrs,
                parse_channel_open_ack_event,
            )?,
            "channel_open_confirm" => parse_event_with_context(
                "channel_open_confirm",
                &attributes,
                attrs,
                parse_channel_open_confirm_event,
            )?,
            "channel_close_init" => parse_event_with_context(
                "channel_close_init",
                &attributes,
                attrs,
                parse_channel_close_init_event,
            )?,
            "channel_close_confirm" => parse_event_with_context(
                "channel_close_confirm",
                &attributes,
                attrs,
                parse_channel_close_confirm_event,
            )?,

            // Packet events
            "send_packet" => parse_event_with_context(
                "send_packet",
                &attributes,
                attrs,
                parse_send_packet_event,
            )?,
            "recv_packet" => parse_event_with_context(
                "recv_packet",
                &attributes,
                attrs,
                parse_recv_packet_event,
            )?,
            "write_acknowledgement" => parse_event_with_context(
                "write_acknowledgement",
                &attributes,
                attrs,
                parse_write_acknowledgement_event,
            )?,
            "acknowledge_packet" => parse_event_with_context(
                "acknowledge_packet",
                &attributes,
                attrs,
                parse_acknowledge_packet_event,
            )?,
            "timeout_packet" => parse_event_with_context(
                "timeout_packet",
                &attributes,
                attrs,
                parse_timeout_packet_event,
            )?,
            "timeout_on_close_packet" => parse_event_with_context(
                "timeout_on_close_packet",
                &attributes,
                attrs,
                parse_timeout_on_close_packet_event,
            )?,

            // Unknown event type - log warning and skip
            _ => {
                let keys = attributes
                    .iter()
                    .map(|attr| attr.key.as_str())
                    .collect::<Vec<_>>();
                tracing::warn!(
                    "Unknown event type: {}; attribute keys: {:?}",
                    event_type,
                    keys
                );
                unknown_event_count += 1;
                continue;
            }
        };

        ibc_events.push(ibc_event);
        *parsed_type_counts.entry(event_type.clone()).or_default() += 1;
        tracing::debug!("Parsed event type: {}", event_type);
    }

    tracing::debug!(
        "Parsed {} of {} gateway events into IBC events",
        ibc_events.len(),
        event_count
    );

    if ibc_events.is_empty() && event_count > 0 {
        tracing::warn!("No events could be parsed from gateway response");
    }

    if !parsed_type_counts.is_empty() {
        tracing::debug!(
            "Parsed event counts by gateway type: {:?}",
            parsed_type_counts
        );
    }

    if unknown_event_count > 0 {
        tracing::warn!(
            "{} gateway events were ignored because event type was unknown",
            unknown_event_count
        );
    }

    Ok(ibc_events)
}

fn parse_event_with_context(
    event_type: &str,
    raw_attributes: &[EventAttribute],
    attrs: HashMap<String, String>,
    parser: impl FnOnce(HashMap<String, String>) -> Result<IbcEvent, Error>,
) -> Result<IbcEvent, Error> {
    match parser(attrs) {
        Ok(event) => Ok(event),
        Err(error) => {
            let keys = raw_attributes
                .iter()
                .map(|attribute| attribute.key.as_str())
                .collect::<Vec<_>>();

            tracing::warn!(
                "Failed to parse gateway event '{}'; attribute keys {:?}; error: {}",
                event_type,
                keys,
                error
            );

            Err(error)
        }
    }
}

/// Convert event attributes to a HashMap for easier lookup
fn attributes_to_map(attributes: Vec<EventAttribute>) -> HashMap<String, String> {
    attributes
        .into_iter()
        .map(|attr| (attr.key, attr.value))
        .collect()
}

//
// Client event parsers
//

fn parse_create_client_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let client_id = parse_client_id(&attrs, "client_id")?;
    let client_type = parse_client_type(&attrs, "client_type")?;
    let consensus_height = parse_height(&attrs, "consensus_height")?;

    let attributes = ClientEvents::Attributes {
        client_id,
        client_type,
        consensus_height,
    };

    Ok(IbcEvent::CreateClient(ClientEvents::CreateClient(
        attributes,
    )))
}

fn parse_update_client_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let client_id = parse_client_id(&attrs, "client_id")?;
    let client_type = parse_client_type(&attrs, "client_type")?;
    let consensus_height = parse_height(&attrs, "consensus_height")?;
    let header = parse_optional_client_message_header(&attrs)?;

    let common = ClientEvents::Attributes {
        client_id,
        client_type,
        consensus_height,
    };

    Ok(IbcEvent::UpdateClient(ClientEvents::UpdateClient {
        common,
        header,
    }))
}

fn parse_optional_client_message_header(
    attrs: &HashMap<String, String>,
) -> Result<Option<AnyHeader>, Error> {
    let Some(encoded_any) = attrs
        .get(ATTR_CLIENT_MESSAGE_ANY_HEX)
        .or_else(|| attrs.get(ATTR_LEGACY_HEADER))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    let bytes =
        hex::decode(encoded_any.strip_prefix("0x").unwrap_or(encoded_any)).map_err(|e| {
            Error::EventAttribute(format!(
                "Invalid hex bytes for {} '{}': {}",
                ATTR_CLIENT_MESSAGE_ANY_HEX, encoded_any, e
            ))
        })?;

    let client_message = ProtoAny::decode(bytes.as_slice()).map_err(|e| {
        Error::EventAttribute(format!(
            "Invalid protobuf Any in {}: {}",
            ATTR_CLIENT_MESSAGE_ANY_HEX, e
        ))
    })?;

    match client_message.type_url.as_str() {
        TENDERMINT_HEADER_TYPE_URL | MITHRIL_HEADER_TYPE_URL | STABILITY_HEADER_TYPE_URL => {
            AnyHeader::try_from(client_message)
                .map(Some)
                .map_err(|e| Error::EventAttribute(format!("Invalid update-client header: {e}")))
        }
        TENDERMINT_MISBEHAVIOR_TYPE_URL
        | MITHRIL_MISBEHAVIOUR_TYPE_URL
        | STABILITY_MISBEHAVIOUR_TYPE_URL => Ok(None),
        other => Err(Error::EventAttribute(format!(
            "Unknown update-client client message type_url: {other}"
        ))),
    }
}

fn parse_upgrade_client_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let client_id = parse_client_id(&attrs, "client_id")?;
    let client_type = parse_client_type(&attrs, "client_type")?;
    let consensus_height = parse_height(&attrs, "consensus_height")?;

    let attributes = ClientEvents::Attributes {
        client_id,
        client_type,
        consensus_height,
    };

    Ok(IbcEvent::UpgradeClient(ClientEvents::UpgradeClient(
        attributes,
    )))
}

fn parse_client_misbehaviour_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let client_id = parse_client_id(&attrs, "client_id")?;
    let client_type = parse_client_type(&attrs, "client_type")?;
    let consensus_height = parse_height(&attrs, "consensus_height")?;

    let attributes = ClientEvents::Attributes {
        client_id,
        client_type,
        consensus_height,
    };

    Ok(IbcEvent::ClientMisbehaviour(
        ClientEvents::ClientMisbehaviour(attributes),
    ))
}

//
// Connection event parsers
//

fn parse_connection_open_init_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let connection_id = parse_optional_connection_id(&attrs, "connection_id");
    let client_id = parse_client_id(&attrs, "client_id")?;
    let counterparty_connection_id =
        parse_optional_connection_id(&attrs, "counterparty_connection_id");
    let counterparty_client_id = parse_client_id(&attrs, "counterparty_client_id")?;

    let attributes = ConnectionEvents::Attributes {
        connection_id,
        client_id,
        counterparty_connection_id,
        counterparty_client_id,
    };

    Ok(IbcEvent::OpenInitConnection(ConnectionEvents::OpenInit(
        attributes,
    )))
}

fn parse_connection_open_try_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let connection_id = parse_optional_connection_id(&attrs, "connection_id");
    let client_id = parse_client_id(&attrs, "client_id")?;
    let counterparty_connection_id =
        parse_optional_connection_id(&attrs, "counterparty_connection_id");
    let counterparty_client_id = parse_client_id(&attrs, "counterparty_client_id")?;

    let attributes = ConnectionEvents::Attributes {
        connection_id,
        client_id,
        counterparty_connection_id,
        counterparty_client_id,
    };

    Ok(IbcEvent::OpenTryConnection(ConnectionEvents::OpenTry(
        attributes,
    )))
}

fn parse_connection_open_ack_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let connection_id = parse_optional_connection_id(&attrs, "connection_id");
    let client_id = parse_client_id(&attrs, "client_id")?;
    let counterparty_connection_id =
        parse_optional_connection_id(&attrs, "counterparty_connection_id");
    let counterparty_client_id = parse_client_id(&attrs, "counterparty_client_id")?;

    let attributes = ConnectionEvents::Attributes {
        connection_id,
        client_id,
        counterparty_connection_id,
        counterparty_client_id,
    };

    Ok(IbcEvent::OpenAckConnection(ConnectionEvents::OpenAck(
        attributes,
    )))
}

fn parse_connection_open_confirm_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let connection_id = parse_optional_connection_id(&attrs, "connection_id");
    let client_id = parse_client_id(&attrs, "client_id")?;
    let counterparty_connection_id =
        parse_optional_connection_id(&attrs, "counterparty_connection_id");
    let counterparty_client_id = parse_client_id(&attrs, "counterparty_client_id")?;

    let attributes = ConnectionEvents::Attributes {
        connection_id,
        client_id,
        counterparty_connection_id,
        counterparty_client_id,
    };

    Ok(IbcEvent::OpenConfirmConnection(
        ConnectionEvents::OpenConfirm(attributes),
    ))
}

//
// Channel event parsers
//

fn parse_channel_open_init_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let port_id = parse_port_id(&attrs, "port_id")?;
    let channel_id = parse_optional_channel_id(&attrs, "channel_id");
    let connection_id = parse_connection_id(&attrs, "connection_id")?;
    let counterparty_port_id = parse_port_id(&attrs, "counterparty_port_id")?;
    let counterparty_channel_id = parse_optional_channel_id(&attrs, "counterparty_channel_id");

    Ok(IbcEvent::OpenInitChannel(ChannelEvents::OpenInit {
        port_id,
        channel_id,
        connection_id,
        counterparty_port_id,
        counterparty_channel_id,
    }))
}

fn parse_channel_open_try_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let port_id = parse_port_id(&attrs, "port_id")?;
    let channel_id = parse_optional_channel_id(&attrs, "channel_id");
    let connection_id = parse_connection_id(&attrs, "connection_id")?;
    let counterparty_port_id = parse_port_id(&attrs, "counterparty_port_id")?;
    let counterparty_channel_id = parse_optional_channel_id(&attrs, "counterparty_channel_id");

    Ok(IbcEvent::OpenTryChannel(ChannelEvents::OpenTry {
        port_id,
        channel_id,
        connection_id,
        counterparty_port_id,
        counterparty_channel_id,
    }))
}

fn parse_channel_open_ack_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let port_id = parse_port_id(&attrs, "port_id")?;
    let channel_id = parse_optional_channel_id(&attrs, "channel_id");
    let connection_id = parse_connection_id(&attrs, "connection_id")?;
    let counterparty_port_id = parse_port_id(&attrs, "counterparty_port_id")?;
    let counterparty_channel_id = parse_optional_channel_id(&attrs, "counterparty_channel_id");

    Ok(IbcEvent::OpenAckChannel(ChannelEvents::OpenAck {
        port_id,
        channel_id,
        connection_id,
        counterparty_port_id,
        counterparty_channel_id,
    }))
}

fn parse_channel_open_confirm_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let port_id = parse_port_id(&attrs, "port_id")?;
    let channel_id = parse_optional_channel_id(&attrs, "channel_id");
    let connection_id = parse_connection_id(&attrs, "connection_id")?;
    let counterparty_port_id = parse_port_id(&attrs, "counterparty_port_id")?;
    let counterparty_channel_id = parse_optional_channel_id(&attrs, "counterparty_channel_id");

    Ok(IbcEvent::OpenConfirmChannel(ChannelEvents::OpenConfirm {
        port_id,
        channel_id,
        connection_id,
        counterparty_port_id,
        counterparty_channel_id,
    }))
}

fn parse_channel_close_init_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let port_id = parse_port_id(&attrs, "port_id")?;
    let channel_id = parse_channel_id(&attrs, "channel_id")?;
    let connection_id = parse_connection_id(&attrs, "connection_id")?;
    let counterparty_port_id = parse_port_id(&attrs, "counterparty_port_id")?;
    let counterparty_channel_id = parse_optional_channel_id(&attrs, "counterparty_channel_id");

    Ok(IbcEvent::CloseInitChannel(ChannelEvents::CloseInit {
        port_id,
        channel_id,
        connection_id,
        counterparty_port_id,
        counterparty_channel_id,
    }))
}

fn parse_channel_close_confirm_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let port_id = parse_port_id(&attrs, "port_id")?;
    let channel_id = parse_optional_channel_id(&attrs, "channel_id");
    let connection_id = parse_connection_id(&attrs, "connection_id")?;
    let counterparty_port_id = parse_port_id(&attrs, "counterparty_port_id")?;
    let counterparty_channel_id = parse_optional_channel_id(&attrs, "counterparty_channel_id");

    Ok(IbcEvent::CloseConfirmChannel(ChannelEvents::CloseConfirm {
        channel_id,
        port_id,
        connection_id,
        counterparty_port_id,
        counterparty_channel_id,
    }))
}

//
// Packet event parsers
//

fn parse_send_packet_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let packet = parse_packet(&attrs)?;
    Ok(IbcEvent::SendPacket(ChannelEvents::SendPacket { packet }))
}

fn parse_recv_packet_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let packet = parse_packet(&attrs)?;
    Ok(IbcEvent::ReceivePacket(ChannelEvents::ReceivePacket {
        packet,
    }))
}

fn parse_write_acknowledgement_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let packet = parse_packet(&attrs)?;
    let ack = parse_bytes_preferring_hex_alias(&attrs, "packet_ack", "packet_ack_hex")?;
    Ok(IbcEvent::WriteAcknowledgement(
        ChannelEvents::WriteAcknowledgement { packet, ack },
    ))
}

fn parse_acknowledge_packet_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let packet = parse_packet(&attrs)?;
    Ok(IbcEvent::AcknowledgePacket(
        ChannelEvents::AcknowledgePacket { packet },
    ))
}

fn parse_timeout_packet_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let packet = parse_packet(&attrs)?;
    Ok(IbcEvent::TimeoutPacket(ChannelEvents::TimeoutPacket {
        packet,
    }))
}

fn parse_timeout_on_close_packet_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let packet = parse_packet(&attrs)?;
    Ok(IbcEvent::TimeoutOnClosePacket(
        ChannelEvents::TimeoutOnClosePacket { packet },
    ))
}

//
// Helper functions for parsing attribute values
//

fn parse_client_id(attrs: &HashMap<String, String>, key: &str) -> Result<ClientId, Error> {
    let value = attrs
        .get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;

    ClientId::from_str(value)
        .map_err(|e| Error::EventAttribute(format!("Invalid client_id '{}': {}", value, e)))
}

fn parse_client_type(
    attrs: &HashMap<String, String>,
    key: &str,
) -> Result<ibc_relayer_types::core::ics02_client::client_type::ClientType, Error> {
    let value = attrs
        .get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;

    match value.as_str() {
        "cardano" | "08-cardano" => {
            Ok(ibc_relayer_types::core::ics02_client::client_type::ClientType::Cardano)
        }
        "cardano-stability" | "08-cardano-stability" => {
            Ok(ibc_relayer_types::core::ics02_client::client_type::ClientType::CardanoStability)
        }
        "tendermint" | "07-tendermint" => {
            Ok(ibc_relayer_types::core::ics02_client::client_type::ClientType::Tendermint)
        }
        _ => Err(Error::EventAttribute(format!(
            "Unknown client type: {}",
            value
        ))),
    }
}

fn parse_height(attrs: &HashMap<String, String>, key: &str) -> Result<Height, Error> {
    let value = attrs
        .get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;

    // Height format: "revision_number-revision_height" (e.g., "0-100")
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() != 2 {
        return Err(Error::EventAttribute(format!(
            "Invalid height format '{}', expected 'revision-height'",
            value
        )));
    }

    let revision_number = parts[0].parse::<u64>().map_err(|e| {
        Error::EventAttribute(format!("Invalid revision number '{}': {}", parts[0], e))
    })?;
    let revision_height = parts[1].parse::<u64>().map_err(|e| {
        Error::EventAttribute(format!("Invalid revision height '{}': {}", parts[1], e))
    })?;

    Height::new(revision_number, revision_height)
        .map_err(|e| Error::EventAttribute(format!("Invalid height: {}", e)))
}

fn parse_timeout_height(
    attrs: &HashMap<String, String>,
    key: &str,
) -> Result<TimeoutHeight, Error> {
    let value = attrs
        .get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;

    match Height::from_str(value) {
        Ok(height) => Ok(TimeoutHeight::from(height)),
        Err(e) => {
            let error_message = e.to_string();
            match e.into_detail() {
                HeightErrorDetail::ZeroHeight(_) => Ok(TimeoutHeight::no_timeout()),
                _ => Err(Error::EventAttribute(format!(
                    "Invalid height: {}",
                    error_message
                ))),
            }
        }
    }
}

fn parse_connection_id(attrs: &HashMap<String, String>, key: &str) -> Result<ConnectionId, Error> {
    let value = attrs
        .get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;

    ConnectionId::from_str(value)
        .map_err(|e| Error::EventAttribute(format!("Invalid connection_id '{}': {}", value, e)))
}

fn parse_optional_connection_id(
    attrs: &HashMap<String, String>,
    key: &str,
) -> Option<ConnectionId> {
    attrs.get(key).and_then(|v| ConnectionId::from_str(v).ok())
}

fn parse_port_id(attrs: &HashMap<String, String>, key: &str) -> Result<PortId, Error> {
    let value = attrs
        .get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;

    PortId::from_str(value)
        .map_err(|e| Error::EventAttribute(format!("Invalid port_id '{}': {}", value, e)))
}

fn parse_channel_id(attrs: &HashMap<String, String>, key: &str) -> Result<ChannelId, Error> {
    let value = attrs
        .get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;

    ChannelId::from_str(value)
        .map_err(|e| Error::EventAttribute(format!("Invalid channel_id '{}': {}", value, e)))
}

fn parse_optional_channel_id(attrs: &HashMap<String, String>, key: &str) -> Option<ChannelId> {
    attrs.get(key).and_then(|v| ChannelId::from_str(v).ok())
}

fn parse_u64(attrs: &HashMap<String, String>, key: &str) -> Result<u64, Error> {
    let value = attrs
        .get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;

    value
        .parse::<u64>()
        .map_err(|e| Error::EventAttribute(format!("Invalid u64 '{}': {}", value, e)))
}

fn parse_bytes(attrs: &HashMap<String, String>, key: &str) -> Result<Vec<u8>, Error> {
    let value = attrs
        .get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;

    let value_trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(value_trimmed).map_err(|e| {
        Error::EventAttribute(format!("Invalid hex bytes for {} '{}': {}", key, value, e))
    })
}

fn parse_bytes_preferring_hex_alias(
    attrs: &HashMap<String, String>,
    key: &str,
    hex_key: &str,
) -> Result<Vec<u8>, Error> {
    // Cardano gateway events may include human-readable packet JSON beside the relayable hex field.
    let selected_key = attrs
        .get(hex_key)
        .filter(|value| !value.is_empty())
        .map(|_| hex_key)
        .unwrap_or(key);

    parse_bytes(attrs, selected_key)
}

fn parse_packet(attrs: &HashMap<String, String>) -> Result<Packet, Error> {
    let sequence = parse_u64(attrs, "packet_sequence")?;
    let source_port = parse_port_id(attrs, "packet_src_port")?;
    let source_channel = parse_channel_id(attrs, "packet_src_channel")?;
    let destination_port = parse_port_id(attrs, "packet_dst_port")?;
    let destination_channel = parse_channel_id(attrs, "packet_dst_channel")?;
    let data = parse_bytes_preferring_hex_alias(attrs, "packet_data", "packet_data_hex")?;
    let timeout_height = parse_timeout_height(attrs, "packet_timeout_height")?;
    let timeout_timestamp_nanos = parse_u64(attrs, "packet_timeout_timestamp")?;
    let timeout_timestamp = Timestamp::from_nanoseconds(timeout_timestamp_nanos)
        .map_err(|e| Error::EventAttribute(format!("Invalid timestamp: {}", e)))?;

    Ok(Packet {
        sequence: sequence.into(),
        source_port,
        source_channel,
        destination_port,
        destination_channel,
        data,
        timeout_height,
        timeout_timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibc_relayer_types::clients::{
        ics08_cardano::raw as mithril_raw, ics08_cardano_stability::raw as stability_raw,
    };
    use ibc_relayer_types::core::ics02_client::client_type::ClientType;
    use ibc_relayer_types::core::ics02_client::height::Height;
    use ibc_relayer_types::core::ics04_channel::timeout::TimeoutHeight;
    use ibc_relayer_types::events::IbcEvent as RelayerIbcEvent;

    fn attrs(kvs: &[(&str, &str)]) -> Vec<EventAttribute> {
        kvs.iter()
            .map(|(k, v)| EventAttribute {
                key: (*k).to_string(),
                value: (*v).to_string(),
            })
            .collect()
    }

    fn any_hex(type_url: &str, value: Vec<u8>) -> String {
        hex::encode(
            ProtoAny {
                type_url: type_url.to_string(),
                value,
            }
            .encode_to_vec(),
        )
    }

    fn raw_mithril_certificate(sealed_at: &str) -> mithril_raw::MithrilCertificate {
        mithril_raw::MithrilCertificate {
            hash: "cert_hash".to_string(),
            previous_hash: String::new(),
            epoch: 0,
            signed_entity_type: None,
            metadata: Some(mithril_raw::CertificateMetadata {
                network: "testnet".to_string(),
                protocol_version: "v1".to_string(),
                protocol_parameters: Some(mithril_raw::MithrilProtocolParameters {
                    k: 1,
                    m: 2,
                    phi_f: None,
                }),
                initiated_at: "2024-01-01T00:00:00Z".to_string(),
                sealed_at: sealed_at.to_string(),
                signers: vec![],
            }),
            protocol_message: None,
            signed_message: String::new(),
            aggregate_verification_key: String::new(),
            multi_signature: String::new(),
            genesis_signature: String::new(),
        }
    }

    fn raw_mithril_header(block_number: u64) -> mithril_raw::MithrilHeader {
        mithril_raw::MithrilHeader {
            mithril_stake_distribution: Some(mithril_raw::MithrilStakeDistribution {
                epoch: 0,
                signers_with_stake: vec![],
                hash: "stake_dist_hash".to_string(),
                certificate_hash: "stake_dist_cert_hash".to_string(),
                created_at: 0,
                protocol_parameter: Some(mithril_raw::MithrilProtocolParameters {
                    k: 1,
                    m: 2,
                    phi_f: None,
                }),
            }),
            mithril_stake_distribution_certificate: Some(raw_mithril_certificate(
                "2024-01-01T00:00:00Z",
            )),
            transaction_snapshot: Some(mithril_raw::CardanoTransactionSnapshot {
                merkle_root: "merkle_root".to_string(),
                epoch: 0,
                block_number,
                hash: "tx_snapshot_hash".to_string(),
                certificate_hash: "tx_snapshot_cert_hash".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
            }),
            transaction_snapshot_certificate: Some(raw_mithril_certificate("2024-01-01T00:00:00Z")),
            previous_mithril_stake_distribution_certificates: vec![],
            host_state_tx_hash: "host_state_tx_hash".to_string(),
            host_state_tx_body_cbor: vec![0x01],
            host_state_tx_output_index: 0,
            host_state_tx_proof: vec![0x02],
        }
    }

    fn raw_stability_block(revision_height: u64, hash: &str) -> stability_raw::StabilityBlock {
        stability_raw::StabilityBlock {
            height: Some(stability_raw::Height {
                revision_number: 0,
                revision_height,
            }),
            slot: revision_height,
            hash: hash.to_string(),
            epoch: 0,
            timestamp: 1_700_000_000,
            block_cbor: vec![0x01],
        }
    }

    fn raw_stability_header(revision_height: u64) -> stability_raw::StabilityHeader {
        stability_raw::StabilityHeader {
            trusted_height: Some(stability_raw::Height {
                revision_number: 0,
                revision_height: revision_height.saturating_sub(1),
            }),
            anchor_block: Some(raw_stability_block(revision_height, "anchor_hash")),
            descendant_blocks: vec![],
            host_state_tx_hash: "host_state_tx_hash".to_string(),
            host_state_tx_output_index: 0,
            bridge_blocks: vec![],
            new_epoch_context: None,
        }
    }

    #[test]
    fn parse_cardano_stability_client_type_ok() {
        let attrs = HashMap::from([(
            "client_type".to_string(),
            "08-cardano-stability".to_string(),
        )]);

        assert_eq!(
            parse_client_type(&attrs, "client_type").unwrap(),
            ClientType::CardanoStability
        );
    }

    #[test]
    fn parse_update_client_event_with_mithril_header_any() {
        let header_hex = any_hex(
            MITHRIL_HEADER_TYPE_URL,
            raw_mithril_header(10).encode_to_vec(),
        );
        let gateway_event = Event {
            r#type: "update_client".to_string(),
            attributes: attrs(&[
                ("client_id", "08-cardano-0"),
                ("client_type", "08-cardano"),
                ("consensus_height", "0-10"),
                (ATTR_CLIENT_MESSAGE_ANY_HEX, &header_hex),
            ]),
        };

        let events = parse_events(vec![gateway_event], Height::new(0, 10).unwrap()).unwrap();

        match &events[0] {
            RelayerIbcEvent::UpdateClient(ev) => {
                assert!(matches!(ev.header, Some(AnyHeader::Mithril(_))));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parse_update_client_event_with_stability_header_any() {
        let header_hex = any_hex(
            STABILITY_HEADER_TYPE_URL,
            raw_stability_header(12).encode_to_vec(),
        );
        let gateway_event = Event {
            r#type: "update_client".to_string(),
            attributes: attrs(&[
                ("client_id", "08-cardano-stability-0"),
                ("client_type", "08-cardano-stability"),
                ("consensus_height", "0-12"),
                (ATTR_CLIENT_MESSAGE_ANY_HEX, &header_hex),
            ]),
        };

        let events = parse_events(vec![gateway_event], Height::new(0, 12).unwrap()).unwrap();

        match &events[0] {
            RelayerIbcEvent::UpdateClient(ev) => {
                assert!(matches!(ev.header, Some(AnyHeader::Stability(_))));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parse_update_client_event_without_client_message_keeps_header_empty() {
        let gateway_event = Event {
            r#type: "update_client".to_string(),
            attributes: attrs(&[
                ("client_id", "07-tendermint-0"),
                ("client_type", "07-tendermint"),
                ("consensus_height", "0-10"),
            ]),
        };

        let events = parse_events(vec![gateway_event], Height::new(0, 10).unwrap()).unwrap();

        match &events[0] {
            RelayerIbcEvent::UpdateClient(ev) => assert!(ev.header.is_none()),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parse_update_client_event_with_misbehaviour_any_keeps_header_empty() {
        let misbehaviour_hex = any_hex(MITHRIL_MISBEHAVIOUR_TYPE_URL, vec![0x01, 0x02]);
        let gateway_event = Event {
            r#type: "update_client".to_string(),
            attributes: attrs(&[
                ("client_id", "08-cardano-0"),
                ("client_type", "08-cardano"),
                ("consensus_height", "0-10"),
                (ATTR_CLIENT_MESSAGE_ANY_HEX, &misbehaviour_hex),
            ]),
        };

        let events = parse_events(vec![gateway_event], Height::new(0, 10).unwrap()).unwrap();

        match &events[0] {
            RelayerIbcEvent::UpdateClient(ev) => assert!(ev.header.is_none()),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parse_update_client_event_with_malformed_client_message_fails() {
        let gateway_event = Event {
            r#type: "update_client".to_string(),
            attributes: attrs(&[
                ("client_id", "08-cardano-0"),
                ("client_type", "08-cardano"),
                ("consensus_height", "0-10"),
                (ATTR_CLIENT_MESSAGE_ANY_HEX, "not-hex"),
            ]),
        };

        let err = parse_events(vec![gateway_event], Height::new(0, 10).unwrap()).unwrap_err();

        match err {
            Error::EventAttribute(msg) => {
                assert!(msg.contains("Invalid hex bytes for client_message_any_hex"))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_client_misbehaviour_event_ok() {
        let gateway_event = Event {
            r#type: "client_misbehaviour".to_string(),
            attributes: attrs(&[
                ("client_id", "07-tendermint-0"),
                ("client_type", "07-tendermint"),
                ("consensus_height", "0-1"),
            ]),
        };

        let events = parse_events(vec![gateway_event], Height::new(0, 1).unwrap()).unwrap();

        assert!(matches!(&events[0], RelayerIbcEvent::ClientMisbehaviour(_)));
    }

    #[test]
    fn parse_timeout_on_close_packet_event_ok() {
        let gateway_event = Event {
            r#type: "timeout_on_close_packet".to_string(),
            attributes: attrs(&[
                ("packet_sequence", "7"),
                ("packet_src_port", "transfer"),
                ("packet_src_channel", "channel-0"),
                ("packet_dst_port", "transfer"),
                ("packet_dst_channel", "channel-1"),
                ("packet_data", "deadbeef"),
                ("packet_timeout_height", "0-10"),
                ("packet_timeout_timestamp", "1000"),
            ]),
        };

        let height = Height::new(0, 1).unwrap();
        let events = parse_events(vec![gateway_event], height).unwrap();

        assert_eq!(events.len(), 1);
        match &events[0] {
            RelayerIbcEvent::TimeoutOnClosePacket(ev) => {
                assert_eq!(ev.packet.sequence, 7.into());
                assert_eq!(ev.packet.source_port.as_str(), "transfer");
                assert_eq!(ev.packet.source_channel.as_str(), "channel-0");
                assert_eq!(ev.packet.destination_port.as_str(), "transfer");
                assert_eq!(ev.packet.destination_channel.as_str(), "channel-1");
                assert_eq!(ev.packet.data, hex::decode("deadbeef").unwrap());
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parse_timeout_on_close_packet_event_missing_attr_fails() {
        let gateway_event = Event {
            r#type: "timeout_on_close_packet".to_string(),
            attributes: attrs(&[
                ("packet_sequence", "7"),
                ("packet_src_port", "transfer"),
                ("packet_src_channel", "channel-0"),
                ("packet_dst_port", "transfer"),
                ("packet_dst_channel", "channel-1"),
                // packet_data missing
                ("packet_timeout_height", "0-10"),
                ("packet_timeout_timestamp", "1000"),
            ]),
        };

        let height = Height::new(0, 1).unwrap();
        let err = parse_events(vec![gateway_event], height).unwrap_err();

        match err {
            Error::EventAttribute(msg) => assert!(msg.contains("Missing attribute: packet_data")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_timeout_on_close_packet_event_malformed_packet_data_fails() {
        let payload = r#"{"amount":"1000000","denom":"stake","receiver":"abc","sender":"def"}"#;
        let gateway_event = Event {
            r#type: "timeout_on_close_packet".to_string(),
            attributes: attrs(&[
                ("packet_sequence", "7"),
                ("packet_src_port", "transfer"),
                ("packet_src_channel", "channel-0"),
                ("packet_dst_port", "transfer"),
                ("packet_dst_channel", "channel-1"),
                ("packet_data", payload),
                ("packet_timeout_height", "0-10"),
                ("packet_timeout_timestamp", "1000"),
            ]),
        };

        let height = Height::new(0, 1).unwrap();
        let err = parse_events(vec![gateway_event], height).unwrap_err();

        match err {
            Error::EventAttribute(msg) => {
                assert!(msg.contains("Invalid hex bytes for packet_data"))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_send_packet_event_prefers_packet_data_hex_over_json_packet_data() {
        let json_payload =
            r#"{"amount":"1000000","denom":"stake","receiver":"abc","sender":"def"}"#;
        let gateway_event = Event {
            r#type: "send_packet".to_string(),
            attributes: attrs(&[
                ("packet_sequence", "7"),
                ("packet_src_port", "transfer"),
                ("packet_src_channel", "channel-0"),
                ("packet_dst_port", "transfer"),
                ("packet_dst_channel", "channel-1"),
                ("packet_data", json_payload),
                ("packet_data_hex", "deadbeef"),
                ("packet_timeout_height", "0-10"),
                ("packet_timeout_timestamp", "1000"),
            ]),
        };

        let height = Height::new(0, 1).unwrap();
        let events = parse_events(vec![gateway_event], height).unwrap();

        match &events[0] {
            RelayerIbcEvent::SendPacket(ev) => {
                assert_eq!(ev.packet.data, hex::decode("deadbeef").unwrap());
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parse_write_acknowledgement_event_malformed_ack_fails() {
        let gateway_event = Event {
            r#type: "write_acknowledgement".to_string(),
            attributes: attrs(&[
                ("packet_sequence", "7"),
                ("packet_src_port", "transfer"),
                ("packet_src_channel", "channel-0"),
                ("packet_dst_port", "transfer"),
                ("packet_dst_channel", "channel-1"),
                ("packet_data", "deadbeef"),
                ("packet_ack", "not-hex"),
                ("packet_timeout_height", "0-10"),
                ("packet_timeout_timestamp", "1000"),
            ]),
        };

        let height = Height::new(0, 1).unwrap();
        let err = parse_events(vec![gateway_event], height).unwrap_err();

        match err {
            Error::EventAttribute(msg) => {
                assert!(msg.contains("Invalid hex bytes for packet_ack"))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_write_acknowledgement_event_prefers_packet_ack_hex() {
        let gateway_event = Event {
            r#type: "write_acknowledgement".to_string(),
            attributes: attrs(&[
                ("packet_sequence", "7"),
                ("packet_src_port", "transfer"),
                ("packet_src_channel", "channel-0"),
                ("packet_dst_port", "transfer"),
                ("packet_dst_channel", "channel-1"),
                ("packet_data", "deadbeef"),
                ("packet_ack", r#"{"result":"AQ=="}"#),
                ("packet_ack_hex", "01"),
                ("packet_timeout_height", "0-10"),
                ("packet_timeout_timestamp", "1000"),
            ]),
        };

        let height = Height::new(0, 1).unwrap();
        let events = parse_events(vec![gateway_event], height).unwrap();

        match &events[0] {
            RelayerIbcEvent::WriteAcknowledgement(ev) => {
                assert_eq!(ev.ack, hex::decode("01").unwrap());
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn parse_send_packet_event_zero_timeout_height_maps_to_no_timeout() {
        let gateway_event = Event {
            r#type: "send_packet".to_string(),
            attributes: attrs(&[
                ("packet_sequence", "9"),
                ("packet_src_port", "transfer"),
                ("packet_src_channel", "channel-0"),
                ("packet_dst_port", "transfer"),
                ("packet_dst_channel", "channel-1"),
                ("packet_data", "deadbeef"),
                ("packet_timeout_height", "0-0"),
                ("packet_timeout_timestamp", "1000"),
            ]),
        };

        let height = Height::new(0, 1).unwrap();
        let events = parse_events(vec![gateway_event], height).unwrap();

        assert_eq!(events.len(), 1);
        match &events[0] {
            RelayerIbcEvent::SendPacket(ev) => {
                assert_eq!(ev.packet.timeout_height, TimeoutHeight::no_timeout());
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
}
