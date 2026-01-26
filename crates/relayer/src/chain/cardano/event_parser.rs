//! Event parsing for Cardano Gateway events -> Hermes `IbcEvent` conversion.
//!
//! The Gateway returns events in the format:
//! `Event { type: "create_client", attributes: [{ key: "client_id", value: "08-cardano-0" }, ...] }`
//!
//! This module converts them into Hermes' `IbcEvent` enum variants.

use ibc_relayer_types::{
    core::{
        ics02_client::{
            events as ClientEvents,
            height::Height,
        },
        ics03_connection::events as ConnectionEvents,
        ics04_channel::{
            events as ChannelEvents,
            packet::Packet,
        },
        ics24_host::identifier::{ClientId, ConnectionId, ChannelId, PortId},
    },
    events::IbcEvent,
    timestamp::Timestamp,
};
use std::collections::HashMap;
use std::str::FromStr;

use super::error::Error;
use super::generated::ibc::cardano::v1::{Event, EventAttribute};

/// Parse a list of Gateway events into Hermes IbcEvent types
pub fn parse_events(gateway_events: Vec<Event>, _height: Height) -> Result<Vec<IbcEvent>, Error> {
    let mut ibc_events = Vec::new();
    
    for event in gateway_events {
        tracing::debug!("Parsing event type: {}", event.r#type);
        
        // Convert attributes to a HashMap for easier lookup
        let attrs = attributes_to_map(event.attributes);
        
        // Parse event based on type
        let ibc_event = match event.r#type.as_str() {
            // Client events
            "create_client" => parse_create_client_event(attrs)?,
            "update_client" => parse_update_client_event(attrs)?,
            "upgrade_client" => parse_upgrade_client_event(attrs)?,
            "client_misbehaviour" => parse_client_misbehaviour_event(attrs)?,
            
            // Connection events
            "connection_open_init" => parse_connection_open_init_event(attrs)?,
            "connection_open_try" => parse_connection_open_try_event(attrs)?,
            "connection_open_ack" => parse_connection_open_ack_event(attrs)?,
            "connection_open_confirm" => parse_connection_open_confirm_event(attrs)?,
            
            // Channel events
            "channel_open_init" => parse_channel_open_init_event(attrs)?,
            "channel_open_try" => parse_channel_open_try_event(attrs)?,
            "channel_open_ack" => parse_channel_open_ack_event(attrs)?,
            "channel_open_confirm" => parse_channel_open_confirm_event(attrs)?,
            "channel_close_init" => parse_channel_close_init_event(attrs)?,
            "channel_close_confirm" => parse_channel_close_confirm_event(attrs)?,
            
            // Packet events
            "send_packet" => parse_send_packet_event(attrs)?,
            "recv_packet" => parse_recv_packet_event(attrs)?,
            "write_acknowledgement" => parse_write_acknowledgement_event(attrs)?,
            "acknowledge_packet" => parse_acknowledge_packet_event(attrs)?,
            "timeout_packet" => parse_timeout_packet_event(attrs)?,
            "timeout_on_close_packet" => parse_timeout_on_close_packet_event(attrs)?,
            
            // Unknown event type - log warning and skip
            _ => {
                tracing::warn!("Unknown event type: {}", event.r#type);
                continue;
            }
        };
        
        ibc_events.push(ibc_event);
    }
    
    Ok(ibc_events)
}

/// Convert event attributes to a HashMap for easier lookup
fn attributes_to_map(attributes: Vec<EventAttribute>) -> HashMap<String, String> {
    attributes.into_iter()
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
    
    Ok(IbcEvent::CreateClient(ClientEvents::CreateClient(attributes)))
}

fn parse_update_client_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let client_id = parse_client_id(&attrs, "client_id")?;
    let client_type = parse_client_type(&attrs, "client_type")?;
    let consensus_height = parse_height(&attrs, "consensus_height")?;
    
    let common = ClientEvents::Attributes {
        client_id,
        client_type,
        consensus_height,
    };
    
    Ok(IbcEvent::UpdateClient(ClientEvents::UpdateClient {
        common,
        header: None, // Header is not included in Gateway events
    }))
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
    
    Ok(IbcEvent::UpgradeClient(ClientEvents::UpgradeClient(attributes)))
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
    
    Ok(IbcEvent::ClientMisbehaviour(ClientEvents::ClientMisbehaviour(attributes)))
}

//
// Connection event parsers
//

fn parse_connection_open_init_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let connection_id = parse_optional_connection_id(&attrs, "connection_id");
    let client_id = parse_client_id(&attrs, "client_id")?;
    let counterparty_connection_id = parse_optional_connection_id(&attrs, "counterparty_connection_id");
    let counterparty_client_id = parse_client_id(&attrs, "counterparty_client_id")?;
    
    let attributes = ConnectionEvents::Attributes {
        connection_id,
        client_id,
        counterparty_connection_id,
        counterparty_client_id,
    };
    
    Ok(IbcEvent::OpenInitConnection(ConnectionEvents::OpenInit(attributes)))
}

fn parse_connection_open_try_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let connection_id = parse_optional_connection_id(&attrs, "connection_id");
    let client_id = parse_client_id(&attrs, "client_id")?;
    let counterparty_connection_id = parse_optional_connection_id(&attrs, "counterparty_connection_id");
    let counterparty_client_id = parse_client_id(&attrs, "counterparty_client_id")?;
    
    let attributes = ConnectionEvents::Attributes {
        connection_id,
        client_id,
        counterparty_connection_id,
        counterparty_client_id,
    };
    
    Ok(IbcEvent::OpenTryConnection(ConnectionEvents::OpenTry(attributes)))
}

fn parse_connection_open_ack_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let connection_id = parse_optional_connection_id(&attrs, "connection_id");
    let client_id = parse_client_id(&attrs, "client_id")?;
    let counterparty_connection_id = parse_optional_connection_id(&attrs, "counterparty_connection_id");
    let counterparty_client_id = parse_client_id(&attrs, "counterparty_client_id")?;
    
    let attributes = ConnectionEvents::Attributes {
        connection_id,
        client_id,
        counterparty_connection_id,
        counterparty_client_id,
    };
    
    Ok(IbcEvent::OpenAckConnection(ConnectionEvents::OpenAck(attributes)))
}

fn parse_connection_open_confirm_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let connection_id = parse_optional_connection_id(&attrs, "connection_id");
    let client_id = parse_client_id(&attrs, "client_id")?;
    let counterparty_connection_id = parse_optional_connection_id(&attrs, "counterparty_connection_id");
    let counterparty_client_id = parse_client_id(&attrs, "counterparty_client_id")?;
    
    let attributes = ConnectionEvents::Attributes {
        connection_id,
        client_id,
        counterparty_connection_id,
        counterparty_client_id,
    };
    
    Ok(IbcEvent::OpenConfirmConnection(ConnectionEvents::OpenConfirm(attributes)))
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
    Ok(IbcEvent::ReceivePacket(ChannelEvents::ReceivePacket { packet }))
}

fn parse_write_acknowledgement_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let packet = parse_packet(&attrs)?;
    let ack = parse_bytes(&attrs, "packet_ack")?;
    Ok(IbcEvent::WriteAcknowledgement(ChannelEvents::WriteAcknowledgement { packet, ack }))
}

fn parse_acknowledge_packet_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let packet = parse_packet(&attrs)?;
    Ok(IbcEvent::AcknowledgePacket(ChannelEvents::AcknowledgePacket { packet }))
}

fn parse_timeout_packet_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let packet = parse_packet(&attrs)?;
    Ok(IbcEvent::TimeoutPacket(ChannelEvents::TimeoutPacket { packet }))
}

fn parse_timeout_on_close_packet_event(attrs: HashMap<String, String>) -> Result<IbcEvent, Error> {
    let packet = parse_packet(&attrs)?;
    Ok(IbcEvent::TimeoutOnClosePacket(ChannelEvents::TimeoutOnClosePacket { packet }))
}

//
// Helper functions for parsing attribute values
//

fn parse_client_id(attrs: &HashMap<String, String>, key: &str) -> Result<ClientId, Error> {
    let value = attrs.get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;
    
    ClientId::from_str(value)
        .map_err(|e| Error::EventAttribute(format!("Invalid client_id '{}': {}", value, e)))
}

fn parse_client_type(attrs: &HashMap<String, String>, key: &str) -> Result<ibc_relayer_types::core::ics02_client::client_type::ClientType, Error> {
    let value = attrs.get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;
    
    match value.as_str() {
        "cardano" | "08-cardano" => Ok(ibc_relayer_types::core::ics02_client::client_type::ClientType::Cardano),
        "tendermint" | "07-tendermint" => Ok(ibc_relayer_types::core::ics02_client::client_type::ClientType::Tendermint),
        _ => Err(Error::EventAttribute(format!("Unknown client type: {}", value)))
    }
}

fn parse_height(attrs: &HashMap<String, String>, key: &str) -> Result<Height, Error> {
    let value = attrs.get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;
    
    // Height format: "revision_number-revision_height" (e.g., "0-100")
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() != 2 {
        return Err(Error::EventAttribute(format!("Invalid height format '{}', expected 'revision-height'", value)));
    }
    
    let revision_number = parts[0].parse::<u64>()
        .map_err(|e| Error::EventAttribute(format!("Invalid revision number '{}': {}", parts[0], e)))?;
    let revision_height = parts[1].parse::<u64>()
        .map_err(|e| Error::EventAttribute(format!("Invalid revision height '{}': {}", parts[1], e)))?;
    
    Ok(Height::new(revision_number, revision_height)
        .map_err(|e| Error::EventAttribute(format!("Invalid height: {}", e)))?)
}

fn parse_connection_id(attrs: &HashMap<String, String>, key: &str) -> Result<ConnectionId, Error> {
    let value = attrs.get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;
    
    ConnectionId::from_str(value)
        .map_err(|e| Error::EventAttribute(format!("Invalid connection_id '{}': {}", value, e)))
}

fn parse_optional_connection_id(attrs: &HashMap<String, String>, key: &str) -> Option<ConnectionId> {
    attrs.get(key).and_then(|v| ConnectionId::from_str(v).ok())
}

fn parse_port_id(attrs: &HashMap<String, String>, key: &str) -> Result<PortId, Error> {
    let value = attrs.get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;
    
    PortId::from_str(value)
        .map_err(|e| Error::EventAttribute(format!("Invalid port_id '{}': {}", value, e)))
}

fn parse_channel_id(attrs: &HashMap<String, String>, key: &str) -> Result<ChannelId, Error> {
    let value = attrs.get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;
    
    ChannelId::from_str(value)
        .map_err(|e| Error::EventAttribute(format!("Invalid channel_id '{}': {}", value, e)))
}

fn parse_optional_channel_id(attrs: &HashMap<String, String>, key: &str) -> Option<ChannelId> {
    attrs.get(key).and_then(|v| ChannelId::from_str(v).ok())
}

fn parse_u64(attrs: &HashMap<String, String>, key: &str) -> Result<u64, Error> {
    let value = attrs.get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;
    
    value.parse::<u64>()
        .map_err(|e| Error::EventAttribute(format!("Invalid u64 '{}': {}", value, e)))
}

fn parse_bytes(attrs: &HashMap<String, String>, key: &str) -> Result<Vec<u8>, Error> {
    let value = attrs.get(key)
        .ok_or_else(|| Error::EventAttribute(format!("Missing attribute: {}", key)))?;
    
    // Assume hex encoding
    hex::decode(value)
        .map_err(|e| Error::EventAttribute(format!("Invalid hex bytes '{}': {}", value, e)))
}

fn parse_packet(attrs: &HashMap<String, String>) -> Result<Packet, Error> {
    let sequence = parse_u64(attrs, "packet_sequence")?;
    let source_port = parse_port_id(attrs, "packet_src_port")?;
    let source_channel = parse_channel_id(attrs, "packet_src_channel")?;
    let destination_port = parse_port_id(attrs, "packet_dst_port")?;
    let destination_channel = parse_channel_id(attrs, "packet_dst_channel")?;
    let data = parse_bytes(attrs, "packet_data")?;
    let timeout_height = parse_height(attrs, "packet_timeout_height")?;
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
        timeout_height: timeout_height.into(),
        timeout_timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibc_relayer_types::core::ics02_client::height::Height;
    use ibc_relayer_types::events::IbcEvent as RelayerIbcEvent;

    fn attrs(kvs: &[(&str, &str)]) -> Vec<EventAttribute> {
        kvs.iter()
            .map(|(k, v)| EventAttribute {
                key: (*k).to_string(),
                value: (*v).to_string(),
            })
            .collect()
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
}
