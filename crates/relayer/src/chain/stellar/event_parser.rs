use ibc_relayer_types::{
    core::ics24_host::identifier::ChainId,
    events::IbcEvent,
    Height,
};

use crate::event::IbcEventWithHeight;

use super::error::StellarError;

pub fn parse_event_bytes(
    raw: &[u8],
    height: Height,
) -> Result<Option<IbcEventWithHeight>, StellarError> {
    let s = std::str::from_utf8(raw)
        .map_err(|e| StellarError::EventAttribute(e.to_string()))?;

    let kind = event_kind(s);

    let ibc_event = match kind {
        "send_packet" => parse_send_packet(s)?,
        "recv_packet" => parse_recv_packet(s)?,
        "write_acknowledgement" => parse_write_ack(s)?,
        "acknowledge_packet" => parse_ack_packet(s)?,
        "timeout_packet" => parse_timeout_packet(s)?,
        "create_client" => parse_create_client(s)?,
        "update_client" => parse_update_client(s)?,
        _ => return Ok(None),
    };

    Ok(ibc_event.map(|ev| IbcEventWithHeight::new(ev, height)))
}

pub fn parse_events_from_tx(
    raw_events: &[Vec<u8>],
    height: Height,
    _chain_id: &ChainId,
) -> Vec<IbcEventWithHeight> {
    raw_events
        .iter()
        .filter_map(|raw| parse_event_bytes(raw, height).ok().flatten())
        .collect()
}

fn event_kind(s: &str) -> &str {
    s.lines()
        .find_map(|l| l.strip_prefix("type="))
        .unwrap_or("")
}

fn attr<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    s.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
}

fn parse_send_packet(s: &str) -> Result<Option<IbcEvent>, StellarError> {
    use ibc_relayer_types::core::ics04_channel::events::SendPacket;
    use ibc_relayer_types::events::IbcEvent;

    let packet = parse_packet(s)?;
    Ok(Some(IbcEvent::SendPacket(SendPacket { packet })))
}

fn parse_recv_packet(s: &str) -> Result<Option<IbcEvent>, StellarError> {
    use ibc_relayer_types::core::ics04_channel::events::ReceivePacket;
    use ibc_relayer_types::events::IbcEvent;

    let packet = parse_packet(s)?;
    Ok(Some(IbcEvent::ReceivePacket(ReceivePacket { packet })))
}

fn parse_write_ack(s: &str) -> Result<Option<IbcEvent>, StellarError> {
    use ibc_relayer_types::core::ics04_channel::events::WriteAcknowledgement;
    use ibc_relayer_types::events::IbcEvent;

    let packet = parse_packet(s)?;
    let ack = attr(s, "acknowledgement")
        .map(|v| v.as_bytes().to_vec())
        .unwrap_or_default();
    Ok(Some(IbcEvent::WriteAcknowledgement(WriteAcknowledgement {
        packet,
        ack,
    })))
}

fn parse_ack_packet(s: &str) -> Result<Option<IbcEvent>, StellarError> {
    use ibc_relayer_types::core::ics04_channel::events::AcknowledgePacket;
    use ibc_relayer_types::events::IbcEvent;

    let packet = parse_packet(s)?;
    Ok(Some(IbcEvent::AcknowledgePacket(AcknowledgePacket { packet })))
}

fn parse_timeout_packet(s: &str) -> Result<Option<IbcEvent>, StellarError> {
    use ibc_relayer_types::core::ics04_channel::events::TimeoutPacket;
    use ibc_relayer_types::events::IbcEvent;

    let packet = parse_packet(s)?;
    Ok(Some(IbcEvent::TimeoutPacket(TimeoutPacket { packet })))
}

fn parse_create_client(s: &str) -> Result<Option<IbcEvent>, StellarError> {
    use ibc_relayer_types::core::ics02_client::client_type::ClientType;
    use ibc_relayer_types::core::ics02_client::events::{Attributes, CreateClient};
    use ibc_relayer_types::events::IbcEvent;

    let client_id = attr(s, "client_id")
        .ok_or_else(|| StellarError::EventAttribute("missing client_id".to_owned()))?
        .parse()
        .map_err(|e: ibc_relayer_types::core::ics24_host::error::ValidationError| {
            StellarError::EventAttribute(e.to_string())
        })?;
    let client_type = ClientType::Tendermint;
    let consensus_height = parse_height_attr(s, "consensus_height")?;

    Ok(Some(IbcEvent::CreateClient(CreateClient(Attributes {
        client_id,
        client_type,
        consensus_height,
    }))))
}

fn parse_update_client(s: &str) -> Result<Option<IbcEvent>, StellarError> {
    use ibc_relayer_types::core::ics02_client::client_type::ClientType;
    use ibc_relayer_types::core::ics02_client::events::{Attributes, UpdateClient};
    use ibc_relayer_types::events::IbcEvent;

    let client_id = attr(s, "client_id")
        .ok_or_else(|| StellarError::EventAttribute("missing client_id".to_owned()))?
        .parse()
        .map_err(|e: ibc_relayer_types::core::ics24_host::error::ValidationError| {
            StellarError::EventAttribute(e.to_string())
        })?;
    let client_type = ClientType::Tendermint;
    let consensus_height = parse_height_attr(s, "consensus_height")?;

    Ok(Some(IbcEvent::UpdateClient(UpdateClient {
        common: Attributes {
            client_id,
            client_type,
            consensus_height,
        },
        header: None,
    })))
}

fn parse_packet(s: &str) -> Result<ibc_relayer_types::core::ics04_channel::packet::Packet, StellarError> {
    use ibc_relayer_types::core::ics04_channel::packet::{Packet, Sequence};
    use ibc_relayer_types::core::ics24_host::identifier::{ChannelId, PortId};
    use ibc_relayer_types::timestamp::Timestamp;

    let sequence: Sequence = attr(s, "packet_sequence")
        .and_then(|v| v.parse::<u64>().ok())
        .map(Sequence::from)
        .unwrap_or_default();

    let source_port: PortId = attr(s, "packet_src_port")
        .unwrap_or("transfer")
        .parse()
        .map_err(|e: ibc_relayer_types::core::ics24_host::error::ValidationError| {
            StellarError::EventAttribute(e.to_string())
        })?;

    let source_channel: ChannelId = attr(s, "packet_src_channel")
        .unwrap_or("channel-0")
        .parse()
        .map_err(|e: ibc_relayer_types::core::ics24_host::error::ValidationError| {
            StellarError::EventAttribute(e.to_string())
        })?;

    let destination_port: PortId = attr(s, "packet_dst_port")
        .unwrap_or("transfer")
        .parse()
        .map_err(|e: ibc_relayer_types::core::ics24_host::error::ValidationError| {
            StellarError::EventAttribute(e.to_string())
        })?;

    let destination_channel: ChannelId = attr(s, "packet_dst_channel")
        .unwrap_or("channel-0")
        .parse()
        .map_err(|e: ibc_relayer_types::core::ics24_host::error::ValidationError| {
            StellarError::EventAttribute(e.to_string())
        })?;

    let data = attr(s, "packet_data")
        .map(|v| v.as_bytes().to_vec())
        .unwrap_or_default();

    let timeout_height = ibc_relayer_types::core::ics04_channel::timeout::TimeoutHeight::Never;

    Ok(Packet {
        sequence,
        source_port,
        source_channel,
        destination_port,
        destination_channel,
        data,
        timeout_height,
        timeout_timestamp: Timestamp::none(),
    })
}

fn parse_height_attr(s: &str, key: &str) -> Result<Height, StellarError> {
    let raw = attr(s, key).unwrap_or("0-0");
    let parts: Vec<&str> = raw.splitn(2, '-').collect();
    let revision_number = parts.first().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let revision_height = parts.get(1).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    Height::new(revision_number, revision_height)
        .map_err(|e| StellarError::EventAttribute(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibc_relayer_types::events::IbcEvent;

    fn height(h: u64) -> Height {
        Height::new(0, h).unwrap()
    }

    fn packet_attrs(seq: u64) -> String {
        format!(
            "type=send_packet\npacket_sequence={seq}\npacket_src_port=transfer\npacket_src_channel=channel-0\npacket_dst_port=transfer\npacket_dst_channel=channel-1\npacket_data=hello\n"
        )
    }

    #[test]
    fn unknown_event_type_returns_none() {
        let raw = b"type=unknown_event\nfoo=bar\n";
        let result = parse_event_bytes(raw, height(1)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn invalid_utf8_returns_error() {
        let raw: &[u8] = &[0xFF, 0xFE];
        assert!(parse_event_bytes(raw, height(1)).is_err());
    }

    #[test]
    fn send_packet_parsed_correctly() {
        let raw = packet_attrs(42);
        let ev = parse_event_bytes(raw.as_bytes(), height(10)).unwrap().unwrap();
        assert_eq!(ev.height, height(10));
        assert!(matches!(ev.event, IbcEvent::SendPacket(_)));
        if let IbcEvent::SendPacket(e) = ev.event {
            assert_eq!(u64::from(e.packet.sequence), 42);
            assert_eq!(e.packet.source_port.as_str(), "transfer");
            assert_eq!(e.packet.destination_channel.as_str(), "channel-1");
        }
    }

    #[test]
    fn recv_packet_parsed_correctly() {
        let raw = "type=recv_packet\npacket_sequence=7\npacket_src_port=transfer\npacket_src_channel=channel-0\npacket_dst_port=transfer\npacket_dst_channel=channel-2\n";
        let ev = parse_event_bytes(raw.as_bytes(), height(5)).unwrap().unwrap();
        assert!(matches!(ev.event, IbcEvent::ReceivePacket(_)));
        if let IbcEvent::ReceivePacket(e) = ev.event {
            assert_eq!(u64::from(e.packet.sequence), 7);
        }
    }

    #[test]
    fn write_ack_includes_acknowledgement() {
        let raw = "type=write_acknowledgement\npacket_sequence=3\npacket_src_port=transfer\npacket_src_channel=channel-0\npacket_dst_port=transfer\npacket_dst_channel=channel-0\nacknowledgement=ack_data\n";
        let ev = parse_event_bytes(raw.as_bytes(), height(1)).unwrap().unwrap();
        assert!(matches!(ev.event, IbcEvent::WriteAcknowledgement(_)));
        if let IbcEvent::WriteAcknowledgement(e) = ev.event {
            assert_eq!(e.ack, b"ack_data");
        }
    }

    #[test]
    fn create_client_parsed_correctly() {
        let raw = "type=create_client\nclient_id=07-tendermint-0\nconsensus_height=1-100\n";
        let ev = parse_event_bytes(raw.as_bytes(), height(1)).unwrap().unwrap();
        assert!(matches!(ev.event, IbcEvent::CreateClient(_)));
        if let IbcEvent::CreateClient(e) = ev.event {
            assert_eq!(e.0.client_id.as_str(), "07-tendermint-0");
            assert_eq!(e.0.consensus_height, Height::new(1, 100).unwrap());
        }
    }

    #[test]
    fn update_client_parsed_correctly() {
        let raw = "type=update_client\nclient_id=07-tendermint-1\nconsensus_height=0-200\n";
        let ev = parse_event_bytes(raw.as_bytes(), height(2)).unwrap().unwrap();
        assert!(matches!(ev.event, IbcEvent::UpdateClient(_)));
        if let IbcEvent::UpdateClient(e) = ev.event {
            assert_eq!(e.common.client_id.as_str(), "07-tendermint-1");
            assert_eq!(e.common.consensus_height, Height::new(0, 200).unwrap());
        }
    }

    #[test]
    fn parse_events_from_tx_filters_unknown() {
        let chain_id = ChainId::from_string("stellar-testnet");
        let events: Vec<Vec<u8>> = vec![
            packet_attrs(1).into_bytes(),
            b"type=garbage\n".to_vec(),
            "type=recv_packet\npacket_sequence=2\npacket_src_port=transfer\npacket_src_channel=channel-0\npacket_dst_port=transfer\npacket_dst_channel=channel-0\n".as_bytes().to_vec(),
        ];
        let results = parse_events_from_tx(&events, height(50), &chain_id);
        assert_eq!(results.len(), 2);
        assert!(matches!(results[0].event, IbcEvent::SendPacket(_)));
        assert!(matches!(results[1].event, IbcEvent::ReceivePacket(_)));
    }

    #[test]
    fn ack_packet_parsed_correctly() {
        let raw = "type=acknowledge_packet\npacket_sequence=5\npacket_src_port=transfer\npacket_src_channel=channel-0\npacket_dst_port=transfer\npacket_dst_channel=channel-0\n";
        let ev = parse_event_bytes(raw.as_bytes(), height(1)).unwrap().unwrap();
        assert!(matches!(ev.event, IbcEvent::AcknowledgePacket(_)));
    }

    #[test]
    fn timeout_packet_parsed_correctly() {
        let raw = "type=timeout_packet\npacket_sequence=9\npacket_src_port=transfer\npacket_src_channel=channel-0\npacket_dst_port=transfer\npacket_dst_channel=channel-0\n";
        let ev = parse_event_bytes(raw.as_bytes(), height(1)).unwrap().unwrap();
        assert!(matches!(ev.event, IbcEvent::TimeoutPacket(_)));
    }
}
