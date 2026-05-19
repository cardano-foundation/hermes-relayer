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
    use ibc_relayer_types::core::ics02_client::events::CreateClient;
    use ibc_relayer_types::core::ics02_client::events::Attributes;
    use ibc_relayer_types::events::IbcEvent;

    let client_id = attr(s, "client_id")
        .ok_or_else(|| StellarError::EventAttribute("missing client_id".to_owned()))?
        .parse()
        .map_err(|e: ibc_relayer_types::core::ics24_host::error::ValidationError| {
            StellarError::EventAttribute(e.to_string())
        })?;
    let client_type = attr(s, "client_type")
        .ok_or_else(|| StellarError::EventAttribute("missing client_type".to_owned()))?
        .parse()
        .map_err(|e: ibc_relayer_types::core::ics02_client::client_type::ClientType| {
            StellarError::EventAttribute(format!("{e}"))
        })
        .or_else(|_| {
            Ok::<_, StellarError>(
                ibc_relayer_types::core::ics02_client::client_type::ClientType::new(
                    attr(s, "client_type").unwrap_or("").to_owned(),
                ),
            )
        })?;
    let consensus_height = parse_height_attr(s, "consensus_height")?;

    Ok(Some(IbcEvent::CreateClient(CreateClient(Attributes {
        client_id,
        client_type,
        consensus_height,
    }))))
}

fn parse_update_client(s: &str) -> Result<Option<IbcEvent>, StellarError> {
    use ibc_relayer_types::core::ics02_client::events::UpdateClient;
    use ibc_relayer_types::core::ics02_client::events::Attributes;
    use ibc_relayer_types::events::IbcEvent;

    let client_id = attr(s, "client_id")
        .ok_or_else(|| StellarError::EventAttribute("missing client_id".to_owned()))?
        .parse()
        .map_err(|e: ibc_relayer_types::core::ics24_host::error::ValidationError| {
            StellarError::EventAttribute(e.to_string())
        })?;
    let client_type = ibc_relayer_types::core::ics02_client::client_type::ClientType::new(
        attr(s, "client_type").unwrap_or("").to_owned(),
    );
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
