// Protobuf parsing utilities for Cardano Gateway responses
//
// The Gateway returns IBC states wrapped in google.protobuf.Any messages.
// This module provides helpers to unwrap and parse these messages.

use prost::Message;
use super::error::Error;
use super::types::client_state::CardanoClientState;
use super::types::consensus_state::CardanoConsensusState;
use ibc_relayer_types::core::ics02_client::height::Height;

/// Type URL for Cardano client state in protobuf Any messages
const CARDANO_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.cardano.v1.ClientState";

/// Type URL for Cardano consensus state in protobuf Any messages
const CARDANO_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.cardano.v1.ConsensusState";

/// Parse ClientState from google.protobuf.Any
/// 
/// The Gateway serializes CardanoClientState as JSON in the Any.value field.
/// This function checks the type_url and deserializes the JSON.
pub fn parse_client_state_from_any(any: prost_types::Any) -> Result<CardanoClientState, Error> {
    // Verify type URL
    if any.type_url != CARDANO_CLIENT_STATE_TYPE_URL {
        return Err(Error::Query(format!(
            "Invalid client state type_url: expected {}, got {}",
            CARDANO_CLIENT_STATE_TYPE_URL, any.type_url
        )));
    }
    
    // For now, parse as JSON since the Gateway is TypeScript/NestJS
    // In the future, we can use proper protobuf if needed
    let client_state_json = String::from_utf8(any.value)
        .map_err(|e| Error::Query(format!("Invalid UTF-8 in client state: {}", e)))?;
    
    let parsed: serde_json::Value = serde_json::from_str(&client_state_json)
        .map_err(|e| Error::Query(format!("Failed to parse client state JSON: {}", e)))?;
    
    // Extract fields from JSON
    let chain_id = parsed["chain_id"]
        .as_str()
        .ok_or_else(|| Error::Query("Missing chain_id in client state".to_string()))?
        .to_string();
    
    let latest_height_obj = parsed["latest_height"]
        .as_object()
        .ok_or_else(|| Error::Query("Missing latest_height in client state".to_string()))?;
    
    let revision_number = latest_height_obj["revision_number"]
        .as_u64()
        .ok_or_else(|| Error::Query("Invalid revision_number in latest_height".to_string()))?;
    
    let revision_height = latest_height_obj["revision_height"]
        .as_u64()
        .ok_or_else(|| Error::Query("Invalid revision_height in latest_height".to_string()))?;
    
    let latest_height = Height::new(revision_number, revision_height)
        .map_err(|e| Error::Query(format!("Invalid height: {}", e)))?;
    
    let trusting_period = parsed["trusting_period"]
        .as_u64()
        .ok_or_else(|| Error::Query("Missing trusting_period in client state".to_string()))?;
    
    let unbonding_period = parsed["unbonding_period"]
        .as_u64()
        .ok_or_else(|| Error::Query("Missing unbonding_period in client state".to_string()))?;
    
    let mithril_genesis_vkey_hex = parsed["mithril_genesis_vkey"]
        .as_str()
        .ok_or_else(|| Error::Query("Missing mithril_genesis_vkey in client state".to_string()))?;
    
    let mithril_genesis_vkey = hex::decode(mithril_genesis_vkey_hex)
        .map_err(|e| Error::Query(format!("Invalid mithril_genesis_vkey hex: {}", e)))?;
    
    Ok(CardanoClientState::new(
        chain_id,
        latest_height,
        trusting_period,
        unbonding_period,
        mithril_genesis_vkey,
    ))
}

/// Parse ConsensusState from google.protobuf.Any
/// 
/// The Gateway serializes CardanoConsensusState as JSON in the Any.value field.
pub fn parse_consensus_state_from_any(any: prost_types::Any) -> Result<CardanoConsensusState, Error> {
    // Verify type URL
    if any.type_url != CARDANO_CONSENSUS_STATE_TYPE_URL {
        return Err(Error::Query(format!(
            "Invalid consensus state type_url: expected {}, got {}",
            CARDANO_CONSENSUS_STATE_TYPE_URL, any.type_url
        )));
    }
    
    // Parse as JSON
    let consensus_state_json = String::from_utf8(any.value)
        .map_err(|e| Error::Query(format!("Invalid UTF-8 in consensus state: {}", e)))?;
    
    let parsed: serde_json::Value = serde_json::from_str(&consensus_state_json)
        .map_err(|e| Error::Query(format!("Failed to parse consensus state JSON: {}", e)))?;
    
    // Extract fields from JSON
    let root_hex = parsed["root"]
        .as_str()
        .ok_or_else(|| Error::Query("Missing root in consensus state".to_string()))?;
    
    let root = hex::decode(root_hex)
        .map_err(|e| Error::Query(format!("Invalid root hex: {}", e)))?;
    
    let timestamp_u64 = parsed["timestamp"]
        .as_u64()
        .ok_or_else(|| Error::Query("Missing timestamp in consensus state".to_string()))?;
    
    let timestamp = timestamp_u64 as i64;
    
    let slot = parsed["slot"]
        .as_u64()
        .ok_or_else(|| Error::Query("Missing slot in consensus state".to_string()))?;
    
    let epoch = parsed["epoch"]
        .as_u64()
        .ok_or_else(|| Error::Query("Missing epoch in consensus state".to_string()))?;
    
    Ok(CardanoConsensusState::new(root, timestamp, slot, epoch))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_client_state_from_any() {
        let json = r#"{
            "chain_id": "cardano-testnet",
            "latest_height": {
                "revision_number": 0,
                "revision_height": 1000
            },
            "trusting_period": 86400,
            "unbonding_period": 1814400,
            "mithril_genesis_vkey": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        }"#;
        
        let any = prost_types::Any {
            type_url: CARDANO_CLIENT_STATE_TYPE_URL.to_string(),
            value: json.as_bytes().to_vec(),
        };
        
        let client_state = parse_client_state_from_any(any).unwrap();
        assert_eq!(client_state.chain_id, "cardano-testnet");
        assert_eq!(client_state.latest_height.revision_height(), 1000);
    }
    
    #[test]
    fn test_parse_consensus_state_from_any() {
        let json = r#"{
            "root": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "timestamp": 1234567890,
            "slot": 12345,
            "epoch": 100
        }"#;
        
        let any = prost_types::Any {
            type_url: CARDANO_CONSENSUS_STATE_TYPE_URL.to_string(),
            value: json.as_bytes().to_vec(),
        };
        
        let consensus_state = parse_consensus_state_from_any(any).unwrap();
        assert_eq!(consensus_state.timestamp, 1234567890);
        assert_eq!(consensus_state.slot, 12345);
        assert_eq!(consensus_state.epoch, 100);
    }
}

