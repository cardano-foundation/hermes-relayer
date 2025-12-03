//! Configuration for Cardano chain

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardanoChainConfig {
    /// Chain ID
    pub id: String,

    /// Gateway gRPC endpoint URL
    pub gateway_url: String,

    /// Network ID (1 = mainnet, 0 = testnet)
    pub network_id: u8,

    /// Key name for signing
    pub key_name: Option<String>,

    /// Account index for CIP-1852 derivation
    pub account: u32,
}

impl Default for CardanoChainConfig {
    fn default() -> Self {
        Self {
            id: "cardano-test".to_string(),
            gateway_url: "http://localhost:3001".to_string(),
            network_id: 0,
            key_name: None,
            account: 0,
        }
    }
}

