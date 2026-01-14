//! Configuration for Cardano chain

use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

use crate::config::PacketFilter;
use crate::keyring::Store;

/// Minimal configuration for Cardano chain integration
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardanoConfig {
    /// The chain's network identifier
    pub id: ChainId,

    /// Gateway gRPC endpoint URL
    pub gateway_url: String,

    /// Network ID (1 = mainnet, 0 = testnet)
    pub network_id: u8,

    /// Key name for signing
    pub key_name: String,

    /// Keystore type (test, file, etc.)
    #[serde(default)]
    pub key_store_type: Store,

    /// Optional path to keystore folder
    pub key_store_folder: Option<PathBuf>,

    /// Account index for CIP-1852 derivation
    #[serde(default)]
    pub account: u32,

    /// Maximum block time (for timeout calculations)
    #[serde(default = "default_max_block_time", with = "humantime_serde")]
    pub max_block_time: Duration,

    /// Packet filter configuration
    #[serde(default)]
    pub packet_filter: PacketFilter,

    /// Optional trust threshold (not used by Cardano but required by config interface)
    #[serde(default)]
    pub trust_threshold: Option<ibc_relayer_types::core::ics02_client::trust_threshold::TrustThreshold>,

    /// How many packets to fetch at once from the chain when clearing packets
    #[serde(default = "default_query_packets_chunk_size")]
    pub query_packets_chunk_size: usize,

    /// Optional clear interval
    pub clear_interval: Option<u64>,

    /// Clock drift tolerance
    #[serde(default = "default_clock_drift", with = "humantime_serde")]
    pub clock_drift: Duration,

    /// Event polling interval for monitoring IBC events
    #[serde(default = "default_event_poll_interval", with = "humantime_serde")]
    pub event_poll_interval: Option<Duration>,
}

fn default_max_block_time() -> Duration {
    Duration::from_secs(30)
}

fn default_query_packets_chunk_size() -> usize {
    50
}

fn default_clock_drift() -> Duration {
    Duration::from_secs(5)
}

fn default_event_poll_interval() -> Option<Duration> {
    Some(Duration::from_secs(5))
}

impl Default for CardanoConfig {
    fn default() -> Self {
        Self {
            id: ChainId::from_string("cardano-test"),
            gateway_url: "http://localhost:3001".to_string(),
            network_id: 0,
            key_name: "default".to_string(),
            key_store_type: Store::Test,
            key_store_folder: None,
            account: 0,
            max_block_time: default_max_block_time(),
            packet_filter: PacketFilter::default(),
            trust_threshold: None,
            query_packets_chunk_size: default_query_packets_chunk_size(),
            clear_interval: None,
            clock_drift: default_clock_drift(),
            event_poll_interval: default_event_poll_interval(),
        }
    }
}
