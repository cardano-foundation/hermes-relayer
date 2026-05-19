use std::time::Duration;

use ibc_relayer_types::core::{
    ics02_client::trust_threshold::TrustThreshold, ics24_host::identifier::ChainId,
};
use serde::{Deserialize, Serialize};

use crate::config::{PacketFilter, RefreshRate};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StellarConfig {
    pub id: ChainId,
    pub event_poll_interval: u32,
    pub event_replay_window: u32,
    pub gateway_url: String,
    pub network_passphrase: String,
    pub ibc_contract_id: String,
    pub key_name: String,
    pub stub_key_name: String,
    pub max_block_time: Duration,
    pub packet_filter: PacketFilter,
    pub trust_threshold: TrustThreshold,
    pub clear_interval: Option<u64>,
    pub query_packets_chunk_size: usize,
    pub clock_drift: Duration,
    pub client_refresh_rate: RefreshRate,
}
