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
    #[serde(with = "humantime_serde")]
    pub max_block_time: Duration,
    pub packet_filter: PacketFilter,
    pub trust_threshold: TrustThreshold,
    pub clear_interval: Option<u64>,
    pub query_packets_chunk_size: usize,
    #[serde(with = "humantime_serde")]
    pub clock_drift: Duration,
    pub client_refresh_rate: RefreshRate,
    /// How long a consensus state stays trustworthy.
    ///
    /// Nothing to do with block time: the risk it bounds is the Stellar
    /// validator set rotating out from under a client that has no way to learn
    /// about it. Days, not seconds. Zero disables expiry entirely, which is
    /// only appropriate for a devnet.
    #[serde(default, with = "humantime_serde")]
    pub trusting_period: Option<Duration>,
    #[serde(default)]
    pub wasm_checksum_hex: Option<String>,
    /// `sha256(SCPQuorumSet XDR)` for every trust root this relayer will accept,
    /// hex-encoded.
    ///
    /// The quorum sets themselves arrive over the gateway, which is untrusted
    /// transport. Pinning their fingerprints here is what stops a compromised
    /// or merely misconfigured gateway from seeding a client with a validator
    /// set of its choosing — every proof would then verify happily against the
    /// wrong network.
    ///
    /// Client creation refuses to proceed when this is empty. Rotating the real
    /// tier-1 set is a deliberate, reviewable edit here.
    ///
    /// Mainnet's current tier-1 set fingerprints to
    /// `958e72b84e731d94ad1487953db489add23b67df1b1afab4d02bbadab0519294`
    /// (verified against ledger 63907880); testnet's must be obtained for the
    /// slot you create the client at.
    #[serde(default)]
    pub pinned_quorum_set_hashes: Vec<String>,
}
