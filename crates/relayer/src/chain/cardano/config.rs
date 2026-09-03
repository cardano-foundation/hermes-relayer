//! Configuration for Cardano chain

use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::{default, PacketFilter, RefreshRate};
use crate::keyring::Store;

/// Minimal configuration for Cardano chain integration
#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardanoConfig {
    /// The chain's network identifier
    pub id: ChainId,

    /// Gateway gRPC endpoint URL
    pub gateway_url: String,

    /// Optional PEM-encoded CA certificate used to authenticate the primary Gateway.
    /// Native trust roots are always used for HTTPS endpoints; this file adds a private CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_tls_ca_file: Option<PathBuf>,

    /// Optional file containing the bearer token sent to the primary Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_auth_token_file: Option<PathBuf>,

    /// Operator-pinned bridge manifest used to authorize Gateway-built transactions.
    /// This must be a trusted local file, not a manifest fetched from the Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_manifest_path: Option<PathBuf>,

    /// Trusted Kupo endpoint used to independently resolve every input before signing.
    /// This trust path must be independent from `gateway_url`. Plaintext HTTP is
    /// accepted only for loopback endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_utxo_kupo_url: Option<String>,

    /// Optional PEM-encoded CA certificate used to authenticate the signing Kupo endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_utxo_kupo_tls_ca_file: Option<PathBuf>,

    /// Optional file containing the API key sent in Kupo's `dmtr-api-key` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_utxo_kupo_api_key_file: Option<PathBuf>,

    /// Trusted Ogmios HTTP endpoint used to evaluate the exact unsigned transaction
    /// before signing. This trust path must be independent from `gateway_url`.
    /// Plaintext HTTP is accepted only for loopback endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_ogmios_url: Option<String>,

    /// Optional PEM-encoded CA certificate used to authenticate signing Ogmios.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_ogmios_tls_ca_file: Option<PathBuf>,

    /// Optional file containing the API key sent in Ogmios's `dmtr-api-key` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_ogmios_api_key_file: Option<PathBuf>,

    /// Maximum transaction fee Hermes will authorize, in lovelace.
    #[serde(default = "default_max_tx_fee_lovelace")]
    pub max_tx_fee_lovelace: u64,

    /// Maximum collateral at risk in a script transaction, in lovelace.
    #[serde(default = "default_max_total_collateral_lovelace")]
    pub max_total_collateral_lovelace: u64,

    /// Maximum encoded unsigned transaction size Hermes will authorize.
    #[serde(default = "default_max_tx_size_bytes")]
    pub max_tx_size_bytes: usize,

    /// Maximum min-ADA carried alongside an authorized external native asset.
    #[serde(default = "default_max_external_output_lovelace")]
    pub max_external_output_lovelace: u64,

    /// Maximum aggregate lovelace in non-escrow protocol outputs of one transaction.
    #[serde(default = "default_max_total_protocol_output_lovelace")]
    pub max_total_protocol_output_lovelace: u64,

    /// Maximum lovelace the signer may contribute to protocol/external min-ADA,
    /// beyond the exact fee and any requested outbound lovelace transfer.
    #[serde(default = "default_max_wallet_lovelace_top_up")]
    pub max_wallet_lovelace_top_up: u64,

    /// Maximum validity interval width when the transaction includes both bounds.
    #[serde(default = "default_max_validity_interval_slots")]
    pub max_validity_interval_slots: u64,

    /// Optional independent Gateway endpoint used to fetch witness headers for misbehaviour checks.
    pub misbehaviour_witness_gateway_url: Option<String>,

    /// Optional PEM-encoded CA certificate used to authenticate the witness Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub misbehaviour_witness_gateway_tls_ca_file: Option<PathBuf>,

    /// Optional file containing the bearer token sent to the witness Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub misbehaviour_witness_gateway_auth_token_file: Option<PathBuf>,

    /// Require Cardano update-client events to include the submitted header before checking misbehaviour.
    #[serde(default)]
    pub require_update_event_headers_for_misbehaviour: bool,

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
    pub trust_threshold:
        Option<ibc_relayer_types::core::ics02_client::trust_threshold::TrustThreshold>,

    /// How many packets to fetch at once from the chain when clearing packets
    #[serde(default = "default_query_packets_chunk_size")]
    pub query_packets_chunk_size: usize,

    /// Optional clear interval
    pub clear_interval: Option<u64>,

    /// Clock drift tolerance
    #[serde(default = "default_clock_drift", with = "humantime_serde")]
    pub clock_drift: Duration,

    /// The rate at which to refresh the client referencing this chain,
    /// expressed as a fraction of the trusting period.
    #[serde(default = "default::client_refresh_rate")]
    pub client_refresh_rate: RefreshRate,

    /// Event polling interval for monitoring IBC events
    #[serde(default = "default_event_poll_interval", with = "humantime_serde")]
    pub event_poll_interval: Option<Duration>,

    /// Number of recent Cardano blocks to replay from the Gateway event stream on startup.
    ///
    /// This may duplicate already-observed events after a restart. Set to 0 to preserve
    /// the previous behavior of starting from the latest Gateway height.
    #[serde(default = "default_event_replay_window")]
    pub event_replay_window: u64,

    /// How often Hermes checks whether the current Cardano epoch is missing a
    /// HostState anchor. `None` disables proactive heartbeats. The Gateway is
    /// authoritative about whether a heartbeat is required, so polling never
    /// creates more than one successful heartbeat per epoch.
    #[serde(default, with = "humantime_serde")]
    pub host_state_heartbeat_interval: Option<Duration>,

    /// Maximum amount of time Hermes will wait after a Cardano transaction is included
    /// until it is also "Mithril-certified".
    ///
    /// Important nuance about "height":
    /// In this Cardano↔Cosmos integration, `Height.revision_height` is treated as a Cardano
    /// *block number* (as surfaced by `db-sync` and by Mithril's `cardano-transactions`
    /// snapshots). It is not a Cardano *slot number*.
    ///
    /// When Hermes submits a transaction on Cardano, the Gateway returns the inclusion
    /// block number. Hermes then waits until the Gateway reports a Mithril snapshot
    /// whose `block_number` is >= that inclusion block number, before proceeding to the
    /// next IBC step. Without this, Hermes can race ahead and build proofs at a height
    /// that the Cosmos-side Mithril light client cannot yet verify.
    #[serde(
        default = "default_mithril_certification_timeout",
        with = "humantime_serde"
    )]
    pub mithril_certification_timeout: Duration,

    /// Polling interval while waiting for Mithril snapshots to catch up.
    #[serde(default = "default_mithril_poll_interval", with = "humantime_serde")]
    pub mithril_poll_interval: Duration,

    /// How often to log progress while waiting for Mithril snapshot catch-up.
    ///
    /// This is intentionally an `INFO`-level log, because in many environments the default
    /// log level is `info` (so `debug` would be invisible and the process would look hung).
    #[serde(
        default = "default_mithril_wait_log_interval",
        with = "humantime_serde"
    )]
    pub mithril_wait_log_interval: Duration,
}

const REDACTED_ENDPOINT: &str = "<redacted>";

impl fmt::Debug for CardanoConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_optional_endpoint =
            |endpoint: &Option<String>| endpoint.as_ref().map(|_| REDACTED_ENDPOINT);

        formatter
            .debug_struct("CardanoConfig")
            .field("id", &self.id)
            .field("gateway_url", &REDACTED_ENDPOINT)
            .field("gateway_tls_ca_file", &self.gateway_tls_ca_file)
            .field("gateway_auth_token_file", &self.gateway_auth_token_file)
            .field("bridge_manifest_path", &self.bridge_manifest_path)
            .field(
                "signing_utxo_kupo_url",
                &redacted_optional_endpoint(&self.signing_utxo_kupo_url),
            )
            .field(
                "signing_utxo_kupo_tls_ca_file",
                &self.signing_utxo_kupo_tls_ca_file,
            )
            .field(
                "signing_utxo_kupo_api_key_file",
                &self.signing_utxo_kupo_api_key_file,
            )
            .field(
                "signing_ogmios_url",
                &redacted_optional_endpoint(&self.signing_ogmios_url),
            )
            .field(
                "signing_ogmios_tls_ca_file",
                &self.signing_ogmios_tls_ca_file,
            )
            .field(
                "signing_ogmios_api_key_file",
                &self.signing_ogmios_api_key_file,
            )
            .field("max_tx_fee_lovelace", &self.max_tx_fee_lovelace)
            .field(
                "max_total_collateral_lovelace",
                &self.max_total_collateral_lovelace,
            )
            .field("max_tx_size_bytes", &self.max_tx_size_bytes)
            .field(
                "max_external_output_lovelace",
                &self.max_external_output_lovelace,
            )
            .field(
                "max_total_protocol_output_lovelace",
                &self.max_total_protocol_output_lovelace,
            )
            .field(
                "max_wallet_lovelace_top_up",
                &self.max_wallet_lovelace_top_up,
            )
            .field(
                "max_validity_interval_slots",
                &self.max_validity_interval_slots,
            )
            .field(
                "misbehaviour_witness_gateway_url",
                &redacted_optional_endpoint(&self.misbehaviour_witness_gateway_url),
            )
            .field(
                "misbehaviour_witness_gateway_tls_ca_file",
                &self.misbehaviour_witness_gateway_tls_ca_file,
            )
            .field(
                "misbehaviour_witness_gateway_auth_token_file",
                &self.misbehaviour_witness_gateway_auth_token_file,
            )
            .field(
                "require_update_event_headers_for_misbehaviour",
                &self.require_update_event_headers_for_misbehaviour,
            )
            .field("network_id", &self.network_id)
            .field("key_name", &self.key_name)
            .field("key_store_type", &self.key_store_type)
            .field("key_store_folder", &self.key_store_folder)
            .field("account", &self.account)
            .field("max_block_time", &self.max_block_time)
            .field("packet_filter", &self.packet_filter)
            .field("trust_threshold", &self.trust_threshold)
            .field("query_packets_chunk_size", &self.query_packets_chunk_size)
            .field("clear_interval", &self.clear_interval)
            .field("clock_drift", &self.clock_drift)
            .field("client_refresh_rate", &self.client_refresh_rate)
            .field("event_poll_interval", &self.event_poll_interval)
            .field("event_replay_window", &self.event_replay_window)
            .field(
                "host_state_heartbeat_interval",
                &self.host_state_heartbeat_interval,
            )
            .field(
                "mithril_certification_timeout",
                &self.mithril_certification_timeout,
            )
            .field("mithril_poll_interval", &self.mithril_poll_interval)
            .field("mithril_wait_log_interval", &self.mithril_wait_log_interval)
            .finish()
    }
}

fn default_max_block_time() -> Duration {
    Duration::from_secs(30)
}

fn default_max_tx_fee_lovelace() -> u64 {
    5_000_000
}

fn default_max_total_collateral_lovelace() -> u64 {
    10_000_000
}

fn default_max_tx_size_bytes() -> usize {
    64 * 1024
}

fn default_max_external_output_lovelace() -> u64 {
    5_000_000
}

fn default_max_total_protocol_output_lovelace() -> u64 {
    50_000_000
}

fn default_max_wallet_lovelace_top_up() -> u64 {
    5_000_000
}

fn default_max_validity_interval_slots() -> u64 {
    3_600
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

fn default_event_replay_window() -> u64 {
    100
}

fn default_mithril_certification_timeout() -> Duration {
    Duration::from_secs(10 * 60)
}

fn default_mithril_poll_interval() -> Duration {
    Duration::from_secs(5)
}

fn default_mithril_wait_log_interval() -> Duration {
    Duration::from_secs(30)
}

impl Default for CardanoConfig {
    fn default() -> Self {
        Self {
            id: ChainId::from_string("cardano-test"),
            gateway_url: "http://localhost:5001".to_string(),
            gateway_tls_ca_file: None,
            gateway_auth_token_file: None,
            bridge_manifest_path: None,
            signing_utxo_kupo_url: None,
            signing_utxo_kupo_tls_ca_file: None,
            signing_utxo_kupo_api_key_file: None,
            signing_ogmios_url: None,
            signing_ogmios_tls_ca_file: None,
            signing_ogmios_api_key_file: None,
            max_tx_fee_lovelace: default_max_tx_fee_lovelace(),
            max_total_collateral_lovelace: default_max_total_collateral_lovelace(),
            max_tx_size_bytes: default_max_tx_size_bytes(),
            max_external_output_lovelace: default_max_external_output_lovelace(),
            max_total_protocol_output_lovelace: default_max_total_protocol_output_lovelace(),
            max_wallet_lovelace_top_up: default_max_wallet_lovelace_top_up(),
            max_validity_interval_slots: default_max_validity_interval_slots(),
            misbehaviour_witness_gateway_url: None,
            misbehaviour_witness_gateway_tls_ca_file: None,
            misbehaviour_witness_gateway_auth_token_file: None,
            require_update_event_headers_for_misbehaviour: false,
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
            client_refresh_rate: default::client_refresh_rate(),
            event_poll_interval: default_event_poll_interval(),
            event_replay_window: default_event_replay_window(),
            host_state_heartbeat_interval: None,
            mithril_certification_timeout: default_mithril_certification_timeout(),
            mithril_poll_interval: default_mithril_poll_interval(),
            mithril_wait_log_interval: default_mithril_wait_log_interval(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CardanoConfig;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn gateway_security_defaults_preserve_local_development() {
        let config = CardanoConfig::default();

        assert_eq!(config.gateway_url, "http://localhost:5001");
        assert_eq!(config.gateway_tls_ca_file, None);
        assert_eq!(config.gateway_auth_token_file, None);
        assert_eq!(config.signing_utxo_kupo_url, None);
        assert_eq!(config.signing_utxo_kupo_tls_ca_file, None);
        assert_eq!(config.signing_utxo_kupo_api_key_file, None);
        assert_eq!(config.signing_ogmios_url, None);
        assert_eq!(config.signing_ogmios_tls_ca_file, None);
        assert_eq!(config.signing_ogmios_api_key_file, None);
        assert_eq!(config.misbehaviour_witness_gateway_tls_ca_file, None);
        assert_eq!(config.misbehaviour_witness_gateway_auth_token_file, None);

        let encoded = toml::to_string(&config).expect("Cardano config should serialize");
        assert!(!encoded.contains("gateway_tls_ca_file"));
        assert!(!encoded.contains("gateway_auth_token_file"));
        assert!(!encoded.contains("signing_utxo_kupo_url"));
        assert!(!encoded.contains("signing_ogmios_url"));

        let decoded: CardanoConfig =
            toml::from_str(&encoded).expect("legacy-compatible Cardano config should deserialize");
        assert_eq!(decoded, config);
    }

    #[test]
    fn gateway_security_files_round_trip() {
        let config = CardanoConfig {
            gateway_url: "https://gateway.example:5001".to_string(),
            gateway_tls_ca_file: Some(PathBuf::from("/run/secrets/gateway-ca.pem")),
            gateway_auth_token_file: Some(PathBuf::from("/run/secrets/gateway-token")),
            signing_utxo_kupo_url: Some("https://kupo.example".to_string()),
            signing_utxo_kupo_tls_ca_file: Some(PathBuf::from("/run/secrets/kupo-ca.pem")),
            signing_utxo_kupo_api_key_file: Some(PathBuf::from("/run/secrets/kupo-api-key")),
            signing_ogmios_url: Some("https://ogmios.example".to_string()),
            signing_ogmios_tls_ca_file: Some(PathBuf::from("/run/secrets/ogmios-ca.pem")),
            signing_ogmios_api_key_file: Some(PathBuf::from("/run/secrets/ogmios-api-key")),
            misbehaviour_witness_gateway_url: Some("https://witness.example:5001".to_string()),
            misbehaviour_witness_gateway_tls_ca_file: Some(PathBuf::from(
                "/run/secrets/witness-ca.pem",
            )),
            misbehaviour_witness_gateway_auth_token_file: Some(PathBuf::from(
                "/run/secrets/witness-token",
            )),
            ..CardanoConfig::default()
        };

        let encoded = toml::to_string(&config).expect("Cardano config should serialize");
        assert!(encoded.contains("signing_utxo_kupo_api_key_file"));
        assert!(!encoded.contains("signing_utxo_kupo_auth_token_file"));
        let decoded: CardanoConfig =
            toml::from_str(&encoded).expect("Cardano config should deserialize");

        assert_eq!(decoded, config);
    }

    #[test]
    fn debug_output_redacts_endpoint_credentials() {
        let secret = "credential-that-must-not-be-logged";
        let config = CardanoConfig {
            gateway_url: format!("https://{secret}@gateway.example:5001"),
            signing_utxo_kupo_url: Some(format!("https://{secret}.kupo.example")),
            signing_ogmios_url: Some(format!("https://{secret}.ogmios.example")),
            misbehaviour_witness_gateway_url: Some(format!(
                "https://{secret}@witness.example:5001"
            )),
            ..CardanoConfig::default()
        };

        let debug = format!("{config:?}");
        assert!(!debug.contains(secret));
        assert!(debug.contains("gateway_url: \"<redacted>\""));
        assert!(debug.contains("signing_ogmios_url: Some(\"<redacted>\")"));
        assert!(debug.contains("misbehaviour_witness_gateway_url: Some(\"<redacted>\")"));
    }

    #[test]
    fn default_event_replay_window_is_100_blocks() {
        assert_eq!(CardanoConfig::default().event_replay_window, 100);
    }

    #[test]
    fn host_state_heartbeat_is_opt_in() {
        assert_eq!(CardanoConfig::default().host_state_heartbeat_interval, None);
    }

    #[test]
    fn host_state_heartbeat_interval_round_trips_as_human_time() {
        let config = CardanoConfig {
            host_state_heartbeat_interval: Some(Duration::from_secs(60)),
            ..CardanoConfig::default()
        };

        let encoded = toml::to_string(&config).expect("Cardano config should serialize");
        let decoded: CardanoConfig =
            toml::from_str(&encoded).expect("Cardano config should deserialize");

        assert_eq!(
            decoded.host_state_heartbeat_interval,
            Some(Duration::from_secs(60))
        );
    }
}
