#[derive(Clone)]
pub struct StellarConfig {
    pub event_poll_interval: u32,
    pub event_replay_window: u32,
    pub gateway_url: String,
    pub network_passphrase: String,
    pub ibc_contract_id: String,
}
