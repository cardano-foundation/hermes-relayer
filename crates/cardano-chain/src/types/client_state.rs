//! Cardano client state for IBC

use ibc_relayer_types::core::ics02_client::client_state::ClientState;
use ibc_relayer_types::core::ics02_client::client_type::ClientType;
use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use ibc_relayer_types::Height;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Cardano IBC client state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardanoClientState {
    /// Chain ID
    pub chain_id: ChainId,
    
    /// Latest height
    pub latest_height: Height,
    
    /// Trusting period (in seconds)
    pub trusting_period: u64,
    
    /// Unbonding period (in seconds)
    pub unbonding_period: u64,
    
    /// Frozen height (if any)
    pub frozen_height: Option<Height>,
    
    /// Mithril genesis verification key
    pub mithril_genesis_vkey: Vec<u8>,
}

impl CardanoClientState {
    pub fn new(
        chain_id: String,
        latest_height: Height,
        trusting_period: u64,
        unbonding_period: u64,
        mithril_genesis_vkey: Vec<u8>,
    ) -> Self {
        Self {
            chain_id: ChainId::from_string(&chain_id),
            latest_height,
            trusting_period,
            unbonding_period,
            frozen_height: None,
            mithril_genesis_vkey,
        }
    }
}

impl ClientState for CardanoClientState {
    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn client_type(&self) -> ClientType {
        ClientType::Cardano
    }

    fn latest_height(&self) -> Height {
        self.latest_height
    }

    fn frozen_height(&self) -> Option<Height> {
        self.frozen_height
    }

    fn expired(&self, elapsed: Duration) -> bool {
        // Check if the client is expired based on the trusting period
        elapsed > Duration::from_secs(self.trusting_period)
    }
}

