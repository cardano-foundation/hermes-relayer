//! Cardano client state for IBC

use ibc_relayer_types::Height;
use serde::{Deserialize, Serialize};

/// Cardano IBC client state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardanoClientState {
    /// Chain ID
    pub chain_id: String,
    
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
            chain_id,
            latest_height,
            trusting_period,
            unbonding_period,
            frozen_height: None,
            mithril_genesis_vkey,
        }
    }
    
    pub fn is_frozen(&self) -> bool {
        self.frozen_height.is_some()
    }
}

