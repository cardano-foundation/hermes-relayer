//! Cardano consensus state for IBC

use serde::{Deserialize, Serialize};

/// Cardano IBC consensus state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardanoConsensusState {
    /// Block hash (commitment root)
    pub root: Vec<u8>,
    
    /// Timestamp (Unix time in seconds)
    pub timestamp: i64,
    
    /// Slot number
    pub slot: u64,
    
    /// Epoch number
    pub epoch: u64,
    
    /// Mithril aggregate signature
    pub mithril_signature: Option<Vec<u8>>,
}

impl CardanoConsensusState {
    pub fn new(root: Vec<u8>, timestamp: i64, slot: u64, epoch: u64) -> Self {
        Self {
            root,
            timestamp,
            slot,
            epoch,
            mithril_signature: None,
        }
    }
    
    pub fn with_mithril_signature(mut self, sig: Vec<u8>) -> Self {
        self.mithril_signature = Some(sig);
        self
    }
}

