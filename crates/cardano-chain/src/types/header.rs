//! Cardano header type for IBC

use ibc_relayer_types::Height;
use serde::{Deserialize, Serialize};

/// Cardano block header for IBC light client
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardanoHeader {
    /// Block height
    pub height: Height,
    
    /// Block hash
    pub block_hash: Vec<u8>,
    
    /// Timestamp (Unix time in seconds)
    pub timestamp: i64,
    
    /// Slot number
    pub slot: u64,
    
    /// Epoch number
    pub epoch: u64,
    
    /// Mithril certificate (optional)
    pub mithril_certificate: Option<Vec<u8>>,
}

impl CardanoHeader {
    pub fn new(height: Height, block_hash: Vec<u8>, timestamp: i64, slot: u64, epoch: u64) -> Self {
        Self {
            height,
            block_hash,
            timestamp,
            slot,
            epoch,
            mithril_certificate: None,
        }
    }
    
    pub fn with_mithril_certificate(mut self, cert: Vec<u8>) -> Self {
        self.mithril_certificate = Some(cert);
        self
    }
}

