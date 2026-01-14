//! Cardano header type for IBC light client

use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::header::Header as IbcHeader;
use crate::timestamp::Timestamp;
use crate::Height;
use serde::{Deserialize, Serialize};

pub const CARDANO_HEADER_TYPE_URL: &str = "/ibc.lightclients.cardano.v1.Header";

/// Cardano block header for IBC light client
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
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

impl Header {
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

impl IbcHeader for Header {
    fn client_type(&self) -> ClientType {
        ClientType::Cardano
    }

    fn height(&self) -> Height {
        self.height
    }

    fn timestamp(&self) -> Timestamp {
        let seconds = u64::try_from(self.timestamp).ok();
        let nanos = seconds.and_then(|s| s.checked_mul(1_000_000_000));

        nanos
            .and_then(|n| Timestamp::from_nanoseconds(n).ok())
            .unwrap_or_else(Timestamp::none)
    }
}
