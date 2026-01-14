//! Cardano consensus state for IBC

use ibc_relayer_types::core::ics02_client::client_type::ClientType;
use ibc_relayer_types::core::ics02_client::consensus_state::ConsensusState;
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentRoot;
use ibc_relayer_types::timestamp::Timestamp;
use serde::{Deserialize, Serialize};

/// Cardano IBC consensus state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardanoConsensusState {
    /// Block hash (commitment root)
    pub root: CommitmentRoot,
    
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
            root: CommitmentRoot::from(root),
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

impl ConsensusState for CardanoConsensusState {
    fn client_type(&self) -> ClientType {
        ClientType::Cardano
    }

    fn root(&self) -> &CommitmentRoot {
        &self.root
    }

    fn timestamp(&self) -> Timestamp {
        let seconds = u64::try_from(self.timestamp).ok();
        let nanos = seconds.and_then(|s| s.checked_mul(1_000_000_000));

        nanos
            .and_then(|n| Timestamp::from_nanoseconds(n).ok())
            .unwrap_or_else(Timestamp::none)
    }
}
