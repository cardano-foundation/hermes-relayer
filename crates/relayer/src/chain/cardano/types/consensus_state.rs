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

impl ConsensusState for CardanoConsensusState {
    fn client_type(&self) -> ClientType {
        ClientType::Cardano
    }

    fn root(&self) -> &CommitmentRoot {
        // Create a commitment root from the block hash
        // For now, return a reference to a lazily created root
        // In production, this should be stored as a CommitmentRoot directly
        lazy_static::lazy_static! {
            static ref DEFAULT_ROOT: CommitmentRoot = CommitmentRoot::from_bytes(&[0u8; 32]);
        }
        &DEFAULT_ROOT
    }

    fn timestamp(&self) -> Timestamp {
        Timestamp::from_nanoseconds(self.timestamp as u64 * 1_000_000_000)
            .expect("Invalid timestamp")
    }
}

