//! Stub implementations for From trait conversions to Any* types
//!
//! These are temporary stubs to satisfy trait bounds. The proper solution is to:
//! 1. Move Cardano types to ibc-relayer-types crate
//! 2. Add Cardano variants to AnyClientState and AnyConsensusState enums in ibc-relayer
//!
//! For now, these implementations will panic if called, as they're only needed
//! to satisfy the trait bounds in ChainEndpoint.

use crate::types::{CardanoClientState, CardanoConsensusState};
use ibc_relayer::client_state::AnyClientState;
use ibc_relayer::consensus_state::AnyConsensusState;

/// Stub implementation - will be replaced when Cardano is added to AnyClientState enum
impl From<CardanoClientState> for AnyClientState {
    fn from(_state: CardanoClientState) -> Self {
        // This is a stub implementation that should never be called in practice
        // The proper implementation requires adding a Cardano variant to AnyClientState
        panic!("CardanoClientState -> AnyClientState conversion not yet implemented. \
                This requires adding Cardano variant to AnyClientState enum in ibc-relayer crate.");
    }
}

/// Stub implementation - will be replaced when Cardano is added to AnyConsensusState enum
impl From<CardanoConsensusState> for AnyConsensusState {
    fn from(_state: CardanoConsensusState) -> Self {
        // This is a stub implementation that should never be called in practice
        // The proper implementation requires adding a Cardano variant to AnyConsensusState
        panic!("CardanoConsensusState -> AnyConsensusState conversion not yet implemented. \
                This requires adding Cardano variant to AnyConsensusState enum in ibc-relayer crate.");
    }
}

