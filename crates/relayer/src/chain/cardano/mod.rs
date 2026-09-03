//! Cardano chain implementation for Hermes IBC relayer
//!
//! This module provides complete Cardano integration following the same pattern
//! as Cosmos and Penumbra implementations in Hermes.

pub mod chain_handle;
pub(crate) mod checkpoint;
pub mod config;
pub mod endpoint;
pub mod error;
pub mod event_parser;
pub mod event_source;
pub mod gateway_client;
pub mod generated;
pub mod keyring;
pub mod signer;
pub mod signing_key_pair;
pub mod signing_policy;
pub mod transaction_evaluator;
pub mod utxo_resolver;

// Re-export key types for convenience
pub use config::CardanoConfig;
pub use endpoint::CardanoChainEndpoint;
pub use error::Error as CardanoError;
pub use gateway_client::GatewayClient;
pub use keyring::CardanoKeyring;
pub use signing_key_pair::CardanoSigningKeyPair;
pub use transaction_evaluator::{EvaluatedRedeemer, OgmiosTransactionEvaluator, RedeemerPurpose};
pub use utxo_resolver::{
    KupoInputResolver, ResolvedAsset, ResolvedInput, ResolvedTransactionInputs, TransactionOutRef,
};

// Type alias matching Cosmos/Penumbra pattern
pub type CardanoChain = CardanoChainEndpoint;
