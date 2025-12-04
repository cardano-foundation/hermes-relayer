//! Cardano chain configuration
//!
//! This module only contains configuration types. The actual CardanoChainEndpoint
//! implementation lives in the ibc-cardano-chain crate to avoid circular dependencies.
//!
//! ## Architecture Note
//!
//! Due to Rust's module system, we cannot directly import CardanoChainEndpoint here because:
//! - ibc-cardano-chain depends on ibc-relayer (for traits, errors, etc.)
//! - ibc-relayer would depend on ibc-cardano-chain (to spawn chains)
//! - This creates a circular dependency
//!
//! ## Integration Options
//!
//! 1. **Standalone Binary**: Run ibc-cardano-chain as a separate process
//! 2. **Plugin System**: Future Hermes plugin architecture  
//! 3. **Workspace Binary**: Create a top-level binary that depends on both crates
//!
//! For now, Cardano chains must be integrated at the application level, not within
//! the ibc-relayer library itself.

pub mod config;

pub use config::CardanoConfig;

