//! Wire types for the Stellar light client.
//!
//! These mirror the prost structs in
//! `interstellar/contracts/cosmwasm/light-client/src/types.rs` **field number
//! for field number**. The contract decodes these bytes directly, so a
//! divergence is not a build error — protobuf will read one LEN field as
//! another and hand the contract garbage.
//!
//! Tag 4 on `ClientState` is the cautionary case: it used to be
//! `repeated bytes trusted_validators`, a flat validator list, and is now
//! `repeated QuorumConfig`. Same wire type, silently different meaning.

use serde_derive::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct Height {
    #[prost(uint64, tag = "1")]
    pub revision_number: u64,
    #[prost(uint64, tag = "2")]
    pub revision_height: u64,
}

/// A trust root that applies from `valid_from` onward, so the validator set can
/// rotate without invalidating headers for older slots.
#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct QuorumConfig {
    #[prost(bytes = "vec", tag = "1")]
    pub quorum_set_xdr: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub valid_from: u64,
}

/// Binds the router's SMT root to the ledger through `header.txSetResultHash`.
///
/// The whole result set travels because that field is a flat hash rather than a
/// Merkle root — there is no logarithmic proof. Splitting it per pair only lets
/// the client address one pair without decoding every classic operation result
/// type; the split itself is untrusted, since a wrong one cannot reproduce the
/// committed hash.
#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct StateRootProof {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub result_pairs: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint32, tag = "2")]
    pub result_index: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub success_preimage_xdr: ::prost::alloc::vec::Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct ClientState {
    #[prost(string, tag = "1")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub latest_height: ::core::option::Option<Height>,
    #[prost(message, optional, tag = "3")]
    pub frozen_height: ::core::option::Option<Height>,
    #[prost(message, repeated, tag = "4")]
    pub quorum_configs: ::prost::alloc::vec::Vec<QuorumConfig>,
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub proof_specs: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "6")]
    pub network_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "7")]
    pub max_consensus_age: u64,
    /// The router whose `ibc_root` event binds the state root.
    #[prost(bytes = "vec", tag = "8")]
    pub router_contract_id: ::prost::alloc::vec::Vec<u8>,
    /// The symbol that event is topic-tagged with.
    #[prost(bytes = "vec", tag = "9")]
    pub root_event_topic: ::prost::alloc::vec::Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct ConsensusState {
    #[prost(uint64, tag = "1")]
    pub timestamp: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub ledger_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub root: ::prost::alloc::vec::Vec<u8>,
}

/// Everything the light client needs to verify one Stellar ledger.
///
/// Every field is raw XDR passed through untouched: SCP signatures cover
/// original bytes, and a re-encode differing by one padding byte invalidates
/// every signature in the update.
#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct StellarHeader {
    #[prost(uint64, tag = "1")]
    pub slot_index: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub ledger_header_xdr: ::prost::alloc::vec::Vec<u8>,
    /// EXTERNALIZE envelopes for `slot_index`.
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub scp_envelopes: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// Preimages for every `commitQuorumSetHash` the envelopes reference.
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub quorum_sets_xdr: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// EXTERNALIZE envelopes for `slot_index + 1`, whose tx set binds the parts
    /// of the header SCP does not sign.
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub next_scp_envelopes: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "6")]
    pub next_tx_set_xdr: ::prost::alloc::vec::Vec<u8>,
    /// Optional: without it the header still verifies for consensus, but binds
    /// no state root and proves nothing about Soroban state.
    #[prost(message, optional, tag = "7")]
    pub state_root_proof: ::core::option::Option<StateRootProof>,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct Misbehaviour {
    #[prost(string, tag = "1")]
    pub client_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub header_1: ::core::option::Option<StellarHeader>,
    #[prost(message, optional, tag = "3")]
    pub header_2: ::core::option::Option<StellarHeader>,
}
