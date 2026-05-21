use serde_derive::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct Height {
    #[prost(uint64, tag = "1")]
    pub revision_number: u64,
    #[prost(uint64, tag = "2")]
    pub revision_height: u64,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct ScpEnvelope {
    #[prost(bytes = "vec", tag = "1")]
    pub node_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub statement_xdr: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct ClientState {
    #[prost(string, tag = "1")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub latest_height: ::core::option::Option<Height>,
    #[prost(message, optional, tag = "3")]
    pub frozen_height: ::core::option::Option<Height>,
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub trusted_validators: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub proof_specs: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
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

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct StellarHeader {
    #[prost(uint64, tag = "1")]
    pub ledger_seq: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub ledger_header_xdr: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub ibc_state_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag = "4")]
    pub scp_envelopes: ::prost::alloc::vec::Vec<ScpEnvelope>,
    #[prost(message, optional, tag = "5")]
    pub trusted_height: ::core::option::Option<Height>,
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
