//! Raw protobuf types for `ibc.lightclients.stability.v1`.

use serde_derive::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct Height {
    #[prost(uint64, tag = "1")]
    pub revision_number: u64,
    #[prost(uint64, tag = "2")]
    pub revision_height: u64,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct HeuristicParams {
    #[prost(uint64, tag = "4")]
    pub threshold_depth: u64,
    #[prost(uint64, tag = "5")]
    pub threshold_unique_pools: u64,
    #[prost(uint64, tag = "6")]
    pub threshold_unique_stake_bps: u64,
    #[prost(uint64, tag = "7")]
    pub depth_weight_bps: u64,
    #[prost(uint64, tag = "8")]
    pub pools_weight_bps: u64,
    #[prost(uint64, tag = "9")]
    pub stake_weight_bps: u64,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct StakeDistributionEntry {
    #[prost(string, tag = "1")]
    pub pool_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub stake: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub vrf_key_hash: ::prost::alloc::vec::Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct ClientState {
    #[prost(string, tag = "1")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub latest_height: ::core::option::Option<Height>,
    #[prost(message, optional, tag = "3")]
    pub frozen_height: ::core::option::Option<Height>,
    #[prost(uint64, tag = "4")]
    pub current_epoch: u64,
    #[prost(message, optional, tag = "5")]
    pub trusting_period: ::core::option::Option<ibc_proto::google::protobuf::Duration>,
    #[prost(message, optional, tag = "6")]
    pub heuristic_params: ::core::option::Option<HeuristicParams>,
    #[prost(string, repeated, tag = "7")]
    pub upgrade_path: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(bytes = "vec", tag = "8")]
    pub host_state_nft_policy_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub host_state_nft_token_name: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag = "10")]
    pub epoch_stake_distribution: ::prost::alloc::vec::Vec<StakeDistributionEntry>,
    #[prost(bytes = "vec", tag = "11")]
    pub epoch_nonce: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "12")]
    pub slots_per_kes_period: u64,
    #[prost(uint64, tag = "13")]
    pub current_epoch_start_slot: u64,
    #[prost(uint64, tag = "14")]
    pub current_epoch_end_slot_exclusive: u64,
    #[prost(uint64, tag = "15")]
    pub system_start_unix_ns: u64,
    #[prost(uint64, tag = "16")]
    pub slot_length_ns: u64,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct ConsensusState {
    #[prost(uint64, tag = "1")]
    pub timestamp: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub ibc_state_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag = "3")]
    pub accepted_block_hash: ::prost::alloc::string::String,
    #[prost(uint64, tag = "4")]
    pub accepted_epoch: u64,
    #[prost(uint64, tag = "5")]
    pub unique_pools_count: u64,
    #[prost(uint64, tag = "6")]
    pub unique_stake_bps: u64,
    #[prost(uint64, tag = "7")]
    pub security_score_bps: u64,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct StabilityBlock {
    #[prost(message, optional, tag = "1")]
    pub height: ::core::option::Option<Height>,
    #[prost(uint64, tag = "2")]
    pub slot: u64,
    #[prost(string, tag = "3")]
    pub hash: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub prev_hash: ::prost::alloc::string::String,
    #[prost(uint64, tag = "5")]
    pub epoch: u64,
    #[prost(uint64, tag = "6")]
    pub timestamp: u64,
    #[prost(string, tag = "7")]
    pub slot_leader: ::prost::alloc::string::String,
    #[prost(uint64, tag = "8")]
    pub stake_bps: u64,
    #[prost(bytes = "vec", tag = "9")]
    pub block_cbor: ::prost::alloc::vec::Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct StabilityHeader {
    #[prost(message, optional, tag = "1")]
    pub trusted_height: ::core::option::Option<Height>,
    #[prost(message, optional, tag = "2")]
    pub anchor_block: ::core::option::Option<StabilityBlock>,
    #[prost(message, repeated, tag = "3")]
    pub descendant_blocks: ::prost::alloc::vec::Vec<StabilityBlock>,
    #[prost(string, tag = "4")]
    pub host_state_tx_hash: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "5")]
    pub host_state_tx_body_cbor: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "6")]
    pub host_state_tx_output_index: u32,
    #[prost(uint64, tag = "7")]
    pub unique_pools_count: u64,
    #[prost(uint64, tag = "8")]
    pub unique_stake_bps: u64,
    #[prost(uint64, tag = "9")]
    pub security_score_bps: u64,
    #[prost(message, repeated, tag = "10")]
    pub bridge_blocks: ::prost::alloc::vec::Vec<StabilityBlock>,
}
