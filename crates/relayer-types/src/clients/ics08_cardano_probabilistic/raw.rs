//! Raw protobuf types for `ibc.lightclients.probabilistic.v1`.

use serde_derive::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct Height {
    #[prost(uint64, tag = "1")]
    pub revision_number: u64,
    #[prost(uint64, tag = "2")]
    pub revision_height: u64,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct StakeDistributionEntry {
    #[prost(string, tag = "1")]
    pub pool_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub stake: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub vrf_key_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub first_registration_slot: u64,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct EpochContext {
    #[prost(uint64, tag = "1")]
    pub epoch: u64,
    #[prost(message, repeated, tag = "2")]
    pub stake_distribution: ::prost::alloc::vec::Vec<StakeDistributionEntry>,
    #[prost(bytes = "vec", tag = "3")]
    pub epoch_nonce: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub slots_per_kes_period: u64,
    #[prost(uint64, tag = "5")]
    pub epoch_start_slot: u64,
    #[prost(uint64, tag = "6")]
    pub epoch_end_slot_exclusive: u64,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct OperationalCertificateCounter {
    #[prost(bytes = "vec", tag = "1")]
    pub pool_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub sequence_number: u64,
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
    #[prost(message, repeated, tag = "17")]
    pub epoch_contexts: ::prost::alloc::vec::Vec<EpochContext>,
    // Tag 18 (`pool_registration_cutoff_slot_exclusive`) is reserved by the
    // canonical schema and must not be reused.
    #[prost(message, optional, tag = "19")]
    pub latest_checkpoint_height: ::core::option::Option<Height>,
    #[prost(string, tag = "20")]
    pub latest_checkpoint_block_hash: ::prost::alloc::string::String,
    #[prost(uint64, tag = "21")]
    pub latest_checkpoint_epoch: u64,
    #[prost(uint64, tag = "22")]
    pub max_kes_evolutions: u64,
    #[prost(message, repeated, tag = "23")]
    pub latest_checkpoint_operational_certificate_counters:
        ::prost::alloc::vec::Vec<OperationalCertificateCounter>,
    #[prost(message, optional, tag = "24")]
    pub operational_certificate_counter_history_start_height: ::core::option::Option<Height>,
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
pub struct Misbehaviour {
    #[prost(string, tag = "1")]
    pub client_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub probabilistic_header_1: ::core::option::Option<ProbabilisticHeader>,
    #[prost(message, optional, tag = "3")]
    pub probabilistic_header_2: ::core::option::Option<ProbabilisticHeader>,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct ProbabilisticBlock {
    #[prost(message, optional, tag = "1")]
    pub height: ::core::option::Option<Height>,
    #[prost(uint64, tag = "2")]
    pub slot: u64,
    #[prost(string, tag = "3")]
    pub hash: ::prost::alloc::string::String,
    #[prost(uint64, tag = "5")]
    pub epoch: u64,
    #[prost(uint64, tag = "6")]
    pub timestamp: u64,
    #[prost(bytes = "vec", tag = "9")]
    pub block_cbor: ::prost::alloc::vec::Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message, Serialize, Deserialize)]
pub struct ProbabilisticHeader {
    #[prost(message, optional, tag = "1")]
    pub trusted_height: ::core::option::Option<Height>,
    #[prost(message, optional, tag = "2")]
    pub anchor_block: ::core::option::Option<ProbabilisticBlock>,
    #[prost(message, repeated, tag = "3")]
    pub descendant_blocks: ::prost::alloc::vec::Vec<ProbabilisticBlock>,
    #[prost(string, tag = "4")]
    pub host_state_tx_hash: ::prost::alloc::string::String,
    #[prost(uint32, tag = "6")]
    pub host_state_tx_output_index: u32,
    #[prost(message, repeated, tag = "10")]
    pub bridge_blocks: ::prost::alloc::vec::Vec<ProbabilisticBlock>,
    #[prost(message, optional, tag = "11")]
    pub new_epoch_context: ::core::option::Option<EpochContext>,
    #[prost(bool, tag = "12")]
    pub is_checkpoint: bool,
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::{ClientState, OperationalCertificateCounter};

    fn counter() -> OperationalCertificateCounter {
        OperationalCertificateCounter {
            pool_id: vec![0xabu8; 28],
            sequence_number: 7,
        }
    }

    #[test]
    fn client_operational_certificate_fields_use_canonical_wire_tags() {
        let encoded = ClientState {
            max_kes_evolutions: 62,
            latest_checkpoint_operational_certificate_counters: vec![counter()],
            operational_certificate_counter_history_start_height: Some(super::Height {
                revision_number: 0,
                revision_height: 10,
            }),
            ..Default::default()
        }
        .encode_to_vec();

        let mut expected = vec![0xb0, 0x01, 62, 0xba, 0x01, 32, 0x0a, 28];
        expected.extend([0xabu8; 28]);
        expected.extend([0x10, 7, 0xc2, 0x01, 2, 0x10, 10]);

        assert_eq!(encoded, expected);
    }
}
