//! Local authorization policy for Gateway-built Cardano transactions.
//!
//! The Gateway is a transaction builder, not a signing authority. The policy in
//! this module is derived from operator-pinned deployment data and the original
//! IBC message, so a compromised Gateway cannot choose what Hermes authorizes.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use bech32::FromBase32;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use pallas_codec::{minicbor, utils::Nullable};
use pallas_primitives::alonzo::{BigInt, PlutusData, Value as LegacyValue};
use pallas_primitives::conway::{
    MintedTransactionOutput, MintedTx, NetworkId, PseudoTransactionOutput, Value,
};
use prost::Message;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Sha3};

use super::error::Error;
use super::generated::ibc::cardano::v1::MsgPrunePacketHistory;
use super::generated::ibc::core::{
    channel::v1::{
        MsgAcknowledgement, MsgChannelCloseConfirm, MsgChannelCloseInit, MsgChannelOpenAck,
        MsgChannelOpenConfirm, MsgChannelOpenInit, MsgChannelOpenTry, MsgRecvPacket, MsgTimeout,
        MsgTimeoutOnClose,
    },
    client::v1::{MsgCreateClient, MsgRecoverClient, MsgUpdateClient},
    connection::v1::{
        MsgConnectionOpenAck, MsgConnectionOpenConfirm, MsgConnectionOpenInit, MsgConnectionOpenTry,
    },
};
use super::utxo_resolver::{ResolvedInput, ResolvedTransactionInputs, TransactionOutRef};
use ibc_relayer_types::clients::ics07_tendermint::{
    header::TENDERMINT_HEADER_TYPE_URL, misbehaviour::TENDERMINT_MISBEHAVIOR_TYPE_URL,
};

const LOVELACE: &str = "lovelace";
const LOVELACE_HEX: &str = "6c6f76656c616365";
const CIP67_FT_LABEL: [u8; 4] = [0x00, 0x14, 0xdf, 0x10];
const CIP67_REFERENCE_NFT_LABEL: [u8; 4] = [0x00, 0x06, 0x43, 0xb0];
const MAX_INPUTS: usize = 128;
const MAX_OUTPUTS: usize = 128;
const MAX_REFERENCE_INPUTS: usize = 128;
const MAX_COLLATERAL_INPUTS: usize = 3;
const MAX_TENDERMINT_SESSION_BATCH_SIZE: usize = 6;
const TENDERMINT_SESSION_TOKEN_NAME_BYTES: usize = 32;

/// Limits that bound the wallet value a transaction may put at risk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningPolicyLimits {
    pub max_fee_lovelace: u64,
    pub max_total_collateral_lovelace: u64,
    pub max_tx_size_bytes: usize,
    pub max_external_output_lovelace: u64,
    pub max_total_protocol_output_lovelace: u64,
    pub max_wallet_lovelace_top_up: u64,
    pub max_validity_interval_slots: u64,
}

type OutRef = (Vec<u8>, u64);
type ModuleRoots = (HashMap<String, ModuleRoot>, HashSet<Vec<u8>>);
type AssetTotals = BTreeMap<(Vec<u8>, Vec<u8>), u128>;

#[derive(Clone, Debug)]
struct ScriptRoot {
    hash: Vec<u8>,
    reference: OutRef,
}

#[derive(Clone, Debug)]
struct StateOutputRoot {
    address: Vec<u8>,
    policy: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ModuleRoot {
    address: Vec<u8>,
    identifier_policy: Vec<u8>,
    identifier_name: Vec<u8>,
    reference_script: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsensusHistoryFormat {
    Legacy,
    ProofBackedV1,
}

/// A policy loaded from an operator-pinned bridge manifest.
#[derive(Clone, Debug)]
pub struct TransactionSigningPolicy {
    network_id: u8,
    consensus_history_format: ConsensusHistoryFormat,
    limits: SigningPolicyLimits,
    protocol_addresses: HashSet<Vec<u8>>,
    scripts: HashMap<String, ScriptRoot>,
    host_state_address: Vec<u8>,
    host_state_nft_policy: Vec<u8>,
    host_state_nft_name: Vec<u8>,
    host_state_reference: OutRef,
    client_state: StateOutputRoot,
    connection_state: StateOutputRoot,
    channel_state: StateOutputRoot,
    modules: HashMap<String, ModuleRoot>,
    module_identity_policies: HashSet<Vec<u8>>,
    transfer_escrow_policy: Vec<u8>,
    trace_registry_address: Vec<u8>,
    trace_registry_policy: Vec<u8>,
    voucher_metadata_address: Vec<u8>,
    voucher_policy: Vec<u8>,
    tendermint_session: Option<StateOutputRoot>,
}

/// Authorization derived exclusively from the request Hermes intended to send.
#[derive(Clone, Debug)]
pub struct SigningIntent {
    operation: String,
    module_port: Option<String>,
    external_output: Option<ExternalOutputIntent>,
    transfer: Option<TransferIntent>,
    state_sequence: Option<u64>,
    recovery_substitute_sequence: Option<u64>,
    packet: Option<PacketIntent>,
    acknowledgement: Option<Vec<u8>>,
    prune_sequence: Option<u64>,
    staged_tendermint: bool,
    staged_misbehaviour: bool,
}

#[derive(Clone, Debug)]
struct ExternalOutputIntent {
    address: Vec<u8>,
    transfer: TransferIntent,
    required: bool,
}

#[derive(Clone, Debug)]
struct TransferIntent {
    denom: String,
    amount: u64,
    source_port: Option<String>,
    source_channel: Option<String>,
    destination_port: Option<String>,
    destination_channel: Option<String>,
    sender: String,
    receiver: String,
    memo: String,
    timeout_revision_number: u64,
    timeout_revision_height: u64,
    timeout_timestamp: u64,
    action: TransferAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PacketIntent {
    sequence: u64,
    source_port: String,
    source_channel: String,
    destination_port: String,
    destination_channel: String,
    data: Vec<u8>,
    timeout_revision_number: u64,
    timeout_revision_height: u64,
    timeout_timestamp: u64,
}

impl PacketIntent {
    fn from_packet(packet: &super::generated::ibc::core::channel::v1::Packet) -> Self {
        let (timeout_revision_number, timeout_revision_height) =
            packet.timeout_height.as_ref().map_or((0, 0), |height| {
                (height.revision_number, height.revision_height)
            });
        Self {
            sequence: packet.sequence,
            source_port: packet.source_port.clone(),
            source_channel: packet.source_channel.clone(),
            destination_port: packet.destination_port.clone(),
            destination_channel: packet.destination_channel.clone(),
            data: packet.data.clone(),
            timeout_revision_number,
            timeout_revision_height,
            timeout_timestamp: packet.timeout_timestamp,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransferAction {
    Receive,
    Refund,
    Send,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VoucherMintAction {
    Mint,
    Burn,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ics20PacketData {
    denom: String,
    amount: String,
    sender: String,
    receiver: String,
    #[serde(default)]
    memo: String,
}

#[derive(Debug)]
struct OutputValue {
    address: Vec<u8>,
    coin: u64,
    assets: Vec<(Vec<u8>, Vec<u8>, u64)>,
    has_script_ref: bool,
    has_inline_datum: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StateOutputKind {
    None,
    Client,
    Connection,
    Channel,
}

struct OperationRequirements<'a> {
    required_scripts: Vec<&'static str>,
    required_mint_scripts: Vec<&'static str>,
    state_output: StateOutputKind,
    module: Option<&'a ModuleRoot>,
    requires_host_state: bool,
    tendermint_session: Option<ValidatedTendermintSessionAction>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TendermintSessionAction {
    Initialize,
    Advance,
    Cancel,
    Finalize,
    FinalizeMisbehaviour,
}

impl TendermintSessionAction {
    pub(crate) fn is_finalization(self) -> bool {
        matches!(self, Self::Finalize | Self::FinalizeMisbehaviour)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTendermintSessionAction {
    pub(crate) action: TendermintSessionAction,
    pub(crate) token_name: Vec<u8>,
    pub(crate) second_token_name: Option<Vec<u8>>,
}

impl ValidatedTendermintSessionAction {
    fn token_names(&self) -> impl Iterator<Item = &[u8]> {
        std::iter::once(self.token_name.as_slice()).chain(self.second_token_name.as_deref())
    }
}

enum ChannelRedeemerIntent<'a> {
    Constructor(u64),
    ProofBackedClientUpdate,
    ClientRecovery {
        alternative: u64,
        substitute_policy: Vec<u8>,
        substitute_name: Vec<u8>,
        history_format: ConsensusHistoryFormat,
    },
    Packet {
        alternative: u64,
        packet: &'a PacketIntent,
        acknowledgement: Option<&'a [u8]>,
    },
    OutboundTransfer(&'a TransferIntent),
    Prune(u64),
}

impl ChannelRedeemerIntent<'_> {
    fn matches(&self, data: &PlutusData) -> bool {
        match self {
            Self::Constructor(alternative) => constructor_fields(data, *alternative).is_some(),
            // Check the versioned shape here; authenticated history and the
            // Tendermint message are verified by the pinned on-chain scripts.
            // The support withdrawal is separately bound to this exact client.
            Self::ProofBackedClientUpdate => constructor_fields(data, 0)
                .filter(|fields| fields.len() == 3)
                .is_some_and(|fields| {
                    matches!(&fields[1], PlutusData::Array(witnesses) if witnesses.len() <= 2)
                        && history_siblings_shape(&fields[2], true)
                }),
            Self::ClientRecovery {
                alternative,
                substitute_policy,
                substitute_name,
                history_format,
            } => constructor_fields(data, *alternative)
                .filter(|fields| match history_format {
                    ConsensusHistoryFormat::Legacy => fields.len() == 1,
                    ConsensusHistoryFormat::ProofBackedV1 => {
                        fields.len() == 2 && history_siblings_shape(&fields[1], false)
                    }
                })
                .and_then(|fields| fields.first())
                .is_some_and(|token| auth_token_matches(token, substitute_policy, substitute_name)),
            Self::Packet {
                alternative,
                packet,
                acknowledgement,
            } => {
                let Some(fields) = constructor_fields(data, *alternative) else {
                    return false;
                };
                if !fields
                    .first()
                    .is_some_and(|candidate| packet_plutus_matches(candidate, packet))
                {
                    return false;
                }
                acknowledgement.is_none_or(|expected| {
                    fields
                        .get(1)
                        .and_then(plutus_bytes)
                        .is_some_and(|actual| actual == expected)
                })
            }
            Self::OutboundTransfer(transfer) => constructor_fields(data, 5)
                .and_then(|fields| fields.first())
                .is_some_and(|packet| outbound_transfer_packet_matches(packet, transfer)),
            Self::Prune(sequence) => {
                constructor_fields(data, 8)
                    .and_then(|fields| fields.first())
                    .and_then(plutus_u64)
                    == Some(*sequence)
            }
        }
    }
}

impl TransactionSigningPolicy {
    pub fn load(path: &Path, network_id: u8, limits: SigningPolicyLimits) -> Result<Self, Error> {
        let contents = fs::read_to_string(path).map_err(|error| {
            Error::Config(format!(
                "failed to read pinned Cardano bridge manifest {}: {error}",
                path.display()
            ))
        })?;
        Self::from_json(&contents, network_id, limits).map_err(|error| {
            Error::Config(format!(
                "invalid pinned Cardano bridge manifest {}: {error}",
                path.display()
            ))
        })
    }

    pub(crate) fn from_json(
        contents: &str,
        network_id: u8,
        limits: SigningPolicyLimits,
    ) -> Result<Self, String> {
        if network_id > 15 {
            return Err(format!(
                "network_id {network_id} is outside Cardano's 0..=15 range"
            ));
        }
        if limits.max_fee_lovelace == 0
            || limits.max_total_collateral_lovelace == 0
            || limits.max_tx_size_bytes == 0
            || limits.max_external_output_lovelace == 0
            || limits.max_total_protocol_output_lovelace == 0
            || limits.max_wallet_lovelace_top_up == 0
            || limits.max_validity_interval_slots == 0
        {
            return Err("all transaction signing limits must be greater than zero".to_string());
        }

        let manifest: JsonValue =
            serde_json::from_str(contents).map_err(|error| error.to_string())?;
        // The operator-pinned format selects an ABI; transaction data must not
        // choose a weaker legacy authorization path for a proof-backed deployment.
        let consensus_history_format = match manifest.get("consensus_history_format") {
            None => ConsensusHistoryFormat::Legacy,
            Some(JsonValue::String(format)) if format == "proof-backed-v1" => {
                ConsensusHistoryFormat::ProofBackedV1
            }
            Some(_) => return Err("unsupported consensus_history_format".to_string()),
        };
        let validators = object_field(&manifest, &["validators"])
            .ok_or_else(|| "manifest has no validators object".to_string())?;
        let host_state = object_field(validators, &["host_state_stt", "hostStateStt"])
            .ok_or_else(|| "manifest has no HostState validator".to_string())?;
        let host_state_address = decode_address(
            required_string(host_state, &["address"], "HostState address")?,
            network_id,
        )?;
        let host_state_reference = parse_out_ref(
            object_field(host_state, &["ref_utxo", "refUtxo"])
                .ok_or_else(|| "HostState validator has no reference UTxO".to_string())?,
        )?;

        let host_state_nft = object_field(&manifest, &["host_state_nft", "hostStateNFT"])
            .ok_or_else(|| "manifest has no HostState NFT".to_string())?;
        let host_state_nft_policy = decode_fixed_hex(
            required_string(
                host_state_nft,
                &["policy_id", "policyId"],
                "HostState policy",
            )?,
            28,
            "HostState policy",
        )?;
        let host_state_nft_name = decode_hex(
            required_string(
                host_state_nft,
                &["token_name", "name"],
                "HostState token name",
            )?,
            "HostState token name",
        )?;

        let scripts = collect_validator_script_roots(validators)?;
        if consensus_history_format == ConsensusHistoryFormat::ProofBackedV1 {
            required_script(&scripts, "recoverclient")?;
        }
        let voucher_policy = required_script(&scripts, "mintvoucher")?.hash.clone();

        let client_state = StateOutputRoot {
            address: validator_address(validators, &["spend_client", "spendClient"], network_id)?,
            policy: required_script(&scripts, "mintclientstt")?.hash.clone(),
        };
        let connection_state = StateOutputRoot {
            address: validator_address(
                validators,
                &["spend_connection", "spendConnection"],
                network_id,
            )?,
            policy: required_script(&scripts, "mintconnectionstt")?.hash.clone(),
        };
        let channel_state = StateOutputRoot {
            address: validator_address(validators, &["spend_channel", "spendChannel"], network_id)?,
            policy: required_script(&scripts, "mintchannelstt")?.hash.clone(),
        };
        let transfer_escrow_policy = required_script(&scripts, "minttransferescrowshard")?
            .hash
            .clone();

        let (modules, mut module_identity_policies) = parse_module_roots(&manifest, network_id)?;
        if !modules.contains_key("transfer") {
            return Err("manifest has no transfer module".to_string());
        }
        module_identity_policies.insert(required_script(&scripts, "mintport")?.hash.clone());

        let trace_registry = object_field(&manifest, &["trace_registry", "traceRegistry"])
            .ok_or_else(|| "manifest has no trace registry".to_string())?;
        let trace_registry_address = decode_address(
            required_string(trace_registry, &["address"], "trace registry address")?,
            network_id,
        )?;
        let trace_registry_policy = decode_fixed_hex(
            required_string(
                trace_registry,
                &["shard_policy_id", "shardPolicyId"],
                "trace registry shard policy",
            )?,
            28,
            "trace registry shard policy",
        )?;
        let voucher_metadata_address = validator_address(
            validators,
            &["voucher_metadata", "voucherMetadata"],
            network_id,
        )?;
        let session_spend = object_field(
            validators,
            &[
                "spend_tendermint_update_session",
                "spendTendermintUpdateSession",
            ],
        );
        let session_mint = object_field(
            validators,
            &[
                "mint_tendermint_update_session",
                "mintTendermintUpdateSession",
            ],
        );
        let tendermint_session = match (session_spend, session_mint) {
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => {
                return Err(
                    "manifest must configure both staged Tendermint session validators".to_string(),
                )
            }
            (Some(spend), Some(_)) => Some(StateOutputRoot {
                address: decode_address(
                    required_string(spend, &["address"], "staged Tendermint session address")?,
                    network_id,
                )?,
                policy: required_script(&scripts, "minttendermintupdatesession")?
                    .hash
                    .clone(),
            }),
        };

        let mut protocol_addresses = HashSet::from([
            host_state_address.clone(),
            client_state.address.clone(),
            connection_state.address.clone(),
            channel_state.address.clone(),
            trace_registry_address.clone(),
            voucher_metadata_address.clone(),
        ]);
        protocol_addresses.extend(modules.values().map(|module| module.address.clone()));
        if let Some(session) = &tendermint_session {
            if protocol_addresses.contains(&session.address) {
                return Err(
                    "staged Tendermint session address overlaps another protocol role".to_string(),
                );
            }
            protocol_addresses.insert(session.address.clone());
        }

        Ok(Self {
            network_id,
            consensus_history_format,
            limits,
            protocol_addresses,
            scripts,
            host_state_address,
            host_state_nft_policy,
            host_state_nft_name,
            host_state_reference,
            client_state,
            connection_state,
            channel_state,
            modules,
            module_identity_policies,
            transfer_escrow_policy,
            trace_registry_address,
            trace_registry_policy,
            voucher_metadata_address,
            voucher_policy,
            tendermint_session,
        })
    }

    fn operation_requirements<'a>(
        &'a self,
        intent: &SigningIntent,
    ) -> Result<OperationRequirements<'a>, String> {
        let (mut required_scripts, required_mint_scripts, state_output, needs_module) =
            match intent.operation.as_str() {
                "HostStateHeartbeat" => (vec![], vec![], StateOutputKind::None, false),
                "TraceRegistryPrelude" => (
                    vec!["spendtraceregistry", "mintvoucher"],
                    vec![],
                    StateOutputKind::None,
                    false,
                ),
                "/ibc.core.client.v1.MsgCreateClient" => (
                    vec!["mintclientstt"],
                    vec!["mintclientstt"],
                    StateOutputKind::Client,
                    false,
                ),
                "/ibc.core.client.v1.MsgUpdateClient" => {
                    let scripts =
                        if self.consensus_history_format == ConsensusHistoryFormat::ProofBackedV1 {
                            vec!["spendclient", "recoverclient"]
                        } else {
                            vec!["spendclient"]
                        };
                    (scripts, vec![], StateOutputKind::Client, false)
                }
                "/ibc.core.client.v1.MsgRecoverClient" => (
                    vec!["spendclient", "recoverclient"],
                    vec![],
                    StateOutputKind::Client,
                    false,
                ),
                "/ibc.core.connection.v1.MsgConnectionOpenInit" => (
                    vec!["mintconnectionstt"],
                    vec!["mintconnectionstt"],
                    StateOutputKind::Connection,
                    false,
                ),
                "/ibc.core.connection.v1.MsgConnectionOpenTry" => (
                    vec!["mintconnectionstt", "verifyproof"],
                    vec!["mintconnectionstt", "verifyproof"],
                    StateOutputKind::Connection,
                    false,
                ),
                "/ibc.core.connection.v1.MsgConnectionOpenAck" => (
                    vec!["spendconnection", "verifyproof"],
                    vec!["verifyproof"],
                    StateOutputKind::Connection,
                    false,
                ),
                "/ibc.core.connection.v1.MsgConnectionOpenConfirm" => (
                    vec!["spendconnection", "verifyproof"],
                    vec!["verifyproof"],
                    StateOutputKind::Connection,
                    false,
                ),
                "/ibc.core.channel.v1.MsgChannelOpenInit" => (
                    vec!["mintchannelstt"],
                    vec!["mintchannelstt"],
                    StateOutputKind::Channel,
                    true,
                ),
                "/ibc.core.channel.v1.MsgChannelOpenTry" => (
                    vec!["mintchannelstt", "verifyproof"],
                    vec!["mintchannelstt", "verifyproof"],
                    StateOutputKind::Channel,
                    true,
                ),
                "/ibc.core.channel.v1.MsgChannelOpenAck" => (
                    vec!["spendchannel", "chanopenack", "verifyproof"],
                    vec!["chanopenack", "verifyproof"],
                    StateOutputKind::Channel,
                    true,
                ),
                "/ibc.core.channel.v1.MsgChannelOpenConfirm" => (
                    vec!["spendchannel", "chanopenconfirm", "verifyproof"],
                    vec!["chanopenconfirm", "verifyproof"],
                    StateOutputKind::Channel,
                    true,
                ),
                "/ibc.core.channel.v1.MsgChannelCloseInit" => (
                    vec!["spendchannel", "chancloseinit"],
                    vec!["chancloseinit"],
                    StateOutputKind::Channel,
                    true,
                ),
                "/ibc.core.channel.v1.MsgChannelCloseConfirm" => (
                    vec!["spendchannel", "chancloseconfirm", "verifyproof"],
                    vec!["chancloseconfirm", "verifyproof"],
                    StateOutputKind::Channel,
                    true,
                ),
                "/ibc.core.channel.v1.MsgRecvPacket" => (
                    vec!["spendchannel", "recvpacket", "verifyproof"],
                    vec!["recvpacket", "verifyproof"],
                    StateOutputKind::Channel,
                    true,
                ),
                "/ibc.core.channel.v1.MsgAcknowledgement" => (
                    vec!["spendchannel", "acknowledgepacket", "verifyproof"],
                    vec!["acknowledgepacket", "verifyproof"],
                    StateOutputKind::Channel,
                    true,
                ),
                "/ibc.core.channel.v1.MsgTimeout" | "/ibc.core.channel.v1.MsgTimeoutOnClose" => (
                    vec!["spendchannel", "timeoutpacket", "verifyproof"],
                    vec!["timeoutpacket", "verifyproof"],
                    StateOutputKind::Channel,
                    true,
                ),
                "/ibc.applications.transfer.v1.MsgTransfer" => (
                    vec!["spendchannel", "sendpacket"],
                    vec!["sendpacket"],
                    StateOutputKind::Channel,
                    true,
                ),
                "/ibc.cardano.v1.MsgPrunePacketHistory" => (
                    vec!["spendchannel", "prunepackethistory", "verifyproof"],
                    vec!["prunepackethistory", "verifyproof"],
                    StateOutputKind::Channel,
                    false,
                ),
                operation => return Err(format!("unsupported signing operation {operation}")),
            };

        let module = if needs_module {
            let port = intent
                .module_port
                .as_deref()
                .ok_or_else(|| format!("{} has no local IBC module port", intent.operation))?;
            let key = module_key_for_port(port)?;
            let module = self
                .modules
                .get(key)
                .ok_or_else(|| format!("pinned manifest has no module for port {port}"))?;
            required_scripts.push(module.reference_script);
            Some(module)
        } else {
            None
        };

        Ok(OperationRequirements {
            required_scripts,
            required_mint_scripts,
            state_output,
            module,
            requires_host_state: true,
            tendermint_session: None,
        })
    }

    fn staged_tendermint_requirements<'a>(
        &'a self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        intent: &SigningIntent,
        resolved_inputs: &ResolvedTransactionInputs,
    ) -> Result<OperationRequirements<'a>, String> {
        if intent.operation != "/ibc.core.client.v1.MsgUpdateClient" {
            return Err("staged Tendermint intent is not an MsgUpdateClient".to_string());
        }
        let session = self.tendermint_session.as_ref().ok_or_else(|| {
            "pinned manifest has no staged Tendermint session validators".to_string()
        })?;
        let requirement = classify_tendermint_session_transaction(
            body,
            resolved_inputs,
            session,
            &self.host_state_address,
            &self.client_state.address,
        )?;
        if requirement.action.is_finalization()
            && (requirement.action == TendermintSessionAction::FinalizeMisbehaviour)
                != intent.staged_misbehaviour
        {
            return Err(
                "staged finalization does not match the requested header or misbehaviour"
                    .to_string(),
            );
        }
        let (mut required_scripts, required_mint_scripts, state_output, requires_host_state) =
            match requirement.action {
                TendermintSessionAction::Initialize => (
                    vec!["minttendermintupdatesession"],
                    vec!["minttendermintupdatesession"],
                    StateOutputKind::None,
                    false,
                ),
                TendermintSessionAction::Advance => (
                    vec!["spendtendermintupdatesession"],
                    vec![],
                    StateOutputKind::None,
                    false,
                ),
                TendermintSessionAction::Cancel => (
                    vec![
                        "spendtendermintupdatesession",
                        "minttendermintupdatesession",
                    ],
                    vec!["minttendermintupdatesession"],
                    StateOutputKind::None,
                    false,
                ),
                TendermintSessionAction::Finalize
                | TendermintSessionAction::FinalizeMisbehaviour => (
                    vec![
                        "spendclient",
                        "spendtendermintupdatesession",
                        "minttendermintupdatesession",
                    ],
                    vec!["minttendermintupdatesession"],
                    StateOutputKind::Client,
                    true,
                ),
            };
        if requirement.action.is_finalization()
            && self.consensus_history_format == ConsensusHistoryFormat::ProofBackedV1
        {
            required_scripts.push("recoverclient");
        }
        Ok(OperationRequirements {
            required_scripts,
            required_mint_scripts,
            state_output,
            module: None,
            requires_host_state,
            tendermint_session: Some(requirement),
        })
    }

    /// Classify the staged action from the same exact transaction body and
    /// trusted inputs used by the signing policy. Callers use this result to
    /// enforce the transaction-chain protocol around individually valid links.
    pub(crate) fn staged_tendermint_action(
        &self,
        transaction_cbor: &[u8],
        resolved_inputs: &ResolvedTransactionInputs,
    ) -> Result<ValidatedTendermintSessionAction, Error> {
        let mut decoder = minicbor::Decoder::new(transaction_cbor);
        let tx: MintedTx<'_> = decoder.decode().map_err(|error| {
            Error::CborDecode(format!(
                "failed to decode staged Tendermint transaction: {error:?}"
            ))
        })?;
        if decoder.position() != transaction_cbor.len() {
            return Err(Error::CborDecode(
                "failed to decode staged Tendermint transaction: trailing CBOR data".to_string(),
            ));
        }
        let session = self.tendermint_session.as_ref().ok_or_else(|| {
            Error::Signer("pinned manifest has no staged Tendermint session validators".to_string())
        })?;
        classify_tendermint_session_transaction(
            &tx.transaction_body,
            resolved_inputs,
            session,
            &self.host_state_address,
            &self.client_state.address,
        )
        .map_err(|reason| {
            Error::Signer(format!(
                "refusing to classify staged Tendermint transaction: {reason}"
            ))
        })
    }

    /// Validate all security-sensitive transaction fields before a signing key is used.
    pub fn validate(
        &self,
        tx: &MintedTx<'_>,
        tx_size: usize,
        signer: &str,
        intent: &SigningIntent,
        resolved_inputs: &ResolvedTransactionInputs,
    ) -> Result<(), Error> {
        let reject = |reason: String| {
            Error::Signer(format!(
                "refusing to sign Gateway transaction for {}: {reason}",
                intent.operation
            ))
        };
        let requirements = if intent.staged_tendermint {
            self.staged_tendermint_requirements(&tx.transaction_body, intent, resolved_inputs)
                .map_err(reject)?
        } else {
            self.operation_requirements(intent).map_err(reject)?
        };
        if intent.unresolved_ibc_denom_hash().is_some() {
            return Err(reject(
                "hashed ICS-20 denomination was not resolved and verified".to_string(),
            ));
        }

        if tx_size > self.limits.max_tx_size_bytes {
            return Err(reject(format!(
                "encoded size {tx_size} exceeds {} bytes",
                self.limits.max_tx_size_bytes
            )));
        }
        if !tx.success {
            return Err(reject(
                "transaction is marked as phase-2 invalid".to_string(),
            ));
        }
        if !matches!(tx.auxiliary_data, Nullable::Null | Nullable::Undefined) {
            return Err(reject("auxiliary data is not authorized".to_string()));
        }

        let body = &*tx.transaction_body;
        if body.fee > self.limits.max_fee_lovelace {
            return Err(reject(format!(
                "fee {} exceeds {} lovelace",
                body.fee, self.limits.max_fee_lovelace
            )));
        }
        let ttl = body
            .ttl
            .ok_or_else(|| reject("transaction has no upper validity bound".to_string()))?;
        if let Some(valid_from) = body.validity_interval_start {
            let span = ttl.checked_sub(valid_from).ok_or_else(|| {
                reject("transaction validity interval ends before it starts".to_string())
            })?;
            if span > self.limits.max_validity_interval_slots {
                return Err(reject(format!(
                    "transaction validity interval spans {span} slots, exceeding {}",
                    self.limits.max_validity_interval_slots
                )));
            }
        }
        if body.certificates.is_some() {
            return Err(reject("certificates are not authorized".to_string()));
        }
        self.validate_withdrawals(
            body,
            intent,
            requirements
                .tendermint_session
                .as_ref()
                .is_some_and(|session| session.action.is_finalization()),
            &reject,
        )?;
        if body.auxiliary_data_hash.is_some() {
            return Err(reject("auxiliary data hash is not authorized".to_string()));
        }
        if body.voting_procedures.is_some()
            || body.proposal_procedures.is_some()
            || body.treasury_value.is_some()
            || body.donation.is_some()
        {
            return Err(reject(
                "Conway governance fields are not authorized".to_string(),
            ));
        }
        if body.inputs.is_empty() || body.inputs.len() > MAX_INPUTS {
            return Err(reject(format!(
                "input count must be between 1 and {MAX_INPUTS}"
            )));
        }
        if body.outputs.is_empty() || body.outputs.len() > MAX_OUTPUTS {
            return Err(reject(format!(
                "output count must be between 1 and {MAX_OUTPUTS}"
            )));
        }

        let input_set: HashSet<_> = body
            .inputs
            .iter()
            .map(|input| (input.transaction_id.to_string(), input.index))
            .collect();
        if input_set.len() != body.inputs.len() {
            return Err(reject("transaction contains duplicate inputs".to_string()));
        }

        let reference_inputs = body
            .reference_inputs
            .as_ref()
            .ok_or_else(|| reject("transaction has no reference inputs".to_string()))?;
        if reference_inputs.len() > MAX_REFERENCE_INPUTS {
            return Err(reject(format!(
                "reference input count exceeds {MAX_REFERENCE_INPUTS}"
            )));
        }
        let reference_set: HashSet<OutRef> = reference_inputs
            .iter()
            .map(|input| (input.transaction_id.as_ref().to_vec(), input.index))
            .collect();
        if reference_set.len() != reference_inputs.len() {
            return Err(reject(
                "transaction contains duplicate reference inputs".to_string(),
            ));
        }
        if requirements.requires_host_state && !reference_set.contains(&self.host_state_reference) {
            return Err(reject(
                "pinned HostState reference script is missing".to_string(),
            ));
        }
        for script_name in &requirements.required_scripts {
            let root = required_script(&self.scripts, script_name).map_err(reject)?;
            if !reference_set.contains(&root.reference) {
                return Err(reject(format!(
                    "pinned {script_name} reference script is missing"
                )));
            }
        }

        let signer_address = decode_address(signer, self.network_id).map_err(reject)?;
        let signer_key_hash = signer_address
            .get(1..)
            .filter(|hash| hash.len() == 28)
            .ok_or_else(|| reject("signer is not a Shelley enterprise address".to_string()))?;

        if let Some(network_id) = body.network_id {
            let expected = if self.network_id == 0 {
                NetworkId::One
            } else if self.network_id == 1 {
                NetworkId::Two
            } else {
                return Err(reject(format!(
                    "transaction network field cannot represent configured network {}",
                    self.network_id
                )));
            };
            if network_id != expected {
                return Err(reject(
                    "transaction network id does not match configuration".to_string(),
                ));
            }
        }

        if let Some(required_signers) = body.required_signers.as_ref() {
            if required_signers.len() != 1 || required_signers[0].as_ref() != signer_key_hash {
                return Err(reject(
                    "required signers contain a key other than the configured relayer".to_string(),
                ));
            }
        }

        let witnesses = &*tx.transaction_witness_set;
        if witnesses.vkeywitness.is_some() || witnesses.bootstrap_witness.is_some() {
            return Err(reject(
                "unsigned transaction already contains a key witness".to_string(),
            ));
        }
        if witnesses.native_script.is_some()
            || witnesses.plutus_v1_script.is_some()
            || witnesses.plutus_v2_script.is_some()
            || witnesses.plutus_v3_script.is_some()
        {
            return Err(reject(
                "embedded scripts are forbidden; pinned reference scripts are required".to_string(),
            ));
        }

        if intent.operation == "TraceRegistryPrelude" {
            self.validate_trace_registry_prelude(
                body,
                &signer_address,
                intent,
                witnesses.redeemer.as_deref(),
                resolved_inputs,
                &reference_set,
                &reject,
            )?;
            self.validate_collateral(body, &signer_address, resolved_inputs, &reject)?;
            self.validate_wallet_delta(body, &signer_address, intent, resolved_inputs, &reject)?;
            return Ok(());
        }

        self.validate_resolved_inputs(
            body,
            &signer_address,
            intent,
            &requirements,
            resolved_inputs,
            &reject,
        )?;

        self.validate_message_binding(
            body,
            witnesses.redeemer.as_deref(),
            &signer_address,
            intent,
            &requirements,
            resolved_inputs,
            &reject,
        )?;

        self.validate_collateral(body, &signer_address, resolved_inputs, &reject)?;
        self.validate_mint(body, intent, &requirements, &reference_set, &reject)?;
        self.validate_outputs(
            body,
            &signer_address,
            intent,
            &requirements,
            &reference_set,
            &reject,
        )?;
        self.validate_wallet_delta(body, &signer_address, intent, resolved_inputs, &reject)?;

        Ok(())
    }

    fn validate_trace_registry_prelude<F>(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        signer_address: &[u8],
        intent: &SigningIntent,
        redeemers: Option<&pallas_primitives::conway::Redeemers>,
        resolved_inputs: &ResolvedTransactionInputs,
        reference_inputs: &HashSet<OutRef>,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let transaction_inputs: BTreeSet<_> = body
            .inputs
            .iter()
            .map(TransactionOutRef::from_transaction_input)
            .collect();
        let resolved_regular: BTreeSet<_> = resolved_inputs.regular.keys().cloned().collect();
        if transaction_inputs != resolved_regular {
            return Err(reject(
                "trusted UTxO resolution does not exactly cover the trace-registry prelude inputs"
                    .to_string(),
            ));
        }

        let mut signer_input_count = 0usize;
        for input in resolved_inputs.regular.values() {
            validate_address_network(&input.address, self.network_id).map_err(reject)?;
            if input.address == signer_address {
                signer_input_count += 1;
            } else if input.address != self.trace_registry_address {
                return Err(reject(
                    "trace-registry prelude spends an unauthorized protocol input".to_string(),
                ));
            }
        }
        if signer_input_count == 0 {
            return Err(reject(
                "trace-registry prelude does not consume an input owned by the configured signer"
                    .to_string(),
            ));
        }

        let mut trace_outputs = 0usize;
        for output in body.outputs.iter().map(unpack_output) {
            validate_address_network(&output.address, self.network_id).map_err(reject)?;
            if output.has_script_ref {
                return Err(reject(
                    "trace-registry prelude outputs may not install scripts".to_string(),
                ));
            }
            if output.address == signer_address {
                continue;
            }
            if output.address == self.voucher_metadata_address {
                continue;
            }
            if output.address != self.trace_registry_address {
                return Err(reject(
                    "trace-registry prelude pays an unauthorized address".to_string(),
                ));
            }
            if output.assets.is_empty()
                || !output.assets.iter().all(|(policy, _, quantity)| {
                    policy == &self.trace_registry_policy && *quantity == 1
                })
            {
                return Err(reject(
                    "trace-registry prelude output contains unauthorized assets".to_string(),
                ));
            }
            trace_outputs += 1;
        }
        if trace_outputs == 0 || trace_outputs > 3 {
            return Err(reject(
                "trace-registry prelude must create between one and three registry outputs"
                    .to_string(),
            ));
        }

        let expected_reference_name =
            intent
                .transfer
                .as_ref()
                .and_then(|transfer| match expected_asset(transfer) {
                    ExpectedAsset::Voucher {
                        reference_name: Some(name),
                        ..
                    } => Some(name),
                    _ => None,
                });
        let mut minted_reference = false;
        let mut minted_identifier = false;
        if let Some(mint) = body.mint.as_ref() {
            for (policy, assets) in mint.iter() {
                let is_identifier = policy.as_ref()
                    == required_script(&self.scripts, "mintidentifier")
                        .map_err(reject)?
                        .hash
                        .as_slice();
                let is_voucher = policy.as_ref() == self.voucher_policy.as_slice();
                if (!is_identifier && !is_voucher) || assets.len() != 1 {
                    return Err(reject(
                        "trace-registry prelude may only mint the voucher reference and registry identifier"
                            .to_string(),
                    ));
                }
                let Some((name, quantity)) = assets.iter().next() else {
                    return Err(reject(
                        "trace-registry prelude contains an empty mint policy".to_string(),
                    ));
                };
                if i64::from(*quantity) != 1 {
                    return Err(reject(
                        "trace-registry prelude mint quantities must be one".to_string(),
                    ));
                }
                if is_identifier {
                    minted_identifier = true;
                } else if expected_reference_name
                    .as_ref()
                    .is_none_or(|expected| expected.as_slice() != name.as_slice())
                {
                    return Err(reject(
                        "trace-registry prelude mints an unexpected voucher reference token"
                            .to_string(),
                    ));
                } else {
                    minted_reference = true;
                }
            }
        }
        if !minted_reference {
            return Err(reject(
                "trace-registry prelude must mint the expected voucher reference token".to_string(),
            ));
        }
        if minted_identifier {
            let root = required_script(&self.scripts, "mintidentifier").map_err(reject)?;
            if !reference_inputs.contains(&root.reference) {
                return Err(reject(
                    "trace-registry prelude is missing its pinned identifier reference script"
                        .to_string(),
                ));
            }
        }
        if redeemers.is_none() {
            return Err(reject(
                "trace-registry prelude has no script redeemers".to_string(),
            ));
        }
        if let Some(reference_name) = expected_reference_name {
            let metadata_outputs = body
                .outputs
                .iter()
                .map(unpack_output)
                .filter(|output| output.address == self.voucher_metadata_address)
                .collect::<Vec<_>>();
            if metadata_outputs.len() != 1
                || metadata_outputs[0].assets.len() != 1
                || metadata_outputs[0].assets[0] != (self.voucher_policy.clone(), reference_name, 1)
            {
                return Err(reject(
                    "trace-registry prelude must publish exactly one expected voucher metadata output"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn validate_withdrawals<F>(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        intent: &SigningIntent,
        staged_finalization: bool,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let requires_withdrawal = intent.operation == "/ibc.core.client.v1.MsgRecoverClient"
            || (intent.operation == "/ibc.core.client.v1.MsgUpdateClient"
                && (!intent.staged_tendermint || staged_finalization)
                && self.consensus_history_format == ConsensusHistoryFormat::ProofBackedV1);
        if !requires_withdrawal {
            if body.withdrawals.is_some() {
                return Err(reject("withdrawals are not authorized".to_string()));
            }
            return Ok(());
        }

        let withdrawals = body.withdrawals.as_ref().ok_or_else(|| {
            reject("client transition requires its validator withdrawal".to_string())
        })?;
        if withdrawals.len() != 1 {
            return Err(reject(
                "client transition requires exactly one validator withdrawal".to_string(),
            ));
        }

        let recovery_script = required_script(&self.scripts, "recoverclient").map_err(reject)?;
        let expected_reward_account = [
            &[0xf0 | self.network_id][..],
            recovery_script.hash.as_slice(),
        ]
        .concat();
        let (reward_account, amount) = withdrawals
            .iter()
            .next()
            .expect("non-empty withdrawal map has one entry");
        if reward_account.as_slice() != expected_reward_account || *amount != 0 {
            return Err(reject(
                "client transition withdrawal does not execute the pinned recovery validator with zero value"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_resolved_inputs<F>(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        signer_address: &[u8],
        intent: &SigningIntent,
        requirements: &OperationRequirements<'_>,
        resolved_inputs: &ResolvedTransactionInputs,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let transaction_inputs: BTreeSet<_> = body
            .inputs
            .iter()
            .map(TransactionOutRef::from_transaction_input)
            .collect();
        let resolved_regular: BTreeSet<_> = resolved_inputs.regular.keys().cloned().collect();
        if transaction_inputs != resolved_regular {
            return Err(reject(
                "trusted UTxO resolution does not exactly cover the regular inputs".to_string(),
            ));
        }

        let transaction_collateral: BTreeSet<_> = body
            .collateral
            .as_ref()
            .into_iter()
            .flat_map(|inputs| inputs.iter())
            .map(TransactionOutRef::from_transaction_input)
            .collect();
        let resolved_collateral: BTreeSet<_> = resolved_inputs.collateral.keys().cloned().collect();
        if transaction_collateral != resolved_collateral {
            return Err(reject(
                "trusted UTxO resolution does not exactly cover the collateral inputs".to_string(),
            ));
        }

        // CIP-40 permits a wallet output to fund success and collateral failure.
        // The trusted resolver reads it once; reject inconsistent records from
        // any other caller before checking those mutually exclusive balances.
        for (out_ref, collateral) in &resolved_inputs.collateral {
            if resolved_inputs
                .regular
                .get(out_ref)
                .is_some_and(|regular| regular != collateral)
            {
                return Err(reject(
                    "trusted UTxO resolution disagrees for a shared regular/collateral input"
                        .to_string(),
                ));
            }
        }

        let expected_state = match requirements.state_output {
            StateOutputKind::None => None,
            StateOutputKind::Client => Some(&self.client_state),
            StateOutputKind::Connection => Some(&self.connection_state),
            StateOutputKind::Channel => Some(&self.channel_state),
        };
        let expected_state_name = intent
            .state_sequence
            .zip(expected_state)
            .map(|(sequence, _)| self.state_token_name(requirements.state_output, sequence));
        let expected_session = requirements
            .tendermint_session
            .as_ref()
            .zip(self.tendermint_session.as_ref());

        let mut signer_input_count = 0usize;
        let mut host_state_nft_quantity = 0u64;
        let mut expected_state_quantity = 0u64;
        let mut expected_session_quantity = 0u64;
        for input in resolved_inputs.regular.values() {
            validate_address_network(&input.address, self.network_id).map_err(reject)?;
            if input.address == signer_address {
                signer_input_count += 1;
                continue;
            }

            let allowed_protocol_input = (requirements.requires_host_state
                && input.address == self.host_state_address)
                || expected_state.is_some_and(|state| input.address == state.address)
                || expected_session.is_some_and(|(_, session)| input.address == session.address)
                || requirements
                    .module
                    .is_some_and(|module| input.address == module.address)
                || (intent.transfer.is_some()
                    && (input.address == self.trace_registry_address
                        || input.address == self.voucher_metadata_address));
            if !allowed_protocol_input {
                return Err(reject(format!(
                    "regular input spends an address outside the signer and authorized protocol roles: {}",
                    hex::encode(&input.address)
                )));
            }

            for asset in &input.assets {
                if asset.policy_id.as_slice() == self.host_state_nft_policy
                    && asset.asset_name == self.host_state_nft_name
                {
                    if input.address != self.host_state_address {
                        return Err(reject(
                            "HostState NFT input is not locked by the pinned HostState validator"
                                .to_string(),
                        ));
                    }
                    host_state_nft_quantity = host_state_nft_quantity
                        .checked_add(asset.quantity)
                        .ok_or_else(|| {
                        reject("HostState NFT input quantity overflows u64".to_string())
                    })?;
                }

                for state in [
                    &self.client_state,
                    &self.connection_state,
                    &self.channel_state,
                ] {
                    if asset.policy_id.as_slice() == state.policy && input.address != state.address
                    {
                        return Err(reject(
                            "protocol state token input is not locked by its pinned validator"
                                .to_string(),
                        ));
                    }
                }

                if let (Some(state), Some(name)) = (expected_state, expected_state_name.as_deref())
                {
                    if input.address == state.address
                        && asset.policy_id.as_slice() == state.policy
                        && asset.asset_name.as_slice() == name
                    {
                        expected_state_quantity = expected_state_quantity
                            .checked_add(asset.quantity)
                            .ok_or_else(|| {
                                reject(
                                    "protocol state token input quantity overflows u64".to_string(),
                                )
                            })?;
                    }
                }
                if let Some((requirement, session)) = expected_session {
                    if input.address == session.address
                        && asset.policy_id.as_slice() == session.policy
                        && requirement
                            .token_names()
                            .any(|name| asset.asset_name == name)
                    {
                        expected_session_quantity = expected_session_quantity
                            .checked_add(asset.quantity)
                            .ok_or_else(|| {
                                reject(
                                    "staged Tendermint session NFT input quantity overflows u64"
                                        .to_string(),
                                )
                            })?;
                    }
                }
            }

            if input.address == self.host_state_address
                && (input.assets.len() != 1
                    || input.assets[0].policy_id.as_slice() != self.host_state_nft_policy
                    || input.assets[0].asset_name != self.host_state_nft_name
                    || input.assets[0].quantity != 1)
            {
                return Err(reject(
                    "HostState input does not contain exactly the pinned HostState NFT".to_string(),
                ));
            }
            if let (Some(state), Some(name)) = (expected_state, expected_state_name.as_deref()) {
                if input.address == state.address
                    && (input.assets.len() != 1
                        || input.assets[0].policy_id.as_slice() != state.policy
                        || input.assets[0].asset_name.as_slice() != name
                        || input.assets[0].quantity != 1)
                {
                    return Err(reject(
                        "state input does not contain exactly the token selected by the IBC identifier"
                            .to_string(),
                    ));
                }
            }
            if let Some((requirement, session)) = expected_session {
                if input.address == session.address
                    && (input.assets.len() != 1
                        || input.assets[0].policy_id.as_slice() != session.policy
                        || !requirement
                            .token_names()
                            .any(|name| input.assets[0].asset_name == name)
                        || input.assets[0].quantity != 1)
                {
                    return Err(reject(
                        "staged Tendermint session input does not contain exactly its pinned NFT"
                            .to_string(),
                    ));
                }
            }
        }

        if signer_input_count == 0 {
            return Err(reject(
                "transaction does not consume an input owned by the configured signer".to_string(),
            ));
        }
        let expected_host_state_quantity = u64::from(requirements.requires_host_state);
        if host_state_nft_quantity != expected_host_state_quantity {
            return Err(reject(format!(
                "expected {expected_host_state_quantity} HostState NFTs in regular inputs, found {host_state_nft_quantity}"
            )));
        }
        if expected_state_name.is_some() && expected_state_quantity != 1 {
            return Err(reject(format!(
                "expected exactly one message-selected protocol state token in regular inputs, found {expected_state_quantity}"
            )));
        }
        let expected_session_input_quantity =
            requirements
                .tendermint_session
                .as_ref()
                .map_or(0, |session| {
                    if session.action == TendermintSessionAction::Initialize {
                        0
                    } else {
                        session.token_names().count() as u64
                    }
                });
        if expected_session_quantity != expected_session_input_quantity {
            return Err(reject(format!(
                "expected {expected_session_input_quantity} staged Tendermint session NFTs in regular inputs, found {expected_session_quantity}"
            )));
        }

        Ok(())
    }

    fn validate_collateral<F>(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        signer_address: &[u8],
        resolved_inputs: &ResolvedTransactionInputs,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        match body.collateral.as_ref() {
            None => {
                if body.collateral_return.is_some() || body.total_collateral.is_some() {
                    return Err(reject(
                        "collateral fields are present without collateral inputs".to_string(),
                    ));
                }
            }
            Some(collateral) => {
                if collateral.is_empty() || collateral.len() > MAX_COLLATERAL_INPUTS {
                    return Err(reject(format!(
                        "collateral input count must be between 1 and {MAX_COLLATERAL_INPUTS}"
                    )));
                }
                let total = body.total_collateral.ok_or_else(|| {
                    reject("collateral inputs require an explicit total collateral".to_string())
                })?;
                if total == 0 {
                    return Err(reject(
                        "total collateral must be greater than zero".to_string(),
                    ));
                }
                if total > self.limits.max_total_collateral_lovelace {
                    return Err(reject(format!(
                        "total collateral {total} exceeds {} lovelace",
                        self.limits.max_total_collateral_lovelace
                    )));
                }
                let collateral_return = body.collateral_return.as_ref().ok_or_else(|| {
                    reject("collateral inputs require an explicit collateral return".to_string())
                })?;
                let output = unpack_output(collateral_return);
                if output.address != signer_address {
                    return Err(reject(
                        "collateral return does not pay the configured relayer".to_string(),
                    ));
                }
                if output.has_script_ref {
                    return Err(reject(
                        "collateral return may not install a reference script".to_string(),
                    ));
                }
                let mut seen = HashSet::new();
                let mut collateral_lovelace = 0u64;
                let mut collateral_assets = BTreeMap::new();
                for input in collateral.iter() {
                    let out_ref = (input.transaction_id.to_string(), input.index);
                    if !seen.insert(out_ref) {
                        return Err(reject("collateral inputs contain duplicates".to_string()));
                    }
                    let resolved = resolved_inputs.collateral_input(input).ok_or_else(|| {
                        reject("trusted UTxO resolution is missing a collateral input".to_string())
                    })?;
                    if resolved.address != signer_address {
                        return Err(reject(
                            "collateral input is not owned by the configured relayer".to_string(),
                        ));
                    }
                    collateral_lovelace = collateral_lovelace
                        .checked_add(resolved.lovelace)
                        .ok_or_else(|| {
                            reject("collateral lovelace total overflows u64".to_string())
                        })?;
                    add_resolved_assets(&mut collateral_assets, resolved, reject)?;
                }
                let expected_return = collateral_lovelace.checked_sub(total).ok_or_else(|| {
                    reject("total collateral exceeds the resolved collateral value".to_string())
                })?;
                if output.coin != expected_return {
                    return Err(reject(format!(
                        "collateral return is {} lovelace, expected {expected_return}",
                        output.coin
                    )));
                }
                let return_assets =
                    aggregate_output_assets(std::iter::once(&output), reject, "collateral return")?;
                if return_assets != collateral_assets {
                    return Err(reject(
                        "collateral return does not preserve all collateral native assets"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_mint<F>(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        intent: &SigningIntent,
        requirements: &OperationRequirements<'_>,
        reference_inputs: &HashSet<OutRef>,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let mut voucher_assets = Vec::new();
        let mut actual_policies = HashSet::new();
        let expected_session_mint =
            requirements
                .tendermint_session
                .as_ref()
                .and_then(|requirement| {
                    let quantity = match requirement.action {
                        TendermintSessionAction::Initialize => 1,
                        TendermintSessionAction::Cancel
                        | TendermintSessionAction::Finalize
                        | TendermintSessionAction::FinalizeMisbehaviour => -1,
                        TendermintSessionAction::Advance => return None,
                    };
                    self.tendermint_session
                        .as_ref()
                        .map(|session| (session.policy.as_slice(), requirement, quantity))
                });

        if let Some(mint) = body.mint.as_ref() {
            for (policy, assets) in mint.iter() {
                actual_policies.insert(policy.as_ref().to_vec());
                if policy.as_ref() == self.host_state_nft_policy.as_slice() {
                    return Err(reject(
                        "HostState NFT minting or burning is forbidden".to_string(),
                    ));
                }
                let expected_asset_count = expected_session_mint
                    .filter(|(expected_policy, _, _)| policy.as_ref() == *expected_policy)
                    .map_or(1, |(_, requirement, _)| requirement.token_names().count());
                if policy.as_ref() != self.voucher_policy.as_slice()
                    && assets.len() != expected_asset_count
                {
                    return Err(reject(format!(
                        "bridge authorization policy {policy} must mint exactly {expected_asset_count} asset(s)"
                    )));
                }
                for (name, quantity) in assets.iter() {
                    let quantity = i64::from(quantity);
                    if quantity == 0 {
                        return Err(reject(
                            "zero-quantity mint entries are forbidden".to_string(),
                        ));
                    }
                    if policy.as_ref() == self.voucher_policy.as_slice() {
                        voucher_assets.push((name.as_slice().to_vec(), quantity));
                    } else if expected_session_mint.is_some_and(
                        |(expected_policy, requirement, expected_quantity)| {
                            policy.as_ref() == expected_policy
                                && requirement
                                    .token_names()
                                    .any(|expected| name.as_slice() == expected)
                                && quantity == expected_quantity
                        },
                    ) {
                        // Exact session NFT creation/burn is authorized by the
                        // staged transaction classification above.
                    } else if quantity != 1 {
                        return Err(reject(format!(
                            "bridge authorization token under policy {policy} must mint exactly one unit"
                        )));
                    }
                }
            }
        }

        let mut required_policies = HashSet::new();
        for script_name in &requirements.required_mint_scripts {
            required_policies.insert(
                required_script(&self.scripts, script_name)
                    .map_err(reject)?
                    .hash
                    .clone(),
            );
        }

        let voucher_action = intent.transfer.as_ref().and_then(voucher_mint_action);
        let positive_voucher = voucher_action == Some(VoucherMintAction::Mint);
        let escrow_send = intent.transfer.as_ref().is_some_and(|transfer| {
            transfer.action == TransferAction::Send
                && voucher_action != Some(VoucherMintAction::Burn)
        });

        let mut allowed_policies = required_policies.clone();
        if voucher_action.is_some() {
            allowed_policies.insert(self.voucher_policy.clone());
        }
        if positive_voucher {
            allowed_policies.insert(
                required_script(&self.scripts, "mintidentifier")
                    .map_err(reject)?
                    .hash
                    .clone(),
            );
        }
        if escrow_send {
            allowed_policies.insert(self.transfer_escrow_policy.clone());
        }

        if !required_policies.is_subset(&actual_policies) {
            return Err(reject(
                "transaction omits an authorization mint required for this IBC operation"
                    .to_string(),
            ));
        }
        if !actual_policies.is_subset(&allowed_policies) {
            let unexpected = actual_policies
                .difference(&allowed_policies)
                .next()
                .expect("non-subset has an element");
            return Err(reject(format!(
                "mint policy {} is not authorized for this IBC operation",
                hex::encode(unexpected)
            )));
        }

        for policy in &actual_policies {
            let root = self
                .scripts
                .values()
                .find(|root| &root.hash == policy)
                .ok_or_else(|| {
                    reject(format!(
                        "mint policy {} is not present in the pinned manifest",
                        hex::encode(policy)
                    ))
                })?;
            if !reference_inputs.contains(&root.reference) {
                return Err(reject(format!(
                    "mint policy {} is missing its pinned reference script",
                    hex::encode(policy)
                )));
            }
        }

        self.validate_voucher_mint(&voucher_assets, intent, reject)?;

        let reference_voucher_minted = match intent.transfer.as_ref().map(expected_asset) {
            Some(ExpectedAsset::Voucher {
                reference_name: Some(reference_name),
                ..
            }) => voucher_assets
                .iter()
                .any(|(name, quantity)| name == &reference_name && *quantity == 1),
            _ => false,
        };
        let identifier_policy = required_script(&self.scripts, "mintidentifier")
            .map_err(reject)?
            .hash
            .as_slice();
        if actual_policies.contains(identifier_policy) && !reference_voucher_minted {
            return Err(reject(
                "trace-registry identifier mint is only allowed for a first-seen voucher"
                    .to_string(),
            ));
        }

        Ok(())
    }

    fn validate_voucher_mint<F>(
        &self,
        voucher_assets: &[(Vec<u8>, i64)],
        intent: &SigningIntent,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let Some(transfer) = intent.transfer.as_ref() else {
            if voucher_assets.is_empty() {
                return Ok(());
            }
            return Err(reject(
                "voucher minting or burning is not authorized by this IBC message".to_string(),
            ));
        };
        let Some(action) = voucher_mint_action(transfer) else {
            if voucher_assets.is_empty() {
                return Ok(());
            }
            return Err(reject(
                "voucher minting or burning is not authorized by this transfer path".to_string(),
            ));
        };
        let ExpectedAsset::Voucher {
            user_name,
            reference_name,
        } = expected_asset(transfer)
        else {
            return Err(reject(
                "internal signing policy mismatch for voucher authorization".to_string(),
            ));
        };

        match action {
            VoucherMintAction::Mint => {
                let user_name = user_name.ok_or_else(|| {
                    reject("cannot derive the expected voucher token name".to_string())
                })?;
                let reference_name = reference_name.expect("known voucher names are paired");
                let expected_quantity = i64::try_from(transfer.amount).map_err(|_| {
                    reject("IBC transfer amount exceeds Cardano mint range".to_string())
                })?;
                let valid = matches!(voucher_assets,
                    [(name, quantity)]
                        if name == &user_name && *quantity == expected_quantity
                ) || matches!(voucher_assets,
                    [(first_name, first_quantity), (second_name, second_quantity)]
                        if ((first_name == &user_name && *first_quantity == expected_quantity
                            && second_name == &reference_name && *second_quantity == 1)
                            || (second_name == &user_name && *second_quantity == expected_quantity
                                && first_name == &reference_name && *first_quantity == 1))
                );
                if !valid {
                    return Err(reject(
                        "voucher mint does not match the packet denomination and amount"
                            .to_string(),
                    ));
                }
            }
            VoucherMintAction::Burn => {
                if voucher_assets.len() != 1 {
                    return Err(reject(
                        "voucher send must burn exactly one asset".to_string(),
                    ));
                }
                let (actual_name, actual_quantity) = &voucher_assets[0];
                let expected_quantity = i64::try_from(transfer.amount)
                    .ok()
                    .and_then(i64::checked_neg)
                    .ok_or_else(|| {
                        reject("IBC transfer amount exceeds Cardano mint range".to_string())
                    })?;
                let name_matches = user_name.as_ref().map_or_else(
                    || is_voucher_user_token_name(actual_name),
                    |name| name == actual_name,
                );
                if !name_matches || *actual_quantity != expected_quantity {
                    return Err(reject(
                        "voucher burn does not match the requested denomination and amount"
                            .to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn state_token_name(&self, kind: StateOutputKind, sequence: u64) -> Vec<u8> {
        let prefix = match kind {
            StateOutputKind::Client => b"ibc_client".as_slice(),
            StateOutputKind::Connection => b"connection".as_slice(),
            StateOutputKind::Channel => b"channel".as_slice(),
            StateOutputKind::None => return Vec::new(),
        };
        let mut base_hasher = Sha3::v256();
        base_hasher.update(&self.host_state_nft_policy);
        base_hasher.update(&self.host_state_nft_name);
        let mut base_hash = [0u8; 32];
        base_hasher.finalize(&mut base_hash);

        let mut prefix_hasher = Sha3::v256();
        prefix_hasher.update(prefix);
        let mut prefix_hash = [0u8; 32];
        prefix_hasher.finalize(&mut prefix_hash);

        [
            &base_hash[..20],
            &prefix_hash[..4],
            sequence.to_string().as_bytes(),
        ]
        .concat()
    }

    fn validate_tendermint_session_redeemers<F>(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        redeemers: &pallas_primitives::conway::Redeemers,
        signer_address: &[u8],
        intent: &SigningIntent,
        requirement: &ValidatedTendermintSessionAction,
        resolved_inputs: &ResolvedTransactionInputs,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let session = self
            .tendermint_session
            .as_ref()
            .expect("session requirement needs a configured session root");
        let expected_client_name = intent
            .state_sequence
            .map(|sequence| self.state_token_name(StateOutputKind::Client, sequence))
            .ok_or_else(|| reject("staged update has no selected client identifier".to_string()))?;

        match requirement.action {
            TendermintSessionAction::Initialize => {
                let mint_redeemer =
                    mint_redeemer_for_policy(body, redeemers, &session.policy).map_err(reject)?;
                let fields = constructor_fields(mint_redeemer, 0).ok_or_else(|| {
                    reject("session initialization does not use MintSession".to_string())
                })?;
                if fields.len() != 3 {
                    return Err(reject(
                        "MintSession redeemer must contain seed, owner, and update plan"
                            .to_string(),
                    ));
                }
                let seed = plutus_output_reference(&fields[0]).ok_or_else(|| {
                    reject("MintSession redeemer contains an invalid seed reference".to_string())
                })?;
                let seed_input = resolved_inputs.regular.get(&seed).ok_or_else(|| {
                    reject("MintSession seed is not a regular transaction input".to_string())
                })?;
                if seed_input.address != signer_address {
                    return Err(reject(
                        "MintSession seed is not owned by the configured relayer".to_string(),
                    ));
                }
                if plutus_bytes(&fields[1]) != signer_address.get(1..) {
                    return Err(reject(
                        "MintSession owner is not the configured relayer key".to_string(),
                    ));
                }
                let plan_fields = constructor_fields(&fields[2], 0).ok_or_else(|| {
                    reject("MintSession update plan has an invalid encoding".to_string())
                })?;
                let client_token = plan_fields.first().and_then(plutus_auth_token);
                if client_token
                    != Some((
                        self.client_state.policy.as_slice(),
                        expected_client_name.as_slice(),
                    ))
                {
                    return Err(reject(
                        "MintSession update plan targets a different client".to_string(),
                    ));
                }
            }
            TendermintSessionAction::Advance => {
                let session_redeemer =
                    self.session_spend_redeemer(body, redeemers, resolved_inputs, session, reject)?;
                let batch = constructor_fields(session_redeemer, 0)
                    .or_else(|| constructor_fields(session_redeemer, 1))
                    .and_then(|fields| fields.first())
                    .and_then(|field| match field {
                        PlutusData::Array(items) => Some(items.len()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        reject(
                            "session advance must use VerifyTrusted or VerifyTarget with one batch"
                                .to_string(),
                        )
                    })?;
                if !(1..=MAX_TENDERMINT_SESSION_BATCH_SIZE).contains(&batch) {
                    return Err(reject(format!(
                        "staged Tendermint verifier batch must contain between 1 and {MAX_TENDERMINT_SESSION_BATCH_SIZE} entries"
                    )));
                }
            }
            TendermintSessionAction::Cancel | TendermintSessionAction::Finalize => {
                let session_redeemer =
                    self.session_spend_redeemer(body, redeemers, resolved_inputs, session, reject)?;
                let expected_alternative = if requirement.action == TendermintSessionAction::Cancel
                {
                    3
                } else {
                    2
                };
                if constructor_fields(session_redeemer, expected_alternative)
                    .is_none_or(|fields| !fields.is_empty())
                {
                    return Err(reject(format!(
                        "session {:?} transaction has the wrong session spend redeemer",
                        requirement.action
                    )));
                }
                let mint_redeemer =
                    mint_redeemer_for_policy(body, redeemers, &session.policy).map_err(reject)?;
                let burned_name = constructor_fields(mint_redeemer, 1)
                    .filter(|fields| fields.len() == 1)
                    .and_then(|fields| plutus_bytes(&fields[0]));
                if burned_name != Some(requirement.token_name.as_slice()) {
                    return Err(reject(
                        "BurnSession redeemer does not select the consumed session NFT".to_string(),
                    ));
                }

                if requirement.action == TendermintSessionAction::Finalize {
                    let client_input = selected_state_input(
                        resolved_inputs,
                        &self.client_state,
                        &expected_client_name,
                    )
                    .ok_or_else(|| {
                        reject("staged finalization omits the selected client input".to_string())
                    })?;
                    let client_redeemer =
                        spend_redeemer_for_input(body, redeemers, client_input).map_err(reject)?;
                    let selected_session = constructor_fields(client_redeemer, 0)
                        .filter(|fields| match self.consensus_history_format {
                            ConsensusHistoryFormat::Legacy => fields.len() == 1,
                            ConsensusHistoryFormat::ProofBackedV1 => fields.len() == 3
                                && matches!(&fields[1], PlutusData::Array(witnesses) if witnesses.len() <= 2)
                                && history_siblings_shape(&fields[2], true),
                        })
                        .and_then(|fields| plutus_auth_token(&fields[0]));
                    if selected_session
                        != Some((session.policy.as_slice(), requirement.token_name.as_slice()))
                    {
                        return Err(reject(
                            "staged client finalization redeemer selects a different session NFT"
                                .to_string(),
                        ));
                    }
                }
            }
            TendermintSessionAction::FinalizeMisbehaviour => {
                let selected_names: BTreeSet<_> = requirement.token_names().collect();
                for (out_ref, input) in resolved_inputs
                    .regular
                    .iter()
                    .filter(|(_, input)| input.address == session.address)
                {
                    if input.assets.len() != 1
                        || !selected_names.contains(input.assets[0].asset_name.as_slice())
                    {
                        return Err(reject(
                            "misbehaviour finalization consumes an unrelated session".to_string(),
                        ));
                    }
                    let redeemer =
                        spend_redeemer_for_input(body, redeemers, out_ref).map_err(reject)?;
                    if constructor_fields(redeemer, 2).is_none_or(|fields| !fields.is_empty()) {
                        return Err(reject(
                            "misbehaviour finalization must finalize both sessions".to_string(),
                        ));
                    }
                }
                let mint_redeemer =
                    mint_redeemer_for_policy(body, redeemers, &session.policy).map_err(reject)?;
                let burned_names = constructor_fields(mint_redeemer, 2)
                    .filter(|fields| fields.len() == 1)
                    .and_then(|fields| match &fields[0] {
                        PlutusData::Array(names) if names.len() == 2 => names
                            .iter()
                            .map(plutus_bytes)
                            .collect::<Option<BTreeSet<_>>>(),
                        _ => None,
                    });
                if burned_names.as_ref() != Some(&selected_names) {
                    return Err(reject(
                        "BurnSessions redeemer must select exactly the two consumed session NFTs"
                            .to_string(),
                    ));
                }
                let client_input = selected_state_input(
                    resolved_inputs,
                    &self.client_state,
                    &expected_client_name,
                )
                .ok_or_else(|| {
                    reject("misbehaviour finalization omits the selected client input".to_string())
                })?;
                let client_redeemer =
                    spend_redeemer_for_input(body, redeemers, client_input).map_err(reject)?;
                let client_names = constructor_fields(client_redeemer, 3)
                    .filter(|fields| match self.consensus_history_format {
                        ConsensusHistoryFormat::Legacy => fields.len() == 2,
                        ConsensusHistoryFormat::ProofBackedV1 => fields.len() == 3
                            && matches!(&fields[2], PlutusData::Array(witnesses) if witnesses.len() <= 2),
                    })
                    .and_then(|fields| {
                        fields
                            .iter()
                            .take(2)
                            .map(|field| {
                                plutus_auth_token(field)
                                    .filter(|(policy, _)| *policy == session.policy)
                                    .map(|(_, name)| name)
                            })
                            .collect::<Option<BTreeSet<_>>>()
                    });
                if client_names.as_ref() != Some(&selected_names) {
                    return Err(reject("FinalizeMisbehaviour redeemer must select exactly the two consumed session NFTs".to_string()));
                }
            }
        }
        Ok(())
    }

    fn session_spend_redeemer<'a, F>(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        redeemers: &'a pallas_primitives::conway::Redeemers,
        resolved_inputs: &ResolvedTransactionInputs,
        session: &StateOutputRoot,
        reject: &F,
    ) -> Result<&'a PlutusData, Error>
    where
        F: Fn(String) -> Error,
    {
        let mut inputs = resolved_inputs
            .regular
            .iter()
            .filter(|(_, input)| input.address == session.address)
            .map(|(out_ref, _)| out_ref);
        let input = inputs
            .next()
            .ok_or_else(|| reject("staged Tendermint session input is missing".to_string()))?;
        if inputs.next().is_some() {
            return Err(reject(
                "transaction consumes multiple staged Tendermint sessions".to_string(),
            ));
        }
        spend_redeemer_for_input(body, redeemers, input).map_err(reject)
    }

    fn validate_message_binding<F>(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        redeemers: Option<&pallas_primitives::conway::Redeemers>,
        signer_address: &[u8],
        intent: &SigningIntent,
        requirements: &OperationRequirements<'_>,
        resolved_inputs: &ResolvedTransactionInputs,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let redeemers = redeemers.ok_or_else(|| {
            reject(
                "transaction omits the script redeemers that bind the original IBC action"
                    .to_string(),
            )
        })?;

        if let Some(session) = requirements.tendermint_session.as_ref() {
            self.validate_tendermint_session_redeemers(
                body,
                redeemers,
                signer_address,
                intent,
                session,
                resolved_inputs,
                reject,
            )?;
            if !session.action.is_finalization() {
                return Ok(());
            }
        }

        let host_alternative = match intent.operation.as_str() {
            "HostStateHeartbeat" => 10,
            "/ibc.core.client.v1.MsgCreateClient" => 0,
            "/ibc.core.client.v1.MsgUpdateClient" | "/ibc.core.client.v1.MsgRecoverClient" => 4,
            "/ibc.core.connection.v1.MsgConnectionOpenInit"
            | "/ibc.core.connection.v1.MsgConnectionOpenTry" => 1,
            "/ibc.core.connection.v1.MsgConnectionOpenAck"
            | "/ibc.core.connection.v1.MsgConnectionOpenConfirm" => 5,
            "/ibc.core.channel.v1.MsgChannelOpenInit"
            | "/ibc.core.channel.v1.MsgChannelOpenTry" => 2,
            "/ibc.core.channel.v1.MsgChannelOpenAck"
            | "/ibc.core.channel.v1.MsgChannelOpenConfirm"
            | "/ibc.core.channel.v1.MsgChannelCloseInit"
            | "/ibc.core.channel.v1.MsgChannelCloseConfirm" => 6,
            "/ibc.core.channel.v1.MsgRecvPacket"
            | "/ibc.core.channel.v1.MsgTimeout"
            | "/ibc.core.channel.v1.MsgTimeoutOnClose"
            | "/ibc.core.channel.v1.MsgAcknowledgement"
            | "/ibc.applications.transfer.v1.MsgTransfer"
            | "/ibc.cardano.v1.MsgPrunePacketHistory" => 7,
            operation => {
                return Err(reject(format!(
                    "no HostState redeemer policy exists for {operation}"
                )))
            }
        };
        let host_input = resolved_inputs
            .regular
            .iter()
            .find(|(_, input)| input.address == self.host_state_address)
            .map(|(out_ref, _)| out_ref)
            .ok_or_else(|| reject("resolved HostState input is missing".to_string()))?;
        let host_redeemer =
            spend_redeemer_for_input(body, redeemers, host_input).map_err(reject)?;
        if constructor_fields(host_redeemer, host_alternative).is_none() {
            return Err(reject(format!(
                "HostState redeemer does not authorize the requested {} transition",
                intent.operation
            )));
        }

        let expected = match intent.operation.as_str() {
            "/ibc.core.client.v1.MsgUpdateClient" => {
                let expected = if intent.staged_misbehaviour {
                    ChannelRedeemerIntent::Constructor(3)
                } else if self.consensus_history_format == ConsensusHistoryFormat::ProofBackedV1 {
                    ChannelRedeemerIntent::ProofBackedClientUpdate
                } else {
                    ChannelRedeemerIntent::Constructor(0)
                };
                Some((&self.client_state, expected))
            }
            "/ibc.core.client.v1.MsgRecoverClient" => {
                let substitute_sequence = intent.recovery_substitute_sequence.ok_or_else(|| {
                    reject("recovery substitute client sequence is missing".to_string())
                })?;
                Some((
                    &self.client_state,
                    ChannelRedeemerIntent::ClientRecovery {
                        alternative: if self.tendermint_session.is_some() {
                            2
                        } else {
                            1
                        },
                        history_format: self.consensus_history_format,
                        substitute_policy: self.client_state.policy.clone(),
                        substitute_name: self
                            .state_token_name(StateOutputKind::Client, substitute_sequence),
                    },
                ))
            }
            "/ibc.core.connection.v1.MsgConnectionOpenAck" => Some((
                &self.connection_state,
                ChannelRedeemerIntent::Constructor(0),
            )),
            "/ibc.core.connection.v1.MsgConnectionOpenConfirm" => Some((
                &self.connection_state,
                ChannelRedeemerIntent::Constructor(1),
            )),
            "/ibc.core.channel.v1.MsgChannelOpenAck" => {
                Some((&self.channel_state, ChannelRedeemerIntent::Constructor(0)))
            }
            "/ibc.core.channel.v1.MsgChannelOpenConfirm" => {
                Some((&self.channel_state, ChannelRedeemerIntent::Constructor(1)))
            }
            "/ibc.core.channel.v1.MsgRecvPacket" => Some(ChannelRedeemerIntent::Packet {
                alternative: 2,
                packet: intent
                    .packet
                    .as_ref()
                    .expect("packet intent is decoded eagerly"),
                acknowledgement: None,
            })
            .map(|redeemer| (&self.channel_state, redeemer)),
            "/ibc.core.channel.v1.MsgTimeout" | "/ibc.core.channel.v1.MsgTimeoutOnClose" => {
                Some(ChannelRedeemerIntent::Packet {
                    alternative: 3,
                    packet: intent
                        .packet
                        .as_ref()
                        .expect("packet intent is decoded eagerly"),
                    acknowledgement: None,
                })
                .map(|redeemer| (&self.channel_state, redeemer))
            }
            "/ibc.core.channel.v1.MsgAcknowledgement" => Some((
                &self.channel_state,
                ChannelRedeemerIntent::Packet {
                    alternative: 4,
                    packet: intent
                        .packet
                        .as_ref()
                        .expect("packet intent is decoded eagerly"),
                    acknowledgement: intent.acknowledgement.as_deref(),
                },
            )),
            "/ibc.applications.transfer.v1.MsgTransfer" => intent
                .transfer
                .as_ref()
                .map(ChannelRedeemerIntent::OutboundTransfer)
                .map(|redeemer| (&self.channel_state, redeemer)),
            "/ibc.core.channel.v1.MsgChannelCloseInit" => {
                Some((&self.channel_state, ChannelRedeemerIntent::Constructor(6)))
            }
            "/ibc.core.channel.v1.MsgChannelCloseConfirm" => {
                Some((&self.channel_state, ChannelRedeemerIntent::Constructor(7)))
            }
            "/ibc.cardano.v1.MsgPrunePacketHistory" => intent
                .prune_sequence
                .map(ChannelRedeemerIntent::Prune)
                .map(|redeemer| (&self.channel_state, redeemer)),
            _ => None,
        };
        let Some((state, expected)) = expected else {
            return Ok(());
        };

        let sequence = intent.state_sequence.ok_or_else(|| {
            reject("message-selected protocol state sequence is missing".to_string())
        })?;
        let kind = if state.address == self.client_state.address {
            StateOutputKind::Client
        } else if state.address == self.connection_state.address {
            StateOutputKind::Connection
        } else {
            StateOutputKind::Channel
        };
        let token_name = self.state_token_name(kind, sequence);
        let state_inputs = resolved_inputs.regular.iter().filter(|(_, input)| {
            input.address == state.address
                && input.assets.iter().any(|asset| {
                    asset.policy_id.as_slice() == state.policy
                        && asset.asset_name == token_name
                        && asset.quantity == 1
                })
        });
        let mut state_inputs = state_inputs.map(|(out_ref, _)| out_ref);
        let state_input = state_inputs.next().ok_or_else(|| {
            reject("message-selected protocol state input is missing".to_string())
        })?;
        if state_inputs.next().is_some() {
            return Err(reject(
                "multiple inputs contain the message-selected protocol state token".to_string(),
            ));
        }
        let actual = spend_redeemer_for_input(body, redeemers, state_input).map_err(reject)?;
        if !expected.matches(actual) {
            return Err(reject(
                "redeemer attached to the message-selected protocol state input does not match the original IBC message"
                    .to_string(),
            ));
        }
        if intent.operation == "/ibc.core.client.v1.MsgRecoverClient" {
            let substitute_sequence = intent.recovery_substitute_sequence.ok_or_else(|| {
                reject("recovery substitute client sequence is missing".to_string())
            })?;
            let substitute_name =
                self.state_token_name(StateOutputKind::Client, substitute_sequence);
            self.validate_client_withdrawal_redeemer(
                redeemers,
                &token_name,
                Some(&substitute_name),
                false,
                reject,
            )?;
        } else if intent.operation == "/ibc.core.client.v1.MsgUpdateClient"
            && self.consensus_history_format == ConsensusHistoryFormat::ProofBackedV1
        {
            self.validate_client_withdrawal_redeemer(
                redeemers,
                &token_name,
                None,
                intent.staged_tendermint,
                reject,
            )?;
        }
        Ok(())
    }

    fn validate_client_withdrawal_redeemer<F>(
        &self,
        redeemers: &pallas_primitives::conway::Redeemers,
        subject_name: &[u8],
        substitute_name: Option<&[u8]>,
        staged: bool,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let mut rewards = redeemers
            .iter()
            .filter(|(key, _)| key.tag == pallas_primitives::conway::RedeemerTag::Reward);
        let (key, value) = rewards
            .next()
            .ok_or_else(|| reject("client transition has no withdrawal redeemer".to_string()))?;
        if rewards.next().is_some() || key.index != 0 {
            return Err(reject(
                "client transition must have exactly one withdrawal redeemer at index zero"
                    .to_string(),
            ));
        }
        // RecoverClientWithdrawal is constructor 0 with both requested clients;
        // CheckClientHistory (legacy) is constructor 1; staged history is constructor 4.
        // Both bind the requested subject.
        // Never accept the recovery branch as authorization for an ordinary update.
        let (alternative, arity) = if substitute_name.is_some() {
            (0, 2)
        } else if staged {
            (4, 1)
        } else {
            (1, 1)
        };
        let fields = constructor_fields(&value.data, alternative)
            .filter(|fields| fields.len() == arity)
            .ok_or_else(|| {
                reject("client transition withdrawal redeemer is malformed".to_string())
            })?;
        if !auth_token_matches(&fields[0], &self.client_state.policy, subject_name)
            || substitute_name.is_some_and(|name| {
                !auth_token_matches(&fields[1], &self.client_state.policy, name)
            })
        {
            return Err(reject(
                "client transition withdrawal redeemer does not match the requested clients"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_wallet_delta<F>(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        signer_address: &[u8],
        intent: &SigningIntent,
        resolved_inputs: &ResolvedTransactionInputs,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let mut input_lovelace = 0u128;
        let mut input_assets = BTreeMap::new();
        for input in resolved_inputs
            .regular
            .values()
            .filter(|input| input.address == signer_address)
        {
            input_lovelace = input_lovelace
                .checked_add(u128::from(input.lovelace))
                .ok_or_else(|| reject("signer input lovelace total overflows u128".to_string()))?;
            add_resolved_assets(&mut input_assets, input, reject)?;
        }

        let signer_outputs: Vec<_> = body
            .outputs
            .iter()
            .map(unpack_output)
            .filter(|output| output.address == signer_address)
            .collect();
        let output_lovelace = signer_outputs.iter().try_fold(0u128, |total, output| {
            total
                .checked_add(u128::from(output.coin))
                .ok_or_else(|| reject("signer output lovelace total overflows u128".to_string()))
        })?;
        let output_assets =
            aggregate_output_assets(signer_outputs.iter(), reject, "signer outputs")?;

        let authorized_asset_loss = intent.transfer.as_ref().and_then(|transfer| {
            if transfer.action != TransferAction::Send {
                return None;
            }
            match expected_asset(transfer) {
                ExpectedAsset::Lovelace => None,
                ExpectedAsset::Native(policy, name) => Some(((policy, name), transfer.amount)),
                ExpectedAsset::Voucher {
                    user_name: Some(name),
                    ..
                } => Some(((self.voucher_policy.clone(), name), transfer.amount)),
                ExpectedAsset::Voucher {
                    user_name: None, ..
                } => None,
            }
        });

        let asset_ids: BTreeSet<_> = input_assets
            .keys()
            .chain(output_assets.keys())
            .cloned()
            .collect();
        for asset_id in asset_ids {
            let input = input_assets.get(&asset_id).copied().unwrap_or_default();
            let output = output_assets.get(&asset_id).copied().unwrap_or_default();
            let Some(loss) = input.checked_sub(output) else {
                continue;
            };
            if loss == 0 {
                continue;
            }
            let authorized = authorized_asset_loss
                .as_ref()
                .is_some_and(|(expected, amount)| {
                    expected == &asset_id && loss <= u128::from(*amount)
                });
            if !authorized {
                return Err(reject(format!(
                    "transaction removes {loss} units of unauthorized signer asset {}.{}",
                    hex::encode(&asset_id.0),
                    hex::encode(&asset_id.1)
                )));
            }
        }

        let lovelace_loss = input_lovelace.saturating_sub(output_lovelace);
        let requested_lovelace = intent
            .transfer
            .as_ref()
            .filter(|transfer| transfer.action == TransferAction::Send)
            .filter(|transfer| matches!(expected_asset(transfer), ExpectedAsset::Lovelace))
            .map_or(0, |transfer| transfer.amount);
        let maximum_lovelace_loss = body
            .fee
            .checked_add(self.limits.max_wallet_lovelace_top_up)
            .and_then(|value| value.checked_add(requested_lovelace))
            .ok_or_else(|| reject("authorized signer lovelace loss overflows u64".to_string()))?;
        if lovelace_loss > u128::from(maximum_lovelace_loss) {
            return Err(reject(format!(
                "transaction removes {lovelace_loss} lovelace from the signer, exceeding the fee, requested transfer, and configured top-up allowance of {maximum_lovelace_loss}"
            )));
        }

        Ok(())
    }

    fn validate_outputs<F>(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        signer_address: &[u8],
        intent: &SigningIntent,
        requirements: &OperationRequirements<'_>,
        reference_inputs: &HashSet<OutRef>,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let outputs: Vec<_> = body.outputs.iter().map(unpack_output).collect();
        let mut host_state_nft_quantity = 0u64;
        let mut external_output_count = 0usize;
        let mut state_output_count = 0usize;
        let mut module_output_count = 0usize;
        let mut module_main_output_count = 0usize;
        let mut module_escrow_output_count = 0usize;
        let mut trace_registry_output_count = 0usize;
        let mut voucher_metadata_output_count = 0usize;
        let mut tendermint_session_output_count = 0usize;
        let mut protocol_lovelace = 0u64;

        let expected_state = match requirements.state_output {
            StateOutputKind::None => None,
            StateOutputKind::Client => Some(&self.client_state),
            StateOutputKind::Connection => Some(&self.connection_state),
            StateOutputKind::Channel => Some(&self.channel_state),
        };
        let expected_state_name = intent
            .state_sequence
            .zip(expected_state)
            .map(|(sequence, _)| self.state_token_name(requirements.state_output, sequence));
        let expected_session = requirements
            .tendermint_session
            .as_ref()
            .zip(self.tendermint_session.as_ref());
        let expected_asset = intent.transfer.as_ref().map(expected_asset);
        let reference_voucher_name = match expected_asset.as_ref() {
            Some(ExpectedAsset::Voucher {
                reference_name: Some(name),
                ..
            }) => Some(name),
            _ => None,
        };
        let reference_voucher_minted = reference_voucher_name
            .is_some_and(|name| minted_quantity(body, &self.voucher_policy, name) == 1);

        if let Some(external) = intent.external_output.as_ref() {
            if self
                .protocol_addresses
                .contains(external.address.as_slice())
            {
                return Err(reject(
                    "IBC transfer destination is a pinned protocol address".to_string(),
                ));
            }
        }

        for output in &outputs {
            validate_address_network(&output.address, self.network_id).map_err(reject)?;
            if output.has_script_ref {
                return Err(reject(
                    "transaction outputs may not install scripts".to_string(),
                ));
            }

            for (policy, name, quantity) in &output.assets {
                if policy == &self.host_state_nft_policy && name == &self.host_state_nft_name {
                    if output.address != self.host_state_address {
                        return Err(reject(
                            "HostState NFT is moved away from its pinned validator".to_string(),
                        ));
                    }
                    host_state_nft_quantity = host_state_nft_quantity
                        .checked_add(*quantity)
                        .ok_or_else(|| reject("HostState NFT quantity overflow".to_string()))?;
                }
            }

            let exact_external = intent.external_output.as_ref().is_some_and(|external| {
                output.address == external.address
                    && self
                        .validate_external_value(output, &external.transfer, body, reject)
                        .is_ok()
            });
            if exact_external {
                external_output_count += 1;
                if external_output_count > 1 {
                    return Err(reject(
                        "requested external payment appears in multiple outputs".to_string(),
                    ));
                }
            }

            if output.address == signer_address {
                continue;
            }

            if output.address == self.host_state_address {
                if !requirements.requires_host_state {
                    return Err(reject(
                        "tree-neutral staged Tendermint transaction creates a HostState output"
                            .to_string(),
                    ));
                }
                if !is_exact_state_output(
                    output,
                    &self.host_state_nft_policy,
                    Some(&self.host_state_nft_name),
                ) {
                    return Err(reject(
                        "HostState output contains unauthorized assets or lacks its NFT"
                            .to_string(),
                    ));
                }
                protocol_lovelace = checked_protocol_coin(protocol_lovelace, output.coin, reject)?;
                continue;
            }

            if self
                .tendermint_session
                .as_ref()
                .is_some_and(|session| output.address == session.address)
            {
                let (requirement, session) = expected_session.ok_or_else(|| {
                    reject(
                        "transaction creates a staged Tendermint session output without a staged intent"
                            .to_string(),
                    )
                })?;
                if !matches!(
                    requirement.action,
                    TendermintSessionAction::Initialize | TendermintSessionAction::Advance
                ) || !is_exact_state_output(
                    output,
                    &session.policy,
                    Some(&requirement.token_name),
                ) || !output.has_inline_datum
                {
                    return Err(reject(
                        "staged Tendermint session output must preserve exactly one session NFT and an inline datum"
                            .to_string(),
                    ));
                }
                tendermint_session_output_count += 1;
                if tendermint_session_output_count > 1 {
                    return Err(reject(
                        "transaction creates multiple staged Tendermint session outputs"
                            .to_string(),
                    ));
                }
                protocol_lovelace = checked_protocol_coin(protocol_lovelace, output.coin, reject)?;
                continue;
            }

            if output.address == self.client_state.address
                || output.address == self.connection_state.address
                || output.address == self.channel_state.address
            {
                let state = expected_state.filter(|state| state.address == output.address).ok_or_else(
                    || reject("transaction creates a protocol state output unrelated to the requested operation".to_string()),
                )?;
                if !is_exact_state_output(output, &state.policy, expected_state_name.as_deref()) {
                    return Err(reject(
                        "protocol state output does not contain the exact state token authorized by the IBC message"
                            .to_string(),
                    ));
                }
                state_output_count += 1;
                if state_output_count > 1 {
                    return Err(reject(
                        "transaction creates multiple protocol state outputs".to_string(),
                    ));
                }
                protocol_lovelace = checked_protocol_coin(protocol_lovelace, output.coin, reject)?;
                continue;
            }

            if self
                .modules
                .values()
                .any(|module| module.address == output.address)
            {
                let module = requirements.module.filter(|module| module.address == output.address).ok_or_else(
                    || reject("transaction pays a protocol module unrelated to the requested operation".to_string()),
                )?;
                let is_main_module = output.assets.iter().any(|(policy, name, quantity)| {
                    policy == &module.identifier_policy
                        && name == &module.identifier_name
                        && *quantity == 1
                });
                let escrow_markers = output
                    .assets
                    .iter()
                    .filter(|(policy, _, quantity)| {
                        policy == &self.transfer_escrow_policy && *quantity == 1
                    })
                    .count();

                if is_main_module {
                    if !output.assets.iter().all(|(policy, _, quantity)| {
                        self.module_identity_policies.contains(policy) && *quantity == 1
                    }) {
                        return Err(reject(
                            "module state output contains assets outside pinned module identities"
                                .to_string(),
                        ));
                    }
                    module_main_output_count += 1;
                    protocol_lovelace =
                        checked_protocol_coin(protocol_lovelace, output.coin, reject)?;
                } else if module.reference_script == "spendtransfermodule" && escrow_markers == 1 {
                    let transfer = intent.transfer.as_ref().ok_or_else(|| {
                        reject(
                            "transfer escrow output is not authorized by this IBC message"
                                .to_string(),
                        )
                    })?;
                    self.validate_transfer_escrow_value(output, transfer, reject)?;
                    module_escrow_output_count += 1;
                } else {
                    return Err(reject(
                        "protocol module output lacks its pinned identity or escrow marker"
                            .to_string(),
                    ));
                }

                module_output_count += 1;
                if module_main_output_count > 1
                    || module_escrow_output_count > 1
                    || module_output_count > 2
                {
                    return Err(reject(
                        "transaction creates too many protocol module outputs".to_string(),
                    ));
                }
                continue;
            }

            if output.address == self.trace_registry_address {
                if !reference_voucher_minted
                    || output.assets.is_empty()
                    || !output.assets.iter().all(|(policy, _, quantity)| {
                        policy == &self.trace_registry_policy && *quantity == 1
                    })
                {
                    return Err(reject(
                        "trace-registry output is not authorized by a first-seen voucher mint"
                            .to_string(),
                    ));
                }
                let root = required_script(&self.scripts, "spendtraceregistry").map_err(reject)?;
                if !reference_inputs.contains(&root.reference) {
                    return Err(reject(
                        "trace-registry output is missing its pinned spend reference script"
                            .to_string(),
                    ));
                }
                trace_registry_output_count += 1;
                if trace_registry_output_count > 3 {
                    return Err(reject(
                        "transaction creates too many trace-registry outputs".to_string(),
                    ));
                }
                protocol_lovelace = checked_protocol_coin(protocol_lovelace, output.coin, reject)?;
                continue;
            }

            if output.address == self.voucher_metadata_address {
                let Some(reference_name) = reference_voucher_name else {
                    return Err(reject(
                        "voucher metadata output is not authorized by this IBC message".to_string(),
                    ));
                };
                if !reference_voucher_minted
                    || output.assets.len() != 1
                    || output.assets[0] != (self.voucher_policy.clone(), reference_name.clone(), 1)
                {
                    return Err(reject(
                        "voucher metadata output does not contain the expected reference NFT"
                            .to_string(),
                    ));
                }
                voucher_metadata_output_count += 1;
                if voucher_metadata_output_count > 1 {
                    return Err(reject(
                        "transaction creates multiple voucher metadata outputs".to_string(),
                    ));
                }
                protocol_lovelace = checked_protocol_coin(protocol_lovelace, output.coin, reject)?;
                continue;
            }

            let external = intent.external_output.as_ref().ok_or_else(|| {
                reject(format!(
                    "output pays unauthorized address {}",
                    hex::encode(&output.address)
                ))
            })?;
            if output.address != external.address {
                return Err(reject(format!(
                    "output pays unauthorized address {}",
                    hex::encode(&output.address)
                )));
            }
            if !exact_external {
                return Err(reject(
                    "external output value does not exactly match the authorized IBC payment"
                        .to_string(),
                ));
            }
        }

        let expected_host_state_quantity = u64::from(requirements.requires_host_state);
        if host_state_nft_quantity != expected_host_state_quantity {
            return Err(reject(format!(
                "expected {expected_host_state_quantity} HostState NFTs in outputs, found {host_state_nft_quantity}"
            )));
        }
        if expected_state.is_some() && state_output_count != 1 {
            return Err(reject(
                "transaction omits the protocol state output required by this IBC operation"
                    .to_string(),
            ));
        }
        let expected_session_outputs = usize::from(
            requirements
                .tendermint_session
                .as_ref()
                .is_some_and(|session| {
                    matches!(
                        session.action,
                        TendermintSessionAction::Initialize | TendermintSessionAction::Advance
                    )
                }),
        );
        if tendermint_session_output_count != expected_session_outputs {
            return Err(reject(format!(
                "expected {expected_session_outputs} staged Tendermint session outputs, found {tendermint_session_output_count}"
            )));
        }
        if requirements.module.is_some() && module_output_count == 0 {
            return Err(reject(
                "transaction omits the module state output required by this IBC operation"
                    .to_string(),
            ));
        }
        let escrow_required = intent.transfer.as_ref().is_some_and(|transfer| {
            transfer.action == TransferAction::Send
                && voucher_mint_action(transfer) != Some(VoucherMintAction::Burn)
        });
        if escrow_required && module_escrow_output_count != 1 {
            return Err(reject(
                "outbound transfer omits its uniquely authorized escrow output".to_string(),
            ));
        }
        if reference_voucher_minted
            && (trace_registry_output_count == 0 || voucher_metadata_output_count != 1)
        {
            return Err(reject(
                "first-seen voucher mint omits its trace registry or metadata output".to_string(),
            ));
        }
        if protocol_lovelace > self.limits.max_total_protocol_output_lovelace {
            return Err(reject(format!(
                "non-escrow protocol outputs carry {protocol_lovelace} lovelace, exceeding {}",
                self.limits.max_total_protocol_output_lovelace
            )));
        }
        if intent
            .external_output
            .as_ref()
            .is_some_and(|external| external.required)
            && external_output_count != 1
        {
            return Err(reject(
                "transaction omits the external payment required by the IBC packet".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_transfer_escrow_value<F>(
        &self,
        output: &OutputValue,
        transfer: &TransferIntent,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let marker_count = output
            .assets
            .iter()
            .filter(|(policy, _, quantity)| {
                policy == &self.transfer_escrow_policy && *quantity == 1
            })
            .count();
        if marker_count != 1 {
            return Err(reject(
                "transfer escrow output must contain exactly one pinned shard marker".to_string(),
            ));
        }

        let expected = expected_asset(transfer);
        let expected_unit = match &expected {
            ExpectedAsset::Lovelace => None,
            ExpectedAsset::Native(policy, name) => Some((policy.as_slice(), name.as_slice())),
            ExpectedAsset::Voucher {
                user_name: Some(name),
                ..
            } => Some((self.voucher_policy.as_slice(), name.as_slice())),
            ExpectedAsset::Voucher {
                user_name: None, ..
            } => {
                return Err(reject(
                    "cannot derive the voucher asset authorized for transfer escrow".to_string(),
                ))
            }
        };

        let mut expected_quantity = None;
        for (policy, name, quantity) in &output.assets {
            if policy == &self.transfer_escrow_policy {
                continue;
            }
            if expected_unit.is_none_or(|(expected_policy, expected_name)| {
                policy.as_slice() != expected_policy || name.as_slice() != expected_name
            }) {
                return Err(reject(
                    "transfer escrow output contains an asset unrelated to the requested denomination"
                        .to_string(),
                ));
            }
            if expected_quantity.replace(*quantity).is_some() {
                return Err(reject(
                    "transfer escrow output repeats the requested denomination".to_string(),
                ));
            }
        }

        match expected {
            ExpectedAsset::Lovelace => {
                if output.assets.len() != 1 {
                    return Err(reject(
                        "lovelace escrow output contains an unrelated native asset".to_string(),
                    ));
                }
                if transfer.action == TransferAction::Send && output.coin < transfer.amount {
                    return Err(reject(
                        "lovelace escrow output contains less than the requested transfer"
                            .to_string(),
                    ));
                }
            }
            _ => {
                if output.assets.len() > 2 {
                    return Err(reject(
                        "transfer escrow output contains too many native assets".to_string(),
                    ));
                }
                if transfer.action == TransferAction::Send
                    && expected_quantity.is_none_or(|quantity| quantity < transfer.amount)
                {
                    return Err(reject(
                        "transfer escrow output contains less than the requested asset amount"
                            .to_string(),
                    ));
                }
                if output.coin > self.limits.max_external_output_lovelace {
                    return Err(reject(format!(
                        "transfer escrow output carries {} lovelace, exceeding the non-lovelace allowance {}",
                        output.coin, self.limits.max_external_output_lovelace
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_external_value<F>(
        &self,
        output: &OutputValue,
        transfer: &TransferIntent,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let expected = expected_asset(transfer);
        match expected {
            ExpectedAsset::Lovelace => {
                if !output.assets.is_empty() || output.coin != transfer.amount {
                    return Err(reject(format!(
                        "external lovelace output must equal requested amount {}",
                        transfer.amount
                    )));
                }
            }
            ExpectedAsset::Native(policy, name) => {
                if output.coin > self.limits.max_external_output_lovelace
                    || output.assets.len() != 1
                    || output.assets[0] != (policy.clone(), name.clone(), transfer.amount)
                {
                    return Err(reject(
                        "external native-asset output does not match the requested denomination and amount"
                            .to_string(),
                    ));
                }
            }
            ExpectedAsset::Voucher { user_name, .. } => {
                if output.coin > self.limits.max_external_output_lovelace
                    || output.assets.len() != 1
                {
                    return Err(reject(
                        "external voucher output contains excess lovelace or unrelated assets"
                            .to_string(),
                    ));
                }
                let (policy, name, quantity) = &output.assets[0];
                if policy != &self.voucher_policy
                    || user_name.as_ref() != Some(name)
                    || *quantity != transfer.amount
                {
                    return Err(reject(
                        "external voucher output does not match the requested denomination and amount"
                            .to_string(),
                    ));
                }
                let minted = minted_quantity(body, policy, name);
                if minted != i128::from(transfer.amount) {
                    return Err(reject(
                        "external voucher payment is not covered by the transaction mint"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn classify_tendermint_session_transaction(
    body: &pallas_primitives::conway::MintedTransactionBody<'_>,
    resolved_inputs: &ResolvedTransactionInputs,
    session: &StateOutputRoot,
    host_state_address: &[u8],
    client_address: &[u8],
) -> Result<ValidatedTendermintSessionAction, String> {
    let mut input_names = Vec::new();
    for input in resolved_inputs.regular.values() {
        if input.address != session.address {
            continue;
        }
        if input.assets.len() != 1
            || input.assets[0].policy_id.as_slice() != session.policy
            || input.assets[0].quantity != 1
        {
            return Err(
                "staged Tendermint session input does not contain exactly one pinned session NFT"
                    .to_string(),
            );
        }
        input_names.push(input.assets[0].asset_name.clone());
    }

    let mut output_names = Vec::new();
    for output in body.outputs.iter().map(unpack_output) {
        if output.address != session.address {
            continue;
        }
        if output.assets.len() != 1
            || output.assets[0].0 != session.policy
            || output.assets[0].2 != 1
        {
            return Err(
                "staged Tendermint session output does not contain exactly one pinned session NFT"
                    .to_string(),
            );
        }
        output_names.push(output.assets[0].1.clone());
    }

    let mut mint_entries = Vec::new();
    if let Some(mint) = body.mint.as_ref() {
        for (policy, assets) in mint.iter() {
            if policy.as_ref() != session.policy {
                continue;
            }
            mint_entries.extend(
                assets
                    .iter()
                    .map(|(name, quantity)| (name.as_slice().to_vec(), i64::from(quantity))),
            );
        }
    }

    for name in input_names
        .iter()
        .chain(output_names.iter())
        .chain(mint_entries.iter().map(|(name, _)| name))
    {
        if name.len() != TENDERMINT_SESSION_TOKEN_NAME_BYTES {
            return Err(format!(
                "staged Tendermint session token name must contain {TENDERMINT_SESSION_TOKEN_NAME_BYTES} bytes"
            ));
        }
    }

    let has_finalization_input = resolved_inputs
        .regular
        .values()
        .any(|input| input.address == host_state_address || input.address == client_address);

    // Two sessions are allowed only when both are consumed and burned by one
    // finalization. The request and exact script redeemers are checked below.
    if input_names.len() == 2
        && input_names[0] != input_names[1]
        && output_names.is_empty()
        && mint_entries.len() == 2
        && mint_entries[0].0 != mint_entries[1].0
        && mint_entries
            .iter()
            .all(|(name, quantity)| *quantity == -1 && input_names.contains(name))
        && has_finalization_input
    {
        input_names.sort();
        return Ok(ValidatedTendermintSessionAction {
            action: TendermintSessionAction::FinalizeMisbehaviour,
            token_name: input_names[0].clone(),
            second_token_name: Some(input_names[1].clone()),
        });
    }
    if input_names.len() > 1 || output_names.len() > 1 || mint_entries.len() > 1 {
        return Err(
            "staged Tendermint transaction contains unauthorized multiple session NFTs".to_string(),
        );
    }

    let (action, token_name) = match (
        input_names.as_slice(),
        output_names.as_slice(),
        mint_entries.as_slice(),
    ) {
        ([], [output], [(minted, 1)]) if output == minted => {
            (TendermintSessionAction::Initialize, output.clone())
        }
        ([input], [output], []) if input == output => {
            (TendermintSessionAction::Advance, input.clone())
        }
        ([input], [], [(burned, -1)]) if input == burned => {
            (
                if has_finalization_input {
                    TendermintSessionAction::Finalize
                } else {
                    TendermintSessionAction::Cancel
                },
                input.clone(),
            )
        }
        _ => {
            return Err(
                "transaction is not an exact staged Tendermint init, advance, cancel, or finalize shape"
                    .to_string(),
            )
        }
    };

    Ok(ValidatedTendermintSessionAction {
        action,
        token_name,
        second_token_name: None,
    })
}

fn constructor_fields(data: &PlutusData, alternative: u64) -> Option<&[PlutusData]> {
    let PlutusData::Constr(constructor) = data else {
        return None;
    };
    (constructor_alternative(constructor) == Some(alternative))
        .then_some(constructor.fields.as_slice())
}

fn constructor_alternative(
    constructor: &pallas_primitives::alonzo::Constr<PlutusData>,
) -> Option<u64> {
    match constructor.tag {
        121..=127 => Some(constructor.tag - 121),
        1280..=1400 => Some(constructor.tag - 1280 + 7),
        102 => constructor.any_constructor,
        _ => None,
    }
}

fn plutus_bytes(data: &PlutusData) -> Option<&[u8]> {
    let PlutusData::BoundedBytes(bytes) = data else {
        return None;
    };
    Some(bytes.as_slice())
}

fn history_siblings_shape(data: &PlutusData, allow_empty: bool) -> bool {
    let PlutusData::Array(siblings) = data else {
        return false;
    };
    (allow_empty && siblings.is_empty())
        || (siblings.len() == 64
            && siblings
                .iter()
                .all(|sibling| plutus_bytes(sibling).is_some_and(|bytes| bytes.len() == 32)))
}

fn plutus_u64(data: &PlutusData) -> Option<u64> {
    let PlutusData::BigInt(BigInt::Int(value)) = data else {
        return None;
    };
    u64::try_from(i128::from(*value)).ok()
}

fn auth_token_matches(data: &PlutusData, policy: &[u8], name: &[u8]) -> bool {
    constructor_fields(data, 0)
        .filter(|fields| fields.len() == 2)
        .is_some_and(|fields| {
            fields.first().and_then(plutus_bytes) == Some(policy)
                && fields.get(1).and_then(plutus_bytes) == Some(name)
        })
}

fn plutus_height(data: &PlutusData) -> Option<(u64, u64)> {
    let fields = constructor_fields(data, 0)?;
    Some((plutus_u64(fields.first()?)?, plutus_u64(fields.get(1)?)?))
}

fn packet_fields(data: &PlutusData) -> Option<&[PlutusData]> {
    let fields = constructor_fields(data, 0)?;
    (fields.len() == 8).then_some(fields)
}

fn packet_plutus_matches(data: &PlutusData, expected: &PacketIntent) -> bool {
    let Some(fields) = packet_fields(data) else {
        return false;
    };
    plutus_u64(&fields[0]) == Some(expected.sequence)
        && plutus_bytes(&fields[1]) == Some(expected.source_port.as_bytes())
        && plutus_bytes(&fields[2]) == Some(expected.source_channel.as_bytes())
        && plutus_bytes(&fields[3]) == Some(expected.destination_port.as_bytes())
        && plutus_bytes(&fields[4]) == Some(expected.destination_channel.as_bytes())
        && plutus_bytes(&fields[5]) == Some(expected.data.as_slice())
        && plutus_height(&fields[6])
            == Some((
                expected.timeout_revision_number,
                expected.timeout_revision_height,
            ))
        && plutus_u64(&fields[7]) == Some(expected.timeout_timestamp)
}

fn outbound_transfer_packet_matches(data: &PlutusData, transfer: &TransferIntent) -> bool {
    let Some(fields) = packet_fields(data) else {
        return false;
    };
    let Some(packet_data) = plutus_bytes(&fields[5])
        .and_then(|bytes| serde_json::from_slice::<Ics20PacketData>(bytes).ok())
    else {
        return false;
    };
    let Some(expected_denom) = outbound_packet_denom(transfer) else {
        return false;
    };
    plutus_u64(&fields[0]).is_some_and(|sequence| sequence > 0)
        && transfer
            .source_port
            .as_deref()
            .is_some_and(|port| plutus_bytes(&fields[1]) == Some(port.as_bytes()))
        && transfer
            .source_channel
            .as_deref()
            .is_some_and(|channel| plutus_bytes(&fields[2]) == Some(channel.as_bytes()))
        && plutus_bytes(&fields[3]).is_some_and(|port| !port.is_empty())
        && plutus_bytes(&fields[4]).is_some_and(|channel| !channel.is_empty())
        && packet_data.denom == expected_denom
        && packet_data.amount == transfer.amount.to_string()
        && packet_data.sender == transfer.sender
        && packet_data.receiver == transfer.receiver
        && packet_data.memo == transfer.memo
        && plutus_height(&fields[6])
            == Some((
                transfer.timeout_revision_number,
                transfer.timeout_revision_height,
            ))
        && plutus_u64(&fields[7]) == Some(transfer.timeout_timestamp)
}

fn outbound_packet_denom(transfer: &TransferIntent) -> Option<String> {
    let denom = transfer.denom.trim();
    if denom.is_empty() || denom.starts_with("ibc/") {
        return None;
    }
    if denom.eq_ignore_ascii_case(LOVELACE) {
        return Some(LOVELACE_HEX.to_string());
    }
    let source_prefix = transfer
        .source_port
        .as_deref()
        .zip(transfer.source_channel.as_deref())
        .map(|(port, channel)| format!("{port}/{channel}/"));
    if source_prefix
        .as_deref()
        .is_some_and(|prefix| denom.starts_with(prefix))
        || is_cardano_token_unit(denom)
    {
        return Some(denom.to_string());
    }
    if denom.len() % 2 == 0 && denom.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex::encode(denom.as_bytes()))
}

fn is_cardano_token_unit(denom: &str) -> bool {
    (56..=120).contains(&denom.len())
        && denom.len() % 2 == 0
        && denom.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl SigningIntent {
    pub(crate) fn is_staged_tendermint(&self) -> bool {
        self.staged_tendermint
    }

    pub fn trace_registry_prelude(
        message: &[u8],
        expected_signer: &str,
        network_id: u8,
    ) -> Result<Self, Error> {
        let mut intent = Self::ibc(
            "/ibc.core.channel.v1.MsgRecvPacket",
            message,
            expected_signer,
            network_id,
        )?;
        intent.operation = "TraceRegistryPrelude".to_string();
        Ok(intent)
    }

    pub fn heartbeat(signer: &str, expected_signer: &str, network_id: u8) -> Result<Self, Error> {
        validate_request_signer(signer, expected_signer, network_id, "HostStateHeartbeat")?;
        Ok(Self {
            operation: "HostStateHeartbeat".to_string(),
            module_port: None,
            external_output: None,
            transfer: None,
            state_sequence: None,
            recovery_substitute_sequence: None,
            packet: None,
            acknowledgement: None,
            prune_sequence: None,
            staged_tendermint: false,
            staged_misbehaviour: false,
        })
    }

    /// Build the signing intent shared by every transaction in one staged
    /// Tendermint update. The nested client message is checked here so this
    /// policy cannot accidentally authorize staged transactions for another
    /// light-client implementation.
    pub fn staged_tendermint_update(
        type_url: &str,
        message: &[u8],
        expected_signer: &str,
        network_id: u8,
    ) -> Result<Self, Error> {
        if type_url != "/ibc.core.client.v1.MsgUpdateClient" {
            return Err(Error::Signer(
                "staged Tendermint signing requires MsgUpdateClient".to_string(),
            ));
        }
        let update = MsgUpdateClient::decode(message).map_err(decode_error)?;
        let header = update.client_message.as_ref().ok_or_else(|| {
            Error::Signer("staged Tendermint update has no client message".to_string())
        })?;
        if !matches!(
            header.type_url.as_str(),
            TENDERMINT_HEADER_TYPE_URL | TENDERMINT_MISBEHAVIOR_TYPE_URL
        ) {
            return Err(Error::Signer(format!(
                "staged Tendermint update has unsupported client message type {}",
                header.type_url
            )));
        }

        let mut intent = Self::ibc(type_url, message, expected_signer, network_id)?;
        intent.staged_tendermint = true;
        intent.staged_misbehaviour = header.type_url == TENDERMINT_MISBEHAVIOR_TYPE_URL;
        Ok(intent)
    }

    pub fn ibc(
        type_url: &str,
        message: &[u8],
        expected_signer: &str,
        network_id: u8,
    ) -> Result<Self, Error> {
        let mut external_output = None;
        let mut transfer = None;
        let mut module_port = None;
        let mut state_sequence = None;
        let mut recovery_substitute_sequence = None;
        let mut packet_intent = None;
        let mut acknowledgement = None;
        let mut prune_sequence = None;

        let signer = match type_url {
            "/ibc.core.client.v1.MsgCreateClient" => {
                MsgCreateClient::decode(message)
                    .map_err(decode_error)?
                    .signer
            }
            "/ibc.core.client.v1.MsgUpdateClient" => {
                let msg = MsgUpdateClient::decode(message).map_err(decode_error)?;
                state_sequence = Some(parse_identifier_sequence(&msg.client_id, None)?);
                msg.signer
            }
            "/ibc.core.client.v1.MsgRecoverClient" => {
                let msg = MsgRecoverClient::decode(message).map_err(decode_error)?;
                let subject_sequence =
                    parse_identifier_sequence(&msg.subject_client_id, Some("07-tendermint"))?;
                let substitute_sequence =
                    parse_identifier_sequence(&msg.substitute_client_id, Some("07-tendermint"))?;
                if subject_sequence == substitute_sequence {
                    return Err(Error::Signer(
                        "recovery subject and substitute clients must be different".to_string(),
                    ));
                }
                state_sequence = Some(subject_sequence);
                recovery_substitute_sequence = Some(substitute_sequence);
                msg.signer
            }
            "/ibc.core.connection.v1.MsgConnectionOpenInit" => {
                MsgConnectionOpenInit::decode(message)
                    .map_err(decode_error)?
                    .signer
            }
            "/ibc.core.connection.v1.MsgConnectionOpenTry" => {
                MsgConnectionOpenTry::decode(message)
                    .map_err(decode_error)?
                    .signer
            }
            "/ibc.core.connection.v1.MsgConnectionOpenAck" => {
                let msg = MsgConnectionOpenAck::decode(message).map_err(decode_error)?;
                state_sequence = Some(parse_identifier_sequence(
                    &msg.connection_id,
                    Some("connection"),
                )?);
                msg.signer
            }
            "/ibc.core.connection.v1.MsgConnectionOpenConfirm" => {
                let msg = MsgConnectionOpenConfirm::decode(message).map_err(decode_error)?;
                state_sequence = Some(parse_identifier_sequence(
                    &msg.connection_id,
                    Some("connection"),
                )?);
                msg.signer
            }
            "/ibc.core.channel.v1.MsgChannelOpenInit" => {
                let msg = MsgChannelOpenInit::decode(message).map_err(decode_error)?;
                module_port = Some(validate_module_port(&msg.port_id)?);
                msg.signer
            }
            "/ibc.core.channel.v1.MsgChannelOpenTry" => {
                let msg = MsgChannelOpenTry::decode(message).map_err(decode_error)?;
                module_port = Some(validate_module_port(&msg.port_id)?);
                msg.signer
            }
            "/ibc.core.channel.v1.MsgChannelOpenAck" => {
                let msg = MsgChannelOpenAck::decode(message).map_err(decode_error)?;
                module_port = Some(validate_module_port(&msg.port_id)?);
                state_sequence = Some(parse_identifier_sequence(&msg.channel_id, Some("channel"))?);
                msg.signer
            }
            "/ibc.core.channel.v1.MsgChannelOpenConfirm" => {
                let msg = MsgChannelOpenConfirm::decode(message).map_err(decode_error)?;
                module_port = Some(validate_module_port(&msg.port_id)?);
                state_sequence = Some(parse_identifier_sequence(&msg.channel_id, Some("channel"))?);
                msg.signer
            }
            "/ibc.core.channel.v1.MsgChannelCloseInit" => {
                let msg = MsgChannelCloseInit::decode(message).map_err(decode_error)?;
                module_port = Some(validate_module_port(&msg.port_id)?);
                state_sequence = Some(parse_identifier_sequence(&msg.channel_id, Some("channel"))?);
                msg.signer
            }
            "/ibc.core.channel.v1.MsgChannelCloseConfirm" => {
                let msg = MsgChannelCloseConfirm::decode(message).map_err(decode_error)?;
                module_port = Some(validate_module_port(&msg.port_id)?);
                state_sequence = Some(parse_identifier_sequence(&msg.channel_id, Some("channel"))?);
                msg.signer
            }
            "/ibc.core.channel.v1.MsgRecvPacket" => {
                let msg = MsgRecvPacket::decode(message).map_err(decode_error)?;
                let packet = msg
                    .packet
                    .as_ref()
                    .ok_or_else(|| Error::Signer("MsgRecvPacket has no packet".to_string()))?;
                module_port = Some(validate_module_port(&packet.destination_port)?);
                state_sequence = Some(parse_identifier_sequence(
                    &packet.destination_channel,
                    Some("channel"),
                )?);
                packet_intent = Some(PacketIntent::from_packet(packet));
                if packet.destination_port == "transfer" {
                    let packet_data = parse_packet_data(&packet.data)?;
                    let item = transfer_intent(packet, &packet_data, TransferAction::Receive)?;
                    external_output = Some(ExternalOutputIntent {
                        address: decode_address(&packet_data.receiver, network_id)
                            .map_err(Error::Signer)?,
                        transfer: item.clone(),
                        required: true,
                    });
                    transfer = Some(item);
                }
                msg.signer
            }
            "/ibc.core.channel.v1.MsgAcknowledgement" => {
                let msg = MsgAcknowledgement::decode(message).map_err(decode_error)?;
                let packet = msg
                    .packet
                    .as_ref()
                    .ok_or_else(|| Error::Signer("MsgAcknowledgement has no packet".to_string()))?;
                module_port = Some(validate_module_port(&packet.source_port)?);
                state_sequence = Some(parse_identifier_sequence(
                    &packet.source_channel,
                    Some("channel"),
                )?);
                packet_intent = Some(PacketIntent::from_packet(packet));
                acknowledgement = Some(msg.acknowledgement.clone());
                if packet.source_port == "transfer"
                    && acknowledgement_is_error(&msg.acknowledgement)?
                {
                    let packet_data = parse_packet_data(&packet.data)?;
                    let item = transfer_intent(packet, &packet_data, TransferAction::Refund)?;
                    external_output = Some(ExternalOutputIntent {
                        address: decode_address(&packet_data.sender, network_id)
                            .map_err(Error::Signer)?,
                        transfer: item.clone(),
                        required: true,
                    });
                    transfer = Some(item);
                } else if packet.source_port == "transfer" {
                    // Successful acknowledgements do not pay a refund, but malformed
                    // transfer packet data must still fail closed.
                    parse_packet_data(&packet.data)?;
                }
                msg.signer
            }
            "/ibc.core.channel.v1.MsgTimeout" => {
                let msg = MsgTimeout::decode(message).map_err(decode_error)?;
                let packet = msg
                    .packet
                    .as_ref()
                    .ok_or_else(|| Error::Signer("MsgTimeout has no packet".to_string()))?;
                module_port = Some(validate_module_port(&packet.source_port)?);
                state_sequence = Some(parse_identifier_sequence(
                    &packet.source_channel,
                    Some("channel"),
                )?);
                packet_intent = Some(PacketIntent::from_packet(packet));
                if packet.source_port == "transfer" {
                    let packet_data = parse_packet_data(&packet.data)?;
                    let item = transfer_intent(packet, &packet_data, TransferAction::Refund)?;
                    external_output = Some(ExternalOutputIntent {
                        address: decode_address(&packet_data.sender, network_id)
                            .map_err(Error::Signer)?,
                        transfer: item.clone(),
                        required: true,
                    });
                    transfer = Some(item);
                }
                msg.signer
            }
            "/ibc.core.channel.v1.MsgTimeoutOnClose" => {
                let msg = MsgTimeoutOnClose::decode(message).map_err(decode_error)?;
                let packet = msg
                    .packet
                    .as_ref()
                    .ok_or_else(|| Error::Signer("MsgTimeoutOnClose has no packet".to_string()))?;
                module_port = Some(validate_module_port(&packet.source_port)?);
                state_sequence = Some(parse_identifier_sequence(
                    &packet.source_channel,
                    Some("channel"),
                )?);
                packet_intent = Some(PacketIntent::from_packet(packet));
                if packet.source_port == "transfer" {
                    let packet_data = parse_packet_data(&packet.data)?;
                    let item = transfer_intent(packet, &packet_data, TransferAction::Refund)?;
                    external_output = Some(ExternalOutputIntent {
                        address: decode_address(&packet_data.sender, network_id)
                            .map_err(Error::Signer)?,
                        transfer: item.clone(),
                        required: true,
                    });
                    transfer = Some(item);
                }
                msg.signer
            }
            "/ibc.applications.transfer.v1.MsgTransfer" => {
                let msg = ibc_proto::ibc::applications::transfer::v1::MsgTransfer::decode(message)
                    .map_err(decode_error)?;
                let token = msg
                    .token
                    .ok_or_else(|| Error::Signer("IBC transfer has no token".to_string()))?;
                let amount = parse_transfer_amount(&token.amount)?;
                let denom = token.denom.as_str();
                if denom.is_empty() {
                    return Err(Error::Signer(
                        "IBC transfer denomination is empty".to_string(),
                    ));
                }
                if denom.trim() != denom {
                    return Err(Error::Signer(
                        "IBC transfer denomination must not contain surrounding whitespace"
                            .to_string(),
                    ));
                }
                if denom.starts_with("ibc/") {
                    canonical_ibc_denom_hash(denom)?;
                }
                if msg.source_port.is_empty() || msg.source_channel.is_empty() {
                    return Err(Error::Signer(
                        "IBC transfer source port and channel are required".to_string(),
                    ));
                }
                module_port = Some(validate_module_port(&msg.source_port)?);
                state_sequence = Some(parse_identifier_sequence(
                    &msg.source_channel,
                    Some("channel"),
                )?);
                let (timeout_revision_number, timeout_revision_height) =
                    msg.timeout_height.as_ref().map_or((0, 0), |height| {
                        (height.revision_number, height.revision_height)
                    });
                transfer = Some(TransferIntent {
                    denom: denom.to_string(),
                    amount,
                    source_port: Some(msg.source_port.clone()),
                    source_channel: Some(msg.source_channel.clone()),
                    destination_port: None,
                    destination_channel: None,
                    sender: outbound_transfer_sender(&msg.sender, network_id)
                        .map_err(Error::Signer)?,
                    receiver: msg.receiver,
                    memo: msg.memo,
                    timeout_revision_number,
                    timeout_revision_height,
                    timeout_timestamp: msg.timeout_timestamp,
                    action: TransferAction::Send,
                });
                msg.sender
            }
            "/ibc.cardano.v1.MsgPrunePacketHistory" => {
                let msg = MsgPrunePacketHistory::decode(message).map_err(decode_error)?;
                module_port = Some(validate_module_port(&msg.port_id)?);
                state_sequence = Some(parse_identifier_sequence(&msg.channel_id, Some("channel"))?);
                prune_sequence = Some(msg.sequence);
                msg.signer
            }
            other => {
                return Err(Error::Signer(format!(
                    "no Cardano transaction signing policy exists for {other}"
                )))
            }
        };

        validate_request_signer(&signer, expected_signer, network_id, type_url)?;
        Ok(Self {
            operation: type_url.to_string(),
            module_port,
            external_output,
            transfer,
            state_sequence,
            recovery_substitute_sequence,
            packet: packet_intent,
            acknowledgement,
            prune_sequence,
            staged_tendermint: false,
            staged_misbehaviour: false,
        })
    }

    /// Return the hash that must be resolved before an outbound hashed voucher
    /// denomination can be authorized.
    pub fn unresolved_ibc_denom_hash(&self) -> Option<&str> {
        self.transfer
            .as_ref()
            .filter(|transfer| transfer.action == TransferAction::Send)
            .and_then(|transfer| transfer.denom.strip_prefix("ibc/"))
    }

    /// Replace an outbound `ibc/<SHA256>` denomination with its full trace only
    /// after cryptographically verifying the Gateway's response.
    pub fn resolve_ibc_denom(&mut self, full_denom: &str) -> Result<(), Error> {
        if full_denom.is_empty() {
            return Err(Error::Signer(
                "resolved ICS-20 denomination is empty".to_string(),
            ));
        }

        let transfer = self
            .transfer
            .as_mut()
            .filter(|transfer| transfer.action == TransferAction::Send)
            .ok_or_else(|| {
                Error::Signer(
                    "cannot resolve an ICS-20 denomination for a non-transfer intent".to_string(),
                )
            })?;
        let expected_hash = canonical_ibc_denom_hash(&transfer.denom)?;
        let actual_hash: [u8; 32] = Sha256::digest(full_denom.as_bytes()).into();
        if actual_hash != expected_hash {
            return Err(Error::Signer(format!(
                "resolved denomination does not match requested ICS-20 hash {}",
                hex::encode_upper(expected_hash)
            )));
        }

        transfer.denom = full_denom.to_string();
        Ok(())
    }
}

fn canonical_ibc_denom_hash(denom: &str) -> Result<[u8; 32], Error> {
    let hash = denom.strip_prefix("ibc/").ok_or_else(|| {
        Error::Signer("hashed ICS-20 denomination must start with 'ibc/'".to_string())
    })?;
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Signer(
            "hashed ICS-20 denomination must use canonical ibc/<64-hex> form".to_string(),
        ));
    }

    let bytes = hex::decode(hash).map_err(|_| {
        Error::Signer("hashed ICS-20 denomination must use canonical ibc/<64-hex> form".to_string())
    })?;
    bytes.try_into().map_err(|_| {
        Error::Signer("hashed ICS-20 denomination must contain exactly 32 hash bytes".to_string())
    })
}

fn decode_error(error: prost::DecodeError) -> Error {
    Error::Signer(format!("failed to decode signing intent: {error}"))
}

fn validate_request_signer(
    actual: &str,
    expected: &str,
    network_id: u8,
    operation: &str,
) -> Result<(), Error> {
    let actual = decode_address(actual, network_id).map_err(Error::Signer)?;
    let expected = decode_address(expected, network_id).map_err(Error::Signer)?;
    if actual != expected {
        return Err(Error::Signer(format!(
            "refusing {operation}: message signer does not match the configured Cardano key"
        )));
    }
    Ok(())
}

fn parse_packet_data(data: &[u8]) -> Result<Ics20PacketData, Error> {
    let packet: Ics20PacketData = serde_json::from_slice(data)
        .map_err(|error| Error::Signer(format!("invalid ICS-20 packet data: {error}")))?;
    if packet.denom.is_empty() || packet.sender.is_empty() || packet.receiver.is_empty() {
        return Err(Error::Signer(
            "ICS-20 packet denomination, sender, and receiver are required".to_string(),
        ));
    }
    parse_transfer_amount(&packet.amount)?;
    Ok(packet)
}

fn parse_transfer_amount(amount: &str) -> Result<u64, Error> {
    let amount = amount
        .parse()
        .map_err(|_| Error::Signer("ICS-20 transfer amount is not a u64".to_string()))?;
    if amount == 0 {
        return Err(Error::Signer(
            "ICS-20 transfer amount must be greater than zero".to_string(),
        ));
    }
    Ok(amount)
}

fn transfer_intent(
    packet: &super::generated::ibc::core::channel::v1::Packet,
    data: &Ics20PacketData,
    action: TransferAction,
) -> Result<TransferIntent, Error> {
    let amount = parse_transfer_amount(&data.amount)?;
    let (timeout_revision_number, timeout_revision_height) =
        packet.timeout_height.as_ref().map_or((0, 0), |height| {
            (height.revision_number, height.revision_height)
        });
    Ok(TransferIntent {
        denom: data.denom.clone(),
        amount,
        source_port: Some(packet.source_port.clone()),
        source_channel: Some(packet.source_channel.clone()),
        destination_port: Some(packet.destination_port.clone()),
        destination_channel: Some(packet.destination_channel.clone()),
        sender: data.sender.clone(),
        receiver: data.receiver.clone(),
        memo: data.memo.clone(),
        timeout_revision_number,
        timeout_revision_height,
        timeout_timestamp: packet.timeout_timestamp,
        action,
    })
}

fn acknowledgement_is_error(bytes: &[u8]) -> Result<bool, Error> {
    let value: JsonValue = serde_json::from_slice(bytes)
        .map_err(|error| Error::Signer(format!("invalid IBC acknowledgement JSON: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| Error::Signer("IBC acknowledgement must be a JSON object".to_string()))?;
    if object.get("result").and_then(JsonValue::as_str).is_some() {
        return Ok(false);
    }
    if object.get("error").and_then(JsonValue::as_str).is_some()
        || object.get("err").and_then(JsonValue::as_str).is_some()
    {
        return Ok(true);
    }
    Err(Error::Signer(
        "IBC acknowledgement contains neither result nor error".to_string(),
    ))
}

enum ExpectedAsset {
    Lovelace,
    Native(Vec<u8>, Vec<u8>),
    Voucher {
        user_name: Option<Vec<u8>>,
        reference_name: Option<Vec<u8>>,
    },
}

fn voucher_mint_action(transfer: &TransferIntent) -> Option<VoucherMintAction> {
    if !matches!(expected_asset(transfer), ExpectedAsset::Voucher { .. }) {
        return None;
    }
    match transfer.action {
        TransferAction::Receive | TransferAction::Refund => Some(VoucherMintAction::Mint),
        TransferAction::Send => {
            let returns_to_source = transfer
                .source_port
                .as_ref()
                .zip(transfer.source_channel.as_ref())
                .is_some_and(|(port, channel)| {
                    transfer.denom.starts_with(&format!("{port}/{channel}/"))
                });
            returns_to_source.then_some(VoucherMintAction::Burn)
        }
    }
}

fn expected_asset(transfer: &TransferIntent) -> ExpectedAsset {
    let source_prefix = transfer
        .source_port
        .as_ref()
        .zip(transfer.source_channel.as_ref())
        .map(|(port, channel)| format!("{port}/{channel}/"));

    match transfer.action {
        TransferAction::Receive => {
            if let Some(unwrapped) = source_prefix
                .as_deref()
                .and_then(|prefix| transfer.denom.strip_prefix(prefix))
            {
                return native_or_lovelace(unwrapped);
            }
            let full_denom = transfer
                .destination_port
                .as_ref()
                .zip(transfer.destination_channel.as_ref())
                .map(|(port, channel)| format!("{port}/{channel}/{}", transfer.denom));
            voucher_asset(full_denom.as_deref())
        }
        TransferAction::Refund => {
            if source_prefix
                .as_deref()
                .is_some_and(|prefix| transfer.denom.starts_with(prefix))
            {
                voucher_asset(Some(&transfer.denom))
            } else {
                native_or_lovelace(&transfer.denom)
            }
        }
        TransferAction::Send => {
            if transfer.denom.starts_with("ibc/") {
                voucher_asset(None)
            } else if source_prefix
                .as_deref()
                .is_some_and(|prefix| transfer.denom.starts_with(prefix))
            {
                voucher_asset(Some(&transfer.denom))
            } else {
                native_or_lovelace(&transfer.denom)
            }
        }
    }
}

fn native_or_lovelace(denom: &str) -> ExpectedAsset {
    if denom.eq_ignore_ascii_case(LOVELACE) || denom.eq_ignore_ascii_case(LOVELACE_HEX) {
        return ExpectedAsset::Lovelace;
    }
    if let Ok(unit) = hex::decode(denom) {
        if (28..=60).contains(&unit.len()) {
            return ExpectedAsset::Native(unit[..28].to_vec(), unit[28..].to_vec());
        }
    }
    voucher_asset(Some(denom))
}

fn voucher_asset(full_denom: Option<&str>) -> ExpectedAsset {
    let Some(full_denom) = full_denom else {
        return ExpectedAsset::Voucher {
            user_name: None,
            reference_name: None,
        };
    };
    let mut hash = [0u8; 28];
    let mut hasher = Blake2bVar::new(hash.len()).expect("valid Blake2b-224 output size");
    hasher.update(full_denom.as_bytes());
    hasher
        .finalize_variable(&mut hash)
        .expect("fixed Blake2b-224 buffer size");
    ExpectedAsset::Voucher {
        user_name: Some([CIP67_FT_LABEL.as_slice(), hash.as_slice()].concat()),
        reference_name: Some([CIP67_REFERENCE_NFT_LABEL.as_slice(), hash.as_slice()].concat()),
    }
}

fn is_voucher_user_token_name(name: &[u8]) -> bool {
    name.len() == 32 && name.starts_with(&CIP67_FT_LABEL)
}

fn spend_redeemer_for_input<'a>(
    body: &pallas_primitives::conway::MintedTransactionBody<'_>,
    redeemers: &'a pallas_primitives::conway::Redeemers,
    out_ref: &TransactionOutRef,
) -> Result<&'a PlutusData, String> {
    let mut ordered_inputs: Vec<_> = body
        .inputs
        .iter()
        .map(TransactionOutRef::from_transaction_input)
        .collect();
    ordered_inputs.sort_unstable();
    let index = ordered_inputs
        .iter()
        .position(|candidate| candidate == out_ref)
        .ok_or_else(|| "resolved protocol input is absent from the transaction body".to_string())?;
    let index = u32::try_from(index)
        .map_err(|_| "protocol input index exceeds the Cardano redeemer range".to_string())?;

    let mut matching = redeemers.iter().filter(|(key, _)| {
        key.tag == pallas_primitives::conway::RedeemerTag::Spend && key.index == index
    });
    let data = matching
        .next()
        .map(|(_, value)| &value.data)
        .ok_or_else(|| format!("transaction has no Spend[{index}] redeemer for protocol input"))?;
    if matching.next().is_some() {
        return Err(format!(
            "transaction has duplicate Spend[{index}] redeemers for protocol input"
        ));
    }
    Ok(data)
}

fn mint_redeemer_for_policy<'a>(
    body: &pallas_primitives::conway::MintedTransactionBody<'_>,
    redeemers: &'a pallas_primitives::conway::Redeemers,
    policy: &[u8],
) -> Result<&'a PlutusData, String> {
    let mut policies: Vec<Vec<u8>> = body
        .mint
        .as_ref()
        .into_iter()
        .flat_map(|mint| mint.iter().map(|(policy, _)| policy.as_ref().to_vec()))
        .collect();
    policies.sort_unstable();
    let index = policies
        .iter()
        .position(|candidate| candidate.as_slice() == policy)
        .ok_or_else(|| "session minting policy is absent from the transaction body".to_string())?;
    let index = u32::try_from(index)
        .map_err(|_| "minting policy index exceeds the Cardano redeemer range".to_string())?;

    let mut matching = redeemers.iter().filter(|(key, _)| {
        key.tag == pallas_primitives::conway::RedeemerTag::Mint && key.index == index
    });
    let data = matching
        .next()
        .map(|(_, value)| &value.data)
        .ok_or_else(|| format!("transaction has no Mint[{index}] redeemer for session policy"))?;
    if matching.next().is_some() {
        return Err(format!(
            "transaction has duplicate Mint[{index}] redeemers for session policy"
        ));
    }
    Ok(data)
}

fn plutus_output_reference(data: &PlutusData) -> Option<TransactionOutRef> {
    let fields = constructor_fields(data, 0)?;
    if fields.len() != 2 {
        return None;
    }
    // Aiken's OutputReference stores the transaction hash directly as bytes.
    let transaction_id: [u8; 32] = plutus_bytes(&fields[0])?.try_into().ok()?;
    Some(TransactionOutRef {
        transaction_id,
        output_index: plutus_u64(&fields[1])?,
    })
}

fn plutus_auth_token(data: &PlutusData) -> Option<(&[u8], &[u8])> {
    let fields = constructor_fields(data, 0)?;
    if fields.len() != 2 {
        return None;
    }
    Some((plutus_bytes(&fields[0])?, plutus_bytes(&fields[1])?))
}

fn selected_state_input<'a>(
    resolved_inputs: &'a ResolvedTransactionInputs,
    state: &StateOutputRoot,
    token_name: &[u8],
) -> Option<&'a TransactionOutRef> {
    let mut matches = resolved_inputs
        .regular
        .iter()
        .filter_map(|(out_ref, input)| {
            (input.address == state.address
                && input.assets.len() == 1
                && input.assets[0].policy_id.as_slice() == state.policy
                && input.assets[0].asset_name == token_name
                && input.assets[0].quantity == 1)
                .then_some(out_ref)
        });
    let selected = matches.next()?;
    matches.next().is_none().then_some(selected)
}

fn add_resolved_assets<F>(
    totals: &mut AssetTotals,
    input: &ResolvedInput,
    reject: &F,
) -> Result<(), Error>
where
    F: Fn(String) -> Error,
{
    for asset in &input.assets {
        let entry = totals
            .entry((asset.policy_id.to_vec(), asset.asset_name.clone()))
            .or_default();
        *entry = entry
            .checked_add(u128::from(asset.quantity))
            .ok_or_else(|| reject("resolved native-asset total overflows u128".to_string()))?;
    }
    Ok(())
}

fn aggregate_output_assets<'a, F>(
    outputs: impl Iterator<Item = &'a OutputValue>,
    reject: &F,
    description: &str,
) -> Result<AssetTotals, Error>
where
    F: Fn(String) -> Error,
{
    let mut totals = AssetTotals::new();
    for output in outputs {
        for (policy, name, quantity) in &output.assets {
            let entry = totals.entry((policy.clone(), name.clone())).or_default();
            *entry = entry.checked_add(u128::from(*quantity)).ok_or_else(|| {
                reject(format!("{description} native-asset total overflows u128"))
            })?;
        }
    }
    Ok(totals)
}

fn unpack_output(output: &MintedTransactionOutput<'_>) -> OutputValue {
    match output {
        PseudoTransactionOutput::Legacy(output) => OutputValue {
            address: output.address.as_slice().to_vec(),
            coin: legacy_coin(&output.amount),
            assets: legacy_assets(&output.amount),
            has_script_ref: false,
            has_inline_datum: false,
        },
        PseudoTransactionOutput::PostAlonzo(output) => OutputValue {
            address: output.address.as_slice().to_vec(),
            coin: conway_coin(&output.value),
            assets: conway_assets(&output.value),
            has_script_ref: output.script_ref.is_some(),
            has_inline_datum: matches!(
                output.datum_option.as_ref(),
                Some(pallas_primitives::babbage::PseudoDatumOption::Data(_))
            ),
        },
    }
}

fn legacy_coin(value: &LegacyValue) -> u64 {
    match value {
        LegacyValue::Coin(coin) | LegacyValue::Multiasset(coin, _) => *coin,
    }
}

fn legacy_assets(value: &LegacyValue) -> Vec<(Vec<u8>, Vec<u8>, u64)> {
    let LegacyValue::Multiasset(_, assets) = value else {
        return Vec::new();
    };
    assets
        .iter()
        .flat_map(|(policy, entries)| {
            entries.iter().map(move |(name, quantity)| {
                (
                    policy.as_ref().to_vec(),
                    name.as_slice().to_vec(),
                    *quantity,
                )
            })
        })
        .collect()
}

fn conway_coin(value: &Value) -> u64 {
    match value {
        Value::Coin(coin) | Value::Multiasset(coin, _) => *coin,
    }
}

fn conway_assets(value: &Value) -> Vec<(Vec<u8>, Vec<u8>, u64)> {
    let Value::Multiasset(_, assets) = value else {
        return Vec::new();
    };
    assets
        .iter()
        .flat_map(|(policy, entries)| {
            entries.iter().map(move |(name, quantity)| {
                (
                    policy.as_ref().to_vec(),
                    name.as_slice().to_vec(),
                    u64::from(quantity),
                )
            })
        })
        .collect()
}

fn minted_quantity(
    body: &pallas_primitives::conway::MintedTransactionBody<'_>,
    expected_policy: &[u8],
    expected_name: &[u8],
) -> i128 {
    body.mint
        .as_ref()
        .into_iter()
        .flat_map(|mint| mint.iter())
        .filter(|(policy, _)| policy.as_ref() == expected_policy)
        .flat_map(|(_, assets)| assets.iter())
        .filter(|(name, _)| name.as_slice() == expected_name)
        .map(|(_, quantity)| i128::from(i64::from(quantity)))
        .sum()
}

fn is_exact_state_output(output: &OutputValue, policy: &[u8], name: Option<&[u8]>) -> bool {
    output.assets.len() == 1
        && output.assets[0].0 == policy
        && name.is_none_or(|expected_name| output.assets[0].1 == expected_name)
        && output.assets[0].2 == 1
}

fn checked_protocol_coin<F>(current: u64, coin: u64, reject: &F) -> Result<u64, Error>
where
    F: Fn(String) -> Error,
{
    current
        .checked_add(coin)
        .ok_or_else(|| reject("protocol output lovelace total overflows u64".to_string()))
}

fn collect_validator_script_roots(
    validators: &JsonValue,
) -> Result<HashMap<String, ScriptRoot>, String> {
    let mut scripts = HashMap::new();
    collect_validator_script_roots_inner(validators, None, &mut scripts)?;
    if scripts.is_empty() {
        return Err("manifest has no validator script roots".to_string());
    }
    Ok(scripts)
}

fn collect_validator_script_roots_inner(
    value: &JsonValue,
    object_name: Option<&str>,
    scripts: &mut HashMap<String, ScriptRoot>,
) -> Result<(), String> {
    let JsonValue::Object(object) = value else {
        return Ok(());
    };

    if let Some(script_hash) = object_field(value, &["script_hash", "scriptHash"])
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
    {
        let name = object_name
            .map(normalize_manifest_key)
            .ok_or_else(|| "validator script has no manifest key".to_string())?;
        let hash = decode_fixed_hex(script_hash, 28, &format!("{name} script hash"))?;
        let reference = parse_out_ref(
            object_field(value, &["ref_utxo", "refUtxo"])
                .ok_or_else(|| format!("{name} script has no reference UTxO"))?,
        )?;
        if scripts
            .insert(name.clone(), ScriptRoot { hash, reference })
            .is_some()
        {
            return Err(format!(
                "manifest contains duplicate validator script key {name}"
            ));
        }
    }

    for (key, child) in object {
        if child.is_object() {
            collect_validator_script_roots_inner(child, Some(key), scripts)?;
        }
    }
    Ok(())
}

fn parse_module_roots(manifest: &JsonValue, network_id: u8) -> Result<ModuleRoots, String> {
    let modules_value = object_field(manifest, &["modules"])
        .ok_or_else(|| "manifest has no modules object".to_string())?;
    let modules_object = modules_value
        .as_object()
        .ok_or_else(|| "manifest modules is not an object".to_string())?;
    let mut modules = HashMap::new();
    let mut policies = HashSet::new();

    for (key, reference_script) in [
        ("transfer", "spendtransfermodule"),
        ("mock", "spendmockmodule"),
        ("icq", "spendmockmodule"),
    ] {
        let Some(module) = modules_object.get(key) else {
            continue;
        };
        let unit = decode_hex(
            required_string(module, &["identifier"], &format!("{key} module identifier"))?,
            &format!("{key} module identifier"),
        )?;
        if !(29..=60).contains(&unit.len()) {
            return Err(format!(
                "invalid {key} module identifier: expected a 28-byte policy and 1..=32-byte name"
            ));
        }
        let identifier_policy = unit[..28].to_vec();
        policies.insert(identifier_policy.clone());
        modules.insert(
            key.to_string(),
            ModuleRoot {
                address: decode_address(
                    required_string(module, &["address"], &format!("{key} module address"))?,
                    network_id,
                )?,
                identifier_policy,
                identifier_name: unit[28..].to_vec(),
                reference_script,
            },
        );
    }

    Ok((modules, policies))
}

fn validator_address(
    validators: &JsonValue,
    names: &[&str],
    network_id: u8,
) -> Result<Vec<u8>, String> {
    let description = names.first().copied().unwrap_or("validator");
    let validator = object_field(validators, names)
        .ok_or_else(|| format!("manifest has no {description} validator"))?;
    decode_address(
        required_string(validator, &["address"], &format!("{description} address"))?,
        network_id,
    )
}

fn required_script<'a>(
    scripts: &'a HashMap<String, ScriptRoot>,
    name: &str,
) -> Result<&'a ScriptRoot, String> {
    scripts
        .get(name)
        .ok_or_else(|| format!("pinned manifest has no {name} script"))
}

fn normalize_manifest_key(key: &str) -> String {
    key.replace('_', "").to_ascii_lowercase()
}

fn module_key_for_port(port: &str) -> Result<&'static str, String> {
    match port {
        "transfer" => Ok("transfer"),
        "mock" => Ok("mock"),
        "icqhost" => Ok("icq"),
        _ => Err(format!("unsupported Cardano IBC module port {port}")),
    }
}

fn validate_module_port(port: &str) -> Result<String, Error> {
    module_key_for_port(port).map_err(Error::Signer)?;
    Ok(port.to_string())
}

fn parse_identifier_sequence(
    identifier: &str,
    expected_prefix: Option<&str>,
) -> Result<u64, Error> {
    let (prefix, sequence) = identifier
        .rsplit_once('-')
        .ok_or_else(|| Error::Signer(format!("invalid IBC identifier {identifier}")))?;
    if prefix.is_empty()
        || expected_prefix.is_some_and(|expected| prefix != expected)
        || sequence.is_empty()
        || sequence.len() > 8
        || (sequence.len() > 1 && sequence.starts_with('0'))
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::Signer(format!(
            "invalid IBC identifier {identifier}"
        )));
    }
    sequence
        .parse()
        .map_err(|_| Error::Signer(format!("invalid IBC identifier {identifier}")))
}

fn object_field<'a>(value: &'a JsonValue, names: &[&str]) -> Option<&'a JsonValue> {
    let object = value.as_object()?;
    names.iter().find_map(|name| object.get(*name))
}

fn required_string<'a>(
    value: &'a JsonValue,
    names: &[&str],
    description: &str,
) -> Result<&'a str, String> {
    object_field(value, names)
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("manifest has no {description}"))
}

fn parse_out_ref(value: &JsonValue) -> Result<(Vec<u8>, u64), String> {
    let tx_hash = decode_fixed_hex(
        required_string(value, &["tx_hash", "txHash"], "reference transaction hash")?,
        32,
        "reference transaction hash",
    )?;
    let index = object_field(value, &["output_index", "outputIndex"])
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| "manifest reference UTxO has no output index".to_string())?;
    Ok((tx_hash, index))
}

fn decode_address(value: &str, network_id: u8) -> Result<Vec<u8>, String> {
    let value = value.trim();
    let mut bytes = if value.starts_with("addr") {
        let (hrp, data, _) = bech32::decode(value)
            .map_err(|error| format!("invalid Cardano bech32 address: {error}"))?;
        if hrp != "addr" && hrp != "addr_test" {
            return Err(format!("unsupported Cardano address prefix {hrp}"));
        }
        Vec::<u8>::from_base32(&data)
            .map_err(|error| format!("invalid Cardano address payload: {error}"))?
    } else {
        decode_hex(value, "Cardano address")?
    };
    if bytes.len() == 28 {
        bytes.insert(0, 0x60 | network_id);
    }
    validate_address_network(&bytes, network_id)?;
    Ok(bytes)
}

fn outbound_transfer_sender(value: &str, network_id: u8) -> Result<String, String> {
    let address = decode_address(value, network_id)?;
    match address.as_slice() {
        [header, payment_key_hash @ ..] if *header >> 4 == 6 && payment_key_hash.len() == 28 => {
            Ok(hex::encode(payment_key_hash))
        }
        _ => Err(
            "Cardano transfer sender must be a payment key hash or key enterprise address"
                .to_string(),
        ),
    }
}

fn validate_address_network(address: &[u8], network_id: u8) -> Result<(), String> {
    let header = *address
        .first()
        .ok_or_else(|| "Cardano address is empty".to_string())?;
    if header >> 4 > 7 {
        return Err(
            "Byron and reward addresses are not valid transaction destinations".to_string(),
        );
    }
    if header & 0x0f != network_id {
        return Err(format!(
            "Cardano address network {} does not match configured network {network_id}",
            header & 0x0f
        ));
    }
    Ok(())
}

fn decode_hex(value: &str, description: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|error| format!("invalid {description}: {error}"))
}

fn decode_fixed_hex(
    value: &str,
    expected_len: usize,
    description: &str,
) -> Result<Vec<u8>, String> {
    let bytes = decode_hex(value, description)?;
    if bytes.len() != expected_len {
        return Err(format!(
            "invalid {description}: expected {expected_len} bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::cardano::utxo_resolver::ResolvedAsset;
    use pallas_codec::minicbor;

    fn limits() -> SigningPolicyLimits {
        SigningPolicyLimits {
            max_fee_lovelace: 5_000_000,
            max_total_collateral_lovelace: 10_000_000,
            max_tx_size_bytes: 64 * 1024,
            max_external_output_lovelace: 5_000_000,
            max_total_protocol_output_lovelace: 50_000_000,
            max_wallet_lovelace_top_up: 5_000_000,
            max_validity_interval_slots: 3_600,
        }
    }

    fn manifest() -> String {
        format!(
            r#"{{
                "validators": {{
                    "host_state_stt": {{
                        "address": "70{}",
                        "script_hash": "{}",
                        "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}
                    }},
                    "spend_client": {{"address": "70{}", "script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "spend_connection": {{"address": "70{}"}},
                    "spend_channel": {{"address": "70{}"}},
                    "recover_client": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_client_stt": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_connection_stt": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_channel_stt": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_voucher": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_transfer_escrow_shard": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_identifier": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_port": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "spend_transfer_module": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "spend_trace_registry": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "verify_proof": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "voucher_metadata": {{"address": "70{}"}}
                }},
                "host_state_nft": {{"policy_id": "{}", "token_name": "01"}},
                "modules": {{
                    "transfer": {{"identifier": "{}01", "address": "70{}"}}
                }},
                "trace_registry": {{"address": "70{}", "shard_policy_id": "{}"}}
            }}"#,
            "11".repeat(28),
            "21".repeat(28),
            "31".repeat(32),
            "12".repeat(28),
            "22".repeat(28),
            "32".repeat(32),
            "13".repeat(28),
            "14".repeat(28),
            "20".repeat(28),
            "30".repeat(32),
            "25".repeat(28),
            "35".repeat(32),
            "26".repeat(28),
            "36".repeat(32),
            "27".repeat(28),
            "37".repeat(32),
            "23".repeat(28),
            "33".repeat(32),
            "28".repeat(28),
            "38".repeat(32),
            "29".repeat(28),
            "39".repeat(32),
            "2a".repeat(28),
            "3a".repeat(32),
            "2b".repeat(28),
            "3b".repeat(32),
            "2c".repeat(28),
            "3c".repeat(32),
            "2f".repeat(28),
            "3f".repeat(32),
            "15".repeat(28),
            "24".repeat(28),
            "2d".repeat(28),
            "16".repeat(28),
            "17".repeat(28),
            "2e".repeat(28),
        )
    }

    #[test]
    fn pinned_manifest_loads_security_roots() {
        let policy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        assert_eq!(policy.protocol_addresses.len(), 7);
        assert_eq!(policy.voucher_policy, vec![0x23; 28]);
        assert_eq!(policy.host_state_reference, (vec![0x31; 32], 0));
    }

    #[test]
    fn staged_manifest_requires_paired_session_validators() {
        let mut value: JsonValue = serde_json::from_str(&manifest()).unwrap();
        let validators = value["validators"].as_object_mut().unwrap();
        validators.insert(
            "spend_tendermint_update_session".to_string(),
            serde_json::json!({
                "address": format!("70{}", "18".repeat(28)),
                "script_hash": "40".repeat(28),
                "ref_utxo": { "tx_hash": "50".repeat(32), "output_index": 0 }
            }),
        );
        let error = TransactionSigningPolicy::from_json(
            &serde_json::to_string(&value).unwrap(),
            0,
            limits(),
        )
        .unwrap_err();
        assert!(error.contains("both staged Tendermint session validators"));

        value["validators"]["mint_tendermint_update_session"] = serde_json::json!({
            "script_hash": "41".repeat(28),
            "ref_utxo": { "tx_hash": "51".repeat(32), "output_index": 0 }
        });
        let policy = TransactionSigningPolicy::from_json(
            &serde_json::to_string(&value).unwrap(),
            0,
            limits(),
        )
        .unwrap();
        assert_eq!(policy.protocol_addresses.len(), 8);
        assert_eq!(policy.tendermint_session.unwrap().policy, vec![0x41; 28]);
    }

    #[test]
    fn staged_intent_is_limited_to_tendermint_headers_or_misbehaviour() {
        let signer = format!("60{}", "99".repeat(28));
        let update = |type_url: &str| {
            MsgUpdateClient {
                client_id: "07-tendermint-12".to_string(),
                client_message: Some(prost_types::Any {
                    type_url: type_url.to_string(),
                    value: Vec::new(),
                }),
                signer: signer.clone(),
            }
            .encode_to_vec()
        };

        let intent = SigningIntent::staged_tendermint_update(
            "/ibc.core.client.v1.MsgUpdateClient",
            &update(TENDERMINT_HEADER_TYPE_URL),
            &signer,
            0,
        )
        .unwrap();
        assert!(intent.staged_tendermint);
        assert!(!intent.staged_misbehaviour);
        assert_eq!(intent.state_sequence, Some(12));
        let evidence = SigningIntent::staged_tendermint_update(
            "/ibc.core.client.v1.MsgUpdateClient",
            &update(TENDERMINT_MISBEHAVIOR_TYPE_URL),
            &signer,
            0,
        )
        .unwrap();
        assert!(evidence.staged_tendermint && evidence.staged_misbehaviour);

        let error = SigningIntent::staged_tendermint_update(
            "/ibc.core.client.v1.MsgUpdateClient",
            &update("/ibc.lightclients.solomachine.v3.Header"),
            &signer,
            0,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported client message type"));
    }

    #[test]
    fn message_signer_must_match_local_key() {
        let message = MsgCreateClient {
            client_state: None,
            consensus_state: None,
            signer: format!("60{}", "99".repeat(28)),
        }
        .encode_to_vec();
        let error = SigningIntent::ibc(
            "/ibc.core.client.v1.MsgCreateClient",
            &message,
            &format!("60{}", "98".repeat(28)),
            0,
        )
        .unwrap_err();
        assert!(error.to_string().contains("message signer does not match"));
    }

    #[test]
    fn recovery_intent_binds_both_tendermint_clients() {
        let signer = format!("60{}", "99".repeat(28));
        let message = MsgRecoverClient {
            subject_client_id: "07-tendermint-7".to_string(),
            substitute_client_id: "07-tendermint-12".to_string(),
            signer: signer.clone(),
        }
        .encode_to_vec();
        let intent =
            SigningIntent::ibc("/ibc.core.client.v1.MsgRecoverClient", &message, &signer, 0)
                .unwrap();

        assert_eq!(intent.state_sequence, Some(7));
        assert_eq!(intent.recovery_substitute_sequence, Some(12));

        let policy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        let requirements = policy.operation_requirements(&intent).unwrap();
        assert_eq!(requirements.state_output, StateOutputKind::Client);
        assert_eq!(
            requirements.required_scripts,
            vec!["spendclient", "recoverclient"]
        );
        assert!(requirements.required_mint_scripts.is_empty());
    }

    #[test]
    fn recovery_intent_rejects_the_same_or_non_tendermint_client() {
        let signer = format!("60{}", "99".repeat(28));
        for (subject, substitute) in [
            ("07-tendermint-7", "07-tendermint-7"),
            ("08-cardano-7", "07-tendermint-12"),
        ] {
            let message = MsgRecoverClient {
                subject_client_id: subject.to_string(),
                substitute_client_id: substitute.to_string(),
                signer: signer.clone(),
            }
            .encode_to_vec();
            assert!(SigningIntent::ibc(
                "/ibc.core.client.v1.MsgRecoverClient",
                &message,
                &signer,
                0,
            )
            .is_err());
        }
    }

    #[test]
    fn identifier_sequences_must_use_canonical_decimal() {
        assert_eq!(
            parse_identifier_sequence("07-tendermint-0", Some("07-tendermint")).unwrap(),
            0
        );
        assert_eq!(
            parse_identifier_sequence("07-tendermint-7", Some("07-tendermint")).unwrap(),
            7
        );
        for identifier in ["07-tendermint-00", "07-tendermint-0007"] {
            assert!(parse_identifier_sequence(identifier, Some("07-tendermint")).is_err());
        }
    }

    #[test]
    fn recovery_spend_redeemer_binds_the_substitute_token() {
        let policy = vec![0x25; 28];
        let name = b"substitute".to_vec();
        let mut encoded = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut encoded);
        encoder.tag(minicbor::data::Tag::Unassigned(122)).unwrap();
        encoder.array(1).unwrap();
        encoder.tag(minicbor::data::Tag::Unassigned(121)).unwrap();
        encoder.array(2).unwrap();
        encoder.bytes(&policy).unwrap();
        encoder.bytes(&name).unwrap();
        let redeemer: PlutusData = minicbor::decode(&encoded).unwrap();

        assert!(ChannelRedeemerIntent::ClientRecovery {
            alternative: 1,
            substitute_policy: policy.clone(),
            substitute_name: name.clone(),
            history_format: ConsensusHistoryFormat::Legacy,
        }
        .matches(&redeemer));
        assert!(!ChannelRedeemerIntent::ClientRecovery {
            alternative: 1,
            substitute_policy: policy,
            substitute_name: b"another-client".to_vec(),
            history_format: ConsensusHistoryFormat::Legacy,
        }
        .matches(&redeemer));
    }

    const RECOVERY_HOST_INPUT_ID: [u8; 32] = [0x41; 32];
    const RECOVERY_SUBJECT_INPUT_ID: [u8; 32] = [0x42; 32];
    const RECOVERY_SIGNER_INPUT_ID: [u8; 32] = [0x43; 32];
    const RECOVERY_SUBSTITUTE_REFERENCE_ID: [u8; 32] = [0x44; 32];

    fn recovery_signer() -> String {
        format!("60{}", "99".repeat(28))
    }

    fn recovery_intent() -> SigningIntent {
        let signer = recovery_signer();
        let message = MsgRecoverClient {
            subject_client_id: "07-tendermint-7".to_string(),
            substitute_client_id: "07-tendermint-12".to_string(),
            signer: signer.clone(),
        }
        .encode_to_vec();
        SigningIntent::ibc("/ibc.core.client.v1.MsgRecoverClient", &message, &signer, 0).unwrap()
    }

    fn encode_transaction_input(
        encoder: &mut minicbor::Encoder<&mut Vec<u8>>,
        transaction_id: &[u8],
        output_index: u64,
    ) {
        encoder
            .array(2)
            .unwrap()
            .bytes(transaction_id)
            .unwrap()
            .u64(output_index)
            .unwrap();
    }

    fn encode_single_asset_output(
        encoder: &mut minicbor::Encoder<&mut Vec<u8>>,
        address: &[u8],
        policy: &[u8],
        name: &[u8],
    ) {
        encoder
            .array(3)
            .unwrap()
            .bytes(address)
            .unwrap()
            .array(2)
            .unwrap()
            .u64(2_000_000)
            .unwrap()
            .map(1)
            .unwrap()
            .bytes(policy)
            .unwrap()
            .map(1)
            .unwrap()
            .bytes(name)
            .unwrap()
            .u64(1)
            .unwrap()
            .null()
            .unwrap();
    }

    fn encode_auth_token(
        encoder: &mut minicbor::Encoder<&mut Vec<u8>>,
        policy: &[u8],
        name: &[u8],
    ) {
        encoder
            .tag(minicbor::data::Tag::Unassigned(121))
            .unwrap()
            .array(2)
            .unwrap()
            .bytes(policy)
            .unwrap()
            .bytes(name)
            .unwrap();
    }

    fn recovery_transaction(
        policy: &TransactionSigningPolicy,
        spend_substitute_sequence: u64,
    ) -> Vec<u8> {
        let signer_address = hex::decode(recovery_signer()).unwrap();
        let subject_name = policy.state_token_name(StateOutputKind::Client, 7);
        let substitute_name = policy.state_token_name(StateOutputKind::Client, 12);
        let spend_substitute_name =
            policy.state_token_name(StateOutputKind::Client, spend_substitute_sequence);
        let recovery_script = required_script(&policy.scripts, "recoverclient").unwrap();
        let mut reference_inputs = vec![
            policy.host_state_reference.clone(),
            required_script(&policy.scripts, "spendclient")
                .unwrap()
                .reference
                .clone(),
            recovery_script.reference.clone(),
            (RECOVERY_SUBSTITUTE_REFERENCE_ID.to_vec(), 0),
        ];
        reference_inputs.sort_unstable();

        let mut encoded = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut encoded);
        encoder
            .array(4)
            .unwrap()
            .map(7)
            .unwrap()
            .u8(0)
            .unwrap()
            .array(3)
            .unwrap();
        encode_transaction_input(&mut encoder, &RECOVERY_HOST_INPUT_ID, 0);
        encode_transaction_input(&mut encoder, &RECOVERY_SUBJECT_INPUT_ID, 0);
        encode_transaction_input(&mut encoder, &RECOVERY_SIGNER_INPUT_ID, 0);

        encoder.u8(1).unwrap().array(3).unwrap();
        encode_single_asset_output(
            &mut encoder,
            &policy.host_state_address,
            &policy.host_state_nft_policy,
            &policy.host_state_nft_name,
        );
        encode_single_asset_output(
            &mut encoder,
            &policy.client_state.address,
            &policy.client_state.policy,
            &subject_name,
        );
        encoder
            .array(3)
            .unwrap()
            .bytes(&signer_address)
            .unwrap()
            .u64(2_500_000)
            .unwrap()
            .null()
            .unwrap()
            .u8(2)
            .unwrap()
            .u64(500_000)
            .unwrap()
            .u8(3)
            .unwrap()
            .u64(1_000)
            .unwrap()
            .u8(5)
            .unwrap()
            .map(1)
            .unwrap();
        encoder
            .bytes(&[&[0xf0][..], recovery_script.hash.as_slice()].concat())
            .unwrap()
            .u64(0)
            .unwrap()
            .u8(14)
            .unwrap()
            .array(1)
            .unwrap()
            .bytes(&[0x99; 28])
            .unwrap()
            .u8(18)
            .unwrap()
            .array(reference_inputs.len() as u64)
            .unwrap();
        for (transaction_id, output_index) in reference_inputs {
            encode_transaction_input(&mut encoder, &transaction_id, output_index);
        }

        encoder.map(1).unwrap().u8(5).unwrap().array(3).unwrap();

        // HostState UpdateClient, Spend[0].
        encoder
            .array(4)
            .unwrap()
            .u8(0)
            .unwrap()
            .u32(0)
            .unwrap()
            .tag(minicbor::data::Tag::Unassigned(125))
            .unwrap()
            .array(3)
            .unwrap()
            .array(0)
            .unwrap()
            .array(0)
            .unwrap()
            .array(0)
            .unwrap()
            .array(2)
            .unwrap()
            .u64(1)
            .unwrap()
            .u64(1)
            .unwrap();

        // SpendClient RecoverClient, Spend[1].
        encoder
            .array(4)
            .unwrap()
            .u8(0)
            .unwrap()
            .u32(1)
            .unwrap()
            .tag(minicbor::data::Tag::Unassigned(122))
            .unwrap()
            .array(1)
            .unwrap();
        encode_auth_token(
            &mut encoder,
            &policy.client_state.policy,
            &spend_substitute_name,
        );
        encoder.array(2).unwrap().u64(1).unwrap().u64(1).unwrap();

        // RecoverClient withdrawal, Reward[0].
        encoder
            .array(4)
            .unwrap()
            .u8(3)
            .unwrap()
            .u32(0)
            .unwrap()
            .tag(minicbor::data::Tag::Unassigned(121))
            .unwrap()
            .array(2)
            .unwrap();
        encode_auth_token(&mut encoder, &policy.client_state.policy, &subject_name);
        encode_auth_token(&mut encoder, &policy.client_state.policy, &substitute_name);
        encoder
            .array(2)
            .unwrap()
            .u64(1)
            .unwrap()
            .u64(1)
            .unwrap()
            .bool(true)
            .unwrap()
            .null()
            .unwrap();
        encoded
    }

    fn recovery_resolved_inputs(policy: &TransactionSigningPolicy) -> ResolvedTransactionInputs {
        let mut resolved = ResolvedTransactionInputs::default();
        resolved.regular.insert(
            TransactionOutRef {
                transaction_id: RECOVERY_HOST_INPUT_ID,
                output_index: 0,
            },
            ResolvedInput {
                address: policy.host_state_address.clone(),
                lovelace: 2_000_000,
                assets: vec![ResolvedAsset {
                    policy_id: policy.host_state_nft_policy.clone().try_into().unwrap(),
                    asset_name: policy.host_state_nft_name.clone(),
                    quantity: 1,
                }],
            },
        );
        resolved.regular.insert(
            TransactionOutRef {
                transaction_id: RECOVERY_SUBJECT_INPUT_ID,
                output_index: 0,
            },
            ResolvedInput {
                address: policy.client_state.address.clone(),
                lovelace: 2_000_000,
                assets: vec![ResolvedAsset {
                    policy_id: policy.client_state.policy.clone().try_into().unwrap(),
                    asset_name: policy.state_token_name(StateOutputKind::Client, 7),
                    quantity: 1,
                }],
            },
        );
        resolved.regular.insert(
            TransactionOutRef {
                transaction_id: RECOVERY_SIGNER_INPUT_ID,
                output_index: 0,
            },
            ResolvedInput {
                address: hex::decode(recovery_signer()).unwrap(),
                lovelace: 3_000_000,
                assets: Vec::new(),
            },
        );
        resolved
    }

    fn validate_recovery_transaction(
        policy: &TransactionSigningPolicy,
        spend_substitute_sequence: u64,
    ) -> Result<(), Error> {
        let encoded = recovery_transaction(policy, spend_substitute_sequence);
        let mut decoder = minicbor::Decoder::new(&encoded);
        let transaction: MintedTx<'_> = decoder.decode().unwrap();
        assert_eq!(decoder.position(), encoded.len());
        policy.validate(
            &transaction,
            encoded.len(),
            &recovery_signer(),
            &recovery_intent(),
            &recovery_resolved_inputs(policy),
        )
    }

    #[test]
    fn complete_recovery_transaction_matches_signing_policy() {
        let policy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        validate_recovery_transaction(&policy, 12).unwrap();
    }

    #[test]
    fn complete_recovery_rejects_wrong_substitute_token() {
        let policy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        let error = validate_recovery_transaction(&policy, 13).unwrap_err();
        assert!(error
            .to_string()
            .contains("state input does not match the original IBC message"));
    }

    fn proof_backed_policy() -> TransactionSigningPolicy {
        let mut value: JsonValue = serde_json::from_str(&manifest()).unwrap();
        value["consensus_history_format"] = "proof-backed-v1".into();
        TransactionSigningPolicy::from_json(&value.to_string(), 0, limits()).unwrap()
    }

    fn update_intent() -> SigningIntent {
        let signer = recovery_signer();
        let message = MsgUpdateClient {
            client_id: "07-tendermint-7".to_string(),
            client_message: None,
            signer: signer.clone(),
        }
        .encode_to_vec();
        SigningIntent::ibc("/ibc.core.client.v1.MsgUpdateClient", &message, &signer, 0).unwrap()
    }

    fn data_constructor(alternative: u64, fields: Vec<PlutusData>) -> PlutusData {
        PlutusData::Constr(pallas_primitives::alonzo::Constr {
            tag: 121 + alternative,
            any_constructor: None,
            fields,
        })
    }

    #[test]
    fn plutus_output_reference_accepts_gateway_seed_cbor() {
        // Lucid Data.to({ transactionId: '91'.repeat(32), outputIndex: 2n },
        // Data.Object({ transactionId: Data.Bytes(), outputIndex: Data.Integer() })).
        // Aiken's OutputReference has a bare byte-string transaction ID.
        let cbor = hex::decode(
            "d8799f5820919191919191919191919191919191919191919191919191919191919191919102ff",
        )
        .unwrap();
        let seed: PlutusData = minicbor::decode(&cbor).unwrap();
        let reference = plutus_output_reference(&seed).expect("gateway seed must decode");
        assert_eq!(reference.transaction_id, [0x91; 32]);
        assert_eq!(reference.output_index, 2);
    }

    #[test]
    fn plutus_output_reference_rejects_malformed_seeds() {
        let hash = PlutusData::BoundedBytes(vec![0x91; 32].into());
        let index = PlutusData::BigInt(BigInt::Int(2.into()));
        let malformed = [
            data_constructor(1, vec![hash.clone(), index.clone()]),
            data_constructor(0, vec![hash.clone()]),
            data_constructor(0, vec![hash.clone(), index.clone(), index.clone()]),
            data_constructor(
                0,
                vec![data_constructor(0, vec![hash.clone()]), index.clone()],
            ),
            data_constructor(
                0,
                vec![
                    PlutusData::BoundedBytes(vec![0x91; 31].into()),
                    index.clone(),
                ],
            ),
            data_constructor(
                0,
                vec![
                    PlutusData::BoundedBytes(vec![0x91; 33].into()),
                    index.clone(),
                ],
            ),
            data_constructor(0, vec![index.clone(), index]),
            data_constructor(0, vec![hash.clone(), hash.clone()]),
            data_constructor(0, vec![hash, PlutusData::BigInt(BigInt::Int((-1).into()))]),
        ];
        for seed in malformed {
            assert!(
                plutus_output_reference(&seed).is_none(),
                "accepted {seed:?}"
            );
        }
    }

    fn data_token(policy: &[u8], name: &[u8]) -> PlutusData {
        data_constructor(
            0,
            vec![
                PlutusData::BoundedBytes(policy.to_vec().into()),
                PlutusData::BoundedBytes(name.to_vec().into()),
            ],
        )
    }

    fn data_siblings(count: usize, bytes: usize) -> PlutusData {
        PlutusData::Array(vec![PlutusData::BoundedBytes(vec![0; bytes].into()); count])
    }

    fn edit_redeemers(
        tx: &mut pallas_primitives::conway::Tx,
        edit: impl FnOnce(
            &mut Vec<(
                pallas_primitives::conway::RedeemersKey,
                pallas_primitives::conway::RedeemersValue,
            )>,
        ),
    ) {
        let mut values = tx
            .transaction_witness_set
            .redeemer
            .as_ref()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        edit(&mut values);
        tx.transaction_witness_set.redeemer = Some(pallas_primitives::conway::Redeemers::from(
            pallas_codec::utils::NonEmptyKeyValuePairs::try_from(values).unwrap(),
        ));
    }

    fn proof_backed_transaction(
        policy: &TransactionSigningPolicy,
        recovery: bool,
    ) -> pallas_primitives::conway::Tx {
        use pallas_primitives::conway::RedeemerTag;
        // Reuse the complete legacy policy fixture (including trusted wallet
        // resolution), replacing only the versioned client/HostState ABI.
        let mut tx: pallas_primitives::conway::Tx =
            minicbor::decode(&recovery_transaction(policy, 12)).unwrap();
        let subject = data_token(
            &policy.client_state.policy,
            &policy.state_token_name(StateOutputKind::Client, 7),
        );
        let substitute = data_token(
            &policy.client_state.policy,
            &policy.state_token_name(StateOutputKind::Client, 12),
        );
        edit_redeemers(&mut tx, |redeemers| {
            for (key, value) in redeemers {
                value.data = match (key.tag, key.index) {
                    (RedeemerTag::Spend, 0) => data_constructor(
                        4,
                        vec![PlutusData::Array(vec![]), PlutusData::Array(vec![])],
                    ),
                    (RedeemerTag::Spend, 1) if recovery => {
                        data_constructor(1, vec![substitute.clone(), data_siblings(64, 32)])
                    }
                    (RedeemerTag::Spend, 1) => data_constructor(
                        0,
                        vec![
                            data_constructor(0, vec![]),
                            PlutusData::Array(vec![]),
                            data_siblings(64, 32),
                        ],
                    ),
                    (RedeemerTag::Reward, 0) if recovery => {
                        data_constructor(0, vec![subject.clone(), substitute.clone()])
                    }
                    (RedeemerTag::Reward, 0) => data_constructor(1, vec![subject.clone()]),
                    _ => panic!("unexpected fixture redeemer"),
                };
            }
        });
        tx
    }

    fn validate_client_fixture(
        policy: &TransactionSigningPolicy,
        tx: &pallas_primitives::conway::Tx,
        recovery: bool,
    ) -> Result<(), Error> {
        let encoded = minicbor::to_vec(tx).unwrap();
        let transaction: MintedTx<'_> = minicbor::decode(&encoded).unwrap();
        policy.validate(
            &transaction,
            encoded.len(),
            &recovery_signer(),
            &if recovery {
                recovery_intent()
            } else {
                update_intent()
            },
            &recovery_resolved_inputs(policy),
        )
    }

    #[test]
    fn history_format_is_operator_pinned_and_unknown_formats_fail_closed() {
        let legacy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        assert_eq!(
            legacy.consensus_history_format,
            ConsensusHistoryFormat::Legacy
        );
        assert_eq!(
            proof_backed_policy().consensus_history_format,
            ConsensusHistoryFormat::ProofBackedV1
        );
        for format in [
            JsonValue::Null,
            true.into(),
            1.into(),
            "unknown".into(),
            "".into(),
        ] {
            let mut value: JsonValue = serde_json::from_str(&manifest()).unwrap();
            value["consensus_history_format"] = format;
            assert!(
                TransactionSigningPolicy::from_json(&value.to_string(), 0, limits())
                    .unwrap_err()
                    .contains("unsupported consensus_history_format")
            );
        }
        let mut value: JsonValue = serde_json::from_str(&manifest()).unwrap();
        value["consensus_history_format"] = "proof-backed-v1".into();
        value["validators"]
            .as_object_mut()
            .unwrap()
            .remove("recover_client");
        assert!(TransactionSigningPolicy::from_json(&value.to_string(), 0, limits()).is_err());
    }

    #[test]
    fn complete_proof_backed_update_and_recovery_match_signing_policy() {
        use pallas_primitives::conway::RedeemerTag;
        let policy = proof_backed_policy();
        for recovery in [false, true] {
            validate_client_fixture(
                &policy,
                &proof_backed_transaction(&policy, recovery),
                recovery,
            )
            .unwrap();
        }
        let mut freeze = proof_backed_transaction(&policy, false);
        edit_redeemers(&mut freeze, |values| {
            let (_, value) = values
                .iter_mut()
                .find(|(key, _)| key.tag == RedeemerTag::Spend && key.index == 1)
                .unwrap();
            let PlutusData::Constr(constructor) = &mut value.data else {
                unreachable!()
            };
            constructor.fields[2] = PlutusData::Array(vec![]);
        });
        // Empty insertion proofs are the freeze ABI. Classification/signatures
        // remain the pinned validator's responsibility, not this shape check.
        validate_client_fixture(&policy, &freeze, false).unwrap();
        let requirements = policy.operation_requirements(&update_intent()).unwrap();
        assert_eq!(
            requirements.required_scripts,
            vec!["spendclient", "recoverclient"]
        );
        assert!(requirements.required_mint_scripts.is_empty());
    }

    #[test]
    fn actual_evaluated_proof_backed_transactions_match_signing_policy() {
        // Exported only after the matching signed transaction was evaluated and
        // accepted by the production Aiken emulator fixture. These roots and
        // resolved inputs stand in for operator-pinned deployment data and the
        // independent Kupo resolver, never data inferred from transaction outputs.
        let fixture: JsonValue =
            serde_json::from_str(include_str!("fixtures/proof_backed_history_signing.json"))
                .unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 2);
        assert_eq!(cases[0]["name"], "update");
        assert_eq!(cases[1]["name"], "recovery");
        for case in cases {
            let mut pinned: JsonValue = serde_json::from_str(&manifest()).unwrap();
            for role in [
                "host_state_stt",
                "spend_client",
                "recover_client",
                "mint_client_stt",
            ] {
                pinned["validators"][role] = case["manifest"]["validators"][role].clone();
            }
            pinned["host_state_nft"] = case["manifest"]["host_state_nft"].clone();
            pinned["consensus_history_format"] =
                case["manifest"]["consensus_history_format"].clone();
            let ledger_sized_limits = SigningPolicyLimits {
                max_tx_size_bytes: 16_384,
                ..limits()
            };
            let policy =
                TransactionSigningPolicy::from_json(&pinned.to_string(), 0, ledger_sized_limits)
                    .unwrap();
            let signer = case["signer_address"].as_str().unwrap();
            let operation = case["operation"].as_str().unwrap();
            let client_id = case["client_id"].as_str().unwrap().to_string();
            let message = match operation {
                "/ibc.core.client.v1.MsgUpdateClient" => MsgUpdateClient {
                    client_id,
                    client_message: None,
                    signer: signer.to_string(),
                }
                .encode_to_vec(),
                "/ibc.core.client.v1.MsgRecoverClient" => MsgRecoverClient {
                    subject_client_id: client_id,
                    substitute_client_id: case["substitute_client_id"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    signer: signer.to_string(),
                }
                .encode_to_vec(),
                _ => panic!("unexpected fixture operation"),
            };
            let intent = SigningIntent::ibc(operation, &message, signer, 0).unwrap();
            let mut resolved = ResolvedTransactionInputs::default();
            for (kind, inputs) in [
                ("regular", &mut resolved.regular),
                ("collateral", &mut resolved.collateral),
            ] {
                for input in case["resolved_inputs"][kind].as_array().unwrap() {
                    let reference = TransactionOutRef {
                        transaction_id: hex::decode(input["tx_hash"].as_str().unwrap())
                            .unwrap()
                            .try_into()
                            .unwrap(),
                        output_index: input["output_index"].as_u64().unwrap(),
                    };
                    let value = ResolvedInput {
                        address: hex::decode(input["address"].as_str().unwrap()).unwrap(),
                        lovelace: input["lovelace"].as_str().unwrap().parse().unwrap(),
                        assets: input["assets"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|asset| ResolvedAsset {
                                policy_id: hex::decode(asset["policy_id"].as_str().unwrap())
                                    .unwrap()
                                    .try_into()
                                    .unwrap(),
                                asset_name: hex::decode(asset["asset_name"].as_str().unwrap())
                                    .unwrap(),
                                quantity: asset["quantity"].as_str().unwrap().parse().unwrap(),
                            })
                            .collect(),
                    };
                    assert!(inputs.insert(reference, value).is_none());
                }
            }
            let encoded = hex::decode(case["unsigned_tx_cbor"].as_str().unwrap()).unwrap();
            let mut decoder = minicbor::Decoder::new(&encoded);
            let transaction: MintedTx<'_> = decoder.decode().unwrap();
            assert_eq!(decoder.position(), encoded.len());
            policy
                .validate(&transaction, encoded.len(), signer, &intent, &resolved)
                .unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
        }
    }

    #[test]
    fn history_format_never_falls_back_to_legacy_authorization() {
        use pallas_primitives::conway::RedeemerTag;
        let policy = proof_backed_policy();
        let legacy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        let update = proof_backed_transaction(&policy, false);
        assert!(validate_client_fixture(&legacy, &update, false).is_err());
        assert!(
            validate_client_fixture(&legacy, &proof_backed_transaction(&policy, true), true)
                .is_err()
        );
        // Legacy update ABI still permits no withdrawal. The proof-backed mode
        // cannot accept that same transaction even with identical pinned roots.
        let mut legacy_update = update;
        legacy_update.transaction_body.withdrawals = None;
        edit_redeemers(&mut legacy_update, |values| {
            values.retain(|(key, _)| key.tag != RedeemerTag::Reward);
            values
                .iter_mut()
                .find(|(key, _)| key.tag == RedeemerTag::Spend && key.index == 1)
                .unwrap()
                .1
                .data = data_constructor(0, vec![data_constructor(0, vec![])]);
        });
        validate_client_fixture(&legacy, &legacy_update, false).unwrap();
        assert!(validate_client_fixture(&policy, &legacy_update, false).is_err());
        assert!(validate_recovery_transaction(&policy, 12).is_err());
    }

    #[test]
    fn proof_backed_client_transitions_reject_missing_or_unpinned_support_reference() {
        let policy = proof_backed_policy();
        let expected = required_script(&policy.scripts, "recoverclient")
            .unwrap()
            .reference
            .clone();
        for recovery in [false, true] {
            let mut tx = proof_backed_transaction(&policy, recovery);
            let mut references = tx
                .transaction_body
                .reference_inputs
                .clone()
                .unwrap()
                .to_vec();
            references
                .retain(|input| (input.transaction_id.as_ref().to_vec(), input.index) != expected);
            tx.transaction_body.reference_inputs = Some(references.clone().try_into().unwrap());
            assert!(validate_client_fixture(&policy, &tx, recovery)
                .unwrap_err()
                .to_string()
                .contains("pinned recoverclient reference script is missing"));
            references.push(pallas_primitives::conway::TransactionInput {
                transaction_id: [0x77; 32].into(),
                index: 0,
            });
            tx.transaction_body.reference_inputs = Some(references.try_into().unwrap());
            assert!(validate_client_fixture(&policy, &tx, recovery).is_err());
        }
    }

    #[test]
    fn proof_backed_client_transitions_reject_invalid_withdrawal_accounts_and_values() {
        let policy = proof_backed_policy();
        let credential = required_script(&policy.scripts, "recoverclient")
            .unwrap()
            .hash
            .clone();
        let valid_account = [&[0xf0][..], credential.as_slice()].concat();
        for recovery in [false, true] {
            for withdrawals in [
                None,
                Some(vec![(valid_account.clone(), 1)]),
                Some(vec![([&[0xf1][..], credential.as_slice()].concat(), 0)]),
                Some(vec![([&[0xe0][..], credential.as_slice()].concat(), 0)]),
                Some(vec![(vec![0xf0; 29], 0)]),
                Some(vec![(valid_account.clone(), 0), (vec![0xf0; 29], 0)]),
            ] {
                let mut tx = proof_backed_transaction(&policy, recovery);
                tx.transaction_body.withdrawals = withdrawals.map(|values| {
                    values
                        .into_iter()
                        .map(|(account, amount)| (account.into(), amount))
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap()
                });
                let error = validate_client_fixture(&policy, &tx, recovery)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("withdrawal"), "{error}");
            }
        }
    }

    #[test]
    fn proof_backed_mode_keeps_no_mint_and_unrelated_withdrawal_prohibitions() {
        let policy = proof_backed_policy();
        for recovery in [false, true] {
            let mut tx = proof_backed_transaction(&policy, recovery);
            tx.transaction_body.mint = Some(
                vec![(
                    policy.client_state.policy.as_slice().into(),
                    vec![(vec![1].into(), 1i64.try_into().unwrap())]
                        .try_into()
                        .unwrap(),
                )]
                .try_into()
                .unwrap(),
            );
            assert!(validate_client_fixture(&policy, &tx, recovery)
                .unwrap_err()
                .to_string()
                .contains("is not authorized for this IBC operation"));
        }
        let encoded = minicbor::to_vec(proof_backed_transaction(&policy, false)).unwrap();
        let tx: MintedTx<'_> = minicbor::decode(&encoded).unwrap();
        for operation in [
            "HostStateHeartbeat",
            "/ibc.core.client.v1.MsgCreateClient",
            "/ibc.core.channel.v1.MsgRecvPacket",
        ] {
            let intent = bare_intent(operation, None);
            assert!(policy
                .validate_withdrawals(&tx.transaction_body, &intent, false, &Error::Signer)
                .unwrap_err()
                .to_string()
                .contains("withdrawals are not authorized"));
        }
    }

    #[test]
    fn proof_backed_client_transitions_bind_exact_reward_branch_index_and_clients() {
        use pallas_primitives::conway::RedeemerTag;
        let policy = proof_backed_policy();
        let subject = data_token(
            &policy.client_state.policy,
            &policy.state_token_name(StateOutputKind::Client, 7),
        );
        let substitute = data_token(
            &policy.client_state.policy,
            &policy.state_token_name(StateOutputKind::Client, 12),
        );
        for recovery in [false, true] {
            let wrong_branch = if recovery {
                data_constructor(1, vec![subject.clone()])
            } else {
                data_constructor(0, vec![subject.clone(), substitute.clone()])
            };
            let correct_branch = if recovery { 0 } else { 1 };
            let mut wrong_client_fields = vec![substitute.clone()];
            if recovery {
                wrong_client_fields.push(substitute.clone());
            }
            let mut wrong_policy_fields = vec![data_token(
                &[0x77; 28],
                &policy.state_token_name(StateOutputKind::Client, 7),
            )];
            if recovery {
                wrong_policy_fields.push(substitute.clone());
            }
            let bad_data = vec![
                wrong_branch,
                data_constructor(correct_branch, vec![]),
                data_constructor(
                    correct_branch,
                    vec![subject.clone(), substitute.clone(), subject.clone()],
                ),
                data_constructor(correct_branch, wrong_client_fields),
                data_constructor(correct_branch, wrong_policy_fields),
            ];
            for data in bad_data {
                let mut tx = proof_backed_transaction(&policy, recovery);
                edit_redeemers(&mut tx, |values| {
                    values
                        .iter_mut()
                        .find(|(key, _)| key.tag == RedeemerTag::Reward)
                        .unwrap()
                        .1
                        .data = data;
                });
                assert!(validate_client_fixture(&policy, &tx, recovery)
                    .unwrap_err()
                    .to_string()
                    .contains("withdrawal redeemer"));
            }
            for mutation in 0..3 {
                let mut tx = proof_backed_transaction(&policy, recovery);
                edit_redeemers(&mut tx, |values| {
                    let position = values
                        .iter()
                        .position(|(key, _)| key.tag == RedeemerTag::Reward)
                        .unwrap();
                    match mutation {
                        0 => {
                            values.remove(position);
                        }
                        1 => {
                            values[position].0.index = 1;
                        }
                        _ => {
                            values.push(values[position].clone());
                        }
                    }
                });
                assert!(validate_client_fixture(&policy, &tx, recovery)
                    .unwrap_err()
                    .to_string()
                    .contains("withdrawal redeemer"));
            }
        }
        let mut tx = proof_backed_transaction(&policy, true);
        edit_redeemers(&mut tx, |values| {
            values
                .iter_mut()
                .find(|(key, _)| key.tag == RedeemerTag::Reward)
                .unwrap()
                .1
                .data = data_constructor(0, vec![subject.clone(), subject]);
        });
        assert!(validate_client_fixture(&policy, &tx, true).is_err());
    }

    #[test]
    fn proof_backed_spend_shapes_and_recovery_substitute_are_strict() {
        let policy = proof_backed_policy();
        let substitute_name = policy.state_token_name(StateOutputKind::Client, 12);
        let token = data_token(&policy.client_state.policy, &substitute_name);
        let expected = ChannelRedeemerIntent::ClientRecovery {
            alternative: 1,
            substitute_policy: policy.client_state.policy.clone(),
            substitute_name,
            history_format: ConsensusHistoryFormat::ProofBackedV1,
        };
        for (count, bytes) in [(0, 32), (63, 32), (65, 32), (64, 31), (64, 33)] {
            assert!(!expected.matches(&data_constructor(
                1,
                vec![token.clone(), data_siblings(count, bytes)]
            )));
        }
        assert!(!expected.matches(&data_constructor(1, vec![token.clone()])));
        assert!(!expected.matches(&data_constructor(
            1,
            vec![token.clone(), data_siblings(64, 32), token.clone()]
        )));
        assert!(!expected.matches(&data_constructor(
            1,
            vec![
                data_token(&policy.client_state.policy, b"other"),
                data_siblings(64, 32)
            ]
        )));
        assert!(expected.matches(&data_constructor(1, vec![token, data_siblings(64, 32)])));
        let update = ChannelRedeemerIntent::ProofBackedClientUpdate;
        for count in [0, 64] {
            assert!(update.matches(&data_constructor(
                0,
                vec![
                    data_constructor(0, vec![]),
                    PlutusData::Array(vec![]),
                    data_siblings(count, 32)
                ]
            )));
        }
        assert!(!update.matches(&data_constructor(0, vec![])));
        assert!(!update.matches(&data_constructor(
            0,
            vec![
                data_constructor(0, vec![]),
                PlutusData::Array(vec![]),
                data_siblings(63, 32)
            ]
        )));
        assert!(!update.matches(&data_constructor(
            0,
            vec![
                data_constructor(0, vec![]),
                PlutusData::Array(vec![data_constructor(0, vec![]); 3]),
                data_siblings(64, 32)
            ]
        )));
    }

    fn client_transaction(
        policy: &TransactionSigningPolicy,
        recovery: bool,
    ) -> pallas_primitives::conway::Tx {
        use pallas_primitives::conway::RedeemerTag;
        let mut tx: pallas_primitives::conway::Tx =
            minicbor::decode(&recovery_transaction(policy, 12)).unwrap();
        if !recovery {
            // Keep the existing legacy update ABI: no withdrawal, SpendClient
            // constructor zero. This is a signing-policy fixture, not an
            // on-chain Tendermint verification fixture.
            tx.transaction_body.withdrawals = None;
            edit_redeemers(&mut tx, |redeemers| {
                redeemers.retain(|(key, _)| key.tag != RedeemerTag::Reward);
                for (key, value) in redeemers {
                    if key.tag == RedeemerTag::Spend && key.index == 1 {
                        value.data = data_constructor(0, vec![]);
                    }
                }
            });
        }
        tx
    }

    fn validate_client_fixture_with_inputs(
        policy: &TransactionSigningPolicy,
        tx: &pallas_primitives::conway::Tx,
        recovery: bool,
        resolved: &ResolvedTransactionInputs,
    ) -> Result<(), Error> {
        let encoded = minicbor::to_vec(tx).unwrap();
        let transaction: MintedTx<'_> = minicbor::decode(&encoded).unwrap();
        policy.validate(
            &transaction,
            encoded.len(),
            &recovery_signer(),
            &if recovery {
                recovery_intent()
            } else {
                update_intent()
            },
            resolved,
        )
    }

    fn set_test_wallet_value(
        output: &mut pallas_primitives::conway::TransactionOutput,
        lovelace: u64,
        asset_quantity: Option<u64>,
    ) {
        let PseudoTransactionOutput::Legacy(output) = output else {
            panic!("expected legacy fixture output")
        };
        output.amount = match asset_quantity {
            None => LegacyValue::Coin(lovelace),
            Some(quantity) => LegacyValue::Multiasset(
                lovelace,
                vec![([0xbb; 28].into(), vec![(vec![1].into(), quantity)].into())].into(),
            ),
        };
    }

    fn shared_collateral_fixture(
        policy: &TransactionSigningPolicy,
        recovery: bool,
    ) -> (pallas_primitives::conway::Tx, ResolvedTransactionInputs) {
        let mut tx = client_transaction(policy, recovery);
        let mut resolved = recovery_resolved_inputs(policy);
        let reference = TransactionOutRef {
            transaction_id: RECOVERY_SIGNER_INPUT_ID,
            output_index: 0,
        };
        let wallet_input = resolved.regular.get_mut(&reference).unwrap();
        wallet_input.assets.push(ResolvedAsset {
            policy_id: [0xbb; 28],
            asset_name: vec![1],
            quantity: 7,
        });
        resolved.collateral.insert(reference, wallet_input.clone());
        tx.transaction_body.collateral = Some(
            vec![pallas_primitives::conway::TransactionInput {
                transaction_id: RECOVERY_SIGNER_INPUT_ID.into(),
                index: 0,
            }]
            .try_into()
            .unwrap(),
        );
        tx.transaction_body.total_collateral = Some(1_000_000);
        // Success: 3 ADA -> 2.5 ADA + 0.5 ADA fee. Failure: 3 ADA ->
        // 2 ADA collateral return + 1 ADA collateral. Tokens survive either path.
        set_test_wallet_value(&mut tx.transaction_body.outputs[2], 2_500_000, Some(7));
        let mut collateral_return = tx.transaction_body.outputs[2].clone();
        set_test_wallet_value(&mut collateral_return, 2_000_000, Some(7));
        tx.transaction_body.collateral_return = Some(collateral_return);
        (tx, resolved)
    }

    #[test]
    fn shared_wallet_input_keeps_success_and_failure_balances_separate() {
        let policy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        for recovery in [false, true] {
            let (tx, resolved) = shared_collateral_fixture(&policy, recovery);
            validate_client_fixture_with_inputs(&policy, &tx, recovery, &resolved).unwrap();
            let mut bad_success = tx.clone();
            set_test_wallet_value(
                &mut bad_success.transaction_body.outputs[2],
                2_500_000,
                Some(6),
            );
            assert!(validate_client_fixture_with_inputs(
                &policy,
                &bad_success,
                recovery,
                &resolved
            )
            .unwrap_err()
            .to_string()
            .contains("unauthorized signer asset"));
            let mut bad_failure = tx.clone();
            set_test_wallet_value(
                bad_failure
                    .transaction_body
                    .collateral_return
                    .as_mut()
                    .unwrap(),
                2_000_000,
                Some(6),
            );
            assert!(validate_client_fixture_with_inputs(
                &policy,
                &bad_failure,
                recovery,
                &resolved
            )
            .unwrap_err()
            .to_string()
            .contains("preserve all collateral native assets"));

            // A good failure return cannot compensate for excessive success loss.
            let mut tight_policy = policy.clone();
            tight_policy.limits.max_wallet_lovelace_top_up = 1;
            let mut bad_success_value = tx;
            set_test_wallet_value(
                &mut bad_success_value.transaction_body.outputs[2],
                2_000_000,
                Some(7),
            );
            assert!(validate_client_fixture_with_inputs(
                &tight_policy,
                &bad_success_value,
                recovery,
                &resolved
            )
            .unwrap_err()
            .to_string()
            .contains("configured top-up allowance"));
        }
    }

    #[test]
    fn shared_wallet_input_rejects_conflicting_trusted_resolution() {
        let policy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        let (tx, resolved) = shared_collateral_fixture(&policy, false);
        for mutation in 0..3 {
            let mut inconsistent = resolved.clone();
            let collateral = inconsistent.collateral.values_mut().next().unwrap();
            match mutation {
                0 => collateral.address[1] ^= 1,
                1 => collateral.lovelace += 1,
                _ => collateral.assets[0].quantity += 1,
            }
            assert!(
                validate_client_fixture_with_inputs(&policy, &tx, false, &inconsistent)
                    .unwrap_err()
                    .to_string()
                    .contains("disagrees for a shared regular/collateral input")
            );
        }
    }

    #[test]
    fn shared_collateral_keeps_duplicate_loss_return_and_ownership_checks() {
        let policy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        for recovery in [false, true] {
            let (tx, resolved) = shared_collateral_fixture(&policy, recovery);
            for mutation in 0..7 {
                let mut bad = tx.clone();
                let expected_error = match mutation {
                    0 => {
                        let input = bad
                            .transaction_body
                            .collateral
                            .as_ref()
                            .unwrap()
                            .first()
                            .unwrap()
                            .clone();
                        bad.transaction_body.collateral =
                            Some(vec![input.clone(), input].try_into().unwrap());
                        "collateral inputs contain duplicates"
                    }
                    1 => {
                        bad.transaction_body.total_collateral = None;
                        "explicit total collateral"
                    }
                    2 => {
                        bad.transaction_body.total_collateral = Some(0);
                        "greater than zero"
                    }
                    3 => {
                        bad.transaction_body.total_collateral =
                            Some(policy.limits.max_total_collateral_lovelace + 1);
                        "exceeds"
                    }
                    4 => {
                        bad.transaction_body.collateral_return = None;
                        "explicit collateral return"
                    }
                    5 => {
                        let PseudoTransactionOutput::Legacy(output) =
                            bad.transaction_body.collateral_return.as_mut().unwrap()
                        else {
                            unreachable!()
                        };
                        output.address = vec![0x60; 29].into();
                        "does not pay the configured relayer"
                    }
                    _ => {
                        set_test_wallet_value(
                            bad.transaction_body.collateral_return.as_mut().unwrap(),
                            2_000_001,
                            Some(7),
                        );
                        "collateral return is"
                    }
                };
                let error = validate_client_fixture_with_inputs(&policy, &bad, recovery, &resolved)
                    .unwrap_err()
                    .to_string();
                assert!(
                    error.contains(expected_error),
                    "mutation {mutation}: {error}"
                );
            }
            let mut foreign = tx;
            let mut foreign_resolved = resolved;
            foreign.transaction_body.collateral = Some(
                vec![pallas_primitives::conway::TransactionInput {
                    transaction_id: RECOVERY_HOST_INPUT_ID.into(),
                    index: 0,
                }]
                .try_into()
                .unwrap(),
            );
            foreign_resolved.collateral.clear();
            let reference = TransactionOutRef {
                transaction_id: RECOVERY_HOST_INPUT_ID,
                output_index: 0,
            };
            foreign_resolved.collateral.insert(
                reference.clone(),
                foreign_resolved.regular[&reference].clone(),
            );
            assert!(validate_client_fixture_with_inputs(
                &policy,
                &foreign,
                recovery,
                &foreign_resolved
            )
            .unwrap_err()
            .to_string()
            .contains("collateral input is not owned by the configured relayer"));
        }
    }

    fn staged_policy() -> TransactionSigningPolicy {
        let mut value: JsonValue = serde_json::from_str(&manifest()).unwrap();
        value["validators"]["spend_tendermint_update_session"] = serde_json::json!({
            "address": format!("70{}", "18".repeat(28)),
            "script_hash": "40".repeat(28),
            "ref_utxo": { "tx_hash": "50".repeat(32), "output_index": 0 }
        });
        value["validators"]["mint_tendermint_update_session"] = serde_json::json!({
            "script_hash": "41".repeat(28),
            "ref_utxo": { "tx_hash": "51".repeat(32), "output_index": 0 }
        });
        TransactionSigningPolicy::from_json(&serde_json::to_string(&value).unwrap(), 0, limits())
            .unwrap()
    }

    #[test]
    fn staged_advance_accepts_shared_wallet_collateral_without_relaxing_its_redeemer() {
        for proof_backed in [false, true] {
            let mut policy = staged_policy();
            if proof_backed {
                policy.consensus_history_format = ConsensusHistoryFormat::ProofBackedV1;
            }
            let session = policy.tendermint_session.as_ref().unwrap();
            let token_name = vec![0x55; 32];
            let (mut tx, mut resolved) = shared_collateral_fixture(&policy, false);
            tx.transaction_body.inputs = tx.transaction_body.inputs[1..].to_vec().into();
            resolved.regular.remove(&TransactionOutRef {
                transaction_id: RECOVERY_HOST_INPUT_ID,
                output_index: 0,
            });
            resolved.regular.insert(
                TransactionOutRef {
                    transaction_id: RECOVERY_SUBJECT_INPUT_ID,
                    output_index: 0,
                },
                ResolvedInput {
                    address: session.address.clone(),
                    lovelace: 2_000_000,
                    assets: vec![ResolvedAsset {
                        policy_id: session.policy.clone().try_into().unwrap(),
                        asset_name: token_name.clone(),
                        quantity: 1,
                    }],
                },
            );

            // Synthetic policy fixture: the ledger, not the signer, validates the
            // session datum and validator batch. Preserve the pinned NFT and inline
            // datum shape required by the staged signer.
            let mut encoded_output = Vec::new();
            let mut encoder = minicbor::Encoder::new(&mut encoded_output);
            encoder
                .map(3)
                .unwrap()
                .u8(0)
                .unwrap()
                .bytes(&session.address)
                .unwrap();
            encoder
                .u8(1)
                .unwrap()
                .array(2)
                .unwrap()
                .u64(2_000_000)
                .unwrap();
            encoder.map(1).unwrap().bytes(&session.policy).unwrap();
            encoder
                .map(1)
                .unwrap()
                .bytes(&token_name)
                .unwrap()
                .u64(1)
                .unwrap();
            encoder.u8(2).unwrap().array(2).unwrap().u8(1).unwrap();
            encoder
                .tag(minicbor::data::Tag::Cbor)
                .unwrap()
                .bytes(&[0xd8, 0x79, 0x80])
                .unwrap();
            tx.transaction_body.outputs = vec![
                minicbor::decode(&encoded_output).unwrap(),
                tx.transaction_body.outputs[2].clone(),
            ];
            let session_reference =
                &required_script(&policy.scripts, "spendtendermintupdatesession")
                    .unwrap()
                    .reference;
            tx.transaction_body.reference_inputs = Some(
                vec![pallas_primitives::conway::TransactionInput {
                    transaction_id: session_reference.0.as_slice().into(),
                    index: session_reference.1,
                }]
                .try_into()
                .unwrap(),
            );
            edit_redeemers(&mut tx, |redeemers| {
                redeemers.truncate(1);
                redeemers[0].1.data = data_constructor(
                    1,
                    vec![PlutusData::Array(vec![data_constructor(0, vec![])])],
                );
            });
            let signer = recovery_signer();
            let message = MsgUpdateClient {
                client_id: "07-tendermint-7".to_string(),
                client_message: Some(prost_types::Any {
                    type_url: TENDERMINT_HEADER_TYPE_URL.to_string(),
                    value: Vec::new(),
                }),
                signer: signer.clone(),
            }
            .encode_to_vec();
            let intent = SigningIntent::staged_tendermint_update(
                "/ibc.core.client.v1.MsgUpdateClient",
                &message,
                &signer,
                0,
            )
            .unwrap();
            let validate = |tx: &pallas_primitives::conway::Tx| {
                let encoded = minicbor::to_vec(tx).unwrap();
                let transaction: MintedTx<'_> = minicbor::decode(&encoded).unwrap();
                policy.validate(&transaction, encoded.len(), &signer, &intent, &resolved)
            };
            validate(&tx).unwrap();
            edit_redeemers(&mut tx, |redeemers| {
                redeemers[0].1.data = data_constructor(3, vec![]);
            });
            assert!(validate(&tx)
                .unwrap_err()
                .to_string()
                .contains("session advance must use VerifyTrusted or VerifyTarget"));
        }
    }

    fn staged_finalization_fixture(
        policy: &TransactionSigningPolicy,
        evidence: bool,
    ) -> (
        pallas_primitives::conway::Tx,
        ResolvedTransactionInputs,
        SigningIntent,
    ) {
        use pallas_primitives::conway::{ExUnits, RedeemerTag, RedeemersKey, RedeemersValue};
        let (mut tx, mut resolved) = shared_collateral_fixture(policy, false);
        let session = policy.tendermint_session.as_ref().unwrap();
        let names = if evidence {
            vec![vec![0x55; 32], vec![0x56; 32]]
        } else {
            vec![vec![0x55; 32]]
        };
        let mut inputs = tx.transaction_body.inputs.to_vec();
        for (index, name) in names.iter().enumerate() {
            let transaction_id = [0x44 + index as u8; 32];
            inputs.push(pallas_primitives::conway::TransactionInput {
                transaction_id: transaction_id.into(),
                index: 0,
            });
            resolved.regular.insert(
                TransactionOutRef {
                    transaction_id,
                    output_index: 0,
                },
                ResolvedInput {
                    address: session.address.clone(),
                    lovelace: 2_000_000,
                    assets: vec![ResolvedAsset {
                        policy_id: session.policy.clone().try_into().unwrap(),
                        asset_name: name.clone(),
                        quantity: 1,
                    }],
                },
            );
        }
        tx.transaction_body.inputs = inputs.into();
        tx.transaction_body.mint = Some(
            vec![(
                session.policy.as_slice().into(),
                names
                    .iter()
                    .map(|name| (name.clone().into(), (-1i64).try_into().unwrap()))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            )]
            .try_into()
            .unwrap(),
        );
        set_test_wallet_value(
            &mut tx.transaction_body.outputs[2],
            2_500_000 + 2_000_000 * names.len() as u64,
            Some(7),
        );
        let mut references: Vec<_> = tx
            .transaction_body
            .reference_inputs
            .as_ref()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        for script in [
            "spendtendermintupdatesession",
            "minttendermintupdatesession",
        ] {
            let reference = &required_script(&policy.scripts, script).unwrap().reference;
            references.push(pallas_primitives::conway::TransactionInput {
                transaction_id: reference.0.as_slice().into(),
                index: reference.1,
            });
        }
        tx.transaction_body.reference_inputs = Some(references.try_into().unwrap());
        if policy.consensus_history_format == ConsensusHistoryFormat::ProofBackedV1 {
            let support = required_script(&policy.scripts, "recoverclient").unwrap();
            let account = [&[0xf0 | policy.network_id][..], support.hash.as_slice()].concat();
            tx.transaction_body.withdrawals = Some(vec![(account.into(), 0)].try_into().unwrap());
            let mut refs = tx
                .transaction_body
                .reference_inputs
                .as_ref()
                .unwrap()
                .clone()
                .to_vec();
            let support_ref = pallas_primitives::conway::TransactionInput {
                transaction_id: support.reference.0.as_slice().into(),
                index: support.reference.1,
            };
            if !refs.contains(&support_ref) {
                refs.push(support_ref);
            }
            tx.transaction_body.reference_inputs = Some(refs.try_into().unwrap());
            edit_redeemers(&mut tx, |redeemers| {
                redeemers.push((
                    RedeemersKey {
                        tag: RedeemerTag::Reward,
                        index: 0,
                    },
                    RedeemersValue {
                        data: data_constructor(
                            4,
                            vec![data_token(
                                &policy.client_state.policy,
                                &policy.state_token_name(StateOutputKind::Client, 7),
                            )],
                        ),
                        ex_units: ExUnits { mem: 1, steps: 1 },
                    },
                ))
            });
        }
        edit_redeemers(&mut tx, |redeemers| {
            redeemers
                .iter_mut()
                .find(|(key, _)| key.tag == RedeemerTag::Spend && key.index == 1)
                .unwrap()
                .1
                .data = data_constructor(if evidence { 3 } else { 0 }, {
                let mut fields: Vec<_> = names
                    .iter()
                    .map(|name| data_token(&session.policy, name))
                    .collect();
                if policy.consensus_history_format == ConsensusHistoryFormat::ProofBackedV1 {
                    fields.push(PlutusData::Array(vec![]));
                    if !evidence {
                        fields.push(PlutusData::Array(vec![
                            PlutusData::BoundedBytes(
                                vec![0; 32].into()
                            );
                            64
                        ]));
                    }
                }
                fields
            });
            for index in 0..names.len() {
                redeemers.push((
                    RedeemersKey {
                        tag: RedeemerTag::Spend,
                        index: 3 + index as u32,
                    },
                    RedeemersValue {
                        data: data_constructor(2, vec![]),
                        ex_units: ExUnits { mem: 1, steps: 1 },
                    },
                ));
            }
            let burned = names
                .iter()
                .map(|name| PlutusData::BoundedBytes(name.clone().into()))
                .collect::<Vec<_>>();
            redeemers.push((
                RedeemersKey {
                    tag: RedeemerTag::Mint,
                    index: 0,
                },
                RedeemersValue {
                    data: data_constructor(
                        if evidence { 2 } else { 1 },
                        if evidence {
                            vec![PlutusData::Array(burned)]
                        } else {
                            burned
                        },
                    ),
                    ex_units: ExUnits { mem: 1, steps: 1 },
                },
            ));
        });
        let signer = recovery_signer();
        let message = MsgUpdateClient {
            client_id: "07-tendermint-7".into(),
            signer: signer.clone(),
            client_message: Some(prost_types::Any {
                type_url: if evidence {
                    TENDERMINT_MISBEHAVIOR_TYPE_URL
                } else {
                    TENDERMINT_HEADER_TYPE_URL
                }
                .into(),
                value: vec![],
            }),
        }
        .encode_to_vec();
        let intent = SigningIntent::staged_tendermint_update(
            "/ibc.core.client.v1.MsgUpdateClient",
            &message,
            &signer,
            0,
        )
        .unwrap();
        (tx, resolved, intent)
    }

    fn validate_staged_fixture(
        policy: &TransactionSigningPolicy,
        tx: &pallas_primitives::conway::Tx,
        resolved: &ResolvedTransactionInputs,
        intent: &SigningIntent,
    ) -> Result<(), Error> {
        let encoded = minicbor::to_vec(tx).unwrap();
        let transaction: MintedTx<'_> = minicbor::decode(&encoded).unwrap();
        policy.validate(
            &transaction,
            encoded.len(),
            &recovery_signer(),
            intent,
            resolved,
        )
    }

    #[test]
    fn proof_backed_staged_finalization_binds_history_shape_and_support_withdrawal() {
        use pallas_primitives::conway::RedeemerTag;
        let mut policy = staged_policy();
        policy.consensus_history_format = ConsensusHistoryFormat::ProofBackedV1;
        for evidence in [false, true] {
            let (tx, resolved, intent) = staged_finalization_fixture(&policy, evidence);
            validate_staged_fixture(&policy, &tx, &resolved, &intent).unwrap();
            let mut missing = tx.clone();
            missing.transaction_body.withdrawals = None;
            assert!(validate_staged_fixture(&policy, &missing, &resolved, &intent).is_err());
            let mut wrong_branch = tx.clone();
            edit_redeemers(&mut wrong_branch, |redeemers| {
                let reward = &mut redeemers
                    .iter_mut()
                    .find(|(key, _)| key.tag == RedeemerTag::Reward)
                    .unwrap()
                    .1;
                reward.data = data_constructor(
                    1,
                    vec![data_token(
                        &policy.client_state.policy,
                        &policy.state_token_name(StateOutputKind::Client, 7),
                    )],
                );
            });
            assert!(validate_staged_fixture(&policy, &wrong_branch, &resolved, &intent).is_err());
            for invalid in 0..4 {
                let mut changed = tx.clone();
                edit_redeemers(&mut changed, |redeemers| {
                    let data = &mut redeemers
                        .iter_mut()
                        .find(|(key, _)| key.tag == RedeemerTag::Spend && key.index == 1)
                        .unwrap()
                        .1
                        .data;
                    let alternative = if evidence { 3 } else { 0 };
                    let mut fields = constructor_fields(data, alternative).unwrap().to_vec();
                    match invalid {
                        0 => {
                            fields.pop();
                        }
                        1 => {
                            fields[if evidence { 2 } else { 1 }] =
                                PlutusData::Array(vec![data_constructor(0, vec![]); 3])
                        }
                        2 => fields[0] = data_token(&[0xaa; 28], &[0x55; 32]),
                        _ => fields[2] = PlutusData::BoundedBytes(vec![0; 32].into()),
                    }
                    *data = data_constructor(alternative, fields);
                });
                assert!(validate_staged_fixture(&policy, &changed, &resolved, &intent).is_err());
            }
        }
    }

    #[test]
    fn staged_finalization_requires_the_requested_header_or_evidence_shape() {
        let policy = staged_policy();
        for evidence in [false, true] {
            let (tx, resolved, mut intent) = staged_finalization_fixture(&policy, evidence);
            validate_staged_fixture(&policy, &tx, &resolved, &intent).unwrap();
            intent.staged_misbehaviour = !evidence;
            assert!(validate_staged_fixture(&policy, &tx, &resolved, &intent)
                .unwrap_err()
                .to_string()
                .contains("does not match the requested header or misbehaviour"));
        }
    }

    #[test]
    fn staged_misbehaviour_rejects_wrong_or_duplicate_session_redeemers() {
        use pallas_primitives::conway::RedeemerTag;
        let policy = staged_policy();
        let session = policy.tendermint_session.as_ref().unwrap();
        let (tx, resolved, intent) = staged_finalization_fixture(&policy, true);
        for mutation in 0..8 {
            let mut bad = tx.clone();
            edit_redeemers(&mut bad, |redeemers| {
                let (tag, index, data) = match mutation {
                    0 | 1 => (
                        RedeemerTag::Spend,
                        3 + mutation,
                        data_constructor(3, vec![]),
                    ),
                    2 => (
                        RedeemerTag::Mint,
                        0,
                        data_constructor(1, vec![PlutusData::BoundedBytes(vec![0x55; 32].into())]),
                    ),
                    3 => (
                        RedeemerTag::Mint,
                        0,
                        data_constructor(
                            2,
                            vec![PlutusData::Array(vec![
                                PlutusData::BoundedBytes(
                                    vec![0x55; 32].into()
                                );
                                2
                            ])],
                        ),
                    ),
                    4 => (
                        RedeemerTag::Spend,
                        1,
                        data_constructor(3, vec![data_token(&session.policy, &[0x55; 32]); 2]),
                    ),
                    5 => (
                        RedeemerTag::Spend,
                        1,
                        data_constructor(
                            3,
                            vec![
                                data_token(&session.policy, &[0x55; 32]),
                                data_token(&[0x98; 28], &[0x56; 32]),
                            ],
                        ),
                    ),
                    6 => (
                        RedeemerTag::Spend,
                        1,
                        data_constructor(0, vec![data_token(&session.policy, &[0x55; 32])]),
                    ),
                    _ => (RedeemerTag::Spend, 0, data_constructor(5, vec![])),
                };
                redeemers
                    .iter_mut()
                    .find(|(key, _)| key.tag == tag && key.index == index)
                    .unwrap()
                    .1
                    .data = data;
            });
            assert!(
                validate_staged_fixture(&policy, &bad, &resolved, &intent).is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn staged_misbehaviour_requires_exactly_two_pinned_session_burns_and_inputs() {
        let policy = staged_policy();
        let (tx, resolved, intent) = staged_finalization_fixture(&policy, true);
        for mutation in 0..8 {
            let mut bad = tx.clone();
            let mut bad_inputs = resolved.clone();
            match mutation {
                0 => bad.transaction_body.mint = None,
                1..=3 => {
                    let session = policy.tendermint_session.as_ref().unwrap();
                    let entries = if mutation == 1 {
                        vec![(0x55, -1)]
                    } else if mutation == 2 {
                        vec![(0x55, -1), (0x56, 1)]
                    } else {
                        vec![(0x55, -1), (0x57, -1)]
                    };
                    bad.transaction_body.mint = Some(
                        vec![(
                            session.policy.as_slice().into(),
                            entries
                                .into_iter()
                                .map(|(name, quantity)| {
                                    (
                                        vec![name; 32].into(),
                                        i64::from(quantity).try_into().unwrap(),
                                    )
                                })
                                .collect::<Vec<_>>()
                                .try_into()
                                .unwrap(),
                        )]
                        .try_into()
                        .unwrap(),
                    );
                }
                4 | 5 => {
                    let second = bad_inputs
                        .regular
                        .get_mut(&TransactionOutRef {
                            transaction_id: [0x45; 32],
                            output_index: 0,
                        })
                        .unwrap();
                    if mutation == 4 {
                        second.assets[0].asset_name = vec![0x55; 32];
                    } else {
                        second.assets[0].policy_id = [0x98; 28];
                    }
                }
                6 => {
                    let subject = bad_inputs
                        .regular
                        .get_mut(&TransactionOutRef {
                            transaction_id: RECOVERY_SUBJECT_INPUT_ID,
                            output_index: 0,
                        })
                        .unwrap();
                    subject.assets[0].asset_name =
                        policy.state_token_name(StateOutputKind::Client, 8);
                }
                _ => {
                    let third = bad_inputs.regular[&TransactionOutRef {
                        transaction_id: [0x45; 32],
                        output_index: 0,
                    }]
                        .clone();
                    bad_inputs.regular.insert(
                        TransactionOutRef {
                            transaction_id: [0x46; 32],
                            output_index: 0,
                        },
                        third,
                    );
                    let mut inputs = bad.transaction_body.inputs.to_vec();
                    inputs.push(pallas_primitives::conway::TransactionInput {
                        transaction_id: [0x46; 32].into(),
                        index: 0,
                    });
                    bad.transaction_body.inputs = inputs.into();
                }
            }
            assert!(
                validate_staged_fixture(&policy, &bad, &bad_inputs, &intent).is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn staged_recovery_uses_its_pinned_constructor_and_exact_substitute() {
        use pallas_primitives::conway::RedeemerTag;
        let policy = staged_policy();
        let mut tx = client_transaction(&policy, true);
        assert!(validate_client_fixture(&policy, &tx, true).is_err());
        edit_redeemers(&mut tx, |redeemers| {
            redeemers
                .iter_mut()
                .find(|(key, _)| key.tag == RedeemerTag::Spend && key.index == 1)
                .unwrap()
                .1
                .data = data_constructor(
                2,
                vec![data_token(
                    &policy.client_state.policy,
                    &policy.state_token_name(StateOutputKind::Client, 12),
                )],
            );
        });
        validate_client_fixture(&policy, &tx, true).unwrap();
        let direct = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        assert!(validate_client_fixture(&direct, &tx, true).is_err());
        edit_redeemers(&mut tx, |redeemers| {
            redeemers
                .iter_mut()
                .find(|(key, _)| key.tag == RedeemerTag::Spend && key.index == 1)
                .unwrap()
                .1
                .data = data_constructor(
                2,
                vec![data_token(
                    &policy.client_state.policy,
                    &policy.state_token_name(StateOutputKind::Client, 13),
                )],
            );
        });
        assert!(validate_client_fixture(&policy, &tx, true).is_err());
    }

    fn transaction_with_withdrawal(reward_account: &[u8], amount: u64) -> Vec<u8> {
        let mut encoded = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut encoded);
        encoder.array(4).unwrap();
        encoder.map(4).unwrap();
        encoder.u8(0).unwrap();
        encoder.array(0).unwrap();
        encoder.u8(1).unwrap();
        encoder.array(0).unwrap();
        encoder.u8(2).unwrap();
        encoder.u64(1).unwrap();
        encoder.u8(5).unwrap();
        encoder.map(1).unwrap();
        encoder.bytes(reward_account).unwrap();
        encoder.u64(amount).unwrap();
        encoder.map(0).unwrap();
        encoder.bool(true).unwrap();
        encoder.null().unwrap();
        encoded
    }

    #[test]
    fn only_the_pinned_zero_value_recovery_withdrawal_is_authorized() {
        let policy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        let recovery_script = required_script(&policy.scripts, "recoverclient").unwrap();
        let reward_account = [&[0xf0][..], recovery_script.hash.as_slice()].concat();
        let encoded = transaction_with_withdrawal(&reward_account, 0);
        let tx: MintedTx<'_> = minicbor::decode(&encoded).unwrap();
        let recovery_intent = bare_intent("/ibc.core.client.v1.MsgRecoverClient", None);
        let reject = |reason| Error::Signer(reason);

        policy
            .validate_withdrawals(&tx.transaction_body, &recovery_intent, false, &reject)
            .unwrap();

        let encoded = transaction_with_withdrawal(&reward_account, 1);
        let tx: MintedTx<'_> = minicbor::decode(&encoded).unwrap();
        assert!(policy
            .validate_withdrawals(&tx.transaction_body, &recovery_intent, false, &reject)
            .is_err());

        let encoded = transaction_with_withdrawal(&reward_account, 0);
        let tx: MintedTx<'_> = minicbor::decode(&encoded).unwrap();
        assert!(policy
            .validate_withdrawals(
                &tx.transaction_body,
                &bare_intent("/ibc.core.client.v1.MsgUpdateClient", None),
                false,
                &reject,
            )
            .is_err());
    }

    fn recovery_withdrawal_redeemer_data(
        policy: &[u8],
        subject_name: &[u8],
        substitute_name: &[u8],
    ) -> PlutusData {
        let mut encoded = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut encoded);
        encoder.tag(minicbor::data::Tag::Unassigned(121)).unwrap();
        encoder.array(2).unwrap();
        for name in [subject_name, substitute_name] {
            encoder.tag(minicbor::data::Tag::Unassigned(121)).unwrap();
            encoder.array(2).unwrap();
            encoder.bytes(policy).unwrap();
            encoder.bytes(name).unwrap();
        }
        minicbor::decode(&encoded).unwrap()
    }

    #[test]
    fn recovery_withdrawal_redeemer_binds_subject_and_substitute_tokens() {
        use pallas_codec::utils::NonEmptyKeyValuePairs;
        use pallas_primitives::conway::{
            ExUnits, RedeemerTag, Redeemers, RedeemersKey, RedeemersValue,
        };

        let policy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        let subject_name = policy.state_token_name(StateOutputKind::Client, 7);
        let substitute_name = policy.state_token_name(StateOutputKind::Client, 12);
        let data = recovery_withdrawal_redeemer_data(
            &policy.client_state.policy,
            &subject_name,
            &substitute_name,
        );
        let pairs: NonEmptyKeyValuePairs<_, _> = vec![(
            RedeemersKey {
                tag: RedeemerTag::Reward,
                index: 0,
            },
            RedeemersValue {
                data,
                ex_units: ExUnits { mem: 1, steps: 1 },
            },
        )]
        .try_into()
        .unwrap();
        let redeemers = Redeemers::from(pairs);
        let reject = |reason| Error::Signer(reason);

        policy
            .validate_client_withdrawal_redeemer(
                &redeemers,
                &subject_name,
                Some(&substitute_name),
                false,
                &reject,
            )
            .unwrap();
        assert!(policy
            .validate_client_withdrawal_redeemer(
                &redeemers,
                &substitute_name,
                Some(&subject_name),
                false,
                &reject,
            )
            .is_err());
    }

    fn transfer_message(denom: String, signer: String) -> Vec<u8> {
        ibc_proto::ibc::applications::transfer::v1::MsgTransfer {
            source_port: "transfer".to_string(),
            source_channel: "channel-0".to_string(),
            token: Some(ibc_proto::cosmos::base::v1beta1::Coin {
                denom,
                amount: "42".to_string(),
            }),
            sender: signer,
            receiver: "destination".to_string(),
            timeout_height: None,
            timeout_timestamp: 1,
            memo: String::new(),
        }
        .encode_to_vec()
    }

    #[test]
    fn outbound_transfer_sender_uses_payment_key_hash_without_relaxing_signer_check() {
        use bech32::ToBase32;

        let payment_key_hash = "99".repeat(28);
        let signer = format!("60{payment_key_hash}");
        let bech32_signer = bech32::encode(
            "addr_test",
            hex::decode(&signer).unwrap().to_base32(),
            bech32::Variant::Bech32,
        )
        .unwrap();

        for sender in [signer.clone(), bech32_signer, payment_key_hash.clone()] {
            let message = transfer_message("lovelace".to_string(), sender);
            let intent = SigningIntent::ibc(
                "/ibc.applications.transfer.v1.MsgTransfer",
                &message,
                &signer,
                0,
            )
            .unwrap();
            assert_eq!(intent.transfer.unwrap().sender, payment_key_hash);
        }

        for sender in [
            format!("60{}", "98".repeat(28)),
            format!("61{payment_key_hash}"),
            format!("70{payment_key_hash}"),
            format!("60{}", "99".repeat(27)),
        ] {
            let message = transfer_message("lovelace".to_string(), sender);
            assert!(SigningIntent::ibc(
                "/ibc.applications.transfer.v1.MsgTransfer",
                &message,
                &signer,
                0,
            )
            .is_err());
        }
    }

    #[test]
    fn outbound_transfer_packet_still_binds_the_sender_to_the_message() {
        let payment_key_hash = "99".repeat(28);
        let signer = format!("60{payment_key_hash}");
        let message = transfer_message("lovelace".to_string(), signer.clone());
        let intent = SigningIntent::ibc(
            "/ibc.applications.transfer.v1.MsgTransfer",
            &message,
            &signer,
            0,
        )
        .unwrap();
        let transfer = intent.transfer.as_ref().unwrap();
        let bytes = |value: &[u8]| PlutusData::BoundedBytes(value.to_vec().into());
        let integer = |value: i64| PlutusData::BigInt(BigInt::Int(value.into()));
        let constructor = |fields: Vec<PlutusData>| {
            PlutusData::Constr(pallas_primitives::alonzo::Constr {
                tag: 121,
                any_constructor: None,
                fields: fields.into(),
            })
        };
        let packet_json = serde_json::json!({
            "denom": LOVELACE_HEX,
            "amount": "42",
            "sender": payment_key_hash,
            "receiver": "destination",
            "memo": "",
        });
        let fields = vec![
            integer(1),
            bytes(b"transfer"),
            bytes(b"channel-0"),
            bytes(b"transfer"),
            bytes(b"channel-1"),
            bytes(&serde_json::to_vec(&packet_json).unwrap()),
            constructor(vec![integer(0), integer(0)]),
            integer(1),
        ];
        assert!(outbound_transfer_packet_matches(
            &constructor(fields.clone()),
            transfer
        ));

        for altered_sender in [signer, "98".repeat(28)] {
            let mut altered_packet = packet_json.clone();
            altered_packet["sender"] = serde_json::Value::String(altered_sender);
            let mut altered_fields = fields.clone();
            altered_fields[5] = bytes(&serde_json::to_vec(&altered_packet).unwrap());
            assert!(!outbound_transfer_packet_matches(
                &constructor(altered_fields),
                transfer,
            ));
        }
    }

    #[test]
    fn hashed_transfer_denom_is_resolved_only_by_matching_sha256_preimage() {
        let signer = format!("60{}", "99".repeat(28));
        let full_denom = "transfer/channel-7/uatom";
        let hash = hex::encode_upper(Sha256::digest(full_denom.as_bytes()));
        let message = transfer_message(format!("ibc/{hash}"), signer.clone());
        let mut intent = SigningIntent::ibc(
            "/ibc.applications.transfer.v1.MsgTransfer",
            &message,
            &signer,
            0,
        )
        .unwrap();

        assert_eq!(intent.unresolved_ibc_denom_hash(), Some(hash.as_str()));
        intent.resolve_ibc_denom(full_denom).unwrap();
        assert_eq!(intent.unresolved_ibc_denom_hash(), None);
        let transfer = intent.transfer.as_ref().unwrap();
        assert_eq!(transfer.denom, full_denom);
        assert!(matches!(
            expected_asset(transfer),
            ExpectedAsset::Voucher {
                user_name: Some(_),
                reference_name: Some(_)
            }
        ));
    }

    #[test]
    fn hashed_transfer_denom_rejects_wrong_preimage_and_noncanonical_hash() {
        let signer = format!("60{}", "99".repeat(28));
        let hash = hex::encode_upper(Sha256::digest(b"transfer/channel-7/uatom"));
        let message = transfer_message(format!("ibc/{hash}"), signer.clone());
        let mut intent = SigningIntent::ibc(
            "/ibc.applications.transfer.v1.MsgTransfer",
            &message,
            &signer,
            0,
        )
        .unwrap();

        let error = intent
            .resolve_ibc_denom("transfer/channel-7/uosmo")
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("does not match requested ICS-20 hash"));

        let malformed = transfer_message("ibc/not-a-sha256-hash".to_string(), signer.clone());
        let error = SigningIntent::ibc(
            "/ibc.applications.transfer.v1.MsgTransfer",
            &malformed,
            &signer,
            0,
        )
        .unwrap_err();
        assert!(error.to_string().contains("canonical ibc/<64-hex>"));
    }

    #[test]
    fn outbound_voucher_burn_requires_transfer_module_state() {
        let signer = format!("60{}", "99".repeat(28));
        let message = transfer_message("transfer/channel-0/uatom".to_string(), signer.clone());
        let intent = SigningIntent::ibc(
            "/ibc.applications.transfer.v1.MsgTransfer",
            &message,
            &signer,
            0,
        )
        .unwrap();
        assert_eq!(
            intent.transfer.as_ref().and_then(voucher_mint_action),
            Some(VoucherMintAction::Burn)
        );

        let policy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        let requirements = policy.operation_requirements(&intent).unwrap();
        assert_eq!(
            requirements
                .module
                .expect("voucher burns spend transfer module state")
                .reference_script,
            "spendtransfermodule"
        );
        assert!(requirements
            .required_scripts
            .contains(&"spendtransfermodule"));
    }

    fn bare_intent(operation: &str, module_port: Option<&str>) -> SigningIntent {
        SigningIntent {
            operation: operation.to_string(),
            module_port: module_port.map(str::to_string),
            external_output: None,
            transfer: None,
            state_sequence: None,
            recovery_substitute_sequence: None,
            packet: None,
            acknowledgement: None,
            prune_sequence: None,
            staged_tendermint: false,
            staged_misbehaviour: false,
        }
    }

    #[test]
    fn proof_bearing_handshakes_require_verify_proof_mint() {
        let policy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();

        let connection_try = policy
            .operation_requirements(&bare_intent(
                "/ibc.core.connection.v1.MsgConnectionOpenTry",
                None,
            ))
            .unwrap();
        assert_eq!(
            connection_try.required_scripts,
            vec!["mintconnectionstt", "verifyproof"]
        );
        assert_eq!(
            connection_try.required_mint_scripts,
            vec!["mintconnectionstt", "verifyproof"]
        );

        let connection_confirm = policy
            .operation_requirements(&bare_intent(
                "/ibc.core.connection.v1.MsgConnectionOpenConfirm",
                None,
            ))
            .unwrap();
        assert_eq!(
            connection_confirm.required_scripts,
            vec!["spendconnection", "verifyproof"]
        );
        assert_eq!(
            connection_confirm.required_mint_scripts,
            vec!["verifyproof"]
        );

        let channel_try = policy
            .operation_requirements(&bare_intent(
                "/ibc.core.channel.v1.MsgChannelOpenTry",
                Some("transfer"),
            ))
            .unwrap();
        assert_eq!(
            channel_try.required_scripts,
            vec!["mintchannelstt", "verifyproof", "spendtransfermodule"]
        );
        assert_eq!(
            channel_try.required_mint_scripts,
            vec!["mintchannelstt", "verifyproof"]
        );
    }

    #[test]
    fn proof_free_handshake_inits_do_not_require_verify_proof() {
        let policy = TransactionSigningPolicy::from_json(&manifest(), 0, limits()).unwrap();
        let connection_init = policy
            .operation_requirements(&bare_intent(
                "/ibc.core.connection.v1.MsgConnectionOpenInit",
                None,
            ))
            .unwrap();
        assert_eq!(connection_init.required_scripts, vec!["mintconnectionstt"]);
        assert_eq!(
            connection_init.required_mint_scripts,
            vec!["mintconnectionstt"]
        );

        let channel_init = policy
            .operation_requirements(&bare_intent(
                "/ibc.core.channel.v1.MsgChannelOpenInit",
                Some("transfer"),
            ))
            .unwrap();
        assert_eq!(
            channel_init.required_scripts,
            vec!["mintchannelstt", "spendtransfermodule"]
        );
        assert_eq!(channel_init.required_mint_scripts, vec!["mintchannelstt"]);
    }

    #[test]
    fn address_credentials_are_normalized_to_enterprise_addresses() {
        assert_eq!(
            decode_address(&"ab".repeat(28), 0).unwrap(),
            [vec![0x60], vec![0xab; 28]].concat()
        );
    }

    #[test]
    fn foreign_network_addresses_are_rejected() {
        let error = decode_address(&format!("61{}", "ab".repeat(28)), 0).unwrap_err();
        assert!(error.contains("does not match configured network"));
    }

    #[test]
    fn message_binding_uses_redeemer_for_exact_sorted_input_not_decoy() {
        let mut encoded = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut encoded);
        encoder.array(4).unwrap();
        encoder.map(3).unwrap();
        encoder.u8(0).unwrap();
        encoder.array(2).unwrap();
        // Deliberately encode the inputs out of lexical order. Spend pointers
        // use the ledger's sorted transaction-input order.
        for transaction_id in [[0x22; 32], [0x11; 32]] {
            encoder.array(2).unwrap();
            encoder.bytes(&transaction_id).unwrap();
            encoder.u64(0).unwrap();
        }
        encoder.u8(1).unwrap();
        encoder.array(0).unwrap();
        encoder.u8(2).unwrap();
        encoder.u64(1).unwrap();

        encoder.map(1).unwrap();
        encoder.u8(5).unwrap();
        encoder.array(2).unwrap();
        for (index, constructor_tag) in [(0u32, 127u64), (1u32, 126u64)] {
            encoder.array(4).unwrap();
            encoder.u8(0).unwrap();
            encoder.u32(index).unwrap();
            encoder
                .tag(minicbor::data::Tag::Unassigned(constructor_tag))
                .unwrap();
            encoder.array(0).unwrap();
            encoder.array(2).unwrap();
            encoder.u64(1).unwrap();
            encoder.u64(1).unwrap();
        }
        encoder.bool(true).unwrap();
        encoder.null().unwrap();

        let tx: MintedTx<'_> = minicbor::decode(&encoded).unwrap();
        let redeemers = tx.transaction_witness_set.redeemer.as_deref().unwrap();
        let expected = ChannelRedeemerIntent::Constructor(5);
        assert!(redeemers
            .iter()
            .any(|(_, value)| expected.matches(&value.data)));

        let attached = spend_redeemer_for_input(
            &tx.transaction_body,
            redeemers,
            &TransactionOutRef {
                transaction_id: [0x11; 32],
                output_index: 0,
            },
        )
        .unwrap();
        assert_eq!(
            constructor_alternative(match attached {
                PlutusData::Constr(constructor) => constructor,
                _ => panic!("expected constructor"),
            }),
            Some(6)
        );
        assert!(!expected.matches(attached));
    }

    #[test]
    fn expected_asset_unwraps_ics20_source_prefix() {
        let transfer = TransferIntent {
            denom: format!("transfer/channel-0/{}", "ab".repeat(28)),
            amount: 10,
            source_port: Some("transfer".to_string()),
            source_channel: Some("channel-0".to_string()),
            destination_port: None,
            destination_channel: None,
            sender: String::new(),
            receiver: String::new(),
            memo: String::new(),
            timeout_revision_number: 0,
            timeout_revision_height: 0,
            timeout_timestamp: 0,
            action: TransferAction::Receive,
        };
        assert!(matches!(
            expected_asset(&transfer),
            ExpectedAsset::Native(_, _)
        ));
    }
}
