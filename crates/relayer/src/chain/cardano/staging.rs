//! Destination snapshot queries and resumable bounded observations. Public client
//! records stay bounded, expansion happens only in this off-chain evidence builder.
use bech32::FromBase32;
use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn hash(raw: &[u8]) -> Vec<u8> {
    Sha256::digest(raw).to_vec()
}
fn byte_field(value: &Value, name: &str) -> Result<Vec<u8>, String> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::String(text)) => {
            subtle_encoding::base64::decode(text.as_bytes()).map_err(|e| e.to_string())
        }
        Some(Value::Array(bytes)) => bytes
            .iter()
            .map(|v| {
                v.as_u64()
                    .filter(|n| *n <= 255)
                    .map(|n| n as u8)
                    .ok_or_else(|| format!("Invalid byte in {name}"))
            })
            .collect(),
        _ => Err(format!("Invalid byte field {name}")),
    }
}
fn number(value: &Value, name: &str) -> Result<u64, String> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("Missing integer {name}"))
}
fn convert_json_bytes(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                if [
                    "vrf_key_hash",
                    "pending_vrf_key_hash",
                    "numerator",
                    "denominator",
                    "epoch_nonce",
                    "evolving_nonce",
                    "candidate_nonce",
                    "last_applied_block_nonce",
                    "last_epoch_block_nonce",
                ]
                .contains(&name.as_str())
                {
                    if let Value::String(text) = value {
                        if let Ok(bytes) = subtle_encoding::base64::decode(text.as_bytes()) {
                            *value = serde_json::to_value(bytes).unwrap();
                        }
                    }
                } else {
                    convert_json_bytes(value)
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                convert_json_bytes(item)
            }
        }
        _ => {}
    }
}
fn records<T: DeserializeOwned>(
    client: &raw::ClientState,
    reference: &[u8],
    kind: u32,
    query: &mut impl FnMut(raw::QueryVerificationRequest) -> Result<Vec<u8>, String>,
) -> Result<Vec<T>, String> {
    let mut after = vec![];
    let mut result = vec![];
    // Registry lifetime capacity is independent of the 4,000-row election table.
    for _ in 0..=513 {
        let response = query(raw::QueryVerificationRequest {
            namespace: client.storage_namespace.clone(),
            generation: client.verification_generation,
            checkpoint_reference: reference.to_vec(),
            kind,
            after: after.clone(),
            limit: 128,
            ..Default::default()
        })?;
        let mut page: Value = serde_json::from_slice(&response).map_err(|e| e.to_string())?;
        convert_json_bytes(&mut page);
        if let Some(rows) = page.get("records").and_then(Value::as_array) {
            for row in rows {
                result.push(serde_json::from_value(row.clone()).map_err(|e| e.to_string())?)
            }
        }
        let next = byte_field(&page, "next")?;
        if next.is_empty() {
            return Ok(result);
        }
        if next <= after {
            return Err("Destination snapshot page did not advance".into());
        }
        after = next;
    }
    Err("Destination snapshot exceeded the retained identity capacity".into())
}

pub(crate) fn hydrate(
    mut client: raw::ClientState,
    reference: Vec<u8>,
    mut query: impl FnMut(raw::QueryVerificationRequest) -> Result<Vec<u8>, String>,
) -> Result<raw::ClientState, String> {
    if client.storage_version != 2 {
        return Err("Unsupported probabilistic client storage format".into());
    }
    let raw = query(raw::QueryVerificationRequest {
        namespace: client.storage_namespace.clone(),
        generation: client.verification_generation,
        checkpoint_reference: reference.clone(),
        kind: 0,
        ..Default::default()
    })?;
    let mut metadata: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    convert_json_bytes(&mut metadata);
    let epoch = number(&metadata, "Epoch")?;
    let length = client
        .current_epoch_end_slot_exclusive
        .checked_sub(client.current_epoch_start_slot)
        .filter(|n| *n > 0)
        .ok_or("Invalid authenticated epoch schedule")?;
    let start = if epoch >= client.current_epoch {
        client.current_epoch_start_slot.checked_add(
            (epoch - client.current_epoch)
                .checked_mul(length)
                .ok_or("Epoch schedule overflow")?,
        )
    } else {
        client.current_epoch_start_slot.checked_sub(
            (client.current_epoch - epoch)
                .checked_mul(length)
                .ok_or("Epoch schedule overflow")?,
        )
    }
    .ok_or("Epoch schedule overflow")?;
    let end = start.checked_add(length).ok_or("Epoch schedule overflow")?;
    let effective: Vec<raw::PoolRegistrationBinding> = records(&client, &reference, 1, &mut query)?;
    let mut stake: Vec<raw::StakeDistributionEntry> = records(&client, &reference, 2, &mut query)?;
    let by_pool: std::collections::BTreeMap<_, _> = effective
        .iter()
        .map(|binding| (binding.pool_id.as_str(), binding))
        .collect();
    for row in &mut stake {
        let binding = by_pool
            .get(row.pool_id.as_str())
            .ok_or("Sealed stake row has no effective registration")?;
        row.vrf_key_hash = binding.vrf_key_hash.clone();
        row.first_registration_slot = binding.first_registration_slot;
    }
    let credit = records(&client, &reference, 3, &mut query)?;
    let production = records(&client, &reference, 4, &mut query)?;
    let pools = records(&client, &reference, 6, &mut query)?;
    let mark = records(&client, &reference, 7, &mut query)?;
    let nonce: raw::PraosNonceState = serde_json::from_value(
        metadata
            .get("Nonce")
            .ok_or("Missing checkpoint nonce")?
            .clone(),
    )
    .map_err(|e| e.to_string())?;
    client.current_epoch = epoch;
    client.current_epoch_start_slot = start;
    client.current_epoch_end_slot_exclusive = end;
    client.latest_checkpoint_height = Some(raw::Height {
        revision_number: 0,
        revision_height: number(&metadata, "Height")?,
    });
    client.latest_height = client.latest_checkpoint_height.clone();
    client.latest_checkpoint_epoch = epoch;
    client.latest_checkpoint_slot = number(&metadata, "Slot")?;
    client.latest_checkpoint_timestamp = number(&metadata, "Timestamp")?;
    client.latest_checkpoint_block_hash = metadata
        .get("BlockHash")
        .and_then(Value::as_str)
        .ok_or("Missing checkpoint block hash")?
        .to_owned();
    client.checkpoint_reference = reference;
    client.epoch_nonce = nonce.epoch_nonce.clone();
    client.latest_checkpoint_nonce_state = Some(nonce);
    client.epoch_stake_distribution = stake.clone();
    client.epoch_contexts = vec![raw::EpochContext {
        epoch,
        stake_distribution: stake,
        epoch_nonce: client.epoch_nonce.clone(),
        slots_per_kes_period: client.slots_per_kes_period,
        epoch_start_slot: start,
        epoch_end_slot_exclusive: end,
    }];
    client.latest_checkpoint_pool_registry = Some(raw::PoolRegistryState {
        epoch,
        pools,
        mark,
        effective,
    });
    client.latest_checkpoint_settlement_credit = Some(raw::SettlementCreditState {
        epoch,
        reference: credit,
    });
    client.latest_checkpoint_pool_production = Some(raw::PoolProductionHistory {
        epoch,
        pools: production,
    });
    Ok(client)
}

pub(crate) struct ObservationPlan {
    pub id: Vec<u8>,
    pub begin: raw::ObservationChunk,
    pub rows: Vec<u8>,
    pub blocks: Vec<raw::ProbabilisticBlock>,
    row_suffixes: Vec<Vec<u8>>,
    block_suffixes: Vec<Vec<u8>>,
}
fn extend_u64(raw: &mut Vec<u8>, value: u64) {
    raw.extend_from_slice(&value.to_be_bytes())
}
fn session_id(client: &raw::ClientState, chunk: &raw::ObservationChunk) -> Result<Vec<u8>, String> {
    let mut bytes = b"cardano-ibc.session/v2\0".to_vec();
    bytes.extend_from_slice(&client.storage_namespace);
    extend_u64(&mut bytes, client.verification_generation);
    bytes.extend_from_slice(&chunk.base_checkpoint_reference);
    bytes.extend_from_slice(&(chunk.original_receipt.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&chunk.original_receipt);
    extend_u64(&mut bytes, chunk.anchor_height);
    bytes.extend_from_slice(&chunk.block_count.to_be_bytes());
    bytes.push(u8::from(chunk.is_checkpoint) | (u8::from(chunk.isolated) << 1));
    if chunk.host_state_tx_hash.is_empty() {
        bytes.extend_from_slice(&[0; 32])
    } else {
        bytes.extend_from_slice(&hex::decode(&chunk.host_state_tx_hash).map_err(|e| e.to_string())?)
    }
    if let Some(table) = &chunk.table_context {
        bytes.push(1);
        for value in [
            table.epoch,
            chunk.table_rows as u64,
            chunk.table_total,
            table.slots_per_kes_period,
            table.epoch_start_slot,
            table.epoch_end_slot_exclusive,
        ] {
            extend_u64(&mut bytes, value)
        }
        bytes.extend_from_slice(&table.epoch_nonce);
        bytes.extend_from_slice(&chunk.table_digest);
    } else {
        bytes.push(0)
    }
    bytes.extend_from_slice(&chunk.evidence_digest);
    Ok(hash(&bytes))
}
pub(crate) fn plan(
    client: &raw::ClientState,
    header: &raw::ProbabilisticHeader,
    original: Vec<u8>,
) -> Result<ObservationPlan, String> {
    let anchor = header
        .anchor_block
        .as_ref()
        .ok_or("Missing observation anchor")?;
    let anchor_height = anchor
        .height
        .as_ref()
        .ok_or("Missing observation anchor height")?
        .revision_height;
    let mut begin = raw::ObservationChunk {
        operation: 1,
        base_checkpoint_reference: client.checkpoint_reference.clone(),
        original_receipt: original,
        anchor_height,
        block_count: (header.bridge_blocks.len() + 1 + header.descendant_blocks.len()) as u32,
        is_checkpoint: header.is_checkpoint,
        host_state_tx_hash: header.host_state_tx_hash.clone(),
        ..Default::default()
    };
    let mut table_digest = hash(b"cardano-ibc.stake-table/v2\0");
    let mut rows = vec![];
    if let Some(context) = header
        .new_epoch_context
        .as_ref()
        .filter(|context| context.epoch > client.current_epoch)
    {
        let mut entries = Vec::new();
        for row in &context.stake_distribution {
            let (prefix, data, variant) =
                bech32::decode(&row.pool_id).map_err(|e| e.to_string())?;
            let key = Vec::<u8>::from_base32(&data).map_err(|e| e.to_string())?;
            if prefix != "pool"
                || variant != bech32::Variant::Bech32
                || key.len() != 28
                || row.stake == 0
            {
                return Err("Invalid canonical stake row".into());
            }
            entries.push((key, row.stake));
        }
        entries.sort();
        let mut last = vec![];
        for (key, amount) in entries {
            if key <= last {
                return Err("Duplicate stake identity".into());
            };
            last = key.clone();
            let row = [key, amount.to_be_bytes().to_vec()].concat();
            begin.table_total = begin
                .table_total
                .checked_add(amount)
                .ok_or("Stake total overflow")?;
            rows.extend_from_slice(&row);
            table_digest = hash(&[table_digest, row].concat());
        }
        let mut table = context.clone();
        table.stake_distribution.clear();
        begin.table_context = Some(table);
        begin.table_rows = (rows.len() / 36) as u32;
        begin.table_digest = table_digest;
    }
    let mut blocks = header.bridge_blocks.clone();
    blocks.push(anchor.clone());
    blocks.extend(header.descendant_blocks.clone());
    let mut records = vec![];
    for block in &blocks {
        let height = block.height.as_ref().ok_or("Missing evidence height")?;
        if height.revision_number != 0 {
            return Err("Unsupported source revision".into());
        }
        let mut record = vec![];
        for value in [
            height.revision_height,
            block.slot,
            block.epoch,
            block.timestamp,
        ] {
            extend_u64(&mut record, value)
        }
        let hash = hex::decode(&block.hash).map_err(|e| e.to_string())?;
        if hash.len() != 32 {
            return Err("Invalid native block hash".into());
        };
        record.extend_from_slice(&hash);
        if height.revision_height > anchor_height && !block.block_cbor.is_empty() {
            return Err("Gateway must provide compact descendant headers for staging".into());
        }
        let witness = if block.block_cbor.is_empty() {
            &block.header_cbor
        } else {
            &block.block_cbor
        };
        record.extend_from_slice(&(witness.len() as u32).to_be_bytes());
        record.extend_from_slice(witness);
        records.push(record);
    }
    let mut block_suffixes = vec![vec![]; blocks.len() + 1];
    block_suffixes[blocks.len()] = hash(
        &[
            b"cardano-ibc.observation-segments/v2\0".as_slice(),
            &client.checkpoint_reference,
        ]
        .concat(),
    );
    for i in (0..blocks.len()).rev() {
        block_suffixes[i] = hash(&[&block_suffixes[i + 1][..], &records[i]].concat());
    }
    let mut row_suffixes = vec![vec![]; rows.len() / 36 + 1];
    let last = row_suffixes.len() - 1;
    row_suffixes[last] = block_suffixes[0].clone();
    for i in (0..last).rev() {
        row_suffixes[i] = hash(&[&row_suffixes[i + 1][..], &rows[i * 36..(i + 1) * 36]].concat());
    }
    begin.evidence_digest = row_suffixes[0].clone();
    let id = session_id(client, &begin)?;
    Ok(ObservationPlan {
        id,
        begin,
        rows,
        blocks,
        row_suffixes,
        block_suffixes,
    })
}

pub(crate) fn submit(
    plan: &ObservationPlan,
    mut query: impl FnMut(&[u8]) -> Result<Value, String>,
    mut send: impl FnMut(raw::ObservationChunk) -> Result<(), String>,
) -> Result<Vec<u8>, String> {
    send(plan.begin.clone())?;
    for _ in 0..4096 {
        let session = query(&plan.id)?;
        if session.get("Complete").and_then(Value::as_bool) == Some(true) {
            return byte_field(&session, "Receipt");
        }
        let sequence = u32::try_from(number(&session, "Sequence")?)
            .map_err(|e| e.to_string())?
            .checked_add(1)
            .ok_or("Observation sequence overflow")?;
        let mut chunk = raw::ObservationChunk {
            session_id: plan.id.clone(),
            sequence,
            ..Default::default()
        };
        let rows = number(&session, "RowsRead")? as usize;
        if rows < (plan.rows.len() / 36) {
            chunk.operation = 2;
            chunk.stake_rows =
                plan.rows[rows * 36..std::cmp::min((rows + 128) * 36, plan.rows.len())].to_vec();
            chunk.evidence_digest = plan.row_suffixes[rows + chunk.stake_rows.len() / 36].clone();
        } else if session.get("CreditReady").and_then(Value::as_bool) != Some(true) {
            chunk.operation = 3
        } else if !session.get("PendingBlock").is_none_or(Value::is_null) {
            chunk.operation = 5
        } else {
            let count = number(&session, "ProcessedBlocks")? as usize;
            if count < plan.blocks.len() {
                let size = if plan.blocks[count].block_cbor.is_empty() {
                    4
                } else {
                    1
                };
                chunk.operation = 4;
                chunk.blocks =
                    plan.blocks[count..std::cmp::min(count + size, plan.blocks.len())].to_vec();
                chunk.evidence_digest = plan.block_suffixes[count + chunk.blocks.len()].clone();
            } else {
                chunk.operation = 6
            }
        }
        send(chunk)?;
    }
    Err("Observation exceeded its bounded step count".into())
}

pub(crate) fn decode_bytes(value: &Value, name: &str) -> Result<Vec<u8>, String> {
    byte_field(value, name)
}
pub(crate) fn integer(value: &Value, name: &str) -> Result<u64, String> {
    number(value, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::ToBase32;
    use serde_json::json;
    use std::cell::RefCell;

    #[test]
    fn segment_commitments_match_go() {
        let client = raw::ClientState {
            storage_version: 2,
            current_epoch: 7,
            checkpoint_reference: vec![2; 32],
            storage_namespace: vec![1; 32],
            verification_generation: 7,
            ..Default::default()
        };
        let header = raw::ProbabilisticHeader {
            anchor_block: Some(raw::ProbabilisticBlock {
                height: Some(raw::Height {
                    revision_number: 0,
                    revision_height: 42,
                }),
                slot: 100,
                epoch: 8,
                timestamp: 1234,
                hash: hex::encode([3; 32]),
                header_cbor: vec![4, 5],
                ..Default::default()
            }),
            descendant_blocks: vec![raw::ProbabilisticBlock {
                height: Some(raw::Height {
                    revision_number: 0,
                    revision_height: 43,
                }),
                slot: 101,
                epoch: 8,
                timestamp: 1235,
                hash: hex::encode([6; 32]),
                header_cbor: vec![7, 8],
                ..Default::default()
            }],
            new_epoch_context: Some(raw::EpochContext {
                epoch: 8,
                stake_distribution: [1u8, 2]
                    .into_iter()
                    .map(|key| raw::StakeDistributionEntry {
                        pool_id: bech32::encode(
                            "pool",
                            vec![key; 28].to_base32(),
                            bech32::Variant::Bech32,
                        )
                        .unwrap(),
                        stake: u64::from(key) * 10,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let plan = plan(&client, &header, vec![]).unwrap();
        assert_eq!(
            hex::encode(&plan.begin.evidence_digest),
            "47f9a8871da8cf81d8345564d023a95888035fbb34189d7d183d5c69383caa0a"
        );
        assert_eq!(
            hex::encode(&plan.row_suffixes[1]),
            "879a70ff65d65797e73dcfa01a48711491871537323a01ca562f983fbf086381"
        );
        assert_eq!(
            hex::encode(&plan.block_suffixes[0]),
            "10495c5e7616f6bdc85b7cfee7b46e71f0f66ae54f369cdc28877190a216fdb9"
        );
        assert_eq!(
            hex::encode(&plan.block_suffixes[2]),
            "2e8bcd5d17896af3c4db1ecc52f6d6827ff840aa12a64bc3927f480c0a765845"
        );
    }

    #[test]
    fn session_encoding_matches_go() {
        let client = raw::ClientState {
            storage_namespace: vec![1; 32],
            verification_generation: 7,
            ..Default::default()
        };
        let chunk = raw::ObservationChunk {
            base_checkpoint_reference: vec![2; 32],
            original_receipt: vec![3; 32],
            anchor_height: 42,
            block_count: 27,
            is_checkpoint: true,
            table_context: Some(raw::EpochContext {
                epoch: 8,
                slots_per_kes_period: 129600,
                epoch_start_slot: 20000000,
                epoch_end_slot_exclusive: 20432000,
                epoch_nonce: vec![4; 32],
                ..Default::default()
            }),
            table_rows: 4000,
            table_total: 10000000,
            table_digest: vec![5; 32],
            evidence_digest: vec![6; 32],
            ..Default::default()
        };
        assert_eq!(
            hex::encode(session_id(&client, &chunk).unwrap()),
            "6852dd5a8b07d87585faff64cf45131624bad30fd3efd3b48fb9902bc0e522be"
        );
    }

    #[test]
    fn restart_resumes_after_imported_rows_and_finishes_body_before_next_block() {
        let plan = ObservationPlan {
            id: vec![8; 32],
            begin: raw::ObservationChunk {
                operation: 1,
                ..Default::default()
            },
            rows: vec![9; 129 * 36],
            blocks: vec![
                raw::ProbabilisticBlock {
                    block_cbor: vec![1],
                    ..Default::default()
                },
                raw::ProbabilisticBlock {
                    header_cbor: vec![2],
                    ..Default::default()
                },
            ],
            row_suffixes: vec![vec![1; 32]; 130],
            block_suffixes: vec![vec![2; 32]; 3],
        };
        let state = RefCell::new(
            json!({"Sequence":4,"RowsRead":128,"CreditReady":false,"PendingBlock":null,"ProcessedBlocks":0,"Complete":false}),
        );
        let operations = RefCell::new(vec![]);
        let receipt = submit(
            &plan,
            |_| Ok(state.borrow().clone()),
            |chunk| {
                operations.borrow_mut().push(chunk.operation);
                let mut state = state.borrow_mut();
                if chunk.operation == 1 {
                    return Ok(());
                }
                assert_eq!(
                    chunk.sequence,
                    state["Sequence"].as_u64().unwrap() as u32 + 1
                );
                state["Sequence"] = json!(chunk.sequence);
                match chunk.operation {
                    2 => {
                        assert_eq!(chunk.stake_rows.len(), 36);
                        assert_eq!(chunk.evidence_digest, vec![1; 32]);
                        state["RowsRead"] = json!(129)
                    }
                    3 => state["CreditReady"] = json!(true),
                    4 => {
                        assert_eq!(chunk.evidence_digest, vec![2; 32]);
                        if state["ProcessedBlocks"] == json!(0) {
                            state["PendingBlock"] = json!({"height":1})
                        } else {
                            state["ProcessedBlocks"] = json!(2)
                        }
                    }
                    5 => {
                        state["PendingBlock"] = Value::Null;
                        state["ProcessedBlocks"] = json!(1)
                    }
                    6 => {
                        state["Complete"] = json!(true);
                        state["Receipt"] = json!(vec![7; 32])
                    }
                    _ => panic!("unexpected phase"),
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(receipt, vec![7; 32]);
        assert_eq!(*operations.borrow(), vec![1, 2, 3, 4, 5, 4, 6]);
    }
}
