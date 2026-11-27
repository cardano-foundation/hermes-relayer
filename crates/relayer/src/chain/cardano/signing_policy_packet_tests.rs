use super::super::transaction_evaluator::validate_key_only_transaction;
use super::super::utxo_resolver::ResolvedAsset;
use super::*;

struct Fixture {
    policy: TransactionSigningPolicy,
    bytes: Vec<u8>,
    signer: String,
    intent: SigningIntent,
    resolved: ResolvedTransactionInputs,
}

impl Fixture {
    fn load(name: &str) -> Self {
        let data: JsonValue = serde_json::from_str(if name == "consolidate" {
            include_str!("fixtures/packet-consolidation-signing.json")
        } else {
            include_str!("fixtures/packet-lane-signing.json")
        })
        .unwrap();
        let row = data["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap();
        let signer = data["signer"].as_str().unwrap().to_string();
        let intent = if name == "consolidate" {
            let message = MsgRecvPacket {
                packet: Some(super::super::generated::ibc::core::channel::v1::Packet {
                    sequence: 1, source_port: "transfer".into(), source_channel: "channel-7".into(),
                    destination_port: "transfer".into(), destination_channel: "channel-0".into(),
                    data: serde_json::to_vec(&serde_json::json!({"denom": "transfer/channel-7/6c6f76656c616365", "amount": "12000000", "sender": "cosmos1sender", "receiver": signer, "memo": ""})).unwrap(),
                    timeout_height: None, timeout_timestamp: 1800000000000000000,
                }), signer: signer.clone(), ..Default::default()
            };
            let original = SigningIntent::ibc(
                "/ibc.core.channel.v1.MsgRecvPacket",
                &message.encode_to_vec(),
                &signer,
                0,
            )
            .unwrap();
            SigningIntent::packet_consolidation(&original).unwrap()
        } else if name == "send" {
            SigningIntent::funded_batch(
                "transfer",
                "channel-0",
                row["fundedIntent"].as_str().unwrap(),
                false,
            )
            .unwrap()
        } else {
            let intent = SigningIntent::ibc(
                row["operation"].as_str().unwrap(),
                &hex::decode(row["message"].as_str().unwrap()).unwrap(),
                &signer,
                0,
            )
            .unwrap();
            if name == "initialize" {
                SigningIntent::packet_initialization(&intent)
            } else {
                intent
            }
        };
        let resolve = |kind: &str| {
            row[kind]
                .as_array()
                .unwrap()
                .iter()
                .map(|input| {
                    (
                        TransactionOutRef {
                            transaction_id: hex::decode(input["txHash"].as_str().unwrap())
                                .unwrap()
                                .try_into()
                                .unwrap(),
                            output_index: input["outputIndex"].as_u64().unwrap(),
                        },
                        ResolvedInput {
                            address: hex::decode(input["address"].as_str().unwrap()).unwrap(),
                            lovelace: input["lovelace"].as_u64().unwrap(),
                            inline_datum: input["datum"]
                                .as_str()
                                .map(|value| hex::decode(value).unwrap()),
                            assets: input["assets"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|asset| ResolvedAsset {
                                    policy_id: hex::decode(asset["policy"].as_str().unwrap())
                                        .unwrap()
                                        .try_into()
                                        .unwrap(),
                                    asset_name: hex::decode(asset["name"].as_str().unwrap())
                                        .unwrap(),
                                    quantity: asset["quantity"].as_u64().unwrap(),
                                })
                                .collect(),
                        },
                    )
                })
                .collect()
        };
        let limits = tests::limits();
        let mut transaction: pallas_primitives::conway::Tx =
            minicbor::decode(&hex::decode(row["cbor"].as_str().unwrap()).unwrap()).unwrap();
        transaction.transaction_witness_set.vkeywitness = None;
        Self {
            policy: TransactionSigningPolicy::from_json(&data["manifest"].to_string(), 0, limits)
                .unwrap(),
            bytes: minicbor::to_vec(transaction).unwrap(),
            signer,
            intent,
            resolved: ResolvedTransactionInputs {
                regular: resolve("regular"),
                collateral: resolve("collateral"),
            },
        }
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), Error> {
        let tx: MintedTx<'_> = minicbor::decode(bytes).unwrap();
        self.policy
            .validate(&tx, bytes.len(), &self.signer, &self.intent, &self.resolved)
    }

    fn transaction(&self) -> pallas_primitives::conway::Tx {
        minicbor::decode(&self.bytes).unwrap()
    }
}

#[test]
fn native_packet_transactions_pass_with_only_their_executed_script_references() {
    for name in ["admission", "initialize", "send", "receive", "acknowledge"] {
        let fixture = Fixture::load(name);
        fixture
            .validate(&fixture.bytes)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn successful_acknowledgement_signing_does_not_require_the_funds_policy() {
    use pallas_primitives::conway::{RedeemerTag, Redeemers, RedeemersKey, RedeemersValue};

    let fixture = Fixture::load("acknowledge");
    let funds = required_script(&fixture.policy.scripts, "packetoperationfunds").unwrap();
    let mut tx = fixture.transaction();
    let mut mint = tx.transaction_body.mint.take().unwrap().to_vec();
    mint.sort_by(|a, b| a.0.cmp(&b.0));
    let index = mint
        .iter()
        .position(|(policy, _)| policy.as_ref() == funds.hash)
        .unwrap();
    mint.remove(index);
    tx.transaction_body.mint = Some(mint.try_into().unwrap());
    let references = tx
        .transaction_body
        .reference_inputs
        .take()
        .unwrap()
        .to_vec();
    tx.transaction_body.reference_inputs = Some(
        references
            .into_iter()
            .filter(|input| {
                (input.transaction_id.as_ref().to_vec(), input.index) != funds.reference
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );
    let mut redeemers: Vec<(RedeemersKey, RedeemersValue)> = tx
        .transaction_witness_set
        .redeemer
        .as_ref()
        .unwrap()
        .iter()
        .cloned()
        .collect();
    redeemers.retain(|(key, _)| key.tag != RedeemerTag::Mint || key.index != index as u32);
    for (key, _) in &mut redeemers {
        if key.tag == RedeemerTag::Mint && key.index > index as u32 {
            key.index -= 1;
        }
    }
    tx.transaction_witness_set.redeemer = Some(Redeemers::from(
        pallas_codec::utils::NonEmptyKeyValuePairs::try_from(redeemers).unwrap(),
    ));
    fixture.validate(&minicbor::to_vec(&tx).unwrap()).unwrap();

    for script in [
        "packetoperationacknowledge",
        "verifyproof",
        "packetguard",
        "packetbatch",
    ] {
        let required = required_script(&fixture.policy.scripts, script).unwrap();
        let mut missing = tx.clone();
        let references = missing
            .transaction_body
            .reference_inputs
            .take()
            .unwrap()
            .to_vec();
        missing.transaction_body.reference_inputs = Some(
            references
                .into_iter()
                .filter(|input| {
                    (input.transaction_id.as_ref().to_vec(), input.index) != required.reference
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        assert!(
            fixture
                .validate(&minicbor::to_vec(missing).unwrap())
                .is_err(),
            "missing {script}"
        );
    }
    let mut changed = Fixture::load("acknowledge");
    changed.intent.packet.as_mut().unwrap().sequence += 1;
    assert!(changed.validate(&minicbor::to_vec(tx).unwrap()).is_err());
}

#[test]
fn native_packet_transactions_reject_missing_executed_script_references() {
    for (name, scripts) in [
        ("initialize", vec!["packetstate"]),
        (
            "send",
            vec!["packetbatch", "packetguard", "packetoperationsend"],
        ),
        (
            "receive",
            vec![
                "packetbatch",
                "packetguard",
                "packetoperationreceive",
                "mintvoucher",
                "verifyproof",
            ],
        ),
        (
            "acknowledge",
            vec![
                "packetbatch",
                "packetguard",
                "packetoperationacknowledge",
                "verifyproof",
            ],
        ),
    ] {
        let fixture = Fixture::load(name);
        for script in scripts {
            let root = required_script(&fixture.policy.scripts, script).unwrap();
            let mut tx = fixture.transaction();
            let mut references = tx
                .transaction_body
                .reference_inputs
                .take()
                .unwrap()
                .to_vec();
            let before = references.len();
            references.retain(|input| {
                (input.transaction_id.as_ref().to_vec(), input.index) != root.reference
            });
            assert_eq!(references.len() + 1, before, "{name}: {script}");
            tx.transaction_body.reference_inputs = Some(references.try_into().unwrap());
            assert!(
                fixture.validate(&minicbor::to_vec(tx).unwrap()).is_err(),
                "{name}: missing {script}"
            );
        }
    }
}

#[test]
fn executed_script_selection_still_binds_the_original_transfer_and_packet() {
    let mut admission = Fixture::load("admission");
    admission.intent.transfer.as_mut().unwrap().amount += 1;
    assert!(admission.validate(&admission.bytes).is_err());
    for name in ["receive", "acknowledge"] {
        let mut fixture = Fixture::load(name);
        fixture.intent.packet.as_mut().unwrap().sequence += 1;
        assert!(fixture.validate(&fixture.bytes).is_err());
    }
}

#[test]
fn phase_one_exception_accepts_only_completely_resolved_key_owned_inputs() {
    let fixture = Fixture::load("admission");
    assert!(fixture.intent.is_transfer_admission());
    validate_key_only_transaction(&fixture.bytes, &fixture.resolved).unwrap();
    let mut incomplete = fixture.resolved.clone();
    incomplete.regular.pop_first();
    assert!(validate_key_only_transaction(&fixture.bytes, &incomplete).is_err());
    for header in [0x10, 0x30, 0x50, 0x70, 0x80] {
        let mut script_input = fixture.resolved.clone();
        script_input.regular.values_mut().next().unwrap().address[0] = header;
        assert!(validate_key_only_transaction(&fixture.bytes, &script_input).is_err());
    }
    for name in ["initialize", "send", "receive", "acknowledge"] {
        let script_tx = Fixture::load(name);
        assert!(!script_tx.intent.is_transfer_admission());
        assert!(validate_key_only_transaction(&script_tx.bytes, &script_tx.resolved).is_err());
    }
}

#[test]
fn phase_one_exception_rejects_hidden_script_work_and_invalid_envelopes() {
    let fixture = Fixture::load("admission");
    let script_tx = Fixture::load("send").transaction();
    let mut cases = Vec::new();
    let mut invalid = fixture.transaction();
    invalid.success = false;
    cases.push(invalid);
    let mut mint = fixture.transaction();
    mint.transaction_body.mint = script_tx.transaction_body.mint;
    cases.push(mint);
    let mut redeemers = fixture.transaction();
    redeemers.transaction_witness_set.redeemer = script_tx.transaction_witness_set.redeemer;
    cases.push(redeemers);
    let mut script_hash = fixture.transaction();
    script_hash.transaction_body.script_data_hash = Some([1; 32].into());
    cases.push(script_hash);
    for tx in cases {
        assert!(
            validate_key_only_transaction(&minicbor::to_vec(tx).unwrap(), &fixture.resolved)
                .is_err()
        );
    }
    let mut trailing = fixture.bytes.clone();
    trailing.push(0);
    assert!(validate_key_only_transaction(&trailing, &fixture.resolved).is_err());
}

#[test]
fn fragmented_escrow_consolidation_passes_independent_signing_policy() {
    let fixture = Fixture::load("consolidate");
    fixture.validate(&fixture.bytes).unwrap();
}

#[test]
fn consolidation_is_bound_to_the_packet_and_cannot_replace_settlement() {
    for mutation in 0..5 {
        let mut fixture = Fixture::load("consolidate");
        match mutation {
            0 => fixture.intent.state_sequence = Some(1),
            1 => {
                fixture.intent.transfer.as_mut().unwrap().denom = "transfer/channel-7/other".into()
            }
            2 => fixture.intent.transfer.as_mut().unwrap().amount = 10_000_000,
            3 => fixture.intent.operation = "/ibc.core.channel.v1.MsgRecvPacket".into(),
            _ => fixture.intent.transfer.as_mut().unwrap().action = TransferAction::Send,
        }
        assert!(
            fixture.validate(&fixture.bytes).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn consolidation_rejects_changes_to_principal_reserves_and_owners() {
    let fixture = Fixture::load("consolidate");
    for index in 0..fixture.transaction().transaction_body.outputs.len() {
        let mut transaction = fixture.transaction();
        match &mut transaction.transaction_body.outputs[index] {
            PseudoTransactionOutput::PostAlonzo(output) => output.address = vec![0x60; 29].into(),
            PseudoTransactionOutput::Legacy(output) => output.address = vec![0x60; 29].into(),
        }
        assert!(
            fixture
                .validate(&minicbor::to_vec(transaction).unwrap())
                .is_err(),
            "output {index}"
        );
    }
}

#[test]
fn consolidation_is_not_authorized_for_admission_successful_ack_or_voucher_mint() {
    for name in ["admission", "acknowledge", "send"] {
        assert!(SigningIntent::packet_consolidation(&Fixture::load(name).intent).is_err());
    }
    let mut intent = Fixture::load("consolidate").intent;
    intent.transfer.as_mut().unwrap().denom = "uatom".into();
    assert!(SigningIntent::packet_consolidation(&intent).is_err());
    intent.transfer.as_mut().unwrap().action = TransferAction::Refund;
    intent.transfer.as_mut().unwrap().denom = "transfer/channel-7/uatom".into();
    assert!(SigningIntent::packet_consolidation(&intent).is_err());
}

#[test]
fn consolidation_cannot_remove_a_donor_refund_or_change_the_survivor_value() {
    let fixture = Fixture::load("consolidate");
    fixture.validate(&fixture.bytes).unwrap();
    for index in 0..fixture.transaction().transaction_body.outputs.len() {
        let mut transaction = fixture.transaction();
        let PseudoTransactionOutput::PostAlonzo(output) =
            &mut transaction.transaction_body.outputs[index]
        else {
            continue;
        };
        match &mut output.value {
            Value::Coin(coin) | Value::Multiasset(coin, _) => *coin += 1,
        }
        assert!(
            fixture
                .validate(&minicbor::to_vec(transaction).unwrap())
                .is_err(),
            "changed value {index}"
        );
        let mut transaction = fixture.transaction();
        transaction.transaction_body.outputs.remove(index);
        assert!(
            fixture
                .validate(&minicbor::to_vec(transaction).unwrap())
                .is_err(),
            "missing output {index}"
        );
    }
}

#[test]
fn initialization_uses_its_own_bounded_allowance() {
    let mut fixture = Fixture::load("initialize");
    fixture.policy.limits.max_wallet_lovelace_top_up = 1;
    fixture.validate(&fixture.bytes).unwrap();
    fixture
        .policy
        .limits
        .max_packet_lane_initialization_lovelace = 20_000_000;
    fixture.policy.limits.max_wallet_lovelace_top_up = 100_000_000;
    let error = fixture.validate(&fixture.bytes).unwrap_err().to_string();
    assert!(error.contains("configured top-up allowance"), "{error}");
}

#[test]
fn initialization_allowance_does_not_override_fee_cap() {
    let mut fixture = Fixture::load("initialize");
    fixture.policy.limits.max_fee_lovelace = 1;
    assert!(fixture.validate(&fixture.bytes).is_err());
}

#[test]
fn ordinary_packet_cannot_borrow_initialization_allowance() {
    let mut fixture = Fixture::load("receive");
    fixture.policy.limits.max_wallet_lovelace_top_up = 1;
    let error = fixture.validate(&fixture.bytes).unwrap_err().to_string();
    assert!(error.contains("configured top-up allowance"), "{error}");
    fixture.intent.operation = "InitializePacketLanes".into();
    assert!(fixture.validate(&fixture.bytes).is_err());
}

#[test]
fn initialization_allowance_cannot_fund_an_unrelated_wallet() {
    let fixture = Fixture::load("initialize");
    for index in 0..fixture.transaction().transaction_body.outputs.len() {
        let mut transaction = fixture.transaction();
        match &mut transaction.transaction_body.outputs[index] {
            PseudoTransactionOutput::PostAlonzo(output) => output.address = vec![0x60; 29].into(),
            PseudoTransactionOutput::Legacy(output) => output.address = vec![0x60; 29].into(),
        }
        assert!(
            fixture
                .validate(&minicbor::to_vec(transaction).unwrap())
                .is_err(),
            "output {index}"
        );
    }
}
