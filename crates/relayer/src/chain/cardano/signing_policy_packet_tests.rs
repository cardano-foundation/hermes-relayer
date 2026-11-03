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
        let data: JsonValue =
            serde_json::from_str(include_str!("fixtures/packet-lane-signing.json")).unwrap();
        let row = data["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap();
        let signer = data["signer"].as_str().unwrap().to_string();
        let intent = if name == "send" {
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
        let mut limits = tests::limits();
        // Creating sixteen lanes commits about 25 ADA once. Keep the ordinary
        // packet allowance unchanged, but authorize this setup reserve explicitly.
        if name == "initialize" {
            limits.max_wallet_lovelace_top_up = 30_000_000;
        }
        Self {
            policy: TransactionSigningPolicy::from_json(&data["manifest"].to_string(), 0, limits)
                .unwrap(),
            bytes: hex::decode(row["cbor"].as_str().unwrap()).unwrap(),
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
