//! Authorization for the cache paired with the message-selected client.
use super::*;
use pallas_primitives::babbage::PseudoDatumOption;

pub(super) fn load(
    manifest: &JsonValue,
    network: u8,
    scripts: &mut HashMap<String, ScriptRoot>,
) -> Result<Option<StateOutputRoot>, String> {
    let Some(group) = object_field(manifest, &["cached_tendermint", "cachedTendermint"]) else {
        return Ok(None);
    };
    if required_string(group, &["format"], "validator cache format")?
        != "authenticated-validator-cache-v1"
    {
        return Err("unsupported validator cache format".into());
    }
    let validators = object_field(group, &["validators"]).ok_or("missing cache validators")?;
    let roots = collect_validator_script_roots(validators)?;
    for (name, role) in [
        ("update", "updatecachedclient"),
        ("updatecore", "verifycachedclient"),
        ("generalupdatecore", "verifygeneralcachedclient"),
        ("cachespend", "spendvalidatorcache"),
        ("cachemint", "mintvalidatorcache"),
    ] {
        let root = required_script(&roots, name)?.clone();
        if scripts.insert(role.into(), root).is_some() {
            return Err(format!("duplicate cache script role {role}"));
        }
    }
    let staged = required_script(&roots, "stagedupdate")?;
    let ordinary = required_script(scripts, "updateclient")?;
    if staged.hash != ordinary.hash || staged.reference != ordinary.reference {
        return Err("cache staged verifier differs from the standard staged verifier".into());
    }
    let cache = object_field(validators, &["cacheSpend", "cache_spend"])
        .ok_or("missing cache spend validator")?;
    Ok(Some(StateOutputRoot {
        address: decode_address(
            required_string(cache, &["address"], "cache address")?,
            network,
        )?,
        policy: required_script(scripts, "mintvalidatorcache")?.hash.clone(),
    }))
}

// Aiken serialiseData uses indefinite constructor fields. The identity must not
// depend on whichever CBOR array representation a Rust encoder chooses.
fn cache_name(policy: &[u8], name: &[u8]) -> Vec<u8> {
    let mut encoded = vec![0xd8, 0x79, 0x9f, 0x58, policy.len() as u8];
    encoded.extend_from_slice(policy);
    if name.len() < 24 {
        encoded.push(0x40 + name.len() as u8);
    } else {
        encoded.extend_from_slice(&[0x58, name.len() as u8]);
    }
    encoded.extend_from_slice(name);
    encoded.push(0xff);
    let mut result = vec![0; 32];
    let mut hasher = Sha3::v256();
    hasher.update(&encoded);
    hasher.finalize(&mut result);
    result
}

fn inline<'a>(output: &'a MintedTransactionOutput<'_>) -> Option<&'a PlutusData> {
    match output {
        PseudoTransactionOutput::PostAlonzo(output) => match output.datum_option.as_ref()? {
            PseudoDatumOption::Data(data) => Some(&data.0),
            _ => None,
        },
        _ => None,
    }
}

impl TransactionSigningPolicy {
    pub(super) fn is_cached_direct(&self, intent: &SigningIntent) -> bool {
        self.validator_cache.is_some()
            && intent.operation == "/ibc.core.client.v1.MsgUpdateClient"
            && intent.tendermint_header.is_some()
            && !intent.staged_tendermint
    }

    pub(super) fn uses_validator_cache(
        &self,
        intent: &SigningIntent,
        requirements: &OperationRequirements<'_>,
    ) -> bool {
        self.validator_cache.is_some()
            && (intent.operation == "/ibc.core.client.v1.MsgCreateClient"
                || self.is_cached_direct(intent)
                || requirements
                    .tendermint_session
                    .as_ref()
                    .is_some_and(|session| session.action == TendermintSessionAction::Finalize))
    }

    pub(super) fn cached_core(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
    ) -> Result<&'static str, String> {
        let withdrawals = body
            .withdrawals
            .as_ref()
            .ok_or("cached update omits withdrawals")?;
        let mut selected = None;
        for role in ["verifycachedclient", "verifygeneralcachedclient"] {
            let root = required_script(&self.scripts, role)?;
            let account = [vec![0xf0 | self.network_id], root.hash.clone()].concat();
            if withdrawals
                .iter()
                .any(|(key, value)| key.as_slice() == account && *value == 0)
                && selected.replace(role).is_some()
            {
                return Err("cached update selects multiple verifiers".into());
            }
        }
        selected.ok_or("cached update omits a pinned verifier".into())
    }

    pub(super) fn validate_cached_withdrawals(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
    ) -> Result<(), String> {
        let core = self.cached_core(body)?;
        let expected = ["updatecachedclient", core]
            .map(|role| {
                required_script(&self.scripts, role)
                    .map(|root| [vec![0xf0 | self.network_id], root.hash.clone()].concat())
            })
            .into_iter()
            .collect::<Result<HashSet<_>, _>>()?;
        let actual = body
            .withdrawals
            .as_ref()
            .ok_or("missing cached withdrawals")?;
        if actual.len() != 2
            || !actual
                .iter()
                .all(|(account, value)| *value == 0 && expected.contains(account.as_slice()))
        {
            return Err("cached update requires exactly its pinned dispatcher and verifier with zero withdrawals".into());
        }
        Ok(())
    }

    pub(super) fn validate_cache_transition(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        intent: &SigningIntent,
        requirements: &OperationRequirements<'_>,
        resolved: &ResolvedTransactionInputs,
    ) -> Result<(), String> {
        let Some(cache) = &self.validator_cache else {
            return Ok(());
        };
        let creating = intent.operation == "/ibc.core.client.v1.MsgCreateClient";
        let used = self.uses_validator_cache(intent, requirements);
        let inputs: Vec<_> = resolved
            .regular
            .values()
            .filter(|input| {
                input.address == cache.address
                    || input
                        .assets
                        .iter()
                        .any(|asset| asset.policy_id.as_slice() == cache.policy)
            })
            .collect();
        let outputs: Vec<_> = body
            .outputs
            .iter()
            .filter(|output| {
                let value = unpack_output(output);
                value.address == cache.address
                    || value
                        .assets
                        .iter()
                        .any(|(policy, _, _)| policy == &cache.policy)
            })
            .collect();
        if !used {
            if !inputs.is_empty() || !outputs.is_empty() {
                return Err("validator cache is unrelated to the requested operation".into());
            }
            return Ok(());
        }
        let client_name = if let Some(sequence) = intent.state_sequence {
            self.state_token_name(StateOutputKind::Client, sequence)
        } else {
            let clients: Vec<_> = body
                .outputs
                .iter()
                .map(unpack_output)
                .filter(|output| output.address == self.client_state.address)
                .collect();
            if clients.len() != 1
                || clients[0].assets.len() != 1
                || clients[0].assets[0].0 != self.client_state.policy
                || clients[0].assets[0].2 != 1
            {
                return Err("paired cache requires one created client".into());
            }
            clients[0].assets[0].1.clone()
        };
        let name = cache_name(&self.client_state.policy, &client_name);
        if outputs.len() != 1 || inputs.len() != usize::from(!creating) {
            return Err("client transition requires one paired cache continuation".into());
        }
        let output = unpack_output(outputs[0]);
        if output.address != cache.address
            || !is_exact_state_output(&output, &cache.policy, Some(&name))
            || !output.has_inline_datum
        {
            return Err(
                "cache output does not contain its canonical NFT at the pinned address".into(),
            );
        }
        let next = constructor_fields(inline(outputs[0]).ok_or("missing cache output datum")?, 0)
            .filter(|fields| fields.len() == 4)
            .ok_or("malformed cache datum")?;
        self.validate_cache_identity(next, &name, &client_name)?;
        let PlutusData::Array(records) = &next[3] else {
            return Err("malformed cache records".into());
        };
        if records.len() > 2
            || records.iter().any(|record| {
                constructor_fields(record, 0)
                    .filter(|fields| fields.len() == 3)
                    .is_none_or(|fields| {
                        plutus_bytes(&fields[0]).is_none_or(|root| root.len() != 32)
                            || plutus_u64(&fields[1]).is_none_or(|count| count == 0 || count > 256)
                            || plutus_u64(&fields[2]).is_none_or(|power| power == 0)
                    })
            })
        {
            return Err("invalid bounded cache records".into());
        }
        if creating {
            if !records.is_empty() || minted_quantity(body, &cache.policy, &name) != 1 {
                return Err("client creation requires an empty paired cache".into());
            }
        } else {
            let input = inputs[0];
            if input.address != cache.address
                || input.assets.len() != 1
                || input.assets[0].policy_id.as_slice() != cache.policy
                || input.assets[0].asset_name != name
                || input.assets[0].quantity != 1
                || output.coin < input.lovelace
                || minted_quantity(body, &cache.policy, &name) != 0
            {
                return Err("cache transition changes its identity or removes its reserve".into());
            }
            let old: PlutusData = minicbor::decode(
                input
                    .inline_datum
                    .as_deref()
                    .ok_or("missing cache input datum")?,
            )
            .map_err(|_| "malformed cache input datum")?;
            let old = constructor_fields(&old, 0)
                .filter(|fields| fields.len() == 4)
                .ok_or("malformed cache input datum")?;
            self.validate_cache_identity(old, &name, &client_name)?;
            if old[..3] != next[..3] {
                return Err("cache transition changes its authenticated client identity".into());
            }
        }
        Ok(())
    }

    fn validate_cache_identity(
        &self,
        fields: &[PlutusData],
        name: &[u8],
        client_name: &[u8],
    ) -> Result<(), String> {
        let cache = self
            .validator_cache
            .as_ref()
            .ok_or("cache not configured")?;
        let address = constructor_fields(&fields[2], 0)
            .filter(|fields| fields.len() == 2)
            .ok_or("malformed cache client address")?;
        let credential = constructor_fields(&address[0], 1)
            .filter(|fields| fields.len() == 1)
            .and_then(|fields| plutus_bytes(&fields[0]));
        // The deployment pins an enterprise script address. No staking credential.
        if !auth_token_matches(&fields[0], &cache.policy, name)
            || !auth_token_matches(&fields[1], &self.client_state.policy, client_name)
            || credential != self.client_state.address.get(1..)
            || constructor_fields(&address[1], 1).is_none_or(|fields| !fields.is_empty())
        {
            return Err("cache datum does not authenticate the message-selected client".into());
        }
        Ok(())
    }

    pub(super) fn validate_cached_message(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        redeemers: &pallas_primitives::conway::Redeemers,
        intent: &SigningIntent,
        resolved: &ResolvedTransactionInputs,
    ) -> Result<(), String> {
        let name = self.state_token_name(
            StateOutputKind::Client,
            intent.state_sequence.ok_or("missing requested client")?,
        );
        let (client_ref, _) = resolved
            .regular
            .iter()
            .find(|(_, input)| {
                input.address == self.client_state.address
                    && input.assets.iter().any(|asset| asset.asset_name == name)
            })
            .ok_or("missing requested client input")?;
        let raw = spend_redeemer_for_input(body, redeemers, client_ref)?;
        let update = constructor_fields(raw, 6)
            .filter(|fields| fields.len() == 1)
            .and_then(|fields| constructor_fields(&fields[0], 0))
            .filter(|fields| fields.len() == 9)
            .ok_or("cached client update has the wrong redeemer")?;
        let cache = self
            .validator_cache
            .as_ref()
            .ok_or("cache not configured")?;
        if !auth_token_matches(
            &update[0],
            &cache.policy,
            &cache_name(&self.client_state.policy, &name),
        ) {
            return Err("cached update selects another client cache".into());
        }
        let requested = ibc_proto::ibc::lightclients::tendermint::v1::Header::decode(
            intent
                .tendermint_header
                .as_deref()
                .ok_or("missing requested header")?,
        )
        .map_err(|_| "malformed requested header")?;
        let trusted = requested
            .trusted_height
            .ok_or("missing requested trust height")?;
        let signed = requested
            .signed_header
            .ok_or("missing requested signed header")?;
        let requested_header: tendermint::block::Header = signed
            .header
            .ok_or("missing requested header fields")?
            .try_into()
            .map_err(|_| "invalid requested Tendermint header")?;
        let commit = signed.commit.ok_or("missing requested commit")?;
        let block = commit.block_id.ok_or("missing requested block ID")?;
        if requested_header.hash().as_bytes() != block.hash.as_slice() {
            return Err("requested header does not match its commit hash".into());
        }
        let signed_fields = constructor_fields(&update[1], 0)
            .filter(|fields| fields.len() == 2)
            .ok_or("malformed cached signed header")?;
        let actual = constructor_fields(&signed_fields[1], 0)
            .filter(|fields| fields.len() == 4)
            .ok_or("malformed cached commit")?;
        let actual_block = constructor_fields(&actual[2], 0)
            .filter(|fields| fields.len() == 2)
            .ok_or("malformed cached block ID")?;
        if plutus_height(&update[2]) != Some((trusted.revision_number, trusted.revision_height))
            || plutus_u64(&actual[0]) != u64::try_from(commit.height).ok()
            || plutus_u64(&actual[1]) != u64::try_from(commit.round).ok()
            || plutus_bytes(&actual_block[0]) != Some(block.hash.as_slice())
        {
            return Err("cached update does not verify the original requested header".into());
        }
        let mut rewards = 0;
        for (key, value) in redeemers
            .iter()
            .filter(|(key, _)| key.tag == pallas_primitives::conway::RedeemerTag::Reward)
        {
            if key.index > 1 || !auth_token_matches(&value.data, &self.client_state.policy, &name) {
                return Err("cached withdrawal redeemer authorizes another client".into());
            }
            rewards += 1;
        }
        if rewards != 2 {
            return Err("cached update requires both subject-bound withdrawal redeemers".into());
        }
        let (cache_ref, _) = resolved
            .regular
            .iter()
            .find(|(_, input)| input.address == cache.address)
            .ok_or("missing paired cache input")?;
        if constructor_fields(spend_redeemer_for_input(body, redeemers, cache_ref)?, 0)
            .is_none_or(|fields| !fields.is_empty())
        {
            return Err("cached update selects an unauthorized cache branch".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        data_constructor, data_token, limits, manifest, proof_backed_policy,
    };
    use super::*;

    fn cached_manifest() -> JsonValue {
        let mut value: JsonValue = serde_json::from_str(&manifest()).unwrap();
        value["consensus_history_format"] = "proof-backed-v1".into();
        for (role, hash) in [
            ("spend_tendermint_update_session", "a0"),
            ("mint_tendermint_update_session", "a1"),
            ("update_client", "a2"),
        ] {
            value["validators"][role] = serde_json::json!({"script_hash":hash.repeat(28),"address":format!("70{}",hash.repeat(28)),"ref_utxo":{"tx_hash":hash.repeat(32),"output_index":0}});
        }
        let mut validators = serde_json::Map::new();
        for (index, role) in [
            "update",
            "updateCore",
            "generalUpdateCore",
            "cacheSpend",
            "cacheMint",
        ]
        .into_iter()
        .enumerate()
        {
            let hash = format!("{:02x}", 0xb0 + index);
            validators.insert(role.into(), serde_json::json!({"script_hash":hash.repeat(28),"address":format!("70{}",hash.repeat(28)),"ref_utxo":{"tx_hash":hash.repeat(32),"output_index":0}}));
        }
        validators.insert(
            "stagedUpdate".into(),
            value["validators"]["update_client"].clone(),
        );
        value["cached_tendermint"] = serde_json::json!({"format":"authenticated-validator-cache-v1","validators":validators});
        value
    }

    #[test]
    fn cache_identity_matches_aiken_indefinite_serialization() {
        assert_eq!(
            hex::encode(cache_name(&[0x83; 28], &[0x84; 25])),
            "14042214c1889f1c768657a42d64c86d06c914bdea3f3ffac61c404bc87b6965"
        );
        assert_ne!(
            cache_name(&[0x83; 28], &[0x84; 25]),
            cache_name(&[0x83; 28], &[0x85; 25])
        );
    }

    #[test]
    fn cache_manifest_requires_all_pinned_roles_and_one_staged_verifier() {
        let original = cached_manifest();
        let policy =
            TransactionSigningPolicy::from_json(&original.to_string(), 0, limits()).unwrap();
        assert!(policy.validator_cache.is_some());
        for role in [
            "update",
            "updateCore",
            "generalUpdateCore",
            "cacheSpend",
            "cacheMint",
            "stagedUpdate",
        ] {
            let mut bad = original.clone();
            bad["cached_tendermint"]["validators"]
                .as_object_mut()
                .unwrap()
                .remove(role);
            assert!(
                TransactionSigningPolicy::from_json(&bad.to_string(), 0, limits()).is_err(),
                "{role}"
            );
        }
        let mut bad = original.clone();
        bad["cached_tendermint"]["validators"]["stagedUpdate"]["script_hash"] =
            "ff".repeat(28).into();
        assert!(TransactionSigningPolicy::from_json(&bad.to_string(), 0, limits()).is_err());
        let mut bad = original;
        bad["cached_tendermint"]["validators"]["cacheSpend"]["address"] =
            bad["validators"]["spend_client"]["address"].clone();
        assert!(TransactionSigningPolicy::from_json(&bad.to_string(), 0, limits()).is_err());
    }

    #[test]
    fn unrelated_cache_and_identity_changes_are_rejected() {
        let mut policy = proof_backed_policy();
        policy.validator_cache = Some(StateOutputRoot {
            address: vec![0x70; 29],
            policy: vec![0x87; 28],
        });
        let client_name = policy.state_token_name(StateOutputKind::Client, 7);
        let name = cache_name(&policy.client_state.policy, &client_name);
        let fields = vec![
            data_token(&[0x87; 28], &name),
            data_token(&policy.client_state.policy, &client_name),
            data_constructor(
                0,
                vec![
                    data_constructor(
                        1,
                        vec![PlutusData::BoundedBytes(
                            policy.client_state.address[1..].to_vec().into(),
                        )],
                    ),
                    data_constructor(1, vec![]),
                ],
            ),
            PlutusData::Array(vec![]),
        ];
        policy
            .validate_cache_identity(&fields, &name, &client_name)
            .unwrap();
        for mutation in 0..4 {
            let mut changed = fields.clone();
            match mutation {
                0 => changed[0] = data_token(&[0x87; 28], &[0xff; 32]),
                1 => changed[1] = data_token(&policy.client_state.policy, b"another-client"),
                2 => {
                    changed[2] = data_constructor(
                        0,
                        vec![
                            data_constructor(
                                1,
                                vec![PlutusData::BoundedBytes(vec![0xff; 28].into())],
                            ),
                            data_constructor(1, vec![]),
                        ],
                    )
                }
                _ => {
                    changed[2] = data_constructor(
                        0,
                        vec![
                            data_constructor(
                                0,
                                vec![PlutusData::BoundedBytes(
                                    policy.client_state.address[1..].to_vec().into(),
                                )],
                            ),
                            data_constructor(1, vec![]),
                        ],
                    )
                }
            }
            assert!(policy
                .validate_cache_identity(&changed, &name, &client_name)
                .is_err());
        }
    }

    #[test]
    #[ignore = "requires native Gateway transactions produced by the incubator integration test"]
    fn production_gateway_transactions_pass_independent_policy() {
        let path =
            std::env::var("IBC_CACHE_SIGNING_EVIDENCE").expect("set IBC_CACHE_SIGNING_EVIDENCE");
        let fixture: JsonValue =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mut limits = limits();
        // The fixture deliberately raises reference prices for one case. This
        // is an operator wallet limit and not the 3 ADA engineering target.
        limits.max_tx_size_bytes = 16_384;
        limits.max_fee_lovelace = 50_000_000;
        limits.max_total_collateral_lovelace = 50_000_000;
        limits.max_total_protocol_output_lovelace = 500_000_000;
        limits.max_wallet_lovelace_top_up = 100_000_000;
        let policy =
            TransactionSigningPolicy::from_json(&fixture["manifest"].to_string(), 0, limits)
                .unwrap();
        let transactions = fixture["transactions"].as_array().unwrap();
        assert!(
            transactions.len() >= 12,
            "must include direct updates and a completed staged fallback"
        );
        for (index, row) in transactions.iter().enumerate() {
            let bytes = hex::decode(row["cbor"].as_str().unwrap()).unwrap();
            let tx: MintedTx<'_> = minicbor::decode(&bytes).unwrap();
            let request = &row["request"];
            let message = hex::decode(request["value"].as_str().unwrap()).unwrap();
            let staged = request["staged"].as_bool().unwrap();
            let make_intent = if staged {
                SigningIntent::staged_tendermint_update
            } else {
                SigningIntent::ibc
            };
            let intent = make_intent(
                request["type"].as_str().unwrap(),
                &message,
                request["signer"].as_str().unwrap(),
                0,
            )
            .unwrap();
            let resolve = |kind: &str| {
                row[kind]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|input| {
                        let key = TransactionOutRef {
                            transaction_id: hex::decode(input["txHash"].as_str().unwrap())
                                .unwrap()
                                .try_into()
                                .unwrap(),
                            output_index: input["outputIndex"].as_u64().unwrap(),
                        };
                        let value = ResolvedInput {
                            address: hex::decode(input["address"].as_str().unwrap()).unwrap(),
                            lovelace: input["lovelace"].as_str().unwrap().parse().unwrap(),
                            inline_datum: input["datum"]
                                .as_str()
                                .map(|data| hex::decode(data).unwrap()),
                            assets: input["assets"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|asset| super::super::super::utxo_resolver::ResolvedAsset {
                                    policy_id: hex::decode(asset["policy"].as_str().unwrap())
                                        .unwrap()
                                        .try_into()
                                        .unwrap(),
                                    asset_name: hex::decode(asset["name"].as_str().unwrap())
                                        .unwrap(),
                                    quantity: asset["quantity"].as_str().unwrap().parse().unwrap(),
                                })
                                .collect(),
                        };
                        (key, value)
                    })
                    .collect()
            };
            let resolved = ResolvedTransactionInputs {
                regular: resolve("regular"),
                collateral: resolve("collateral"),
            };
            policy
                .validate(
                    &tx,
                    bytes.len(),
                    request["signer"].as_str().unwrap(),
                    &intent,
                    &resolved,
                )
                .unwrap_or_else(|error| panic!("transaction {index}: {error}"));
            if policy.is_cached_direct(&intent) {
                let mut wrong_client = intent.clone();
                wrong_client.state_sequence = Some(intent.state_sequence.unwrap() + 1);
                assert!(policy
                    .validate(
                        &tx,
                        bytes.len(),
                        request["signer"].as_str().unwrap(),
                        &wrong_client,
                        &resolved
                    )
                    .is_err());
                let mut wrong_header = intent.clone();
                let mut header = ibc_proto::ibc::lightclients::tendermint::v1::Header::decode(
                    wrong_header.tendermint_header.as_deref().unwrap(),
                )
                .unwrap();
                header
                    .signed_header
                    .as_mut()
                    .unwrap()
                    .header
                    .as_mut()
                    .unwrap()
                    .chain_id
                    .push_str("-substituted");
                wrong_header.tendermint_header = Some(header.encode_to_vec());
                assert!(policy
                    .validate(
                        &tx,
                        bytes.len(),
                        request["signer"].as_str().unwrap(),
                        &wrong_header,
                        &resolved
                    )
                    .is_err());
                let mut bad_inputs = resolved.clone();
                let cache = policy.validator_cache.as_ref().unwrap();
                let cache_input = bad_inputs
                    .regular
                    .values_mut()
                    .find(|input| input.address == cache.address)
                    .unwrap();
                cache_input.assets[0].asset_name[0] ^= 1;
                assert!(policy
                    .validate(
                        &tx,
                        bytes.len(),
                        request["signer"].as_str().unwrap(),
                        &intent,
                        &bad_inputs
                    )
                    .is_err());
            }
        }
    }

    #[test]
    fn merkle_receipt_manifest_does_not_enable_legacy_pruning() {
        let mut manifest = cached_manifest();
        manifest["packet_state"]["operations"]
            .as_object_mut()
            .unwrap()
            .remove("prune");
        assert!(TransactionSigningPolicy::from_json(&manifest.to_string(), 0, limits()).is_err());
        manifest["packet_state"]["receipt_storage"] = "merkle-history-v1".into();
        let policy =
            TransactionSigningPolicy::from_json(&manifest.to_string(), 0, limits()).unwrap();
        assert!(!policy.scripts.contains_key("packetoperationprune"));
        let mut request = super::super::tests::update_intent();
        request.operation = "/ibc.cardano.v1.MsgPrunePacketHistory".into();
        request.module_port = Some("transfer".into());
        request.prune_sequence = Some(1);
        assert!(policy.operation_requirements(&request).is_err());
    }
}
