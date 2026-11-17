//! Authorization for the canonical packet-lane ABI. The pinned validators enforce
//! lane transitions and conservation. Local checks bind the requested packet and
//! restrict which wallet funds, script inputs, policies and payouts may be used.
use super::*;
use pallas_primitives::babbage::PseudoDatumOption;

#[derive(Clone, Debug)]
pub(super) struct PacketRoots {
    guard: Vec<u8>,
    batch: Vec<u8>,
    registry: Vec<u8>,
    state_policy: Vec<u8>,
    batch_policy: Vec<u8>,
    operation_scripts: Vec<ScriptRoot>,
    pub(super) lane_count: Option<u64>,
    pub(super) acknowledgement_batch: bool,
    pub(super) acknowledgement_batch_tag: u64,
}
impl PacketRoots {
    pub(super) fn load(
        manifest: &JsonValue,
        network: u8,
        scripts: &mut HashMap<String, ScriptRoot>,
    ) -> Result<Self, String> {
        let root = object_field(manifest, &["packet_state", "packetState"])
            .ok_or("packet-lane deployment is required")?;
        if required_string(root, &["format"], "packet format")? != "packet-lanes-v1" {
            return Err("unsupported packet ABI".into());
        }
        let mut addresses = Vec::new();
        for (name, key) in [
            ("state", "packetstate"),
            ("batch", "packetbatch"),
            ("guard", "packetguard"),
        ] {
            let validator = object_field(root, &[name]).ok_or("missing packet validator")?;
            collect_validator_script_roots_inner(validator, Some(key), scripts)?;
            addresses.push(decode_address(
                required_string(validator, &["address"], name)?,
                network,
            )?);
        }
        let operations =
            object_field(root, &["operations"]).ok_or("missing packet operation policies")?;
        let mut operation_scripts = Vec::new();
        for name in [
            "send",
            "acknowledge",
            "timeout",
            "reject",
            "receive",
            "prune",
            "timeout_on_close",
            "retire",
            "funds",
            "send_funds",
        ] {
            // Merkle receipt histories do not mint the old pruning policy.
            // Keep that ABI change explicit instead of inventing a script root.
            if name == "prune"
                && object_field(operations, &[name]).is_none()
                && root.get("receipt_storage").and_then(JsonValue::as_str)
                    == Some("merkle-history-v1")
            {
                continue;
            }
            let validator =
                object_field(operations, &[name]).ok_or("missing packet operation policy")?;
            let key = normalize_manifest_key(&format!("packetoperation{name}"));
            collect_validator_script_roots_inner(validator, Some(&key), scripts)?;
            operation_scripts.push(required_script(scripts, &key)?.clone());
        }
        operation_scripts.push(required_script(scripts, "verifyproof")?.clone());
        if let Some(membership) = scripts.get("verifymembership") {
            operation_scripts.push(membership.clone());
        }
        Ok(Self {
            acknowledgement_batch_tag: if root.get("receipt_storage").and_then(JsonValue::as_str)
                == Some("merkle-history-v1")
            {
                9
            } else {
                10
            },
            acknowledgement_batch: root
                .get("acknowledgement_batch_size")
                .and_then(JsonValue::as_u64)
                == Some(2),
            lane_count: root
                .get("lane_count")
                .or_else(|| root.get("laneCount"))
                .and_then(JsonValue::as_u64)
                .filter(|count| *count > 0 && *count <= 64),
            operation_scripts,
            registry: addresses[0].clone(),
            batch: addresses[1].clone(),
            guard: addresses[2].clone(),
            state_policy: required_script(scripts, "packetstate")?.hash.clone(),
            batch_policy: required_script(scripts, "packetbatch")?.hash.clone(),
        })
    }

    fn operation_mint_allowed(
        &self,
        policy: &[u8],
        references: &HashSet<OutRef>,
    ) -> Result<bool, String> {
        let Some(script) = self
            .operation_scripts
            .iter()
            .find(|script| script.hash == policy)
        else {
            return Ok(false);
        };
        if !references.contains(&script.reference) {
            return Err("missing pinned packet operation validator".into());
        }
        Ok(true)
    }
}

pub(super) fn is_lane_operation(intent: &SigningIntent) -> bool {
    intent.operation == "PacketBatch"
        || intent.operation == "PacketAcknowledgementBatch"
        || intent.operation == "InitializePacketLanes"
        || intent.operation == "/ibc.applications.transfer.v1.MsgTransfer"
        || intent.module_port.as_deref() == Some("transfer")
            && (intent.packet.is_some() || intent.prune_sequence.is_some())
}

pub(super) fn acknowledgement_batch_matches(
    operation: &PlutusData,
    packets: &[PacketIntent],
    expected_tag: u64,
) -> bool {
    let Some(children) = constructor_fields(operation, expected_tag)
        .filter(|fields| fields.len() == 1)
        .and_then(|fields| match &fields[0] {
            PlutusData::Array(items) => Some(items.as_slice()),
            _ => None,
        })
    else {
        return false;
    };
    packets.len() == 2
        && children.len() == packets.len()
        && children.iter().zip(packets).all(|(child, packet)| {
            constructor_fields(child, 1)
                .filter(|fields| fields.len() == 4)
                .is_some_and(|fields| packet_plutus_matches(&fields[0], packet))
        })
}

fn inline_datum<'a>(output: &'a MintedTransactionOutput<'_>) -> Option<&'a PlutusData> {
    match output {
        PseudoTransactionOutput::PostAlonzo(output) => match output.datum_option.as_ref()? {
            PseudoDatumOption::Data(data) => Some(&data.0),
            _ => None,
        },
        _ => None,
    }
}
fn reserve_payment_matches(
    input: &ResolvedInput,
    address: &[u8],
    coin: u64,
    liquidity: bool,
    network: u8,
) -> bool {
    let Some(raw) = input.inline_datum.as_ref() else {
        return false;
    };
    let Ok(datum) = pallas_codec::minicbor::decode::<PlutusData>(raw) else {
        return false;
    };
    let Some(fields) = constructor_fields(&datum, 0) else {
        return false;
    };
    let (owner, reserve) = if liquidity {
        if fields.len() != 8 {
            return false;
        }
        let Some(owner_address) = constructor_fields(&fields[7], 0).filter(|f| f.len() == 2) else {
            return false;
        };
        if constructor_fields(&owner_address[1], 1).is_none_or(|f| !f.is_empty()) {
            return false;
        }
        let Some(credential) = constructor_fields(&owner_address[0], 0).filter(|f| f.len() == 1)
        else {
            return false;
        };
        let Some(owner) = plutus_bytes(&credential[0]) else {
            return false;
        };
        let principal = if plutus_bytes(&fields[3]) == Some(&[][..])
            && plutus_bytes(&fields[4]) == Some(&[][..])
        {
            let Some(amount) = plutus_u64(&fields[6]) else {
                return false;
            };
            amount
        } else {
            0
        };
        let Some(reserve) = input.lovelace.checked_sub(principal) else {
            return false;
        };
        (owner, reserve)
    } else {
        if fields.len() != 5 {
            return false;
        }
        let Some(owner) = plutus_bytes(&fields[2]) else {
            return false;
        };
        (owner, input.lovelace)
    };
    owner.len() == 28
        && address.len() == 29
        && address[0] == (0x60 | network)
        && &address[1..] == owner
        && coin == reserve
}

fn mint_redeemer<'a>(
    body: &pallas_primitives::conway::MintedTransactionBody<'_>,
    redeemers: &'a pallas_primitives::conway::Redeemers,
    policy: &[u8],
) -> Option<&'a PlutusData> {
    let mut policies: Vec<_> = body
        .mint
        .as_ref()?
        .iter()
        .map(|(p, _)| p.as_ref())
        .collect();
    policies.sort_unstable();
    let index = policies.iter().position(|p| *p == policy)? as u32;
    let mut matching = redeemers.iter().filter(|(key, _)| {
        key.tag == pallas_primitives::conway::RedeemerTag::Mint && key.index == index
    });
    let value = &matching.next()?.1.data;
    if matching.next().is_some() {
        return None;
    }
    Some(value)
}

impl TransactionSigningPolicy {
    pub(super) fn validate_packet_lanes<F>(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        redeemers: Option<&pallas_primitives::conway::Redeemers>,
        signer: &[u8],
        intent: &SigningIntent,
        resolved: &ResolvedTransactionInputs,
        reference_set: &HashSet<OutRef>,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        let regular: BTreeSet<_> = body
            .inputs
            .iter()
            .map(TransactionOutRef::from_transaction_input)
            .collect();
        if regular != resolved.regular.keys().cloned().collect() {
            return Err(reject("incomplete independent input resolution".into()));
        }
        if !resolved
            .regular
            .values()
            .any(|input| input.address == signer)
        {
            return Err(reject("missing signer funding input".into()));
        }
        let admission = intent.operation == "/ibc.applications.transfer.v1.MsgTransfer";
        let initialization = intent.operation == "InitializePacketLanes";
        let batch = intent.operation == "PacketBatch";
        let consolidation = intent.operation == "ConsolidatePacketLiquidity";
        if admission {
            return self.validate_funded_intent(body, signer, intent, resolved, reject);
        }
        let redeemers = redeemers.ok_or_else(|| reject("missing packet redeemers".into()))?;
        for (reference, input) in &resolved.regular {
            if input.address == signer {
                continue;
            }
            if initialization && input.address == self.packet_lanes.registry {
                if !input.assets.iter().any(|asset| {
                    asset.policy_id.as_slice() == self.packet_lanes.state_policy
                        && asset.asset_name == b"ibc_packet_registry"
                        && asset.quantity == 1
                }) {
                    return Err(reject("unauthenticated packet registry".into()));
                }
            } else if !initialization && input.address == self.packet_lanes.guard {
                if !reference_set.contains(
                    &required_script(&self.scripts, "packetguard")
                        .map_err(reject)?
                        .reference,
                ) {
                    return Err(reject("missing pinned packet guard validator".into()));
                }
                let action =
                    spend_redeemer_for_input(body, redeemers, reference).map_err(reject)?;
                if constructor_fields(action, 3).is_none()
                    && !(batch
                        && (constructor_fields(action, 0).is_some()
                            || constructor_fields(action, 2).is_some()))
                {
                    return Err(reject("packet transaction cannot cancel intents".into()));
                }
            } else if !initialization && input.address == self.packet_lanes.batch {
                if !input.assets.iter().any(|asset| {
                    asset.policy_id.as_slice() == self.packet_lanes.batch_policy
                        && asset.quantity == 1
                }) {
                    return Err(reject("unauthenticated liquidity input".into()));
                }
            } else if input.address != self.trace_registry_address {
                return Err(reject(
                    "unrelated script or third-party wallet input".into(),
                ));
            }
        }
        if batch
            && !resolved.regular.iter().any(|(reference, input)| {
                Some(reference.transaction_id) == intent.funded_intent
                    && input.address == self.packet_lanes.guard
            })
        {
            return Err(reject(
                "batch does not consume the requested funded intent".into(),
            ));
        }
        let policy = if initialization {
            &self.packet_lanes.state_policy
        } else {
            &self.packet_lanes.batch_policy
        };
        let action = mint_redeemer(body, redeemers, policy)
            .ok_or_else(|| reject("missing authenticated packet operation".into()))?;
        if initialization {
            let fields = constructor_fields(action, 1)
                .filter(|f| f.len() == 1)
                .ok_or_else(|| reject("unexpected packet issuance operation".into()))?;
            let registry = resolved
                .regular
                .values()
                .find(|input| input.address == self.packet_lanes.registry)
                .ok_or_else(|| reject("missing packet registry input".into()))?;
            let registry_datum: PlutusData = pallas_codec::minicbor::decode(
                registry
                    .inline_datum
                    .as_deref()
                    .ok_or_else(|| reject("missing authenticated registry datum".into()))?,
            )
            .map_err(|_| reject("invalid registry datum".into()))?;
            let channel = constructor_fields(&registry_datum, 0)
                .filter(|f| f.len() == 1)
                .and_then(|f| plutus_u64(&f[0]))
                .ok_or_else(|| reject("invalid registry counter".into()))?;
            if intent
                .state_sequence
                .is_none_or(|requested| channel > requested)
                || !auth_token_matches(
                    &fields[0],
                    &self.channel_state.policy,
                    &self.state_token_name(StateOutputKind::Channel, channel),
                )
            {
                return Err(reject(
                    "packet initialization is outside the requested channel prefix".into(),
                ));
            }
        } else {
            let authorized = constructor_fields(action, 0)
                .filter(|f| f.len() == 3)
                .ok_or_else(|| reject("invalid authorized packet operation".into()))?;
            let channel = intent
                .state_sequence
                .ok_or_else(|| reject("missing channel intent".into()))?;
            if !auth_token_matches(
                &authorized[0],
                &self.channel_state.policy,
                &self.state_token_name(StateOutputKind::Channel, channel),
            ) {
                return Err(reject("packet operation refers to another channel".into()));
            }
            let operation = &authorized[1];
            if consolidation {
                self.validate_liquidity_consolidation(
                    body,
                    operation,
                    signer,
                    intent,
                    resolved,
                    reference_set,
                )
                .map_err(reject)?;
            } else if batch {
                if constructor_fields(operation, 0).is_none() {
                    return Err(reject("unexpected send-batch operation".into()));
                }
            } else if !intent.acknowledgement_packets.is_empty() {
                if !acknowledgement_batch_matches(
                    operation,
                    &intent.acknowledgement_packets,
                    self.packet_lanes.acknowledgement_batch_tag,
                ) {
                    return Err(reject(
                        "acknowledgement batch changes the requested packets".into(),
                    ));
                }
            } else if let Some(packet) = &intent.packet {
                let alternatives: &[u64] = if intent.operation.ends_with("MsgRecvPacket") {
                    &[5]
                } else if intent.operation.ends_with("MsgAcknowledgement") {
                    &[1, 6]
                } else if intent.operation.ends_with("MsgTimeout") {
                    &[2]
                } else if intent.operation.ends_with("MsgTimeoutOnClose") {
                    &[8]
                } else {
                    &[]
                };
                if !alternatives.iter().any(|index| {
                    constructor_fields(operation, *index)
                        .and_then(|fields| fields.first())
                        .is_some_and(|data| packet_plutus_matches(data, packet))
                }) {
                    return Err(reject(
                        "lane operation does not match the requested packet".into(),
                    ));
                }
            } else if let Some(sequence) = intent.prune_sequence {
                if constructor_fields(operation, 7)
                    .and_then(|fields| fields.first())
                    .and_then(plutus_u64)
                    != Some(sequence)
                {
                    return Err(reject(
                        "pruning operation changes the requested sequence".into(),
                    ));
                }
            } else {
                return Err(reject("unsupported packet intent".into()));
            }
        }
        if let Some(mint) = &body.mint {
            for (policy, _) in mint.iter() {
                let operation_mint = self
                    .packet_lanes
                    .operation_mint_allowed(policy.as_ref(), reference_set)
                    .map_err(reject)?;
                let permitted = if consolidation {
                    policy.as_ref() == self.packet_lanes.batch_policy
                        || policy.as_ref()
                            == required_script(&self.scripts, "packetoperationretire")
                                .map_err(reject)?
                                .hash
                } else if initialization {
                    policy.as_ref() == self.packet_lanes.state_policy
                } else {
                    policy.as_ref() == self.packet_lanes.batch_policy
                        || policy.as_ref() == self.voucher_policy
                        || policy.as_ref() == self.trace_registry_policy
                        || operation_mint
                };
                if !permitted {
                    return Err(reject("unrelated minting policy".into()));
                }
                if policy.as_ref() == self.voucher_policy
                    && !reference_set.contains(
                        &required_script(&self.scripts, "mintvoucher")
                            .map_err(reject)?
                            .reference,
                    )
                {
                    return Err(reject("missing pinned voucher validator".into()));
                }
            }
        }
        let mut protocol_lovelace = 0u64;
        for output in &body.outputs {
            let value = unpack_output(output);
            validate_address_network(&value.address, self.network_id).map_err(reject)?;
            if value.has_script_ref {
                return Err(reject("packet outputs cannot install scripts".into()));
            }
            if value.address == signer {
                continue;
            }
            if value.address == self.packet_lanes.guard
                || value.address == self.packet_lanes.batch
                || initialization && value.address == self.packet_lanes.registry
                || value.address == self.trace_registry_address
                || value.address == self.voucher_metadata_address
            {
                protocol_lovelace = protocol_lovelace
                    .checked_add(value.coin)
                    .ok_or_else(|| reject("protocol ADA overflow".into()))?;
                continue;
            }
            let datum = inline_datum(output).and_then(|data| constructor_fields(data, 0));
            let reserve_refund = datum
                .filter(|fields| fields.len() == 2)
                .is_some_and(|fields| {
                    plutus_bytes(&fields[0]) == Some(self.packet_lanes.batch_policy.as_slice())
                        && plutus_bytes(&fields[1]).is_some_and(|name| {
                            resolved.regular.values().any(|input| {
                                input.address == self.packet_lanes.batch
                                    && reserve_payment_matches(
                                        input,
                                        &value.address,
                                        value.coin,
                                        true,
                                        self.network_id,
                                    )
                                    && input.assets.iter().any(|asset| {
                                        asset.policy_id.as_slice() == self.packet_lanes.batch_policy
                                            && asset.asset_name == name
                                            && asset.quantity == 1
                                    })
                            })
                        })
                });
            let burned_intent_reserve = batch
                && datum
                    .filter(|fields| fields.len() == 2)
                    .is_some_and(|fields| {
                        plutus_bytes(&fields[0])
                            .zip(plutus_u64(&fields[1]))
                            .is_some_and(|(hash, index)| {
                                resolved.regular.iter().any(|(reference, input)| {
                                    reference.transaction_id.as_slice() == hash
                                        && reference.output_index == index
                                        && input.address == self.packet_lanes.guard
                                        && reserve_payment_matches(
                                            input,
                                            &value.address,
                                            value.coin,
                                            false,
                                            self.network_id,
                                        )
                                })
                            })
                    });
            if reserve_refund || burned_intent_reserve {
                if !value.assets.is_empty() || value.coin > self.limits.max_external_output_lovelace
                {
                    return Err(reject("invalid reserve reimbursement".into()));
                }
                continue;
            }
            let external = intent
                .external_output
                .as_ref()
                .filter(|expected| expected.address == value.address)
                .ok_or_else(|| reject("unrequested external packet payout".into()))?;
            self.validate_external_value(&value, &external.transfer, body, reject)?;
        }
        if protocol_lovelace > self.limits.max_total_protocol_output_lovelace {
            return Err(reject("packet protocol ADA exceeds signing limit".into()));
        }
        Ok(())
    }

    fn validate_liquidity_consolidation(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        operation: &PlutusData,
        signer: &[u8],
        intent: &SigningIntent,
        resolved: &ResolvedTransactionInputs,
        references: &HashSet<OutRef>,
    ) -> Result<(), String> {
        let fields = constructor_fields(operation, 4)
            .filter(|f| f.len() == 2)
            .ok_or("expected liquidity consolidation")?;
        let PlutusData::Array(items) = &fields[0] else {
            return Err("invalid consolidation inputs".into());
        };
        let selected = items
            .iter()
            .map(plutus_output_reference)
            .collect::<Option<Vec<_>>>()
            .ok_or("invalid consolidation reference")?;
        let unique: BTreeSet<_> = selected.iter().cloned().collect();
        let script_inputs: BTreeSet<_> = resolved
            .regular
            .iter()
            .filter(|(_, input)| input.address != signer)
            .map(|(reference, _)| reference.clone())
            .collect();
        if !(2..=5).contains(&selected.len())
            || unique.len() != selected.len()
            || unique != script_inputs
        {
            return Err("consolidation must consume two to five distinct escrow inputs".into());
        }
        let survivor =
            plutus_output_reference(&fields[1]).ok_or("invalid consolidation survivor")?;
        if !unique.contains(&survivor) {
            return Err("consolidation survivor is not an input".into());
        }
        let transfer = intent
            .transfer
            .as_ref()
            .ok_or("missing consolidation transfer")?;
        let source_prefix = format!(
            "{}/{}/",
            transfer
                .source_port
                .as_deref()
                .ok_or("missing source port")?,
            transfer
                .source_channel
                .as_deref()
                .ok_or("missing source channel")?
        );
        let denom = match transfer.action {
            TransferAction::Receive => transfer
                .denom
                .strip_prefix(&source_prefix)
                .ok_or("receive does not release escrow")?,
            TransferAction::Refund if !transfer.denom.starts_with(&source_prefix) => {
                &transfer.denom
            }
            _ => return Err("packet does not release escrow".into()),
        };
        let channel = format!(
            "channel-{}",
            intent
                .state_sequence
                .ok_or("missing consolidation channel")?
        );
        let retire = required_script(&self.scripts, "packetoperationretire")?;
        if !references.contains(&retire.reference)
            || !body.mint.as_ref().is_some_and(|mint| {
                mint.iter()
                    .any(|(policy, _)| policy.as_ref() == retire.hash)
            })
        {
            return Err("missing pinned consolidation policy".into());
        }
        let mut total = 0u64;
        let mut survivor_datum = None;
        for reference in &selected {
            let input = &resolved.regular[reference];
            if input.address != self.packet_lanes.batch {
                return Err("consolidation spends unrelated state".into());
            }
            let datum: PlutusData = minicbor::decode(
                input
                    .inline_datum
                    .as_deref()
                    .ok_or("missing liquidity datum")?,
            )
            .map_err(|_| "invalid liquidity datum")?;
            let data = constructor_fields(&datum, 0)
                .filter(|f| f.len() == 8)
                .ok_or("invalid liquidity record")?;
            if plutus_bytes(&data[0]) != Some(b"transfer".as_slice())
                || plutus_bytes(&data[1]) != Some(channel.as_bytes())
                || plutus_bytes(&data[2]) != Some(denom.as_bytes())
            {
                return Err("consolidation changes the requested channel or denomination".into());
            }
            let principal = plutus_u64(&data[6])
                .filter(|amount| *amount > 0)
                .ok_or("invalid liquidity principal")?;
            total = total
                .checked_add(principal)
                .ok_or("liquidity principal overflow")?;
            if reference == &survivor {
                survivor_datum = Some(datum);
            }
        }
        let mut burns = BTreeMap::new();
        for reference in selected.iter().filter(|reference| **reference != survivor) {
            let input = &resolved.regular[reference];
            let identities: Vec<_> = input
                .assets
                .iter()
                .filter(|asset| asset.policy_id.as_slice() == self.packet_lanes.batch_policy)
                .collect();
            if identities.len() != 1 || identities[0].quantity != 1 {
                return Err("invalid donor identity".into());
            }
            let name = &identities[0].asset_name;
            if burns.insert(name.clone(), -1i64).is_some() {
                return Err("duplicate donor identity".into());
            }
            let refunds = body
                .outputs
                .iter()
                .filter(|output| {
                    let value = unpack_output(output);
                    inline_datum(output).is_some_and(|datum| {
                        auth_token_matches(datum, &self.packet_lanes.batch_policy, name)
                    }) && value.assets.is_empty()
                        && reserve_payment_matches(
                            input,
                            &value.address,
                            value.coin,
                            true,
                            self.network_id,
                        )
                })
                .count();
            if refunds != 1 {
                return Err("missing or duplicate donor reserve reimbursement".into());
            }
        }
        let minted: BTreeMap<_, _> = body
            .mint
            .as_ref()
            .into_iter()
            .flat_map(|mint| mint.iter())
            .filter(|(policy, _)| policy.as_ref() == self.packet_lanes.batch_policy)
            .flat_map(|(_, assets)| {
                assets
                    .iter()
                    .map(|(name, quantity)| (name.to_vec(), i64::from(*quantity)))
            })
            .collect();
        if minted != burns {
            return Err("consolidation must burn exactly the donor identities".into());
        }
        // A sufficient bounded selection should settle directly instead of spending
        // another maintenance fee. The pinned retire validator enforces NFT identity,
        // equal asset units, donor burns and all reserve reimbursements.
        if total >= transfer.amount {
            return Err("selected liquidity already covers the packet".into());
        }
        let input = &resolved.regular[&survivor];
        let mut datum = survivor_datum.ok_or("missing survivor datum")?;
        let old = constructor_fields(&datum, 0).ok_or("invalid survivor datum")?;
        let principal = plutus_u64(&old[6]).ok_or("invalid survivor principal")?;
        let policy = plutus_bytes(&old[3])
            .ok_or("invalid asset policy")?
            .to_vec();
        let name = plutus_bytes(&old[4]).ok_or("invalid asset name")?.to_vec();
        let delta = total - principal;
        let mut coin = input.lovelace;
        let mut assets: BTreeMap<_, _> = input
            .assets
            .iter()
            .map(|a| ((a.policy_id.to_vec(), a.asset_name.clone()), a.quantity))
            .collect();
        if policy.is_empty() && name.is_empty() {
            coin = coin.checked_add(delta).ok_or("liquidity value overflow")?;
        } else {
            let amount = assets
                .get_mut(&(policy, name))
                .ok_or("missing principal asset")?;
            *amount = amount
                .checked_add(delta)
                .ok_or("liquidity value overflow")?;
        }
        let PlutusData::Constr(ref mut constructor) = datum else {
            unreachable!()
        };
        constructor.fields[6] = PlutusData::BigInt(BigInt::Int(
            i128::from(total)
                .try_into()
                .map_err(|_| "principal overflow")?,
        ));
        let mut survivors = 0;
        for output in &body.outputs {
            let value = unpack_output(output);
            if value.address == self.packet_lanes.batch {
                survivors += 1;
                let output_assets: BTreeMap<_, _> = value
                    .assets
                    .iter()
                    .map(|(p, n, q)| ((p.clone(), n.clone()), *q))
                    .collect();
                if value.coin != coin
                    || output_assets != assets
                    || inline_datum(output) != Some(&datum)
                {
                    return Err("consolidation changes principal or survivor reserve".into());
                }
            } else if value.address != signer
                && !selected
                    .iter()
                    .filter(|reference| **reference != survivor)
                    .any(|reference| {
                        reserve_payment_matches(
                            &resolved.regular[reference],
                            &value.address,
                            value.coin,
                            true,
                            self.network_id,
                        )
                    })
            {
                return Err("consolidation has an unrelated output".into());
            }
        }
        if survivors != 1 {
            return Err("consolidation requires one survivor".into());
        }
        Ok(())
    }

    fn validate_funded_intent<F>(
        &self,
        body: &pallas_primitives::conway::MintedTransactionBody<'_>,
        signer: &[u8],
        intent: &SigningIntent,
        resolved: &ResolvedTransactionInputs,
        reject: &F,
    ) -> Result<(), Error>
    where
        F: Fn(String) -> Error,
    {
        if body.mint.is_some()
            || resolved
                .regular
                .values()
                .any(|input| input.address != signer)
        {
            return Err(reject(
                "admission may only spend signer funds and cannot mint".into(),
            ));
        }
        let transfer = intent
            .transfer
            .as_ref()
            .ok_or_else(|| reject("missing transfer request".into()))?;
        let denom = outbound_packet_denom(transfer)
            .ok_or_else(|| reject("unresolved transfer denomination".into()))?;
        let outputs: Vec<_> = body
            .outputs
            .iter()
            .filter(|output| unpack_output(output).address != signer)
            .collect();
        if outputs.len() != 1 {
            return Err(reject(
                "admission requires exactly one funded intent".into(),
            ));
        }
        let output = outputs[0];
        let value = unpack_output(output);
        if value.address != self.packet_lanes.guard || value.has_script_ref {
            return Err(reject("intent is not at the pinned guard".into()));
        }
        let fields = inline_datum(output)
            .and_then(|data| constructor_fields(data, 0))
            .filter(|f| f.len() == 5)
            .ok_or_else(|| reject("invalid funded intent datum".into()))?;
        let payload = constructor_fields(&fields[3], 0)
            .filter(|f| f.len() == 5)
            .ok_or_else(|| reject("invalid transfer intent payload".into()))?;
        let owner = &signer[1..];
        let owner_hex = hex::encode(owner);
        let amount_text = transfer.amount.to_string();
        let expected = [
            denom.as_bytes(),
            amount_text.as_bytes(),
            owner_hex.as_bytes(),
            transfer.receiver.as_bytes(),
            transfer.memo.as_bytes(),
        ];
        if plutus_bytes(&fields[0]) != transfer.source_port.as_deref().map(str::as_bytes)
            || plutus_bytes(&fields[1]) != transfer.source_channel.as_deref().map(str::as_bytes)
            || plutus_bytes(&fields[2]) != Some(owner)
            || plutus_u64(&fields[4]) != Some(transfer.timeout_timestamp)
            || !payload
                .iter()
                .zip(expected)
                .all(|(actual, expected)| plutus_bytes(actual) == Some(expected))
        {
            return Err(reject(
                "funded intent differs from the original transfer".into(),
            ));
        }
        let (minimum_ada, expected_asset) = match expected_asset(transfer) {
            ExpectedAsset::Lovelace => (transfer.amount, None),
            ExpectedAsset::Native(policy, name) => (0, Some((policy, name))),
            ExpectedAsset::Voucher {
                user_name: Some(name),
                ..
            } => (0, Some((self.voucher_policy.clone(), name))),
            _ => return Err(reject("unresolved intent asset".into())),
        };
        if value.coin < minimum_ada
            || value.coin.saturating_sub(minimum_ada) > self.limits.max_wallet_lovelace_top_up
        {
            return Err(reject("invalid intent ADA reserve".into()));
        }
        match expected_asset {
            None if !value.assets.is_empty() => {
                return Err(reject("unexpected intent assets".into()))
            }
            Some((policy, name))
                if value.assets != vec![(policy.clone(), name.clone(), transfer.amount)] =>
            {
                return Err(reject("incorrect intent asset quantity".into()))
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_codec::minicbor::{data::Tag, Encoder};

    #[test]
    fn membership_mints_require_the_manifest_policy_and_its_exact_reference() {
        for name in ["verify_membership", "verifyMembership"] {
            let mut manifest: JsonValue =
                serde_json::from_str(&super::super::tests::manifest()).unwrap();
            manifest["validators"][name] = serde_json::json!({
                "script_hash": "ab".repeat(28),
                "ref_utxo": {"tx_hash": "cd".repeat(32), "output_index": 2}
            });
            let policy = TransactionSigningPolicy::from_json(
                &manifest.to_string(),
                0,
                super::super::tests::limits(),
            )
            .unwrap();
            let membership = required_script(&policy.scripts, "verifymembership").unwrap();
            let pinned = HashSet::from([membership.reference.clone()]);
            assert_eq!(
                policy
                    .packet_lanes
                    .operation_mint_allowed(&membership.hash, &pinned),
                Ok(true)
            );
            assert!(policy
                .packet_lanes
                .operation_mint_allowed(&membership.hash, &HashSet::new())
                .is_err());
            let wrong_reference = HashSet::from([(membership.reference.0.clone(), 3)]);
            assert!(policy
                .packet_lanes
                .operation_mint_allowed(&membership.hash, &wrong_reference)
                .is_err());
            assert_eq!(
                policy
                    .packet_lanes
                    .operation_mint_allowed(&[0xef; 28], &pinned),
                Ok(false)
            );
            let general = required_script(&policy.scripts, "verifyproof").unwrap();
            assert_eq!(
                policy.packet_lanes.operation_mint_allowed(
                    &general.hash,
                    &HashSet::from([general.reference.clone()])
                ),
                Ok(true)
            );
        }
    }

    #[test]
    fn older_manifests_keep_the_general_verifier_and_reject_unpinned_membership() {
        let policy = TransactionSigningPolicy::from_json(
            &super::super::tests::manifest(),
            0,
            super::super::tests::limits(),
        )
        .unwrap();
        let general = required_script(&policy.scripts, "verifyproof").unwrap();
        assert_eq!(
            policy
                .packet_lanes
                .operation_mint_allowed(&general.hash, &HashSet::from([general.reference.clone()])),
            Ok(true)
        );
        assert_eq!(
            policy
                .packet_lanes
                .operation_mint_allowed(&[0xab; 28], &HashSet::new()),
            Ok(false)
        );
    }

    fn reserve_input(liquidity: bool, native: bool) -> ResolvedInput {
        let mut cbor = Vec::new();
        let mut enc = Encoder::new(&mut cbor);
        enc.tag(Tag::Unassigned(121))
            .unwrap()
            .array(if liquidity { 8 } else { 5 })
            .unwrap();
        enc.bytes(b"transfer").unwrap().bytes(b"channel-0").unwrap();
        if liquidity {
            enc.bytes(b"identity")
                .unwrap()
                .bytes(if native { &[] } else { &[1; 28] })
                .unwrap();
            enc.bytes(&[])
                .unwrap()
                .u64(0)
                .unwrap()
                .u64(7_000_000)
                .unwrap();
            enc.tag(Tag::Unassigned(121)).unwrap().array(2).unwrap();
            enc.tag(Tag::Unassigned(121))
                .unwrap()
                .array(1)
                .unwrap()
                .bytes(&[9; 28])
                .unwrap();
            enc.tag(Tag::Unassigned(122)).unwrap().array(0).unwrap();
        } else {
            enc.bytes(&[9; 28]).unwrap().u64(0).unwrap().u64(0).unwrap();
        }
        ResolvedInput {
            address: vec![],
            lovelace: 10_000_000,
            assets: vec![],
            inline_datum: Some(cbor),
        }
    }

    #[test]
    fn reserve_refunds_require_the_authenticated_owner_and_exact_reserve() {
        let owner = [vec![0x60], vec![9; 28]].concat();
        let attacker = [vec![0x60], vec![8; 28]].concat();
        for (liquidity, native, reserve) in [
            (true, true, 3_000_000),
            (true, false, 10_000_000),
            (false, false, 10_000_000),
        ] {
            let mut input = reserve_input(liquidity, native);
            assert!(reserve_payment_matches(
                &input, &owner, reserve, liquidity, 0
            ));
            assert!(!reserve_payment_matches(
                &input, &attacker, reserve, liquidity, 0
            ));
            assert!(!reserve_payment_matches(
                &input,
                &owner,
                reserve + 1,
                liquidity,
                0
            ));
            assert!(!reserve_payment_matches(
                &input, &owner, reserve, liquidity, 1
            ));
            input.inline_datum = None;
            assert!(!reserve_payment_matches(
                &input, &owner, reserve, liquidity, 0
            ));
        }
    }
}
