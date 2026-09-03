//! Cardano transaction signing using Pallas

use super::error::Error;
use super::keyring::CardanoKeyring;
use super::signing_policy::{SigningIntent, TransactionSigningPolicy};
use super::utxo_resolver::ResolvedTransactionInputs;
use blake2::Digest;
use pallas_codec::minicbor;
use pallas_primitives::conway::{MintedTx, VKeyWitness};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTransaction {
    pub cbor: Vec<u8>,
    pub tx_hash: String,
}

/// Sign a Cardano transaction
pub fn sign_transaction(
    unsigned_tx_cbor: &[u8],
    keyring: &CardanoKeyring,
    signer_address: &str,
    policy: &TransactionSigningPolicy,
    intent: &SigningIntent,
    resolved_inputs: &ResolvedTransactionInputs,
) -> Result<SignedTransaction, Error> {
    // 1. Parse the unsigned transaction
    let mut decoder = minicbor::Decoder::new(unsigned_tx_cbor);
    let tx: MintedTx<'_> = decoder
        .decode()
        .map_err(|e| Error::CborDecode(format!("Failed to decode transaction: {:?}", e)))?;
    if decoder.position() != unsigned_tx_cbor.len() {
        return Err(Error::CborDecode(
            "Failed to decode transaction: trailing CBOR data".to_string(),
        ));
    }

    // The Gateway only builds a candidate. Authorization is derived from local,
    // pinned deployment data and the original message Hermes intended to relay.
    policy.validate(
        &tx,
        unsigned_tx_cbor.len(),
        signer_address,
        intent,
        resolved_inputs,
    )?;

    // 2. Extract and hash the transaction body
    // Use the original raw bytes preserved by KeepRaw, not re-encoded bytes
    let tx_body_cbor = tx.transaction_body.raw_cbor();

    // Cardano uses Blake2b-256 for transaction hashing
    use blake2::digest::consts::U32;
    use blake2::Blake2b;
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(tx_body_cbor);
    let tx_hash = hasher.finalize();
    let tx_hash_hex = hex::encode(tx_hash.as_slice());

    // 3. Sign the transaction hash
    let signature = keyring.sign(tx_hash.as_slice());

    // 4. Create VKeyWitness
    let vkey = keyring.verifying_key().as_bytes().to_vec();
    let sig = signature.to_bytes().to_vec();

    let vkey_witness = VKeyWitness {
        vkey: vkey.into(),
        signature: sig.into(),
    };

    // 5. Reconstruct the transaction with the new witness
    // We need to work around Pallas's KeepRaw immutability by manually building CBOR

    // Get existing witnesses
    let mut new_vkeywitnesses: Vec<VKeyWitness> = tx
        .transaction_witness_set
        .vkeywitness
        .clone()
        .map(|set| set.to_vec())
        .unwrap_or_default();
    new_vkeywitnesses.push(vkey_witness);

    // Encode the new witness set manually
    let mut witness_set_cbor = Vec::new();
    {
        let mut encoder = minicbor::Encoder::new(&mut witness_set_cbor);

        // Count how many witness set fields we have
        let ws = &tx.transaction_witness_set;
        let mut map_size = 1u64; // Always have vkeywitness
        if ws.native_script.is_some() {
            map_size += 1;
        }
        if ws.bootstrap_witness.is_some() {
            map_size += 1;
        }
        if ws.plutus_v1_script.is_some() {
            map_size += 1;
        }
        if ws.plutus_data.is_some() {
            map_size += 1;
        }
        if ws.redeemer.is_some() {
            map_size += 1;
        }
        if ws.plutus_v2_script.is_some() {
            map_size += 1;
        }
        if ws.plutus_v3_script.is_some() {
            map_size += 1;
        }

        // Witness set is a CBOR map
        encoder
            .map(map_size)
            .map_err(|e| Error::Signer(format!("Failed to encode witness map: {:?}", e)))?;

        // Key 0: vkeywitness array
        encoder
            .u8(0)
            .map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
        encoder
            .array(new_vkeywitnesses.len() as u64)
            .map_err(|e| Error::Signer(format!("Failed to encode array: {:?}", e)))?;
        for witness in &new_vkeywitnesses {
            encoder
                .encode(witness)
                .map_err(|e| Error::Signer(format!("Failed to encode witness: {:?}", e)))?;
        }

        // Copy other witness set fields if present
        if let Some(ref native_scripts) = ws.native_script {
            encoder
                .u8(1)
                .map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder
                .encode(native_scripts)
                .map_err(|e| Error::Signer(format!("Failed to encode native scripts: {:?}", e)))?;
        }

        if let Some(ref bootstrap) = ws.bootstrap_witness {
            encoder
                .u8(2)
                .map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder
                .encode(bootstrap)
                .map_err(|e| Error::Signer(format!("Failed to encode bootstrap: {:?}", e)))?;
        }

        if let Some(ref plutus_v1) = ws.plutus_v1_script {
            encoder
                .u8(3)
                .map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder
                .encode(plutus_v1)
                .map_err(|e| Error::Signer(format!("Failed to encode plutus v1: {:?}", e)))?;
        }

        if let Some(ref plutus_data) = ws.plutus_data {
            encoder
                .u8(4)
                .map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder
                .encode(plutus_data)
                .map_err(|e| Error::Signer(format!("Failed to encode plutus data: {:?}", e)))?;
        }

        if let Some(ref redeemers) = ws.redeemer {
            encoder
                .u8(5)
                .map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder
                .encode(redeemers)
                .map_err(|e| Error::Signer(format!("Failed to encode redeemers: {:?}", e)))?;
        }

        if let Some(ref plutus_v2) = ws.plutus_v2_script {
            encoder
                .u8(6)
                .map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder
                .encode(plutus_v2)
                .map_err(|e| Error::Signer(format!("Failed to encode plutus v2: {:?}", e)))?;
        }

        if let Some(ref plutus_v3) = ws.plutus_v3_script {
            encoder
                .u8(7)
                .map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder
                .encode(plutus_v3)
                .map_err(|e| Error::Signer(format!("Failed to encode plutus v3: {:?}", e)))?;
        }
    }

    // Build the final signed transaction CBOR
    // Conway transaction is an array: [transaction_body, transaction_witness_set, is_valid, auxiliary_data]
    // where auxiliary_data can be null
    let mut signed_tx_cbor = Vec::new();
    {
        let mut encoder = minicbor::Encoder::new(&mut signed_tx_cbor);

        // Conway transactions always have 4 elements
        encoder
            .array(4)
            .map_err(|e| Error::Signer(format!("Failed to encode tx array: {:?}", e)))?;

        // Encode transaction body
        encoder
            .encode(&tx.transaction_body)
            .map_err(|e| Error::Signer(format!("Failed to encode tx body: {:?}", e)))?;

        // Write the witness set CBOR directly (not as a byte string wrapper)
        use std::io::Write;
        encoder
            .writer_mut()
            .write_all(&witness_set_cbor)
            .map_err(|e| Error::Signer(format!("Failed to write witness set: {:?}", e)))?;

        // Encode isValid flag
        encoder
            .bool(tx.success)
            .map_err(|e| Error::Signer(format!("Failed to encode success: {:?}", e)))?;

        // Encode auxiliary data (using Nullable encoding)
        encoder
            .encode(&tx.auxiliary_data)
            .map_err(|e| Error::Signer(format!("Failed to encode aux data: {:?}", e)))?;
    }

    Ok(SignedTransaction {
        cbor: signed_tx_cbor,
        tx_hash: tx_hash_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::cardano::signing_policy::SigningPolicyLimits;
    use crate::chain::cardano::utxo_resolver::{ResolvedAsset, ResolvedInput, TransactionOutRef};

    const HOST_ADDRESS: [u8; 29] = [
        0x70, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    ];

    fn policy() -> TransactionSigningPolicy {
        let manifest = format!(
            r#"{{
                "validators": {{
                    "host_state_stt": {{
                        "address": "{}",
                        "script_hash": "{}",
                        "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}
                    }},
                    "spend_client": {{"address": "70{}"}},
                    "spend_connection": {{"address": "70{}"}},
                    "spend_channel": {{"address": "70{}"}},
                    "mint_client_stt": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_connection_stt": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_channel_stt": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_voucher": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_transfer_escrow_shard": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_identifier": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "mint_port": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "spend_transfer_module": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "spend_trace_registry": {{"script_hash": "{}", "ref_utxo": {{"tx_hash": "{}", "output_index": 0}}}},
                    "voucher_metadata": {{"address": "70{}"}}
                }},
                "host_state_nft": {{"policy_id": "{}", "token_name": "01"}},
                "modules": {{"transfer": {{"identifier": "{}01", "address": "70{}"}}}},
                "trace_registry": {{"address": "70{}", "shard_policy_id": "{}"}}
            }}"#,
            hex::encode(HOST_ADDRESS),
            "21".repeat(28),
            "31".repeat(32),
            "12".repeat(28),
            "13".repeat(28),
            "14".repeat(28),
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
            "15".repeat(28),
            "24".repeat(28),
            "2d".repeat(28),
            "16".repeat(28),
            "17".repeat(28),
            "2e".repeat(28),
        );
        TransactionSigningPolicy::from_json(
            &manifest,
            0,
            SigningPolicyLimits {
                max_fee_lovelace: 5_000_000,
                max_total_collateral_lovelace: 10_000_000,
                max_tx_size_bytes: 64 * 1024,
                max_external_output_lovelace: 5_000_000,
                max_total_protocol_output_lovelace: 50_000_000,
                max_wallet_lovelace_top_up: 5_000_000,
                max_validity_interval_slots: 3_600,
            },
        )
        .unwrap()
    }

    fn unsigned_tx_fixture(
        keyring: &CardanoKeyring,
        existing_vkey_witness: bool,
        protocol_sink: bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);

        enc.array(4).unwrap();
        enc.map(5).unwrap();

        enc.u8(0).unwrap();
        enc.array(2).unwrap();
        enc.array(2).unwrap();
        enc.bytes(&[0u8; 32]).unwrap();
        enc.u64(0).unwrap();
        enc.array(2).unwrap();
        enc.bytes(&[0x40u8; 32]).unwrap();
        enc.u64(0).unwrap();

        enc.u8(1).unwrap();
        enc.array(if protocol_sink { 3 } else { 2 }).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&HOST_ADDRESS).unwrap();
        enc.array(2).unwrap();
        enc.u64(2_000_000).unwrap();
        enc.map(1).unwrap();
        enc.bytes(&[0x24; 28]).unwrap();
        enc.map(1).unwrap();
        enc.bytes(&[0x01]).unwrap();
        enc.u64(1).unwrap();
        enc.null().unwrap();
        enc.array(3).unwrap();
        enc.bytes(&hex::decode(keyring.address(0)).unwrap())
            .unwrap();
        enc.u64(3_000_000).unwrap();
        enc.null().unwrap();
        if protocol_sink {
            enc.array(3).unwrap();
            enc.bytes(&[vec![0x70], vec![0x15; 28]].concat()).unwrap();
            enc.u64(25_000_000).unwrap();
            enc.null().unwrap();
        }

        enc.u8(2).unwrap();
        enc.u64(500_000).unwrap();
        enc.u8(3).unwrap();
        enc.u64(1_000).unwrap();
        enc.u8(18).unwrap();
        enc.array(1).unwrap();
        enc.array(2).unwrap();
        enc.bytes(&[0x31; 32]).unwrap();
        enc.u64(0).unwrap();

        if existing_vkey_witness {
            enc.map(2).unwrap();
            enc.u8(0).unwrap();
            enc.array(1).unwrap();
            enc.array(2).unwrap();
            enc.bytes(&[2u8; 32]).unwrap();
            enc.bytes(&[3u8; 64]).unwrap();
        } else {
            enc.map(1).unwrap();
        }
        enc.u8(5).unwrap();
        enc.array(1).unwrap();
        enc.array(4).unwrap();
        enc.u8(0).unwrap();
        enc.u32(1).unwrap();
        enc.tag(minicbor::data::Tag::Unassigned(1283)).unwrap();
        enc.array(0).unwrap();
        enc.array(2).unwrap();
        enc.u64(1).unwrap();
        enc.u64(1).unwrap();
        enc.bool(true).unwrap();
        enc.null().unwrap();
        out
    }

    fn intent(keyring: &CardanoKeyring) -> SigningIntent {
        let signer = keyring.address(0);
        SigningIntent::heartbeat(&signer, &signer, 0).unwrap()
    }

    fn resolved_inputs(keyring: &CardanoKeyring) -> ResolvedTransactionInputs {
        let mut resolved = ResolvedTransactionInputs::default();
        resolved.regular.insert(
            TransactionOutRef {
                transaction_id: [0u8; 32],
                output_index: 0,
            },
            ResolvedInput {
                address: hex::decode(keyring.address(0)).unwrap(),
                lovelace: 3_500_000,
                assets: Vec::new(),
            },
        );
        resolved.regular.insert(
            TransactionOutRef {
                transaction_id: [0x40u8; 32],
                output_index: 0,
            },
            ResolvedInput {
                address: HOST_ADDRESS.to_vec(),
                lovelace: 2_000_000,
                assets: vec![ResolvedAsset {
                    policy_id: [0x24; 28],
                    asset_name: vec![0x01],
                    quantity: 1,
                }],
            },
        );
        resolved
    }

    fn sign_fixture(unsigned: &[u8], keyring: &CardanoKeyring) -> Result<SignedTransaction, Error> {
        sign_transaction(
            unsigned,
            keyring,
            &keyring.address(0),
            &policy(),
            &intent(keyring),
            &resolved_inputs(keyring),
        )
    }

    #[test]
    fn sign_transaction_adds_vkey_witness_and_returns_body_hash() {
        let keyring = CardanoKeyring::new_for_testing().unwrap();
        let unsigned = unsigned_tx_fixture(&keyring, false, false);
        let unsigned_tx: MintedTx<'_> = minicbor::decode(&unsigned).unwrap();

        let signed = sign_fixture(&unsigned, &keyring).unwrap();
        let signed_tx: MintedTx<'_> = minicbor::decode(&signed.cbor).unwrap();

        assert_eq!(
            signed_tx.transaction_body.raw_cbor(),
            unsigned_tx.transaction_body.raw_cbor()
        );

        use blake2::digest::consts::U32;
        use blake2::Blake2b;
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(signed_tx.transaction_body.raw_cbor());
        let tx_hash = hasher.finalize();
        assert_eq!(signed.tx_hash, hex::encode(tx_hash));

        let witnesses = signed_tx
            .transaction_witness_set
            .vkeywitness
            .clone()
            .expect("expected vkey witness set")
            .to_vec();
        let added_witness = witnesses
            .iter()
            .find(|witness| witness.vkey.as_slice() == keyring.verifying_key().as_bytes())
            .expect("expected witness with the configured verification key");

        use ed25519_dalek::Verifier;
        let mut signature_bytes = [0u8; 64];
        signature_bytes.copy_from_slice(&added_witness.signature);
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        keyring
            .verifying_key()
            .verify(tx_hash.as_slice(), &signature)
            .unwrap();
    }

    #[test]
    fn sign_transaction_rejects_existing_key_witnesses() {
        let keyring = CardanoKeyring::new_for_testing().unwrap();
        let unsigned = unsigned_tx_fixture(&keyring, true, false);
        let error = sign_fixture(&unsigned, &keyring).unwrap_err();
        assert!(error.to_string().contains("already contains a key witness"));
    }

    #[test]
    fn sign_transaction_rejects_invalid_cbor() {
        let keyring = CardanoKeyring::new_for_testing().unwrap();

        let err = sign_fixture(&[0xff], &keyring).unwrap_err();
        assert!(matches!(err, Error::CborDecode(_)));
    }

    #[test]
    fn sign_transaction_rejects_protocol_address_value_sink() {
        let keyring = CardanoKeyring::new_for_testing().unwrap();
        let unsigned = unsigned_tx_fixture(&keyring, false, true);

        let error = sign_fixture(&unsigned, &keyring).unwrap_err();

        assert!(error
            .to_string()
            .contains("voucher metadata output is not authorized"));
    }

    #[test]
    fn sign_transaction_rejects_excess_signer_lovelace_loss() {
        let keyring = CardanoKeyring::new_for_testing().unwrap();
        let unsigned = unsigned_tx_fixture(&keyring, false, false);
        let mut resolved = resolved_inputs(&keyring);
        resolved
            .regular
            .get_mut(&TransactionOutRef {
                transaction_id: [0u8; 32],
                output_index: 0,
            })
            .unwrap()
            .lovelace = 100_000_000;

        let error = sign_transaction(
            &unsigned,
            &keyring,
            &keyring.address(0),
            &policy(),
            &intent(&keyring),
            &resolved,
        )
        .unwrap_err();

        assert!(error.to_string().contains("removes 97000000 lovelace"));
    }

    #[test]
    fn sign_transaction_rejects_unrelated_signer_asset_loss() {
        let keyring = CardanoKeyring::new_for_testing().unwrap();
        let unsigned = unsigned_tx_fixture(&keyring, false, false);
        let mut resolved = resolved_inputs(&keyring);
        resolved
            .regular
            .get_mut(&TransactionOutRef {
                transaction_id: [0u8; 32],
                output_index: 0,
            })
            .unwrap()
            .assets
            .push(ResolvedAsset {
                policy_id: [0xaa; 28],
                asset_name: vec![0xbb],
                quantity: 42,
            });

        let error = sign_transaction(
            &unsigned,
            &keyring,
            &keyring.address(0),
            &policy(),
            &intent(&keyring),
            &resolved,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unauthorized signer asset"));
    }

    #[test]
    fn sign_transaction_rejects_trailing_cbor() {
        let keyring = CardanoKeyring::new_for_testing().unwrap();
        let mut unsigned = unsigned_tx_fixture(&keyring, false, false);
        unsigned.push(0);
        let error = sign_fixture(&unsigned, &keyring).unwrap_err();
        assert!(error.to_string().contains("trailing CBOR data"));
    }
}
