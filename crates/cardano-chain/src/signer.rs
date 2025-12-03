//! Cardano transaction signing using Pallas

use crate::error::Error;
use crate::keyring::CardanoKeyring;
use blake2::digest::Digest;
use blake2::Blake2b512;
use pallas_codec::minicbor;
use pallas_primitives::babbage::{MintedTx, VKeyWitness};

/// Sign a Cardano transaction
pub fn sign_transaction(
    unsigned_tx_cbor: &[u8],
    keyring: &CardanoKeyring,
) -> Result<Vec<u8>, Error> {
    // 1. Parse the unsigned transaction
    let mut tx: MintedTx = minicbor::decode(unsigned_tx_cbor)
        .map_err(|e| Error::CborDecode(format!("Failed to decode transaction: {:?}", e)))?;

    // 2. Extract and hash the transaction body
    let tx_body_cbor = minicbor::to_vec(&tx.transaction_body)
        .map_err(|e| Error::Signer(format!("Failed to encode transaction body: {:?}", e)))?;

    // Cardano uses Blake2b-256 for transaction hashing
    let mut hasher = Blake2b512::new();
    hasher.update(&tx_body_cbor);
    let hash_output = hasher.finalize();
    let tx_hash = &hash_output[..32]; // Take first 32 bytes for Blake2b-256

    // 3. Sign the transaction hash
    let signature = keyring.sign(&tx_hash);

    // 4. Create VKeyWitness
    let vkey = keyring.verifying_key().as_bytes().to_vec();
    let sig = signature.to_bytes().to_vec();

    let vkey_witness = VKeyWitness {
        vkey: vkey.into(),
        signature: sig.into(),
    };

    // 5. Reconstruct the transaction with the new witness
    // We need to work around Pallas's KeepRaw immutability by reconstructing the entire tx
    let mut new_vkeywitnesses = tx.transaction_witness_set.vkeywitness.clone().unwrap_or_default().to_vec();
    new_vkeywitnesses.push(vkey_witness);
    
    // Create a new witness set with the added signature
    let new_witness_set = pallas_primitives::babbage::MintedWitnessSet {
        vkeywitness: Some(new_vkeywitnesses.into()),
        native_script: tx.transaction_witness_set.native_script.clone(),
        bootstrap_witness: tx.transaction_witness_set.bootstrap_witness.clone(),
        plutus_v1_script: tx.transaction_witness_set.plutus_v1_script.clone(),
        plutus_data: tx.transaction_witness_set.plutus_data.clone(),
        redeemer: tx.transaction_witness_set.redeemer.clone(),
        plutus_v2_script: tx.transaction_witness_set.plutus_v2_script.clone(),
    };
    
    // Create new transaction with updated witness set
    let signed_tx = pallas_primitives::babbage::MintedTx {
        transaction_body: tx.transaction_body.clone(),
        transaction_witness_set: new_witness_set,
        success: tx.success,
        auxiliary_data: tx.auxiliary_data.clone(),
    };

    // 6. Encode the signed transaction
    let signed_tx_cbor = minicbor::to_vec(&signed_tx)
        .map_err(|e| Error::Signer(format!("Failed to encode signed transaction: {:?}", e)))?;

    Ok(signed_tx_cbor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_signing_structure() {
        // This test verifies the signing workflow structure
        // Actual transaction signing requires valid CBOR from Gateway
        
        let keyring = CardanoKeyring::new_for_testing().unwrap();
        
        // Test that we can create a signature
        let test_message = b"test transaction hash";
        let signature = keyring.sign(test_message);
        
        assert_eq!(signature.to_bytes().len(), 64); // Ed25519 signature is 64 bytes
    }

    #[test]
    fn test_keyring_signing() {
        let keyring = CardanoKeyring::new_for_testing().unwrap();
        let message = b"test message";
        
        let signature = keyring.sign(message);
        
        // Verify signature format
        assert_eq!(signature.to_bytes().len(), 64);
        
        // Verify the public key is valid
        let vkey = keyring.verifying_key();
        assert_eq!(vkey.as_bytes().len(), 32);
    }
}

