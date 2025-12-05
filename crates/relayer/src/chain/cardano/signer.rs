//! Cardano transaction signing using Pallas

use super::error::Error;
use super::keyring::CardanoKeyring;
use blake2::digest::Digest;
use blake2::Blake2b512;
use pallas_codec::minicbor;
use pallas_codec::utils::KeepRaw;
use pallas_primitives::babbage::{MintedTx, VKeyWitness};

/// Sign a Cardano transaction
pub fn sign_transaction(
    unsigned_tx_cbor: &[u8],
    keyring: &CardanoKeyring,
) -> Result<Vec<u8>, Error> {
    // 1. Parse the unsigned transaction
    let tx: MintedTx<'_> = minicbor::decode(unsigned_tx_cbor)
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
    // We need to work around Pallas's KeepRaw immutability by manually building CBOR
    
    // Get existing witnesses
    let mut new_vkeywitnesses = tx.transaction_witness_set.vkeywitness.clone().unwrap_or_default().to_vec();
    new_vkeywitnesses.push(vkey_witness);
    
    // Encode the new witness set manually
    let mut witness_set_cbor = Vec::new();
    {
        let mut encoder = minicbor::Encoder::new(&mut witness_set_cbor);
        
        // Witness set is a CBOR map
        encoder.map(7).map_err(|e| Error::Signer(format!("Failed to encode witness map: {:?}", e)))?;
        
        // Key 0: vkeywitness array
        encoder.u8(0).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
        encoder.array(new_vkeywitnesses.len() as u64).map_err(|e| Error::Signer(format!("Failed to encode array: {:?}", e)))?;
        for witness in &new_vkeywitnesses {
            encoder.encode(witness).map_err(|e| Error::Signer(format!("Failed to encode witness: {:?}", e)))?;
        }
        
        // Copy other witness set fields if present
        if let Some(ref native_scripts) = tx.transaction_witness_set.native_script {
            encoder.u8(1).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(native_scripts).map_err(|e| Error::Signer(format!("Failed to encode native scripts: {:?}", e)))?;
        }
        
        if let Some(ref bootstrap) = tx.transaction_witness_set.bootstrap_witness {
            encoder.u8(2).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(bootstrap).map_err(|e| Error::Signer(format!("Failed to encode bootstrap: {:?}", e)))?;
        }
        
        if let Some(ref plutus_v1) = tx.transaction_witness_set.plutus_v1_script {
            encoder.u8(3).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(plutus_v1).map_err(|e| Error::Signer(format!("Failed to encode plutus v1: {:?}", e)))?;
        }
        
        if let Some(ref plutus_data) = tx.transaction_witness_set.plutus_data {
            encoder.u8(4).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(plutus_data).map_err(|e| Error::Signer(format!("Failed to encode plutus data: {:?}", e)))?;
        }
        
        if let Some(ref redeemers) = tx.transaction_witness_set.redeemer {
            encoder.u8(5).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(redeemers).map_err(|e| Error::Signer(format!("Failed to encode redeemers: {:?}", e)))?;
        }
        
        if let Some(ref plutus_v2) = tx.transaction_witness_set.plutus_v2_script {
            encoder.u8(6).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(plutus_v2).map_err(|e| Error::Signer(format!("Failed to encode plutus v2: {:?}", e)))?;
        }
    }
    
    // Build the final signed transaction CBOR
    // Transaction is an array: [transaction_body, transaction_witness_set, success, auxiliary_data?]
    let mut signed_tx_cbor = Vec::new();
    {
        let mut encoder = minicbor::Encoder::new(&mut signed_tx_cbor);
        
        // Check if auxiliary data is present using Nullable
        let has_aux_data = matches!(tx.auxiliary_data, pallas_codec::utils::Nullable::Some(_));
        encoder.array(if has_aux_data { 4 } else { 3 })
            .map_err(|e| Error::Signer(format!("Failed to encode tx array: {:?}", e)))?;
        
        // Encode transaction body (already have the CBOR from earlier)
        encoder.encode(&tx.transaction_body)
            .map_err(|e| Error::Signer(format!("Failed to encode tx body: {:?}", e)))?;
        
        // Encode the witness set we just built (as raw bytes)
        encoder.bytes(&witness_set_cbor)
            .map_err(|e| Error::Signer(format!("Failed to encode witness set: {:?}", e)))?;
        
        // Encode success flag
        encoder.bool(tx.success)
            .map_err(|e| Error::Signer(format!("Failed to encode success: {:?}", e)))?;
        
        // Encode auxiliary data if present
        if let pallas_codec::utils::Nullable::Some(ref aux_data) = tx.auxiliary_data {
            encoder.encode(aux_data)
                .map_err(|e| Error::Signer(format!("Failed to encode aux data: {:?}", e)))?;
        }
    }

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

