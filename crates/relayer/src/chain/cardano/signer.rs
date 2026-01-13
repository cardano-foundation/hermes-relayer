//! Cardano transaction signing using Pallas

use super::error::Error;
use super::keyring::CardanoKeyring;
use blake2::Digest;
use pallas_codec::minicbor;
use pallas_primitives::conway::{MintedTx, VKeyWitness};

/// Sign a Cardano transaction
pub fn sign_transaction(
    unsigned_tx_cbor: &[u8],
    keyring: &CardanoKeyring,
) -> Result<Vec<u8>, Error> {
    // 1. Parse the unsigned transaction
    let tx: MintedTx<'_> = minicbor::decode(unsigned_tx_cbor)
        .map_err(|e| Error::CborDecode(format!("Failed to decode transaction: {:?}", e)))?;

    // 2. Extract and hash the transaction body
    // Use the original raw bytes preserved by KeepRaw, not re-encoded bytes
    let tx_body_cbor = tx.transaction_body.raw_cbor();

    // Cardano uses Blake2b-256 for transaction hashing
    use blake2::Blake2b;
    use blake2::digest::consts::U32;
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(tx_body_cbor);
    let tx_hash = hasher.finalize();

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
    let mut new_vkeywitnesses: Vec<VKeyWitness> = tx.transaction_witness_set.vkeywitness
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
        if ws.native_script.is_some() { map_size += 1; }
        if ws.bootstrap_witness.is_some() { map_size += 1; }
        if ws.plutus_v1_script.is_some() { map_size += 1; }
        if ws.plutus_data.is_some() { map_size += 1; }
        if ws.redeemer.is_some() { map_size += 1; }
        if ws.plutus_v2_script.is_some() { map_size += 1; }
        if ws.plutus_v3_script.is_some() { map_size += 1; }
        
        // Witness set is a CBOR map
        encoder.map(map_size).map_err(|e| Error::Signer(format!("Failed to encode witness map: {:?}", e)))?;
        
        // Key 0: vkeywitness array
        encoder.u8(0).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
        encoder.array(new_vkeywitnesses.len() as u64).map_err(|e| Error::Signer(format!("Failed to encode array: {:?}", e)))?;
        for witness in &new_vkeywitnesses {
            encoder.encode(witness).map_err(|e| Error::Signer(format!("Failed to encode witness: {:?}", e)))?;
        }
        
        // Copy other witness set fields if present
        if let Some(ref native_scripts) = ws.native_script {
            encoder.u8(1).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(native_scripts).map_err(|e| Error::Signer(format!("Failed to encode native scripts: {:?}", e)))?;
        }
        
        if let Some(ref bootstrap) = ws.bootstrap_witness {
            encoder.u8(2).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(bootstrap).map_err(|e| Error::Signer(format!("Failed to encode bootstrap: {:?}", e)))?;
        }
        
        if let Some(ref plutus_v1) = ws.plutus_v1_script {
            encoder.u8(3).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(plutus_v1).map_err(|e| Error::Signer(format!("Failed to encode plutus v1: {:?}", e)))?;
        }
        
        if let Some(ref plutus_data) = ws.plutus_data {
            encoder.u8(4).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(plutus_data).map_err(|e| Error::Signer(format!("Failed to encode plutus data: {:?}", e)))?;
        }
        
        if let Some(ref redeemers) = ws.redeemer {
            encoder.u8(5).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(redeemers).map_err(|e| Error::Signer(format!("Failed to encode redeemers: {:?}", e)))?;
        }
        
        if let Some(ref plutus_v2) = ws.plutus_v2_script {
            encoder.u8(6).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(plutus_v2).map_err(|e| Error::Signer(format!("Failed to encode plutus v2: {:?}", e)))?;
        }
        
        if let Some(ref plutus_v3) = ws.plutus_v3_script {
            encoder.u8(7).map_err(|e| Error::Signer(format!("Failed to encode key: {:?}", e)))?;
            encoder.encode(plutus_v3).map_err(|e| Error::Signer(format!("Failed to encode plutus v3: {:?}", e)))?;
        }
    }
    
    // Build the final signed transaction CBOR
    // Conway transaction is an array: [transaction_body, transaction_witness_set, is_valid, auxiliary_data]
    // where auxiliary_data can be null
    let mut signed_tx_cbor = Vec::new();
    {
        let mut encoder = minicbor::Encoder::new(&mut signed_tx_cbor);
        
        // Conway transactions always have 4 elements
        encoder.array(4)
            .map_err(|e| Error::Signer(format!("Failed to encode tx array: {:?}", e)))?;
        
        // Encode transaction body
        encoder.encode(&tx.transaction_body)
            .map_err(|e| Error::Signer(format!("Failed to encode tx body: {:?}", e)))?;
        
        // Write the witness set CBOR directly (not as a byte string wrapper)
        use std::io::Write;
        encoder.writer_mut().write_all(&witness_set_cbor)
            .map_err(|e| Error::Signer(format!("Failed to write witness set: {:?}", e)))?;
        
        // Encode isValid flag
        encoder.bool(tx.success)
            .map_err(|e| Error::Signer(format!("Failed to encode success: {:?}", e)))?;
        
        // Encode auxiliary data (using Nullable encoding)
        encoder.encode(&tx.auxiliary_data)
            .map_err(|e| Error::Signer(format!("Failed to encode aux data: {:?}", e)))?;
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

