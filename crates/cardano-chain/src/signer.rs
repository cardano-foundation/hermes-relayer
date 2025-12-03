//! Cardano transaction signing using Pallas

use crate::error::Error;
use crate::keyring::CardanoKeyring;
use blake2::{Blake2b256, Digest};
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

    let mut hasher = Blake2b256::new();
    hasher.update(&tx_body_cbor);
    let tx_hash = hasher.finalize();

    // 3. Sign the transaction hash
    let signature = keyring.sign(&tx_hash);

    // 4. Create VKeyWitness
    let vkey = keyring.verifying_key().as_bytes().to_vec();
    let sig = signature.to_bytes().to_vec();

    let vkey_witness = VKeyWitness {
        vkey: vkey.into(),
        signature: sig.into(),
    };

    // 5. Add witness to witness set
    let mut witness_set = tx.transaction_witness_set.clone();
    
    if witness_set.vkeywitness.is_none() {
        witness_set.vkeywitness = Some(vec![]);
    }
    
    if let Some(ref mut vkeys) = witness_set.vkeywitness {
        vkeys.push(vkey_witness);
    }

    // 6. Update the transaction with new witness set
    tx.transaction_witness_set = witness_set;

    // 7. Re-encode the signed transaction
    let signed_tx_cbor = minicbor::to_vec(&tx)
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

