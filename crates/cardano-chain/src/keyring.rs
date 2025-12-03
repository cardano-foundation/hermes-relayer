//! Cardano keyring implementation with CIP-1852 derivation

use crate::error::Error;
use blake2::{Blake2b512, Digest as Blake2Digest};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};
use slip10::BIP32Path;
use std::str::FromStr;

/// Cardano keyring for signing transactions
#[derive(Clone, Debug)]
pub struct CardanoKeyring {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    account: u32,
}

impl CardanoKeyring {
    /// Create a new keyring from a mnemonic phrase
    /// Uses CIP-1852 derivation: m/1852'/1815'/account'/2'/0'
    pub fn from_mnemonic(mnemonic: &str, account: u32) -> Result<Self, Error> {
        // Parse mnemonic
        let mnemonic = tiny_bip39::Mnemonic::from_phrase(mnemonic, tiny_bip39::Language::English)
            .map_err(|e| Error::Keyring(format!("Invalid mnemonic: {:?}", e)))?;

        // Generate seed
        let seed = tiny_bip39::Seed::new(&mnemonic, "");
        let seed_bytes = seed.as_bytes();

        // CIP-1852 path: m/1852'/1815'/account'/2'/0'
        // 1852' = purpose (CIP-1852), 1815' = coin type (Cardano), 2' = payment key role
        let path = BIP32Path::from_str(&format!("m/1852'/1815'/{}'/2'/0'", account))
            .map_err(|e| Error::Keyring(format!("Invalid derivation path: {:?}", e)))?;

        // Derive key using SLIP-0010 Ed25519
        let derived_key = slip10::derive_key_from_path(seed_bytes, slip10::Curve::Ed25519, &path)
            .map_err(|e| Error::Keyring(format!("Key derivation failed: {:?}", e)))?;

        // Create Ed25519 signing key
        let signing_key = SigningKey::from_bytes(&derived_key.key);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
            account,
        })
    }

    /// Get the public key (verifying key)
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Get the Cardano payment address (enterprise address for simplicity)
    /// Enterprise address = 0x61 | Blake2b-224(verifying_key)
    pub fn address(&self, network_id: u8) -> String {
        let vkey_bytes = self.verifying_key.as_bytes();
        
        // Hash the public key with Blake2b-224 (28 bytes)
        let mut hasher = Blake2b512::new();
        hasher.update(vkey_bytes);
        let hash = hasher.finalize();
        let payment_hash = &hash[..28];
        
        // Construct enterprise address: header | payment_hash
        // Header = 0x61 for enterprise address on testnet (0b0110_0001)
        // Header = 0x71 for enterprise address on mainnet (0b0111_0001)
        let header = if network_id == 1 { 0x71 } else { 0x61 };
        
        let mut address_bytes = vec![header];
        address_bytes.extend_from_slice(payment_hash);
        
        // Encode as hex
        hex::encode(address_bytes)
    }

    /// Create a test keyring with deterministic keys
    pub fn new_for_testing() -> Result<Self, Error> {
        // Standard test mnemonic (DO NOT USE IN PRODUCTION)
        let mnemonic = "test walk nut penalty hip pave soap entry language right filter choice";
        Self::from_mnemonic(mnemonic, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_derivation() {
        let mnemonic = "test walk nut penalty hip pave soap entry language right filter choice";
        let keyring = CardanoKeyring::from_mnemonic(mnemonic, 0).unwrap();
        
        // Should generate consistent keys
        let address = keyring.address(0);
        assert!(!address.is_empty());
        assert!(address.starts_with("61")); // Enterprise testnet address
    }

    #[test]
    fn test_signing() {
        let keyring = CardanoKeyring::new_for_testing().unwrap();
        let message = b"test message";
        
        let signature = keyring.sign(message);
        
        // Verify the signature
        use ed25519_dalek::Verifier;
        assert!(keyring.verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_different_accounts() {
        let mnemonic = "test walk nut penalty hip pave soap entry language right filter choice";
        let keyring1 = CardanoKeyring::from_mnemonic(mnemonic, 0).unwrap();
        let keyring2 = CardanoKeyring::from_mnemonic(mnemonic, 1).unwrap();
        
        // Different accounts should produce different addresses
        assert_ne!(keyring1.address(0), keyring2.address(0));
    }
}

