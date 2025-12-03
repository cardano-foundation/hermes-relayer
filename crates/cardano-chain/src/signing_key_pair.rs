//! Cardano SigningKeyPair implementation for Hermes keyring

use crate::error::Error as CardanoError;
use crate::keyring::CardanoKeyring;
use hdpath::StandardHDPath;
use ibc_relayer::config::AddressType;
use ibc_relayer::keyring::{errors::Error as KeyringError, KeyType, SigningKeyPair};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Keyfile format for Cardano keys
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CardanoKeyFile {
    pub name: String,
    pub r#type: String,
    pub address: String,
    pub pubkey: String,
    pub mnemonic: String,
}

/// Cardano signing key pair wrapper for Hermes
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CardanoSigningKeyPair {
    #[serde(skip)]
    keyring: Option<CardanoKeyring>,
    // Store serializable data
    mnemonic: String,
    account: u32,
    network_id: u8,
}

impl CardanoSigningKeyPair {
    /// Create a new CardanoSigningKeyPair from components
    pub fn new(mnemonic: String, account: u32, network_id: u8) -> Result<Self, KeyringError> {
        let keyring = CardanoKeyring::from_mnemonic(&mnemonic, account)
            .map_err(|e| KeyringError::encode(e.to_string()))?;
        
        Ok(Self {
            keyring: Some(keyring),
            mnemonic,
            account,
            network_id,
        })
    }

    /// Ensure the keyring is initialized (for after deserialization)
    fn ensure_keyring(&mut self) -> Result<(), KeyringError> {
        if self.keyring.is_none() {
            let keyring = CardanoKeyring::from_mnemonic(&self.mnemonic, self.account)
                .map_err(|e| KeyringError::encode(e.to_string()))?;
            self.keyring = Some(keyring);
        }
        Ok(())
    }

    /// Get a reference to the keyring, initializing if needed
    fn keyring(&mut self) -> Result<&CardanoKeyring, KeyringError> {
        self.ensure_keyring()?;
        self.keyring.as_ref().ok_or_else(|| {
            KeyringError::encode("Keyring not initialized".to_string())
        })
    }

    /// Get a mutable reference to the keyring, initializing if needed
    fn keyring_mut(&mut self) -> Result<&mut CardanoKeyring, KeyringError> {
        self.ensure_keyring()?;
        self.keyring.as_mut().ok_or_else(|| {
            KeyringError::encode("Keyring not initialized".to_string())
        })
    }
}

impl SigningKeyPair for CardanoSigningKeyPair {
    const KEY_TYPE: KeyType = KeyType::Ed25519;
    type KeyFile = CardanoKeyFile;

    fn from_key_file(key_file: Self::KeyFile, hd_path: &StandardHDPath) -> Result<Self, KeyringError>
    where
        Self: Sized,
    {
        // For Cardano, we use the account from the HD path
        let account = hd_path.account();
        // Cardano testnet by default (can be overridden in config)
        let network_id = 0;

        Self::new(key_file.mnemonic, account, network_id)
    }

    fn from_mnemonic(
        mnemonic: &str,
        hd_path: &StandardHDPath,
        _address_type: &AddressType,
        _account_prefix: &str,
    ) -> Result<Self, KeyringError>
    where
        Self: Sized,
    {
        let account = hd_path.account();
        // Cardano testnet by default
        let network_id = 0;

        Self::new(mnemonic.to_string(), account, network_id)
    }

    fn account(&self) -> String {
        // Return cached address or generate it
        // Clone self to make it mutable for ensure_keyring
        let mut mutable_self = self.clone();
        match mutable_self.keyring() {
            Ok(keyring) => keyring.address(self.network_id),
            Err(_) => format!("cardano_address_error_account_{}", self.account),
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyringError> {
        let mut mutable_self = self.clone();
        let keyring = mutable_self.keyring_mut()?;
        let signature = keyring.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cardano_signing_key_pair_creation() {
        let mnemonic = "test walk nut penalty hip pave soap entry language right filter choice";
        let key_pair = CardanoSigningKeyPair::new(mnemonic.to_string(), 0, 0).unwrap();
        
        let account = key_pair.account();
        assert!(!account.is_empty());
        assert!(account.starts_with("61")); // Cardano enterprise testnet address
    }

    #[test]
    fn test_cardano_signing() {
        let mnemonic = "test walk nut penalty hip pave soap entry language right filter choice";
        let key_pair = CardanoSigningKeyPair::new(mnemonic.to_string(), 0, 0).unwrap();
        
        let message = b"test message";
        let signature = key_pair.sign(message).unwrap();
        
        assert_eq!(signature.len(), 64); // Ed25519 signature is 64 bytes
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mnemonic = "test walk nut penalty hip pave soap entry language right filter choice";
        let key_pair = CardanoSigningKeyPair::new(mnemonic.to_string(), 0, 0).unwrap();
        
        // Serialize
        let json = serde_json::to_string(&key_pair).unwrap();
        
        // Deserialize
        let mut deserialized: CardanoSigningKeyPair = serde_json::from_str(&json).unwrap();
        
        // Test that it still works
        let message = b"test";
        let signature = deserialized.sign(message).unwrap();
        assert_eq!(signature.len(), 64);
    }
}

