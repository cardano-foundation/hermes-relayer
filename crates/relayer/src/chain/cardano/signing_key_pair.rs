//! Cardano SigningKeyPair implementation for Hermes keyring

use super::keyring::CardanoKeyring;
use crate::config::AddressType;
use crate::keyring::{errors::Error as KeyringError, KeyType, SigningKeyPair};
use hdpath::StandardHDPath;
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
    #[serde(default)]
    pub network_id: Option<u8>,
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
    /// Supports both mnemonic phrases and bech32-encoded private keys (ed25519_sk...)
    ///
    /// Mnemonic derivation uses Hermes' Cardano-shaped SLIP-0010 Ed25519 path, not
    /// Cardano wallet Ed25519-BIP32. Operators importing wallet mnemonics should verify
    /// the derived address before funding or relaying.
    pub fn new(
        mnemonic_or_key: String,
        account: u32,
        network_id: u8,
    ) -> Result<Self, KeyringError> {
        // Check if this is a bech32 private key instead of a mnemonic
        let keyring = if mnemonic_or_key.starts_with("ed25519_sk") {
            CardanoKeyring::from_bech32_key(&mnemonic_or_key).map_err(|_| {
                KeyringError::invalid_mnemonic(anyhow::anyhow!(
                    "Failed to load Cardano key from bech32"
                ))
            })?
        } else {
            CardanoKeyring::from_mnemonic(&mnemonic_or_key, account).map_err(|_| {
                KeyringError::invalid_mnemonic(anyhow::anyhow!(
                    "Failed to derive Cardano key from mnemonic"
                ))
            })?
        };

        Ok(Self {
            keyring: Some(keyring),
            mnemonic: mnemonic_or_key,
            account,
            network_id,
        })
    }

    pub fn from_key_file_with_network_id(
        key_file: CardanoKeyFile,
        hd_path: &StandardHDPath,
        network_id: u8,
    ) -> Result<Self, KeyringError> {
        let account = hd_path.account();
        Self::new(key_file.mnemonic, account, network_id)
    }

    pub fn from_seed_file_with_network_id(
        contents: &str,
        hd_path: &StandardHDPath,
        network_id: u8,
    ) -> Result<Self, KeyringError> {
        let key_file = serde_json::from_str(contents).map_err(KeyringError::encode)?;
        Self::from_key_file_with_network_id(key_file, hd_path, network_id)
    }

    pub fn from_mnemonic_with_network_id(
        mnemonic: &str,
        hd_path: &StandardHDPath,
        network_id: u8,
    ) -> Result<Self, KeyringError> {
        let account = hd_path.account();
        Self::new(mnemonic.to_string(), account, network_id)
    }

    pub fn network_id(&self) -> u8 {
        self.network_id
    }

    /// Ensure the keyring is initialized (for after deserialization)
    fn ensure_keyring(&mut self) -> Result<(), KeyringError> {
        if self.keyring.is_none() {
            let keyring = if self.mnemonic.starts_with("ed25519_sk") {
                CardanoKeyring::from_bech32_key(&self.mnemonic).map_err(|_| {
                    KeyringError::invalid_mnemonic(anyhow::anyhow!(
                        "Failed to reinitialize keyring from bech32"
                    ))
                })?
            } else {
                CardanoKeyring::from_mnemonic(&self.mnemonic, self.account).map_err(|_| {
                    KeyringError::invalid_mnemonic(anyhow::anyhow!(
                        "Failed to reinitialize keyring from mnemonic"
                    ))
                })?
            };
            self.keyring = Some(keyring);
        }
        Ok(())
    }

    /// Get a reference to the keyring, initializing if needed
    fn keyring(&mut self) -> Result<&CardanoKeyring, KeyringError> {
        self.ensure_keyring()?;
        self.keyring
            .as_ref()
            .ok_or_else(KeyringError::key_not_found)
    }

    /// Get a mutable reference to the keyring, initializing if needed
    fn keyring_mut(&mut self) -> Result<&mut CardanoKeyring, KeyringError> {
        self.ensure_keyring()?;
        self.keyring
            .as_mut()
            .ok_or_else(KeyringError::key_not_found)
    }

    /// Get a clone of the CardanoKeyring (public method for external signing)
    /// This clones self internally to handle lazy initialization
    pub fn get_cardano_keyring(&self) -> Result<CardanoKeyring, KeyringError> {
        let mut mutable_self = self.clone();
        mutable_self.ensure_keyring()?;
        mutable_self.keyring.ok_or_else(KeyringError::key_not_found)
    }
}

impl SigningKeyPair for CardanoSigningKeyPair {
    const KEY_TYPE: KeyType = KeyType::Ed25519;
    type KeyFile = CardanoKeyFile;

    fn from_key_file(
        key_file: Self::KeyFile,
        hd_path: &StandardHDPath,
    ) -> Result<Self, KeyringError>
    where
        Self: Sized,
    {
        let network_id = key_file
            .network_id
            .or_else(|| network_id_from_hex_enterprise_address(&key_file.address))
            .ok_or_else(|| {
                KeyringError::invalid_mnemonic(anyhow::anyhow!(
                    "Cardano key files must include network_id or a hex enterprise address; \
                     use the Cardano chain configuration when importing keys"
                ))
            })?;

        Self::from_key_file_with_network_id(key_file, hd_path, network_id)
    }

    fn from_mnemonic(
        _mnemonic: &str,
        _hd_path: &StandardHDPath,
        _address_type: &AddressType,
        _account_prefix: &str,
    ) -> Result<Self, KeyringError>
    where
        Self: Sized,
    {
        Err(KeyringError::invalid_mnemonic(anyhow::anyhow!(
            "Cardano mnemonic restore requires an explicit network_id from the chain \
             configuration; use CardanoSigningKeyPair::from_mnemonic_with_network_id"
        )))
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

fn network_id_from_hex_enterprise_address(address: &str) -> Option<u8> {
    let header = *hex::decode(address).ok()?.first()?;
    (header >> 4 == 0x06).then_some(header & 0x0f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const TEST_MNEMONIC: &str =
        "test walk nut penalty hip pave soap entry language right filter choice";

    #[test]
    fn test_cardano_signing_key_pair_creation() {
        let key_pair = CardanoSigningKeyPair::new(TEST_MNEMONIC.to_string(), 0, 0).unwrap();

        let account = key_pair.account();
        assert!(!account.is_empty());
        assert!(account.starts_with("60")); // Cardano enterprise testnet address
    }

    #[test]
    fn test_cardano_signing_key_pair_creation_mainnet() {
        let key_pair = CardanoSigningKeyPair::new(TEST_MNEMONIC.to_string(), 0, 1).unwrap();

        let account = key_pair.account();
        assert!(!account.is_empty());
        assert_eq!(key_pair.network_id(), 1);
        assert!(account.starts_with("61")); // Cardano enterprise mainnet address
    }

    #[test]
    fn test_cardano_from_mnemonic_with_network_id() {
        let hd_path = StandardHDPath::from_str("m/44'/118'/0'/0/0").unwrap();
        let key_pair =
            CardanoSigningKeyPair::from_mnemonic_with_network_id(TEST_MNEMONIC, &hd_path, 1)
                .unwrap();

        assert_eq!(key_pair.network_id(), 1);
        assert!(key_pair.account().starts_with("61"));
    }

    #[test]
    fn test_cardano_generic_from_mnemonic_requires_explicit_network_id() {
        let hd_path = StandardHDPath::from_str("m/44'/118'/0'/0/0").unwrap();

        let err = CardanoSigningKeyPair::from_mnemonic(
            TEST_MNEMONIC,
            &hd_path,
            &AddressType::Cosmos,
            "cardano",
        )
        .unwrap_err();

        assert!(err.to_string().contains("requires an explicit network_id"));
    }

    #[test]
    fn test_cardano_from_seed_file_with_network_id() {
        let hd_path = StandardHDPath::from_str("m/44'/118'/0'/0/0").unwrap();
        let key_file = r#"{
            "name": "test",
            "type": "local",
            "address": "",
            "pubkey": "",
            "mnemonic": "test walk nut penalty hip pave soap entry language right filter choice"
        }"#;

        let key_pair =
            CardanoSigningKeyPair::from_seed_file_with_network_id(key_file, &hd_path, 1).unwrap();

        assert_eq!(key_pair.network_id(), 1);
        assert!(key_pair.account().starts_with("61"));
    }

    #[test]
    fn test_cardano_from_key_file_uses_network_id_when_present() {
        let hd_path = StandardHDPath::from_str("m/44'/118'/0'/0/0").unwrap();
        let key_file = CardanoKeyFile {
            name: "test".to_string(),
            r#type: "local".to_string(),
            address: String::new(),
            pubkey: String::new(),
            mnemonic: TEST_MNEMONIC.to_string(),
            network_id: Some(1),
        };

        let key_pair = CardanoSigningKeyPair::from_key_file(key_file, &hd_path).unwrap();

        assert_eq!(key_pair.network_id(), 1);
        assert!(key_pair.account().starts_with("61"));
    }

    #[test]
    fn test_cardano_from_key_file_requires_network_id_or_address() {
        let hd_path = StandardHDPath::from_str("m/44'/118'/0'/0/0").unwrap();
        let key_file = CardanoKeyFile {
            name: "test".to_string(),
            r#type: "local".to_string(),
            address: String::new(),
            pubkey: String::new(),
            mnemonic: TEST_MNEMONIC.to_string(),
            network_id: None,
        };

        let err = CardanoSigningKeyPair::from_key_file(key_file, &hd_path).unwrap_err();

        assert!(err.to_string().contains("must include network_id"));
    }

    #[test]
    fn test_cardano_from_key_file_infers_network_id_from_enterprise_address() {
        let hd_path = StandardHDPath::from_str("m/44'/118'/0'/0/0").unwrap();
        let address = CardanoSigningKeyPair::new(TEST_MNEMONIC.to_string(), 0, 1)
            .unwrap()
            .account();
        let key_file = CardanoKeyFile {
            name: "test".to_string(),
            r#type: "local".to_string(),
            address,
            pubkey: String::new(),
            mnemonic: TEST_MNEMONIC.to_string(),
            network_id: None,
        };

        let key_pair = CardanoSigningKeyPair::from_key_file(key_file, &hd_path).unwrap();

        assert_eq!(key_pair.network_id(), 1);
    }

    #[test]
    fn test_cardano_signing() {
        let key_pair = CardanoSigningKeyPair::new(TEST_MNEMONIC.to_string(), 0, 0).unwrap();

        let message = b"test message";
        let signature = key_pair.sign(message).unwrap();

        assert_eq!(signature.len(), 64); // Ed25519 signature is 64 bytes
    }

    #[test]
    fn test_serialization_roundtrip() {
        let key_pair = CardanoSigningKeyPair::new(TEST_MNEMONIC.to_string(), 0, 0).unwrap();

        // Serialize
        let json = serde_json::to_string(&key_pair).unwrap();

        // Deserialize
        let deserialized: CardanoSigningKeyPair = serde_json::from_str(&json).unwrap();

        // Test that it still works
        let message = b"test";
        let signature = deserialized.sign(message).unwrap();
        assert_eq!(signature.len(), 64);
    }
}
