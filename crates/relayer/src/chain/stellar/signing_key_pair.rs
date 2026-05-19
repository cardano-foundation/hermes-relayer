use core::any::Any;

use bip39::{Language, Mnemonic, Seed};
use ed25519_dalek::SigningKey;
use ed25519_dalek_bip32::{ChildIndex, DerivationPath, ExtendedSigningKey};
use hdpath::StandardHDPath;
use serde::{Deserialize, Serialize};
use signature::Signer;
use stellar_strkey::ed25519::{PrivateKey as StrKeySecret, PublicKey as StrKeyPublic};

use super::error::StellarError;
use crate::config::AddressType;
use crate::keyring::{errors::Error as KeyringError, KeyType, SigningKeyPair};

#[derive(Deserialize)]
pub struct StellarKeyFile {
    pub secret_key: Option<String>,
    pub mnemonic: Option<String>,
}

fn sep0005_path(account: u32) -> DerivationPath {
    DerivationPath::new(vec![
        ChildIndex::hardened(44).expect("44 is valid"),
        ChildIndex::hardened(148).expect("148 is valid"),
        ChildIndex::hardened(account).expect("account is valid"),
    ])
}

fn key_from_mnemonic(words: &str, account: u32) -> Result<SigningKey, KeyringError> {
    let mnemonic =
        Mnemonic::from_phrase(words, Language::English).map_err(KeyringError::invalid_mnemonic)?;

    let seed = Seed::new(&mnemonic, "");

    let master = ExtendedSigningKey::from_seed(seed.as_bytes()).map_err(|e| {
        KeyringError::bip32_key_generation_failed(StellarSigningKeyPair::KEY_TYPE, e.into())
    })?;

    let child = master.derive(&sep0005_path(account)).map_err(|e| {
        KeyringError::bip32_key_generation_failed(StellarSigningKeyPair::KEY_TYPE, e.into())
    })?;

    Ok(child.signing_key)
}

fn stellar_to_keyring(e: StellarError) -> KeyringError {
    KeyringError::bip32_key_generation_failed(
        StellarSigningKeyPair::KEY_TYPE,
        anyhow::anyhow!("{}", e),
    )
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StellarSigningKeyPair {
    signing_key: SigningKey,
}

impl StellarSigningKeyPair {
    pub fn account_id(&self) -> String {
        format!("{}", StrKeyPublic(*self.signing_key.verifying_key().as_bytes()))
    }

    pub fn secret_key_strkey(&self) -> String {
        format!("{}", StrKeySecret(self.signing_key.to_bytes()))
    }

    pub fn key_hint(&self) -> [u8; 4] {
        let bytes = self.signing_key.verifying_key().to_bytes();
        bytes[28..].try_into().expect("slice is 4 bytes")
    }

    pub fn from_strkey(strkey: &str) -> Result<Self, StellarError> {
        let StrKeySecret(raw) = strkey
            .parse::<StrKeySecret>()
            .map_err(|_| StellarError::InvalidStrKey(strkey.to_owned()))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&raw),
        })
    }
}

impl SigningKeyPair for StellarSigningKeyPair {
    const KEY_TYPE: KeyType = KeyType::Ed25519;
    type KeyFile = StellarKeyFile;

    fn from_key_file(key_file: StellarKeyFile, hd_path: &StandardHDPath) -> Result<Self, KeyringError> {
        if let Some(strkey) = key_file.secret_key {
            return Self::from_strkey(&strkey).map_err(stellar_to_keyring);
        }
        if let Some(mnemonic) = key_file.mnemonic {
            let signing_key = key_from_mnemonic(&mnemonic, hd_path.account())?;
            return Ok(Self { signing_key });
        }
        Err(stellar_to_keyring(StellarError::InvalidStrKey(
            "key file must contain 'secret_key' or 'mnemonic'".to_owned(),
        )))
    }

    fn from_mnemonic(
        mnemonic: &str,
        hd_path: &StandardHDPath,
        _address_type: &AddressType,
        _account_prefix: &str,
    ) -> Result<Self, KeyringError> {
        let signing_key = key_from_mnemonic(mnemonic, hd_path.account())?;
        Ok(Self { signing_key })
    }

    fn account(&self) -> String {
        self.account_id()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyringError> {
        Ok(self.signing_key.sign(message).to_bytes().to_vec())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    const EXPECTED_SECRET: &str = "SBGWSG6BTNCKCOB3DIFPQJAIYMIQF7DMHP7N46WQZR5UHKJCXIPRLHFG";
    const EXPECTED_ACCOUNT: &str = "GDAHPZ2NSYIIHZXM56Y36SBVTV5QKFIZGYMEGSFDN6CEI7BESNOIMR5M";

    #[test]
    fn strkey_round_trip() {
        let kp = StellarSigningKeyPair::from_strkey(EXPECTED_SECRET).unwrap();
        assert_eq!(kp.secret_key_strkey(), EXPECTED_SECRET);
        assert_eq!(kp.account_id(), EXPECTED_ACCOUNT);
    }

    #[test]
    fn sep0005_derivation_matches_known_vector() {
        let signing_key = key_from_mnemonic(MNEMONIC, 0).unwrap();
        let kp = StellarSigningKeyPair { signing_key };
        assert_eq!(kp.secret_key_strkey(), EXPECTED_SECRET);
        assert_eq!(kp.account_id(), EXPECTED_ACCOUNT);
    }

    #[test]
    fn invalid_strkey_is_rejected() {
        assert!(StellarSigningKeyPair::from_strkey("not-a-key").is_err());
        assert!(StellarSigningKeyPair::from_strkey(EXPECTED_ACCOUNT).is_err());
    }

    #[test]
    fn sign_produces_64_bytes() {
        let kp = StellarSigningKeyPair::from_strkey(EXPECTED_SECRET).unwrap();
        let sig = kp.sign(b"hello stellar").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn key_hint_is_last_4_bytes_of_pubkey() {
        let kp = StellarSigningKeyPair::from_strkey(EXPECTED_SECRET).unwrap();
        let pubkey_bytes = kp.signing_key.verifying_key().to_bytes();
        let expected: [u8; 4] = pubkey_bytes[28..].try_into().unwrap();
        assert_eq!(kp.key_hint(), expected);
    }
}
