use std::path::PathBuf;

use hdpath::StandardHDPath;

use crate::keyring::{errors::Error, KeyStore, SigningKeyPair, Test};

use super::signing_key_pair::{StellarKeyFile, StellarSigningKeyPair};

pub struct StellarKeyRing {
    inner: Test,
}

impl StellarKeyRing {
    pub fn new(store: PathBuf) -> Self {
        Self {
            inner: Test::new("stellar".to_owned(), store),
        }
    }

    pub fn get_key(&self, key_name: &str) -> Result<StellarSigningKeyPair, Error> {
        self.inner.get_key(key_name)
    }

    pub fn add_key(&mut self, key_name: &str, key_pair: StellarSigningKeyPair) -> Result<(), Error> {
        self.inner.add_key(key_name, key_pair)
    }

    pub fn add_key_from_file(
        &mut self,
        key_name: &str,
        file_contents: &str,
        hd_path: &StandardHDPath,
    ) -> Result<StellarSigningKeyPair, Error> {
        let key_file: StellarKeyFile =
            serde_json::from_str(file_contents).map_err(Error::encode)?;
        let key_pair = StellarSigningKeyPair::from_key_file(key_file, hd_path)?;
        self.inner.add_key(key_name, key_pair.clone())?;
        Ok(key_pair)
    }

    pub fn remove_key(&mut self, key_name: &str) -> Result<(), Error> {
        <Test as KeyStore<StellarSigningKeyPair>>::remove_key(&mut self.inner, key_name)
    }

    pub fn keys(&self) -> Result<Vec<(String, StellarSigningKeyPair)>, Error> {
        self.inner.keys()
    }
}
