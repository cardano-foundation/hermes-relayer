pub mod errors;
pub use any_signing_key_pair::AnySigningKeyPair;
pub use ed25519_key_pair::Ed25519KeyPair;
pub use key_type::KeyType;
pub use secp256k1_key_pair::Secp256k1KeyPair;
pub use signing_key_pair::{SigningKeyPair, SigningKeyPairSized};

pub use crate::chain::namada::key::NamadaKeyPair;

mod any_signing_key_pair;
mod ed25519_key_pair;
mod key_type;
mod key_utils;
mod pub_key;
mod secp256k1_key_pair;
mod signing_key_pair;

use alloc::collections::btree_map::BTreeMap as HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use atomic_write_file::AtomicWriteFile;
use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use serde::{Deserialize, Serialize};

use errors::Error;

pub const KEYSTORE_DEFAULT_FOLDER: &str = ".hermes/keys/";
pub const KEYSTORE_DISK_BACKEND: &str = "keyring-test";
pub const KEYSTORE_FILE_EXTENSION: &str = "json";

fn open_private_key_file(path: &Path) -> io::Result<AtomicWriteFile> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to overwrite symlinked key file '{}'",
                    path.display()
                ),
            ));
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("key path '{}' is not a regular file", path.display()),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut options = AtomicWriteFile::options();

    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt as AtomicOpenOptionsExt;
        use std::os::unix::fs::OpenOptionsExt as StdOpenOptionsExt;

        // Never inherit permissive mode or ownership from an old key file (or
        // from a path replaced while this write is in progress).
        AtomicOpenOptionsExt::preserve_mode(&mut options, false);
        AtomicOpenOptionsExt::try_preserve_owner(&mut options, false);
        StdOpenOptionsExt::mode(&mut options, 0o600);
    }

    let file = options.open(path)?;

    // Enforce the exact mode on the temporary file before any secret is written.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    Ok(file)
}

fn ensure_private_key_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to use symlinked private key directory '{}'",
                path.display()
            ),
        ));
    }
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private key directory '{}' is not a directory",
                path.display()
            ),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

fn open_private_key_file_for_read(path: &Path) -> io::Result<File> {
    let metadata_before_open = fs::symlink_metadata(path)?;
    if metadata_before_open.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to read symlinked key file '{}'", path.display()),
        ));
    }
    if !metadata_before_open.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("key path '{}' is not a regular file", path.display()),
        ));
    }

    let file = File::open(path)?;
    #[cfg(unix)]
    let opened_metadata = file.metadata()?;
    let metadata_after_open = fs::symlink_metadata(path)?;

    if metadata_after_open.file_type().is_symlink() || !metadata_after_open.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("key file '{}' changed while it was opened", path.display()),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        // Compare the opened descriptor to the directory entry before touching or
        // decoding its contents. This closes the regular-file-to-symlink swap
        // window between the initial `symlink_metadata` call and `File::open`.
        if opened_metadata.dev() != metadata_before_open.dev()
            || opened_metadata.ino() != metadata_before_open.ino()
            || opened_metadata.dev() != metadata_after_open.dev()
            || opened_metadata.ino() != metadata_after_open.ino()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("key file '{}' changed while it was opened", path.display()),
            ));
        }

        // Older Hermes versions could leave key files readable by other users.
        // Repair those permissions through the already-verified descriptor before
        // deserializing any secret material.
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    Ok(file)
}

/// JSON key seed file
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyFile {
    name: String,
    r#type: String,
    address: String,
    pubkey: String,
    mnemonic: String,
}

pub trait KeyStore<S> {
    fn get_key(&self, key_name: &str) -> Result<S, Error>;
    fn add_key(&mut self, key_name: &str, key_entry: S) -> Result<(), Error>;
    fn remove_key(&mut self, key_name: &str) -> Result<(), Error>;
    fn keys(&self) -> Result<Vec<(String, S)>, Error>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Memory<S> {
    account_prefix: String,
    keys: HashMap<String, S>,
}

impl<S> Memory<S> {
    pub fn new(account_prefix: String) -> Self {
        Self {
            account_prefix,
            keys: HashMap::new(),
        }
    }
}

impl<S: SigningKeyPairSized> KeyStore<S> for Memory<S> {
    fn get_key(&self, key_name: &str) -> Result<S, Error> {
        self.keys
            .get(key_name)
            .cloned()
            .ok_or_else(Error::key_not_found)
    }

    fn add_key(&mut self, key_name: &str, key_entry: S) -> Result<(), Error> {
        if self.keys.contains_key(key_name) {
            Err(Error::key_already_exist())
        } else {
            self.keys.insert(key_name.to_string(), key_entry);

            Ok(())
        }
    }

    fn remove_key(&mut self, key_name: &str) -> Result<(), Error> {
        self.keys
            .remove(key_name)
            .ok_or_else(Error::key_not_found)?;

        Ok(())
    }

    fn keys(&self) -> Result<Vec<(String, S)>, Error> {
        Ok(self
            .keys
            .iter()
            .map(|(n, k)| (n.to_string(), k.clone()))
            .collect())
    }
}

// TODO: Rename this to something like `Disk`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Test {
    account_prefix: String,
    store: PathBuf,
}

impl Test {
    pub fn new(account_prefix: String, store: PathBuf) -> Self {
        Self {
            account_prefix,
            store,
        }
    }
}

impl<S: SigningKeyPairSized> KeyStore<S> for Test {
    fn get_key(&self, key_name: &str) -> Result<S, Error> {
        let mut key_file = self.store.join(key_name);
        key_file.set_extension(KEYSTORE_FILE_EXTENSION);

        ensure_private_key_directory(&self.store).map_err(|e| {
            Error::key_file_io(
                self.store.display().to_string(),
                "failed to secure keys folder before reading".to_string(),
                e,
            )
        })?;

        let file = match open_private_key_file_for_read(&key_file) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(Error::key_file_not_found(key_file.display().to_string()));
            }
            Err(e) => {
                return Err(Error::key_file_io(
                    key_file.display().to_string(),
                    "refused to open insecure key file".to_string(),
                    e,
                ));
            }
        };

        let key_entry = serde_json::from_reader(file)
            .map_err(|e| Error::key_file_decode(format!("{}", key_file.display()), e))?;

        Ok(key_entry)
    }

    fn add_key(&mut self, key_name: &str, key_entry: S) -> Result<(), Error> {
        let mut filename = self.store.join(key_name);
        filename.set_extension(KEYSTORE_FILE_EXTENSION);
        let file_path = filename.display().to_string();

        ensure_private_key_directory(&self.store).map_err(|e| {
            Error::key_file_io(
                self.store.display().to_string(),
                "failed to secure keys folder before writing".to_string(),
                e,
            )
        })?;

        let mut file = open_private_key_file(&filename).map_err(|e| {
            Error::key_file_io(file_path.clone(), "failed to create file".to_string(), e)
        })?;

        serde_json::to_writer_pretty(&mut file, &key_entry)
            .map_err(|e| Error::key_file_encode(file_path.clone(), e))?;

        file.commit().map_err(|e| {
            Error::key_file_io(
                file_path,
                "failed to atomically replace key file".to_string(),
                e,
            )
        })?;

        Ok(())
    }

    fn remove_key(&mut self, key_name: &str) -> Result<(), Error> {
        let mut filename = self.store.join(key_name);
        filename.set_extension(KEYSTORE_FILE_EXTENSION);

        fs::remove_file(filename.clone())
            .map_err(|e| Error::remove_io_fail(filename.display().to_string(), e))?;

        Ok(())
    }

    fn keys(&self) -> Result<Vec<(String, S)>, Error> {
        let dir = fs::read_dir(&self.store).map_err(|e| {
            Error::key_file_io(
                self.store.display().to_string(),
                "failed to list keys".to_string(),
                e,
            )
        })?;

        let ext = OsStr::new(KEYSTORE_FILE_EXTENSION);

        dir.into_iter()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension() == Some(ext))
            .flat_map(|path| path.file_stem().map(OsStr::to_owned))
            .flat_map(|stem| stem.to_str().map(ToString::to_string))
            .map(|name| self.get_key(&name).map(|key| (name, key)))
            .collect()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Store {
    Memory,
    Test,
}

impl Default for Store {
    fn default() -> Self {
        Self::Test
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyRing<S> {
    Memory(Memory<S>),
    Test(Test),
}

impl<S: SigningKeyPairSized> KeyRing<S> {
    pub fn new(
        store: Store,
        account_prefix: &str,
        chain_id: &ChainId,
        ks_folder: &Option<PathBuf>,
    ) -> Result<Self, Error> {
        match store {
            Store::Memory => Ok(Self::Memory(Memory::new(account_prefix.to_string()))),

            Store::Test => {
                let keys_folder = disk_store_path(chain_id.as_str(), ks_folder)?;

                // Create keys folder if it does not exist
                ensure_private_key_directory(&keys_folder).map_err(|e| {
                    Error::key_file_io(
                        keys_folder.display().to_string(),
                        "failed to create or secure keys folder".to_string(),
                        e,
                    )
                })?;

                Ok(Self::Test(Test::new(
                    account_prefix.to_string(),
                    keys_folder,
                )))
            }
        }
    }

    pub fn get_key(&self, key_name: &str) -> Result<S, Error> {
        match self {
            Self::Memory(m) => m.get_key(key_name),
            Self::Test(d) => d.get_key(key_name),
        }
    }

    pub fn add_key(&mut self, key_name: &str, key_entry: S) -> Result<(), Error> {
        match self {
            Self::Memory(m) => m.add_key(key_name, key_entry),
            Self::Test(d) => d.add_key(key_name, key_entry),
        }
    }

    pub fn remove_key(&mut self, key_name: &str) -> Result<(), Error> {
        match self {
            Self::Memory(m) => m.remove_key(key_name),
            Self::Test(d) => <Test as KeyStore<S>>::remove_key(d, key_name),
        }
    }

    pub fn keys(&self) -> Result<Vec<(String, S)>, Error> {
        match self {
            Self::Memory(m) => m.keys(),
            Self::Test(d) => d.keys(),
        }
    }

    pub fn account_prefix(&self) -> &str {
        match self {
            Self::Memory(m) => &m.account_prefix,
            Self::Test(d) => &d.account_prefix,
        }
    }
}

impl KeyRing<Secp256k1KeyPair> {
    pub fn new_secp256k1(
        store: Store,
        account_prefix: &str,
        chain_id: &ChainId,
        ks_folder: &Option<PathBuf>,
    ) -> Result<Self, Error> {
        Self::new(store, account_prefix, chain_id, ks_folder)
    }
}

impl KeyRing<Ed25519KeyPair> {
    pub fn new_ed25519(
        store: Store,
        account_prefix: &str,
        chain_id: &ChainId,
        ks_folder: &Option<PathBuf>,
    ) -> Result<Self, Error> {
        Self::new(store, account_prefix, chain_id, ks_folder)
    }
}

impl KeyRing<NamadaKeyPair> {
    pub fn new_namada(
        store: Store,
        chain_id: &ChainId,
        ks_folder: &Option<PathBuf>,
    ) -> Result<Self, Error> {
        Self::new(store, "", chain_id, ks_folder)
    }
}

fn disk_store_path(folder_name: &str, keystore_folder: &Option<PathBuf>) -> Result<PathBuf, Error> {
    let ks_folder = match keystore_folder {
        Some(folder) => folder.to_owned(),
        None => {
            let home = dirs_next::home_dir().ok_or_else(Error::home_location_unavailable)?;
            home.join(KEYSTORE_DEFAULT_FOLDER)
        }
    };

    let folder = ks_folder.join(folder_name).join(KEYSTORE_DISK_BACKEND);

    Ok(folder)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    struct TestDirectory(std::path::PathBuf);

    #[cfg(unix)]
    impl TestDirectory {
        fn new(prefix: &str) -> Self {
            Self(std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4())))
        }
    }

    #[cfg(unix)]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn key_store_paths_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new("hermes-keyring-permissions");
        super::ensure_private_key_directory(&directory.0).unwrap();
        assert_eq!(
            std::fs::metadata(&directory.0)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let key_path = directory.0.join("relayer.json");
        super::open_private_key_file(&key_path)
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        super::open_private_key_file(&key_path)
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_write_rejects_symlink_without_touching_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = TestDirectory::new("hermes-keyring-write-symlink");
        let key_directory = directory.0.join("keys");
        super::ensure_private_key_directory(&key_directory).unwrap();

        let target = directory.0.join("target.json");
        std::fs::write(&target, b"must remain unchanged").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let key_path = key_directory.join("relayer.json");
        symlink(&target, &key_path).unwrap();

        let error = super::open_private_key_file(&key_path).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(std::fs::symlink_metadata(&key_path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"must remain unchanged");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_write_does_not_follow_symlink_created_before_commit() {
        use std::io::Write;
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = TestDirectory::new("hermes-keyring-write-raced-symlink");
        let key_directory = directory.0.join("keys");
        super::ensure_private_key_directory(&key_directory).unwrap();

        let target = directory.0.join("target.json");
        std::fs::write(&target, b"must remain unchanged").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let key_path = key_directory.join("relayer.json");

        let mut file = super::open_private_key_file(&key_path).unwrap();
        file.write_all(b"new key material").unwrap();
        symlink(&target, &key_path).unwrap();
        file.commit().unwrap();

        assert!(!std::fs::symlink_metadata(&key_path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&key_path).unwrap(), b"new key material");
        assert_eq!(std::fs::read(&target).unwrap(), b"must remain unchanged");
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_key_permissions_are_repaired_before_reading() {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new("hermes-keyring-read-permissions");
        std::fs::create_dir_all(&directory.0).unwrap();
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o755)).unwrap();

        let key_path = directory.0.join("relayer.json");
        std::fs::write(&key_path, b"private key material").unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        super::ensure_private_key_directory(&directory.0).unwrap();
        let mut file = super::open_private_key_file_for_read(&key_path).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        assert_eq!(contents, "private key material");
        assert_eq!(
            std::fs::metadata(&directory.0)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_key_file_is_rejected_without_touching_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = TestDirectory::new("hermes-keyring-symlink-file");
        let key_directory = directory.0.join("keys");
        super::ensure_private_key_directory(&key_directory).unwrap();

        let target = directory.0.join("target.json");
        std::fs::write(&target, b"do not open through symlink").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let key_path = key_directory.join("relayer.json");
        symlink(&target, &key_path).unwrap();

        let error = super::open_private_key_file_for_read(&key_path).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"do not open through symlink"
        );
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_key_directory_is_rejected_without_touching_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = TestDirectory::new("hermes-keyring-symlink-directory");
        std::fs::create_dir_all(&directory.0).unwrap();
        let target = directory.0.join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let key_directory = directory.0.join("keys");
        symlink(&target, &key_directory).unwrap();

        let error = super::ensure_private_key_directory(&key_directory).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o755
        );
    }
}
