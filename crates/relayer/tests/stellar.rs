use std::sync::atomic::{AtomicU32, Ordering};

use hdpath::StandardHDPath;
use ibc_relayer::chain::stellar::{
    keyring::StellarKeyRing,
    signer::{sign_tx, stellar_tx_hash},
    signing_key_pair::StellarSigningKeyPair,
};
use ibc_relayer::keyring::SigningKeyPair;

const SECRET: &str = "SBGWSG6BTNCKCOB3DIFBGCVMUPQFYPA2G4O34RMTB343OYPXU5DJDVMN";
const ACCOUNT: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
const MNEMONIC: &str = "illness spike retreat truth genius clock brain pass fit cave bargain toe";
const PASSPHRASE: &str = "Test SDF Network ; September 2015";

// ── helpers ──────────────────────────────────────────────────────────────────

struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_keystore() -> (std::path::PathBuf, TempDir) {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let path = std::env::temp_dir().join(format!(
        "hermes-stellar-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst),
    ));
    std::fs::create_dir_all(&path).unwrap();
    let guard = TempDir(path.clone());
    (path, guard)
}

fn kp() -> StellarSigningKeyPair {
    StellarSigningKeyPair::from_strkey(SECRET).unwrap()
}

// ── keyring round-trip ────────────────────────────────────────────────────────

#[test]
fn keyring_add_then_get_returns_same_account() {
    let (store, _guard) = temp_keystore();
    let mut ring = StellarKeyRing::new(store);

    ring.add_key("alice", kp()).unwrap();

    let retrieved = ring.get_key("alice").unwrap();
    assert_eq!(retrieved.account_id(), ACCOUNT);
}

#[test]
fn keyring_remove_makes_key_unavailable() {
    let (store, _guard) = temp_keystore();
    let mut ring = StellarKeyRing::new(store);

    ring.add_key("bob", kp()).unwrap();
    ring.remove_key("bob").unwrap();

    assert!(ring.get_key("bob").is_err());
}

#[test]
fn keyring_keys_lists_all_added_keys() {
    let (store, _guard) = temp_keystore();
    let mut ring = StellarKeyRing::new(store);

    ring.add_key("k1", kp()).unwrap();
    ring.add_key("k2", kp()).unwrap();

    let names: Vec<String> = ring.keys().unwrap().into_iter().map(|(n, _)| n).collect();
    assert!(names.contains(&"k1".to_string()));
    assert!(names.contains(&"k2".to_string()));
}

// ── add_key_from_file ─────────────────────────────────────────────────────────

#[test]
fn keyring_add_key_from_secret_key_json() {
    let (store, _guard) = temp_keystore();
    let mut ring = StellarKeyRing::new(store);
    let hd_path: StandardHDPath = "m/44'/148'/0'/0/0".parse().unwrap();

    let json = format!(r#"{{"secret_key": "{SECRET}"}}"#);
    let kp = ring.add_key_from_file("alice", &json, &hd_path).unwrap();

    assert_eq!(kp.account_id(), ACCOUNT);
    assert_eq!(ring.get_key("alice").unwrap().account_id(), ACCOUNT);
}

#[test]
fn keyring_add_key_from_mnemonic_json() {
    let (store, _guard) = temp_keystore();
    let mut ring = StellarKeyRing::new(store);
    let hd_path: StandardHDPath = "m/44'/148'/0'/0/0".parse().unwrap();

    let json = format!(r#"{{"mnemonic": "{MNEMONIC}"}}"#);
    let kp = ring.add_key_from_file("alice", &json, &hd_path).unwrap();

    assert_eq!(kp.account_id(), ACCOUNT);
}

#[test]
fn keyring_add_key_from_empty_json_fails() {
    let (store, _guard) = temp_keystore();
    let mut ring = StellarKeyRing::new(store);
    let hd_path: StandardHDPath = "m/44'/148'/0'/0/0".parse().unwrap();

    assert!(ring.add_key_from_file("alice", "{}", &hd_path).is_err());
}

// ── signing round-trip ────────────────────────────────────────────────────────

#[test]
fn sign_tx_hint_matches_key_hint() {
    let kp = kp();
    let (hint, _sig) = sign_tx(&kp, PASSPHRASE, b"fake_xdr_payload").unwrap();
    assert_eq!(hint, kp.key_hint());
}

#[test]
fn sign_tx_same_input_same_output() {
    let kp = kp();
    let (h1, s1) = sign_tx(&kp, PASSPHRASE, b"tx_xdr").unwrap();
    let (h2, s2) = sign_tx(&kp, PASSPHRASE, b"tx_xdr").unwrap();
    assert_eq!(h1, h2);
    assert_eq!(s1, s2);
}

#[test]
fn sign_tx_different_network_different_sig() {
    let kp = kp();
    let (_, s1) = sign_tx(&kp, "Network A", b"tx").unwrap();
    let (_, s2) = sign_tx(&kp, "Network B", b"tx").unwrap();
    assert_ne!(s1, s2);
}

#[test]
fn sign_tx_different_payload_different_sig() {
    let kp = kp();
    let (_, s1) = sign_tx(&kp, PASSPHRASE, b"tx_a").unwrap();
    let (_, s2) = sign_tx(&kp, PASSPHRASE, b"tx_b").unwrap();
    assert_ne!(s1, s2);
}

// ── tx hash properties ────────────────────────────────────────────────────────

#[test]
fn tx_hash_is_32_bytes() {
    let h = stellar_tx_hash(PASSPHRASE, b"some_xdr");
    assert_eq!(h.len(), 32);
}

#[test]
fn tx_hash_differs_for_different_payloads() {
    let h1 = stellar_tx_hash(PASSPHRASE, b"xdr_a");
    let h2 = stellar_tx_hash(PASSPHRASE, b"xdr_b");
    assert_ne!(h1, h2);
}

// ── mnemonic derivation ───────────────────────────────────────────────────────

#[test]
fn key_from_mnemonic_account0_matches_known_vector() {
    use ibc_relayer::config::AddressType;
    let hd_path: StandardHDPath = "m/44'/148'/0'/0/0".parse().unwrap();
    let kp =
        StellarSigningKeyPair::from_mnemonic(MNEMONIC, &hd_path, &AddressType::Cosmos, "").unwrap();
    assert_eq!(kp.account(), ACCOUNT);
}

#[test]
fn key_from_mnemonic_different_accounts_differ() {
    use ibc_relayer::config::AddressType;
    let hd0: StandardHDPath = "m/44'/148'/0'/0/0".parse().unwrap();
    let hd1: StandardHDPath = "m/44'/148'/1'/0/0".parse().unwrap();
    let kp0 =
        StellarSigningKeyPair::from_mnemonic(MNEMONIC, &hd0, &AddressType::Cosmos, "").unwrap();
    let kp1 =
        StellarSigningKeyPair::from_mnemonic(MNEMONIC, &hd1, &AddressType::Cosmos, "").unwrap();
    assert_ne!(kp0.account(), kp1.account());
}
