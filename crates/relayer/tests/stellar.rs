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

mod send_ledger {
    use ibc_relayer::worker::stellar_packet::ledger_from_event_id;

    #[test]
    fn it_recovers_the_ledger_from_a_soroban_toid() {
        assert_eq!(
            ledger_from_event_id("0018332299103842304-0000000001"),
            Some(4_268_321)
        );
    }

    #[test]
    fn it_ignores_the_operation_suffix() {
        assert_eq!(
            ledger_from_event_id("0018332299103842304-0000000009"),
            ledger_from_event_id("0018332299103842304-0000000001")
        );
    }

    #[test]
    fn it_returns_none_for_an_unparseable_id() {
        assert_eq!(ledger_from_event_id("not-a-toid"), None);
        assert_eq!(ledger_from_event_id(""), None);
    }
}

mod retry_queue {
    use std::time::Instant;

    use ibc_relayer::worker::stellar_packet::{
        is_retriable, RetryQueue, StellarPacketEvent, RETRY_BACKOFF, RETRY_MAX_ATTEMPTS,
    };

    fn event(id: &str) -> StellarPacketEvent {
        StellarPacketEvent {
            kind: "send_packet".to_string(),
            client_id: "07-tendermint-12".to_string(),
            sequence: 1,
            tx_hash: "abcd".to_string(),
            event_id: id.to_string(),
            value_xdr: vec![],
            contract_id: "C".to_string(),
        }
    }

    #[test]
    fn a_proof_that_is_not_ready_yet_is_retriable() {
        assert!(is_retriable(
            "build_failed: proof source failed: chain did not reach ledger 4281542 (last seen 4281534) after 24s"
        ));
        assert!(is_retriable(
            "build_failed: no commitment for client_id=07-tendermint-12 sequence=1 at height=4281534"
        ));
        assert!(is_retriable("client_update_failed: rpc timeout"));
        assert!(is_retriable(
            "recv bytes=42 submit=failed: account sequence mismatch"
        ));
    }

    #[test]
    fn a_malformed_or_unconfigured_relay_is_not_retriable() {
        assert!(!is_retriable("decode_failed: bad xdr"));
        assert!(!is_retriable("no_proof_source"));
        assert!(!is_retriable("recv bytes=42 submit=no_destination"));
        assert!(!is_retriable("n/a"));
    }

    #[test]
    fn a_successful_relay_is_never_retried() {
        assert!(!is_retriable(
            "recv bytes=42 submit=ok events=1 ack=no_raw_ack"
        ));
    }

    #[test]
    fn an_enqueued_event_is_not_due_immediately() {
        let mut q = RetryQueue::default();
        let now = Instant::now();
        q.enqueue(event("e1"), now);

        assert_eq!(q.len(), 1);
        assert!(q.due(now).is_empty(), "must wait out the backoff first");
        assert_eq!(q.due(now + RETRY_BACKOFF).len(), 1);
    }

    #[test]
    fn the_same_event_is_never_queued_twice() {
        let mut q = RetryQueue::default();
        let now = Instant::now();
        q.enqueue(event("e1"), now);
        q.enqueue(event("e1"), now);

        assert_eq!(
            q.len(),
            1,
            "an event already pending must not be duplicated"
        );
    }

    #[test]
    fn success_removes_the_event_from_the_queue() {
        let mut q = RetryQueue::default();
        let now = Instant::now();
        q.enqueue(event("e1"), now);

        assert_eq!(q.record("e1", false, now), None);
        assert!(q.is_empty(), "a resolved packet must leave the queue");
    }

    #[test]
    fn a_still_failing_event_is_rescheduled_not_dropped() {
        let mut q = RetryQueue::default();
        let now = Instant::now();
        q.enqueue(event("e1"), now);

        assert_eq!(q.record("e1", true, now), None);
        assert_eq!(q.len(), 1);
        assert!(
            q.due(now).is_empty(),
            "the retry is pushed out by the backoff"
        );
        assert_eq!(q.due(now + RETRY_BACKOFF).len(), 1);
    }

    #[test]
    fn the_queue_gives_up_after_the_attempt_cap() {
        let mut q = RetryQueue::default();
        let now = Instant::now();
        q.enqueue(event("e1"), now);

        for _ in 0..RETRY_MAX_ATTEMPTS - 2 {
            assert_eq!(q.record("e1", true, now), None);
        }
        assert_eq!(
            q.record("e1", true, now),
            Some(RETRY_MAX_ATTEMPTS),
            "the final attempt reports how many were made"
        );
        assert!(
            q.is_empty(),
            "a packet past the cap must not be retried forever"
        );
    }

    #[test]
    fn recording_an_unknown_event_is_harmless() {
        let mut q = RetryQueue::default();
        assert_eq!(q.record("never-seen", true, Instant::now()), None);
        assert!(q.is_empty());
    }

    #[test]
    fn independent_events_are_tracked_separately() {
        let mut q = RetryQueue::default();
        let now = Instant::now();
        q.enqueue(event("e1"), now);
        q.enqueue(event("e2"), now);
        assert_eq!(q.len(), 2);

        q.record("e1", false, now);
        assert_eq!(q.len(), 1, "resolving one must not evict the other");
        assert_eq!(q.due(now + RETRY_BACKOFF).len(), 1);
    }
}

mod proof_height {
    use ibc_relayer::worker::stellar_packet_adapters::proof_height;
    use ibc_relayer_types::Height;

    fn h(n: u64) -> Height {
        Height::new(0, n).unwrap()
    }

    #[test]
    fn it_proves_at_the_ledger_the_packet_was_sent_in() {
        let chosen = proof_height(h(4_282_530), 4_282_516).unwrap();
        assert_eq!(
            chosen.revision_height(),
            4_282_516,
            "only the send ledger carries an ibc_root event, so only it has a bound state root"
        );
    }

    #[test]
    fn it_does_not_advance_past_the_send_ledger() {
        let chosen = proof_height(h(4_282_517), 4_282_516).unwrap();
        assert_ne!(
            chosen.revision_height(),
            4_282_517,
            "the tendermint proof-at-h-verified-at-h+1 idiom does not hold for the stellar smt"
        );
    }

    #[test]
    fn it_keeps_the_revision_number_of_the_chain() {
        let chosen = proof_height(Height::new(3, 900).unwrap(), 850).unwrap();
        assert_eq!(chosen.revision_number(), 3);
        assert_eq!(chosen.revision_height(), 850);
    }

    #[test]
    fn without_a_send_ledger_it_falls_back_to_the_tip() {
        let chosen = proof_height(h(4_282_530), 0).unwrap();
        assert_eq!(chosen.revision_height(), 4_282_530);
    }
}
