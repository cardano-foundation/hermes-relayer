use ibc_relayer_types::clients::ics10_stellar::consensus_state::ConsensusState;
use ibc_relayer_types::clients::ics10_stellar::raw::ConsensusState as RawConsensusState;

fn raw(root: Vec<u8>) -> RawConsensusState {
    RawConsensusState {
        timestamp: 1_700_000_000,
        ledger_hash: vec![0xaa; 32],
        root,
    }
}

#[test]
fn a_creation_height_state_with_no_root_decodes() {
    let decoded = ConsensusState::try_from(raw(vec![]))
        .expect("hermes writes an empty root at creation; it must be able to read it back");

    assert!(
        decoded.root.as_bytes().is_empty(),
        "the empty root must survive decoding rather than being invented"
    );
    assert_eq!(decoded.timestamp, 1_700_000_000);
}

#[test]
fn a_real_root_decodes() {
    let decoded = ConsensusState::try_from(raw(vec![0x11; 32])).unwrap();
    assert_eq!(decoded.root.as_bytes(), &[0x11; 32]);
}

#[test]
fn a_root_of_the_wrong_length_is_still_rejected() {
    let err = ConsensusState::try_from(raw(vec![0x11; 31])).unwrap_err();
    assert!(
        err.to_string().contains("root"),
        "a truncated root must not be accepted: {err}"
    );

    let err = ConsensusState::try_from(raw(vec![0x11; 33])).unwrap_err();
    assert!(err.to_string().contains("root"), "got: {err}");
}

#[test]
fn a_ledger_hash_of_the_wrong_length_is_rejected() {
    let mut r = raw(vec![]);
    r.ledger_hash = vec![0xaa; 7];
    let err = ConsensusState::try_from(r).unwrap_err();
    assert!(err.to_string().contains("ledger_hash"), "got: {err}");
}

#[test]
fn an_empty_root_round_trips_through_raw() {
    let decoded = ConsensusState::try_from(raw(vec![])).unwrap();
    let back: RawConsensusState = decoded.into();
    assert!(
        back.root.is_empty(),
        "re-encoding must not fabricate a root the light client never verified"
    );
}
