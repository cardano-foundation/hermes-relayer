//! Request-level coverage of Mithril certificate submission from refresh.
use super::*;
use crate::chain::cardano::mithril_stake::MITHRIL_STAKE_CERTIFICATES_TYPE_URL;
use crate::chain::handle::{BaseChainHandle, ChainRequest};
use ibc_relayer_types::clients::ics08_cardano_probabilistic::raw;
use ibc_relayer_types::signer::Signer;
use prost::Message;
use std::sync::{Arc, Mutex};

struct Harness {
    source: BaseChainHandle,
    destination: BaseChainHandle,
    queried: Arc<Mutex<Vec<u64>>>,
    submitted: Arc<Mutex<Vec<raw::MithrilStakeCertificates>>>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Harness {
    // The source holds certificates for anchor epochs listed in `available`.
    fn new(available: Vec<u64>) -> Self {
        let queried = Arc::new(Mutex::new(vec![]));
        let submitted = Arc::new(Mutex::new(vec![]));
        let (tx, rx) = crossbeam_channel::unbounded();
        let source = BaseChainHandle::new(ChainId::from_string("cardano-0"), tx);
        let asked = queried.clone();
        let source_thread = thread::spawn(move || {
            for (_, request) in rx {
                match request {
                    ChainRequest::QueryMithrilStakeCertificates {
                        mithril_epoch,
                        reply_to,
                    } => {
                        asked.lock().unwrap().push(mithril_epoch);
                        let message = available.contains(&mithril_epoch).then(|| {
                            ibc_proto::google::protobuf::Any {
                                type_url: MITHRIL_STAKE_CERTIFICATES_TYPE_URL.to_owned(),
                                value: raw::MithrilStakeCertificates {
                                    certificates: vec![format!("{{\"epoch\":{mithril_epoch}}}")],
                                }
                                .encode_to_vec(),
                            }
                        });
                        reply_to.send(Ok(message)).unwrap();
                    }
                    unexpected => panic!("unexpected source request: {unexpected:?}"),
                }
            }
        });
        let (tx, rx) = crossbeam_channel::unbounded();
        let destination = BaseChainHandle::new(ChainId::from_string("cosmos-0"), tx);
        let recorded = submitted.clone();
        let destination_thread = thread::spawn(move || {
            for (_, request) in rx {
                match request {
                    ChainRequest::Signer { reply_to } => {
                        reply_to.send(Ok(Signer::dummy())).unwrap();
                    }
                    ChainRequest::SendMessagesAndWaitCommit {
                        tracked_msgs,
                        reply_to,
                    } => {
                        assert_eq!(tracked_msgs.msgs.len(), 1);
                        let update = ibc_proto::ibc::core::client::v1::MsgUpdateClient::decode(
                            tracked_msgs.msgs[0].value.as_slice(),
                        )
                        .unwrap();
                        assert_eq!(update.client_id, "08-cardano-probabilistic-0");
                        let message = update.client_message.unwrap();
                        assert_eq!(message.type_url, MITHRIL_STAKE_CERTIFICATES_TYPE_URL);
                        recorded.lock().unwrap().push(
                            raw::MithrilStakeCertificates::decode(message.value.as_slice())
                                .unwrap(),
                        );
                        reply_to.send(Ok(vec![])).unwrap();
                    }
                    unexpected => panic!("unexpected destination request: {unexpected:?}"),
                }
            }
        });
        Self {
            source,
            destination,
            queried,
            submitted,
            threads: vec![source_thread, destination_thread],
        }
    }

    fn client(&self) -> ForeignClient<BaseChainHandle, BaseChainHandle> {
        ForeignClient::restore(
            "08-cardano-probabilistic-0".parse().unwrap(),
            self.destination.clone(),
            self.source.clone(),
        )
    }

    fn close(self) {
        drop(self.source);
        drop(self.destination);
        for thread in self.threads {
            thread.join().unwrap();
        }
    }
}

fn client_state(mithril_epoch: u64) -> AnyClientState {
    let AnyClientState::Probabilistic(mut client) =
        super::tests::checkpoint_test_client_state(false)
    else {
        unreachable!()
    };
    client.mithril_epoch = mithril_epoch;
    AnyClientState::Probabilistic(client)
}

#[test]
fn an_anchored_client_records_the_certificates_that_extend_its_anchor() {
    let h = Harness::new(vec![7]);
    h.client().record_mithril_stake(&client_state(7));
    assert_eq!(*h.queried.lock().unwrap(), vec![7]);
    assert_eq!(
        h.submitted.lock().unwrap()[0].certificates,
        vec!["{\"epoch\":7}".to_owned()]
    );
    h.close();
}

#[test]
fn nothing_is_submitted_until_mithril_certifies_more_stake() {
    let h = Harness::new(vec![]);
    h.client().record_mithril_stake(&client_state(7));
    assert_eq!(*h.queried.lock().unwrap(), vec![7]);
    assert!(h.submitted.lock().unwrap().is_empty());
    h.close();
}

#[test]
fn an_unanchored_client_never_asks_for_certificates() {
    let h = Harness::new(vec![0]);
    h.client().record_mithril_stake(&client_state(0));
    assert!(h.queried.lock().unwrap().is_empty());
    assert!(h.submitted.lock().unwrap().is_empty());
    h.close();
}
