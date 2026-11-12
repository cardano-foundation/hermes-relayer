use tendermint::abci::Event;
use tracing::warn;

const FALLBACK_EVENT: &str = "cardano_block_decode_fallback";

pub(super) fn warn_on_fallback(event: &Event) {
    if event.kind != FALLBACK_EVENT {
        return;
    }
    let height = diagnostic_attribute(event, "block_height");
    let hash = diagnostic_attribute(event, "block_hash");
    let cause = diagnostic_attribute(event, "cause");
    warn!(
        block_height = %height,
        block_hash = %hash,
        cause = %cause,
        "gouroboros parsing failed at Cardano block {} ({}). Fell back to legacy parser. Requires immediate attention.",
        height,
        hash,
    );
}

fn diagnostic_attribute(event: &Event, key: &str) -> String {
    event
        .attributes
        .iter()
        .find_map(|attribute| {
            (attribute.key_str().ok() == Some(key))
                .then(|| attribute.value_str().ok())
                .flatten()
        })
        .unwrap_or("unknown")
        .chars()
        .take(512)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use ibc_relayer_types::events::IbcEvent;
    use ibc_relayer_types::Height;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::chain::cosmos::types::events::from_tx_response_event;

    #[derive(Clone)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl Write for LogCapture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for LogCapture {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn capture_logs(run: impl FnOnce()) -> String {
        let writer = LogCapture(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(writer.clone())
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::with_default(subscriber, run);
        let bytes = writer.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn decoder_fallback_warns_without_interrupting_client_events() {
        let hash = "ecea5dca941ec52645d41bc8f6a161793511c6323c50e32bf24b236c50117684";
        let fallback = Event::new(
            FALLBACK_EVENT,
            [
                ("block_height", "4846910"),
                ("block_hash", hash),
                ("cause", "cbor: invalid map key type: []interface {}"),
            ],
        );
        let update = Event::new(
            "update_client",
            [
                ("client_id", "07-tendermint-0"),
                ("client_type", "07-tendermint"),
                ("consensus_height", "1-10"),
            ],
        );
        let height = Height::new(1, 10).unwrap();
        let logs = capture_logs(|| {
            let events: Vec<_> = [fallback, update]
                .iter()
                .filter_map(|event| from_tx_response_event(height, event))
                .collect();
            assert_eq!(events.len(), 1);
            assert!(matches!(events[0].event, IbcEvent::UpdateClient(_)));
        });
        assert!(logs.contains("WARN"));
        assert!(logs.contains("gouroboros parsing failed at Cardano block 4846910"));
        assert!(logs.contains(hash));
        assert!(logs.contains("Fell back to legacy parser. Requires immediate attention."));
        assert!(logs.contains("cbor: invalid map key type"));
    }

    #[test]
    fn unrelated_events_do_not_warn() {
        let event = Event::new("unrelated", Vec::<(String, String)>::new());
        assert!(capture_logs(|| warn_on_fallback(&event)).is_empty());
    }

    #[test]
    fn incomplete_decoder_diagnostic_is_nonfatal_and_bounded() {
        let event = Event::new(
            FALLBACK_EVENT,
            [("cause", "\n\t".to_string() + &"x".repeat(1024))],
        );
        let cause = diagnostic_attribute(&event, "cause");
        assert_eq!(cause.len(), 512);
        assert!(!cause.contains('\n'));
        assert!(!cause.contains('\t'));
        let logs = capture_logs(|| {
            assert!(from_tx_response_event(Height::new(1, 10).unwrap(), &event).is_none());
        });
        assert!(logs.contains("Cardano block unknown (unknown)"));
        assert!(logs.contains("Requires immediate attention."));
    }
}
