use super::*;
use crate::event::tx::operation_fixtures::{records, v10_records, Record};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::mpsc as std_mpsc;
use std::thread;
use tendermint_rpc::event::{Event, EventData, TxInfo, TxResult};
use tungstenite::Message;

enum ServerCommand {
    Publish(usize),
    Disconnect,
}

// Serve real committed keeper results over Comet's WebSocket RPC protocol. Push
// notifications deliberately omit the message, so production's tx(hash) lookup
// must recover it. A second connection exercises reconnect and resubscription.
fn serve(
    listener: TcpListener,
    records: Vec<Record>,
    commands: std_mpsc::Receiver<ServerCommand>,
    queries: Arc<AtomicUsize>,
) {
    let responses: HashMap<_, _> = records
        .iter()
        .map(|record| {
            let response = record.response();
            let request = tendermint_rpc::endpoint::tx::Request::new(response.hash, false);
            (
                serde_json::to_value(request).unwrap()["hash"]
                    .clone()
                    .to_string(),
                response,
            )
        })
        .collect();
    for _ in 0..2 {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let mut ws = tungstenite::accept(socket).unwrap();
        let mut subscriptions = HashMap::new();
        loop {
            match commands.try_recv() {
                Ok(ServerCommand::Publish(index)) => {
                    let record = &records[index];
                    let query = super::super::queries::ibc_client().to_string();
                    let id = subscriptions.get(&query).unwrap();
                    let mut events = record.events.clone();
                    for event in &mut events {
                        if event.kind == "update_client" {
                            event.attributes.retain(|a| a.key_bytes() == b"client_id");
                        }
                    }
                    let notification = Event {
                        query,
                        data: EventData::Tx {
                            tx_result: TxInfo {
                                height: record.height as i64,
                                index: Some(0),
                                tx: hex::decode(&record.tx).unwrap(),
                                result: TxResult {
                                    log: None,
                                    gas_wanted: None,
                                    gas_used: None,
                                    events,
                                },
                            },
                        },
                        events: Some(Default::default()),
                    };
                    let event = tendermint_rpc::event::v0_38::SerEvent::from(notification);
                    ws.send(Message::Text(
                        json!({"jsonrpc":"2.0", "id":id, "result":event}).to_string(),
                    ))
                    .unwrap();
                }
                Ok(ServerCommand::Disconnect) => break,
                Err(std_mpsc::TryRecvError::Disconnected) => return,
                Err(std_mpsc::TryRecvError::Empty) => {}
            }
            let message = match ws.read() {
                Ok(message) => message,
                Err(tungstenite::Error::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(_) => break,
            };
            match message {
                Message::Text(text) => {
                    let request: Value = serde_json::from_str(&text).unwrap();
                    let result = match request["method"].as_str().unwrap() {
                        "subscribe" => {
                            subscriptions.insert(
                                request["params"]["query"].as_str().unwrap().to_owned(),
                                request["id"].clone(),
                            );
                            json!({})
                        }
                        "tx" => {
                            queries.fetch_add(1, AtomicOrdering::SeqCst);
                            serde_json::to_value(
                                responses
                                    .get(&request["params"]["hash"].to_string())
                                    .unwrap(),
                            )
                            .unwrap()
                        }
                        method => panic!("unexpected RPC method {method}"),
                    };
                    ws.send(Message::Text(
                        json!({"jsonrpc":"2.0", "id":request["id"], "result":result}).to_string(),
                    ))
                    .unwrap();
                }
                Message::Ping(payload) => {
                    ws.send(Message::Pong(payload)).unwrap();
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }
}

#[test]
fn committed_operations_survive_production_push_collection_and_reconnect() {
    check_push_collection_and_reconnect(records());
    check_push_collection_and_reconnect(v10_records());
}

fn check_push_collection_and_reconnect(records: Vec<Record>) {
    let expected: Vec<_> = records
        .iter()
        .flat_map(|r| r.consensus_heights.clone().unwrap_or_default())
        .collect();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}/websocket", listener.local_addr().unwrap());
    let (commands, rx) = std_mpsc::channel();
    let queries = Arc::new(AtomicUsize::new(0));
    let server_queries = queries.clone();
    let server_records = records.clone();
    let server = thread::spawn(move || serve(listener, server_records, rx, server_queries));
    let rt = Arc::new(TokioRuntime::new().unwrap());
    let (mut source, _control) = EventSource::new(
        ChainId::from_string("relayer-events-1"),
        url.parse().unwrap(),
        CompatMode::V0_38,
        Duration::from_millis(10),
        rt.clone(),
    )
    .unwrap();
    source.init_subscriptions().unwrap();
    for round in 0..2 {
        let subscriptions =
            core::mem::replace(&mut source.subscriptions, Box::new(stream::empty()));
        let heights = rt.block_on(async {
            let batches = stream_batches(
                subscriptions,
                source.chain_id.clone(),
                source.batch_delay,
                source.client.clone(),
            );
            pin_mut!(batches);
            for index in 0..records.len() {
                commands.send(ServerCommand::Publish(index)).unwrap();
            }
            let mut heights = Vec::new();
            while heights.len() < expected.len() {
                let batch = tokio::time::timeout(Duration::from_secs(10), batches.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                for event in batch.events {
                    assert!(!matches!(event.event, IbcEvent::ChainError(_)));
                    if let IbcEvent::UpdateClient(update) = event.event {
                        assert!(update.header.is_none());
                        heights.push(update.consensus_height().to_string());
                    }
                }
            }
            heights
        });
        assert_eq!(heights, expected, "round {round}");
        if round == 0 {
            commands.send(ServerCommand::Disconnect).unwrap();
            rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(10), source.rx_err.recv())
                    .await
                    .unwrap()
                    .unwrap();
            });
            source.try_reconnect().unwrap();
            source.try_resubscribe().unwrap();
        }
    }
    let expected_queries = records
        .iter()
        .filter(|r| r.events.iter().any(|e| e.kind == "update_client"))
        .count()
        * 2;
    assert_eq!(queries.load(AtomicOrdering::SeqCst), expected_queries);
    source.client.close().unwrap();
    rt.block_on(source.driver_handle).unwrap();
    drop(commands);
    server.join().unwrap();
}
