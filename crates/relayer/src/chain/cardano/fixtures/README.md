`gateway-packet-batch.json` contains an actual `BuildPacketBatchResponse` from the incubator Gateway's `PacketLaneService.batch()` and `TxOperationRunnerService.runChain()` at commit `d3e83b3a`, captured with the fixture export added to the backlog harness. The harness uses a disposable emulator provider with compiled packet validators and the production Lucid builders. The fixture records the protobuf response bytes and the original transaction CBOR and body hash calculated by CML before Hermes receives it.

To capture a fresh response from an incubator checkout with the Gateway dependencies installed and built, run this from `cardano/offchain` with the output path set to this fixture's absolute path.

```sh
GATEWAY_BATCH_RESPONSE_FIXTURE_PATH=/absolute/path/to/gateway-packet-batch.json deno run --allow-env --allow-read --allow-net --allow-run scripts/test-gateway-packet-backlog.ts
```

The harness still signs and submits the batches through the emulator and checks that the backlog drains. Wallet keys and transaction hashes change between runs. The regression test checks the captured bytes and CML body hash against Hermes' decoding of the same protobuf response.
