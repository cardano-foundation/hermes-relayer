# Packet Relaying

This section describes the configuration and commands that can be used to start Hermes and relay packets over one or multiple paths.

## Table of Contents

<!-- toc -->

## The `start` Command

To relay packets only configure the `mode` section of the configuration file like so:
```toml
[global]
log_level = 'info'

[mode]

[mode.clients]
enabled = true
# ...

[mode.connections]
enabled = false

[mode.channels]
enabled = false

[mode.packets]
enabled = true
# ...
```

Then start Hermes using the start command:

```shell
{{#template ../../../templates/commands/hermes/start_1.md}}
```

Hermes sends packet transactions triggered by IBC packet events for all open channels between the configured chains.
This is also referred to packet streaming.

## Packet Streaming

After Hermes is started using the `start` command, it listens to IBC packet events emitted by any of
the configured chains. Assuming the events are coming from a `source` chain, Hermes builds packets
based on these events, packets that are then sent either to the `source` chain or the counterparty (`destination`) chain.

Current events and actions are:

- `send_packet`: Hermes builds a packet message with the `packet` obtained from the event and any required proofs obtained from the counterparty of the chain where the message is sent. The concrete packet is:
  - `MsgRecvPacket`, sent to `destination` chain if the channel is in open state on the `destination` chain, and a timeout has not occurred,
  - `MsgTimeout`, sent to the `source` chain if the channel is in open state on the `destination` chain, but a timeout has occurred.
  - `MsgTimeoutOnClose`, sent to the `source` chain if the channel is in closed state on the `destination` chain.
- `write_acknowledgement`: Hermes builds a `MsgAcknowledgement` packet that is sent to the `destination` chain.

In addition to these events, Hermes will also handle channel closing events:
- `chan_close_init`: Hermes builds a `MsgChannelCloseConfirm` and sends it to the `destination` chain

## Cardano proof reuse

For unordered paths into Cardano, the packet worker schedules the event batches
already queued when dispatch starts. It does not wait for more packets. Receives
and acknowledgements can use the same source state even when their events were
emitted at different heights.

Hermes first tries fresh consensus roots retained by the Cardano client. It then
considers updates already in progress for that client and finally the latest
available source header. Each commitment or acknowledgement is queried again
with its proof at the selected state. Missing leaves, changed commitments or
unavailable historical proofs leave the operation's original proof unchanged.
For Cosmos sources, querying state at height `h` requires the client root from
header `h + 1`. A later client height never substitutes for that exact root.

Roots are rediscovered on each dispatch so updates rolled back on Cardano are
not cached as successful. Existing client freshness, timeout and connection
delay checks still apply. Work with a connection delay can only switch to a
retained root whose own time and block delays have elapsed.

Successful acknowledgements from separate ready entries at a common proof height
are submitted together. The Cardano adapter chooses pairs with a compatible
signer and channel and distinct lane inputs under the pinned signing policy.
Unpaired acknowledgements are submitted immediately. A batch build failure
falls back to singleton submission before any batch transaction is broadcast.
Savings depend on the available roots and the arrival pattern of relay work.

## Packet Delay

If the relay path is using a non-zero delay connection, then `hermes` will delay all packet transactions. The delay is relative to the submission time for the client update at the height required by the packet proof.
The delay is used to prevent light client attacks and ensures that misbehavior detection finalizes before the transaction is submitted.
For more information on the misbehavior detector see [the misbehaviour section](../misbehaviour/index.md#monitoring-misbehaviour-and-evidence-submission).

