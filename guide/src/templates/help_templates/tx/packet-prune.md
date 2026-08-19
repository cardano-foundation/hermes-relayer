DESCRIPTION:
Prune one finalized packet receipt/acknowledgement pair on Cardano

USAGE:
    hermes tx packet-prune [OPTIONS] --dst-chain <DST_CHAIN_ID> --src-chain <SRC_CHAIN_ID> --src-port <SRC_PORT_ID> --src-channel <SRC_CHANNEL_ID> --sequence <SEQUENCE>

OPTIONS:
    -h, --help
            Print help information

        --proof-height <REVISION-HEIGHT>
            IBC height at which to prove source commitment absence (defaults to the destination
            client's latest verified height; for a nonzero connection delay, select an older matured
            client height that is still at or above the channel receive high-water mark and pruning
            floor)

REQUIRED:
        --dst-chain <DST_CHAIN_ID>
            Identifier of the Cardano destination chain

        --sequence <SEQUENCE>
            Sequence of the destination receipt and acknowledgement pair to prune

        --src-chain <SRC_CHAIN_ID>
            Identifier of the source chain

        --src-channel <SRC_CHANNEL_ID>
            Identifier of the source channel [aliases: src-chan]

        --src-port <SRC_PORT_ID>
            Identifier of the source port
