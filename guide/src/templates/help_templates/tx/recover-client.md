DESCRIPTION:
Recover a frozen or expired Cardano IBC client using an active substitute

USAGE:
    hermes tx recover-client [OPTIONS] --host-chain <HOST_CHAIN_ID> --subject-client <SUBJECT_CLIENT_ID> --substitute-client <SUBSTITUTE_CLIENT_ID>

OPTIONS:
    -h, --help                   Print help information
        --key-name <KEY_NAME>    Use the given recovery authority key name (default: `key_name`
                                 config)

REQUIRED:
        --host-chain <HOST_CHAIN_ID>
            Identifier of the chain that hosts both clients

        --subject-client <SUBJECT_CLIENT_ID>
            Identifier of the frozen or expired client to recover

        --substitute-client <SUBSTITUTE_CLIENT_ID>
            Identifier of the active client used as the recovery checkpoint
