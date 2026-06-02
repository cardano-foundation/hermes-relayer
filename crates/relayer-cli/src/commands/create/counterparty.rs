use abscissa_core::clap::Parser;
use abscissa_core::{Command, Runnable};

use ibc_relayer::chain::handle::ChainHandle;
use ibc_relayer::chain::tracking::TrackedMsgs;
use ibc_relayer_types::clients::ics10_stellar::v2_msgs::MsgRegisterCounterparty;
use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ClientId};

use crate::application::app_config;
use crate::cli_utils::spawn_chain_runtime;
use crate::conclude::{exit_with_unrecoverable_error, Output};
use crate::error::Error;

/// Register a counterparty for an existing client (IBC v2 `MsgRegisterCounterparty`).
#[derive(Clone, Command, Debug, Parser, PartialEq, Eq)]
pub struct CreateCounterpartyCommand {
    #[clap(
        long = "chain",
        required = true,
        value_name = "CHAIN_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the chain that hosts the client and on which the counterparty is registered"
    )]
    chain_id: ChainId,

    #[clap(
        long = "client",
        required = true,
        value_name = "CLIENT_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the local client on the host chain"
    )]
    client_id: ClientId,

    #[clap(
        long = "counterparty-client",
        required = true,
        value_name = "COUNTERPARTY_CLIENT_ID",
        help_heading = "REQUIRED",
        help = "Identifier of the counterparty client on the other chain"
    )]
    counterparty_client_id: ClientId,

    #[clap(
        long = "commitment-prefix",
        value_name = "PREFIX",
        default_value = "ibc",
        help = "Counterparty commitment prefix (single segment; default `ibc`)"
    )]
    commitment_prefix: String,
}

impl Runnable for CreateCounterpartyCommand {
    fn run(&self) {
        run_create_counterparty(self).unwrap_or_else(exit_with_unrecoverable_error);

        Output::success_msg("Successfully registered counterparty").exit()
    }
}

fn run_create_counterparty(cmd: &CreateCounterpartyCommand) -> Result<(), Error> {
    let config = app_config();

    let chain_handle = spawn_chain_runtime(&config, &cmd.chain_id)?;

    let signer = chain_handle.get_signer().map_err(Error::relayer)?;

    let msg = MsgRegisterCounterparty {
        client_id: cmd.client_id.to_string(),
        counterparty_client_id: cmd.counterparty_client_id.to_string(),
        counterparty_commitment_prefix: vec![cmd.commitment_prefix.clone().into_bytes()],
        signer: signer.to_string(),
    };

    let messages = TrackedMsgs::new_static(vec![msg.into()], "cli");

    chain_handle
        .send_messages_and_wait_commit(messages)
        .map_err(Error::relayer)?;

    Ok(())
}
