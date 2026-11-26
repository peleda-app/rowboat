//! Commands and results over the mesh: channel `baton/command/1` for commands to a leaseholder,
//! `baton/result/1` for results back. Frames are already signed and roster-checked by the
//! transport; commands and results are decoded and signature-checked here, and anything else is
//! dropped. Authorization stays with [`Command::check`] and [`CommandResult::check`], which need
//! the receiver's group log.

use baton_core::NodeId;
use baton_mesh::{Transport, TransportError};
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;

use crate::{Command, CommandResult};

/// The channel commands travel on.
pub const COMMANDS: &str = "baton/command/1";

/// The channel results travel on.
pub const RESULTS: &str = "baton/result/1";

/// Sends `command` to `to` (best effort, like every mesh send; the issuer retries or falls back to
/// a mailbox until it has a result).
pub async fn send_command(
    transport: &dyn Transport,
    to: &NodeId,
    command: &Command,
) -> Result<(), TransportError> {
    transport
        .send(to, COMMANDS, Bytes::from(command.encode()))
        .await
}

/// Sends `result` to `to`.
pub async fn send_result(
    transport: &dyn Transport,
    to: &NodeId,
    result: &CommandResult,
) -> Result<(), TransportError> {
    transport
        .send(to, RESULTS, Bytes::from(result.encode()))
        .await
}

/// Commands arriving from now on, with the member that delivered them; malformed or badly signed
/// ones are dropped.
pub async fn commands(
    transport: &dyn Transport,
) -> Result<BoxStream<'static, (NodeId, Command)>, TransportError> {
    let s = transport.subscribe(COMMANDS).await?;
    Ok(
        s.filter_map(
            |env| async move { Command::decode(&env.payload).ok().map(|c| (env.from, c)) },
        )
        .boxed(),
    )
}

/// Results arriving from now on; malformed or badly signed ones are dropped.
pub async fn results(
    transport: &dyn Transport,
) -> Result<BoxStream<'static, (NodeId, CommandResult)>, TransportError> {
    let s = transport.subscribe(RESULTS).await?;
    Ok(s.filter_map(|env| async move {
        CommandResult::decode(&env.payload)
            .ok()
            .map(|r| (env.from, r))
    })
    .boxed())
}
