use std::collections::HashMap;
use std::time::Duration;

use async_imap::extensions::idle::IdleResponse;
use async_imap::imap_proto::{MailboxDatum, Response};
use async_imap::types::UnsolicitedResponse;
use async_trait::async_trait;
use skein_mail::{Changed, MailError, MailWatch};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::{Session, convert, timed};

/// What one watching connection listens to.
pub(crate) enum Target {
    /// The mailbox it has selected, by id and by the server's name for it.
    Mailbox { id: String, raw: String },
    /// `NOTIFY` for several mailboxes: mailbox ids by the server's names, answered with `STATUS`.
    Notify { ids: HashMap<String, String> },
}

impl Target {
    fn path_of(&self, response: &Response<'_>) -> Option<String> {
        match (self, response) {
            (
                Target::Mailbox { id: path, .. },
                Response::MailboxData(MailboxDatum::Exists(_))
                | Response::Expunge(_)
                | Response::Fetch(..)
                | Response::Vanished { .. },
            ) => Some(path.clone()),
            (_, Response::MailboxData(MailboxDatum::Status { mailbox, .. })) => {
                self.status_path(mailbox)
            }
            _ => None,
        }
    }

    fn status_path(&self, mailbox: &str) -> Option<String> {
        match self {
            Target::Mailbox { id: path, raw } => (raw == mailbox).then(|| path.clone()),
            Target::Notify { ids: paths } => paths.get(mailbox).cloned(),
        }
    }

    fn unsolicited_path(&self, response: &UnsolicitedResponse) -> Option<String> {
        match response {
            UnsolicitedResponse::Status { mailbox, .. } => self.status_path(mailbox),
            UnsolicitedResponse::Exists(_) | UnsolicitedResponse::Expunge(_) => match self {
                Target::Mailbox { id: path, .. } => Some(path.clone()),
                Target::Notify { .. } => None,
            },
            UnsolicitedResponse::Other(data) => self.path_of(data.parsed()),
            _ => None,
        }
    }
}

/// The `NOTIFY SET` command for `names`: new and expunged messages and flag changes in each.
pub(crate) fn notify_command<'a>(names: impl IntoIterator<Item = &'a str>) -> String {
    let quoted: Vec<String> = names
        .into_iter()
        .map(|name| format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    format!(
        "NOTIFY SET (mailboxes ({}) (MessageNew MessageExpunge FlagChange))",
        quoted.join(" ")
    )
}

/// Watching connections, each in a task of its own, reporting changed mailbox ids. Dropping it
/// stops every connection.
pub(crate) struct ImapWatch {
    changes: mpsc::UnboundedReceiver<Result<String, MailError>>,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl ImapWatch {
    pub(crate) fn start(
        connections: Vec<(Session, Target)>,
        timeout: Duration,
        renew: Duration,
    ) -> Self {
        let (tx, changes) = mpsc::unbounded_channel();
        let (stop, stopped) = watch::channel(false);
        let tasks = connections
            .into_iter()
            .map(|(session, target)| {
                let tx = tx.clone();
                let stopped = stopped.clone();
                tokio::spawn(async move {
                    if let Err(error) = listen(session, &target, &tx, stopped, timeout, renew).await
                    {
                        let _ = tx.send(Err(error));
                    }
                })
            })
            .collect();
        Self {
            changes,
            stop,
            tasks,
        }
    }
}

impl Drop for ImapWatch {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[async_trait]
impl MailWatch for ImapWatch {
    async fn next(&mut self) -> Result<Changed, MailError> {
        let first = self
            .changes
            .recv()
            .await
            .ok_or_else(|| MailError::Network("the watch ended".into()))??;
        let mut mailboxes = vec![first];
        while let Ok(more) = self.changes.try_recv() {
            let path = more?;
            if !mailboxes.contains(&path) {
                mailboxes.push(path);
            }
        }
        Ok(Changed {
            mailboxes: Some(mailboxes),
        })
    }
}

async fn listen(
    mut session: Session,
    target: &Target,
    tx: &mpsc::UnboundedSender<Result<String, MailError>>,
    mut stopped: watch::Receiver<bool>,
    timeout: Duration,
    renew: Duration,
) -> Result<(), MailError> {
    if let Target::Mailbox { raw, .. } = target {
        timed(timeout, session.examine(raw))
            .await?
            .map_err(convert)?;
    }
    loop {
        let mut idle = session.idle();
        timed(timeout, idle.init()).await?.map_err(convert)?;
        let (outcome, stopping) = {
            let (wait, interrupt) = idle.wait_with_timeout(renew);
            let mut wait = std::pin::pin!(wait);
            tokio::select! {
                outcome = &mut wait => (outcome, false),
                _ = stopped.changed() => {
                    drop(interrupt);
                    (wait.await, true)
                }
            }
        };
        let response = outcome.map_err(convert)?;
        session = timed(timeout, idle.done()).await?.map_err(convert)?;
        let mut paths = Vec::new();
        if let IdleResponse::NewData(data) = &response {
            paths.extend(target.path_of(data.parsed()));
        }
        while let Ok(unsolicited) = session.unsolicited_responses.try_recv() {
            paths.extend(target.unsolicited_path(&unsolicited));
        }
        for path in paths {
            if tx.send(Ok(path)).is_err() {
                return Ok(());
            }
        }
        if stopping || *stopped.borrow() {
            let _ = timed(timeout, session.logout()).await;
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_mailbox_names_for_notify() {
        assert_eq!(
            notify_command(["INBOX", "Projekte/\"2025\"", "a\\b"]),
            r#"NOTIFY SET (mailboxes ("INBOX" "Projekte/\"2025\"" "a\\b") (MessageNew MessageExpunge FlagChange))"#
        );
    }
}
