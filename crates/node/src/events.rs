use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use rowboat_api::{
    AccountId, CommandId, CommandOutcome, EVENT_BUFFER, EventStream, MailboxId, NodeEvent,
    SendOutcome,
};
use skein_view::{OutcomeKind, PageReport, Touched, ViewObserver};
use tokio::sync::{broadcast, mpsc};

use crate::overlay::Overlay;

/// Fans events out to subscribers; a slow subscriber loses events and gets `Lagged`, it never
/// holds up the sender.
#[derive(Clone)]
pub(crate) struct Hub {
    tx: broadcast::Sender<NodeEvent>,
}

impl Hub {
    pub(crate) fn new() -> Self {
        let (tx, _) = broadcast::channel(EVENT_BUFFER);
        Self { tx }
    }

    pub(crate) fn send(&self, event: NodeEvent) {
        let _ = self.tx.send(event);
    }

    pub(crate) fn subscribe(&self) -> EventStream {
        let rx = self.tx.subscribe();
        Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            match rx.recv().await {
                Ok(e) => Some((e, rx)),
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    Some((NodeEvent::Lagged { missed }, rx))
                }
                Err(broadcast::error::RecvError::Closed) => None,
            }
        }))
        .boxed()
    }
}

/// Send commands the node queued and has not seen settle.
#[derive(Default)]
pub(crate) struct Sends(Mutex<BTreeSet<String>>);

impl Sends {
    pub(crate) fn add(&self, command: &str) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(command.to_owned());
    }

    pub(crate) fn contains(&self, command: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(command)
    }

    pub(crate) fn remove(&self, command: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(command)
    }
}

/// Housekeeping the observer hands to the node's tasks, since it may not block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Chore {
    /// A send settled for good: drop its draft (sent) or bring it back (failed).
    SendDone { command: String, sent: bool },
    /// Messages arrived after the account's first sync: ask the notification policy.
    Arrived {
        account: AccountId,
        added: Vec<skein_view::Added>,
    },
}

/// Turns committed pages into events and settles the overlay.
pub(crate) struct Observer {
    pub hub: Hub,
    pub overlay: Arc<Overlay>,
    pub sends: Arc<Sends>,
    pub chores: mpsc::Sender<Chore>,
    /// Accounts whose first sync finished, as far as committed pages tell.
    pub synced: Arc<Mutex<BTreeSet<String>>>,
}

impl ViewObserver for Observer {
    fn page_applied(&self, report: &PageReport) {
        let Ok(account) = AccountId::new(report.account.clone()) else {
            return;
        };
        let was_synced = {
            let mut synced = self.synced.lock().unwrap_or_else(|e| e.into_inner());
            let was = synced.contains(account.as_str());
            if report.first_sync_completed {
                synced.insert(account.to_string());
            }
            was
        };
        if was_synced && !report.rebuilt && report.added.iter().any(|a| !a.seen) {
            let _ = self.chores.try_send(Chore::Arrived {
                account: account.clone(),
                added: report.added.iter().filter(|a| !a.seen).cloned().collect(),
            });
        }
        if report.messages_added > 0
            || report.head > report.checkpoint
            || report.first_sync_completed
        {
            self.hub.send(NodeEvent::SyncProgress {
                account: account.clone(),
                first_sync_completed: report.first_sync_completed,
                messages: report.messages_added as u64,
                behind: report.head.saturating_sub(report.checkpoint),
            });
        }
        if report.mailboxes_changed {
            self.hub.send(NodeEvent::MailboxesChanged {
                account: account.clone(),
            });
        }
        let touched = match &report.mailboxes {
            Touched::Many => Some(Vec::new()),
            Touched::Some(list) if list.is_empty() => None,
            Touched::Some(list) => Some(
                list.iter()
                    .filter_map(|m| MailboxId::new(m.clone()).ok())
                    .collect(),
            ),
        };
        if let Some(mailboxes) = touched {
            self.hub.send(NodeEvent::MessagesChanged {
                account: account.clone(),
                mailboxes,
            });
        }
        for o in &report.outcomes {
            let Ok(command) = CommandId::new(o.command.clone()) else {
                continue;
            };
            let applied = matches!(o.kind, OutcomeKind::Applied | OutcomeKind::Sent { .. });
            self.overlay
                .settled(account.as_str(), command.as_str(), applied);
            let reason = || o.reason.clone().unwrap_or_else(|| "other".into());
            if self.sends.contains(command.as_str()) {
                let outcome = match o.kind {
                    OutcomeKind::Applied => continue,
                    OutcomeKind::Sent { refused } => SendOutcome::Sent { refused },
                    OutcomeKind::Failed | OutcomeKind::Conflict => {
                        SendOutcome::Failed { reason: reason() }
                    }
                    OutcomeKind::Uncertain => SendOutcome::Uncertain,
                };
                let sent = !matches!(outcome, SendOutcome::Failed { .. });
                self.sends.remove(command.as_str());
                let _ = self.chores.try_send(Chore::SendDone {
                    command: command.to_string(),
                    sent,
                });
                self.hub.send(NodeEvent::SendSettled {
                    account: account.clone(),
                    command,
                    outcome,
                });
                continue;
            }
            let outcome = match o.kind {
                OutcomeKind::Applied | OutcomeKind::Sent { .. } => CommandOutcome::Applied,
                OutcomeKind::Failed => CommandOutcome::Failed { reason: reason() },
                OutcomeKind::Conflict => CommandOutcome::Conflict,
                OutcomeKind::Uncertain => CommandOutcome::Uncertain,
            };
            self.hub.send(NodeEvent::CommandSettled {
                account: account.clone(),
                command,
                outcome,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_slow_subscriber_gets_lagged_and_never_blocks_the_sender() {
        let hub = Hub::new();
        let mut slow = hub.subscribe();
        for _ in 0..(EVENT_BUFFER * 4) {
            hub.send(NodeEvent::AccountsChanged);
        }
        match slow.next().await.unwrap() {
            NodeEvent::Lagged { missed } => assert!(missed >= (EVENT_BUFFER * 3) as u64),
            other => panic!("{other:?}"),
        }
        assert_eq!(slow.next().await.unwrap(), NodeEvent::AccountsChanged);
    }

    #[test]
    fn a_report_becomes_events_and_settles_the_overlay() {
        let hub = Hub::new();
        let mut rx = hub.tx.subscribe();
        let (tx, mut chores) = mpsc::channel(8);
        let sends = Arc::new(Sends::default());
        let send_id = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
        sends.add(send_id);
        let obs = Observer {
            hub: hub.clone(),
            overlay: Arc::new(Overlay::default()),
            sends: sends.clone(),
            chores: tx,
            synced: Arc::default(),
        };
        let account = format!("a{}", "b".repeat(26));
        obs.page_applied(&PageReport {
            account: account.clone(),
            checkpoint: 5,
            head: 9,
            messages_added: 2,
            mailboxes: Touched::Some(vec!["INBOX".into(), "bad\u{1}".into()]),
            outcomes: vec![
                skein_view::CommandOutcome {
                    command: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
                    kind: OutcomeKind::Failed,
                    reason: Some("no_trash".into()),
                },
                skein_view::CommandOutcome {
                    command: send_id.into(),
                    kind: OutcomeKind::Applied,
                    reason: None,
                },
                skein_view::CommandOutcome {
                    command: send_id.into(),
                    kind: OutcomeKind::Sent { refused: 1 },
                    reason: None,
                },
                skein_view::CommandOutcome {
                    command: "../evil".into(),
                    kind: OutcomeKind::Applied,
                    reason: None,
                },
            ],
            ..PageReport::default()
        });
        let mut got = Vec::new();
        while let Ok(e) = rx.try_recv() {
            got.push(e);
        }
        assert_eq!(got.len(), 4, "{got:?}");
        assert!(matches!(
            got[0],
            NodeEvent::SyncProgress {
                behind: 4,
                messages: 2,
                ..
            }
        ));
        assert!(
            matches!(&got[1], NodeEvent::MessagesChanged { mailboxes, .. } if mailboxes.len() == 1)
        );
        assert!(
            matches!(&got[2], NodeEvent::CommandSettled { outcome: CommandOutcome::Failed { reason }, .. } if reason == "no_trash")
        );
        assert!(matches!(
            got[3],
            NodeEvent::SendSettled {
                outcome: SendOutcome::Sent { refused: 1 },
                ..
            }
        ));
        assert_eq!(
            chores.try_recv().unwrap(),
            Chore::SendDone {
                command: send_id.into(),
                sent: true
            }
        );
        assert!(!sends.contains(send_id));
    }

    fn added(n: u8, seen: bool) -> skein_view::Added {
        skein_view::Added {
            mailbox: "INBOX".into(),
            message: format!("{n:02x}").repeat(32),
            seen,
        }
    }

    #[test]
    fn only_arrivals_after_the_first_sync_reach_the_notification_policy() {
        let (tx, mut chores) = mpsc::channel(8);
        let obs = Observer {
            hub: Hub::new(),
            overlay: Arc::new(Overlay::default()),
            sends: Arc::new(Sends::default()),
            chores: tx,
            synced: Arc::default(),
        };
        let account = format!("a{}", "b".repeat(26));
        let report = |first: bool, rebuilt: bool, added: Vec<skein_view::Added>| PageReport {
            account: account.clone(),
            first_sync_completed: first,
            rebuilt,
            messages_added: added.len(),
            added,
            ..PageReport::default()
        };
        obs.page_applied(&report(false, false, vec![added(1, false)]));
        obs.page_applied(&report(true, false, vec![added(2, false)]));
        assert!(chores.try_recv().is_err(), "backfill never notifies");
        obs.page_applied(&report(false, true, vec![added(3, false)]));
        assert!(chores.try_recv().is_err(), "a rebuild never notifies");
        obs.page_applied(&report(false, false, vec![added(4, true), added(5, false)]));
        match chores.try_recv().unwrap() {
            Chore::Arrived { added, .. } => {
                assert_eq!(added.len(), 1);
                assert!(!added[0].seen);
            }
            other => panic!("{other:?}"),
        }
        obs.page_applied(&report(false, false, vec![added(6, true)]));
        assert!(chores.try_recv().is_err(), "read arrivals never notify");
    }
}
