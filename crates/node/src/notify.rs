//! New-mail notifications: bento's notification policy over what the mail database holds.
//!
//! The follower's observer hands the node every message a committed page added once the
//! account's first sync finished before that page (backfill never notifies); the node reads each
//! one's envelope and tags from the database, builds bento's `MessageNotice` from stored values
//! only, asks `bento_notify` for a desktop decision and publishes the alerts and silent notices as
//! one [`NodeEvent::NewMail`]. No text of a message reaches the policy or the event.

use std::collections::BTreeMap;

use bento_category::{MessageKind, TopicSet};
use bento_insight_view::{AccountRef, FolderRole, ScoreBucket, SpamAction};
use bento_notify::{
    AccountMode, AccountSettings, LocalClock, MessageNotice, MessageRef, NotifyAction, NotifyInput,
    NotifySettings, PersonPrefs, PresenceSnapshot, RateState, Target, ThreadRef, Urgency,
};
use bento_trust::TrustLevel;
use rowboat_api::{
    AccountId, Attention, MAX_NEW_MAIL, MailboxId, MessageId, NewMail, NodeEvent, ThreadId,
};
use skein_view::Added;

use crate::boot::Core;

/// Arrivals older than this when the node sees them (a move into the inbox, a late listing) do
/// not notify.
pub(crate) const FRESH_MS: i64 = 24 * 60 * 60 * 1000;

/// What one arrival looks like to the policy, read from the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Arrival {
    pub message: String,
    pub thread: i64,
    pub mailbox: String,
    pub role: Option<String>,
    pub unread: bool,
    pub received_at: i64,
    pub server_time: bool,
    pub available: bool,
    pub tags: Vec<String>,
    pub sender_domain: Option<String>,
}

fn folder(role: Option<&str>) -> FolderRole {
    match role {
        Some("inbox") => FolderRole::Inbox,
        Some("archive") => FolderRole::Archive,
        Some("sent") => FolderRole::Sent,
        Some("drafts") => FolderRole::Drafts,
        Some("junk") => FolderRole::Spam,
        Some("trash") => FolderRole::Trash,
        _ => FolderRole::Other,
    }
}

fn kind(tags: &[String]) -> MessageKind {
    let class = tags
        .iter()
        .find_map(|t| t.strip_prefix("category."))
        .and_then(bento::ClassId::new);
    let hint = class.and_then(|c| {
        bento::Taxonomy::embedded()
            .ok()
            .and_then(|t| t.get(&c).map(|d| d.kind))
    });
    hint.and_then(|h| MessageKind::from_name(h.name()).ok())
        .unwrap_or(MessageKind::Notification)
}

/// The policy's input for one arrival. Spam tags, the folder and freshness come from the
/// database; trust is `Unknown` until rinse's authentication facts are stored, so nothing is
/// ever escalated (no VIP, no time-sensitive alert). Freshness needs the server's receive time,
/// never later than now; a message the content pipeline refused counts as suspicious.
pub(crate) fn notice(account: &str, a: &Arrival, now_ms: i64) -> MessageNotice {
    let junk = a.tags.iter().any(|t| t == "spam.junk");
    let suspicious = !a.available || a.tags.iter().any(|t| t == "spam.suspicious");
    MessageNotice {
        message: MessageRef(a.message.clone()),
        account: AccountRef(account.to_owned()),
        thread: Some(ThreadRef(a.thread.to_string())),
        folder: folder(a.role.as_deref()),
        folder_id: Some(a.mailbox.clone()),
        fresh: a.unread
            && a.server_time
            && a.received_at <= now_ms
            && now_ms.saturating_sub(a.received_at) <= FRESH_MS,
        received_at_ms: a.received_at,
        own: a.role.as_deref() == Some("sent"),
        own_unverified: false,
        spam_action: if junk {
            SpamAction::Tag
        } else {
            SpamAction::Accept
        },
        score: if junk {
            ScoreBucket::Spam
        } else if suspicious {
            ScoreBucket::Suspicious
        } else {
            ScoreBucket::NotChecked
        },
        kind: kind(&a.tags),
        topics: TopicSet::default(),
        trust: TrustLevel::Unknown,
        items: Default::default(),
        code: None,
        sender_person: None,
        sender_domain: a.sender_domain.clone(),
        summary_eligible: false,
    }
}

/// The policy's settings for one account: the defaults of bento's NOTIFY.md, the account off
/// when the person turned it off, its skipped mailboxes excluded.
pub(crate) fn settings(account: &str, on: bool, skipped: &[String]) -> NotifySettings {
    NotifySettings {
        accounts: vec![AccountSettings {
            account: AccountRef(account.to_owned()),
            mode: if on {
                AccountMode::Important
            } else {
                AccountMode::Off
            },
            excluded_folders: skipped.to_vec(),
        }],
        ..NotifySettings::default()
    }
}

/// Decides every arrival of one batch, in order, against `rate`; returns what to publish.
pub(crate) fn decide(
    account: &AccountId,
    arrivals: &[Arrival],
    settings: &NotifySettings,
    rate: &mut RateState,
    now_ms: i64,
) -> Vec<NewMail> {
    let clock = LocalClock {
        now_ms,
        weekday: (((now_ms.div_euclid(86_400_000)) + 3).rem_euclid(7)) as u8,
        minute: (now_ms.rem_euclid(86_400_000) / 60_000) as u16,
    };
    let person = PersonPrefs::default();
    let presence = PresenceSnapshot::default();
    let mut out = Vec::new();
    for a in arrivals {
        let message = notice(account.as_str(), a, now_ms);
        let decision = bento_notify::decide_in_place(
            &NotifyInput {
                message: &message,
                settings,
                person: &person,
                presence: &presence,
                clock,
                target: Target::Desktop,
            },
            rate,
        );
        let attention = match decision.action {
            NotifyAction::Alert if decision.urgency > Urgency::Passive => Attention::Alert,
            NotifyAction::Alert => Attention::Silent,
            NotifyAction::Silent => Attention::Silent,
            NotifyAction::None | NotifyAction::Digest => continue,
        };
        let (Ok(id), Ok(thread), Ok(mailbox)) = (
            MessageId::new(a.message.clone()),
            ThreadId::new(a.thread),
            MailboxId::new(a.mailbox.clone()),
        ) else {
            continue;
        };
        if out.len() == MAX_NEW_MAIL {
            break;
        }
        out.push(NewMail {
            message: id,
            thread,
            mailbox,
            attention,
            show_sender: decision.show.sender_name,
            show_subject: decision.show.subject_unlocked,
        });
    }
    out
}

/// Reads the added messages of one page, decides and publishes [`NodeEvent::NewMail`]. Unread
/// arrivals only; a message the database does not hold (yet) is left out.
pub(crate) async fn arrived(core: &Core, account: AccountId, added: Vec<Added>) {
    let Ok(meta) = crate::api::all_metas(core).await.map(|all| {
        all.into_iter()
            .find(|m| m.account == account && !m.removing)
    }) else {
        return;
    };
    let Some(meta) = meta else {
        return;
    };
    let skipped = match skein_core::AccountId::new(account.as_str()) {
        Ok(id) => core
            .accounts
            .get(&core.tenant, &id)
            .await
            .ok()
            .flatten()
            .map(|r| r.exclude)
            .unwrap_or_default(),
        Err(_) => return,
    };
    let store = core.store.clone();
    let id = account.to_string();
    let arrivals = tokio::task::spawn_blocking(move || {
        let roles: BTreeMap<String, Option<String>> = store
            .mailboxes(&id)
            .map(|rows| rows.into_iter().map(|m| (m.id, m.role)).collect())
            .unwrap_or_default();
        added
            .into_iter()
            .filter(|a| !a.seen)
            .filter_map(|a| {
                let detail = store.message(&id, &a.message).ok().flatten()?;
                let e = detail.envelope;
                let sender_domain = match e.from.as_slice() {
                    [one] => one
                        .address
                        .as_deref()
                        .and_then(|a| a.rsplit_once('@'))
                        .map(|(_, d)| d.to_ascii_lowercase()),
                    _ => None,
                };
                Some(Arrival {
                    role: roles.get(&a.mailbox).cloned().flatten(),
                    message: e.id,
                    thread: e.thread,
                    mailbox: a.mailbox,
                    unread: e.unread,
                    received_at: e.received_at.unwrap_or(e.sort_date),
                    server_time: e.received_at.is_some(),
                    available: e.available,
                    tags: e.tags,
                    sender_domain,
                })
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();
    if arrivals.is_empty() {
        return;
    }
    let settings = settings(account.as_str(), meta.notify, &skipped);
    let now = core.clock.now_ms();
    let items = {
        let mut rate = core.notify_rate.lock().unwrap_or_else(|e| e.into_inner());
        decide(&account, &arrivals, &settings, &mut rate, now)
    };
    if !items.is_empty() {
        core.hub.send(NodeEvent::NewMail { account, items });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    fn account() -> AccountId {
        AccountId::new(format!("a{}", "b".repeat(26))).unwrap()
    }

    fn arrival(n: u8) -> Arrival {
        Arrival {
            message: format!("{n:02x}").repeat(32),
            thread: 1 + n as i64,
            mailbox: "INBOX".into(),
            role: Some("inbox".into()),
            unread: true,
            received_at: NOW - 1_000,
            server_time: true,
            available: true,
            tags: vec!["category.person.direct".into()],
            sender_domain: Some("example.com".into()),
        }
    }

    fn run(arrivals: &[Arrival], on: bool) -> Vec<NewMail> {
        let mut rate = RateState::default();
        let settings = settings(account().as_str(), on, &[]);
        decide(&account(), arrivals, &settings, &mut rate, NOW)
    }

    #[test]
    fn a_fresh_personal_message_in_the_inbox_alerts_with_sender_and_subject() {
        let got = run(&[arrival(1)], true);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].attention, Attention::Alert);
        assert!(got[0].show_sender && got[0].show_subject);
        assert_eq!(got[0].thread, ThreadId::new(2).unwrap());
    }

    #[test]
    fn spam_never_notifies() {
        let mut junk = arrival(1);
        junk.tags.push("spam.junk".into());
        let mut in_junk = arrival(2);
        in_junk.role = Some("junk".into());
        assert!(run(&[junk, in_junk], true).is_empty());
    }

    #[test]
    fn mail_the_content_pipeline_refused_is_at_most_silent() {
        let mut refused = arrival(1);
        refused.available = false;
        refused.tags.clear();
        refused.sender_domain = None;
        let got = run(&[refused], true);
        assert!(got.iter().all(|n| n.attention == Attention::Silent));
    }

    #[test]
    fn a_sender_written_date_never_makes_mail_fresh() {
        let mut future = arrival(1);
        future.received_at = NOW + 365 * FRESH_MS;
        let mut no_server_time = arrival(2);
        no_server_time.server_time = false;
        let mut future_from_server = arrival(3);
        future_from_server.received_at = NOW + FRESH_MS;
        assert!(run(&[future, no_server_time, future_from_server], true).is_empty());
    }

    #[test]
    fn suspicious_mail_is_at_most_silent() {
        let mut odd = arrival(1);
        odd.tags.push("spam.suspicious".into());
        let got = run(&[odd], true);
        assert!(got.iter().all(|n| n.attention == Attention::Silent));
    }

    #[test]
    fn an_account_turned_off_never_notifies() {
        assert!(run(&[arrival(1)], false).is_empty());
    }

    #[test]
    fn read_old_and_other_folders_do_not_notify() {
        let mut read = arrival(1);
        read.unread = false;
        let mut old = arrival(2);
        old.received_at = NOW - FRESH_MS - 1;
        let mut sent = arrival(3);
        sent.role = Some("sent".into());
        let mut archived = arrival(4);
        archived.role = Some("archive".into());
        assert!(run(&[read, old, sent, archived], true).is_empty());
    }

    #[test]
    fn skipped_mailboxes_never_notify() {
        let mut rate = RateState::default();
        let settings = settings(account().as_str(), true, &["INBOX".into()]);
        assert!(decide(&account(), &[arrival(1)], &settings, &mut rate, NOW).is_empty());
    }

    #[test]
    fn a_flood_is_rate_limited_and_bounded() {
        let flood: Vec<Arrival> = (0..=255u8).map(arrival).collect();
        let got = run(&flood, true);
        assert!(got.len() <= MAX_NEW_MAIL);
        let alerts = got
            .iter()
            .filter(|n| n.attention == Attention::Alert)
            .count();
        assert!(alerts <= 6, "{alerts} alerts");
    }

    #[test]
    fn forged_ids_are_dropped_not_published() {
        let mut bad = arrival(1);
        bad.message = "../../etc".into();
        assert!(run(&[bad], true).is_empty());
    }
}
