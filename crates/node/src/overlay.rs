use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;

use rowboat_api::{Envelope, MailboxId};

/// Most entries the overlay keeps; the oldest go first.
pub(crate) const MAX_ENTRIES: usize = 10_000;
/// How long an entry lives without its commands settling.
pub(crate) const TTL_MS: i64 = 10 * 60 * 1000;

/// What the node expects a message to look like once its queued commands are applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Expect {
    pub read: Option<bool>,
    pub flagged: Option<bool>,
    pub moved_to: Option<MailboxId>,
    pub gone: bool,
}

#[derive(Debug, Clone)]
struct Entry {
    expect: Expect,
    pending: BTreeSet<String>,
    applied: bool,
    at: i64,
}

type Key = (String, String);

/// Pending changes per `(account, message)`, applied to every read so a mark-read shows at once.
///
/// An entry is dropped when every command it waits for failed, conflicted or was cancelled (the
/// change did not happen); when every one was applied and the database already shows the
/// expected state; after [`TTL_MS`]; or when [`MAX_ENTRIES`] is exceeded, oldest first.
#[derive(Default)]
pub(crate) struct Overlay {
    inner: Mutex<(BTreeMap<Key, Entry>, VecDeque<Key>)>,
}

impl Overlay {
    pub(crate) fn expect(
        &self,
        account: &str,
        message: &str,
        change: &Expect,
        command: &str,
        now: i64,
    ) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (map, order) = &mut *guard;
        let key = (account.to_owned(), message.to_owned());
        let entry = map.entry(key.clone()).or_insert_with(|| {
            order.push_back(key.clone());
            Entry {
                expect: Expect::default(),
                pending: BTreeSet::new(),
                applied: false,
                at: now,
            }
        });
        if change.read.is_some() {
            entry.expect.read = change.read;
        }
        if change.flagged.is_some() {
            entry.expect.flagged = change.flagged;
        }
        if change.moved_to.is_some() {
            entry.expect.moved_to.clone_from(&change.moved_to);
        }
        entry.expect.gone |= change.gone;
        entry.pending.insert(command.to_owned());
        entry.applied = false;
        entry.at = now;
        while map.len() > MAX_ENTRIES {
            match order.pop_front() {
                Some(old) => {
                    map.remove(&old);
                }
                None => break,
            }
        }
    }

    /// A command settled: `applied` when the provider applied it.
    pub(crate) fn settled(&self, account: &str, command: &str, applied: bool) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (map, _) = &mut *guard;
        map.retain(|(a, _), e| {
            if a != account || !e.pending.remove(command) {
                return true;
            }
            if !applied {
                return false;
            }
            e.applied = true;
            true
        });
    }

    /// Drops entries older than [`TTL_MS`].
    pub(crate) fn expire(&self, now: i64) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (map, order) = &mut *guard;
        map.retain(|_, e| now - e.at < TTL_MS);
        order.retain(|k| map.contains_key(k));
    }

    /// Applies the pending changes to `env`; `None` when the message is expected gone from the
    /// listed scope (`scope_mailboxes` is the mailboxes a list covers, `None` for any).
    pub(crate) fn apply(
        &self,
        mut env: Envelope,
        scope_mailboxes: Option<&[MailboxId]>,
    ) -> Option<Envelope> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (map, _) = &mut *guard;
        let key = (env.account.to_string(), env.id.to_string());
        let Some(entry) = map.get(&key) else {
            return Some(env);
        };
        let x = entry.expect.clone();
        let agrees = x.read.is_none_or(|r| env.unread != r)
            && x.flagged.is_none_or(|f| env.flagged == f)
            && x.moved_to
                .as_ref()
                .is_none_or(|m| env.mailboxes == [m.clone()])
            && !x.gone;
        if entry.applied && entry.pending.is_empty() && agrees {
            map.remove(&key);
            return Some(env);
        }
        if x.gone {
            return None;
        }
        if let Some(read) = x.read {
            env.unread = !read;
        }
        if let Some(flagged) = x.flagged {
            env.flagged = flagged;
        }
        if let Some(to) = x.moved_to {
            env.mailboxes = vec![to.clone()];
            if let Some(scope) = scope_mailboxes
                && !scope.contains(&to)
            {
                return None;
            }
        }
        Some(env)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().unwrap().0.len()
    }
}

#[cfg(test)]
mod tests {
    use rowboat_api::{AccountId, MessageId, ThreadId};

    use super::*;

    fn env(n: u8) -> Envelope {
        Envelope {
            account: AccountId::new(format!("a{}", "b".repeat(26))).unwrap(),
            id: MessageId::new(format!("{n:02x}").repeat(32)).unwrap(),
            thread: ThreadId::new(1).unwrap(),
            subject: None,
            from: vec![],
            to: vec![],
            cc: vec![],
            date: None,
            received_at: None,
            sort_date: 1,
            size: 1,
            has_attachments: false,
            snippet: None,
            unread: true,
            flagged: false,
            mailboxes: vec![MailboxId::new("INBOX").unwrap()],
            tags: vec![],
            available: true,
        }
    }

    fn read() -> Expect {
        Expect {
            read: Some(true),
            ..Expect::default()
        }
    }

    #[test]
    fn a_pending_read_shows_until_the_database_agrees() {
        let o = Overlay::default();
        let e = env(1);
        o.expect(e.account.as_str(), e.id.as_str(), &read(), "c1", 0);
        assert!(!o.apply(e.clone(), None).unwrap().unread);
        o.settled(e.account.as_str(), "c1", true);
        assert!(
            !o.apply(e.clone(), None).unwrap().unread,
            "applied, database behind"
        );
        assert_eq!(o.len(), 1);
        let mut synced = e.clone();
        synced.unread = false;
        assert!(!o.apply(synced, None).unwrap().unread);
        assert_eq!(o.len(), 0);
    }

    #[test]
    fn a_failed_command_reverts_and_moves_hide_from_their_source() {
        let o = Overlay::default();
        let e = env(2);
        let inbox = [MailboxId::new("INBOX").unwrap()];
        o.expect(
            e.account.as_str(),
            e.id.as_str(),
            &Expect {
                moved_to: Some(MailboxId::new("Archive").unwrap()),
                ..Expect::default()
            },
            "c1",
            0,
        );
        assert!(o.apply(e.clone(), Some(&inbox)).is_none());
        assert_eq!(
            o.apply(e.clone(), None).unwrap().mailboxes[0].as_str(),
            "Archive"
        );
        o.settled(e.account.as_str(), "c1", false);
        assert!(o.apply(e.clone(), Some(&inbox)).is_some());
        assert_eq!(o.len(), 0);
    }

    #[test]
    fn entries_expire_and_are_capped() {
        let o = Overlay::default();
        let e = env(3);
        o.expect(e.account.as_str(), e.id.as_str(), &read(), "c", 0);
        o.expire(TTL_MS - 1);
        assert_eq!(o.len(), 1);
        o.expire(TTL_MS);
        assert_eq!(o.len(), 0);
        for i in 0..(MAX_ENTRIES + 5) {
            o.expect("a", &format!("{i}"), &read(), "c", 0);
        }
        assert_eq!(o.len(), MAX_ENTRIES);
    }
}
