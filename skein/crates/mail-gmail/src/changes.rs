//! `changes`: a paged first listing with `messages.list`, then `history.list` from the history id
//! taken before the listing started.

use std::collections::{BTreeSet, HashMap};

use bytes::Bytes;
use serde::Deserialize;
use skein_core::{ItemRef, Timestamp};
use skein_mail::{Cursor, MailChange, MailError, MailboxChanges};

use crate::cursor::{CursorState, Phase};
use crate::labels::{self, SPAM, TRASH};
use crate::{GmailSession, Meta, http, parse_number, plausible_id, quota};

/// Largest page `messages.list` and `history.list` return.
const MAX_PAGE: usize = 500;

#[derive(Deserialize)]
pub(crate) struct IdOnly {
    pub(crate) id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListPage {
    #[serde(default)]
    pub(crate) messages: Vec<IdOnly>,
    pub(crate) next_page_token: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Wrapped {
    pub(crate) message: IdOnly,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LabelChange {
    pub(crate) message: IdOnly,
    #[serde(default)]
    pub(crate) label_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Record {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) messages_added: Vec<Wrapped>,
    #[serde(default)]
    pub(crate) messages_deleted: Vec<Wrapped>,
    #[serde(default)]
    pub(crate) labels_added: Vec<LabelChange>,
    #[serde(default)]
    pub(crate) labels_removed: Vec<LabelChange>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HistoryPage {
    #[serde(default)]
    pub(crate) history: Vec<Record>,
    pub(crate) next_page_token: Option<String>,
    pub(crate) history_id: Option<String>,
}

pub(crate) async fn changes(
    s: &mut GmailSession,
    mailbox: &str,
    cursor: Option<&Cursor>,
    limit: usize,
) -> Result<MailboxChanges, MailError> {
    s.check_mailbox(mailbox).await?;
    let limit = limit.clamp(1, MAX_PAGE);
    let mut out = Vec::new();
    let decoded = match cursor.map(|c| CursorState::decode(&c.0)) {
        None => None,
        Some(Ok(state)) => Some(state),
        Some(Err(_)) => {
            out.push(MailChange::Reset {
                reason: "unreadable_cursor".into(),
            });
            None
        }
    };
    let mut state = match decoded {
        Some(state) => state,
        None => CursorState::listing(s.profile().await?),
    };
    let more = match state.phase {
        Phase::Tracking => match track(s, mailbox, &mut state, limit, &mut out).await? {
            Some(more) => more,
            None => {
                out.push(MailChange::Reset {
                    reason: "history_expired".into(),
                });
                state = CursorState::listing(s.profile().await?);
                list(s, mailbox, &mut state, limit, &mut out).await?
            }
        },
        Phase::Listing { .. } => list(s, mailbox, &mut state, limit, &mut out).await?,
    };
    tracing::debug!(
        changes = out.len(),
        known = state.len(),
        more,
        "gmail changes"
    );
    Ok(MailboxChanges {
        changes: out,
        cursor: Cursor(Bytes::from(state.encode())),
        more,
    })
}

async fn list_page(
    s: &GmailSession,
    mailbox: &str,
    token: Option<&str>,
    limit: usize,
) -> Result<Option<ListPage>, MailError> {
    let mut url = s.http.endpoint(false, &["messages"]);
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("maxResults", &limit.to_string());
        match mailbox {
            crate::ALL => {
                q.append_pair("includeSpamTrash", "false");
            }
            TRASH | SPAM => {
                q.append_pair("labelIds", mailbox);
                q.append_pair("includeSpamTrash", "true");
            }
            label => {
                q.append_pair("labelIds", label);
                q.append_pair("includeSpamTrash", "false");
            }
        }
        if let Some(t) = token {
            q.append_pair("pageToken", t);
        }
    }
    s.http
        .get_lenient(url, quota::MESSAGES_LIST, http::MAX_JSON)
        .await
}

async fn added(s: &mut GmailSession, id: &str, meta: &Meta) -> Result<MailChange, MailError> {
    let received_at = meta
        .internal_date
        .as_deref()
        .and_then(|d| d.trim().parse::<i64>().ok())
        .map(Timestamp);
    Ok(MailChange::Added {
        item: item(id),
        flags: labels::flags(&meta.label_ids),
        labels: Some(s.names(&meta.label_ids).await?),
        received_at,
    })
}

fn item(id: &str) -> ItemRef {
    ItemRef {
        id: id.to_owned(),
        uid: None,
    }
}

/// One page of the listing. Messages already known are skipped, so a listing restarted after
/// its page token expired reports nothing twice.
async fn list(
    s: &mut GmailSession,
    mailbox: &str,
    state: &mut CursorState,
    limit: usize,
    out: &mut Vec<MailChange>,
) -> Result<bool, MailError> {
    let Phase::Listing { token } = state.phase.clone() else {
        unreachable!("list runs in the listing phase");
    };
    let page = match list_page(s, mailbox, token.as_deref(), limit).await? {
        Some(page) => page,
        None if token.is_some() => list_page(s, mailbox, None, limit)
            .await?
            .ok_or(MailError::MailboxNotFound)?,
        None => return Err(MailError::MailboxNotFound),
    };
    let mut ids: Vec<String> = Vec::with_capacity(page.messages.len());
    for m in page.messages {
        if plausible_id(&m.id) && !state.contains(&m.id) && !ids.contains(&m.id) {
            ids.push(m.id);
        }
    }
    let metas = s.metas(&ids).await?;
    for (id, meta) in ids.iter().zip(metas) {
        let Some(meta) = meta else { continue };
        if labels::member(mailbox, &meta.label_ids) {
            let change = added(s, id, &meta).await?;
            state.insert(id);
            out.push(change);
        }
    }
    Ok(match page.next_page_token.filter(|t| !t.is_empty()) {
        Some(t) => {
            state.phase = Phase::Listing { token: Some(t) };
            true
        }
        None => {
            state.phase = Phase::Tracking;
            false
        }
    })
}

#[derive(Default)]
pub(crate) struct Touch {
    pub(crate) deleted: bool,
    pub(crate) changed: BTreeSet<String>,
}

fn touch<'a>(
    order: &mut Vec<String>,
    touched: &'a mut HashMap<String, Touch>,
    id: String,
) -> Option<&'a mut Touch> {
    if !plausible_id(&id) {
        return None;
    }
    if !touched.contains_key(&id) {
        order.push(id.clone());
    }
    Some(touched.entry(id).or_default())
}

/// Folds history records newer than `start` into the messages they touch, in first-seen order;
/// returns the newest record id, or `start` when every record was older.
pub(crate) fn fold(
    history: Vec<Record>,
    start: u64,
    order: &mut Vec<String>,
    touched: &mut HashMap<String, Touch>,
) -> Result<u64, MailError> {
    let mut last = start;
    for record in history {
        let rid = parse_number(&record.id)?;
        if rid <= start {
            continue;
        }
        last = last.max(rid);
        for w in record.messages_added {
            touch(order, touched, w.message.id);
        }
        for c in record.labels_added.into_iter().chain(record.labels_removed) {
            if let Some(t) = touch(order, touched, c.message.id) {
                t.changed.extend(c.label_ids);
            }
        }
        for w in record.messages_deleted {
            if let Some(t) = touch(order, touched, w.message.id) {
                t.deleted = true;
            }
        }
    }
    Ok(last)
}

/// One page of history. `None` when Gmail no longer has history from the cursor's id.
async fn track(
    s: &mut GmailSession,
    mailbox: &str,
    state: &mut CursorState,
    limit: usize,
    out: &mut Vec<MailChange>,
) -> Result<Option<bool>, MailError> {
    let start = state.history_id;
    let mut last = start;
    let mut order: Vec<String> = Vec::new();
    let mut touched: HashMap<String, Touch> = HashMap::new();
    let mut token: Option<String> = None;
    let (next, newest) = loop {
        let mut url = s.http.endpoint(false, &["history"]);
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("startHistoryId", &start.to_string());
            q.append_pair("maxResults", &limit.to_string());
            if let Some(t) = &token {
                q.append_pair("pageToken", t);
            }
        }
        let Some(page) = s
            .http
            .get_lenient::<HistoryPage>(url, quota::HISTORY_LIST, http::MAX_JSON)
            .await?
        else {
            if token.is_some() {
                return Err(MailError::Protocol(
                    "the Gmail API refused a history page token".into(),
                ));
            }
            return Ok(None);
        };
        last = last.max(fold(page.history, start, &mut order, &mut touched)?);
        let next = page.next_page_token.filter(|t| !t.is_empty());
        if next.is_some() && last == start {
            token = next;
            continue;
        }
        let newest = match &page.history_id {
            Some(h) => parse_number(h)?,
            None => last,
        };
        break (next, newest);
    };

    let wanted: Vec<String> = order
        .iter()
        .filter(|id| {
            let t = &touched[*id];
            !t.deleted && (!state.contains(id) || !t.changed.is_empty())
        })
        .cloned()
        .collect();
    let metas: HashMap<String, Option<Meta>> = wanted
        .iter()
        .cloned()
        .zip(s.metas(&wanted).await?)
        .collect();

    for id in &order {
        let t = &touched[id];
        let before = state.contains(id);
        let meta = match metas.get(id) {
            _ if t.deleted => None,
            Some(meta) => meta.as_ref(),
            None => continue,
        };
        let Some(meta) = meta else {
            if state.remove(id) {
                out.push(MailChange::Removed { item: item(id) });
            }
            continue;
        };
        let after = labels::member(mailbox, &meta.label_ids);
        match (before, after) {
            (false, true) => {
                let change = added(s, id, meta).await?;
                state.insert(id);
                out.push(change);
            }
            (true, false) => {
                state.remove(id);
                out.push(MailChange::Removed { item: item(id) });
            }
            (true, true) => {
                if t.changed.iter().any(|l| labels::is_flag_label(l)) {
                    out.push(MailChange::Flags {
                        item: item(id),
                        flags: labels::flags(&meta.label_ids),
                    });
                }
                if t.changed.iter().any(|l| labels::is_named_label(l)) {
                    out.push(MailChange::Labels {
                        item: item(id),
                        labels: s.names(&meta.label_ids).await?,
                    });
                }
            }
            (false, false) => {}
        }
    }
    state.history_id = match next {
        Some(_) => last,
        None => last.max(newest),
    };
    Ok(Some(next.is_some()))
}
