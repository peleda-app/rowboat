//! Writes: flags, labels, moves, copies, deletes, appends and mailboxes.

use async_imap::imap_proto::{RequestId, Response, ResponseCode, Status};
use bytes::Bytes;
use futures::TryStreamExt;
use skein_core::{CommandBody, Flags, ItemRef, MailCapabilities, MailboxRole, Timestamp};
use skein_mail::{MailError, WriteOutcome, basic_capabilities};
use tokio::io::AsyncWriteExt;

use crate::session::ImapSession;
use crate::{convert, labels, quote, timed, uid_set, utf7};

/// UIDs named in one `STORE`, `COPY`, `MOVE` or `EXPUNGE`, which keeps command lines short.
const WRITE_BATCH: usize = 1_000;

/// How a sent command ended when it did not succeed.
enum Ended {
    /// The server answered with a tagged `NO` or `BAD`.
    Refused { code: Code, throttled: bool },
    /// The command may have left; no answer came back.
    Uncertain,
}

impl Ended {
    fn outcome(self) -> Result<WriteOutcome, MailError> {
        match self {
            Ended::Refused {
                throttled: true, ..
            } => Err(MailError::Throttled { retry_after: None }),
            Ended::Refused {
                code: Code::TryCreate,
                ..
            } => failed("no_such_mailbox"),
            Ended::Refused {
                code: Code::AlreadyExists,
                ..
            } => failed("exists"),
            Ended::Refused {
                code: Code::NonExistent,
                ..
            } => Err(MailError::MailboxNotFound),
            Ended::Refused { .. } => Ok(WriteOutcome::Failed {
                reason: "refused".into(),
            }),
            Ended::Uncertain => Ok(WriteOutcome::Uncertain),
        }
    }
}

/// The response codes a refusal is told apart by.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Code {
    None,
    TryCreate,
    /// RFC 5530 `ALREADYEXISTS`.
    AlreadyExists,
    /// RFC 5530 `NONEXISTENT`.
    NonExistent,
}

macro_rules! step {
    ($e:expr) => {
        if let Err(ended) = $e {
            return ended.outcome();
        }
    };
}

/// System flags this provider sets, and keywords that are IMAP atoms.
fn flag_ok(flag: &str) -> bool {
    if let Some(system) = flag.strip_prefix('\\') {
        return ["Seen", "Answered", "Flagged", "Deleted", "Draft"]
            .iter()
            .any(|s| s.eq_ignore_ascii_case(system));
    }
    !flag.is_empty()
        && flag
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"(){%*\"\\]".contains(&b))
}

fn flags_ok(flags: &Flags) -> bool {
    flags.iter().all(flag_ok)
}

fn failed(reason: &str) -> Result<WriteOutcome, MailError> {
    Ok(WriteOutcome::Failed {
        reason: reason.into(),
    })
}

impl ImapSession {
    pub(crate) async fn apply_inner(
        &mut self,
        command: &CommandBody,
        content: Option<Bytes>,
    ) -> Result<WriteOutcome, MailError> {
        let started = std::time::Instant::now();
        let outcome = match command {
            CommandBody::SetFlags {
                mailbox,
                items,
                add,
                remove,
            } => self.set_flags(mailbox, items, add, remove).await,
            CommandBody::Move { from, to, items } => self.move_to(from, to, items).await,
            CommandBody::Delete {
                mailbox,
                items,
                to_trash: false,
            } => self.delete(mailbox, items).await,
            CommandBody::Delete {
                mailbox,
                items,
                to_trash: true,
            } => self.trash_messages(mailbox, items).await,
            CommandBody::Copy { from, to, items } => self.copy(from, to, items).await,
            CommandBody::SetLabels {
                mailbox,
                items,
                add,
                remove,
            } => self.set_labels(mailbox, items, add, remove).await,
            CommandBody::CreateMailbox { path } => self.create_mailbox(path).await,
            CommandBody::RenameMailbox { mailbox, path } => {
                self.rename_mailbox(mailbox, path).await
            }
            CommandBody::DeleteMailbox { mailbox } => self.delete_mailbox(mailbox).await,
            CommandBody::Append {
                mailbox,
                flags,
                received_at,
                ..
            } => self.append(mailbox, flags, *received_at, content).await,
            CommandBody::Refetch { .. }
            | CommandBody::Send { .. }
            | CommandBody::PutObject { .. }
            | CommandBody::DeleteObject { .. }
            | CommandBody::RespondObject { .. }
            | CommandBody::RespondInvitation { .. }
            | CommandBody::Unknown => failed("unsupported"),
        };
        tracing::debug!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            ok = matches!(outcome, Ok(WriteOutcome::Applied)),
            "imap write"
        );
        outcome
    }

    pub(crate) async fn capabilities_inner(&mut self) -> Result<MailCapabilities, MailError> {
        let boxes = self.refresh_names().await?;
        if !self.selected.as_ref().is_some_and(|s| s.writable)
            && let Some(inbox) = boxes
                .iter()
                .find(|b| b.role == Some(MailboxRole::Inbox) && b.selectable)
        {
            match self.select_writable(&inbox.id).await {
                Ok(_) | Err(MailError::MailboxNotFound) => {}
                Err(other) => return Err(other),
            }
        }
        let mut caps = basic_capabilities();
        if let Some(selected) = self.selected.as_ref().filter(|s| s.writable) {
            let mut system: Vec<String> = selected
                .permanent
                .iter()
                .filter(|f| f.starts_with('\\') && flag_ok(f))
                .cloned()
                .collect();
            system.sort();
            system.dedup();
            if !system.is_empty() {
                caps.system_flags = system;
            }
            caps.keywords = selected.keywords;
        }
        caps.copy = true;
        caps.trash = self.trash.is_some() && (self.caps.moves || self.caps.uidplus);
        caps.append_received_at = true;
        caps.mailboxes = true;
        caps.labels = self.caps.gmail;
        Ok(caps)
    }

    /// UIDs of `items` that name messages in the selected mailbox. On Gmail, ids are
    /// `X-GM-MSGID`s and are checked against the server, so a stale UID never hits another
    /// message.
    async fn resolve(&mut self, items: &[ItemRef], validity: u32) -> Result<Vec<u32>, MailError> {
        let mut uids: Vec<u32> = items
            .iter()
            .filter_map(|i| self.plausible(i, validity))
            .collect();
        uids.sort_unstable();
        uids.dedup();
        if !self.caps.gmail || uids.is_empty() {
            return Ok(uids);
        }
        let mut wanted: std::collections::HashMap<u32, Vec<&str>> = Default::default();
        for item in items {
            if let Some(uid) = self.plausible(item, validity) {
                wanted.entry(uid).or_default().push(&item.id);
            }
        }
        let mut out = Vec::new();
        for chunk in uids.chunks(WRITE_BATCH) {
            for fetch in self.uid_fetch(&uid_set(chunk), "(UID X-GM-MSGID)").await? {
                let Some(uid) = fetch.uid else { continue };
                let msgid = fetch.gmail_msg_id().map(u64::to_string);
                let validity_id = format!("{validity}:{uid}");
                if wanted.get(&uid).is_some_and(|ids| {
                    ids.iter()
                        .any(|id| *id == validity_id || Some(*id) == msgid.as_deref())
                }) {
                    out.push(uid);
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    async fn store(&mut self, uids: &[u32], item: &str, flags: &[&str]) -> Result<(), Ended> {
        if flags.is_empty() {
            return Ok(());
        }
        for chunk in uids.chunks(WRITE_BATCH) {
            self.exchange(&format!(
                "UID STORE {} {item} ({})",
                uid_set(chunk),
                flags.join(" ")
            ))
            .await?;
        }
        Ok(())
    }

    async fn expunge(&mut self, uids: &[u32]) -> Result<(), Ended> {
        for chunk in uids.chunks(WRITE_BATCH) {
            self.exchange(&format!("UID EXPUNGE {}", uid_set(chunk)))
                .await?;
        }
        Ok(())
    }

    async fn set_flags(
        &mut self,
        mailbox: &str,
        items: &[ItemRef],
        add: &Flags,
        remove: &Flags,
    ) -> Result<WriteOutcome, MailError> {
        if !flags_ok(add) || !flags_ok(remove) {
            return failed("invalid_flag");
        }
        let validity = self.select_writable(mailbox).await?;
        let uids = self.resolve(items, validity).await?;
        if uids.is_empty() {
            return Ok(WriteOutcome::Applied);
        }
        let removing: Vec<&str> = remove.iter().filter(|f| !add.contains(f)).collect();
        let adding: Vec<&str> = add.iter().collect();
        step!(self.store(&uids, "-FLAGS.SILENT", &removing).await);
        step!(self.store(&uids, "+FLAGS.SILENT", &adding).await);
        Ok(WriteOutcome::Applied)
    }

    async fn move_to(
        &mut self,
        from: &str,
        to: &str,
        items: &[ItemRef],
    ) -> Result<WriteOutcome, MailError> {
        if !self.caps.moves && !self.caps.uidplus {
            return failed("no_uidplus");
        }
        let validity = self.select_writable(from).await?;
        let target = match self.raw_name(to).await {
            Ok(raw) => quote(&raw),
            Err(MailError::MailboxNotFound) => return failed("no_such_mailbox"),
            Err(other) => return Err(other),
        };
        let uids = self.resolve(items, validity).await?;
        if uids.is_empty() {
            return Ok(WriteOutcome::Applied);
        }
        if self.caps.moves {
            for chunk in uids.chunks(WRITE_BATCH) {
                step!(
                    self.exchange(&format!("UID MOVE {} {target}", uid_set(chunk)))
                        .await
                );
            }
            return Ok(WriteOutcome::Applied);
        }
        for chunk in uids.chunks(WRITE_BATCH) {
            step!(
                self.exchange(&format!("UID COPY {} {target}", uid_set(chunk)))
                    .await
            );
        }
        if self
            .store(&uids, "+FLAGS.SILENT", &["\\Deleted"])
            .await
            .is_err()
            || self.expunge(&uids).await.is_err()
        {
            return Ok(WriteOutcome::Uncertain);
        }
        Ok(WriteOutcome::Applied)
    }

    async fn copy(
        &mut self,
        from: &str,
        to: &str,
        items: &[ItemRef],
    ) -> Result<WriteOutcome, MailError> {
        let validity = self.examined(from).await?;
        let target = match self.raw_name(to).await {
            Ok(raw) => quote(&raw),
            Err(MailError::MailboxNotFound) => return failed("no_such_mailbox"),
            Err(other) => return Err(other),
        };
        let uids = self.resolve(items, validity).await?;
        for chunk in uids.chunks(WRITE_BATCH) {
            step!(
                self.exchange(&format!("UID COPY {} {target}", uid_set(chunk)))
                    .await
            );
        }
        Ok(WriteOutcome::Applied)
    }

    async fn trash_messages(
        &mut self,
        mailbox: &str,
        items: &[ItemRef],
    ) -> Result<WriteOutcome, MailError> {
        if self.trash.is_none() {
            self.refresh_names().await?;
        }
        let Some(trash) = self.trash.clone() else {
            return failed("no_trash");
        };
        if trash == mailbox {
            return Ok(WriteOutcome::Applied);
        }
        self.move_to(mailbox, &trash, items).await
    }

    async fn set_labels(
        &mut self,
        mailbox: &str,
        items: &[ItemRef],
        add: &[String],
        remove: &[String],
    ) -> Result<WriteOutcome, MailError> {
        if !self.caps.gmail {
            return failed("unsupported");
        }
        if !add.iter().chain(remove).all(|l| labels::label_ok(l)) {
            return failed("invalid_label");
        }
        let validity = self.select_writable(mailbox).await?;
        let uids = self.resolve(items, validity).await?;
        if uids.is_empty() {
            return Ok(WriteOutcome::Applied);
        }
        let wire = |names: &mut dyn Iterator<Item = &String>| {
            let mut out: Vec<String> = names.map(|l| labels::label_wire(l)).collect();
            out.sort();
            out.dedup();
            out
        };
        let removing = wire(&mut remove.iter().filter(|l| !add.contains(l)));
        let adding = wire(&mut add.iter());
        let removing: Vec<&str> = removing.iter().map(String::as_str).collect();
        let adding: Vec<&str> = adding.iter().map(String::as_str).collect();
        step!(self.store(&uids, "-X-GM-LABELS", &removing).await);
        step!(self.store(&uids, "+X-GM-LABELS", &adding).await);
        Ok(WriteOutcome::Applied)
    }

    /// The hierarchy delimiter from `LIST "" ""`; `None` for a flat server.
    async fn delimiter(&mut self) -> Result<Option<String>, MailError> {
        if let Some(known) = &self.delimiter {
            return Ok(known.clone());
        }
        let names: Vec<_> = timed(self.timeout, async {
            self.session
                .list(Some(""), None)
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?
        .map_err(convert)?;
        let delimiter = names.first().and_then(|n| n.delimiter().map(str::to_owned));
        self.delimiter = Some(delimiter.clone());
        Ok(delimiter)
    }

    /// The server's name for `path`, or `None` when a level is empty, holds the server's
    /// delimiter, wildcards or control characters, or the server is flat and `path` is not.
    async fn encode_path(&mut self, path: &str) -> Result<Option<String>, MailError> {
        let delimiter = self.delimiter().await?;
        let levels: Vec<&str> = path.split('/').collect();
        let bad_level = |level: &&str| {
            level.is_empty()
                || level
                    .chars()
                    .any(|c| c.is_control() || c == '*' || c == '%')
                || delimiter.as_deref().is_some_and(|d| level.contains(d))
        };
        if levels.iter().any(bad_level) || (delimiter.is_none() && levels.len() > 1) {
            return Ok(None);
        }
        let encoded: Vec<String> = levels.iter().map(|l| utf7::encode(l)).collect();
        Ok(Some(encoded.join(delimiter.as_deref().unwrap_or(""))))
    }

    /// The inbox, and on Gmail its system mailboxes, which the server will not rename or delete.
    fn protected(&self, raw: &str, role: Option<MailboxRole>) -> bool {
        raw.eq_ignore_ascii_case("INBOX")
            || (self.caps.gmail
                && matches!(
                    role,
                    Some(
                        MailboxRole::All
                            | MailboxRole::Sent
                            | MailboxRole::Drafts
                            | MailboxRole::Trash
                            | MailboxRole::Junk
                            | MailboxRole::Flagged
                    )
                ))
    }

    fn taken(&self, path: &str) -> bool {
        path.eq_ignore_ascii_case("INBOX") || self.names.get(path).is_some_and(|n| n.selectable)
    }

    /// Runs a mailbox command; the listing is stale afterwards whatever the answer.
    async fn mailbox_command(
        &mut self,
        command: &str,
        id: &str,
    ) -> Result<WriteOutcome, MailError> {
        if self.selected.as_ref().is_some_and(|s| s.id == id) {
            self.selected = None;
        }
        let ended = self.exchange(command).await;
        self.clear_names();
        step!(ended);
        Ok(WriteOutcome::Applied)
    }

    async fn create_mailbox(&mut self, path: &str) -> Result<WriteOutcome, MailError> {
        let Some(raw) = self.encode_path(path).await? else {
            return failed("invalid_name");
        };
        self.refresh_names().await?;
        if self.taken(path) {
            return failed("exists");
        }
        self.mailbox_command(&format!("CREATE {}", quote(&raw)), path)
            .await
    }

    async fn rename_mailbox(
        &mut self,
        mailbox: &str,
        path: &str,
    ) -> Result<WriteOutcome, MailError> {
        self.refresh_names().await?;
        let Some(named) = self.names.get(mailbox) else {
            return Err(MailError::MailboxNotFound);
        };
        let (raw, role) = (named.raw.clone(), named.role);
        if self.protected(&raw, role) {
            return failed("protected");
        }
        if path == mailbox {
            return Ok(WriteOutcome::Applied);
        }
        if self.taken(path) {
            return failed("exists");
        }
        let Some(new) = self.encode_path(path).await? else {
            return failed("invalid_name");
        };
        self.mailbox_command(&format!("RENAME {} {}", quote(&raw), quote(&new)), mailbox)
            .await
    }

    async fn delete_mailbox(&mut self, mailbox: &str) -> Result<WriteOutcome, MailError> {
        self.refresh_names().await?;
        let Some(named) = self.names.get(mailbox) else {
            return Err(MailError::MailboxNotFound);
        };
        let (raw, role) = (named.raw.clone(), named.role);
        if self.protected(&raw, role) {
            return failed("protected");
        }
        self.mailbox_command(&format!("DELETE {}", quote(&raw)), mailbox)
            .await
    }

    async fn delete(
        &mut self,
        mailbox: &str,
        items: &[ItemRef],
    ) -> Result<WriteOutcome, MailError> {
        if !self.caps.uidplus {
            return failed("no_uidplus");
        }
        let validity = self.select_writable(mailbox).await?;
        let uids = self.resolve(items, validity).await?;
        if uids.is_empty() {
            return Ok(WriteOutcome::Applied);
        }
        step!(self.store(&uids, "+FLAGS.SILENT", &["\\Deleted"]).await);
        step!(self.expunge(&uids).await);
        Ok(WriteOutcome::Applied)
    }

    async fn append(
        &mut self,
        mailbox: &str,
        flags: &Flags,
        received_at: Option<Timestamp>,
        content: Option<Bytes>,
    ) -> Result<WriteOutcome, MailError> {
        let Some(content) = content else {
            return failed("missing_content");
        };
        if !flags_ok(flags) {
            return failed("invalid_flag");
        }
        let raw = self.raw_name(mailbox).await?;
        let flags: Vec<&str> = flags.iter().collect();
        let date = received_at
            .and_then(imap_date)
            .map(|d| format!(" \"{d}\""))
            .unwrap_or_default();
        let command = format!(
            "APPEND {} ({}){date} {{{}}}",
            quote(&raw),
            flags.join(" "),
            content.len()
        );
        match timed(self.timeout, self.append_literal(&command, &content)).await {
            Ok(Ok(())) => Ok(WriteOutcome::Applied),
            Ok(Err(Ended::Refused {
                code: Code::TryCreate | Code::NonExistent,
                ..
            })) => {
                self.clear_names();
                Err(MailError::MailboxNotFound)
            }
            Ok(Err(ended)) => ended.outcome(),
            Err(_) => Ok(WriteOutcome::Uncertain),
        }
    }

    /// Sends `command` and reads every response up to its tagged answer.
    async fn exchange(&mut self, command: &str) -> Result<(), Ended> {
        match timed(self.timeout, async {
            let id = self
                .session
                .run_command(command)
                .await
                .map_err(|_| Ended::Uncertain)?;
            self.finish(&id).await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(Ended::Uncertain),
        }
    }

    async fn finish(&mut self, id: &RequestId) -> Result<(), Ended> {
        loop {
            let response = self
                .session
                .read_response()
                .await
                .map_err(|_| Ended::Uncertain)?
                .ok_or(Ended::Uncertain)?;
            if let Response::Done {
                tag,
                status,
                outcome,
            } = response.parsed()
                && tag == id
            {
                return match status {
                    Status::Ok => Ok(()),
                    _ => Err(refused(
                        outcome.code.as_ref(),
                        outcome.information.as_deref(),
                    )),
                };
            }
        }
    }

    /// `APPEND` with the message as a synchronizing literal; a server that refuses before the
    /// continuation answers with its tagged `NO` instead.
    async fn append_literal(&mut self, command: &str, content: &[u8]) -> Result<(), Ended> {
        let id = self
            .session
            .run_command(command)
            .await
            .map_err(|_| Ended::Uncertain)?;
        loop {
            let response = self
                .session
                .read_response()
                .await
                .map_err(|_| Ended::Uncertain)?
                .ok_or(Ended::Uncertain)?;
            match response.parsed() {
                Response::Continue(_) => break,
                Response::Done { tag, outcome, .. } if tag == &id => {
                    return Err(refused(
                        outcome.code.as_ref(),
                        outcome.information.as_deref(),
                    ));
                }
                _ => {}
            }
        }
        let stream = self.session.get_mut();
        let sent = async {
            stream.write_all(content).await?;
            stream.write_all(b"\r\n").await?;
            stream.flush().await
        };
        sent.await.map_err(|_| Ended::Uncertain)?;
        self.finish(&id).await
    }
}

/// imap-proto parses only RFC 3501 codes; the RFC 5530 ones stay at the start of the text.
fn refused(code: Option<&ResponseCode<'_>>, information: Option<&str>) -> Ended {
    let text = information.unwrap_or_default();
    let unknown = |name: &str| {
        text.get(..name.len() + 2)
            .is_some_and(|start| start.eq_ignore_ascii_case(&format!("[{name}]")))
    };
    let code = if matches!(code, Some(ResponseCode::TryCreate)) {
        Code::TryCreate
    } else if unknown("ALREADYEXISTS") {
        Code::AlreadyExists
    } else if unknown("NONEXISTENT") {
        Code::NonExistent
    } else {
        Code::None
    };
    let throttled = code == Code::None && crate::throttle_hint(text);
    Ended::Refused { code, throttled }
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// An IMAP `date-time` in UTC; `None` outside years 1 to 9999.
fn imap_date(at: Timestamp) -> Option<String> {
    let secs = at.0.div_euclid(1000);
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    if !(1..=9999).contains(&year) {
        return None;
    }
    Some(format!(
        "{day:02}-{}-{year:04} {:02}:{:02}:{:02} +0000",
        MONTHS[(month - 1) as usize],
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_internal_dates() {
        assert_eq!(
            imap_date(Timestamp(0)).unwrap(),
            "01-Jan-1970 00:00:00 +0000"
        );
        assert_eq!(
            imap_date(Timestamp(1_795_000_000_000)).unwrap(),
            "18-Nov-2026 11:06:40 +0000"
        );
        assert_eq!(
            imap_date(Timestamp(1_000 * (951_782_400 + 86_399) + 999)).unwrap(),
            "29-Feb-2000 23:59:59 +0000"
        );
        assert_eq!(
            imap_date(Timestamp(-1_000)).unwrap(),
            "31-Dec-1969 23:59:59 +0000"
        );
        assert!(imap_date(Timestamp(i64::MAX)).is_none());
    }

    #[test]
    fn reads_rfc_5530_codes() {
        let code = |text| match refused(None, Some(text)) {
            Ended::Refused { code, .. } => code,
            Ended::Uncertain => unreachable!(),
        };
        assert!(code("[ALREADYEXISTS] Mailbox exists") == Code::AlreadyExists);
        assert!(code("[nonexistent] no such mailbox") == Code::NonExistent);
        assert!(code("Mailbox exists") == Code::None);
    }
}
