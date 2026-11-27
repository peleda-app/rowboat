use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_core::{
    AccountId, Command, CommandBody, EventBody, FencingToken, Flags, RefusedRecipient,
    SendEnvelope, SentCopy, SyncOutcome, TenantId, Timestamp,
};
use skein_itip::imip::{Outgoing, compose, describe};
use skein_mail::{MailError, MailProvider, MailSession, WriteOutcome};
use skein_send::{Envelope, RecipientResult, SendError, SendReport, Sender};
use skein_storage::{Expect, StorageError};
use tracing::{info, warn};

use crate::message_id;
use crate::state::command_marker;
use crate::status::{Area, send_outcome};
use crate::{AccountConfig, Engine, EngineError};

/// Commands read from the queue per page.
const PAGE: usize = 100;
/// Commands looked at in one run at most; the rest wait for the next run.
const MAX_PER_RUN: usize = 2_000;

/// What one run of queued commands did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandReport {
    /// Commands applied.
    pub applied: u64,
    /// Commands that failed for good or conflicted.
    pub failed: u64,
    /// Commands whose outcome is unknown.
    pub uncertain: u64,
    /// Sends left queued: scheduled for later, or waiting to be tried again.
    pub waiting: u64,
    /// The earliest time a waiting send is due, when one is waiting.
    pub next_due: Option<Timestamp>,
}

/// Where the engine finds an account's sending service. Implementations resolve credentials
/// when a message is sent, which only happens on the account's owner.
#[async_trait]
pub trait SenderDirectory: Send + Sync {
    /// The account's sender; `Ok(None)` when it has none. An error is treated like an error of
    /// the sender itself (nothing was sent).
    async fn sender(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Option<Arc<dyn Sender>>, SendError>;
}

/// When sends go out, and how often and how fast a send that was certainly not sent is tried
/// again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendPolicy {
    /// The undo window in milliseconds: a send (`send`, `respond_invitation`) is not handed over
    /// before its `created_at` plus this, and stays queued until then, so cancelling it through
    /// the API still stops it. A `send_at` earlier than the end of the window is moved to it; a
    /// later one is kept. Dry runs do not wait for it. Zero or less turns the window off and sends
    /// at once (or at `send_at`).
    pub undo_ms: i64,
    /// Tries in all, the first included; after the last one fails the command fails with
    /// `gave_up`.
    pub max_attempts: u32,
    /// The wait after the first failed try; it doubles after every further one.
    pub first_delay_ms: i64,
    /// The longest wait between tries.
    pub max_delay_ms: i64,
}

impl Default for SendPolicy {
    /// No undo window; eight tries, one minute apart at first, at most an hour apart.
    fn default() -> Self {
        Self {
            undo_ms: 0,
            max_attempts: 8,
            first_delay_ms: 60_000,
            max_delay_ms: 3_600_000,
        }
    }
}

/// The longest wait a sending service may ask for before the next try.
const MAX_RETRY_AFTER_MS: i64 = 3_600_000;

impl SendPolicy {
    /// The time before which `command` must not be sent: its `send_at` or the end of the undo
    /// window, whichever is later. `None` when nothing holds it back or it does not send.
    pub(crate) fn not_before(&self, command: &Command) -> Option<Timestamp> {
        let (send_at, dry_run) = match &command.body {
            CommandBody::Send {
                send_at, dry_run, ..
            } => (*send_at, *dry_run),
            CommandBody::RespondInvitation { .. } => (None, false),
            _ => return None,
        };
        let window =
            (self.undo_ms > 0 && !dry_run).then(|| command.created_at.plus_ms(self.undo_ms));
        send_at.max(window)
    }

    /// The wait before the next try: the policy's backoff, or the wait the service asked for
    /// when that is longer, the latter capped at an hour.
    fn retry_delay(&self, failures: u32, error: &SendError) -> i64 {
        let asked = error.retry_after().map_or(0, |d| {
            i64::try_from(d.as_millis())
                .unwrap_or(i64::MAX)
                .min(MAX_RETRY_AFTER_MS)
        });
        self.delay(failures).max(asked)
    }

    fn delay(&self, failures: u32) -> i64 {
        let factor = 1i64 << failures.saturating_sub(1).min(30);
        self.first_delay_ms
            .saturating_mul(factor)
            .min(self.max_delay_ms)
            .max(0)
    }
}

/// Tries of a send so far, kept at `sending/{account}/{command}` while it waits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Attempts {
    failures: u32,
    next_at: Timestamp,
}

fn attempts_path(account: &AccountId, id: &str) -> String {
    format!("sending/{account}/{id}")
}

enum Step {
    Done {
        outcome: WriteOutcome,
        result: Option<EventBody>,
    },
    Waiting(Timestamp),
    Cancelled,
}

fn failed(reason: &str) -> Step {
    Step::Done {
        outcome: WriteOutcome::Failed {
            reason: reason.to_owned(),
        },
        result: None,
    }
}

fn wait(report: &mut CommandReport, at: Timestamp) {
    report.waiting += 1;
    report.next_due = Some(report.next_due.map_or(at, |d| d.min(at)));
}

fn repeatable(body: &CommandBody) -> bool {
    matches!(
        body,
        CommandBody::SetFlags { .. } | CommandBody::SetLabels { .. } | CommandBody::Refetch { .. }
    )
}

/// Marks every queued command of `account` that cannot be repeated safely (move, delete, append,
/// send; not flag and label changes or refetches) as started, unless it already has a marker, so
/// that the next run reports it as uncertain instead of carrying it out. For a node that takes an
/// account over from a holder that may still have been running the same queue when it went
/// silent: an uncertain outcome is shown, nothing runs twice. Returns how many were marked.
/// Idempotent; a command cancelled meanwhile keeps its cancellation.
pub async fn presume_started(
    storage: &skein_storage::Storage,
    tenant: &TenantId,
    account: &AccountId,
) -> Result<usize, EngineError> {
    let mut after: Option<skein_core::CommandId> = None;
    let mut marked = 0;
    loop {
        let pending = storage
            .commands
            .pending_after(tenant, account, after.as_ref(), PAGE)
            .await?;
        let Some(last) = pending.last() else {
            break;
        };
        after = Some(last.id.clone());
        for command in &pending {
            if command.body.is_collection_command() || repeatable(&command.body) {
                continue;
            }
            let marker = command_marker(account, command.id.as_str());
            match storage
                .control
                .put(
                    tenant,
                    &marker,
                    Bytes::from_static(b"started"),
                    Expect::Absent,
                )
                .await
            {
                Ok(_) => marked += 1,
                Err(StorageError::Conflict) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if pending.len() < PAGE {
            break;
        }
    }
    Ok(marked)
}

fn refused(command: &Command, results: &[RecipientResult], copy: Option<SentCopy>) -> EventBody {
    delivered(command, &SendReport::new(results.to_vec()), copy)
}

fn delivered(command: &Command, report: &SendReport, copy: Option<SentCopy>) -> EventBody {
    EventBody::SendResult {
        command: command.id.clone(),
        refused: report
            .refused()
            .map(|(address, r)| RefusedRecipient {
                address: address.to_owned(),
                code: r.code,
                permanent: r.permanent,
            })
            .collect(),
        sent_copy: copy,
        message_id: report
            .message_id
            .clone()
            .filter(|id| message_id::well_formed(id)),
        provider_message_id: report.provider_message_id.clone().filter(|id| {
            !id.is_empty() && id.len() <= 256 && id.bytes().all(|b| b.is_ascii_graphic())
        }),
        dry_run: false,
    }
}

async fn open<'a>(
    slot: &'a mut Option<Box<dyn MailSession>>,
    provider: &dyn MailProvider,
) -> Result<&'a mut Box<dyn MailSession>, MailError> {
    if slot.is_none() {
        *slot = Some(provider.connect().await?);
    }
    Ok(slot.as_mut().expect("just connected"))
}

impl Engine {
    /// Sends `send` commands through the accounts' senders from `senders`. Without it, every
    /// `send` fails with `no_sender`.
    pub fn with_senders(mut self, senders: Arc<dyn SenderDirectory>) -> Self {
        self.senders = Some(senders);
        self
    }

    /// Tries sends that were certainly not sent again by `policy` instead of the default.
    pub fn with_send_policy(mut self, policy: SendPolicy) -> Self {
        self.send_policy = policy;
        self
    }

    /// Runs the account's queued commands in submission order, if this node owns the account.
    ///
    /// Before a command that cannot be repeated safely (move, delete, append, send) reaches the
    /// provider, a marker is stored; if the node crashes before the outcome is in the log, the
    /// next run reports the command as uncertain instead of running it twice. Once the outcome is in
    /// the log the marker says so, and a crash before the command leaves the queue does not record
    /// a second outcome.
    ///
    /// A send whose `send_at` or undo window ([`SendPolicy::undo_ms`]) is still ahead stays
    /// queued and is skipped, without holding up the commands behind it, and is counted in
    /// [`CommandReport::waiting`]; until it is due, cancelling it through the API stops it. A send
    /// that certainly did not go out for a reason that may pass (an unreachable service, a
    /// temporary refusal, throttling) stays queued and is tried again by the engine's
    /// [`SendPolicy`], never sooner than a wait the service asked for (at most an hour), then
    /// fails with `gave_up`. A send that may have gone out is reported as uncertain and never sent
    /// again. When the sending service does not keep a copy in Sent and the command names a
    /// mailbox, the message is appended there after it was sent. A dry run makes every check of a
    /// real send and records `write_applied` with a `send_result` marked `dry_run`, without
    /// handing anything over or saving a copy.
    pub async fn run_commands(
        &self,
        config: &AccountConfig,
        provider: &dyn MailProvider,
    ) -> Result<CommandReport, EngineError> {
        let lease = self.lease(config).await?;
        let mut report = CommandReport::default();
        let now = Timestamp::now();
        let mut session: Option<Box<dyn MailSession>> = None;
        let mut after: Option<skein_core::CommandId> = None;
        let mut seen = 0usize;
        let mut any = false;
        loop {
            let pending = self
                .storage
                .commands
                .pending_after(&config.tenant, &config.account, after.as_ref(), PAGE)
                .await?;
            if pending.is_empty() || seen >= MAX_PER_RUN {
                break;
            }
            any = true;
            after = pending.last().map(|c| c.id.clone());
            seen += pending.len();
            for command in pending {
                if command.body.is_collection_command() {
                    continue;
                }
                if let Some(at) = self.send_policy.not_before(&command)
                    && at > now
                {
                    wait(&mut report, at);
                    continue;
                }
                let marker = command_marker(&config.account, command.id.as_str());
                let mark = self
                    .storage
                    .control
                    .get(&config.tenant, &marker)
                    .await?
                    .map(|(b, _)| b);
                if matches!(mark.as_deref(), Some(b"done") | Some(b"cancelled")) {
                    self.finish(config, &command).await?;
                    continue;
                }
                let started = mark.is_some();
                let (outcome, result) = if command.body.is_send() {
                    match self
                        .send(
                            config,
                            &command,
                            started,
                            &mut session,
                            provider,
                            now,
                            lease.fence,
                        )
                        .await?
                    {
                        Step::Done { outcome, result } => (outcome, result),
                        Step::Cancelled => {
                            self.finish(config, &command).await?;
                            continue;
                        }
                        Step::Waiting(at) => {
                            wait(&mut report, at);
                            continue;
                        }
                    }
                } else if let CommandBody::Refetch { mailbox, item } = &command.body {
                    let raw = match open(&mut session, provider)
                        .await?
                        .fetch(mailbox, std::slice::from_ref(item))
                        .await
                    {
                        Ok(raw) => raw,
                        Err(MailError::MailboxNotFound) => Vec::new(),
                        Err(e) => return Err(e.into()),
                    };
                    let outcome = match raw.into_iter().next() {
                        Some(msg) => {
                            self.storage.blobs.put(&config.tenant, msg.bytes).await?;
                            WriteOutcome::Applied
                        }
                        None => WriteOutcome::Failed {
                            reason: "not_found".into(),
                        },
                    };
                    (outcome, None)
                } else if started && !repeatable(&command.body) {
                    (WriteOutcome::Uncertain, None)
                } else {
                    let content = self.content(config, &command).await?;
                    let opened = open(&mut session, provider).await?;
                    if !self.mark_started(config, lease.fence, &marker).await? {
                        self.finish(config, &command).await?;
                        continue;
                    }
                    let outcome = match opened.apply(&command.body, content).await {
                        Ok(o) => o,
                        Err(e) if e.connection_lost() => WriteOutcome::Uncertain,
                        Err(MailError::MailboxNotFound) => WriteOutcome::Failed {
                            reason: "mailbox_not_found".into(),
                        },
                        Err(e) => {
                            if matches!(
                                e,
                                MailError::Auth
                                    | MailError::Config(_)
                                    | MailError::Insecure(_)
                                    | MailError::Tls(_)
                                    | MailError::Quota
                                    | MailError::Throttled { .. }
                            ) {
                                self.storage
                                    .control
                                    .delete(&config.tenant, &marker, Expect::Any)
                                    .await?;
                            }
                            return Err(e.into());
                        }
                    };
                    (outcome, None)
                };
                let body = match &outcome {
                    WriteOutcome::Applied => {
                        report.applied += 1;
                        EventBody::WriteApplied {
                            command: command.id.clone(),
                        }
                    }
                    WriteOutcome::Conflict => {
                        report.failed += 1;
                        EventBody::Conflict {
                            command: command.id.clone(),
                            server_blob: None,
                        }
                    }
                    WriteOutcome::Failed { reason } => {
                        report.failed += 1;
                        EventBody::WriteFailed {
                            command: command.id.clone(),
                            reason: reason.clone(),
                        }
                    }
                    WriteOutcome::Uncertain => {
                        report.uncertain += 1;
                        EventBody::WriteUncertain {
                            command: command.id.clone(),
                        }
                    }
                };
                let mut events = vec![self.event(config, format!("command-{}", command.id), body)];
                if let Some(result) = result {
                    events.push(self.event(config, format!("command-{}-send", command.id), result));
                }
                for event in &mut events {
                    event.origin = Some(command.id.clone());
                    event.trace = command.trace.clone();
                }
                self.append(config, lease.fence, events).await?;
                self.storage
                    .control
                    .put(
                        &config.tenant,
                        &marker,
                        Bytes::from_static(b"done"),
                        Expect::Any,
                    )
                    .await?;
                self.finish(config, &command).await?;
            }
        }
        if !any {
            return Ok(report);
        }
        if let Some(mut session) = session {
            let _ = session.logout().await;
        }
        let head = self
            .storage
            .log
            .head(&config.tenant, &config.account)
            .await?;
        let metrics = skein_metrics::global();
        metrics.commands_applied.add(report.applied);
        metrics.commands_failed.add(report.failed);
        metrics.commands_uncertain.add(report.uncertain);
        info!(
            account = %config.account,
            applied = report.applied,
            failed = report.failed,
            uncertain = report.uncertain,
            waiting = report.waiting,
            "commands finished"
        );
        self.hint(config, head).await;
        Ok(report)
    }

    /// Records that a command is about to reach the provider. Returns `false` when it was
    /// cancelled through the API first; a marker left by an earlier attempt counts as started.
    async fn mark_started(
        &self,
        config: &AccountConfig,
        fence: FencingToken,
        marker: &str,
    ) -> Result<bool, EngineError> {
        self.check_lease(config, fence)?;
        match self
            .storage
            .control
            .put(
                &config.tenant,
                marker,
                Bytes::from_static(b"started"),
                Expect::Absent,
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(StorageError::Conflict) => {
                let current = self.storage.control.get(&config.tenant, marker).await?;
                Ok(!matches!(current, Some((b, _)) if &b[..] == b"cancelled"))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Takes a command whose outcome is in the log out of the queue and drops its records.
    async fn finish(&self, config: &AccountConfig, command: &Command) -> Result<(), EngineError> {
        self.storage
            .commands
            .complete(&config.tenant, &config.account, &command.id)
            .await?;
        let paths = [
            attempts_path(&config.account, command.id.as_str()),
            command_marker(&config.account, command.id.as_str()),
        ];
        for path in paths {
            match self
                .storage
                .control
                .delete(&config.tenant, &path, Expect::Any)
                .await
            {
                Ok(()) | Err(StorageError::Conflict) => {}
                Err(e) => warn!(error = %e, "command record not removed"),
            }
        }
        Ok(())
    }

    async fn content(
        &self,
        config: &AccountConfig,
        command: &Command,
    ) -> Result<Option<Bytes>, EngineError> {
        match &command.body {
            CommandBody::Append { blob, .. } => {
                Ok(self.storage.blobs.get(&config.tenant, blob).await?)
            }
            _ => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send(
        &self,
        config: &AccountConfig,
        command: &Command,
        started: bool,
        session: &mut Option<Box<dyn MailSession>>,
        provider: &dyn MailProvider,
        now: Timestamp,
        fence: FencingToken,
    ) -> Result<Step, EngineError> {
        let (save_to_sent, dry_run) = match &command.body {
            CommandBody::Send {
                save_to_sent,
                dry_run,
                ..
            } => (save_to_sent, *dry_run),
            CommandBody::RespondInvitation { save_to_sent, .. } => (save_to_sent, false),
            _ => return Ok(failed("unsupported")),
        };
        if started && !dry_run {
            return Ok(Step::Done {
                outcome: WriteOutcome::Uncertain,
                result: None,
            });
        }
        let path = attempts_path(&config.account, command.id.as_str());
        let attempts: Attempts = match self.storage.control.get(&config.tenant, &path).await? {
            Some((bytes, _)) => serde_json::from_slice(&bytes).unwrap_or_default(),
            None => Attempts::default(),
        };
        if attempts.next_at > now {
            return Ok(Step::Waiting(attempts.next_at));
        }
        let (envelope, prepared) = match &command.body {
            CommandBody::Send { envelope, .. } => (envelope.clone(), None),
            _ => match self.invitation_reply(config, command).await? {
                Ok((envelope, bytes)) => (envelope, Some(bytes)),
                Err(reason) => return Ok(failed(reason)),
            },
        };
        if envelope.check().is_err() {
            return Ok(failed("invalid_envelope"));
        }
        let Some(senders) = &self.senders else {
            return Ok(failed("no_sender"));
        };
        let sender = match senders.sender(&config.tenant, &config.account).await {
            Ok(Some(sender)) => sender,
            Ok(None) => return Ok(failed("no_sender")),
            Err(e) => {
                self.record_send(config, fence, &Err(&e)).await;
                return self.not_sent(config, command, &path, attempts, &e).await;
            }
        };
        let bytes = match (prepared, &command.body) {
            (Some(bytes), _) => bytes,
            (None, CommandBody::Send { blob, .. }) => {
                match self.storage.blobs.get(&config.tenant, blob).await? {
                    Some(bytes) => bytes,
                    None => return Ok(failed("blob_missing")),
                }
            }
            (None, _) => return Ok(failed("unsupported")),
        };
        let handover = Envelope {
            mail_from: envelope.from.clone(),
            recipients: envelope.to.clone(),
            dsn: envelope.dsn.clone(),
            envid: Some(command.id.to_string()),
        };
        if handover.validate(&bytes).is_err() {
            return Ok(failed("invalid_message"));
        }
        let marker = command_marker(&config.account, command.id.as_str());
        if !self.mark_started(config, fence, &marker).await? {
            return Ok(Step::Cancelled);
        }
        if dry_run {
            info!(account = %config.account, command = %command.id, "send dry run passed");
            return Ok(Step::Done {
                outcome: WriteOutcome::Applied,
                result: Some(EventBody::SendResult {
                    command: command.id.clone(),
                    refused: Vec::new(),
                    sent_copy: None,
                    message_id: None,
                    provider_message_id: None,
                    dry_run: true,
                }),
            });
        }
        let sent = sender.send(&handover, &bytes).await;
        self.record_send(config, fence, &sent.as_ref().map(|_| ()))
            .await;
        match sent {
            Ok(sent) => {
                let copy = if sender.saves_to_sent() {
                    Some(SentCopy::Provider)
                } else if let Some(mailbox) = save_to_sent {
                    let copy = sent
                        .message_id
                        .as_deref()
                        .and_then(|id| message_id::rewrite(&bytes, id))
                        .map_or(bytes, Bytes::from);
                    Some(
                        self.save_copy(config, command, mailbox, copy, session, provider)
                            .await,
                    )
                } else {
                    None
                };
                Ok(Step::Done {
                    outcome: WriteOutcome::Applied,
                    result: Some(delivered(command, &sent, copy)),
                })
            }
            Err(e) if e.may_have_been_sent() => {
                warn!(account = %config.account, command = %command.id, "send outcome unknown");
                Ok(Step::Done {
                    outcome: WriteOutcome::Uncertain,
                    result: None,
                })
            }
            Err(e) => {
                let step = self.not_sent(config, command, &path, attempts, &e).await?;
                if matches!(step, Step::Waiting(_)) {
                    self.storage
                        .control
                        .delete(&config.tenant, &marker, Expect::Any)
                        .await?;
                }
                Ok(step)
            }
        }
    }

    async fn record_send(
        &self,
        config: &AccountConfig,
        fence: FencingToken,
        result: &Result<(), &SendError>,
    ) {
        let outcome = match result {
            Ok(()) => Some(SyncOutcome::Ok),
            Err(e) => send_outcome(e),
        };
        if let Some(outcome) = outcome {
            self.record_status(config, fence, Area::Send, outcome, false)
                .await;
        }
    }

    /// The iMIP `REPLY` a `respond_invitation` sends, built the same way on every try: its
    /// envelope and bytes, or why it cannot be built.
    async fn invitation_reply(
        &self,
        config: &AccountConfig,
        command: &Command,
    ) -> Result<Result<(SendEnvelope, Bytes), &'static str>, EngineError> {
        let CommandBody::RespondInvitation {
            invitation,
            answer,
            attendee,
            comment,
            ..
        } = &command.body
        else {
            return Ok(Err("unsupported"));
        };
        if !self.inspect_messages {
            return Ok(Err("unsupported"));
        }
        let Some(raw) = self.storage.blobs.get(&config.tenant, invitation).await? else {
            return Ok(Err("blob_missing"));
        };
        let built = (|| {
            let found = skein_itip::imip::read(&raw).map_err(|e| e.reason())?;
            let facts = skein_itip::facts(&found.calendar).map_err(|e| e.reason())?;
            let who = match attendee {
                Some(a) => skein_itip::address(a),
                None => {
                    let mut invited = facts
                        .attendees
                        .iter()
                        .filter(|a| found.recipients.contains(&a.address));
                    match (invited.next(), invited.next()) {
                        (Some(one), None) => one.address.clone(),
                        _ => return Err("attendee_required"),
                    }
                }
            };
            let organizer = facts.organizer.clone().ok_or("no_organizer")?;
            let calendar = skein_itip::reply(
                &found.calendar,
                &who,
                *answer,
                comment.as_deref(),
                command.created_at,
            )
            .map_err(|e| e.reason())?;
            let (subject, text) = describe("REPLY", &calendar, &who, Some(*answer));
            let to = vec![organizer];
            let bytes = compose(&Outgoing {
                from: &who,
                to: &to,
                calendar: &calendar,
                method: "REPLY",
                subject: &subject,
                text: &text,
                token: command.id.as_str(),
                at: command.created_at,
                in_reply_to: found.message_id.as_deref(),
                references: &found.references,
            });
            Ok((
                SendEnvelope {
                    from: who,
                    to,
                    dsn: None,
                },
                bytes,
            ))
        })();
        Ok(built)
    }

    /// A send that certainly did not go out: tried again later while the error may pass and
    /// tries remain, else failed for good.
    async fn not_sent(
        &self,
        config: &AccountConfig,
        command: &Command,
        path: &str,
        attempts: Attempts,
        error: &SendError,
    ) -> Result<Step, EngineError> {
        if !error.is_retryable() {
            info!(account = %config.account, command = %command.id, reason = error.reason(), "send refused");
            return Ok(Step::Done {
                outcome: WriteOutcome::Failed {
                    reason: error.reason().to_owned(),
                },
                result: match error {
                    SendError::RecipientsRefused(results) => Some(refused(command, results, None)),
                    _ => None,
                },
            });
        }
        let failures = attempts.failures + 1;
        if failures >= self.send_policy.max_attempts {
            warn!(account = %config.account, command = %command.id, failures, "send gave up");
            return Ok(failed("gave_up"));
        }
        let next_at = Timestamp::now().plus_ms(self.send_policy.retry_delay(failures, error));
        let record = Attempts { failures, next_at };
        let bytes = serde_json::to_vec(&record)
            .map_err(|e| EngineError::Storage(StorageError::Corrupt(e.to_string())))?;
        self.storage
            .control
            .put(&config.tenant, path, Bytes::from(bytes), Expect::Any)
            .await?;
        info!(account = %config.account, command = %command.id, failures, reason = error.reason(), "send will be tried again");
        Ok(Step::Waiting(next_at))
    }

    async fn save_copy(
        &self,
        config: &AccountConfig,
        command: &Command,
        mailbox: &str,
        bytes: Bytes,
        session: &mut Option<Box<dyn MailSession>>,
        provider: &dyn MailProvider,
    ) -> SentCopy {
        let blob = match self.storage.blobs.put(&config.tenant, bytes.clone()).await {
            Ok(blob) => blob,
            Err(_) => {
                warn!(account = %config.account, command = %command.id, reason = "store", "sent copy not saved");
                return SentCopy::Failed;
            }
        };
        let append = CommandBody::Append {
            mailbox: mailbox.to_owned(),
            blob,
            flags: Flags::new(["\\Seen"]),
            received_at: None,
        };
        let outcome = match open(session, provider).await {
            Ok(s) => s.apply(&append, Some(bytes)).await,
            Err(e) => Err(e),
        };
        match outcome {
            Ok(WriteOutcome::Applied) => SentCopy::Saved,
            other => {
                let reason = match &other {
                    Ok(_) => "refused",
                    Err(_) => "error",
                };
                warn!(account = %config.account, command = %command.id, reason, "sent copy not saved");
                SentCopy::Failed
            }
        }
    }
}

#[cfg(test)]
#[path = "send_tests.rs"]
mod send_tests;
