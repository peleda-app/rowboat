use bytes::Bytes;
use skein_core::{
    Command, CommandBody, EventBody, PartStat, RefusedRecipient, ScheduleMessage, ScheduleStatus,
    ScheduleVia, SendEnvelope,
};
use skein_itip::imip::{Outgoing, compose, describe};
use skein_pim::RawObject;
use skein_send::{Envelope, SendError, SendReport};
use tracing::warn;

use crate::{AccountConfig, Engine};

/// One iMIP message a scheduling command must send.
pub(crate) struct Planned {
    pub method: &'static str,
    pub from: String,
    pub to: Vec<String>,
    pub calendar: Bytes,
    pub answer: Option<PartStat>,
}

pub(crate) fn told(command: &Command, via: ScheduleVia, reason: Option<&str>) -> EventBody {
    EventBody::ScheduleResult {
        command: command.id.clone(),
        via,
        messages: Vec::new(),
        reason: reason.map(str::to_owned),
    }
}

fn is_calendar(raw: &RawObject) -> bool {
    raw.content_type
        .split(';')
        .next()
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/calendar"))
}

/// The iMIP messages an organizer's `put_object` or `delete_object` must send, from the object
/// before (`previous`) and after (`next`), or why none are sent.
pub(crate) fn organizer_messages(
    command: &Command,
    previous: Option<&RawObject>,
    next: Option<&RawObject>,
    own: &[String],
) -> Result<Vec<Planned>, &'static str> {
    let previous = previous.filter(|r| is_calendar(r)).map(|r| &r.bytes);
    let next = next.filter(|r| is_calendar(r)).map(|r| &r.bytes);
    if previous.is_none() && next.is_none() {
        return Err("not_a_calendar_object");
    }
    if matches!(command.body, CommandBody::DeleteObject { .. }) && previous.is_none() {
        return Err("previous_unknown");
    }
    let plan = skein_itip::plan(previous.map(|b| &b[..]), next.map(|b| &b[..]))
        .map_err(|e| e.reason())?
        .ok_or("not_a_scheduling_object")?;
    let facts =
        skein_itip::facts(next.or(previous).expect("one is there")).map_err(|e| e.reason())?;
    if !facts.organized_by(own) {
        return Err("not_organizer");
    }
    if plan.is_empty() {
        return Err("no_attendees");
    }
    let at = command.created_at;
    let mut out = Vec::new();
    if let Some(next) = next
        && !plan.request.is_empty()
    {
        out.push(Planned {
            method: "REQUEST",
            from: plan.organizer.clone(),
            to: plan.request.clone(),
            calendar: skein_itip::request(next, at).map_err(|e| e.reason())?,
            answer: None,
        });
    }
    if !plan.cancel.is_empty() {
        let previous = previous.ok_or("previous_unknown")?;
        let (only, sequence) = match next {
            Some(_) => (Some(&plan.cancel[..]), Some(facts.sequence)),
            None => (None, None),
        };
        out.push(Planned {
            method: "CANCEL",
            from: plan.organizer.clone(),
            to: plan.cancel.clone(),
            calendar: skein_itip::cancel(previous, only, sequence, at).map_err(|e| e.reason())?,
            answer: None,
        });
    }
    Ok(out)
}

/// The iMIP `REPLY` an attendee's `respond_object` must send, from the object as it is after
/// the answer was written, or why none is sent.
pub(crate) fn reply_message(
    command: &Command,
    object: Option<&RawObject>,
    own: &[String],
) -> Result<Vec<Planned>, &'static str> {
    let CommandBody::RespondObject {
        answer,
        attendee,
        comment,
        ..
    } = &command.body
    else {
        return Err("unsupported");
    };
    let object = object.ok_or("object_unknown")?;
    if !is_calendar(object) {
        return Err("not_a_calendar_object");
    }
    let facts = skein_itip::facts(&object.bytes).map_err(|e| e.reason())?;
    let organizer = facts.organizer.clone().ok_or("no_organizer")?;
    if facts.organizer_agent != skein_itip::Agent::Server {
        return Err("organizer_not_scheduled");
    }
    let who = match attendee {
        Some(a) => skein_itip::address(a),
        None => facts
            .own_attendee(own)
            .map(|a| a.address.clone())
            .ok_or("attendee_not_found")?,
    };
    if who == organizer {
        return Err("own_event");
    }
    let calendar = skein_itip::reply(
        &object.bytes,
        &who,
        *answer,
        comment.as_deref(),
        command.created_at,
    )
    .map_err(|e| e.reason())?;
    Ok(vec![Planned {
        method: "REPLY",
        from: who,
        to: vec![organizer],
        calendar,
        answer: Some(*answer),
    }])
}

fn refused_of(report: &SendReport) -> Vec<RefusedRecipient> {
    report
        .refused()
        .map(|(address, r)| RefusedRecipient {
            address: address.to_owned(),
            code: r.code,
            permanent: r.permanent,
        })
        .collect()
}

impl Engine {
    /// Mails `planned` through the account's sender, each message once, and reports what became
    /// of each. Nothing is retried: a message that failed is reported as failed.
    pub(crate) async fn mail_itip(
        &self,
        config: &AccountConfig,
        command: &Command,
        planned: Vec<Planned>,
    ) -> EventBody {
        let Some(senders) = &self.senders else {
            return told(command, ScheduleVia::None, Some("no_sender"));
        };
        let sender = match senders.sender(&config.tenant, &config.account).await {
            Ok(Some(sender)) => sender,
            Ok(None) => return told(command, ScheduleVia::None, Some("no_sender")),
            Err(e) => return told(command, ScheduleVia::None, Some(e.reason())),
        };
        let mut messages = Vec::new();
        for (n, p) in planned.into_iter().enumerate() {
            let mut message = ScheduleMessage {
                method: p.method.to_owned(),
                to: p.to.clone(),
                status: ScheduleStatus::Failed,
                refused: Vec::new(),
                reason: None,
            };
            let envelope = SendEnvelope {
                from: p.from.clone(),
                to: p.to.clone(),
                dsn: None,
            };
            if envelope.check().is_err() {
                message.reason = Some("invalid_address".into());
                messages.push(message);
                continue;
            }
            let token = format!("{}-{n}", command.id);
            let (subject, text) = describe(p.method, &p.calendar, &p.from, p.answer);
            let bytes = compose(&Outgoing {
                from: &p.from,
                to: &p.to,
                calendar: &p.calendar,
                method: p.method,
                subject: &subject,
                text: &text,
                token: &token,
                at: command.created_at,
                in_reply_to: None,
                references: &[],
            });
            let handover = Envelope {
                mail_from: p.from,
                recipients: p.to,
                dsn: None,
                envid: Some(token),
            };
            match sender.send(&handover, &bytes).await {
                Ok(report) => {
                    message.status = ScheduleStatus::Sent;
                    message.refused = refused_of(&report);
                }
                Err(e) if e.may_have_been_sent() => {
                    warn!(account = %config.account, command = %command.id, "itip outcome unknown");
                    message.status = ScheduleStatus::Uncertain;
                    message.reason = Some(e.reason().to_owned());
                }
                Err(SendError::RecipientsRefused(results)) => {
                    message.refused = refused_of(&SendReport::new(results.clone()));
                    message.reason = Some("recipients_refused".into());
                }
                Err(e) => message.reason = Some(e.reason().to_owned()),
            }
            messages.push(message);
        }
        EventBody::ScheduleResult {
            command: command.id.clone(),
            via: ScheduleVia::Mail,
            messages,
            reason: None,
        }
    }
}

#[cfg(test)]
#[path = "schedule_tests.rs"]
mod schedule_tests;
