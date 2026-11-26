//! Reading and building iTIP messages (RFC 5546) and the mail that carries them (iMIP,
//! RFC 6047).
//!
//! Pure functions over bytes: no I/O, no state. Everything that is not touched is kept as it was
//! written (unknown properties, parameters, time zones), so a message built from an object says
//! what the object says. Lines are written with CRLF and folded at 75 octets.

mod ical;
pub mod imip;
mod time;

#[cfg(test)]
mod tests;

use bytes::Bytes;
use skein_core::{ItipAttendee, ItipSummary, PartStat, Timestamp};

pub use ical::{MAX_CALENDAR, address};

use crate::ical::{Component, Property};

const PRODID: &str = "-//Skein//iTIP//EN";

/// Why an iTIP message cannot be read or built. Messages never carry content or addresses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ItipError {
    /// The bytes are not a readable iCalendar object.
    #[error("not a readable iCalendar object: {0}")]
    Invalid(&'static str),
    /// The object is larger than [`MAX_CALENDAR`].
    #[error("the object is too large")]
    TooLarge,
    /// The object has no event, task or journal entry.
    #[error("no event or task")]
    NoComponent,
    /// The object has no `METHOD`, or one this operation does not take.
    #[error("not an iTIP message this operation takes")]
    WrongMethod,
    /// The object names no organizer.
    #[error("no organizer")]
    NoOrganizer,
    /// The attendee is not invited.
    #[error("the attendee is not invited")]
    AttendeeNotFound,
    /// The message carries no `text/calendar` part with a `METHOD`.
    #[error("no iTIP part")]
    NoCalendarPart,
}

impl ItipError {
    /// A short machine-readable reason, such as `attendee_not_found`.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid_calendar",
            Self::TooLarge => "too_large",
            Self::NoComponent => "no_component",
            Self::WrongMethod => "wrong_method",
            Self::NoOrganizer => "no_organizer",
            Self::AttendeeNotFound => "attendee_not_found",
            Self::NoCalendarPart => "no_calendar_part",
        }
    }
}

/// Who sends iTIP messages for an attendee (RFC 6638 `SCHEDULE-AGENT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Agent {
    /// The server, or whoever acts as one: the default.
    Server,
    /// The calendar client.
    Client,
    /// Nobody.
    None,
}

/// An attendee of a stored object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attendee {
    /// The address, lower case, without `mailto:`.
    pub address: String,
    /// `PARTSTAT` in upper case, when given.
    pub partstat: Option<String>,
    /// `RSVP=TRUE`.
    pub rsvp: bool,
    /// Who tells this attendee.
    pub agent: Agent,
}

/// The scheduling facts of a stored event or task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The `UID`.
    pub uid: String,
    /// The highest `SEQUENCE` of its components, 0 when missing.
    pub sequence: u32,
    /// The organizer's address.
    pub organizer: Option<String>,
    /// Who tells the attendees for the organizer.
    pub organizer_agent: Agent,
    /// Every attendee of the series and its instances, each once, in the order first seen.
    pub attendees: Vec<Attendee>,
    /// The `SUMMARY` as text, when given.
    pub summary: Option<String>,
}

impl Facts {
    /// The first attendee whose address is one of `own` (in any case, with or without
    /// `mailto:`).
    pub fn own_attendee(&self, own: &[String]) -> Option<&Attendee> {
        let own: Vec<String> = own.iter().map(|a| address(a)).collect();
        self.attendees.iter().find(|a| own.contains(&a.address))
    }

    /// Whether the organizer is one of `own`. True when `own` is empty and there is an
    /// organizer: without a list of own addresses the writer is taken at its word.
    pub fn organized_by(&self, own: &[String]) -> bool {
        match &self.organizer {
            None => false,
            Some(o) => own.is_empty() || own.iter().any(|a| address(a) == *o),
        }
    }
}

fn agent(p: &Property) -> Agent {
    match p
        .param("SCHEDULE-AGENT")
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        Some("CLIENT") => Agent::Client,
        Some("NONE") => Agent::None,
        _ => Agent::Server,
    }
}

fn scheduling(root: &Component) -> impl Iterator<Item = &Component> {
    root.children.iter().filter(|c| c.is_scheduling())
}

fn first(root: &Component) -> Result<&Component, ItipError> {
    scheduling(root).next().ok_or(ItipError::NoComponent)
}

/// The `UID` of the series: the first event, task or journal entry's.
fn series_uid(root: &Component) -> Result<String, ItipError> {
    first(root)?
        .value("UID")
        .map(str::to_owned)
        .ok_or(ItipError::Invalid("no UID"))
}

/// Gives a component without a `UID` the series' one, so every component of a built message
/// names the same object (RFC 5546 section 2.1.5).
fn with_uid(part: &mut Component, uid: &str) {
    if part.prop("UID").is_none() {
        part.props
            .insert(part.props.len().min(1), Property::new("UID", uid));
    }
}

fn method(root: &Component) -> Option<String> {
    root.value("METHOD").map(str::to_ascii_uppercase)
}

/// The scheduling facts of an iTIP message, read from its first event, task or journal entry.
/// Fails with [`ItipError::WrongMethod`] when it has no `METHOD`.
pub fn summary(calendar: &[u8]) -> Result<ItipSummary, ItipError> {
    let root = ical::parse(calendar)?;
    let method = method(&root).ok_or(ItipError::WrongMethod)?;
    let c = first(&root)?;
    let uid = c
        .value("UID")
        .ok_or(ItipError::Invalid("no UID"))?
        .to_owned();
    let all: Vec<&Property> = c.props_named("ATTENDEE").collect();
    let attendees = all
        .iter()
        .take(ItipSummary::MAX_ATTENDEES)
        .map(|p| ItipAttendee {
            address: p.address(),
            partstat: p.param("PARTSTAT").map(str::to_ascii_uppercase),
            rsvp: p
                .param("RSVP")
                .is_some_and(|v| v.eq_ignore_ascii_case("TRUE")),
        })
        .collect();
    Ok(ItipSummary {
        method,
        component: c.name.clone(),
        uid,
        sequence: c.sequence(),
        recurrence_id: c.value("RECURRENCE-ID").map(str::to_owned),
        organizer: c.prop("ORGANIZER").map(Property::address),
        attendees,
        more_attendees: all.len() > ItipSummary::MAX_ATTENDEES,
    })
}

/// The scheduling facts of a stored object (or an iTIP message): attendees of the series and
/// every instance together.
pub fn facts(object: &[u8]) -> Result<Facts, ItipError> {
    let root = ical::parse(object)?;
    let c = first(&root)?;
    let uid = c
        .value("UID")
        .ok_or(ItipError::Invalid("no UID"))?
        .to_owned();
    let mut attendees: Vec<Attendee> = Vec::new();
    let mut organizer = None;
    let mut organizer_agent = Agent::Server;
    let mut sequence = 0;
    for comp in scheduling(&root) {
        sequence = sequence.max(comp.sequence());
        if organizer.is_none()
            && let Some(o) = comp.prop("ORGANIZER")
        {
            organizer = Some(o.address());
            organizer_agent = agent(o);
        }
        for p in comp.props_named("ATTENDEE") {
            let a = p.address();
            if a.is_empty() || attendees.iter().any(|x| x.address == a) {
                continue;
            }
            attendees.push(Attendee {
                address: a,
                partstat: p.param("PARTSTAT").map(str::to_ascii_uppercase),
                rsvp: p
                    .param("RSVP")
                    .is_some_and(|v| v.eq_ignore_ascii_case("TRUE")),
                agent: agent(p),
            });
        }
    }
    Ok(Facts {
        uid,
        sequence,
        organizer,
        organizer_agent,
        attendees,
        summary: c.value("SUMMARY").map(ical::unescape),
    })
}

fn calendar(method: &str) -> Component {
    let mut root = Component::new("VCALENDAR");
    root.props.push(Property::new("PRODID", PRODID));
    root.props.push(Property::new("VERSION", "2.0"));
    root.props.push(Property::new("METHOD", method));
    root
}

fn timezones(source: &Component) -> impl Iterator<Item = Component> + '_ {
    source
        .children
        .iter()
        .filter(|c| c.name == "VTIMEZONE")
        .cloned()
}

fn clean_scheduling_params(p: &mut Property) {
    p.remove_param("SCHEDULE-STATUS");
    p.remove_param("SCHEDULE-FORCE-SEND");
}

/// Sets `attendee`'s `PARTSTAT` to `answer` on the series and on every instance the attendee
/// is on, drops their `RSVP=TRUE` and server-written `SCHEDULE-STATUS`, and sets `comment` as
/// the component's `COMMENT` when given. Everything else is kept. This is what an attendee's
/// client writes to its copy (RFC 6638 section 3.2.2.1).
pub fn set_partstat(
    object: &[u8],
    attendee: &str,
    answer: PartStat,
    comment: Option<&str>,
) -> Result<Bytes, ItipError> {
    let mut root = ical::parse(object)?;
    let who = address(attendee);
    let mut found = false;
    for comp in root.children.iter_mut().filter(|c| c.is_scheduling()) {
        let mut here = false;
        for p in comp.props.iter_mut().filter(|p| p.name == "ATTENDEE") {
            if p.address() == who {
                p.set_param("PARTSTAT", answer.as_ical());
                p.remove_param("RSVP");
                clean_scheduling_params(p);
                here = true;
            }
        }
        if here {
            found = true;
            if let Some(text) = comment {
                comp.set("COMMENT", ical::escape(text));
            }
        }
    }
    if !found {
        return Err(ItipError::AttendeeNotFound);
    }
    Ok(Bytes::from(ical::write(&root)))
}

const REPLY_KEEP: &[&str] = &[
    "UID",
    "SEQUENCE",
    "RECURRENCE-ID",
    "ORGANIZER",
    "DTSTART",
    "DTEND",
    "DURATION",
    "DUE",
    "SUMMARY",
    "LOCATION",
];

/// An iTIP `REPLY` from `attendee` with `answer`, for the event or task in `source`: an
/// invitation (`METHOD:REQUEST` or `ADD`) or a stored copy without `METHOD`. It covers the series
/// and every instance the attendee is on; each component keeps only what identifies the event
/// and when it is, plus the one attendee, `DTSTAMP` set to `at` and `comment` as `COMMENT`. An
/// instance without a `UID` gets the series' one; a series without one is
/// [`ItipError::Invalid`].
pub fn reply(
    source: &[u8],
    attendee: &str,
    answer: PartStat,
    comment: Option<&str>,
    at: Timestamp,
) -> Result<Bytes, ItipError> {
    let root = ical::parse(source)?;
    if let Some(m) = method(&root)
        && !matches!(m.as_str(), "REQUEST" | "ADD" | "PUBLISH")
    {
        return Err(ItipError::WrongMethod);
    }
    let who = address(attendee);
    let mut out = calendar("REPLY");
    out.children.extend(timezones(&root));
    let stamp = time::ical(at);
    let uid = series_uid(&root)?;
    let mut found = false;
    for comp in scheduling(&root) {
        let Some(mut me) = comp
            .props_named("ATTENDEE")
            .find(|p| p.address() == who)
            .cloned()
        else {
            continue;
        };
        if comp.prop("ORGANIZER").is_none() {
            return Err(ItipError::NoOrganizer);
        }
        found = true;
        let mut part = Component::new(&comp.name);
        part.props.push(Property::new("DTSTAMP", stamp.clone()));
        for name in REPLY_KEEP {
            if let Some(p) = comp.prop(name) {
                let mut p = p.clone();
                clean_scheduling_params(&mut p);
                part.props.push(p);
            }
        }
        with_uid(&mut part, &uid);
        me.set_param("PARTSTAT", answer.as_ical());
        me.remove_param("RSVP");
        clean_scheduling_params(&mut me);
        part.props.push(me);
        if let Some(text) = comment {
            part.props
                .push(Property::new("COMMENT", ical::escape(text)));
        }
        out.children.push(part);
    }
    if !found {
        return Err(ItipError::AttendeeNotFound);
    }
    Ok(Bytes::from(ical::write(&out)))
}

/// An iTIP `REQUEST` for a stored object the account organizes: the object as it is, with
/// `METHOD:REQUEST`, `DTSTAMP` set to `at`, alarms left out and server-written scheduling
/// parameters removed. An instance without a `UID` gets the series' one; a series without one is
/// [`ItipError::Invalid`].
pub fn request(object: &[u8], at: Timestamp) -> Result<Bytes, ItipError> {
    let root = ical::parse(object)?;
    let mut out = calendar("REQUEST");
    out.children.extend(timezones(&root));
    let stamp = time::ical(at);
    let uid = series_uid(&root)?;
    for comp in scheduling(&root) {
        if comp.prop("ORGANIZER").is_none() {
            return Err(ItipError::NoOrganizer);
        }
        let mut part = comp.clone();
        with_uid(&mut part, &uid);
        part.children.retain(|c| c.name != "VALARM");
        for p in &mut part.props {
            clean_scheduling_params(p);
        }
        part.set("DTSTAMP", stamp.clone());
        out.children.push(part);
    }
    if out.children.iter().all(|c| !c.is_scheduling()) {
        return Err(ItipError::NoComponent);
    }
    Ok(Bytes::from(ical::write(&out)))
}

/// An iTIP `CANCEL` for a stored object the account organizes. With `only`, it names just those
/// attendees (removed from the event); otherwise every attendee (the event is cancelled). The
/// `SEQUENCE` is `sequence`, or one more than the object's when `None`. A series without a `UID`
/// is [`ItipError::Invalid`].
pub fn cancel(
    object: &[u8],
    only: Option<&[String]>,
    sequence: Option<u32>,
    at: Timestamp,
) -> Result<Bytes, ItipError> {
    let root = ical::parse(object)?;
    let only: Option<Vec<String>> = only.map(|o| o.iter().map(|a| address(a)).collect());
    let mut out = calendar("CANCEL");
    out.children.extend(timezones(&root));
    let stamp = time::ical(at);
    let Some(series) = scheduling(&root).next() else {
        return Err(ItipError::NoComponent);
    };
    series_uid(&root)?;
    let organizer = series.prop("ORGANIZER").ok_or(ItipError::NoOrganizer)?;
    let seq = sequence.unwrap_or_else(|| {
        scheduling(&root)
            .map(Component::sequence)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
    });
    let mut part = Component::new(&series.name);
    part.props.push(Property::new("DTSTAMP", stamp));
    for name in ["UID", "DTSTART", "SUMMARY"] {
        if let Some(p) = series.prop(name) {
            part.props.push(p.clone());
        }
    }
    let mut organizer = organizer.clone();
    clean_scheduling_params(&mut organizer);
    part.props.push(organizer);
    part.props.push(Property::new("SEQUENCE", seq.to_string()));
    part.props.push(Property::new("STATUS", "CANCELLED"));
    let mut named: Vec<String> = Vec::new();
    for comp in scheduling(&root) {
        for p in comp.props_named("ATTENDEE") {
            let a = p.address();
            if named.contains(&a) || only.as_ref().is_some_and(|o| !o.contains(&a)) {
                continue;
            }
            named.push(a);
            let mut p = p.clone();
            clean_scheduling_params(&mut p);
            p.remove_param("PARTSTAT");
            p.remove_param("RSVP");
            part.props.push(p);
        }
    }
    if named.is_empty() {
        return Err(ItipError::AttendeeNotFound);
    }
    out.children.push(part);
    Ok(Bytes::from(ical::write(&out)))
}

/// Who an organizer's change must tell when nobody else does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The organizer's address, the sender.
    pub organizer: String,
    /// Attendees that get the new version as a `REQUEST`.
    pub request: Vec<String>,
    /// Attendees no longer on the event, who get a `CANCEL`.
    pub cancel: Vec<String>,
}

impl Plan {
    /// Whether nobody needs to be told.
    pub fn is_empty(&self) -> bool {
        self.request.is_empty() && self.cancel.is_empty()
    }
}

/// What an organizer's write from `previous` (`None` for a create) to `next` (`None` for a
/// delete) must send when the writer schedules (RFC 6638 section 3.2.1, with the writer in the
/// server's place): every attendee of `next` a `REQUEST`, every attendee only in `previous` a
/// `CANCEL`, and for a delete every attendee a `CANCEL`. Attendees whose `SCHEDULE-AGENT` is
/// `CLIENT` or `NONE` and the organizer itself are left out; an organizer with
/// `SCHEDULE-AGENT=NONE` or `CLIENT` tells nobody. `None` when the object is not a scheduling
/// object (no organizer).
pub fn plan(previous: Option<&[u8]>, next: Option<&[u8]>) -> Result<Option<Plan>, ItipError> {
    let previous = previous.map(facts).transpose()?;
    let next = next.map(facts).transpose()?;
    let Some(base) = next.as_ref().or(previous.as_ref()) else {
        return Ok(None);
    };
    let Some(organizer) = base.organizer.clone() else {
        return Ok(None);
    };
    if base.organizer_agent != Agent::Server {
        return Ok(Some(Plan {
            organizer,
            request: Vec::new(),
            cancel: Vec::new(),
        }));
    }
    let told = |a: &&Attendee| a.agent == Agent::Server && a.address != organizer;
    let request: Vec<String> = next
        .as_ref()
        .map(|n| {
            n.attendees
                .iter()
                .filter(told)
                .map(|a| a.address.clone())
                .collect()
        })
        .unwrap_or_default();
    let still = |addr: &str| {
        next.as_ref()
            .is_some_and(|n| n.attendees.iter().any(|a| a.address == addr))
    };
    let cancel: Vec<String> = previous
        .as_ref()
        .map(|p| {
            p.attendees
                .iter()
                .filter(told)
                .filter(|a| !still(&a.address))
                .map(|a| a.address.clone())
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(Plan {
        organizer,
        request,
        cancel,
    }))
}
