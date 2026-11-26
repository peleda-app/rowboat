//! iTIP in mail (iMIP, RFC 6047): finding the `text/calendar` part of a message and composing
//! the message that carries an iTIP object.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use mail_parser::MessageParser;
use skein_core::{PartStat, Timestamp};

use crate::{ItipError, MAX_CALENDAR, facts, time};

/// Whether `message` may carry a calendar part: a quick byte scan for `text/calendar` or
/// `application/ics`, in any case, so most messages are skipped without parsing. False means
/// it certainly carries none.
pub fn may_carry_calendar(message: &[u8]) -> bool {
    contains(message, b"text/calendar") || contains(message, b"application/ics")
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// An iTIP message found in mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    /// The `text/calendar` part, decoded.
    pub calendar: Bytes,
    /// The `To` and `Cc` addresses, lower case; empty when only a calendar was given.
    pub recipients: Vec<String>,
    /// The message's `Message-ID`, without angle brackets.
    pub message_id: Option<String>,
    /// Its `References`, oldest first, without angle brackets.
    pub references: Vec<String>,
}

/// The first `text/calendar` (or `application/ics`) part of `message` whose iCalendar object
/// has a `METHOD`, with the message's addressing. Parts of forwarded messages are not looked at.
/// `None` when there is none or the message cannot be read.
pub fn find(message: &[u8]) -> Option<Invitation> {
    if !may_carry_calendar(message) {
        return None;
    }
    let parsed = MessageParser::new().parse(message)?;
    let root = parsed.root();
    let calendar = root.parts().find_map(|part| {
        let ct = part.content_type()?;
        let calendar = (ct.ctype().eq_ignore_ascii_case("text")
            && ct
                .subtype()
                .is_some_and(|s| s.eq_ignore_ascii_case("calendar")))
            || (ct.ctype().eq_ignore_ascii_case("application")
                && ct.subtype().is_some_and(|s| s.eq_ignore_ascii_case("ics")));
        if !calendar || part.decoded_len() > MAX_CALENDAR {
            return None;
        }
        let bytes = part.decoded();
        crate::summary(&bytes).ok()?;
        Some(Bytes::copy_from_slice(&bytes))
    })?;
    let headers = root.headers();
    let mut recipients = Vec::new();
    for list in headers.all_to().chain(headers.all_cc()) {
        for mailbox in list.mailboxes() {
            if let Some(a) = mailbox.address().filter(|a| a.contains('@')) {
                let a = a.to_ascii_lowercase();
                if !recipients.contains(&a) {
                    recipients.push(a);
                }
            }
        }
    }
    let references = headers
        .references()
        .map(|list| {
            (0..list.len())
                .filter_map(|i| list.get(i))
                .map(bare_id)
                .collect()
        })
        .unwrap_or_default();
    Some(Invitation {
        calendar,
        recipients,
        message_id: headers.message_id().map(bare_id),
        references,
    })
}

/// An invitation from bytes that are either a whole message or an iCalendar object on its own.
pub fn read(bytes: &[u8]) -> Result<Invitation, ItipError> {
    let head = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| &bytes[i..])
        .unwrap_or_default();
    let head = head.strip_prefix("\u{feff}".as_bytes()).unwrap_or(head);
    if head.len() >= 15 && head[..15].eq_ignore_ascii_case(b"BEGIN:VCALENDAR") {
        crate::summary(bytes)?;
        return Ok(Invitation {
            calendar: Bytes::copy_from_slice(bytes),
            recipients: Vec::new(),
            message_id: None,
            references: Vec::new(),
        });
    }
    find(bytes).ok_or(ItipError::NoCalendarPart)
}

fn bare_id(id: &str) -> String {
    id.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_owned()
}

/// A message to compose around an iTIP object.
#[derive(Debug, Clone)]
pub struct Outgoing<'a> {
    /// The sender: `From` and the address the iTIP object speaks for.
    pub from: &'a str,
    /// The recipients, all in `To`.
    pub to: &'a [String],
    /// The iTIP object.
    pub calendar: &'a [u8],
    /// Its `METHOD`, for the `method` parameter of the part.
    pub method: &'a str,
    /// The `Subject`.
    pub subject: &'a str,
    /// The plain text part.
    pub text: &'a str,
    /// A token unique to this message (a command id), for `Message-ID` and the boundary. The
    /// same token always gives the same bytes.
    pub token: &'a str,
    /// The `Date`.
    pub at: Timestamp,
    /// The message this one answers, for `In-Reply-To`.
    pub in_reply_to: Option<&'a str>,
    /// Earlier `References`, oldest first.
    pub references: &'a [String],
}

fn clean_token(token: &str) -> String {
    token
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        .take(64)
        .collect()
}

fn clean_id(id: &str) -> Option<String> {
    let id: String = id
        .chars()
        .filter(|c| c.is_ascii_graphic() && !matches!(c, '<' | '>' | '"' | ',' | ';'))
        .take(250)
        .collect();
    (!id.is_empty()).then_some(id)
}

/// A header value as plain ASCII, or as RFC 2047 encoded words when it is not; control
/// characters are dropped either way.
fn header_text(text: &str) -> String {
    let text: String = text.chars().filter(|c| !c.is_control()).take(250).collect();
    if text.is_ascii() {
        return text;
    }
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in text.chars() {
        if chunk.len() + c.len_utf8() > 45 {
            words.push(format!("=?utf-8?b?{}?=", STANDARD.encode(&chunk)));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(format!("=?utf-8?b?{}?=", STANDARD.encode(&chunk)));
    }
    words.join("\r\n ")
}

fn base64_lines(bytes: &[u8], out: &mut String) {
    let encoded = STANDARD.encode(bytes);
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push_str("\r\n");
    }
}

/// An RFC 5322 message carrying `outgoing.calendar` as RFC 6047 asks: `multipart/alternative`
/// with a plain text part and a `text/calendar; method=...` part, both base64, CRLF throughout.
/// Addresses are written as given, so the caller checks them first
/// ([`skein_core::plausible_address`]).
pub fn compose(outgoing: &Outgoing<'_>) -> Bytes {
    let token = clean_token(outgoing.token);
    let domain = outgoing
        .from
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or("skein.invalid");
    let boundary = format!("=_skein_{token}");
    let method: String = outgoing
        .method
        .chars()
        .filter(char::is_ascii_alphabetic)
        .collect::<String>()
        .to_ascii_uppercase();
    let mut m = String::new();
    m.push_str(&format!("From: <{}>\r\n", outgoing.from));
    m.push_str("To: ");
    m.push_str(
        &outgoing
            .to
            .iter()
            .map(|a| format!("<{a}>"))
            .collect::<Vec<_>>()
            .join(",\r\n "),
    );
    m.push_str("\r\n");
    m.push_str(&format!("Subject: {}\r\n", header_text(outgoing.subject)));
    m.push_str(&format!("Date: {}\r\n", time::rfc5322(outgoing.at)));
    m.push_str(&format!("Message-ID: <{token}.itip@{domain}>\r\n"));
    let mut refs: Vec<String> = outgoing
        .references
        .iter()
        .filter_map(|r| clean_id(r))
        .collect();
    if let Some(parent) = outgoing.in_reply_to.and_then(clean_id) {
        m.push_str(&format!("In-Reply-To: <{parent}>\r\n"));
        if !refs.contains(&parent) {
            refs.push(parent);
        }
    }
    if !refs.is_empty() {
        let refs: Vec<String> = refs.iter().map(|r| format!("<{r}>")).collect();
        m.push_str(&format!("References: {}\r\n", refs.join("\r\n ")));
    }
    m.push_str("MIME-Version: 1.0\r\n");
    m.push_str(&format!(
        "Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n"
    ));
    m.push_str(&format!("--{boundary}\r\n"));
    m.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    m.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
    base64_lines(outgoing.text.as_bytes(), &mut m);
    m.push_str(&format!("--{boundary}\r\n"));
    m.push_str(&format!(
        "Content-Type: text/calendar; charset=utf-8; method={method}\r\n"
    ));
    m.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
    base64_lines(outgoing.calendar, &mut m);
    m.push_str(&format!("--{boundary}--\r\n"));
    Bytes::from(m)
}

/// A plain English subject and text for an iTIP message built from `calendar`, such as
/// `Accepted: Planning` and `ada@example.com has accepted the invitation.`. Consumers who want
/// other words build the message themselves and send it with `send`.
pub fn describe(
    method: &str,
    calendar: &[u8],
    sender: &str,
    answer: Option<PartStat>,
) -> (String, String) {
    let title = facts(calendar)
        .ok()
        .and_then(|f| f.summary)
        .map(|s| s.replace(['\r', '\n'], " "))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "(no title)".into());
    match (method.to_ascii_uppercase().as_str(), answer) {
        ("REPLY", Some(PartStat::Accepted)) => (
            format!("Accepted: {title}"),
            format!("{sender} has accepted the invitation: {title}"),
        ),
        ("REPLY", Some(PartStat::Declined)) => (
            format!("Declined: {title}"),
            format!("{sender} has declined the invitation: {title}"),
        ),
        ("REPLY", _) => (
            format!("Tentative: {title}"),
            format!("{sender} has tentatively accepted the invitation: {title}"),
        ),
        ("CANCEL", _) => (
            format!("Cancelled: {title}"),
            format!("{sender} has cancelled this event: {title}"),
        ),
        _ => (
            format!("Invitation: {title}"),
            format!("{sender} has invited you to: {title}"),
        ),
    }
}
