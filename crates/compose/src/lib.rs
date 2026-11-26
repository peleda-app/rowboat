//! A draft to RFC 5322 bytes and a send envelope.
//!
//! Pure and deterministic: the date, the `Message-ID` and the MIME boundary come from the
//! caller, so equal input gives equal bytes. Header values are RFC 2047 encoded where they are
//! not plain ASCII and never carry CR or LF; addresses are checked with
//! [`rowboat_api::plausible_address`]; Bcc recipients go only to the envelope.

mod date;
mod encode;

use rowboat_api::{Draft, EmailAddress, NodeError, check};

pub use date::rfc5322_date;
pub use encode::{encode_header_text, media_type};

/// Why a draft could not be composed. Carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ComposeError {
    /// The draft breaks a rule of `rowboat_api::check::sendable`.
    #[error("the draft is not sendable")]
    Invalid,
    /// The `Message-ID` or boundary given is not usable.
    #[error("bad message id or boundary")]
    BadIdentity,
}

impl From<ComposeError> for NodeError {
    fn from(_: ComposeError) -> Self {
        NodeError::InvalidInput
    }
}

/// What is needed besides the draft.
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    /// The account's address, the `From` and the return path.
    pub from: &'a EmailAddress,
    /// The account's display name.
    pub from_name: Option<&'a str>,
    /// The time to write into `Date`, milliseconds since the epoch, written in UTC.
    pub date_ms: i64,
    /// The left part of the `Message-ID`: 1 to 64 characters of `[A-Za-z0-9]` (a ULID).
    pub message_id_local: &'a str,
    /// Random characters for the MIME boundary: 8 to 40 characters of `[A-Za-z0-9]`.
    pub boundary_seed: &'a str,
}

/// A composed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composed {
    /// The message with CRLF line endings.
    pub bytes: Vec<u8>,
    /// The return path.
    pub envelope_from: String,
    /// Every recipient (To, Cc, Bcc), without repeats (case-insensitive), in that order.
    pub recipients: Vec<String>,
    /// The `Message-ID` without angle brackets.
    pub message_id: String,
}

fn alnum(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Composes `draft` as sent by `identity`.
///
/// The message: `From`, `To`, `Cc` (when any), `Subject`, `Date`, `Message-ID`, `In-Reply-To`
/// and `References` for replies, `MIME-Version`; a `text/plain; charset=utf-8` body (7bit when
/// it is ASCII with short lines, else quoted-printable); with attachments a `multipart/mixed`
/// body whose parts are base64 with RFC 2231 names and a type from the file extension.
pub fn compose(draft: &Draft, identity: &Identity<'_>) -> Result<Composed, ComposeError> {
    check::sendable(draft).map_err(|_| ComposeError::Invalid)?;
    if identity
        .from_name
        .is_some_and(|n| !check::one_line(n, rowboat_api::MAX_NAME_CHARS))
    {
        return Err(ComposeError::Invalid);
    }
    if !alnum(identity.message_id_local, 1, 64) || !alnum(identity.boundary_seed, 8, 40) {
        return Err(ComposeError::BadIdentity);
    }
    let domain = identity.from.domain().to_ascii_lowercase();
    let message_id = format!("{}@{domain}", identity.message_id_local);

    let mut out = String::new();
    let mut header = |name: &str, value: &str| {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    };
    header(
        "From",
        &encode::mailbox(identity.from_name, identity.from.as_str()),
    );
    let list = |rs: &[rowboat_api::Recipient]| {
        rs.iter()
            .map(|r| encode::mailbox(r.name.as_deref(), r.address.as_str()))
            .collect::<Vec<_>>()
            .join(",\r\n ")
    };
    if !draft.to.is_empty() {
        header("To", &list(&draft.to));
    }
    if !draft.cc.is_empty() {
        header("Cc", &list(&draft.cc));
    }
    header("Subject", &encode_header_text(&draft.subject));
    header("Date", &rfc5322_date(identity.date_ms));
    header("Message-ID", &format!("<{message_id}>"));
    if let Some(reply) = &draft.reply {
        header("In-Reply-To", &format!("<{}>", reply.message_id));
        let mut refs: Vec<&str> = reply.references.iter().map(String::as_str).collect();
        if refs.last() != Some(&reply.message_id.as_str()) {
            refs.push(&reply.message_id);
        }
        let joined = refs
            .iter()
            .map(|r| format!("<{r}>"))
            .collect::<Vec<_>>()
            .join("\r\n ");
        header("References", &joined);
    }
    header("MIME-Version", "1.0");

    if draft.attachments.is_empty() {
        encode::text_part(&mut out, &draft.text, false);
    } else {
        let boundary = format!("=_rowboat_{}", identity.boundary_seed);
        out.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n"
        ));
        out.push_str(&format!("--{boundary}\r\n"));
        encode::text_part(&mut out, &draft.text, true);
        for a in &draft.attachments {
            out.push_str(&format!("\r\n--{boundary}\r\n"));
            encode::attachment_part(&mut out, &a.name, &a.bytes);
        }
        out.push_str(&format!("\r\n--{boundary}--\r\n"));
    }

    let mut recipients: Vec<String> = Vec::new();
    for r in draft.to.iter().chain(&draft.cc).chain(&draft.bcc) {
        let a = r.address.as_str();
        if !recipients.iter().any(|x| x.eq_ignore_ascii_case(a)) {
            recipients.push(a.to_owned());
        }
    }
    Ok(Composed {
        bytes: out.into_bytes(),
        envelope_from: identity.from.as_str().to_owned(),
        recipients,
        message_id,
    })
}

#[cfg(test)]
mod tests;
