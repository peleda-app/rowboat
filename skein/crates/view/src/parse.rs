use async_trait::async_trait;
use bytes::Bytes;
use mail_parser::PartKind;
use serde::{Deserialize, Serialize};
use skein_core::MailboxRole;

/// Most bytes of text body kept per message; longer text is cut at a character boundary.
pub const TEXT_CAP: usize = 1024 * 1024;
/// Most bytes of HTML body kept per message; a longer HTML body is not kept at all, since a
/// cut document would render wrongly. The original stays reachable through `/raw`.
pub const HTML_CAP: usize = 2 * 1024 * 1024;
/// Most characters of the snippet.
pub const SNIPPET_CHARS: usize = 200;

/// A mailbox in an address header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addr {
    /// The display name, decoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `local@domain`, when the header had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// An attachment of a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// The part's index among the message's MIME parts in document order (0 is the root).
    pub part: u32,
    /// The file name the message gives, decoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `type/subtype` in lower case; `application/octet-stream` when missing.
    pub content_type: String,
    /// Decoded size in bytes.
    pub size: u64,
}

/// What the view keeps of a message. Derived from the original bytes, never authoritative.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// False when the bytes could not be read from Skein (gone, too large) or parsed.
    pub available: bool,
    /// `Message-ID` without angle brackets.
    pub message_id: Option<String>,
    /// `In-Reply-To` ids without angle brackets.
    pub in_reply_to: Vec<String>,
    /// `References` ids without angle brackets, in header order.
    pub references: Vec<String>,
    /// The decoded subject.
    pub subject: Option<String>,
    /// `From` addresses.
    pub from: Vec<Addr>,
    /// `To` addresses.
    pub to: Vec<Addr>,
    /// `Cc` addresses.
    pub cc: Vec<Addr>,
    /// The `Date` header in milliseconds since the epoch, UTC.
    pub date: Option<i64>,
    /// RFC 8621 `hasAttachment`: an attachment not marked inline.
    pub has_attachments: bool,
    /// The attachments, in part order.
    pub attachments: Vec<Attachment>,
    /// Plain text, or text made from HTML when there is no plain part; at most [`TEXT_CAP`].
    pub text: Option<String>,
    /// The HTML body as the message has it, unsanitized; `None` above [`HTML_CAP`].
    pub html: Option<String>,
    /// The first [`SNIPPET_CHARS`] characters of `text`, whitespace collapsed.
    pub snippet: Option<String>,
    /// What the message's iMIP calendar part says (RFC 6047), when it carries one.
    pub itip: Option<skein_core::ItipSummary>,
    /// Labels a parser hook attached, such as a spam verdict or a category; the store keeps at
    /// most [`MAX_TAGS`] that pass [`valid_tag`] and drops the rest.
    pub tags: Vec<String>,
}

/// Most tags kept per message.
pub const MAX_TAGS: usize = 8;

/// Whether `tag` may be stored: 1 to 64 characters of `[a-z0-9._-]`.
pub fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// The tags of `tags` the store keeps: valid ones, without repeats, sorted, at most [`MAX_TAGS`].
pub fn clean_tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = tags.iter().filter(|t| valid_tag(t)).cloned().collect();
    out.sort();
    out.dedup();
    out.truncate(MAX_TAGS);
    out
}

/// Where a message was first seen, for parser hooks whose output depends on placement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParseContext {
    /// The account.
    pub account: String,
    /// The mailbox the message was added to, when it came from a `message_added` event.
    pub mailbox: Option<String>,
    /// That mailbox's role, when the journal named one before or in the same page.
    pub role: Option<MailboxRole>,
}

/// Why a parser hook refused a message. Carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The bytes were refused, or the parser's output failed its checks; the message is stored
    /// as unavailable.
    #[error("the message was refused")]
    Refused,
    /// The parser could not run now; the follower stops the page and retries it next round.
    #[error("the parser is unavailable")]
    Unavailable,
}

/// Turns a message's original bytes into what the view stores. The follower calls it once per
/// new blob per account, at most one call at a time per follower, never for bytes larger than
/// its blob limit.
///
/// Implementations must not panic on any input; a hostile message gives fewer fields or
/// [`ParseError::Refused`].
#[async_trait]
pub trait MessageParser: Send + Sync {
    /// Parses `raw`; the result is stored with `available` forced to true.
    async fn parse(&self, raw: &Bytes, context: &ParseContext) -> Result<Parsed, ParseError>;

    /// The parser's version; stored with each message parsed by it.
    fn version(&self) -> String;
}

/// The built-in parser over `mail-parser`, used when no hook is given.
#[derive(Debug, Clone, Copy, Default)]
pub struct MailParser;

#[async_trait]
impl MessageParser for MailParser {
    async fn parse(&self, raw: &Bytes, _: &ParseContext) -> Result<Parsed, ParseError> {
        let parsed = parse(raw);
        if parsed.available {
            Ok(parsed)
        } else {
            Err(ParseError::Refused)
        }
    }

    fn version(&self) -> String {
        "mail-parser-1".into()
    }
}

impl Parsed {
    /// A message whose bytes are not available.
    pub fn unavailable() -> Self {
        Self::default()
    }
}

/// Parses RFC 5322 bytes. Never fails: unreadable input gives [`Parsed::unavailable`], and
/// damaged structure keeps whatever parsed.
pub fn parse(bytes: &[u8]) -> Parsed {
    let Some(message) = mail_parser::MessageParser::new().parse(bytes) else {
        return Parsed::unavailable();
    };
    let addrs = |list: Option<mail_parser::AddressList<'_>>| -> Vec<Addr> {
        list.map(|l| {
            l.mailboxes()
                .map(|m| Addr {
                    name: m.name().map(str::to_owned).filter(|n| !n.is_empty()),
                    address: m.address().map(str::to_owned),
                })
                .collect()
        })
        .unwrap_or_default()
    };
    let ids = |list: Option<mail_parser::TextList<'_>>| -> Vec<String> {
        let Some(list) = list else {
            return Vec::new();
        };
        (0..list.len())
            .filter_map(|i| list.get(i))
            .filter_map(clean_id)
            .collect()
    };

    let mut text = String::new();
    for part in message.text_bodies() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&part);
        if text.len() > TEXT_CAP {
            break;
        }
    }
    truncate(&mut text, TEXT_CAP);

    let mut html = String::new();
    for part in message.html_body() {
        if matches!(part.kind(), PartKind::Html)
            && let Some(h) = part.text()
        {
            html.push_str(&h);
        }
    }

    let attachments = message
        .attachments()
        .map(|part| Attachment {
            part: part.id(),
            name: part.attachment_name().map(str::to_owned),
            content_type: part
                .content_type()
                .map(|ct| match ct.subtype() {
                    Some(sub) => format!("{}/{}", ct.ctype(), sub),
                    None => ct.ctype().to_owned(),
                })
                .unwrap_or_else(|| "application/octet-stream".into())
                .to_ascii_lowercase(),
            size: part.decoded_len() as u64,
        })
        .collect();

    let snippet = snippet(&text);
    Parsed {
        available: true,
        message_id: message.message_id().and_then(clean_id),
        in_reply_to: ids(message.in_reply_to()),
        references: ids(message.references()),
        subject: message.subject().map(str::to_owned),
        from: addrs(message.from()),
        to: addrs(message.to()),
        cc: addrs(message.cc()),
        date: message
            .date()
            .map(|d| d.to_timestamp().saturating_mul(1000)),
        has_attachments: message.has_attachments(),
        attachments,
        text: (!text.is_empty()).then_some(text),
        html: (!html.is_empty() && html.len() <= HTML_CAP).then_some(html),
        snippet,
        itip: skein_itip::imip::find(bytes).and_then(|i| skein_itip::summary(&i.calendar).ok()),
        tags: Vec::new(),
    }
}

fn clean_id(id: &str) -> Option<String> {
    let id = id
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim();
    (!id.is_empty() && id.len() <= 998).then(|| id.to_owned())
}

fn truncate(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

fn snippet(text: &str) -> Option<String> {
    let s: String = text
        .split_whitespace()
        .flat_map(|w| std::iter::once(' ').chain(w.chars()))
        .skip(1)
        .take(SNIPPET_CHARS)
        .collect();
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(path).unwrap()
    }

    #[test]
    fn plain_message() {
        let p = parse(&fixture("plain.eml"));
        assert!(p.available);
        assert_eq!(p.message_id.as_deref(), Some("plain@example.org"));
        assert_eq!(p.subject.as_deref(), Some("Quarterly garden report"));
        assert_eq!(
            p.from,
            vec![Addr {
                name: Some("Pat Doe".into()),
                address: Some("pat@example.com".into())
            }]
        );
        assert_eq!(p.to[0].address.as_deref(), Some("sam@example.org"));
        assert_eq!(p.date, Some(1_793_610_900_000));
        assert!(p.text.as_deref().unwrap().contains("tomatoes did well"));
        assert_eq!(p.html, None);
        assert!(!p.has_attachments);
        assert_eq!(
            p.snippet.as_deref(),
            Some("The tomatoes did well this quarter. The zucchini did not.")
        );
    }

    #[test]
    fn multipart_with_html_and_attachment() {
        let p = parse(&fixture("multipart.eml"));
        assert_eq!(
            p.text.as_deref().map(str::trim),
            Some("Please find the seating plan attached.")
        );
        assert!(p.html.as_deref().unwrap().contains("<b>seating plan</b>"));
        assert!(p.has_attachments);
        assert_eq!(p.attachments.len(), 1);
        let a = &p.attachments[0];
        assert_eq!(a.name.as_deref(), Some("seating.pdf"));
        assert_eq!(a.content_type, "application/pdf");
        assert_eq!(a.size, 45);
        assert!(a.part > 0);
        assert_eq!(p.to.len(), 2);
        assert_eq!(p.cc[0].address.as_deref(), Some("team@example.com"));
        assert_eq!(p.cc[0].name, None);
    }

    #[test]
    fn encoded_subject_and_html_only_body() {
        let p = parse(&fixture("encoded.eml"));
        assert_eq!(p.subject.as_deref(), Some("Grüße aus Köln"));
        assert_eq!(p.from[0].name.as_deref(), Some("Jürgen Beispiel"));
        let text = p.text.unwrap();
        assert!(text.contains("Viele Grüße vom Rhein."), "{text}");
        assert!(!text.contains("<p>"));
        assert!(p.html.unwrap().contains("<script>"), "HTML is kept as-is");
        assert_eq!(p.date, Some(1_793_777_400_000));
    }

    #[test]
    fn reply_ids() {
        let p = parse(&fixture("reply2.eml"));
        assert_eq!(p.message_id.as_deref(), Some("reply2@example.com"));
        assert_eq!(p.in_reply_to, vec!["reply1@example.com"]);
        assert_eq!(p.references, vec!["root@example.com", "reply1@example.com"]);
    }

    #[test]
    fn caps_text_and_drops_oversized_html() {
        let body = "word ".repeat(TEXT_CAP / 4);
        let raw = format!("Subject: big\r\nContent-Type: text/plain\r\n\r\n{body}");
        let p = parse(raw.as_bytes());
        assert!(p.text.as_ref().unwrap().len() <= TEXT_CAP);
        assert_eq!(p.snippet.unwrap().chars().count(), SNIPPET_CHARS);
        let html = format!(
            "Subject: big\r\nContent-Type: text/html\r\n\r\n<p>{}</p>",
            "x".repeat(HTML_CAP)
        );
        let p = parse(html.as_bytes());
        assert_eq!(p.html, None);
        assert!(p.text.is_some());
    }

    #[test]
    fn tags_are_checked_sorted_and_capped() {
        assert!(valid_tag("spam.junk"));
        assert!(valid_tag("category.person-direct_1"));
        for bad in ["", "Spam", "a b", "a/b", "x\n", &"a".repeat(65), "é"] {
            assert!(!valid_tag(bad), "{bad:?}");
        }
        let many: Vec<String> = (0..20).rev().map(|i| format!("t{i:02}")).collect();
        let mut with_bad = many.clone();
        with_bad.push("BAD".into());
        with_bad.push("t01".into());
        let kept = clean_tags(&with_bad);
        assert_eq!(kept.len(), MAX_TAGS);
        assert_eq!(kept[0], "t00");
        assert!(kept.windows(2).all(|w| w[0] < w[1]));
    }

    #[tokio::test]
    async fn the_default_parser_refuses_what_it_cannot_read() {
        let ok = MailParser
            .parse(&Bytes::from(fixture("plain.eml")), &ParseContext::default())
            .await
            .unwrap();
        assert!(ok.available);
        assert_eq!(
            MailParser
                .parse(&Bytes::from_static(b""), &ParseContext::default())
                .await,
            Err(ParseError::Refused)
        );
    }

    #[test]
    fn garbage_still_parses_to_something() {
        let p = parse(b"\x00\xff not a message");
        assert!(p.message_id.is_none());
        let mut s = "aé".repeat(3);
        truncate(&mut s, 2);
        assert_eq!(s, "a");
    }
}
