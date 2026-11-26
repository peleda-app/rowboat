//! The sent copy of a message whose sending service replaced its `Message-ID`.

/// The header a rewritten sent copy keeps the message's own `Message-ID` in.
pub const ORIGINAL_MESSAGE_ID: &str = "X-Skein-Original-Message-ID";

/// Whether `id` is a `Message-ID` value that is safe to write into a header: `<left@right>` of
/// printable ASCII without spaces, at most 998 bytes.
pub(crate) fn well_formed(id: &str) -> bool {
    id.len() <= 998
        && id
            .strip_prefix('<')
            .and_then(|rest| rest.strip_suffix('>'))
            .is_some_and(|inner| {
                inner
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && b != b'<' && b != b'>')
                    && inner
                        .split_once('@')
                        .is_some_and(|(l, r)| !l.is_empty() && !r.is_empty() && !r.contains('@'))
            })
}

struct Field {
    start: usize,
    colon: usize,
    end: usize,
    eol: &'static [u8],
}

fn line_end(message: &[u8], from: usize) -> (usize, &'static [u8]) {
    match message[from..].iter().position(|&b| b == b'\n') {
        Some(at) if at > 0 && message[from + at - 1] == b'\r' => (from + at + 1, b"\r\n"),
        Some(at) => (from + at + 1, b"\n"),
        None => (message.len(), b"\r\n"),
    }
}

/// The header fields of `message`, and where its header block ends (the start of the blank
/// line, or the end of the message when there is none).
fn fields(message: &[u8]) -> (Vec<Field>, usize, &'static [u8]) {
    let mut fields: Vec<Field> = Vec::new();
    let mut eol: Option<&'static [u8]> = None;
    let mut at = 0;
    while at < message.len() {
        let (next, this_eol) = line_end(message, at);
        let line = &message[at..next];
        if line == b"\r\n" || line == b"\n" {
            return (fields, at, eol.unwrap_or(this_eol));
        }
        eol.get_or_insert(this_eol);
        match (line.first(), fields.last_mut()) {
            (Some(b' ' | b'\t'), Some(field)) => field.end = next,
            _ => {
                if let Some(colon) = line.iter().position(|&b| b == b':') {
                    fields.push(Field {
                        start: at,
                        colon: at + colon,
                        end: next,
                        eol: this_eol,
                    });
                }
            }
        }
        at = next;
    }
    (fields, message.len(), eol.unwrap_or(b"\r\n"))
}

fn unfolded(value: &[u8]) -> String {
    let text: Vec<u8> = value
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    String::from_utf8_lossy(&text).trim().to_owned()
}

/// `message` with the value of its first `Message-ID` field replaced by `delivered`, and the
/// value it had kept in an [`ORIGINAL_MESSAGE_ID`] field right after it. Only the header block
/// changes: the field name keeps its spelling, a folded value becomes one line, every other byte
/// stays as it was, and the body is never touched. A message without a `Message-ID` gets one at
/// the end of its header block. New lines end like the message's own (`CRLF` or `LF`).
///
/// `None` when nothing needs to change: `delivered` is not [`well_formed`], or it is already the
/// message's `Message-ID`.
pub(crate) fn rewrite(message: &[u8], delivered: &str) -> Option<Vec<u8>> {
    if !well_formed(delivered) {
        return None;
    }
    let (fields, header_end, eol) = fields(message);
    let found = fields.iter().find(|f| {
        message[f.start..f.colon]
            .trim_ascii_end()
            .eq_ignore_ascii_case(b"message-id")
    });
    let mut out = Vec::with_capacity(message.len() + 2 * delivered.len() + 64);
    match found {
        Some(field) => {
            let original = unfolded(&message[field.colon + 1..field.end]);
            if original == delivered {
                return None;
            }
            out.extend_from_slice(&message[..=field.colon]);
            out.push(b' ');
            out.extend_from_slice(delivered.as_bytes());
            out.extend_from_slice(field.eol);
            if !original.is_empty() {
                out.extend_from_slice(ORIGINAL_MESSAGE_ID.as_bytes());
                out.extend_from_slice(b": ");
                out.extend_from_slice(original.as_bytes());
                out.extend_from_slice(field.eol);
            }
            out.extend_from_slice(&message[field.end..]);
        }
        None => {
            out.extend_from_slice(&message[..header_end]);
            if header_end == message.len() && !message.is_empty() && !message.ends_with(b"\n") {
                out.extend_from_slice(eol);
            }
            out.extend_from_slice(b"Message-ID: ");
            out.extend_from_slice(delivered.as_bytes());
            out.extend_from_slice(eol);
            out.extend_from_slice(&message[header_end..]);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SES: &str = "<0102-abc-000000@eu-west-1.amazonses.com>";

    fn rewritten(message: &str) -> String {
        String::from_utf8(rewrite(message.as_bytes(), SES).expect("rewritten")).unwrap()
    }

    #[test]
    fn replaces_only_the_message_id_value() {
        let message = "From: Ada <ada@example.com>\r\nMessage-ID: <a1@example.com>\r\nSubject: Hi\r\n\r\nMessage-ID: <body@example.com>\r\n";
        assert_eq!(
            rewritten(message),
            format!(
                "From: Ada <ada@example.com>\r\nMessage-ID: {SES}\r\n{ORIGINAL_MESSAGE_ID}: <a1@example.com>\r\nSubject: Hi\r\n\r\nMessage-ID: <body@example.com>\r\n"
            )
        );
    }

    #[test]
    fn unfolds_a_folded_message_id() {
        let message = "Subject: Hi\r\nMessage-Id:\r\n <folded@example.com>\r\nTo: bob@example.org\r\n\r\nHello\r\n";
        assert_eq!(
            rewritten(message),
            format!(
                "Subject: Hi\r\nMessage-Id: {SES}\r\n{ORIGINAL_MESSAGE_ID}: <folded@example.com>\r\nTo: bob@example.org\r\n\r\nHello\r\n"
            )
        );
    }

    #[test]
    fn matches_the_name_in_any_case_and_with_space_before_the_colon() {
        let message = "MESSAGE-ID : <a1@example.com>\r\n\r\nHi\r\n";
        assert_eq!(
            rewritten(message),
            format!("MESSAGE-ID : {SES}\r\n{ORIGINAL_MESSAGE_ID}: <a1@example.com>\r\n\r\nHi\r\n")
        );
        let lookalike = "X-Message-ID: <x@example.com>\r\n\r\nHi\r\n";
        assert_eq!(
            rewritten(lookalike),
            format!("X-Message-ID: <x@example.com>\r\nMessage-ID: {SES}\r\n\r\nHi\r\n")
        );
    }

    #[test]
    fn adds_a_missing_message_id_at_the_end_of_the_header_block() {
        let message = "From: ada@example.com\r\nSubject: Hi\r\n\r\nBody\r\n";
        assert_eq!(
            rewritten(message),
            format!("From: ada@example.com\r\nSubject: Hi\r\nMessage-ID: {SES}\r\n\r\nBody\r\n")
        );
        let headers_only = "Subject: Hi\r\n";
        assert_eq!(
            rewritten(headers_only),
            format!("Subject: Hi\r\nMessage-ID: {SES}\r\n")
        );
    }

    #[test]
    fn keeps_bare_lf_line_endings() {
        let message = "Subject: Hi\nMessage-ID: <a1@example.com>\n\nBody\n";
        assert_eq!(
            rewritten(message),
            format!(
                "Subject: Hi\nMessage-ID: {SES}\n{ORIGINAL_MESSAGE_ID}: <a1@example.com>\n\nBody\n"
            )
        );
        let missing = "Subject: Hi\n\nBody\n";
        assert_eq!(
            rewritten(missing),
            format!("Subject: Hi\nMessage-ID: {SES}\n\nBody\n")
        );
    }

    #[test]
    fn never_reads_the_body_as_headers() {
        let message = "Subject: Hi\r\n\r\nMessage-ID: <in-body@example.com>\r\n";
        assert_eq!(
            rewritten(message),
            format!(
                "Subject: Hi\r\nMessage-ID: {SES}\r\n\r\nMessage-ID: <in-body@example.com>\r\n"
            )
        );
        let body_bytes = b"Message-ID: <a@example.com>\r\n\r\n\xff\xfe binary\r\n";
        let out = rewrite(body_bytes, SES).unwrap();
        assert!(out.ends_with(b"\r\n\r\n\xff\xfe binary\r\n"));
    }

    #[test]
    fn leaves_the_message_alone_when_nothing_changes() {
        let message = format!("Message-ID: {SES}\r\n\r\nHi\r\n");
        assert_eq!(rewrite(message.as_bytes(), SES), None);
        for bad in [
            "",
            "plain@example.com",
            "<no-at>",
            "<a b@example.com>",
            "<a@example.com>\r\nBcc: eve@example.org",
            "<a@b@c>",
        ] {
            assert_eq!(rewrite(b"Subject: Hi\r\n\r\nHi\r\n", bad), None, "{bad:?}");
        }
    }
}
