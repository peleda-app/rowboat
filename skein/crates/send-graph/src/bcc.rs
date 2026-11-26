use std::borrow::Cow;

use mail_parser::{HeaderName, MessageParser};
use skein_send::{Envelope, SendError};

/// The bytes a service that reads recipients from the header receives for `envelope`: `message` unchanged when its To, Cc and Bcc name
/// every envelope recipient, else `message` with one `Bcc` field in front naming the rest.
pub(crate) fn with_bcc<'a>(
    envelope: &Envelope,
    message: &'a [u8],
) -> Result<Cow<'a, [u8]>, SendError> {
    let parsed = MessageParser::new()
        .parse_headers(message)
        .ok_or_else(|| SendError::Invalid("the message header cannot be read".into()))?;
    let headers = parsed.headers();
    let mut named = Vec::new();
    for list in headers
        .all_to()
        .chain(headers.all_cc())
        .chain(headers.all_bcc())
    {
        for mailbox in list.mailboxes() {
            let address = mailbox
                .address()
                .filter(|a| a.contains('@'))
                .ok_or_else(|| {
                    SendError::Invalid("an address in To, Cc or Bcc cannot be read".into())
                })?;
            named.push(address);
        }
    }
    let in_envelope = |address: &str| {
        envelope
            .recipients
            .iter()
            .any(|r| r.eq_ignore_ascii_case(address))
    };
    if !named.iter().all(|a| in_envelope(a)) {
        return Err(SendError::Invalid(
            "the service sends to every address in To, Cc and Bcc, and one of them is not in \
             the envelope"
                .into(),
        ));
    }
    let mut extra: Vec<&str> = Vec::new();
    for recipient in &envelope.recipients {
        let known = named
            .iter()
            .chain(extra.iter())
            .any(|a| a.eq_ignore_ascii_case(recipient));
        if !known {
            extra.push(recipient);
        }
    }
    if extra.is_empty() {
        return Ok(Cow::Borrowed(message));
    }
    if headers.all(HeaderName::Bcc).next().is_some() {
        return Err(SendError::Invalid(
            "the message has a Bcc field and the envelope has recipients it does not name".into(),
        ));
    }
    let mut out =
        Vec::with_capacity(message.len() + extra.iter().map(|a| a.len() + 4).sum::<usize>() + 8);
    out.extend_from_slice(b"Bcc: ");
    out.extend_from_slice(extra.join(",\r\n ").as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(message);
    Ok(Cow::Owned(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(recipients: &[&str]) -> Envelope {
        Envelope {
            mail_from: "ada@example.com".into(),
            dsn: None,
            envid: None,
            recipients: recipients.iter().map(|r| (*r).to_owned()).collect(),
        }
    }

    const MESSAGE: &[u8] = b"From: Ada <ada@example.com>\r\nTo: Bob <bob@example.org>\r\nCc: carol@example.org\r\nSubject: Hi\r\n\r\nHello\r\n";

    #[test]
    fn leaves_messages_alone_when_the_headers_name_everyone() {
        let out = with_bcc(
            &envelope(&["BOB@example.org", "carol@example.org"]),
            MESSAGE,
        )
        .unwrap();
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(&*out, MESSAGE);
    }

    #[test]
    fn adds_one_bcc_field_for_envelope_only_recipients() {
        let out = with_bcc(
            &envelope(&[
                "bob@example.org",
                "dan@example.org",
                "carol@example.org",
                "erin@example.org",
                "Dan@example.org",
            ]),
            MESSAGE,
        )
        .unwrap();
        let mut expected = b"Bcc: dan@example.org,\r\n erin@example.org\r\n".to_vec();
        expected.extend_from_slice(MESSAGE);
        assert_eq!(&*out, expected.as_slice());
    }

    #[test]
    fn adds_bcc_to_undisclosed_recipients() {
        let message = b"From: ada@example.com\r\nTo: undisclosed-recipients:;\r\n\r\nHi\r\n";
        let out = with_bcc(&envelope(&["bob@example.org"]), message).unwrap();
        assert!(out.starts_with(b"Bcc: bob@example.org\r\nFrom:"));
    }

    #[test]
    fn refuses_header_recipients_outside_the_envelope() {
        let error = with_bcc(&envelope(&["bob@example.org"]), MESSAGE).unwrap_err();
        assert!(matches!(error, SendError::Invalid(_)));
        let grouped = b"To: Team: bob@example.org, dan@example.org;\r\n\r\nHi\r\n";
        assert!(with_bcc(&envelope(&["bob@example.org"]), grouped).is_err());
    }

    #[test]
    fn refuses_a_second_bcc_field() {
        let message = b"To: bob@example.org\r\nBcc: carol@example.org\r\n\r\nHi\r\n";
        let same = with_bcc(
            &envelope(&["bob@example.org", "carol@example.org"]),
            message,
        )
        .unwrap();
        assert_eq!(&*same, message.as_slice());
        let error = with_bcc(
            &envelope(&["bob@example.org", "carol@example.org", "dan@example.org"]),
            message,
        )
        .unwrap_err();
        assert!(matches!(error, SendError::Invalid(_)));
    }
}
