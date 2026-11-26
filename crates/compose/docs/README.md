# rowboat-compose

A draft (`rowboat_api::Draft`) to RFC 5322 bytes and a send envelope. Pure and deterministic: the date, the `Message-ID` and the MIME boundary seed come from the caller (`Identity`), so equal input gives equal bytes.

```rust
let composed = compose(&draft, &Identity {
    from: &account_address,
    from_name: Some("Pat Doe"),
    date_ms: now_ms,
    message_id_local: &ulid,        // [A-Za-z0-9]{1,64}
    boundary_seed: &random_alnum,   // [A-Za-z0-9]{8,40}
})?;
// composed.bytes, composed.envelope_from, composed.recipients, composed.message_id
```

## What it writes

- Headers: `From`, `To`, `Cc` (when any), `Subject`, `Date` (UTC, `+0000`), `Message-ID` (`<local@domain-of-from>`, domain lower case), `In-Reply-To` and `References` for replies (the answered id appended to its references), `MIME-Version`.
- Header text that is not short plain ASCII (non-ASCII, over 70 characters, or containing `=?`) becomes RFC 2047 `B` encoded words of at most 45 bytes each, folded onto continuation lines; plain display names are quoted with `"` and `\` escaped. Control characters become spaces, so no header value can carry CR or LF.
- Body: `text/plain; charset=utf-8`, line endings CRLF, `7bit` when ASCII with lines of at most 76 bytes, otherwise quoted-printable (always quoted-printable inside a multipart body, so the boundary can never appear in it).
- Attachments: `multipart/mixed` with boundary `=_rowboat_<seed>`, each part base64 in 76-character lines, `name*` and `filename*` in RFC 2231 form on their own folded lines, split into numbered continuations (`name*0*=`, `name*1*=`) of at most 60 characters, whole characters each, when longer, the type from the file extension (`media_type`; `application/octet-stream` otherwise).
- Bcc recipients go only to `recipients`, never into the bytes. `recipients` is To, Cc, Bcc in that order without repeats, compared case-insensitively.

## Limits and refusals

`compose` runs `rowboat_api::check::sendable` first (500 recipients, 25 MiB of attachments, 1 MiB of text, one-line subject and names, attachment names without `/`, `\` or control characters) and refuses a bad `Message-ID` part or boundary seed. `ComposeError` carries no content and maps to `NodeError::InvalidInput`.

## Tests

Round trips through `rinse-mail-direct` (subject, names, text, attachments and their names, reply facts), header injection attempts through subject and names, Bcc never in the bytes, dates, and a property test that any sendable draft gives an ASCII message with CRLF line endings, lines of at most 998 bytes and only field or continuation lines in the header.
