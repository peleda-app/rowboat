# skein-send-ses

The sending contract (`skein-send`) on Amazon SES through the v2 `SendEmail` API. An account can read mail through its own provider (IMAP, Graph, Gmail, JMAP) and send from the same address through SES. `SesSender` posts the message as `Content.Raw`, byte for byte, to `POST /v2/email/outbound-emails`, signed with AWS Signature Version 4 by this crate (no AWS SDK). SES keeps no copy in a Sent mailbox, so `saves_to_sent()` is false and the engine appends the copy through the mail provider when the command asks for one.

## Public API

- `SesSender::new(settings, credentials)` takes only `Credentials::AccessKey { id, secret, session_token }`. Anything else, an id that is not letters and digits, an empty or non-printable secret or token, a region that is not a region name, an endpoint that is not `https` (plain `http` only to loopback) or has a path, query or credentials, an empty configuration set or identity ARN, a `message_id_domain` that is not a hostname, or a zero size limit is `Invalid`, before anything is sent.
- `send` reports SES's `MessageId` as `provider_message_id` and the `Message-ID` SES gives the message, `<{MessageId}@{message_id_domain}>`, as `message_id` (see [Message-ID](#message-id)). An answer without a usable `MessageId` (missing, or not letters, digits, `-`, `_`, `.`) is still a success, with neither.
- `valid_hostname(name)` and `region_message_id_domain(region)` are what `new` uses.
- `SesSender::with_timeout(d)` (default 120 s). A send without an answer by then is `Uncertain`.
- `check()` reads `GET /v2/email/account` and sends nothing: `SendingEnabled: false` or `EnforcementStatus: SHUTDOWN` is `Invalid`; a server error or no answer is `Unavailable`. Returns `Limits { max_size, smtputf8: false, dsn: false }`.
- `SesSettings::from_json`; `MAX_SIZE` (30,000,000 bytes of raw message: SES v2 takes 40 MB per message after base64), `MAX_RECIPIENTS` (50).

## Settings

The account record's `send` is `{"kind": "ses", "settings": {...}}`; the access key is sealed separately (`skein account send-key`, `Accounts::set_send_key`) and never returned.

| Field | Default | Meaning |
| --- | --- | --- |
| `region` | required | AWS region, such as `eu-west-1` |
| `endpoint` | `https://email.{region}.amazonaws.com` | API origin for compatible services and tests; `https` only, plain `http` only to loopback; no path |
| `configuration_set` | none | `ConfigurationSetName` for every message (event publishing, dedicated IPs) |
| `from_identity_arn` | none | `FromEmailAddressIdentityArn`, when another AWS account authorized this one to send from its identity |
| `message_id_domain` | from the region on AWS endpoints; none with a custom endpoint | The domain SES puts in the `Message-ID` it gives each message: `email.amazonses.com` in `us-east-1`, `{region}.amazonses.com` elsewhere. Set it for a compatible service behind `endpoint`, or if AWS's domain for a region differs; a hostname |
| `max_size` | 30,000,000 | Largest raw message handed over, capped at the default |
| `roots` | none | `TlsRoots` trusted besides the built-in roots; not serialized |

## Prerequisites

- **A verified identity.** The sending address or its domain must be a verified SES identity in the region. New accounts are in the sandbox and may send only to verified addresses until production access is granted.
- **Domain authentication.** Publish Easy DKIM records (three CNAMEs) for the domain, for SPF alignment set up a custom MAIL FROM subdomain with an MX record and `v=spf1 include:amazonses.com ~all` (without one the return path is on `amazonses.com` and DMARC passes through DKIM alone), and publish a DMARC policy. Without DKIM alignment, recipients that enforce DMARC reject or junk the mail.
- **IAM.** The key needs `ses:SendEmail` and `ses:SendRawEmail` (grant both: which one SES checks for a raw v2 `SendEmail` has changed over time) on the identity and the configuration set, and `ses:GetAccount` for `check()`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ses:SendEmail", "ses:SendRawEmail"],
      "Resource": [
        "arn:aws:ses:eu-west-1:123456789012:identity/example.com",
        "arn:aws:ses:eu-west-1:123456789012:configuration-set/transactional"
      ]
    },
    { "Effect": "Allow", "Action": "ses:GetAccount", "Resource": "*" }
  ]
}
```

Temporary credentials (with `session_token`) stop working when they expire; the next send is then `Auth`.

## Request

```json
{
  "FromEmailAddress": "ada@example.com",
  "FromEmailAddressIdentityArn": "arn:aws:ses:eu-west-1:123456789012:identity/example.com",
  "Destination": { "ToAddresses": ["bob@example.org", "carol@example.org"] },
  "Content": { "Raw": { "Data": "<base64 of the message>" } },
  "ConfigurationSetName": "transactional"
}
```

- `Destination.ToAddresses` holds every envelope recipient, so a Bcc recipient reaches SES without a `Bcc` field in the bytes; the header fields recipients see are the message's own.
- `FromEmailAddress` is the envelope return path when it is not empty; SES uses it for bounce and complaint feedback and requires it to be a verified identity. With the null return path it is left out and SES takes the `From` field.
- Signed headers: `content-type`, `host`, `x-amz-date` and `x-amz-security-token` when there is a session token. The key goes only to the configured origin; redirects are never followed.

## Error mapping

| SES answer | Result |
| --- | --- |
| `TooManyRequestsException`, `ThrottlingException`, `LimitExceededException` (daily quota), any `429` | `Throttled` with `Retry-After` in seconds when given; nothing sent |
| `MessageRejected` | `Refused { permanent, 554 }` (content, or an unverified address in the sandbox); text carries SES's message |
| `AccountSuspendedException`, `SendingPausedException`, `MailFromDomainNotVerifiedException`, `NotFoundException` (configuration set or identity), `OptInRequired`, any `404` | `Invalid`: the account cannot send as configured; the engine records it as `config` in the account's send status |
| `UnrecognizedClientException`, `InvalidSignatureException`, `SignatureDoesNotMatch`, `IncompleteSignature`, `InvalidClientTokenId`, `ExpiredTokenException`, `MissingAuthenticationToken`, `NotAuthorized`, `AccessDeniedException`, any other `401`/`403` | `Auth` (`reauth_required`): a new key or IAM permission is needed |
| `RequestEntityTooLargeException`, `413` | `TooLarge` |
| `RequestTimeoutException`, `RequestAbortedException`, `408` | `Temporary`: SES did not get the whole request |
| `BadRequestException`, other `4xx` | `Refused { permanent, 554 }` |
| `5xx`, a broken connection or no answer after the request left | `Uncertain`: never resent |
| connection refused or failed before the request | `Unavailable` |

The code comes from the `x-amzn-ErrorType` header or, without it, from the body's `__type` or `code`. Texts that `Display` shows carry only the status and the code, never SES's message, which may name addresses.

Checked before connecting: `Envelope::validate`, at most 50 recipients and ASCII addresses (`Invalid`; SES takes internationalized domains only as punycode and no non-ASCII local parts), and the size limit (`TooLarge`).

## Message-ID

SES overrides any `Message-ID` header in the message with its own value ([SES header fields](https://docs.aws.amazon.com/ses/latest/dg/header-fields.html)). The value is the `MessageId` that `SendEmail` answers, in angle brackets, at `email.amazonses.com` for `us-east-1` and at `{region}.amazonses.com` elsewhere, such as `<0102018c...-000000@eu-west-1.amazonses.com>`. Recipients' replies point at it in `In-Reply-To` and `References`.

So a successful send reports `message_id: "<{MessageId}@{domain}>"`, and the engine saves the sent copy with that `Message-ID` (keeping the original in `X-Skein-Original-Message-ID`), so replies thread with it. An endpoint on `amazonaws.com` (AWS's own, including FIPS endpoints) takes the domain from the region; any other endpoint needs `message_id_domain`, and without it only `provider_message_id` is reported and the copy keeps the message's own `Message-ID`.

## Quirks

- One refused recipient refuses the whole message; there are no per-recipient results. DSN and `ENVID` are not available: SES reports bounces through feedback forwarding or event destinations.
- SES replaces the `Message-ID` (see above) and the `Date` of every message it delivers, and signs with DKIM when the identity has it; the journal keeps the bytes Skein handed over, and the saved sent copy differs from them only in its `Message-ID`.
- Messages over 10 MB may be sent more slowly by SES.
- Signing follows AWS Signature Version 4 and is tested against the AWS test suite vectors in `tests/fixtures/sigv4/`; the fake SES in the tests recomputes the signature of every request it receives.
