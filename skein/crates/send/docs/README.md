# skein-send

The sending contract. Skein is not an MTA: a `Sender` hands the exact bytes of a prebuilt RFC 5322 message, with an explicit envelope, to the account's sending service (SMTP submission, the Gmail API, Microsoft Graph, JMAP, Amazon SES), which signs, queues and delivers it. The one distinction every caller depends on is whether a failed send may have reached the service: only `SendError::Uncertain` may have; every other error guarantees nothing was sent.

## Public API

- `Envelope { mail_from, recipients, dsn, envid }`: the return path (empty is `<>`), every recipient in offer order (Bcc recipients are here and never in the bytes), delivery status notifications to ask for (`skein_core::Dsn`) and the transmission id (`ENVID`, printable ASCII). `Envelope::new(from, recipients)`.
- `Envelope::validate(message)`: refuses with `Invalid` an envelope without recipients, an address without `@` or with whitespace, control characters or angle brackets, a non-printable `envid`, and a message that is empty, holds a NUL or a bare CR or LF, or does not end with CRLF.
- `Sender` (object-safe, `Send + Sync`, `#[async_trait]`):
  - `check()` signs in without sending and returns `Limits { max_size, smtputf8, dsn }`.
  - `send(envelope, message)`: **at most once** (one call offers the message once and never retries on its own); **bytes unchanged** (except one added `Bcc` field for services that read recipients from the header, Gmail and Graph); invalid input is refused before connecting; a message over an announced limit is `TooLarge` before it is sent; `Ok(SendReport)` means at least one recipient was taken, with one `RecipientResult` per envelope recipient in envelope order, and says what the service delivered (below); every recipient refused is `RecipientsRefused` with nothing sent.
  - `saves_to_sent()`: whether the service keeps the sent copy itself, so the caller must not append one.
- `SendReport { recipients, message_id, provider_message_id }` (`#[non_exhaustive]`: build it with `SendReport::new(recipients)` or `SendReport::all_accepted(envelope)`, then `with_message_id` and `with_provider_message_id`), `SendReport::refused()`:
  - `message_id`: the `Message-ID` recipients got, as the header value with angle brackets (`<id@host>`), when the service replaced the message's own (Amazon SES does). `None` means the service keeps the message's own `Message-ID`, or the sender cannot know what it delivered. Callers that save a sent copy themselves use it so replies thread with the copy.
  - `provider_message_id`: the service's own id for the message (SES `MessageId`, Gmail message id, JMAP `EmailSubmission` id), for matching the service's later notifications; `None` when it gave none (SMTP, Graph). Never shown to recipients.
-  `RecipientResult`, `RecipientOutcome::{Accepted, Refused(Refusal)}`, `Refusal { permanent, code, text }` (`text` may name addresses: never log it).
- `SendError::{Auth, Refused, RecipientsRefused, Temporary, Throttled, Uncertain, TooLarge, Invalid, Unavailable, Tls, Insecure, Timeout}`:
  - `Tls`: the handshake or certificate check failed, or the server answered in plain text where TLS was expected, before anything was sent; `Insecure`: plain text to a remote host or a server without STARTTLS, nothing sent; `Timeout`: no answer within the deadline before the message was complete (after it, `Uncertain`).
  - `cause()`: the variant as a closed, serializable `SendCause` without text (`unreachable` for `Unavailable`), for callers that must not match texts.
  - `Throttled { retry_after: Option<Duration> }`: the service refused the request for its rate (an HTTP `429`, or a `503` marked as throttling) before it took the message, so nothing was sent; `retry_after` is the `Retry-After` it gave, when it gave one.
  - `is_retryable()`: temporary refusals, broken exchanges, throttling, unreachable services, TLS failures, timeouts, recipient refusals with at least one temporary. Never for `Uncertain` or `Insecure`.
  - `retry_after()`: the wait the service asked for before the next try, only from `Throttled`; `None` when it named none (SMTP never does: `421` and `451` carry no delay).
  - `may_have_been_sent()`: only `Uncertain`.
  - `reason()`: a machine-readable word without addresses or server text, for journal events and logs. `Display` never includes server text either.

## What an implementation must do

- Validate with `Envelope::validate` before connecting.
- Report `message_id` only when the service replaces the message's `Message-ID` and the new value is known; report a `provider_message_id` when the service answers one at no extra cost. Neither may hold whitespace or control characters.
- Map a rate refusal before the service took the message to `Throttled`, with the service's requested wait when it gave one in seconds.
- Map every failure before the whole message left to an error other than `Uncertain`; map silence, a broken connection or a server error after the message left to `Uncertain`. Never retry inside `send`.
- Send credentials only where its configuration says, follow no redirects with credentials, and never log content, addresses or secrets.
- Pass the conformance suite.

## Conformance and the fake

Behind the `testing` feature:

- `testing::conformance(&receiver)` runs the suite against fakes a `Receiver` starts per `Behavior` (`AcceptAll`, `RefuseRecipient`, `TemporaryFailure` (which an HTTP service may answer as `Throttled`), `PermanentFailure`, `DropAfterData`, `SizeLimit`). When a report carries ids, the suite checks that `message_id` is `<left@right>` and differs from the message's own, and that `provider_message_id` is printable. `Receiver::profile()` says what the protocol can express: `Profile::FULL` (SMTP, JMAP: return path and per-recipient refusals) or `Profile::HEADER_ONLY` (Gmail, Graph). Fakes record `Delivery { mail_from, recipients, bytes }` as recipients get them.
- `testing::FakeSender`: an in-memory service for engine tests. It takes everything by default, records deliveries, counts calls, can be scripted (`script(result)`), can claim to keep sent copies (`saving_to_sent()`) and can replace the `Message-ID` like SES (`replacing_message_id(message_id, provider_message_id)`, reported on every unscripted send). `FakeReceiver` holds it to the suite.

```rust
#[tokio::test]
async fn keeps_the_send_contract() {
    skein_send::testing::conformance(&MyReceiver).await;
}
```
