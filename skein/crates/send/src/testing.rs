//! A fake sender for engine tests, and the conformance suite every [`Sender`] implementation runs
//! in its own tests against a fake service it brings along.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::{
    Envelope, Limits, RecipientOutcome, RecipientResult, Refusal, SendError, SendReport, Sender,
};

/// How a fake service behaves for one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Behavior {
    /// Takes every message for every recipient.
    AcceptAll,
    /// Refuses this recipient permanently and takes the message for the others.
    RefuseRecipient(String),
    /// Refuses every message temporarily once it is complete. An HTTP service may answer as
    /// throttled ([`SendError::Throttled`]).
    TemporaryFailure,
    /// Refuses every message permanently once it is complete.
    PermanentFailure,
    /// Reads the whole message, records it, and drops the connection without answering.
    DropAfterData,
    /// Announces this limit in bytes and refuses larger messages.
    SizeLimit(u64),
}

/// A message as a fake service received it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The return path the client gave; empty when the protocol has none.
    pub mail_from: String,
    /// The recipients the service took.
    pub recipients: Vec<String>,
    /// The message bytes as recipients get them (transfer encoding undone, an added `Bcc` field
    /// removed).
    pub bytes: Vec<u8>,
}

/// Messages a fake service received, shared between the fake and the suite.
#[derive(Debug, Clone, Default)]
pub struct Deliveries(Arc<Mutex<Vec<Delivery>>>);

impl Deliveries {
    /// Records a received message, including one the fake will not answer.
    pub fn push(&self, delivery: Delivery) {
        self.0.lock().expect("deliveries").push(delivery);
    }

    /// Every message received so far, in order.
    pub fn all(&self) -> Vec<Delivery> {
        self.0.lock().expect("deliveries").clone()
    }
}

/// A started fake service and a sender pointed at it.
pub struct Fake {
    /// A sender configured for the fake service.
    pub sender: Box<dyn Sender>,
    /// What the fake service receives.
    pub deliveries: Deliveries,
}

/// What the protocol under test can express, so the suite holds it only to what it allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// It hands the envelope's return path to the service, the null one included (SMTP, JMAP).
    /// Without it (Gmail, Graph) the service picks the return path and the suite does not check
    /// it.
    pub return_path: bool,
    /// The service takes or refuses each recipient on its own (SMTP, JMAP). Without it (Gmail,
    /// Graph) one refused recipient refuses the whole message, which must then be a definite,
    /// permanent refusal with nothing sent.
    pub per_recipient: bool,
}

impl Profile {
    /// Everything an SMTP submission server can express.
    pub const FULL: Profile = Profile {
        return_path: true,
        per_recipient: true,
    };

    /// A service that takes recipients from the header and picks the return path (Gmail, Graph).
    pub const HEADER_ONLY: Profile = Profile {
        return_path: false,
        per_recipient: false,
    };
}

/// Starts fake services for the suite.
#[async_trait]
pub trait Receiver: Send + Sync {
    /// Starts a fresh fake service that behaves as `behavior` and returns a sender for it.
    async fn start(&self, behavior: Behavior) -> Fake;

    /// What the protocol can express; [`Profile::FULL`] unless the implementation says less.
    fn profile(&self) -> Profile {
        Profile::FULL
    }
}

const ADA: &str = "ada@example.com";
const BOB: &str = "bob@example.org";
const CAROL: &str = "carol@example.org";
const REFUSED: &str = "nobody@example.org";

fn message() -> Vec<u8> {
    let mut bytes = b"From: Ada Example <ada@example.com>\r\n\
To: Bob Example <bob@example.org>\r\n\
Subject: Conformance\r\n\
Message-ID: <conformance@example.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: 8bit\r\n\
\r\n\
.leading dot\r\n\
.\r\n\
..two dots\r\n\
 trailing space \r\n\
\t\r\n\
Gr\xc3\xbc\xc3\x9fe\r\n"
        .to_vec();
    for line in 0..200 {
        bytes.extend_from_slice(format!("line {line} of the body\r\n").as_bytes());
    }
    bytes
}

fn msg_id_shaped(id: &str) -> bool {
    id.strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
        .and_then(|inner| inner.split_once('@'))
        .is_some_and(|(left, right)| {
            !left.is_empty()
                && !right.is_empty()
                && !right.contains('@')
                && id.len() <= 998
                && id[1..id.len() - 1]
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && b != b'<' && b != b'>')
        })
}

fn envelope(recipients: &[&str]) -> Envelope {
    Envelope::new(ADA, recipients.iter().map(|r| (*r).to_owned()).collect())
}

/// Checks that the senders `receiver` hands out keep the [`Sender`] contract. Panics on the first
/// violation.
pub async fn conformance(receiver: &dyn Receiver) {
    accepts_and_keeps_bytes(receiver).await;
    adds_envelope_only_recipients(receiver).await;
    refuses_invalid_input(receiver).await;
    reports_refused_recipients(receiver).await;
    maps_temporary_failure(receiver).await;
    maps_permanent_failure(receiver).await;
    reports_uncertain_after_data(receiver).await;
    enforces_size_limit(receiver).await;
}

async fn accepts_and_keeps_bytes(receiver: &dyn Receiver) {
    let fake = receiver.start(Behavior::AcceptAll).await;
    fake.sender.check().await.expect("check");
    assert!(fake.deliveries.all().is_empty(), "check sent a message");

    let bytes = message();
    let report = fake
        .sender
        .send(&envelope(&[BOB, CAROL]), &bytes)
        .await
        .expect("send");
    assert_eq!(report.recipients.len(), 2, "one result per recipient");
    assert_eq!(
        report.recipients[0].address, BOB,
        "results keep envelope order"
    );
    assert_eq!(
        report.recipients[1].address, CAROL,
        "results keep envelope order"
    );
    assert!(
        report
            .recipients
            .iter()
            .all(|r| r.outcome == RecipientOutcome::Accepted),
        "accepted recipients reported as refused"
    );
    assert_eq!(report.refused().count(), 0);
    if let Some(id) = &report.message_id {
        assert!(
            msg_id_shaped(id),
            "the delivered Message-ID is not <left@right>: {id:?}"
        );
        assert_ne!(
            id, "<conformance@example.com>",
            "a delivered Message-ID is reported only when the service replaced it"
        );
    }
    if let Some(id) = &report.provider_message_id {
        assert!(
            !id.is_empty() && id.bytes().all(|b| b.is_ascii_graphic()),
            "the provider message id is empty or not printable"
        );
    }

    let delivered = fake.deliveries.all();
    assert_eq!(delivered.len(), 1, "one send must deliver once");
    if receiver.profile().return_path {
        assert_eq!(delivered[0].mail_from, ADA, "return path changed");
    }
    assert_eq!(
        delivered[0].recipients,
        vec![BOB, CAROL],
        "recipients changed"
    );
    assert!(delivered[0].bytes == bytes, "bytes changed on the way");

    if !receiver.profile().return_path {
        return;
    }
    let null = Envelope::new("", vec![BOB.into()]);
    fake.sender
        .send(&null, &bytes)
        .await
        .expect("null return path");
    assert_eq!(
        fake.deliveries.all()[1].mail_from,
        "",
        "null return path changed"
    );
}

async fn adds_envelope_only_recipients(receiver: &dyn Receiver) {
    let fake = receiver.start(Behavior::AcceptAll).await;
    let bytes = message();
    let dan = "dan@example.net";
    let report = fake
        .sender
        .send(&envelope(&[BOB, CAROL, dan]), &bytes)
        .await
        .expect("a recipient only in the envelope");
    assert_eq!(report.recipients.len(), 3);
    let delivered = fake.deliveries.all();
    assert_eq!(delivered.len(), 1);
    assert_eq!(
        delivered[0].recipients,
        vec![BOB, CAROL, dan],
        "a Bcc recipient was lost"
    );
    assert!(
        delivered[0].bytes == bytes,
        "recipients see a Bcc recipient, or the bytes changed"
    );
}

async fn refuses_invalid_input(receiver: &dyn Receiver) {
    let fake = receiver.start(Behavior::AcceptAll).await;
    let bytes = message();
    let invalid = [
        fake.sender.send(&envelope(&[]), &bytes).await,
        fake.sender.send(&envelope(&["bob"]), &bytes).await,
        fake.sender
            .send(&envelope(&[BOB]), b"Subject: x\n\nbare LF\n")
            .await,
        fake.sender
            .send(&envelope(&[BOB]), b"Subject: x\r\n\r\nno end")
            .await,
    ];
    for (at, result) in invalid.into_iter().enumerate() {
        assert!(
            matches!(result, Err(SendError::Invalid(_))),
            "invalid input {at} was not refused as invalid: {result:?}"
        );
    }
    assert!(fake.deliveries.all().is_empty(), "invalid input was sent");
}

async fn reports_refused_recipients(receiver: &dyn Receiver) {
    let fake = receiver
        .start(Behavior::RefuseRecipient(REFUSED.into()))
        .await;
    let bytes = message();
    if !receiver.profile().per_recipient {
        let error = fake
            .sender
            .send(&envelope(&[BOB, REFUSED, CAROL]), &bytes)
            .await
            .expect_err("a refused recipient refuses the whole message");
        assert!(
            matches!(
                error,
                SendError::Refused {
                    permanent: true,
                    ..
                } | SendError::RecipientsRefused(_)
            ),
            "a refused recipient mapped to {error:?}"
        );
        assert!(!error.is_retryable());
        assert!(!error.may_have_been_sent());
        assert!(
            fake.deliveries.all().is_empty(),
            "a refused message was sent"
        );
        return;
    }
    let report = fake
        .sender
        .send(&envelope(&[BOB, REFUSED, CAROL]), &bytes)
        .await
        .expect("partial refusal still sends");
    assert_eq!(report.recipients.len(), 3);
    assert_eq!(report.recipients[0].outcome, RecipientOutcome::Accepted);
    assert_eq!(report.recipients[2].outcome, RecipientOutcome::Accepted);
    let refused: Vec<_> = report.refused().collect();
    assert_eq!(refused.len(), 1, "one recipient refused");
    assert_eq!(refused[0].0, REFUSED);
    assert!(refused[0].1.permanent, "refusal should be permanent");
    assert!(
        (500..600).contains(&refused[0].1.code),
        "permanent refusal code {}",
        refused[0].1.code
    );
    let delivered = fake.deliveries.all();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].recipients, vec![BOB, CAROL]);
    assert!(delivered[0].bytes == bytes, "bytes changed on the way");

    match fake.sender.send(&envelope(&[REFUSED]), &bytes).await {
        Err(error @ SendError::RecipientsRefused(_)) => {
            let SendError::RecipientsRefused(results) = &error else {
                unreachable!()
            };
            assert_eq!(results.len(), 1);
            assert!(
                !error.is_retryable(),
                "permanent refusals are not retryable"
            );
            assert!(!error.may_have_been_sent());
        }
        other => panic!("every recipient refused gave {other:?}"),
    }
    assert_eq!(
        fake.deliveries.all().len(),
        1,
        "a message with no recipient was sent"
    );
}

async fn maps_temporary_failure(receiver: &dyn Receiver) {
    let fake = receiver.start(Behavior::TemporaryFailure).await;
    let error = fake
        .sender
        .send(&envelope(&[BOB]), &message())
        .await
        .expect_err("temporary failure");
    assert!(
        matches!(
            error,
            SendError::Refused {
                permanent: false,
                ..
            } | SendError::Temporary(_)
                | SendError::Throttled { .. }
        ),
        "temporary failure mapped to {error:?}"
    );
    assert!(error.is_retryable(), "temporary failure must be retryable");
    assert!(!error.may_have_been_sent());
}

async fn maps_permanent_failure(receiver: &dyn Receiver) {
    let fake = receiver.start(Behavior::PermanentFailure).await;
    let error = fake
        .sender
        .send(&envelope(&[BOB]), &message())
        .await
        .expect_err("permanent failure");
    assert!(
        matches!(
            error,
            SendError::Refused {
                permanent: true,
                code: 500..600,
                ..
            }
        ),
        "permanent failure mapped to {error:?}"
    );
    assert!(!error.is_retryable());
    assert!(!error.may_have_been_sent());
}

async fn reports_uncertain_after_data(receiver: &dyn Receiver) {
    let fake = receiver.start(Behavior::DropAfterData).await;
    let bytes = message();
    let error = fake
        .sender
        .send(&envelope(&[BOB]), &bytes)
        .await
        .expect_err("dropped connection");
    assert!(
        matches!(error, SendError::Uncertain(_)),
        "drop after the message mapped to {error:?}"
    );
    assert!(error.may_have_been_sent());
    assert!(
        !error.is_retryable(),
        "uncertain must never be retried on its own"
    );
    let delivered = fake.deliveries.all();
    assert_eq!(delivered.len(), 1, "the sender retried on its own");
    assert!(delivered[0].bytes == bytes, "bytes changed on the way");
}

async fn enforces_size_limit(receiver: &dyn Receiver) {
    let bytes = message();
    let limit = bytes.len() as u64 - 1;
    let fake = receiver.start(Behavior::SizeLimit(limit)).await;
    let limits = fake.sender.check().await.expect("check");
    assert_eq!(limits.max_size, Some(limit), "announced size not reported");

    let error = fake
        .sender
        .send(&envelope(&[BOB]), &bytes)
        .await
        .expect_err("too large");
    assert!(matches!(error, SendError::TooLarge { .. }), "{error:?}");
    assert!(!error.is_retryable());
    assert!(
        fake.deliveries.all().is_empty(),
        "an oversized message was sent"
    );

    let small = b"To: bob@example.org\r\nSubject: Small\r\n\r\nHi\r\n";
    fake.sender
        .send(&envelope(&[BOB]), small)
        .await
        .expect("a message under the limit");
    assert_eq!(fake.deliveries.all().len(), 1);
}

#[derive(Default)]
struct FakeState {
    behavior: Option<Behavior>,
    scripted: VecDeque<Result<SendReport, SendError>>,
    calls: u64,
    message_id: Option<String>,
    provider_message_id: Option<String>,
}

/// An in-memory sending service for engine tests: it takes every message unless told otherwise,
/// records what it took, and can be scripted to answer the next calls with chosen results.
/// Clones share their state.
#[derive(Clone)]
pub struct FakeSender {
    state: Arc<Mutex<FakeState>>,
    deliveries: Deliveries,
    saves: bool,
}

impl Default for FakeSender {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeSender {
    /// A service that takes everything and does not keep a sent copy.
    pub fn new() -> Self {
        Self {
            state: Arc::default(),
            deliveries: Deliveries::default(),
            saves: false,
        }
    }

    /// A service that behaves as `behavior`, as the conformance suite expects.
    pub fn behaving(behavior: Behavior) -> Self {
        let fake = Self::new();
        fake.state.lock().expect("fake").behavior = Some(behavior);
        fake
    }

    /// Says the service keeps sent copies itself.
    pub fn saving_to_sent(mut self) -> Self {
        self.saves = true;
        self
    }

    /// Says the service delivers every message it takes as `message_id` (`<id@host>`) instead
    /// of the message's own `Message-ID`, and names it `provider_message_id`, as SES does. Both
    /// end up in every report it gives, scripted ones excepted.
    pub fn replacing_message_id(
        self,
        message_id: impl Into<String>,
        provider_message_id: impl Into<String>,
    ) -> Self {
        {
            let mut state = self.state.lock().expect("fake");
            state.message_id = Some(message_id.into());
            state.provider_message_id = Some(provider_message_id.into());
        }
        self
    }

    /// Answers the next call with `result` instead of taking the message. Scripted results are
    /// used in order; an `Ok` or an [`SendError::Uncertain`] still records the delivery.
    pub fn script(&self, result: Result<SendReport, SendError>) {
        self.state.lock().expect("fake").scripted.push_back(result);
    }

    /// Every message taken (or possibly taken), in order.
    pub fn deliveries(&self) -> Vec<Delivery> {
        self.deliveries.all()
    }

    /// How many times `send` was called, refusals included.
    pub fn calls(&self) -> u64 {
        self.state.lock().expect("fake").calls
    }

    fn record(&self, envelope: &Envelope, recipients: Vec<String>, message: &[u8]) {
        self.deliveries.push(Delivery {
            mail_from: envelope.mail_from.clone(),
            recipients,
            bytes: message.to_vec(),
        });
    }
}

fn refusal(permanent: bool, code: u16) -> Refusal {
    Refusal {
        permanent,
        code,
        text: format!("{code} refused by the fake"),
    }
}

#[async_trait]
impl Sender for FakeSender {
    async fn check(&self) -> Result<Limits, SendError> {
        let state = self.state.lock().expect("fake");
        Ok(Limits {
            max_size: match state.behavior {
                Some(Behavior::SizeLimit(limit)) => Some(limit),
                _ => None,
            },
            smtputf8: true,
            dsn: true,
        })
    }

    async fn send(&self, envelope: &Envelope, message: &[u8]) -> Result<SendReport, SendError> {
        envelope.validate(message)?;
        let (scripted, behavior, ids) = {
            let mut state = self.state.lock().expect("fake");
            state.calls += 1;
            (
                state.scripted.pop_front(),
                state.behavior.clone(),
                (state.message_id.clone(), state.provider_message_id.clone()),
            )
        };
        let identify = |mut report: SendReport| {
            report.message_id = ids.0.clone();
            report.provider_message_id = ids.1.clone();
            report
        };
        if let Some(result) = scripted {
            match &result {
                Ok(report) => {
                    let taken = report
                        .recipients
                        .iter()
                        .filter(|r| r.outcome == RecipientOutcome::Accepted)
                        .map(|r| r.address.clone())
                        .collect();
                    self.record(envelope, taken, message);
                }
                Err(SendError::Uncertain(_)) => {
                    self.record(envelope, envelope.recipients.clone(), message);
                }
                Err(_) => {}
            }
            return result;
        }
        match behavior.unwrap_or(Behavior::AcceptAll) {
            Behavior::AcceptAll => {}
            Behavior::TemporaryFailure => {
                return Err(SendError::Refused {
                    permanent: false,
                    code: 451,
                    text: "try later".into(),
                });
            }
            Behavior::PermanentFailure => {
                return Err(SendError::Refused {
                    permanent: true,
                    code: 554,
                    text: "rejected".into(),
                });
            }
            Behavior::DropAfterData => {
                self.record(envelope, envelope.recipients.clone(), message);
                return Err(SendError::Uncertain(
                    "the fake dropped the connection".into(),
                ));
            }
            Behavior::SizeLimit(limit) if message.len() as u64 > limit => {
                return Err(SendError::TooLarge { limit: Some(limit) });
            }
            Behavior::SizeLimit(_) => {}
            Behavior::RefuseRecipient(refused) => {
                let results: Vec<RecipientResult> = envelope
                    .recipients
                    .iter()
                    .map(|address| RecipientResult {
                        address: address.clone(),
                        outcome: if *address == refused {
                            RecipientOutcome::Refused(refusal(true, 550))
                        } else {
                            RecipientOutcome::Accepted
                        },
                    })
                    .collect();
                let taken: Vec<String> = results
                    .iter()
                    .filter(|r| r.outcome == RecipientOutcome::Accepted)
                    .map(|r| r.address.clone())
                    .collect();
                if taken.is_empty() {
                    return Err(SendError::RecipientsRefused(results));
                }
                self.record(envelope, taken, message);
                return Ok(identify(SendReport::new(results)));
            }
        }
        self.record(envelope, envelope.recipients.clone(), message);
        Ok(identify(SendReport::all_accepted(envelope)))
    }

    fn saves_to_sent(&self) -> bool {
        self.saves
    }
}

/// A [`Receiver`] of [`FakeSender`]s, so the fake itself is held to the contract.
pub struct FakeReceiver;

#[async_trait]
impl Receiver for FakeReceiver {
    async fn start(&self, behavior: Behavior) -> Fake {
        let sender = FakeSender::behaving(behavior);
        let deliveries = sender.deliveries.clone();
        Fake {
            sender: Box::new(sender),
            deliveries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_fake_keeps_the_contract() {
        conformance(&FakeReceiver).await;
    }

    #[tokio::test]
    async fn scripted_results_come_first() {
        let fake = FakeSender::new();
        fake.script(Err(SendError::Temporary("down".into())));
        let e = Envelope::new(ADA, vec![BOB.into()]);
        let m = b"To: bob@example.org\r\n\r\nHi\r\n";
        assert!(fake.send(&e, m).await.is_err());
        assert!(fake.deliveries().is_empty());
        fake.send(&e, m).await.unwrap();
        assert_eq!(fake.deliveries().len(), 1);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_fake_can_replace_the_message_id() {
        let fake = FakeSender::new().replacing_message_id("<0001@ses.example.net>", "0001");
        let e = Envelope::new(ADA, vec![BOB.into()]);
        let report = fake
            .send(&e, b"Message-ID: <a@example.com>\r\n\r\nHi\r\n")
            .await
            .unwrap();
        assert_eq!(report.message_id.as_deref(), Some("<0001@ses.example.net>"));
        assert_eq!(report.provider_message_id.as_deref(), Some("0001"));
        assert!(msg_id_shaped("<0001@ses.example.net>"));
        assert!(!msg_id_shaped("0001@ses.example.net"));
        assert!(!msg_id_shaped("<a b@example.net>"));
        assert!(!msg_id_shaped("<a@example.net>\r\nBcc: x"));
    }
}
