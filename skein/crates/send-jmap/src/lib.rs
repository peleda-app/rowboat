//! The [`Sender`] contract on JMAP servers (RFC 8620, RFC 8621), such as Stalwart or Fastmail.
//!
//! [`JmapSender`] uploads the exact bytes as a blob, imports them into the account's Drafts
//! mailbox (or Sent when there is none) and creates an `EmailSubmission` with the explicit
//! envelope in the same request. `onSuccessUpdateEmail` moves the email to Sent and clears
//! `$draft`, so the server keeps the sent copy itself; after a definite failure the imported copy
//! is destroyed again. Delivery status notification parameters go into the envelope when the
//! account offers the `DSN` submission extension.
//!
//! Credentials go only to the origin of the session resource: an `apiUrl` or `uploadUrl` on
//! another origin is refused, and requests that carry credentials never follow redirects.

mod http;
mod session;

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use skein_core::{Credentials, DsnNotify, DsnReturn, TlsRoots};
use skein_send::{
    Envelope, Limits, RecipientOutcome, RecipientResult, Refusal, SendError, SendReport, Sender,
};
use url::Url;

use http::{Http, Stage};
use session::{CORE, MAIL, SUBMISSION, Session, pointer_key};

/// Where the account is and as whom to sign in. The password or token is passed separately and
/// never stored here. Reads the same JSON as the JMAP mail provider's settings.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JmapSendSettings {
    /// The session resource or a server address, where `/.well-known/jmap` is asked; see
    /// [`session_url`].
    pub url: String,
    /// The user name for a password sign-in, often the address; unused with a token.
    #[serde(default)]
    pub username: String,
    /// The address whose JMAP identity sends. Missing uses the envelope's return path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Certificates trusted besides the built-in roots. They never turn verification off.
    #[serde(skip)]
    pub roots: TlsRoots,
}

impl fmt::Debug for JmapSendSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JmapSendSettings")
            .field("url", &self.url)
            .field("username", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl JmapSendSettings {
    /// Settings for the server at `url`, signing in as `username` when a password is used.
    pub fn new(url: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            username: username.into(),
            address: None,
            roots: TlsRoots::default(),
        }
    }

    /// Reads settings from JSON; other keys are ignored. `Invalid` when they do not parse.
    pub fn from_json(value: &Value) -> Result<Self, SendError> {
        serde_json::from_value(value.clone()).map_err(|e| SendError::Invalid(e.to_string()))
    }
}

/// The session resource for what someone typed: `https://` is added when no scheme is given, and
/// an address without a path gets `/.well-known/jmap`. Only `https` is accepted, except plain
/// `http` to a loopback address, and no credentials in the address. [`SendError::Invalid`]
/// otherwise.
pub fn session_url(input: &str) -> Result<String, SendError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(SendError::Invalid("the JMAP address is empty".into()));
    }
    let with_scheme = if input.contains("://") {
        input.to_owned()
    } else {
        format!("https://{input}")
    };
    let mut url = Url::parse(&with_scheme)
        .map_err(|_| SendError::Invalid("the JMAP address is not a web address".into()))?;
    if !http::allowed(&url) {
        return Err(SendError::Invalid("the JMAP address must use https".into()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(SendError::Invalid(
            "the JMAP address must not hold credentials".into(),
        ));
    }
    url.set_fragment(None);
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("/.well-known/jmap");
    }
    Ok(url.to_string())
}

/// A JMAP sender. Every call asks for the session afresh; calls share nothing. The server keeps
/// the sent copy itself.
pub struct JmapSender {
    url: String,
    address: Option<String>,
    http: Http,
}

impl fmt::Debug for JmapSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JmapSender")
            .field("url", &self.url)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

struct Account {
    identities: Vec<(String, String)>,
    drafts: Option<String>,
    sent: Option<String>,
}

enum Outcome {
    Created(Value),
    Failed(Value),
    MethodError(String),
    Missing,
}

impl JmapSender {
    /// A sender for `settings`. A password signs in with HTTP Basic as `username`, an access
    /// token as a bearer token. `Invalid` before anything is sent for an unusable address, a
    /// password without a user name, or an extra root that is not a certificate.
    pub fn new(settings: JmapSendSettings, credentials: Credentials) -> Result<Self, SendError> {
        let url = session_url(&settings.url)?;
        let auth = match credentials {
            Credentials::Password { secret } => {
                if settings.username.trim().is_empty() {
                    return Err(SendError::Invalid(
                        "signing in with a password needs a user name".into(),
                    ));
                }
                http::Auth::Basic(settings.username.trim().to_owned(), secret)
            }
            Credentials::AccessToken { token } => http::Auth::Bearer(token),
            Credentials::AccessKey { .. } => {
                return Err(SendError::Invalid(
                    "JMAP signs in with a password or a token, not an access key".into(),
                ));
            }
        };
        Ok(Self {
            http: Http::new(auth, Duration::from_secs(120), &settings.roots)?,
            address: settings.address,
            url,
        })
    }

    /// Gives every request `timeout` instead of two minutes. A submission without an answer by
    /// then is [`SendError::Uncertain`].
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, SendError> {
        self.http = self.http.with_timeout(timeout)?;
        Ok(self)
    }

    async fn open(&self) -> Result<Session, SendError> {
        let mut base = Url::parse(&self.url).map_err(|e| SendError::Invalid(e.to_string()))?;
        if base.path().starts_with("/.well-known/") {
            base = self.http.resolve(base).await?;
        }
        let value = self.http.session(&base).await?;
        Session::parse(&base, &value)
    }

    async fn call(
        &self,
        session: &Session,
        calls: Vec<(&str, Value)>,
        stage: Stage,
    ) -> Result<Vec<(String, Value, String)>, SendError> {
        let body = json!({
            "using": [CORE, MAIL, SUBMISSION],
            "methodCalls": calls
                .into_iter()
                .enumerate()
                .map(|(i, (name, args))| json!([name, args, i.to_string()]))
                .collect::<Vec<_>>(),
        });
        let answer = self.http.post_json(&session.api_url, &body, stage).await?;
        let malformed = || match stage {
            Stage::Handover => SendError::Uncertain("the JMAP answer is malformed".into()),
            Stage::Before => SendError::Unavailable("the JMAP answer is malformed".into()),
        };
        answer
            .get("methodResponses")
            .and_then(Value::as_array)
            .ok_or_else(malformed)?
            .iter()
            .map(|response| match response.as_array().map(Vec::as_slice) {
                Some([Value::String(name), args, Value::String(id)]) => {
                    Ok((name.clone(), args.clone(), id.clone()))
                }
                _ => Err(malformed()),
            })
            .collect()
    }

    async fn account(&self, session: &Session) -> Result<Account, SendError> {
        let responses = self
            .call(
                session,
                vec![
                    (
                        "Mailbox/get",
                        json!({ "accountId": session.account, "ids": null, "properties": ["id", "role"] }),
                    ),
                    (
                        "Identity/get",
                        json!({ "accountId": session.account, "ids": null }),
                    ),
                ],
                Stage::Before,
            )
            .await?;
        let list = |id: &str| -> Result<Vec<Value>, SendError> {
            match responses.iter().find(|(_, _, i)| i == id) {
                Some((name, args, _)) if name == "error" => {
                    let kind = args
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    Err(match kind {
                        "serverUnavailable" | "serverFail" => SendError::Unavailable(format!(
                            "the JMAP server failed a request: {kind}"
                        )),
                        "forbidden" | "accountNotFound" => {
                            SendError::Auth(format!("the JMAP server refused the account: {kind}"))
                        }
                        _ => {
                            SendError::Invalid(format!("the JMAP server refused a request: {kind}"))
                        }
                    })
                }
                Some((_, args, _)) => Ok(args
                    .get("list")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()),
                None => Err(SendError::Unavailable(
                    "the JMAP server left a call unanswered".into(),
                )),
            }
        };
        let mailboxes = list("0")?;
        let role = |role: &str| {
            mailboxes
                .iter()
                .find(|m| m.get("role").and_then(Value::as_str) == Some(role))
                .and_then(|m| m.get("id").and_then(Value::as_str))
                .map(str::to_owned)
        };
        let identities = list("1")?
            .iter()
            .filter_map(|i| {
                Some((
                    i.get("id")?.as_str()?.to_owned(),
                    i.get("email")?.as_str()?.to_owned(),
                ))
            })
            .collect();
        let sent = role("sent");
        let drafts = role("drafts").filter(|d| Some(d) != sent.as_ref());
        Ok(Account {
            identities,
            drafts,
            sent,
        })
    }

    async fn destroy(&self, session: &Session, email: &str) {
        let _ = self
            .call(
                session,
                vec![(
                    "Email/set",
                    json!({ "accountId": session.account, "destroy": [email] }),
                )],
                Stage::Before,
            )
            .await;
    }
}

/// The identity whose email is `address`, or a wildcard identity `*@domain` for its domain;
/// without an address, the first identity.
fn identity<'a>(identities: &'a [(String, String)], address: Option<&str>) -> Option<&'a str> {
    let Some(address) = address else {
        return identities.first().map(|(id, _)| id.as_str());
    };
    let domain = address.rsplit_once('@').map(|(_, d)| d);
    identities
        .iter()
        .find(|(_, email)| email.eq_ignore_ascii_case(address))
        .or_else(|| {
            identities.iter().find(|(_, email)| {
                email
                    .strip_prefix("*@")
                    .is_some_and(|d| domain.is_some_and(|domain| d.eq_ignore_ascii_case(domain)))
            })
        })
        .map(|(id, _)| id.as_str())
}

fn outcome(responses: &[(String, Value, String)], call: &str, creation: &str) -> Outcome {
    let Some((name, args, _)) = responses.iter().find(|(_, _, id)| id == call) else {
        return Outcome::Missing;
    };
    if name == "error" {
        return Outcome::MethodError(
            args.get("type")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
        );
    }
    if let Some(created) = args.pointer(&format!("/created/{creation}")) {
        return Outcome::Created(created.clone());
    }
    match args.pointer(&format!("/notCreated/{creation}")) {
        Some(error) => Outcome::Failed(error.clone()),
        None => Outcome::Missing,
    }
}

fn error_text(error: &Value) -> (String, String) {
    let kind = error
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let text = match error.get("description").and_then(Value::as_str) {
        Some(description) => format!("{kind}: {description}"),
        None => kind.clone(),
    };
    (kind, text)
}

fn refused(code: u16, text: String) -> SendError {
    SendError::Refused {
        permanent: true,
        code,
        text,
    }
}

fn set_error(error: &Value, limit: Option<u64>) -> SendError {
    let (kind, text) = error_text(error);
    match kind.as_str() {
        "forbiddenMailFrom" | "forbiddenFrom" | "forbiddenToSend" | "forbidden" => {
            refused(550, text)
        }
        "tooLarge" => SendError::TooLarge {
            limit: error.get("maxSize").and_then(Value::as_u64).or(limit),
        },
        "tooManyRecipients" | "overQuota" => refused(552, text),
        "rateLimit" => SendError::Throttled { retry_after: None },
        "noRecipients" | "invalidProperties" => SendError::Invalid(text),
        _ => refused(554, text),
    }
}

fn method_error(kind: &str) -> SendError {
    let text = format!("the JMAP server refused the submission: {kind}");
    match kind {
        "serverFail" => SendError::Uncertain(text),
        "serverUnavailable" => SendError::Temporary(text),
        "forbidden" | "accountReadOnly" => refused(550, text),
        _ => SendError::Invalid(text),
    }
}

fn refusal_from_reply(reply: &str) -> Option<Refusal> {
    let code: u16 = reply.get(..3)?.parse().ok()?;
    (400..600).contains(&code).then(|| Refusal {
        permanent: code >= 500,
        code,
        text: reply.to_owned(),
    })
}

fn report(
    envelope: &Envelope,
    invalid: &[(String, Refusal)],
    created: &Value,
) -> Result<SendReport, SendError> {
    if created.get("undoStatus").and_then(Value::as_str) == Some("canceled") {
        return Err(refused(554, "the server canceled the submission".into()));
    }
    let status = created.get("deliveryStatus").and_then(Value::as_object);
    let recipients: Vec<RecipientResult> = envelope
        .recipients
        .iter()
        .map(|address| {
            let refusal = invalid
                .iter()
                .find(|(a, _)| a.eq_ignore_ascii_case(address))
                .map(|(_, r)| r.clone())
                .or_else(|| {
                    let entry = status?
                        .iter()
                        .find(|(a, _)| a.eq_ignore_ascii_case(address))?
                        .1;
                    if entry.get("delivered").and_then(Value::as_str) != Some("no") {
                        return None;
                    }
                    refusal_from_reply(entry.get("smtpReply")?.as_str()?)
                });
            RecipientResult {
                address: address.clone(),
                outcome: refusal.map_or(RecipientOutcome::Accepted, RecipientOutcome::Refused),
            }
        })
        .collect();
    if recipients
        .iter()
        .all(|r| matches!(r.outcome, RecipientOutcome::Refused(_)))
    {
        return Err(SendError::RecipientsRefused(recipients));
    }
    let report = SendReport::new(recipients);
    Ok(match created.get("id").and_then(Value::as_str) {
        Some(id) if !id.is_empty() => report.with_provider_message_id(id),
        _ => report,
    })
}

fn refused_all(envelope: &Envelope, invalid: &[(String, Refusal)]) -> SendError {
    SendError::RecipientsRefused(
        envelope
            .recipients
            .iter()
            .map(|address| RecipientResult {
                address: address.clone(),
                outcome: RecipientOutcome::Refused(
                    invalid
                        .iter()
                        .find(|(a, _)| a.eq_ignore_ascii_case(address))
                        .map(|(_, r)| r.clone())
                        .unwrap_or_else(invalid_recipient),
                ),
            })
            .collect(),
    )
}

fn invalid_recipient() -> Refusal {
    Refusal {
        permanent: true,
        code: 550,
        text: "invalidRecipients".into(),
    }
}

#[async_trait]
impl Sender for JmapSender {
    /// Fetches the session and checks that it offers mail submission for the account, that the
    /// account has a Sent mailbox and, when [`JmapSendSettings::address`] is set, an identity
    /// for it. Sends nothing and changes nothing.
    async fn check(&self) -> Result<Limits, SendError> {
        let session = self.open().await?;
        let account = self.account(&session).await?;
        if account.sent.is_none() {
            return Err(SendError::Invalid(
                "the JMAP account has no Sent mailbox".into(),
            ));
        }
        if let Some(address) = &self.address
            && identity(&account.identities, Some(address)).is_none()
        {
            return Err(SendError::Invalid(
                "the JMAP account has no identity for this address".into(),
            ));
        }
        Ok(Limits {
            max_size: session.max_size,
            smtputf8: false,
            dsn: session.dsn,
        })
    }

    async fn send(&self, envelope: &Envelope, message: &[u8]) -> Result<SendReport, SendError> {
        envelope.validate(message)?;
        let session = self.open().await?;
        let size = message.len() as u64;
        if session.max_size.is_some_and(|max| size > max) {
            return Err(SendError::TooLarge {
                limit: session.max_size,
            });
        }
        let account = self.account(&session).await?;
        let sent = account
            .sent
            .clone()
            .ok_or_else(|| SendError::Invalid("the JMAP account has no Sent mailbox".into()))?;
        let address = self
            .address
            .as_deref()
            .or((!envelope.mail_from.is_empty()).then_some(envelope.mail_from.as_str()));
        let identity_id = identity(&account.identities, address)
            .ok_or_else(|| {
                SendError::Invalid("the JMAP account has no identity for this address".into())
            })?
            .to_owned();

        let uploaded = self
            .http
            .upload(&session.upload_url, message, session.max_size)
            .await?;
        let blob = uploaded
            .get("blobId")
            .and_then(Value::as_str)
            .ok_or_else(|| SendError::Unavailable("the upload gave no blob".into()))?
            .to_owned();

        let target = account.drafts.clone().unwrap_or_else(|| sent.clone());
        let mut patch = Map::new();
        if let Some(drafts) = &account.drafts {
            patch.insert(format!("mailboxIds/{}", pointer_key(drafts)), Value::Null);
            patch.insert(format!("mailboxIds/{}", pointer_key(&sent)), json!(true));
        }
        patch.insert("keywords/$draft".into(), Value::Null);
        let on_success = json!({ "#s": patch });
        let dsn = envelope.dsn.as_ref().filter(|_| session.dsn);
        let from_parameters = dsn.map_or(Value::Null, |dsn| {
            let mut p = Map::new();
            match dsn.ret {
                Some(DsnReturn::Full) => {
                    p.insert("RET".into(), json!("FULL"));
                }
                Some(DsnReturn::Headers) => {
                    p.insert("RET".into(), json!("HDRS"));
                }
                None => {}
            }
            if let Some(envid) = &envelope.envid {
                p.insert("ENVID".into(), json!(envid));
            }
            if p.is_empty() {
                Value::Null
            } else {
                Value::Object(p)
            }
        });
        let rcpt_parameters = |address: &str| {
            dsn.filter(|d| !d.notify.is_empty())
                .map_or(Value::Null, |d| {
                    let mut p = Map::new();
                    p.insert("NOTIFY".into(), json!(notify(&d.notify)));
                    if address.is_ascii() {
                        p.insert("ORCPT".into(), json!(format!("rfc822;{address}")));
                    }
                    Value::Object(p)
                })
        };
        let submission = |email: &str, recipients: &[&String]| {
            json!({
                "accountId": session.account,
                "create": { "s": {
                    "identityId": identity_id,
                    "emailId": email,
                    "envelope": {
                        "mailFrom": { "email": envelope.mail_from, "parameters": from_parameters },
                        "rcptTo": recipients
                            .iter()
                            .map(|r| json!({ "email": r, "parameters": rcpt_parameters(r) }))
                            .collect::<Vec<_>>(),
                    },
                } },
                "onSuccessUpdateEmail": on_success,
            })
        };

        let mut invalid: Vec<(String, Refusal)> = Vec::new();
        let mut email: Option<String> = None;
        loop {
            let remaining: Vec<&String> = envelope
                .recipients
                .iter()
                .filter(|r| !invalid.iter().any(|(a, _)| a.eq_ignore_ascii_case(r)))
                .collect();
            if remaining.is_empty() {
                if let Some(email) = &email {
                    self.destroy(&session, email).await;
                }
                return Err(refused_all(envelope, &invalid));
            }
            let result = match &email {
                None => {
                    let import = json!({
                        "accountId": session.account,
                        "emails": { "m": {
                            "blobId": blob,
                            "mailboxIds": { target.clone(): true },
                            "keywords": { "$draft": true, "$seen": true },
                        } },
                    });
                    let responses = self
                        .call(
                            &session,
                            vec![
                                ("Email/import", import),
                                ("EmailSubmission/set", submission("#m", &remaining)),
                            ],
                            Stage::Handover,
                        )
                        .await?;
                    let submitted = outcome(&responses, "1", "s");
                    if matches!(submitted, Outcome::Failed(_) | Outcome::MethodError(_)) {
                        match outcome(&responses, "0", "m") {
                            Outcome::Created(created) => {
                                email =
                                    created.get("id").and_then(Value::as_str).map(str::to_owned);
                            }
                            Outcome::Failed(error) => {
                                return Err(set_error(&error, session.max_size));
                            }
                            Outcome::MethodError(kind) => {
                                return Err(match kind.as_str() {
                                    "serverFail" | "serverUnavailable" => SendError::Temporary(
                                        format!("the JMAP server failed the import: {kind}"),
                                    ),
                                    _ => method_error(&kind),
                                });
                            }
                            Outcome::Missing => {}
                        }
                    }
                    submitted
                }
                Some(id) => {
                    let responses = self
                        .call(
                            &session,
                            vec![("EmailSubmission/set", submission(id, &remaining))],
                            Stage::Handover,
                        )
                        .await?;
                    outcome(&responses, "0", "s")
                }
            };
            let failure = match result {
                Outcome::Created(created) => return report(envelope, &invalid, &created),
                Outcome::Missing => {
                    return Err(SendError::Uncertain(
                        "the JMAP server did not say whether it took the submission".into(),
                    ));
                }
                Outcome::MethodError(kind) => method_error(&kind),
                Outcome::Failed(error) => {
                    let named: Vec<String> = error
                        .get("invalidRecipients")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .filter(|a| remaining.iter().any(|r| r.eq_ignore_ascii_case(a)))
                        .map(str::to_owned)
                        .collect();
                    if error.get("type").and_then(Value::as_str) == Some("invalidRecipients") {
                        let (_, text) = error_text(&error);
                        if named.is_empty() {
                            remaining.iter().for_each(|r| {
                                invalid.push(((*r).clone(), invalid_recipient()));
                            });
                        }
                        for address in named {
                            invalid.push((
                                address,
                                Refusal {
                                    permanent: true,
                                    code: 550,
                                    text: text.clone(),
                                },
                            ));
                        }
                        continue;
                    }
                    set_error(&error, session.max_size)
                }
            };
            if !failure.may_have_been_sent()
                && let Some(email) = &email
            {
                self.destroy(&session, email).await;
            }
            return Err(failure);
        }
    }

    fn saves_to_sent(&self) -> bool {
        true
    }
}

fn notify(when: &[DsnNotify]) -> String {
    if when.contains(&DsnNotify::Never) {
        return "NEVER".into();
    }
    [
        (DsnNotify::Success, "SUCCESS"),
        (DsnNotify::Failure, "FAILURE"),
        (DsnNotify::Delay, "DELAY"),
    ]
    .iter()
    .filter(|(kind, _)| when.contains(kind))
    .map(|(_, word)| *word)
    .collect::<Vec<_>>()
    .join(",")
}

#[cfg(test)]
mod tests;
