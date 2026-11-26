use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use rinse_mail::{
    Content, ContentError, ContentLimits, RenderOptions, RenderRequest, Rendered, verify_rendered,
};
use rowboat_category::{Categorizer, CategoryInput};
use rowboat_spam::{SpamFilter, SpamInput};
use skein_core::MailboxRole;
use skein_view::{Addr, Attachment, MessageParser, ParseContext, ParseError, Parsed, TEXT_CAP};
use tokio::sync::Semaphore;
use tracing::debug;

/// The adapter's own version; bump on any change to the mapping below.
const ADAPTER: &str = "rowboat-parser-1";

/// The domains whose servers receive mail for an account (see
/// `rowboat_spam_signals::receivers_for`).
#[async_trait]
pub(crate) trait Receivers: Send + Sync {
    async fn receivers(&self, account: &str) -> Arc<[String]>;
}

/// Receivers from the account's IMAP host and address, read once per account.
pub(crate) struct AccountReceivers {
    accounts: skein_accounts::Accounts,
    control: Arc<dyn skein_storage::ControlStore>,
    tenant: skein_core::TenantId,
    known: Mutex<HashMap<String, Arc<[String]>>>,
}

impl AccountReceivers {
    pub(crate) fn new(
        accounts: skein_accounts::Accounts,
        control: Arc<dyn skein_storage::ControlStore>,
        tenant: skein_core::TenantId,
    ) -> Self {
        Self {
            accounts,
            control,
            tenant,
            known: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Receivers for AccountReceivers {
    async fn receivers(&self, account: &str) -> Arc<[String]> {
        if let Some(r) = self
            .known
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(account)
        {
            return r.clone();
        }
        let Ok(id) = skein_core::AccountId::new(account) else {
            return Arc::from(Vec::new());
        };
        let host = match self.accounts.get(&self.tenant, &id).await {
            Ok(Some(record)) => record.settings["host"].as_str().unwrap_or("").to_owned(),
            _ => return Arc::from(Vec::new()),
        };
        let address = match self
            .control
            .get(&self.tenant, &format!("rowboat/accounts/{account}"))
            .await
        {
            Ok(Some((bytes, _))) => crate::records::decode_account_meta(&bytes)
                .map(|m| m.address.as_str().to_owned())
                .unwrap_or_default(),
            _ => String::new(),
        };
        let found: Arc<[String]> = Arc::from(rowboat_spam_signals::receivers_for(&host, &address));
        self.known
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(account.to_owned(), found.clone());
        found
    }
}

/// `skein-view`'s parser hook over the content pipeline: the node never parses message bytes
/// itself. Every render is checked with `verify_rendered`, whatever produced it; output that
/// fails is refused and the message is stored as unavailable.
pub(crate) struct ContentParser {
    content: Arc<dyn Content>,
    spam: Arc<dyn SpamFilter>,
    category: Arc<dyn Categorizer>,
    receivers: Arc<dyn Receivers>,
    permits: Semaphore,
    version: String,
}

impl ContentParser {
    pub(crate) fn new(
        content: Arc<dyn Content>,
        spam: Arc<dyn SpamFilter>,
        category: Arc<dyn Categorizer>,
        receivers: Arc<dyn Receivers>,
        workers: usize,
    ) -> Self {
        let version = format!("{ADAPTER}+{}+{}", spam.version(), category.version());
        Self {
            content,
            spam,
            category,
            receivers,
            permits: Semaphore::new(workers.max(1)),
            version,
        }
    }

    /// The request the adapter renders with: display only, no original HTML, no remote
    /// images, images re-encoded at the smallest size (1 px; the content engine never goes
    /// below it, so 0 would make every message with an inline image fail verification).
    pub(crate) fn request(raw: &Bytes) -> RenderRequest {
        RenderRequest {
            raw: raw.clone(),
            options: RenderOptions {
                want_original_html: false,
                max_image_px: 1,
                remote_images: Vec::new(),
            },
            limits: ContentLimits::default(),
        }
    }
}

fn addrs(list: &[rinse_mail::MailAddress]) -> Vec<Addr> {
    list.iter()
        .map(|a| Addr {
            name: a.name.clone().filter(|n| !n.is_empty()),
            address: Some(a.address.clone()),
        })
        .collect()
}

fn snippet(text: &str) -> Option<String> {
    let s: String = text
        .split_whitespace()
        .flat_map(|w| std::iter::once(' ').chain(w.chars()))
        .skip(1)
        .take(skein_view::SNIPPET_CHARS)
        .collect();
    (!s.is_empty()).then_some(s)
}

fn cut(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// The view's record of a rendered message, with the hooks' tags.
pub(crate) fn map(r: &Rendered, tags: Vec<String>) -> Parsed {
    let text = cut(r.text.clone(), TEXT_CAP);
    Parsed {
        available: true,
        message_id: r.headers.message_id.clone(),
        in_reply_to: r.facts.thread.in_reply_to.iter().cloned().collect(),
        references: r.facts.thread.references.clone(),
        subject: r.headers.subject.clone(),
        from: addrs(&r.headers.from),
        to: addrs(&r.headers.to),
        cc: addrs(&r.headers.cc),
        date: r.headers.date.map(|s| s.saturating_mul(1000)),
        has_attachments: r.attachments.iter().any(|a| !a.inline),
        attachments: r
            .attachments
            .iter()
            .map(|a| Attachment {
                part: a.part,
                name: a.file_name.clone(),
                content_type: a.declared_type.clone(),
                size: a.size,
            })
            .collect(),
        snippet: snippet(&text),
        text: (!text.is_empty()).then_some(text),
        html: None,
        itip: None,
        tags,
    }
}

#[async_trait]
impl MessageParser for ContentParser {
    async fn parse(&self, raw: &Bytes, context: &ParseContext) -> Result<Parsed, ParseError> {
        let request = Self::request(raw);
        let rendered = {
            let _permit = self
                .permits
                .acquire()
                .await
                .map_err(|_| ParseError::Unavailable)?;
            self.content.render(request.clone()).await
        };
        let rendered = match rendered {
            Ok(r) => r,
            Err(ContentError::Unavailable) => return Err(ParseError::Unavailable),
            Err(e) => {
                debug!(error = %e, "the content pipeline refused a message");
                return Err(ParseError::Refused);
            }
        };
        if verify_rendered(&request, &rendered).is_err() {
            return Err(ParseError::Refused);
        }
        let receivers = self.receivers.receivers(&context.account).await;
        let verdict = self.spam.verdict(&SpamInput {
            rendered: &rendered,
            account: &context.account,
            in_junk: context.role == Some(MailboxRole::Junk),
            receivers: &receivers,
        });
        let mut tags = Vec::new();
        if let Some(tag) = verdict.tag() {
            tags.push(tag.to_owned());
        }
        if let Some(category) = self.category.category(&CategoryInput {
            rendered: &rendered,
            account: &context.account,
        }) {
            tags.push(category.tag());
        }
        Ok(map(&rendered, tags))
    }

    fn version(&self) -> String {
        self.version.clone()
    }
}

#[cfg(test)]
mod tests {
    use rinse_mail::Content;

    use super::*;

    #[tokio::test]
    async fn messages_with_inline_images_are_not_refused() {
        let raw = Bytes::from_static(rinse_mail::testing::fixture("cid-image.eml"));
        let request = ContentParser::request(&raw);
        let rendered = rinse_mail_direct::DirectContent::new()
            .render(request.clone())
            .await
            .expect("renders");
        assert!(verify_rendered(&request, &rendered).is_ok());
    }
}
