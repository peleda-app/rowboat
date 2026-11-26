//! Push through Graph change notifications: `POST /subscriptions` on `me/messages`, `PATCH` to
//! extend, `DELETE` to end.

use reqwest::Method;
use serde_json::{Value, json};
use skein_core::Timestamp;
use skein_mail::{MailError, PUSH_GRAPH, PushTarget, Subscription};
use url::Url;

use crate::http::{self, Body, Wrote};
use crate::{GraphProvider, endpoint, time};

/// What a subscription watches: every message of the signed-in mailbox.
pub(crate) const RESOURCE: &str = "me/messages";
/// Graph keeps message subscriptions at most 4230 minutes; ask for a little less.
pub(crate) const LIFETIME_MINUTES: i64 = 4200;
const MAX_CLIENT_STATE: usize = 128;

fn expiry(now: Timestamp) -> (Timestamp, String) {
    let at = now.plus_ms(LIFETIME_MINUTES * 60_000);
    (at, time::format_utc(at.0.div_euclid(1000)))
}

fn check_target(target: &PushTarget) -> Result<(), MailError> {
    let url = Url::parse(&target.url)
        .map_err(|_| MailError::Config("the push address is not a web address".into()))?;
    if !http::allowed(&url) || url.cannot_be_a_base() {
        return Err(MailError::Config(
            "the push address must use https (plain http only to loopback)".into(),
        ));
    }
    let state = &target.client_state;
    if state.is_empty()
        || state.len() > MAX_CLIENT_STATE
        || !state.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(MailError::Config(
            "the client state must be 1 to 128 printable ASCII characters".into(),
        ));
    }
    Ok(())
}

fn read(
    answer: Option<Value>,
    fallback: Timestamp,
    id: Option<&str>,
) -> Result<Subscription, MailError> {
    let answer = answer.unwrap_or(Value::Null);
    let id = answer
        .get("id")
        .and_then(Value::as_str)
        .or(id)
        .filter(|id| !id.is_empty() && id.len() <= 128)
        .ok_or_else(|| MailError::Protocol("a Graph subscription has no id".into()))?
        .to_owned();
    let expires_at = answer
        .get("expirationDateTime")
        .and_then(Value::as_str)
        .and_then(time::parse_utc)
        .unwrap_or(fallback);
    Ok(Subscription {
        id,
        provider_kind: PUSH_GRAPH.into(),
        expires_at,
        resource: RESOURCE.into(),
    })
}

fn refused(status: u16) -> MailError {
    MailError::Protocol(format!(
        "Microsoft Graph refused the subscription ({status})"
    ))
}

pub(crate) async fn subscribe(
    provider: &GraphProvider,
    target: &PushTarget,
) -> Result<Option<Subscription>, MailError> {
    check_target(target)?;
    let (at, text) = expiry(Timestamp::now());
    let url = endpoint(&provider.base, &["subscriptions"], &[])?;
    let body = json!({
        "changeType": "created,updated,deleted",
        "notificationUrl": target.url,
        "lifecycleNotificationUrl": target.url,
        "resource": RESOURCE,
        "expirationDateTime": text,
        "clientState": target.client_state,
    });
    match provider
        .http
        .write(Method::POST, url, Body::Json(body), false)
        .await?
    {
        Wrote::Done(answer) => {
            let sub = read(answer, at, None)?;
            tracing::debug!(expires_at = sub.expires_at.0, "graph subscription made");
            Ok(Some(sub))
        }
        Wrote::Missing => Err(refused(404)),
        Wrote::Uncertain => Err(MailError::Network(
            "Microsoft Graph did not confirm the subscription".into(),
        )),
        Wrote::Refused(status) => Err(refused(status)),
    }
}

pub(crate) async fn renew(
    provider: &GraphProvider,
    subscription: &Subscription,
    target: &PushTarget,
) -> Result<Option<Subscription>, MailError> {
    if subscription.provider_kind != PUSH_GRAPH {
        return subscribe(provider, target).await;
    }
    let (at, text) = expiry(Timestamp::now());
    let url = endpoint(&provider.base, &["subscriptions", &subscription.id], &[])?;
    match provider
        .http
        .write(
            Method::PATCH,
            url,
            Body::Json(json!({ "expirationDateTime": text })),
            true,
        )
        .await?
    {
        Wrote::Done(answer) => Ok(Some(read(answer, at, Some(&subscription.id))?)),
        Wrote::Missing => subscribe(provider, target).await,
        Wrote::Uncertain => Err(MailError::Network(
            "Microsoft Graph did not confirm the renewal".into(),
        )),
        Wrote::Refused(status) => Err(refused(status)),
    }
}

pub(crate) async fn unsubscribe(
    provider: &GraphProvider,
    subscription: &Subscription,
) -> Result<(), MailError> {
    if subscription.provider_kind != PUSH_GRAPH {
        return Ok(());
    }
    let url = endpoint(&provider.base, &["subscriptions", &subscription.id], &[])?;
    match provider
        .http
        .write(Method::DELETE, url, Body::Empty, true)
        .await?
    {
        Wrote::Done(_) | Wrote::Missing => Ok(()),
        Wrote::Uncertain => Err(MailError::Network(
            "Microsoft Graph did not confirm the removal".into(),
        )),
        Wrote::Refused(status) => Err(refused(status)),
    }
}
