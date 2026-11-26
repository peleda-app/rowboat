//! Push through `users.watch`: Gmail publishes `{emailAddress, historyId}` to a Cloud Pub/Sub
//! topic, whose push subscription calls our endpoint.

use bytes::Bytes;
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use skein_core::Timestamp;
use skein_mail::{MailError, PUSH_GMAIL, PushTarget, Subscription};

use crate::http::{self, Http, Wrote};
use crate::{GmailProvider, quota};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Watch {
    history_id: Option<serde_json::Value>,
    expiration: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Address {
    email_address: Option<String>,
}

fn number(value: &serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::String(s) => s.trim().parse().ok(),
        serde_json::Value::Number(n) => n.as_i64(),
        _ => None,
    }
}

/// `projects/{project}/topics/{topic}` with plain segments.
pub(crate) fn valid_topic(topic: &str) -> bool {
    let parts: Vec<&str> = topic.split('/').collect();
    let plain = |s: &str| {
        !s.is_empty()
            && s.len() <= 255
            && s.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'+' | b'%')
            })
    };
    parts.len() == 4
        && parts[0] == "projects"
        && parts[2] == "topics"
        && plain(parts[1])
        && plain(parts[3])
}

async fn email(http: &Http) -> Result<String, MailError> {
    let url = http.endpoint(false, &["profile"]);
    let profile: Address = http
        .get(url, quota::PROFILE, http::MAX_JSON)
        .await?
        .ok_or_else(|| MailError::Protocol("the Gmail API has no such user".into()))?;
    profile
        .email_address
        .filter(|e| e.contains('@'))
        .ok_or_else(|| MailError::Protocol("the profile has no address".into()))
}

async fn watch(http: &Http, topic: &str) -> Result<Watch, MailError> {
    let url = http.endpoint(false, &["watch"]);
    let body = serde_json::json!({ "topicName": topic }).to_string();
    let response = http
        .send(
            Method::POST,
            url,
            Some(("application/json".into(), Bytes::from(body))),
            quota::WATCH,
        )
        .await?
        .map_err(|e| http::network(&e))?;
    let status = response.status();
    if status.is_success() {
        let body = http::read(response, http::MAX_JSON).await?;
        return serde_json::from_slice(&body)
            .map_err(|_| MailError::Protocol("the Gmail API sent an unexpected answer".into()));
    }
    let headers = response.headers().clone();
    let body = http::error_body(response).await;
    let reasons = http::reasons(&body);
    let rate = reasons.iter().any(|r| {
        matches!(
            r.as_str(),
            "rateLimitExceeded" | "userRateLimitExceeded" | "RATE_LIMIT_EXCEEDED"
        )
    });
    Err(match status {
        StatusCode::TOO_MANY_REQUESTS => MailError::Throttled {
            retry_after: http::retry_after(&headers),
        },
        StatusCode::FORBIDDEN if rate => MailError::Throttled {
            retry_after: http::retry_after(&headers),
        },
        StatusCode::UNAUTHORIZED => MailError::Auth,
        StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => {
            MailError::Config(format!(
                "Gmail refused the watch ({}); check the topic and that gmail-api-push@system.gserviceaccount.com may publish to it",
                status.as_u16()
            ))
        }
        s if s.is_server_error() => MailError::Network(format!("the Gmail API answered {s}")),
        s => MailError::Protocol(format!("the Gmail API answered {s}")),
    })
}

pub(crate) async fn subscribe(
    provider: &GmailProvider,
    target: &PushTarget,
) -> Result<Option<Subscription>, MailError> {
    let Some(topic) = target.gmail_topic.as_deref() else {
        return Ok(None);
    };
    if !valid_topic(topic) {
        return Err(MailError::Config(
            "the Gmail topic is not projects/{project}/topics/{topic}".into(),
        ));
    }
    let http = provider.http()?;
    let resource = email(&http).await?;
    let answer = watch(&http, topic).await?;
    let expires_at = answer
        .expiration
        .as_ref()
        .and_then(number)
        .map(Timestamp)
        .ok_or_else(|| MailError::Protocol("the watch has no expiration".into()))?;
    let id = answer
        .history_id
        .as_ref()
        .and_then(number)
        .map(|n| n.to_string())
        .unwrap_or_else(|| "watch".into());
    tracing::debug!(expires_at = expires_at.0, "gmail watch");
    Ok(Some(Subscription {
        id,
        provider_kind: PUSH_GMAIL.into(),
        expires_at,
        resource,
    }))
}

pub(crate) async fn unsubscribe(
    provider: &GmailProvider,
    subscription: &Subscription,
) -> Result<(), MailError> {
    if subscription.provider_kind != PUSH_GMAIL {
        return Ok(());
    }
    let http = provider.http()?;
    let url = http.endpoint(false, &["stop"]);
    match http
        .write(Method::POST, url, None, quota::STOP, true)
        .await?
    {
        Wrote::Done | Wrote::Missing => Ok(()),
        Wrote::Uncertain => Err(MailError::Network(
            "the Gmail API did not confirm the stop".into(),
        )),
        Wrote::Failed(reason) => Err(MailError::Protocol(format!(
            "Gmail refused the stop ({reason})"
        ))),
    }
}
