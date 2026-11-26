//! Live suites against real provider accounts, configured as described in docs/LIVE.md. Each
//! suite skips unless `SKEIN_LIVE=1` and its own secrets are set.

fn live() -> bool {
    std::env::var("SKEIN_LIVE").as_deref() == Ok("1")
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
async fn imap() {
    if !live() {
        eprintln!("SKEIN_LIVE is not set; skipping");
        return;
    }
    let (Some(host), Some(user), Some(password)) = (
        var("SKEIN_LIVE_IMAP_HOST"),
        var("SKEIN_LIVE_IMAP_USER"),
        var("SKEIN_LIVE_IMAP_PASSWORD"),
    ) else {
        eprintln!("IMAP secrets are not set; skipping");
        return;
    };
    use skein_mail_imap::{ImapProvider, ImapSettings, Security};
    let mut settings = ImapSettings::new(host, user);
    settings.port =
        var("SKEIN_LIVE_IMAP_PORT").map(|p| p.parse().expect("SKEIN_LIVE_IMAP_PORT is a number"));
    settings.security = Security::Tls;
    let provider = ImapProvider::new(
        settings,
        skein_core::Credentials::Password { secret: password },
    )
    .expect("IMAP settings");
    let mailbox = var("SKEIN_LIVE_IMAP_MAILBOX").unwrap_or_else(|| "INBOX".into());
    skein_integration::mail_round_trip(&provider, &mailbox).await;
}

#[tokio::test]
async fn gmail_api() {
    if !live() {
        eprintln!("SKEIN_LIVE is not set; skipping");
        return;
    }
    let Some(token) = var("SKEIN_LIVE_GMAIL_ACCESS_TOKEN") else {
        eprintln!(
            "SKEIN_LIVE_GMAIL_ACCESS_TOKEN is not set; skipping (signing in with SKEIN_LIVE_GMAIL_REFRESH_TOKEN comes with skein-oauth)"
        );
        return;
    };
    use skein_mail_gmail::{ALL, GmailProvider, GmailSettings};
    let provider = GmailProvider::new(
        GmailSettings::default(),
        skein_core::Credentials::AccessToken { token },
    )
    .expect("Gmail settings");
    let run = tokio::spawn(async move {
        skein_integration::mail_round_trip(&provider, ALL).await;
    })
    .await;
    if let Err(e) = run {
        panic!(
            "the Gmail round trip failed: {e}. If it failed at the delete step, the token lacks the full scope: messages.delete needs https://mail.google.com/, gmail.modify is not enough."
        );
    }
}

#[tokio::test]
async fn microsoft_graph() {
    if !live() {
        eprintln!("SKEIN_LIVE is not set; skipping");
        return;
    }
    let Some(token) = var("SKEIN_LIVE_GRAPH_ACCESS_TOKEN") else {
        eprintln!(
            "SKEIN_LIVE_GRAPH_ACCESS_TOKEN is not set; skipping (signing in with SKEIN_LIVE_GRAPH_REFRESH_TOKEN comes with skein-oauth)"
        );
        return;
    };
    use skein_mail_graph::{GraphProvider, GraphSettings};
    let settings = GraphSettings {
        api_url: var("SKEIN_LIVE_GRAPH_API_URL"),
        ..GraphSettings::default()
    };
    let provider = GraphProvider::new(settings, skein_core::Credentials::AccessToken { token })
        .expect("Graph settings");
    let mailbox = match var("SKEIN_LIVE_GRAPH_MAILBOX") {
        Some(id) => id,
        None => {
            skein_integration::mailbox_with_role(&provider, skein_core::MailboxRole::Inbox).await
        }
    };
    skein_integration::mail_round_trip(&provider, &mailbox).await;
}
