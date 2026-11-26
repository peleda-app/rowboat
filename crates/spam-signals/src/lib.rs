//! A spam verdict from signals the node already has: where the provider put the message, and
//! what the receiving server's `Authentication-Results` field says.
//!
//! Only the topmost `Authentication-Results` field (position 0, the one the receiving server
//! added last) is read: fields below it can be written by the sender. Its authserv-id must be
//! one of the account's receivers ([`SpamInput::receivers`], see [`receivers_for`]) for it to
//! make a message `Clean`; from any other server it can only lower a verdict to `Suspicious`,
//! never raise trust (SEC-8).

use rinse_mail::facts::{AuthMethod, AuthOutcome};
use rowboat_spam::{SpamFilter, SpamInput, SpamVerdict};

/// The filter's version; bump on any change to the rules below.
pub const VERSION: &str = "signals-2";

const PROVIDERS: &[(&str, &[&str])] = &[
    ("gmail.com", &["google.com"]),
    ("googlemail.com", &["google.com"]),
    ("outlook.com", &["outlook.com"]),
    ("hotmail.com", &["outlook.com"]),
    ("live.com", &["outlook.com"]),
    ("office365.com", &["outlook.com"]),
    ("fastmail.com", &["messagingengine.com"]),
    ("fastmail.fm", &["messagingengine.com"]),
    ("icloud.com", &["icloud.com", "apple.com"]),
    ("me.com", &["icloud.com", "apple.com"]),
    ("mac.com", &["icloud.com", "apple.com"]),
    ("yahoo.com", &["yahoo.com"]),
];

fn plausible_domain(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    let public_second = labels.len() == 2
        && labels[1].len() == 2
        && matches!(
            labels[0],
            "co" | "com" | "net" | "org" | "ac" | "gov" | "edu" | "ne" | "or"
        );
    labels.len() >= 2
        && !public_second
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        && !labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
}

/// The domains whose servers count as the account's receivers: the IMAP host without its first
/// label (when it has three or more), the address's domain, and the receiving domains of a few
/// large providers those name. IP addresses, single labels and public second-level suffixes
/// (`co.uk`) are left out.
pub fn receivers_for(imap_host: &str, address: &str) -> Vec<String> {
    let host = imap_host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let host_base = if labels.len() >= 3 {
        labels[1..].join(".")
    } else {
        host.clone()
    };
    let domain = address
        .rsplit_once('@')
        .map(|(_, d)| d.trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    for base in [host_base, domain] {
        if !plausible_domain(&base) {
            continue;
        }
        let extra = PROVIDERS
            .iter()
            .find(|(d, _)| *d == base)
            .map(|(_, r)| *r)
            .unwrap_or_default();
        for d in std::iter::once(base.as_str()).chain(extra.iter().copied()) {
            if !out.iter().any(|o| o == d) {
                out.push(d.to_owned());
            }
        }
    }
    out
}

fn from_receiver(authserv_id: &str, receivers: &[String]) -> bool {
    receivers.iter().any(|r| {
        authserv_id == r
            || authserv_id
                .strip_suffix(r.as_str())
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

/// Junk placement, then failed or unaligned authentication.
#[derive(Debug, Clone, Copy, Default)]
pub struct SignalsFilter;

fn aligned(from: &str, domain: &str) -> bool {
    from == domain
        || from
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
        || domain
            .strip_suffix(from)
            .is_some_and(|rest| rest.ends_with('.'))
}

impl SpamFilter for SignalsFilter {
    fn verdict(&self, input: &SpamInput<'_>) -> SpamVerdict {
        if input.in_junk {
            return SpamVerdict::Junk;
        }
        let Some(top) = input
            .rendered
            .facts
            .auth
            .results
            .iter()
            .find(|a| a.position == 0)
        else {
            return SpamVerdict::NotChecked;
        };
        match judge(input.rendered, top) {
            SpamVerdict::Clean if !from_receiver(&top.authserv_id, input.receivers) => {
                SpamVerdict::NotChecked
            }
            v => v,
        }
    }

    fn version(&self) -> String {
        VERSION.into()
    }
}

fn judge(r: &rinse_mail::Rendered, top: &rinse_mail::facts::AuthResult) -> SpamVerdict {
    let from = match r.headers.from.as_slice() {
        [one] => one
            .address
            .rsplit_once('@')
            .map(|(_, d)| d.to_ascii_lowercase()),
        _ => None,
    };
    let mut dmarc_pass = false;
    let mut passes: Vec<&str> = Vec::new();
    for m in &top.methods {
        match (m.method, m.result) {
            (AuthMethod::Dmarc, AuthOutcome::Fail) => return SpamVerdict::Suspicious,
            (AuthMethod::Dmarc, AuthOutcome::Pass) => dmarc_pass = true,
            (AuthMethod::Dkim | AuthMethod::Spf, AuthOutcome::Pass) => {
                if let Some(d) = m.domain.as_deref() {
                    passes.push(d);
                }
            }
            _ => {}
        }
    }
    if dmarc_pass {
        return SpamVerdict::Clean;
    }
    match from {
        Some(from) if !passes.is_empty() && !passes.iter().any(|d| aligned(&from, d)) => {
            SpamVerdict::Suspicious
        }
        None if r.headers.from.len() > 1 => SpamVerdict::Suspicious,
        _ => SpamVerdict::Clean,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use rinse_mail::{Content, ContentLimits, RenderOptions, RenderRequest, Rendered};
    use rinse_mail_direct::DirectContent;

    use super::*;

    async fn render(raw: &[u8]) -> Rendered {
        let content: Arc<dyn Content> = Arc::new(DirectContent::new());
        content
            .render(RenderRequest {
                raw: Bytes::copy_from_slice(raw),
                options: RenderOptions {
                    max_image_px: 0,
                    ..RenderOptions::default()
                },
                limits: ContentLimits::default(),
            })
            .await
            .unwrap()
    }

    fn receivers() -> Vec<String> {
        vec!["example.net".into()]
    }

    fn verdict(r: &Rendered) -> SpamVerdict {
        SignalsFilter.verdict(&SpamInput {
            rendered: r,
            account: "a",
            in_junk: false,
            receivers: &receivers(),
        })
    }

    fn verdict_from(r: &Rendered, receivers: &[String]) -> SpamVerdict {
        SignalsFilter.verdict(&SpamInput {
            rendered: r,
            account: "a",
            in_junk: false,
            receivers,
        })
    }

    fn msg(auth: &[&str], from: &str) -> Vec<u8> {
        let mut s = String::new();
        for a in auth {
            s.push_str(&format!("Authentication-Results: {a}\r\n"));
        }
        s.push_str(&format!(
            "From: {from}\r\nTo: sam@example.org\r\nSubject: Hello\r\n\r\nHi there.\r\n"
        ));
        s.into_bytes()
    }

    #[tokio::test]
    async fn conformance_over_the_hostile_corpus() {
        let mut rendered = Vec::new();
        for f in rinse_mail::testing::CORPUS {
            if let Ok(r) = DirectContent::new()
                .render(RenderRequest {
                    raw: Bytes::from_static(f.raw),
                    options: RenderOptions::default(),
                    limits: ContentLimits::default(),
                })
                .await
            {
                rendered.push(r);
            }
        }
        assert!(rendered.len() > 10);
        rowboat_spam::testing::filter(&SignalsFilter, &rendered, true);
    }

    #[tokio::test]
    async fn rules() {
        let pass = msg(
            &["mx.example.net; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"],
            "Pat <pat@example.com>",
        );
        assert_eq!(verdict(&render(&pass).await), SpamVerdict::Clean);

        let fail = msg(
            &["mx.example.net; dmarc=fail header.from=example.com"],
            "pat@example.com",
        );
        assert_eq!(verdict(&render(&fail).await), SpamVerdict::Suspicious);

        let unaligned = msg(
            &["mx.example.net; dkim=pass header.d=bulk.example.net"],
            "pat@example.com",
        );
        assert_eq!(verdict(&render(&unaligned).await), SpamVerdict::Suspicious);

        let sub = msg(
            &["mx.example.net; dkim=pass header.d=mail.example.com"],
            "pat@example.com",
        );
        assert_eq!(verdict(&render(&sub).await), SpamVerdict::Clean);

        let lookalike = msg(
            &["mx.example.net; dkim=pass header.d=evilexample.com"],
            "pat@example.com",
        );
        assert_eq!(verdict(&render(&lookalike).await), SpamVerdict::Suspicious);

        let none = msg(&[], "pat@example.com");
        assert_eq!(verdict(&render(&none).await), SpamVerdict::NotChecked);
    }

    #[tokio::test]
    async fn a_forged_pass_below_the_receiver_raises_nothing() {
        let forged = msg(
            &[
                "mx.example.net; dmarc=fail header.from=example.com",
                "mx.example.net; dmarc=pass header.from=example.com",
            ],
            "pat@example.com",
        );
        assert_eq!(verdict(&render(&forged).await), SpamVerdict::Suspicious);
        let r = render(&forged).await;
        assert_eq!(
            SignalsFilter.verdict(&SpamInput {
                rendered: &r,
                account: "a",
                in_junk: true,
                receivers: &receivers(),
            }),
            SpamVerdict::Junk
        );
    }

    #[tokio::test]
    async fn a_field_from_a_server_that_is_not_the_receiver_never_raises_trust() {
        let forged = msg(
            &[
                "mx.attacker.example; dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
            ],
            "pat@example.com",
        );
        let r = render(&forged).await;
        assert_eq!(verdict(&r), SpamVerdict::NotChecked);
        assert_eq!(verdict_from(&r, &[]), SpamVerdict::NotChecked);
        assert_eq!(
            verdict_from(&r, &["attacker.example".into()]),
            SpamVerdict::Clean
        );
        let lookalike = msg(
            &["mx.evilexample.net; dmarc=pass header.from=example.com"],
            "pat@example.com",
        );
        assert_eq!(verdict(&render(&lookalike).await), SpamVerdict::NotChecked);
        let failing = msg(
            &["mx.attacker.example; dmarc=fail header.from=example.com"],
            "pat@example.com",
        );
        assert_eq!(
            verdict(&render(&failing).await),
            SpamVerdict::Suspicious,
            "a failure lowers the verdict whoever wrote it"
        );
    }

    #[test]
    fn receivers_come_from_the_imap_host_the_address_and_known_providers() {
        assert_eq!(
            receivers_for("imap.example.co.uk", "ada@example.co.uk"),
            vec!["example.co.uk".to_string()]
        );
        assert_eq!(
            receivers_for("mail.example.org", "ada@example.com"),
            vec!["example.org".to_string(), "example.com".to_string()]
        );
        assert!(receivers_for("imap.gmail.com", "ada@gmail.com").contains(&"google.com".into()));
        assert!(
            receivers_for("imap.fastmail.com", "ada@fastmail.com")
                .contains(&"messagingengine.com".into())
        );
        assert!(receivers_for("127.0.0.1", "ada@localhost").is_empty());
        assert!(receivers_for("com", "ada@com").is_empty());
    }
}
