//! Discovery from an embedded, reviewed table of well-known providers, and conventional host
//! guesses for every other domain. No I/O: the table is compiled in, guesses are built from the
//! domain alone and marked unverified (the node probes them when it has a prober).

use async_trait::async_trait;
use rowboat_discover::{
    AuthHint, Candidate, DiscoverError, DiscoverySource, Domain, Endpoint, MAX_CANDIDATES,
    Security, Source, UsernameForm, within,
};

struct Provider {
    domains: &'static [&'static str],
    imap: (&'static str, u16, Security),
    smtp: (&'static str, u16, Security),
    username: UsernameForm,
    auth: AuthHint,
    help: &'static str,
}

const TLS: Security = Security::Tls;
const STARTTLS: Security = Security::StartTls;

const PROVIDERS: &[Provider] = &[
    Provider {
        domains: &["gmail.com", "googlemail.com"],
        imap: ("imap.gmail.com", 993, TLS),
        smtp: ("smtp.gmail.com", 465, TLS),
        username: UsernameForm::Address,
        auth: AuthHint::AppPassword,
        help: "app-password-google",
    },
    Provider {
        domains: &["outlook.com", "hotmail.com", "live.com", "msn.com"],
        imap: ("outlook.office365.com", 993, TLS),
        smtp: ("smtp-mail.outlook.com", 587, STARTTLS),
        username: UsernameForm::Address,
        auth: AuthHint::OAuthOnly,
        help: "oauth-microsoft",
    },
    Provider {
        domains: &["yahoo.com", "ymail.com"],
        imap: ("imap.mail.yahoo.com", 993, TLS),
        smtp: ("smtp.mail.yahoo.com", 465, TLS),
        username: UsernameForm::Address,
        auth: AuthHint::AppPassword,
        help: "app-password-yahoo",
    },
    Provider {
        domains: &["aol.com"],
        imap: ("imap.aol.com", 993, TLS),
        smtp: ("smtp.aol.com", 465, TLS),
        username: UsernameForm::Address,
        auth: AuthHint::AppPassword,
        help: "app-password-aol",
    },
    Provider {
        domains: &["icloud.com", "me.com", "mac.com"],
        imap: ("imap.mail.me.com", 993, TLS),
        smtp: ("smtp.mail.me.com", 587, STARTTLS),
        username: UsernameForm::LocalPart,
        auth: AuthHint::AppPassword,
        help: "app-password-apple",
    },
    Provider {
        domains: &["fastmail.com", "fastmail.fm"],
        imap: ("imap.fastmail.com", 993, TLS),
        smtp: ("smtp.fastmail.com", 465, TLS),
        username: UsernameForm::Address,
        auth: AuthHint::AppPassword,
        help: "app-password-fastmail",
    },
    Provider {
        domains: &["gmx.com", "gmx.net", "gmx.de"],
        imap: ("imap.gmx.net", 993, TLS),
        smtp: ("mail.gmx.net", 587, STARTTLS),
        username: UsernameForm::Address,
        auth: AuthHint::Password,
        help: "imap-enable-gmx",
    },
    Provider {
        domains: &["web.de"],
        imap: ("imap.web.de", 993, TLS),
        smtp: ("smtp.web.de", 587, STARTTLS),
        username: UsernameForm::Address,
        auth: AuthHint::Password,
        help: "imap-enable-webde",
    },
    Provider {
        domains: &["yandex.ru", "yandex.com", "ya.ru"],
        imap: ("imap.yandex.com", 993, TLS),
        smtp: ("smtp.yandex.com", 465, TLS),
        username: UsernameForm::Address,
        auth: AuthHint::AppPassword,
        help: "app-password-yandex",
    },
    Provider {
        domains: &["mail.ru", "inbox.ru", "list.ru", "bk.ru"],
        imap: ("imap.mail.ru", 993, TLS),
        smtp: ("smtp.mail.ru", 465, TLS),
        username: UsernameForm::Address,
        auth: AuthHint::AppPassword,
        help: "app-password-mailru",
    },
    Provider {
        domains: &["zoho.com", "zohomail.com"],
        imap: ("imap.zoho.com", 993, TLS),
        smtp: ("smtp.zoho.com", 465, TLS),
        username: UsernameForm::Address,
        auth: AuthHint::AppPassword,
        help: "app-password-zoho",
    },
    Provider {
        domains: &["posteo.de", "posteo.net"],
        imap: ("posteo.de", 993, TLS),
        smtp: ("posteo.de", 587, STARTTLS),
        username: UsernameForm::Address,
        auth: AuthHint::Password,
        help: "posteo",
    },
];

/// The table and the guesses.
#[derive(Debug, Clone, Copy, Default)]
pub struct TableSource;

impl TableSource {
    /// The source.
    pub fn new() -> Self {
        Self
    }

    /// Every domain the table knows, in table order.
    pub fn known_domains() -> impl Iterator<Item = &'static str> {
        PROVIDERS.iter().flat_map(|p| p.domains.iter().copied())
    }

    /// Whether `host` belongs to a provider the table knows: one of its servers, a name under
    /// the domain of one of its servers (the server's name without its first label, when that
    /// leaves at least two labels), or a name under one of its mail domains. Used to tell
    /// servers that need the person's confirmation from those that do not.
    pub fn known_host(host: &str) -> bool {
        let under = |domain: &str| {
            host == domain
                || host
                    .strip_suffix(domain)
                    .is_some_and(|rest| rest.ends_with('.'))
        };
        PROVIDERS.iter().any(|p| {
            p.domains.iter().any(|d| under(d))
                || [p.imap.0, p.smtp.0].iter().any(|server| {
                    under(server)
                        || server
                            .split_once('.')
                            .filter(|(_, parent)| parent.contains('.'))
                            .is_some_and(|(_, parent)| under(parent))
                })
        })
    }
}

/// Whether a server named `host` for an address on `domain` needs the person's confirmation:
/// it lies outside the domain and outside every provider the table knows. The node marks such
/// candidates `needs_confirmation`, and an app checks every server a person is about to send a
/// password to with the same rule, since the form it shows can be edited.
pub fn needs_confirmation(host: &str, domain: &Domain) -> bool {
    !within(host, domain) && !TableSource::known_host(host)
}

fn endpoint((host, port, security): (&str, u16, Security)) -> Result<Endpoint, DiscoverError> {
    Endpoint::new(host, port, security)
}

fn guesses(domain: &Domain) -> Vec<Candidate> {
    let d = domain.as_str();
    type Server = (&'static str, u16, Security);
    let shapes: [(Server, Server); 4] = [
        (("imap", 993, TLS), ("smtp", 465, TLS)),
        (("imap", 993, TLS), ("smtp", 587, STARTTLS)),
        (("mail", 993, TLS), ("mail", 465, TLS)),
        (("mail", 143, STARTTLS), ("mail", 587, STARTTLS)),
    ];
    shapes
        .iter()
        .filter_map(|((ih, ip, is), (sh, sp, ss))| {
            Some(Candidate {
                imap: Endpoint::new(&format!("{ih}.{d}"), *ip, *is).ok()?,
                smtp: Endpoint::new(&format!("{sh}.{d}"), *sp, *ss).ok()?,
                username: UsernameForm::Address,
                auth: AuthHint::Password,
                help: None,
                source: Source::Guess,
                verified: false,
                needs_confirmation: false,
            })
        })
        .take(MAX_CANDIDATES)
        .collect()
}

#[async_trait]
impl DiscoverySource for TableSource {
    async fn lookup(&self, domain: &Domain) -> Result<Vec<Candidate>, DiscoverError> {
        if let Some(p) = PROVIDERS
            .iter()
            .find(|p| p.domains.contains(&domain.as_str()))
        {
            return Ok(vec![Candidate {
                imap: endpoint(p.imap)?,
                smtp: endpoint(p.smtp)?,
                username: p.username,
                auth: p.auth,
                help: Some(p.help.to_owned()),
                source: Source::Table,
                verified: false,
                needs_confirmation: false,
            }]);
        }
        Ok(guesses(domain))
    }

    fn name(&self) -> &'static str {
        "table"
    }
}

#[cfg(test)]
mod tests {
    use rowboat_discover::valid_topic;

    use super::*;

    #[tokio::test]
    async fn conformance() {
        let answers = rowboat_discover::testing::source(
            &TableSource,
            &[
                "gmail.com",
                "outlook.com",
                "example.com",
                "mail.example.org",
            ],
        )
        .await;
        assert_eq!(answers[0][0].source, Source::Table);
        assert_eq!(answers[1][0].auth, AuthHint::OAuthOnly);
        assert!(
            answers[2]
                .iter()
                .all(|c| c.source == Source::Guess && !c.verified)
        );
    }

    #[test]
    fn the_table_is_well_formed() {
        let mut seen = std::collections::BTreeSet::new();
        for p in PROVIDERS {
            assert!(endpoint(p.imap).is_ok() && endpoint(p.smtp).is_ok());
            assert!(valid_topic(p.help));
            for d in p.domains {
                assert!(Domain::new(d).is_ok(), "{d}");
                assert!(seen.insert(*d), "{d} listed twice");
            }
        }
        assert_eq!(TableSource::known_domains().count(), seen.len());
    }

    #[test]
    fn known_hosts_are_the_providers_own() {
        for host in [
            "imap.gmail.com",
            "smtp.gmail.com",
            "outlook.office365.com",
            "eu.outlook.office365.com",
            "imap.mail.me.com",
            "posteo.de",
        ] {
            assert!(TableSource::known_host(host), "{host}");
        }
        for host in [
            "gmail.com.evil.test",
            "imap.example.com",
            "notgmail.com",
            "com",
        ] {
            assert!(!TableSource::known_host(host), "{host}");
        }
    }

    #[test]
    fn attack_servers_outside_the_domain_and_the_table_need_confirmation() {
        let d = Domain::new("example.com").unwrap();
        for host in [
            "imap.example.com",
            "example.com",
            "imap.gmail.com",
            "posteo.de",
        ] {
            assert!(!needs_confirmation(host, &d), "{host}");
        }
        for host in [
            "mail.attacker.example",
            "imap.example.com.attacker.example",
            "notexample.com",
            "gmail.com.attacker.example",
        ] {
            assert!(needs_confirmation(host, &d), "{host}");
        }
    }

    #[tokio::test]
    async fn guesses_follow_the_domain_and_skip_hosts_that_would_be_too_long() {
        let d = Domain::new("example.com").unwrap();
        let g = TableSource.lookup(&d).await.unwrap();
        assert_eq!(g.len(), 4);
        assert_eq!(g[0].imap.host, "imap.example.com");
        assert_eq!(g[0].smtp.port, 465);
        assert_eq!(g[3].imap.security, Security::StartTls);
        let long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(59)
        );
        let d = Domain::new(&long).unwrap();
        assert!(TableSource.lookup(&d).await.unwrap().is_empty());
    }
}
