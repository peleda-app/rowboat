use std::collections::HashMap;
use std::sync::Arc;

use futures::StreamExt;
use rowboat_discover::{
    AuthHint, Candidate, DiscoverError, DiscoverySource, Domain, Endpoint, Probed, Prober, Source,
};
use tracing::debug;

/// Probes in flight at once during one discovery.
const PROBES_IN_FLIGHT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Imap,
    Smtp,
}

fn rank(source: Source) -> usize {
    match source {
        Source::Table => 0,
        Source::Autoconfig => 1,
        Source::Srv => 2,
        Source::Guess => 3,
    }
}

fn networked(source: Source) -> bool {
    matches!(source, Source::Autoconfig | Source::Srv)
}

/// Candidates for `domain`:
///
/// 1. The first source is asked alone; when it knows the provider (a `table` candidate), the
///    answer is that and nothing goes to the network.
/// 2. Otherwise the other sources are asked at once. Candidates from networked sources that
///    name an IP literal or STARTTLS on an odd port are dropped.
/// 3. Answers are joined by source rank (table, autoconfig, SRV, guesses), duplicates dropped.
/// 4. With a prober, every candidate not from the table is kept only when both servers answer a
///    probe; it is then `verified`, and its sign-in hint follows what the IMAP server offers.
/// 5. A candidate not from the table whose server lies outside the domain and the table's
///    providers `needs_confirmation`.
pub(crate) async fn discover(
    sources: &[Arc<dyn DiscoverySource>],
    prober: Option<&dyn Prober>,
    domain: &Domain,
) -> Vec<Candidate> {
    let Some((first, rest)) = sources.split_first() else {
        return Vec::new();
    };
    let mut answers = vec![first.lookup(domain).await.unwrap_or_default()];
    if !answers[0].iter().any(|c| c.source == Source::Table) {
        let more = futures::future::join_all(rest.iter().map(|s| s.lookup(domain))).await;
        for (source, answer) in rest.iter().zip(more) {
            match answer {
                Ok(list) => answers.push(list),
                Err(e) => debug!(source = source.name(), error = %e, "discovery source failed"),
            }
        }
    }
    let mut buckets: Vec<Vec<Candidate>> = vec![Vec::new(); 4];
    for c in answers.into_iter().flatten() {
        if !networked(c.source) || c.fit_from_network() {
            buckets[rank(c.source)].push(c);
        }
    }
    let merged = rowboat_discover::merge(buckets);
    let mut out = match prober {
        Some(prober) => probed(merged, prober).await,
        None => merged,
    };
    for c in &mut out {
        if c.source != Source::Table {
            c.needs_confirmation = [&c.imap.host, &c.smtp.host]
                .iter()
                .any(|h| rowboat_discover_table::needs_confirmation(h, domain));
        }
    }
    out
}

async fn probed(candidates: Vec<Candidate>, prober: &dyn Prober) -> Vec<Candidate> {
    let mut wanted: Vec<(Kind, Endpoint)> = Vec::new();
    for c in candidates.iter().filter(|c| c.source != Source::Table) {
        for key in [(Kind::Imap, c.imap.clone()), (Kind::Smtp, c.smtp.clone())] {
            if !wanted.contains(&key) {
                wanted.push(key);
            }
        }
    }
    let results: HashMap<(Kind, Endpoint), Result<Probed, DiscoverError>> =
        futures::stream::iter(wanted)
            .map(|(kind, endpoint)| async move {
                let result = match kind {
                    Kind::Imap => prober.probe_imap(&endpoint).await,
                    Kind::Smtp => prober.probe_smtp(&endpoint).await,
                };
                ((kind, endpoint), result)
            })
            .buffer_unordered(PROBES_IN_FLIGHT)
            .collect()
            .await;
    let failed = results.values().filter(|r| r.is_err()).count();
    debug!(probes = results.len(), failed, "discovery probes done");
    candidates
        .into_iter()
        .filter_map(|mut c| {
            if c.source == Source::Table {
                return Some(c);
            }
            let imap = results.get(&(Kind::Imap, c.imap.clone()))?.as_ref().ok()?;
            let smtp = results.get(&(Kind::Smtp, c.smtp.clone()))?.as_ref().ok()?;
            c.auth = match (imap.password_sign_in && smtp.password_sign_in, imap.oauth) {
                (true, _) => c.auth,
                (false, true) => AuthHint::OAuthOnly,
                (false, false) => return None,
            };
            c.verified = true;
            Some(c)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use rowboat_discover::testing::{FakeFetcher, FakeProber, FakeResolver};
    use rowboat_discover::{Security, SrvRecord, UsernameForm};
    use rowboat_discover_autoconfig::AutoconfigSource;
    use rowboat_discover_srv::SrvSource;
    use rowboat_discover_table::TableSource;

    use super::*;

    const OK: Result<Probed, DiscoverError> = Ok(Probed {
        password_sign_in: true,
        oauth: false,
    });

    fn autoconfig(imap: &str, smtp: &str, smtp_port: u16, socket: &str) -> Vec<u8> {
        format!(
            r#"<clientConfig version="1.1"><emailProvider id="x">
<incomingServer type="imap"><hostname>{imap}</hostname><port>993</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username></incomingServer>
<outgoingServer type="smtp"><hostname>{smtp}</hostname><port>{smtp_port}</port><socketType>{socket}</socketType><username>%EMAILADDRESS%</username></outgoingServer>
</emailProvider></clientConfig>"#
        )
        .into_bytes()
    }

    fn sources(
        fetcher: Arc<FakeFetcher>,
        resolver: Arc<FakeResolver>,
    ) -> Vec<Arc<dyn DiscoverySource>> {
        vec![
            Arc::new(TableSource),
            Arc::new(AutoconfigSource::new(fetcher)),
            Arc::new(SrvSource::new(resolver)),
        ]
    }

    fn domain(d: &str) -> Domain {
        Domain::new(d).unwrap()
    }

    #[tokio::test]
    async fn a_known_provider_never_reaches_the_network() {
        let fetcher = Arc::new(FakeFetcher::default());
        let resolver = Arc::new(FakeResolver::default());
        let prober = FakeProber::default();
        let got = discover(
            &sources(fetcher.clone(), resolver.clone()),
            Some(&prober),
            &domain("gmail.com"),
        )
        .await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].source, Source::Table);
        assert!(!got[0].needs_confirmation && !got[0].verified);
        assert!(fetcher.asked().is_empty() && resolver.asked().is_empty());
        assert!(prober.asked().is_empty());
    }

    #[tokio::test]
    async fn autoconfig_and_srv_come_before_guesses_and_only_probed_servers_are_offered() {
        let fetcher = Arc::new(FakeFetcher::new([(
            "https://autoconfig.example.com/mail/config-v1.1.xml".to_owned(),
            autoconfig("imap.example.com", "smtp.example.com", 465, "SSL"),
        )]));
        let resolver = Arc::new(FakeResolver::new([
            (
                "_imaps._tcp.example.com".to_owned(),
                vec![SrvRecord {
                    priority: 0,
                    weight: 0,
                    port: 993,
                    target: "mx.example.com".into(),
                }],
            ),
            (
                "_submissions._tcp.example.com".to_owned(),
                vec![SrvRecord {
                    priority: 0,
                    weight: 0,
                    port: 465,
                    target: "mx.example.com".into(),
                }],
            ),
        ]));
        let prober = FakeProber::new([
            ("imap.example.com".to_owned(), OK),
            ("smtp.example.com".to_owned(), OK),
            ("mx.example.com".to_owned(), OK),
            ("mail.example.com".to_owned(), Err(DiscoverError::TlsFailed)),
        ]);
        let got = discover(
            &sources(fetcher, resolver),
            Some(&prober),
            &domain("example.com"),
        )
        .await;
        let sources: Vec<Source> = got.iter().map(|c| c.source).collect();
        assert_eq!(sources[0], Source::Autoconfig);
        assert_eq!(sources[1], Source::Srv);
        assert!(got.iter().all(|c| c.verified && !c.needs_confirmation));
        assert!(got.iter().all(|c| c.imap.host != "mail.example.com"));
        assert!(
            got.iter()
                .any(|c| c.source == Source::Guess && c.imap.host == "imap.example.com"),
            "a guess equal to no earlier candidate survives when its servers answered"
        );
        let asked = prober.asked();
        let mut unique = asked.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(asked.len(), unique.len(), "every server probed once");
    }

    #[tokio::test]
    async fn hosts_outside_the_domain_need_confirmation_and_hostile_answers_are_dropped() {
        let fetcher = Arc::new(FakeFetcher::new([(
            "https://autoconfig.example.com/mail/config-v1.1.xml".to_owned(),
            [autoconfig(
                "imap.hoster.example.net",
                "smtp.example.com",
                465,
                "SSL",
            )]
            .concat(),
        )]));
        let resolver = Arc::new(FakeResolver::new([
            (
                "_imap._tcp.example.com".to_owned(),
                vec![SrvRecord {
                    priority: 0,
                    weight: 0,
                    port: 2143,
                    target: "imap.example.com".into(),
                }],
            ),
            (
                "_submission._tcp.example.com".to_owned(),
                vec![SrvRecord {
                    priority: 0,
                    weight: 0,
                    port: 587,
                    target: "smtp.gmail.com".into(),
                }],
            ),
        ]));
        let prober = FakeProber::new([
            ("imap.hoster.example.net".to_owned(), OK),
            ("smtp.example.com".to_owned(), OK),
            ("imap.example.com".to_owned(), OK),
            ("smtp.gmail.com".to_owned(), OK),
        ]);
        let got = discover(
            &sources(fetcher, resolver),
            Some(&prober),
            &domain("example.com"),
        )
        .await;
        let auto = got.iter().find(|c| c.source == Source::Autoconfig).unwrap();
        assert!(
            auto.needs_confirmation,
            "a host outside the domain is only suggested"
        );
        assert!(
            !got.iter().any(|c| c.imap.port == 2143),
            "STARTTLS on an odd port from DNS is dropped"
        );
        assert!(
            !prober.asked().iter().any(|p| p.contains(":2143")),
            "a dropped candidate is never probed"
        );
        let guesses = got.iter().filter(|c| c.source == Source::Guess);
        assert!(guesses.into_iter().all(|c| !c.needs_confirmation));
    }

    #[tokio::test]
    async fn oauth_only_and_password_less_servers_follow_the_probe() {
        let prober = FakeProber::new([
            (
                "imap.example.com".to_owned(),
                Ok(Probed {
                    password_sign_in: false,
                    oauth: true,
                }),
            ),
            ("smtp.example.com".to_owned(), OK),
            (
                "mail.example.com".to_owned(),
                Ok(Probed {
                    password_sign_in: false,
                    oauth: false,
                }),
            ),
        ]);
        let sources: Vec<Arc<dyn DiscoverySource>> = vec![Arc::new(TableSource)];
        let got = discover(&sources, Some(&prober), &domain("example.com")).await;
        assert!(!got.is_empty());
        assert!(got.iter().all(|c| c.imap.host == "imap.example.com"
            && c.auth == AuthHint::OAuthOnly
            && c.username == UsernameForm::Address));
    }

    #[tokio::test]
    async fn without_a_prober_guesses_stay_unverified() {
        let sources: Vec<Arc<dyn DiscoverySource>> = vec![Arc::new(TableSource)];
        let got = discover(&sources, None, &domain("example.org")).await;
        assert_eq!(got.len(), 4);
        assert!(got.iter().all(|c| !c.verified && !c.needs_confirmation));
        assert_eq!(got[3].imap.security, Security::StartTls);
    }
}
