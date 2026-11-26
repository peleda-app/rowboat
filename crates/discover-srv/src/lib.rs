//! Discovery from the domain's DNS SRV records: RFC 6186 (`_imaps._tcp`, `_imap._tcp`,
//! `_submission._tcp`) and RFC 8314 (`_submissions._tcp`).
//!
//! Records come through an [`SrvResolver`]; they are untrusted, so targets are checked like any
//! host and every candidate is still probed by the node before it is offered.

use std::sync::Arc;

use async_trait::async_trait;
use rowboat_discover::{
    AuthHint, Candidate, DiscoverError, DiscoverySource, Domain, Endpoint, MAX_CANDIDATES,
    Security, Source, SrvRecord, SrvResolver, UsernameForm, valid_host,
};

/// Most servers of each kind kept from the records, best first.
pub const MAX_SERVERS: usize = 4;

const IMAP: [(&str, Security); 2] = [("_imaps", Security::Tls), ("_imap", Security::StartTls)];
const SUBMISSION: [(&str, Security); 2] = [
    ("_submissions", Security::Tls),
    ("_submission", Security::StartTls),
];

/// The SRV source over a resolver.
pub struct SrvSource {
    resolver: Arc<dyn SrvResolver>,
}

impl SrvSource {
    /// A source resolving with `resolver`.
    pub fn new(resolver: Arc<dyn SrvResolver>) -> Self {
        Self { resolver }
    }

    async fn servers(
        &self,
        domain: &Domain,
        services: &[(&str, Security)],
    ) -> Result<Vec<Endpoint>, DiscoverError> {
        let mut answered = false;
        let mut out = Vec::new();
        for (service, security) in services {
            let name = format!("{service}._tcp.{}", domain.as_str());
            if let Ok(records) = self.resolver.srv(&name).await {
                answered = true;
                out.extend(endpoints(records, *security));
            }
        }
        if !answered {
            return Err(DiscoverError::Unavailable);
        }
        out.truncate(MAX_SERVERS);
        Ok(out)
    }
}

/// The endpoints the records of one service name: targets of `.` (not offered), invalid hosts,
/// IP literals and port 0 dropped; sorted by priority (lower first), then weight (higher
/// first), then target and port, so equal records give equal order; at most [`MAX_SERVERS`].
/// Pure and deterministic.
pub fn endpoints(mut records: Vec<SrvRecord>, security: Security) -> Vec<Endpoint> {
    records.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then(b.weight.cmp(&a.weight))
            .then(a.target.cmp(&b.target))
            .then(a.port.cmp(&b.port))
    });
    let mut out: Vec<Endpoint> = Vec::new();
    for r in records {
        if out.len() == MAX_SERVERS {
            break;
        }
        let host = r.target.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || !valid_host(&host) || rowboat_discover::is_ip_literal(&host) {
            continue;
        }
        if let Ok(e) = Endpoint::new(&host, r.port, security)
            && !out.contains(&e)
        {
            out.push(e);
        }
    }
    out
}

#[async_trait]
impl DiscoverySource for SrvSource {
    async fn lookup(&self, domain: &Domain) -> Result<Vec<Candidate>, DiscoverError> {
        let imap = self.servers(domain, &IMAP).await?;
        let smtp = self.servers(domain, &SUBMISSION).await?;
        let mut out = Vec::new();
        for i in &imap {
            for s in &smtp {
                if out.len() == MAX_CANDIDATES {
                    return Ok(out);
                }
                out.push(Candidate {
                    imap: i.clone(),
                    smtp: s.clone(),
                    username: UsernameForm::Address,
                    auth: AuthHint::Password,
                    help: None,
                    source: Source::Srv,
                    verified: false,
                    needs_confirmation: false,
                });
            }
        }
        Ok(out)
    }

    fn name(&self) -> &'static str {
        "srv"
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rowboat_discover::testing::FakeResolver;

    use super::*;

    fn rec(priority: u16, weight: u16, port: u16, target: &str) -> SrvRecord {
        SrvRecord {
            priority,
            weight,
            port,
            target: target.into(),
        }
    }

    #[test]
    fn records_are_ordered_and_checked() {
        let got = endpoints(
            vec![
                rec(10, 0, 993, "b.example.com"),
                rec(0, 5, 993, "a.example.com"),
                rec(0, 50, 993, "c.example.com"),
                rec(0, 0, 993, ""),
                rec(0, 0, 993, "10.0.0.1"),
                rec(0, 0, 0, "d.example.com"),
                rec(0, 0, 993, "bad_host.example.com"),
                rec(0, 50, 993, "c.example.com."),
            ],
            Security::Tls,
        );
        let hosts: Vec<&str> = got.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(hosts, ["c.example.com", "a.example.com", "b.example.com"]);
    }

    #[tokio::test]
    async fn pairs_imap_and_submission_and_keeps_the_conformance_suite() {
        let resolver = Arc::new(FakeResolver::new([
            (
                "_imaps._tcp.example.com".to_owned(),
                vec![rec(0, 0, 993, "imap.example.com")],
            ),
            (
                "_imap._tcp.example.com".to_owned(),
                vec![rec(0, 0, 143, "imap.example.com")],
            ),
            ("_imap._tcp.example.org".to_owned(), vec![rec(0, 0, 0, "")]),
            (
                "_submission._tcp.example.com".to_owned(),
                vec![rec(0, 0, 587, "smtp.example.net")],
            ),
        ]));
        let source = SrvSource::new(resolver.clone());
        let answers =
            rowboat_discover::testing::source(&source, &["example.com", "example.org"]).await;
        assert_eq!(answers[0].len(), 2);
        assert_eq!(answers[0][0].imap.security, Security::Tls);
        assert_eq!(answers[0][1].imap.security, Security::StartTls);
        assert!(answers[0].iter().all(|c| c.smtp.host == "smtp.example.net"
            && c.smtp.security == Security::StartTls
            && c.source == Source::Srv));
        assert!(answers[1].is_empty());
        assert!(resolver.asked().iter().all(|n| n.ends_with(".example.com")
            || n.ends_with(".example.org")
            || n.contains("._tcp.")));
    }

    proptest! {
        #[test]
        fn endpoints_are_bounded_valid_and_deterministic(
            raw in proptest::collection::vec((any::<u16>(), any::<u16>(), any::<u16>(), "[a-z.]{0,12}"), 0..40)
        ) {
            let records: Vec<SrvRecord> = raw.iter().map(|(p, w, port, t)| rec(*p, *w, *port, t)).collect();
            let mut reversed = records.clone();
            reversed.reverse();
            let got = endpoints(records, Security::Tls);
            prop_assert!(got.len() <= MAX_SERVERS);
            prop_assert!(got.iter().all(Endpoint::is_valid));
            prop_assert_eq!(endpoints(reversed, Security::Tls), got);
        }
    }
}
