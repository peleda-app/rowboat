use proptest::prelude::*;
use rowboat_discover::testing::FakeFetcher;

use super::*;

const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/provider.xml");

fn domain() -> Domain {
    Domain::new("example.com").unwrap()
}

fn wrap(servers: &str) -> Vec<u8> {
    format!(r#"<clientConfig version="1.1"><emailProvider id="x">{servers}</emailProvider></clientConfig>"#)
        .into_bytes()
}

const IMAP: &str = r#"<incomingServer type="imap"><hostname>imap.example.com</hostname><port>993</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username><authentication>password-cleartext</authentication></incomingServer>"#;
const SMTP: &str = r#"<outgoingServer type="smtp"><hostname>smtp.example.com</hostname><port>465</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username><authentication>password-cleartext</authentication></outgoingServer>"#;

#[test]
fn reads_the_fixture_and_skips_plain_and_pop() {
    let found = parse(FIXTURE, &domain());
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].imap.host, "imap.example.com");
    assert_eq!(found[0].imap.security, Security::Tls);
    assert_eq!(found[0].smtp.port, 465);
    assert_eq!(found[1].smtp.security, Security::StartTls);
    assert!(found.iter().all(|c| c.source == Source::Autoconfig
        && !c.verified
        && c.username == UsernameForm::Address
        && c.auth == AuthHint::Password));
}

#[test]
fn reads_oauth_and_local_part_and_refuses_odd_servers() {
    let oauth = IMAP
        .replace("password-cleartext", "OAuth2")
        .replace("%EMAILADDRESS%", "%EMAILLOCALPART%");
    let found = parse(&wrap(&format!("{oauth}{SMTP}")), &domain());
    assert_eq!(found[0].auth, AuthHint::OAuthOnly);
    assert_eq!(found[0].username, UsernameForm::LocalPart);
    for bad in [
        IMAP.replace("SSL", "plain"),
        IMAP.replace("993", "0"),
        IMAP.replace("993", "70000"),
        IMAP.replace("imap.example.com", "imap.example.com:993"),
        IMAP.replace("imap.example.com", "%EMAILLOCALPART%.example.com"),
        IMAP.replace("imap.example.com", "IMAP..example.com"),
        IMAP.replace("%EMAILADDRESS%", "admin"),
        IMAP.replace("password-cleartext", "NTLM"),
        IMAP.replace("password-cleartext", "client-IP-address"),
    ] {
        assert!(
            parse(&wrap(&format!("{bad}{SMTP}")), &domain()).is_empty(),
            "{bad}"
        );
    }
}

#[test]
fn hostile_documents_give_nothing() {
    let deep = format!(
        "<clientConfig>{}{}</clientConfig>",
        "<a>".repeat(MAX_DEPTH + 1),
        "</a>".repeat(MAX_DEPTH + 1)
    );
    let many = wrap(&format!("{}{IMAP}{SMTP}", "<x/>".repeat(MAX_ELEMENTS + 1)));
    let long = wrap(&format!(
        "{}{SMTP}",
        IMAP.replace(
            "imap.example.com",
            &format!("{}.example.com", "a".repeat(300))
        )
    ));
    let entities = format!(
        r#"<?xml version="1.0"?><!DOCTYPE clientConfig [<!ENTITY h "imap.example.com">]>{}"#,
        String::from_utf8(wrap(&format!(
            "{}{SMTP}",
            IMAP.replace("imap.example.com", "&h;")
        )))
        .unwrap()
    );
    let unknown_entity = wrap(&format!(
        "{}{SMTP}",
        IMAP.replace("imap.example.com", "&h;")
    ));
    let two_roots = [
        wrap(&format!("{IMAP}{SMTP}")),
        wrap(&format!("{IMAP}{SMTP}")),
    ]
    .concat();
    let oversized = [wrap(&format!("{IMAP}{SMTP}")), vec![b' '; MAX_FILE_BYTES]].concat();
    for doc in [
        deep.into_bytes(),
        many,
        long,
        entities.into_bytes(),
        unknown_entity,
        two_roots,
        oversized,
        b"\xff\xfe<clientConfig/>".to_vec(),
        b"<other><emailProvider/></other>".to_vec(),
        b"<clientConfig><emailProvider>".to_vec(),
        Vec::new(),
    ] {
        assert!(parse(&doc, &domain()).is_empty());
    }
    let escaped = wrap(&format!(
        "{}{SMTP}",
        IMAP.replace("imap.example.com", "imap&#46;example.com")
    ));
    assert_eq!(parse(&escaped, &domain()).len(), 1);
}

#[test]
fn candidates_are_bounded() {
    let servers = format!("{}{}", IMAP.repeat(10), SMTP.repeat(10));
    let found = parse(&wrap(&servers), &domain());
    assert_eq!(found.len(), MAX_SERVERS * MAX_SERVERS);
    assert!(found.len() <= MAX_CANDIDATES);
}

#[tokio::test]
async fn asks_the_domain_itself_and_keeps_the_conformance_suite() {
    let fetcher = Arc::new(FakeFetcher::new([(
        "https://example.com/.well-known/autoconfig/mail/config-v1.1.xml".to_owned(),
        FIXTURE.to_vec(),
    )]));
    let source = AutoconfigSource::new(fetcher.clone());
    let answers = rowboat_discover::testing::source(&source, &["example.com", "example.org"]).await;
    assert_eq!(answers[0].len(), 2);
    assert!(answers[1].is_empty());
    let asked = fetcher.asked();
    assert_eq!(
        asked[0],
        "https://autoconfig.example.com/mail/config-v1.1.xml"
    );
    assert_eq!(
        asked[1],
        "https://example.com/.well-known/autoconfig/mail/config-v1.1.xml"
    );
    assert!(asked.iter().all(|u| !u.contains('?') && !u.contains('@')));
}

proptest! {
    #[test]
    fn never_panics_and_stays_valid(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let found = parse(&bytes, &domain());
        prop_assert!(found.len() <= MAX_CANDIDATES);
        prop_assert!(found.iter().all(Candidate::is_valid));
    }

    #[test]
    fn mutated_fixtures_stay_valid(at in 0usize..2000, byte in any::<u8>()) {
        let mut doc = FIXTURE.to_vec();
        let i = at % doc.len();
        doc[i] = byte;
        let found = parse(&doc, &domain());
        prop_assert!(found.iter().all(Candidate::is_valid));
        prop_assert_eq!(parse(&doc, &domain()), found);
    }
}
