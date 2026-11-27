use proptest::prelude::*;

use super::*;

const NAME: &str = "_imaps._tcp.example.com";

fn name_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if !name.is_empty() {
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    out
}

fn srv_rr(
    owner: &[u8],
    kind: u16,
    priority: u16,
    weight: u16,
    port: u16,
    target: &[u8],
) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&priority.to_be_bytes());
    rdata.extend_from_slice(&weight.to_be_bytes());
    rdata.extend_from_slice(&port.to_be_bytes());
    rdata.extend_from_slice(target);
    let mut out = owner.to_vec();
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&300u32.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    out
}

fn answer(id: u16, flags: u16, records: &[Vec<u8>]) -> Vec<u8> {
    let mut msg = query(id, NAME).unwrap();
    msg[2..4].copy_from_slice(&flags.to_be_bytes());
    msg[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
    for r in records {
        msg.extend_from_slice(r);
    }
    msg
}

const POINTER_TO_QNAME: [u8; 2] = [0xc0, 12];

#[test]
fn queries_are_well_formed() {
    let q = query(0xabcd, NAME).unwrap();
    assert_eq!(&q[..4], &[0xab, 0xcd, 0x01, 0x00]);
    assert_eq!(&q[q.len() - 4..], &[0, 33, 0, 1]);
    assert!(query(1, &format!("{}.example.com", "a".repeat(64))).is_none());
    assert!(query(1, "a..b").is_none());
}

#[test]
fn reads_srv_records_with_compression() {
    let msg = answer(
        7,
        0x8180,
        &[
            srv_rr(
                &POINTER_TO_QNAME,
                TYPE_SRV,
                0,
                5,
                993,
                &name_wire("IMAP.example.com"),
            ),
            srv_rr(&name_wire(NAME), TYPE_SRV, 10, 0, 993, &name_wire("")),
        ],
    );
    let records = parse_answer(&msg, 7, NAME).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].target, "imap.example.com");
    assert_eq!((records[0].weight, records[0].port), (5, 993));
    assert_eq!(records[1].target, "");
}

#[test]
fn foreign_and_odd_records_are_ignored() {
    let msg = answer(
        7,
        0x8180,
        &[
            srv_rr(
                &name_wire("_imaps._tcp.evil.test"),
                TYPE_SRV,
                0,
                0,
                993,
                &name_wire("x.evil.test"),
            ),
            srv_rr(
                &POINTER_TO_QNAME,
                5,
                0,
                0,
                993,
                &name_wire("cname.example.com"),
            ),
            srv_rr(&POINTER_TO_QNAME, TYPE_SRV, 0, 0, 993, b"\x05a.b\xffc\x00"),
            srv_rr(
                &POINTER_TO_QNAME,
                TYPE_SRV,
                0,
                0,
                993,
                &name_wire("ok.example.com"),
            ),
        ],
    );
    let records = parse_answer(&msg, 7, NAME).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target, "ok.example.com");
}

#[test]
fn hostile_answers_are_refused_without_a_panic() {
    let good = srv_rr(
        &POINTER_TO_QNAME,
        TYPE_SRV,
        0,
        0,
        993,
        &name_wire("a.example.com"),
    );
    assert_eq!(
        parse_answer(&answer(8, 0x8180, std::slice::from_ref(&good)), 7, NAME),
        Err(AnswerError::NotOurs)
    );
    assert_eq!(
        parse_answer(&answer(7, 0x0100, std::slice::from_ref(&good)), 7, NAME),
        Err(AnswerError::NotOurs)
    );
    assert_eq!(
        parse_answer(&answer(7, 0x8380, std::slice::from_ref(&good)), 7, NAME),
        Err(AnswerError::Truncated)
    );
    assert_eq!(
        parse_answer(&answer(7, 0x8182, std::slice::from_ref(&good)), 7, NAME),
        Err(AnswerError::Failed)
    );
    assert_eq!(
        parse_answer(&answer(7, 0x8183, std::slice::from_ref(&good)), 7, NAME),
        Ok(Vec::new())
    );
    assert_eq!(
        parse_answer(
            &answer(7, 0x8180, std::slice::from_ref(&good)),
            7,
            "_imap._tcp.example.com"
        ),
        Err(AnswerError::NotOurs)
    );

    let looping = srv_rr(
        &[0xc0, 40],
        TYPE_SRV,
        0,
        0,
        993,
        &name_wire("a.example.com"),
    );
    let self_pointer = {
        let mut msg = answer(7, 0x8180, &[]);
        msg[6..8].copy_from_slice(&1u16.to_be_bytes());
        let at = msg.len() as u16;
        msg.extend_from_slice(&(0xc000 | at).to_be_bytes());
        msg
    };
    let mut lying_length = answer(7, 0x8180, std::slice::from_ref(&good));
    let rdlen_at = lying_length.len() - good.len() + 2 + 8;
    lying_length[rdlen_at..rdlen_at + 2].copy_from_slice(&5000u16.to_be_bytes());
    let mut target_past_rdata = answer(7, 0x8180, std::slice::from_ref(&good));
    target_past_rdata[rdlen_at..rdlen_at + 2].copy_from_slice(&8u16.to_be_bytes());
    target_past_rdata.extend_from_slice(&[0; 20]);
    let long_label = srv_rr(&POINTER_TO_QNAME, TYPE_SRV, 0, 0, 993, &[0x80, 1, 2]);
    let huge_name: Vec<u8> = std::iter::repeat_n([63u8].into_iter().chain([b'a'; 63]), 5)
        .flatten()
        .chain([0])
        .collect();
    let too_long = srv_rr(&POINTER_TO_QNAME, TYPE_SRV, 0, 0, 993, &huge_name);
    let mut claims_more = answer(7, 0x8180, std::slice::from_ref(&good));
    claims_more[6..8].copy_from_slice(&50u16.to_be_bytes());
    for msg in [
        answer(7, 0x8180, &[looping]),
        self_pointer,
        lying_length,
        target_past_rdata,
        answer(7, 0x8180, &[long_label]),
        answer(7, 0x8180, &[too_long]),
        claims_more,
        vec![0; 11],
        vec![0; MAX_MESSAGE + 1],
    ] {
        assert!(parse_answer(&msg, 7, NAME).is_err());
    }

    let flood: Vec<Vec<u8>> = (0..100)
        .map(|i| {
            srv_rr(
                &POINTER_TO_QNAME,
                TYPE_SRV,
                i,
                0,
                993,
                &name_wire("a.example.com"),
            )
        })
        .collect();
    let message = answer(7, 0x8180, &flood);
    assert!(message.len() <= MAX_MESSAGE && flood.len() > MAX_ANSWERS);
    let records = parse_answer(&message, 7, NAME).unwrap();
    assert_eq!(records.len(), MAX_SRV_RECORDS);
}

#[test]
fn reads_name_servers() {
    let conf = "# comment\nsearch example.com\nnameserver 192.0.2.1\nnameserver fe80::1%en0\nnameserver not-an-ip\nnameserver 2001:db8::1\nnameserver 192.0.2.9\n";
    let got = name_servers(conf);
    assert_eq!(got.len(), MAX_SERVERS);
    assert_eq!(got[0], "192.0.2.1:53".parse().unwrap());
    assert_eq!(got[1].ip().to_string(), "fe80::1");
}

async fn fake_server(reply: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            for datagram in reply(&buf[..n]) {
                let _ = socket.send_to(&datagram, peer).await;
            }
        }
    });
    address
}

fn answer_to(q: &[u8], records: &[Vec<u8>]) -> Vec<u8> {
    let mut msg = q.to_vec();
    msg[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    msg[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
    for r in records {
        msg.extend_from_slice(r);
    }
    msg
}

#[tokio::test]
async fn keeps_the_resolver_contract_against_a_loopback_server() {
    let server = fake_server(|q| {
        let asked = String::from_utf8_lossy(q);
        let records = if asked.contains("_imaps") {
            vec![srv_rr(
                &POINTER_TO_QNAME,
                TYPE_SRV,
                0,
                1,
                993,
                &name_wire("imap.example.com"),
            )]
        } else {
            Vec::new()
        };
        let mut forged = answer_to(
            q,
            &[srv_rr(
                &POINTER_TO_QNAME,
                TYPE_SRV,
                0,
                0,
                993,
                &name_wire("evil.test"),
            )],
        );
        forged[0] ^= 0xff;
        vec![forged, answer_to(q, &records)]
    })
    .await;
    let resolver = UdpResolver::new(vec![server], Duration::from_secs(2));
    rowboat_discover::testing::resolver(
        &resolver,
        NAME,
        &[SrvRecord {
            priority: 0,
            weight: 1,
            port: 993,
            target: "imap.example.com".into(),
        }],
        "_imap._tcp.example.com",
    )
    .await;
}

#[tokio::test]
async fn a_silent_or_truncating_server_gives_no_answer_in_time() {
    let silent = fake_server(|_| Vec::new()).await;
    let truncating = fake_server(|q| {
        let mut msg = answer_to(q, &[]);
        msg[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
        vec![msg]
    })
    .await;
    let hang = Duration::from_secs(30);
    let r = UdpResolver::new(vec![silent], Duration::from_millis(200));
    let got = tokio::time::timeout(hang, r.srv(NAME))
        .await
        .expect("the resolver's own timeout fires");
    assert_eq!(got, Err(DiscoverError::Timeout));
    let r = UdpResolver::new(vec![truncating], Duration::from_millis(200));
    let got = tokio::time::timeout(hang, r.srv(NAME))
        .await
        .expect("a truncated answer ends the query");
    assert_eq!(got, Err(DiscoverError::Unavailable));
}

proptest! {
    #[test]
    fn never_panics_on_any_bytes(mut bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let _ = parse_answer(&bytes, 7, NAME);
        if bytes.len() >= 4 {
            bytes[0] = 0;
            bytes[1] = 7;
            bytes[2] |= 0x80;
        }
        if let Ok(records) = parse_answer(&bytes, 7, NAME) {
            prop_assert!(records.len() <= MAX_SRV_RECORDS);
        }
    }

    #[test]
    fn never_panics_on_mutated_answers(at in 0usize..200, byte in any::<u8>()) {
        let mut msg = answer(
            7,
            0x8180,
            &[srv_rr(&POINTER_TO_QNAME, TYPE_SRV, 0, 5, 993, &name_wire("imap.example.com"))],
        );
        let i = at % msg.len();
        msg[i] = byte;
        let _ = parse_answer(&msg, 7, NAME);
    }
}
