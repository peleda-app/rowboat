//! The whole of batond on 127.0.0.1: data directory and node key file, iroh, the group and
//! lease protocols from a member, the drop service in the same process, restart and refusals.

use std::sync::Arc;
use std::time::Duration;

use baton_core::{GroupId, LeaseKey, Timestamp};
use baton_group::{Founding, GroupLog, Op};
use baton_group_server::{ClientConfig, GroupClient, RemoteError};
use baton_identity::Identity;
use baton_keys::{KemSecret, RecoveryRoot};
use baton_lease::{Leases, Liveness, NodeClass, NodeProfile};
use baton_lease_server::{LeaseClient, RemoteLeases, RemoteLiveness};
use baton_link::{Link, PeerHint, PinnedKeys};
use baton_link_iroh::{IrohConfig, IrohLink};
use baton_mailbox::{Admission, BoxId, BoxKey, BoxPolicy, Mailbox};
use batond::{Clocks, Config, start};
use bytes::Bytes;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn loopback() -> IrohConfig {
    IrohConfig {
        bind: vec![([127, 0, 0, 1], 0).into()],
        open_timeout: Duration::from_secs(5),
        ..IrohConfig::default()
    }
}

#[cfg(unix)]
fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test(flavor = "multi_thread")]
async fn batond_serves_a_member_over_iroh_and_runs_drop() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("batond");
    let owner = Identity::generate();
    let laptop = Identity::generate();
    let laptop_kem = KemSecret::generate();
    let now = Timestamp::now();
    let mut log = GroupLog::genesis(
        GroupId::new("family").unwrap(),
        Founding {
            owner: &owner,
            owner_recovery: RecoveryRoot::generate().public(),
            group_recovery: RecoveryRoot::generate().public(),
            node: &laptop,
            node_kem: laptop_kem.public(),
            class: NodeClass::Desktop,
            expires: now.plus_ms(86_400_000),
        },
        now,
    )
    .unwrap();
    let text = format!(
        r#"
        data_dir = "{data}"
        [[group]]
        id = "family"
        genesis = "{genesis}"
        bootstrap = ["{founder}"]
        [iroh]
        bind = ["127.0.0.1:0"]
        [drop]
        realm = "drop.example.com"
        listen = "127.0.0.1:0"
        data_dir = "{drop}"
        [drop.admission]
        open = true
        "#,
        data = data.display(),
        genesis = hex(&log.genesis_hash()),
        founder = laptop.node_id(),
        drop = dir.path().join("drop").display(),
    );
    let config = Config::parse(&text).unwrap();
    let running = start(&config, Clocks::system()).await.unwrap();
    #[cfg(unix)]
    {
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(&data.join(batond::key::KEY_FILE)), 0o600);
        assert_eq!(mode(&data.join(batond::STATE_FILE)), 0o600);
    }
    let server = running.node;

    let link = Arc::new(
        IrohLink::bind(&laptop, Arc::new(PinnedKeys::new([server])), loopback())
            .await
            .unwrap(),
    );
    Link::add_hint(
        &*link,
        &server,
        PeerHint {
            direct: running.addrs.clone(),
            relay: None,
        },
    )
    .unwrap();
    let groups = GroupClient::connect(link.clone(), server, ClientConfig::default())
        .await
        .unwrap();
    groups.push(&log.entries()[0]).await.unwrap();
    let blind = Identity::generate();
    let e = log
        .append(
            &laptop,
            Op::CertifyNode {
                cert: baton_group::NodeCert::new(
                    &owner,
                    &blind,
                    KemSecret::generate().public(),
                    NodeClass::Blind,
                    now.plus_ms(86_400_000),
                ),
            },
            now,
        )
        .unwrap();
    groups.push(&e).await.unwrap();
    let synced = groups
        .sync(
            &log.state().group().clone(),
            log.genesis_hash(),
            None,
            Timestamp::now(),
        )
        .await
        .unwrap();
    assert_eq!(synced.head_hash(), log.head_hash());

    let client = LeaseClient::connect(link.clone(), server, Default::default())
        .await
        .unwrap();
    let me = NodeProfile {
        node: laptop.node_id(),
        class: NodeClass::Desktop,
        weight: 1,
        can_run: true,
    };
    let g = GroupId::new("family").unwrap();
    RemoteLiveness::new(client.clone())
        .heartbeat(&g, &me, Timestamp(0))
        .await
        .unwrap();
    assert!(
        RemoteLeases::new(client)
            .acquire(&g, &LeaseKey::new("nothing-here").unwrap(), &me)
            .await
            .is_err(),
        "no resource, no lease"
    );

    let url = url::Url::parse(&format!("http://{}", running.drop_addr.unwrap())).unwrap();
    let mb = baton_mailbox_drop::connect(
        &url,
        "drop.example.com",
        baton_drop::system_clock(),
        &baton_mailbox_drop::ClientConfig::default(),
    )
    .await
    .unwrap();
    let (reader, writer) = (BoxKey::generate(), BoxKey::generate());
    let id = BoxId::of_reader(&reader.public());
    mb.create(
        &id,
        &BoxPolicy {
            max_bytes: 1 << 20,
            max_messages: 1000,
            ttl_ms: 24 * 3600 * 1000,
            ..BoxPolicy::new(reader.public(), vec![writer.public()])
        },
        &reader,
        &Admission::None,
    )
    .await
    .unwrap();
    mb.put(&id, &writer, Bytes::from_static(b"sealed"))
        .await
        .unwrap();
    let got = mb
        .take(&id, &reader, None, 10, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(&got[0].bytes[..], b"sealed");

    running.stop().await;
    link.close().await;

    let again = start(&config, Clocks::system()).await.unwrap();
    assert_eq!(again.node, server, "the node key is kept");
    again.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_cannot_reach_batond_and_bad_setups_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("batond");
    let text = format!(
        "data_dir = \"{}\"\n[[group]]\nid = \"family\"\ngenesis = \"{}\"\n[iroh]\nbind = [\"127.0.0.1:0\"]",
        data.display(),
        "11".repeat(32)
    );
    let config = Config::parse(&text).unwrap();
    let running = start(&config, Clocks::system()).await.unwrap();
    let stranger = Identity::generate();
    let link = Arc::new(
        IrohLink::bind(
            &stranger,
            Arc::new(PinnedKeys::new([running.node])),
            loopback(),
        )
        .await
        .unwrap(),
    );
    Link::add_hint(
        &*link,
        &running.node,
        PeerHint {
            direct: running.addrs.clone(),
            relay: None,
        },
    )
    .unwrap();
    assert!(matches!(
        GroupClient::connect(link.clone(), running.node, ClientConfig::default()).await,
        Err(RemoteError::Unavailable)
    ));
    link.close().await;
    running.stop().await;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key = data.join(batond::key::KEY_FILE);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(start(&config, Clocks::system()).await.is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
