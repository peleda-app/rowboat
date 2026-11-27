use std::sync::Arc;

use baton_core::{GroupId, LeaseKey, NodeId, Timestamp};
use baton_group::NodeCert;
use baton_identity::Identity;
use baton_keys::{KemSecret, RecoveryRoot};
use baton_lease::{NodeClass, NodeProfile};
use baton_lease_server::Authorize;
use baton_state_memory::MemoryState;
use rowboat_group::{DAY_MS, Membership, NodeKeys, Now, account_resource};

use super::GroupAuthority;

const T0: i64 = 1_800_000_000_000;

fn now() -> Now {
    Arc::new(|| Timestamp(T0))
}

fn keys(member: Option<&Identity>) -> NodeKeys {
    NodeKeys {
        identity: Identity::generate(),
        kem: KemSecret::generate(),
        member: member.cloned(),
    }
}

fn profile(key: &Identity, class: NodeClass) -> NodeProfile {
    NodeProfile {
        node: NodeId::new(key.public().node_id().to_string()).unwrap(),
        class,
        weight: 1,
        can_run: true,
    }
}

#[tokio::test]
async fn the_lease_server_admits_only_what_the_group_log_grants() {
    let member = Identity::generate();
    let group = GroupId::new("gleasegroup").unwrap();
    let founder = Arc::new(
        Membership::found(
            Arc::new(MemoryState::new()),
            group.clone(),
            keys(Some(&member)),
            RecoveryRoot::generate().public(),
            RecoveryRoot::generate().public(),
            NodeClass::Desktop,
            Timestamp(T0 + 400 * DAY_MS),
            now(),
        )
        .await
        .unwrap(),
    );
    let led = format!("a{}", "k".repeat(26));
    let kept = format!("a{}", "m".repeat(26));
    for a in [&led, &kept] {
        founder
            .ensure_resource(&account_resource(a).unwrap(), &[])
            .await
            .unwrap();
    }
    let certify = |class| {
        let k = keys(Some(&member));
        let cert = NodeCert::new(
            &member,
            &k.identity,
            k.kem.public(),
            class,
            Timestamp(T0 + 90 * DAY_MS),
        );
        (k, cert)
    };
    let (server, cert) = certify(NodeClass::Server);
    founder.certify(cert).await.unwrap();
    founder
        .grant_server(
            &server.identity.public(),
            &[account_resource(&led).unwrap()],
        )
        .await
        .unwrap();
    let (desktop, cert) = certify(NodeClass::Desktop);
    founder.certify(cert).await.unwrap();
    let authority = GroupAuthority {
        membership: founder.clone(),
        group: group.clone(),
    };
    let s = server.identity.public();
    let d = desktop.identity.public();
    let key = |a: &str| LeaseKey::new(a).unwrap();

    assert!(authority.lease(&s, &group, &key(&led)));
    assert!(
        !authority.lease(&s, &group, &key(&kept)),
        "a node without lead on the account may not take its lease"
    );
    assert!(authority.lease(&d, &group, &key(&kept)));
    assert!(!authority.lease(&d, &group, &key("not-an-account")));
    assert!(authority.profile(&s, &group, &profile(&server.identity, NodeClass::Server)));
    assert!(
        !authority.profile(&d, &group, &profile(&desktop.identity, NodeClass::Server)),
        "a desktop cannot announce a server's priority"
    );
    let other = GroupId::new("gothergroup").unwrap();
    assert!(!authority.member(&d, &other), "another group");
    let stranger = Identity::generate().public();
    assert!(!authority.member(&stranger, &group));
    assert!(!authority.lease(&stranger, &group, &key(&led)));

    founder.revoke(&d).await.unwrap();
    assert!(!authority.member(&d, &group));
    assert!(
        !authority.lease(&d, &group, &key(&kept)),
        "a revoked node keeps no lease: renewing is taking"
    );
}
