#![no_main]

use std::sync::OnceLock;

use baton_core::GroupId;
use baton_identity::{Identity, Roster, RosterHandle};
use baton_mesh::frame::Opener;
use libfuzzer_sys::fuzz_target;

struct Fixture {
    member: Identity,
    opener: Opener,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let a = Identity::from_secret_bytes(&[1u8; 32]);
        let b = Identity::from_secret_bytes(&[2u8; 32]);
        let roster = Roster::genesis(&a, GroupId::new("g").unwrap())
            .with_member(&a, b.public())
            .unwrap();
        Fixture {
            member: a,
            opener: Opener::new(b.node_id(), RosterHandle::new(roster).unwrap()),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    if let Ok(env) = f.opener.open(data, None) {
        assert_eq!(
            env.from,
            f.member.node_id(),
            "only a member's genuine frame can open"
        );
    }
    let _ = f.opener.open(data, Some(&f.member.public()));
});
