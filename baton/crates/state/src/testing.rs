//! Conformance suite for [`StateStore`].

use std::sync::Arc;

use baton_core::GroupId;
use bytes::Bytes;

use crate::{Expect, MAX_SECRET, MAX_VALUE, RecordName, SecretStore, StateError, StateStore};

fn name(s: &str) -> RecordName {
    RecordName::new(s).unwrap()
}

/// The [`StateStore`] contract, including concurrent writers. Uses groups starting with
/// `conf-state`.
pub async fn state(store: Arc<dyn StateStore>) {
    let g = GroupId::new("conf-state").unwrap();
    let other = GroupId::new("conf-state-other").unwrap();
    let a = name("rec/a");

    assert!(store.get(&g, &a).await.unwrap().is_none());
    let v1 = store
        .put(&g, &a, Bytes::from_static(b"one"), Expect::Absent)
        .await
        .unwrap();
    assert!(matches!(
        store
            .put(&g, &a, Bytes::from_static(b"x"), Expect::Absent)
            .await,
        Err(StateError::Conflict)
    ));
    let (value, version) = store.get(&g, &a).await.unwrap().unwrap();
    assert_eq!(&value[..], b"one");
    assert_eq!(version, v1);

    let v2 = store
        .put(
            &g,
            &a,
            Bytes::from_static(b"two"),
            Expect::Version(v1.clone()),
        )
        .await
        .unwrap();
    assert_ne!(v1, v2, "every write gets a new version");
    assert!(
        matches!(
            store
                .put(
                    &g,
                    &a,
                    Bytes::from_static(b"stale"),
                    Expect::Version(v1.clone())
                )
                .await,
            Err(StateError::Conflict)
        ),
        "a stale version cannot overwrite"
    );
    assert_eq!(&store.get(&g, &a).await.unwrap().unwrap().0[..], b"two");
    assert!(matches!(
        store
            .put(
                &g,
                &name("rec/missing"),
                Bytes::new(),
                Expect::Version(v2.clone())
            )
            .await,
        Err(StateError::Conflict)
    ));

    assert!(
        store.get(&other, &a).await.unwrap().is_none(),
        "groups never mix"
    );
    store
        .put(&other, &a, Bytes::from_static(b"other"), Expect::Absent)
        .await
        .unwrap();
    assert_eq!(&store.get(&g, &a).await.unwrap().unwrap().0[..], b"two");

    assert!(matches!(
        store
            .put(&g, &a, Bytes::from(vec![0u8; MAX_VALUE + 1]), Expect::Any)
            .await,
        Err(StateError::TooLarge)
    ));
    assert_eq!(
        &store.get(&g, &a).await.unwrap().unwrap().0[..],
        b"two",
        "a refused value writes nothing"
    );
    store
        .put(&g, &a, Bytes::from(vec![7u8; MAX_VALUE]), Expect::Any)
        .await
        .unwrap();

    let (_, current) = store.get(&g, &a).await.unwrap().unwrap();
    assert!(matches!(
        store.delete(&g, &a, Expect::Version(v2.clone())).await,
        Err(StateError::Conflict)
    ));
    store
        .delete(&g, &a, Expect::Version(current))
        .await
        .unwrap();
    assert!(store.get(&g, &a).await.unwrap().is_none());
    store.delete(&g, &a, Expect::Any).await.unwrap();
    let v3 = store
        .put(&g, &a, Bytes::from_static(b"again"), Expect::Absent)
        .await
        .unwrap();
    assert_ne!(v3, v1, "a recreated record never reuses a version");
    assert_ne!(v3, v2);

    for n in ["list/b", "list/a", "list/c/d", "lists/x", "list"] {
        store
            .put(&g, &name(n), Bytes::new(), Expect::Any)
            .await
            .unwrap();
    }
    store
        .put(&other, &name("list/zz"), Bytes::new(), Expect::Any)
        .await
        .unwrap();
    let prefix = name("list");
    let all: Vec<String> = store
        .list(&g, &prefix, None, 100)
        .await
        .unwrap()
        .iter()
        .map(|n| n.as_str().to_owned())
        .collect();
    assert_eq!(all, ["list/a", "list/b", "list/c/d"]);
    let page = store.list(&g, &prefix, None, 2).await.unwrap();
    assert_eq!(page.len(), 2);
    let rest = store.list(&g, &prefix, Some(&page[1]), 100).await.unwrap();
    assert_eq!(
        rest.iter().map(|n| n.as_str()).collect::<Vec<_>>(),
        ["list/c/d"]
    );
    let from_gap = store
        .list(&g, &prefix, Some(&name("list/aa")), 100)
        .await
        .unwrap();
    assert_eq!(
        from_gap.iter().map(|n| n.as_str()).collect::<Vec<_>>(),
        ["list/b", "list/c/d"],
        "paging works from a name that does not exist"
    );
    assert!(
        store
            .list(&g, &prefix, Some(&name("list/zz")), 100)
            .await
            .unwrap()
            .is_empty()
    );

    concurrent_creates(store.clone(), &g).await;
    no_lost_updates(store, &g).await;
}

async fn concurrent_creates(store: Arc<dyn StateStore>, g: &GroupId) {
    let n = name("race/create");
    let mut tasks = Vec::new();
    for i in 0..32u8 {
        let store = store.clone();
        let g = g.clone();
        let n = n.clone();
        tasks.push(tokio::spawn(async move {
            store
                .put(&g, &n, Bytes::from(vec![i]), Expect::Absent)
                .await
        }));
    }
    let mut winners = Vec::new();
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => winners.push(()),
            Err(StateError::Conflict) => {}
            Err(e) => panic!("unexpected error {e}"),
        }
    }
    assert_eq!(winners.len(), 1, "exactly one concurrent create wins");
}

async fn no_lost_updates(store: Arc<dyn StateStore>, g: &GroupId) {
    let n = name("race/counter");
    store
        .put(g, &n, Bytes::from(0u64.to_be_bytes().to_vec()), Expect::Any)
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let store = store.clone();
        let g = g.clone();
        let n = n.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let (v, ver) = store.get(&g, &n).await.unwrap().unwrap();
                let x = u64::from_be_bytes(v[..8].try_into().unwrap()) + 1;
                match store
                    .put(
                        &g,
                        &n,
                        Bytes::from(x.to_be_bytes().to_vec()),
                        Expect::Version(ver),
                    )
                    .await
                {
                    Ok(_) => break,
                    Err(StateError::Conflict) => tokio::task::yield_now().await,
                    Err(e) => panic!("unexpected error {e}"),
                }
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let (v, _) = store.get(g, &n).await.unwrap().unwrap();
    assert_eq!(
        u64::from_be_bytes(v[..8].try_into().unwrap()),
        32,
        "compare-and-swap loses no update"
    );
}

/// The [`SecretStore`] contract. Uses names starting with `conf-secret`.
pub async fn secrets(store: Arc<dyn SecretStore>) {
    use zeroize::Zeroizing;
    let a = name("conf-secret/a");
    assert!(store.get(&a).await.unwrap().is_none());
    store
        .put(&a, Zeroizing::new(b"one".to_vec()))
        .await
        .unwrap();
    assert_eq!(&store.get(&a).await.unwrap().unwrap()[..], b"one");
    store
        .put(&a, Zeroizing::new(b"two".to_vec()))
        .await
        .unwrap();
    assert_eq!(&store.get(&a).await.unwrap().unwrap()[..], b"two");
    assert!(matches!(
        store.put(&a, Zeroizing::new(vec![0; MAX_SECRET + 1])).await,
        Err(StateError::TooLarge)
    ));
    assert_eq!(
        &store.get(&a).await.unwrap().unwrap()[..],
        b"two",
        "a refused secret stores nothing"
    );
    store
        .put(&a, Zeroizing::new(vec![1; MAX_SECRET]))
        .await
        .unwrap();
    store.delete(&a).await.unwrap();
    assert!(store.get(&a).await.unwrap().is_none());
    store.delete(&a).await.unwrap();
}
