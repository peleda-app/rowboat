//! The conformance suites every [`NodeApi`] runs.
//!
//! ```ignore
//! #[tokio::test]
//! async fn conformance() {
//!     let node = test_node().await;
//!     rowboat_api::testing::validation(&*node.api()).await;
//!     let account = node_with_mail(&node).await;
//!     rowboat_api::testing::seeded(&*node.api(), &account).await;
//! }
//! ```

use std::collections::BTreeSet;

use crate::*;

const CANARY: &str = "canary-7f3a";

fn unknown_account() -> AccountId {
    AccountId::new(format!("a{}", "q".repeat(26))).unwrap()
}

fn unknown_message() -> MessageId {
    MessageId::new("0".repeat(64)).unwrap()
}

fn assert_kind(result: Result<impl std::fmt::Debug, NodeError>, kind: NodeError, what: &str) {
    match result {
        Err(e) => {
            assert_eq!(e, kind, "{what}");
            assert!(
                !e.to_string().contains(CANARY),
                "{what}: error carries input"
            );
            assert!(
                !format!("{e:?}").contains(CANARY),
                "{what}: error carries input"
            );
        }
        Ok(v) => panic!("{what}: expected {kind:?}, got {v:?}"),
    }
}

fn query(scope: Scope, limit: u32, cursor: Option<Cursor>) -> ListQuery {
    ListQuery {
        scope,
        unread_only: false,
        cursor,
        limit,
    }
}

/// Every operation's validation and its answers for things that do not exist. Needs no
/// accounts; changes nothing.
pub async fn validation(api: &dyn NodeApi) {
    let info = api.node_info().await.unwrap();
    assert!(!info.node_id.is_empty() && !info.group_id.is_empty());

    let ghost = unknown_account();
    let msg = unknown_message();
    assert_kind(
        api.list_mailboxes(&ghost).await,
        NodeError::NotFound,
        "mailboxes",
    );
    assert_kind(
        api.get_thread(&ghost, ThreadId::new(1).unwrap()).await,
        NodeError::NotFound,
        "thread",
    );
    assert_kind(
        api.get_message(&ghost, &msg).await,
        NodeError::NotFound,
        "message",
    );
    assert_kind(
        api.message_raw(&ghost, &msg).await,
        NodeError::NotFound,
        "raw",
    );
    assert_kind(
        api.update_account(&ghost, AccountPatch::default()).await,
        NodeError::NotFound,
        "update",
    );
    assert_kind(
        api.remove_account(&ghost).await,
        NodeError::NotFound,
        "remove",
    );
    assert_kind(
        api.sync_now(Some(&ghost)).await,
        NodeError::NotFound,
        "sync",
    );
    assert_kind(
        api.update_password(&ghost, Secret::from_text(CANARY)).await,
        NodeError::NotFound,
        "password",
    );
    assert_kind(
        api.cancel_send(
            &ghost,
            &CommandId::new("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap(),
        )
        .await,
        NodeError::NotFound,
        "cancel",
    );
    assert_kind(
        api.get_draft(&DraftId::new("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap())
            .await,
        NodeError::NotFound,
        "draft",
    );
    assert!(
        !api.delete_draft(&DraftId::new("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap())
            .await
            .unwrap()
    );

    for limit in [0, MAX_PAGE + 1] {
        assert_kind(
            api.list_messages(query(Scope::All { account: None }, limit, None))
                .await,
            NodeError::InvalidInput,
            "limit",
        );
        assert_kind(
            api.list_threads(query(Scope::All { account: None }, limit, None))
                .await,
            NodeError::InvalidInput,
            "thread limit",
        );
    }
    assert_kind(
        api.list_messages(query(
            Scope::All { account: None },
            10,
            Some(Cursor::new(format!("c1.{CANARY}")).unwrap()),
        ))
        .await,
        NodeError::InvalidInput,
        "forged cursor",
    );
    assert_kind(
        api.list_messages(query(
            Scope::All {
                account: Some(ghost.clone()),
            },
            10,
            None,
        ))
        .await,
        NodeError::NotFound,
        "unknown account scope",
    );
    let empty = api
        .list_messages(query(Scope::All { account: None }, 10, None))
        .await
        .unwrap();
    assert!(empty.next.is_none() || !empty.items.is_empty());

    let refs = |n: usize| {
        Targets(
            (0..n)
                .map(|i| MessageRef {
                    account: ghost.clone(),
                    message: MessageId::new(format!("{i:064x}")).unwrap(),
                })
                .collect(),
        )
    };
    assert_kind(
        api.set_read(refs(0), true).await,
        NodeError::InvalidInput,
        "no targets",
    );
    assert_kind(
        api.set_read(refs(MAX_TARGETS + 1), true).await,
        NodeError::InvalidInput,
        "too many targets",
    );
    assert_kind(
        api.set_flagged(refs(1), true).await,
        NodeError::NotFound,
        "targets of an unknown account",
    );

    let search = |text: &str| SearchQuery {
        account: None,
        text: text.into(),
        filter: SearchFilter::default(),
        limit: 10,
    };
    assert_kind(
        api.search(search(" ")).await,
        NodeError::InvalidInput,
        "empty search",
    );
    assert!(api.search(search("\"unbalanced OR (")).await.is_ok());
    assert_kind(
        api.suggest_addresses("", 5).await,
        NodeError::InvalidInput,
        "empty prefix",
    );
    assert_kind(
        api.suggest_addresses("pa", MAX_SUGGESTIONS + 1).await,
        NodeError::InvalidInput,
        "suggest limit",
    );

    let draft = Draft {
        id: None,
        account: ghost.clone(),
        to: vec![],
        cc: vec![],
        bcc: vec![],
        subject: format!("{CANARY}\r\nBcc: x@example.net"),
        text: String::new(),
        reply: None,
        attachments: vec![],
    };
    assert_kind(
        api.save_draft(draft.clone()).await,
        NodeError::InvalidInput,
        "draft header",
    );
    assert_kind(
        api.send(draft).await,
        NodeError::InvalidInput,
        "send without recipients",
    );

    let address = EmailAddress::new("pat@example.com").unwrap();
    assert_kind(
        api.knows_address(&ghost, &address).await,
        NodeError::NotFound,
        "knows",
    );
    assert!(api.outbox().await.is_ok());

    group(api, &info).await;
}

async fn group(api: &dyn NodeApi, info: &NodeInfo) {
    let canary_code = format!("peleda-pair:{CANARY}\n");
    let long = "A".repeat(group::MAX_PAIRING_TEXT + 1);
    for bad in ["", "   ", canary_code.as_str(), long.as_str()] {
        assert_kind(
            api.accept_invite(bad, None).await,
            NodeError::InvalidInput,
            "pairing code",
        );
    }
    assert_kind(
        api.accept_invite("peleda-pair:!!!!", None).await,
        NodeError::InvalidInput,
        "undecodable QR",
    );
    assert_kind(
        api.accept_invite("7K-Q2M9-XA3B", None).await,
        NodeError::InvalidInput,
        "a short code needs its address",
    );
    assert_kind(
        api.accept_invite("7K-Q2M9-XA3B", Some(CANARY)).await,
        NodeError::InvalidInput,
        "a bad address",
    );
    assert_kind(
        api.confirm_pairing("0123456789abcdef", true).await,
        NodeError::NotFound,
        "nothing waits",
    );
    assert_kind(
        api.confirm_pairing(CANARY, true).await,
        NodeError::InvalidInput,
        "pairing id",
    );
    assert_kind(
        api.cancel_invite("0123456789abcdef").await,
        NodeError::NotFound,
        "unknown invite",
    );
    assert_kind(
        api.revoke_node(CANARY).await,
        NodeError::InvalidInput,
        "node id",
    );
    assert_kind(
        api.revoke_node(&info.node_id).await,
        NodeError::InvalidInput,
        "revoking itself",
    );
    assert_kind(
        api.revoke_node(&"a".repeat(52)).await,
        NodeError::NotFound,
        "a node the group never had",
    );
    for bad in ["", canary_code.as_str(), "peleda-pair:!!!!", long.as_str()] {
        assert_kind(
            api.inspect_invite(bad, None).await,
            NodeError::InvalidInput,
            "inspected code",
        );
        assert_kind(
            api.adopt_server(bad, None, &[]).await,
            NodeError::InvalidInput,
            "adoption code",
        );
    }
    assert_kind(
        api.grant_to_server(CANARY, &[]).await,
        NodeError::InvalidInput,
        "server id",
    );
    assert_kind(
        api.grant_to_server(&"a".repeat(52), &[]).await,
        NodeError::NotFound,
        "a server the group never had",
    );
    assert_kind(
        api.rename_node(CANARY, Some("name")).await,
        NodeError::InvalidInput,
        "renamed node id",
    );
    for bad in ["", " ", "a\nb", &"a".repeat(group::MAX_NODE_LABEL + 1)] {
        assert_kind(
            api.rename_node(&info.node_id, Some(bad)).await,
            NodeError::InvalidInput,
            "node name",
        );
    }
    assert_kind(
        api.rename_node(&"a".repeat(52), Some("name")).await,
        NodeError::NotFound,
        "naming a node the group never had",
    );
    api.rename_node(&info.node_id, Some("Suite")).await.unwrap();
    let named = api.list_nodes().await.unwrap();
    assert_eq!(
        named
            .iter()
            .find(|n| n.this_node)
            .and_then(|n| n.label.as_deref()),
        Some("Suite")
    );
    api.rename_node(&info.node_id, None).await.unwrap();
    let status = api.group_status().await.unwrap();
    let mut accounts: Vec<_> = status.leaders.iter().map(|l| l.account.clone()).collect();
    accounts.sort();
    accounts.dedup();
    assert_eq!(accounts.len(), status.leaders.len(), "each account once");

    let nodes = api.list_nodes().await.unwrap();
    let mine: Vec<_> = nodes.iter().filter(|n| n.this_node).collect();
    assert_eq!(mine.len(), 1, "exactly one node is this one");
    assert_eq!(mine[0].node_id, info.node_id);
    assert!(mine[0].counts && !mine[0].revoked);
    let mut sorted = nodes.clone();
    sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    assert_eq!(nodes, sorted, "sorted by node id");
}

/// Paging stability and pending changes on an account that holds at least three messages in
/// some mailbox. Marks one message read and unread again.
pub async fn seeded(api: &dyn NodeApi, account: &AccountId) {
    let all = api
        .list_messages(query(
            Scope::All {
                account: Some(account.clone()),
            },
            MAX_PAGE,
            None,
        ))
        .await
        .unwrap();
    assert!(all.items.len() >= 3, "seed at least three messages");
    assert!(
        all.items
            .windows(2)
            .all(|w| (w[0].sort_date, &w[0].id) >= (w[1].sort_date, &w[1].id)),
        "newest first"
    );

    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let page = api
            .list_messages(query(
                Scope::All {
                    account: Some(account.clone()),
                },
                1,
                cursor,
            ))
            .await
            .unwrap();
        assert!(page.items.len() <= 1);
        seen.extend(page.items.iter().map(|e| e.id.clone()));
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
        assert!(seen.len() <= all.items.len(), "paging repeats rows");
    }
    let unique: BTreeSet<_> = seen.iter().collect();
    assert_eq!(unique.len(), seen.len(), "paging repeats rows");
    assert_eq!(seen.len(), all.items.len(), "paging skips rows");

    let threads = api
        .list_threads(query(
            Scope::All {
                account: Some(account.clone()),
            },
            MAX_PAGE,
            None,
        ))
        .await
        .unwrap();
    assert!(!threads.items.is_empty());
    let detail = api.get_thread(account, threads.items[0].id).await.unwrap();
    assert!(!detail.messages.is_empty());

    let target = all.items[0].clone();
    let one = Targets(vec![MessageRef {
        account: account.clone(),
        message: target.id.clone(),
    }]);
    let queued = api.set_read(one.clone(), target.unread).await.unwrap();
    assert!(!queued.commands.is_empty() && queued.skipped.is_empty());
    let after = api.get_message(account, &target.id).await.unwrap();
    assert_eq!(
        after.envelope.unread, !target.unread,
        "pending change shows at once"
    );
    api.set_read(one, !target.unread).await.unwrap();
    let back = api.get_message(account, &target.id).await.unwrap();
    assert_eq!(back.envelope.unread, target.unread);

    let ghost_message = Targets(vec![MessageRef {
        account: account.clone(),
        message: unknown_message(),
    }]);
    let skipped = api.set_flagged(ghost_message, true).await.unwrap();
    assert!(skipped.commands.is_empty());
    assert_eq!(skipped.skipped.len(), 1);

    let raw = api.message_raw(account, &target.id).await.unwrap();
    assert!(!raw.is_empty());
}
