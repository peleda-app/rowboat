//! The server in process, over `rowboat-endpoint-memory` with Skein's fake providers: a desktop
//! adopts a tenant and the tenant takes its account over; a restart keeps the binding and the
//! leases; tenants never share storage or keys; a bound tenant refuses a second adoption.

mod common;

use std::sync::Arc;

use rowboat::host::Host;
use rowboat::tenant::{TenantError, TenantId};
use rowboat_api::*;
use rowboat_endpoint::Endpoints;
use rowboat_endpoint_memory::MemoryEndpoints;
use rowboat_node::testing::FakeProviders;

use common::*;

fn files_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn mentions(dir: &std::path::Path, needle: &str) -> bool {
    files_under(dir).iter().any(|p| {
        p.to_string_lossy().contains(needle)
            || std::fs::read(p)
                .map(|b| b.windows(needle.len()).any(|w| w == needle.as_bytes()))
                .unwrap_or(false)
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_desktop_adopts_a_tenant_that_then_restarts_with_its_binding_and_leases() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    seed(&fakes, "ada", 0, 3, "Note").await;
    let desktop = desktop(&fakes, &endpoints).await;
    let account = add(&desktop, "ada").await;
    shows(&*desktop.node.api(), &account, 3).await;

    let test_host = TestHost::new(&endpoints, &fakes);
    let host = test_host.open();
    assert!(
        matches!(
            Host::open(test_host.tenants.clone(), None, std::time::Duration::ZERO),
            Err(rowboat::host::HostError::Busy)
        ),
        "one serve per data directory"
    );
    let tenant = first_run(&host, &desktop).await;
    let layout = &test_host.tenants.layout;
    let binding = layout.binding(&tenant).unwrap().expect("bound");
    let server = host.node(&tenant).await.unwrap();
    assert_eq!(
        binding.group,
        desktop.node.group_id(),
        "bound to the adopting group"
    );
    assert_eq!(binding.node, server.node_id());
    assert_eq!(
        binding.genesis_bytes(),
        Some(server.genesis_hash().unwrap())
    );
    assert!(server.adopted());

    leads(&host, &tenant, &account).await;
    shows(&*server.api(), &account, 3).await;
    seed(&fakes, "ada", 3, 2, "Note").await;
    shows(&*desktop.node.api(), &account, 5).await;
    let (_, fence, _) = server.head_for_tests(&account).await;

    host.rescan().await;
    let status: rowboat::host::Status =
        serde_json::from_slice(&std::fs::read(layout.status_file()).unwrap()).unwrap();
    let row = &status.tenants[0];
    assert_eq!(
        (row.state.as_str(), row.accounts, row.leading, row.peers),
        ("running", 1, 1, 1)
    );
    assert_eq!(row.group.as_deref(), Some(desktop.node.group_id()));

    let binding_bytes = std::fs::read(layout.tenant(&tenant).join("binding.json")).unwrap();
    let node_id = server.node_id().to_owned();
    drop(server);
    let handed = host.shutdown().await;
    assert_eq!(
        handed,
        vec![tenant.clone()],
        "the desktop took the account back before the server stopped"
    );
    assert!(
        !layout.view(&tenant).exists(),
        "a stopped tenant's mail database is deleted"
    );
    drop(host);

    let host = test_host.open();
    host.rescan().await;
    assert_eq!(host.running().await, vec![tenant.clone()]);
    let server = host.node(&tenant).await.unwrap();
    assert_eq!(server.node_id(), node_id, "the same identity");
    assert_eq!(server.group_id(), desktop.node.group_id());
    assert_eq!(
        std::fs::read(layout.tenant(&tenant).join("binding.json")).unwrap(),
        binding_bytes,
        "the binding is untouched"
    );
    leads(&host, &tenant, &account).await;
    until("the desktop to let go", || async {
        !desktop.node.leads(&account)
    })
    .await;
    let (_, again, _) = server.head_for_tests(&account).await;
    assert!(
        again > fence,
        "the restarted server continues under a higher token"
    );
    seed(&fakes, "ada", 5, 1, "Note").await;
    shows(&*desktop.node.api(), &account, 6).await;
    shows(&*server.api(), &account, 6).await;
    assert_eq!(
        (
            count(&*server.api(), &account).await,
            count(&*desktop.node.api(), &account).await
        ),
        (6, 6),
        "nothing lost or doubled"
    );
    drop(server);
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tenants_never_share_storage_or_keys() {
    log();
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    seed(&fakes, "ada", 0, 2, "Alpha").await;
    seed(&fakes, "bea", 0, 2, "Beta").await;
    let ada = desktop(&fakes, &endpoints).await;
    let bea = desktop(&fakes, &endpoints).await;
    let a_account = add(&ada, "ada").await;
    let b_account = add(&bea, "bea").await;

    let test_host = TestHost::new(&endpoints, &fakes);
    let host = test_host.open();
    let a = first_run(&host, &ada).await;
    let b = first_run(&host, &bea).await;
    assert_ne!(a, b);
    leads(&host, &a, &a_account).await;
    leads(&host, &b, &b_account).await;
    let a_node = host.node(&a).await.unwrap();
    let b_node = host.node(&b).await.unwrap();
    shows(&*a_node.api(), &a_account, 2).await;
    shows(&*b_node.api(), &b_account, 2).await;

    let a_accounts: Vec<AccountId> = a_node
        .api()
        .list_accounts()
        .await
        .unwrap()
        .into_iter()
        .map(|x| x.id)
        .collect();
    assert_eq!(
        a_accounts,
        vec![a_account.clone()],
        "a tenant sees only its group's accounts"
    );
    assert_eq!(
        a_node.api().list_mailboxes(&b_account).await.unwrap_err(),
        NodeError::NotFound,
        "another tenant's account is not there"
    );
    assert!(!a_node.leads(&b_account) && !b_node.leads(&a_account));

    let layout = &test_host.tenants.layout;
    for (dir, other_group, other_account) in [
        (layout.tenant(&a), bea.node.group_id(), b_account.as_str()),
        (layout.tenant(&b), ada.node.group_id(), a_account.as_str()),
    ] {
        assert!(
            !mentions(&dir, other_group),
            "a tenant's directory names no other group"
        );
        assert!(
            !mentions(&dir, other_account),
            "nor another group's account"
        );
    }
    for (tenant, password) in [(&a, PASSWORD), (&b, PASSWORD)] {
        assert!(
            !mentions(&layout.tenant(tenant), password),
            "credentials are sealed at rest"
        );
        assert!(
            !mentions(&layout.tenant(tenant), "Alpha 0"),
            "mail is sealed at rest"
        );
    }
    drop((a_node, b_node));
    host.shutdown().await;
    drop(host);

    let a_keys = layout.keys(&a);
    let b_keys = layout.keys(&b);
    let parked = test_host.dir.path().join("parked");
    std::fs::rename(&a_keys, &parked).unwrap();
    std::fs::rename(&b_keys, &a_keys).unwrap();
    std::fs::rename(&parked, &b_keys).unwrap();
    let record = layout.record(&a).unwrap();
    assert!(
        matches!(
            test_host.tenants.open_node(&record, None, None).await,
            Err(TenantError::Mismatch(_))
        ),
        "one tenant's keys open nothing of another's data"
    );
    let host = test_host.open();
    host.rescan().await;
    assert!(
        host.running().await.is_empty(),
        "swapped tenants do not start"
    );
    let status: rowboat::host::Status =
        serde_json::from_slice(&std::fs::read(layout.status_file()).unwrap()).unwrap();
    assert!(status.tenants.iter().all(|t| t.state == "failed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_tenant_refuses_a_second_adoption() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    let ada = desktop(&fakes, &endpoints).await;
    let mallory = desktop(&fakes, &endpoints).await;
    let test_host = TestHost::new(&endpoints, &fakes);
    let tenants = &test_host.tenants;

    let first = invite(tenants, None, false, &ada).await.unwrap();
    let tenant = first.tenant.clone();
    assert_eq!(first.group, ada.node.group_id());
    assert_eq!(
        invite(tenants, Some(tenant.clone()), false, &mallory)
            .await
            .unwrap_err(),
        TenantError::Bound(tenant.to_string()),
        "a second invite for a bound tenant is refused before anything is shown"
    );
    assert_eq!(
        tenants.layout.binding(&tenant).unwrap(),
        Some(first.clone())
    );

    let host = test_host.open();
    host.rescan().await;
    let server = host.node(&tenant).await.unwrap();
    assert_eq!(
        server.server_invite().await.err(),
        Some(NodeError::Busy),
        "the adopted node itself issues no invite either"
    );
    drop(server);
    host.shutdown().await;
    drop(host);

    let mut forged = first.clone();
    forged.group = mallory.node.group_id().to_owned();
    tenants.layout.write_binding(&forged).unwrap();
    let host = test_host.open();
    host.rescan().await;
    assert!(
        host.running().await.is_empty(),
        "a binding that names another group stops the tenant"
    );
    drop(host);
    let mut forged = first.clone();
    forged.genesis = "ab".repeat(32);
    tenants.layout.write_binding(&forged).unwrap();
    let host = test_host.open();
    host.rescan().await;
    assert!(host.running().await.is_empty(), "so does another genesis");
    drop(host);
    tenants.layout.write_binding(&first).unwrap();

    let rebound = invite(tenants, Some(tenant.clone()), true, &mallory)
        .await
        .unwrap();
    assert_eq!(
        rebound.group,
        mallory.node.group_id(),
        "only the operator's rebind moves it"
    );
    assert_ne!(
        rebound.node, first.node,
        "with a new identity: the old group's data is gone"
    );
    assert!(!tenants.layout.stop_marker(&tenant).exists());
    let host = test_host.open();
    host.rescan().await;
    assert_eq!(host.running().await, vec![tenant]);
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unbound_tenant_does_not_run_and_a_removed_one_is_gone() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    let ada = desktop(&fakes, &endpoints).await;
    let test_host = TestHost::new(&endpoints, &fakes);
    let tenants = &test_host.tenants;
    let idle = tenants
        .layout
        .create(Some(TenantId::parse("idle").unwrap()), 1)
        .unwrap();
    let bound = invite(tenants, None, false, &ada).await.unwrap();
    let host = test_host.open();
    host.rescan().await;
    assert_eq!(host.running().await, vec![bound.tenant.clone()]);
    let rows = tenants.list();
    assert_eq!(
        rows.iter().find(|r| r.id == idle.id).unwrap().state,
        "unbound"
    );

    let remover = {
        let tenants = tenants.clone();
        let id = bound.tenant.clone();
        tokio::spawn(async move {
            tenants
                .remove(&id, std::time::Duration::from_secs(120))
                .await
        })
    };
    until("the stop marker", || async {
        tenants.layout.stop_marker(&bound.tenant).exists()
    })
    .await;
    host.rescan().await;
    within("the removal", remover).await.unwrap().unwrap();
    assert!(host.running().await.is_empty());
    assert!(!tenants.layout.tenant(&bound.tenant).exists());
    assert!(!tenants.layout.keys(&bound.tenant).exists());
    assert_eq!(tenants.layout.ids(), vec![idle.id]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tenant_kept_in_a_bucket_is_sealed_there_and_restarts() {
    log();
    use object_store::{ObjectStore, ObjectStoreExt};
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    seed(&fakes, "ada", 0, 2, "Bucket note").await;
    let ada = desktop(&fakes, &endpoints).await;
    let account = add(&ada, "ada").await;
    let bucket: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let mut test_host = TestHost::new(&endpoints, &fakes);
    let store = bucket.clone();
    test_host.tenants.deps.store = Some(Arc::new(move |id: &TenantId| {
        let objects = skein_storage_s3::S3Objects::with_store(
            store.clone(),
            Some(&format!("prod/tenants/{id}")),
        )
        .map_err(|e| e.to_string())?;
        Ok(Arc::new(objects) as Arc<dyn skein_storage::Objects>)
    }));
    let host = test_host.open();
    let tenant = first_run(&host, &ada).await;
    leads(&host, &tenant, &account).await;
    shows(&*host.node(&tenant).await.unwrap().api(), &account, 2).await;
    host.shutdown().await;
    drop(host);

    let mut keys = Vec::new();
    let mut listing = bucket.list(None);
    while let Some(meta) = futures::StreamExt::next(&mut listing).await {
        keys.push(meta.unwrap().location);
    }
    assert!(!keys.is_empty());
    assert!(
        keys.iter()
            .all(|k| k.as_ref().starts_with(&format!("prod/tenants/{tenant}/")))
    );
    for k in &keys {
        let bytes = bucket.get(k).await.unwrap().bytes().await.unwrap();
        for needle in [PASSWORD.as_bytes(), b"Bucket note", b"ada@example.com"] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "sealed in the bucket"
            );
        }
    }
    let objects_on_disk = files_under(&test_host.tenants.layout.node(&tenant))
        .into_iter()
        .filter(|p| !p.to_string_lossy().contains("lock"))
        .count();
    assert_eq!(objects_on_disk, 0, "the data directory holds only the lock");

    let host = test_host.open();
    host.rescan().await;
    assert_eq!(
        host.running().await,
        vec![tenant.clone()],
        "the bucket keeps the binding's node"
    );
    leads(&host, &tenant, &account).await;
    host.shutdown().await;
}

async fn bucket_keys(bucket: &Arc<dyn object_store::ObjectStore>) -> Vec<String> {
    let mut keys = Vec::new();
    let mut listing = bucket.list(None);
    while let Some(meta) = futures::StreamExt::next(&mut listing).await {
        keys.push(meta.unwrap().location.to_string());
    }
    keys
}

/// Regression (security review): a rebind or removal deleted only the tenant's local directories.
/// With a bucket, the sealed objects stayed, and the rebind then found a node record without its
/// keys and failed for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rebinding_or_removing_a_tenant_kept_in_a_bucket_deletes_its_objects() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    let ada = desktop(&fakes, &endpoints).await;
    let bea = desktop(&fakes, &endpoints).await;
    let bucket: Arc<dyn object_store::ObjectStore> =
        Arc::new(object_store::memory::InMemory::new());
    let mut test_host = TestHost::new(&endpoints, &fakes);
    let store = bucket.clone();
    test_host.tenants.deps.store = Some(Arc::new(move |id: &TenantId| {
        let objects = skein_storage_s3::S3Objects::with_store(
            store.clone(),
            Some(&format!("prod/tenants/{id}")),
        )
        .map_err(|e| e.to_string())?;
        Ok(Arc::new(objects) as Arc<dyn skein_storage::Objects>)
    }));
    let tenants = &test_host.tenants;
    let other = invite(tenants, None, false, &bea).await.unwrap();
    let first = invite(tenants, None, false, &ada).await.unwrap();
    let theirs = format!("prod/tenants/{}/", first.tenant);
    let before: Vec<String> = bucket_keys(&bucket)
        .await
        .into_iter()
        .filter(|k| k.starts_with(&theirs))
        .collect();
    assert!(!before.is_empty());

    let rebound = invite(tenants, Some(first.tenant.clone()), true, &bea)
        .await
        .expect("a rebind of a bucket tenant starts over");
    assert_eq!(rebound.tenant, first.tenant);
    assert_ne!(rebound.node, first.node);

    tenants
        .remove(&first.tenant, std::time::Duration::from_secs(5))
        .await
        .unwrap();
    let left = bucket_keys(&bucket).await;
    assert!(
        left.iter().all(|k| !k.starts_with(&theirs)),
        "a removed tenant leaves nothing in the bucket: {left:?}"
    );
    assert!(
        left.iter()
            .any(|k| k.starts_with(&format!("prod/tenants/{}/", other.tenant))),
        "another tenant's objects stay"
    );
}

/// Regression: a tenant whose accounts were not taken over within the hand-back wait sends no
/// leaving notice (its devices would repeat what it may have started); the desktop takes the
/// account over by silence instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unfinished_hand_back_sends_no_leaving_notice() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    seed(&fakes, "ada", 0, 2, "Note").await;
    let desktop = desktop(&fakes, &endpoints).await;
    let account = add(&desktop, "ada").await;
    shows(&*desktop.node.api(), &account, 2).await;

    let test_host = TestHost::new(&endpoints, &fakes);
    let host =
        Arc::new(Host::open(test_host.tenants.clone(), None, std::time::Duration::ZERO).unwrap());
    let tenant = first_run(&host, &desktop).await;
    leads(&host, &tenant, &account).await;
    until("the desktop to let go", || async {
        !desktop.node.leads(&account)
    })
    .await;

    let handed = host.shutdown().await;
    assert!(handed.is_empty(), "nobody took the account within no wait");
    until("the desktop to take the account over", || async {
        desktop.node.leads(&account)
    })
    .await;
    assert_eq!(
        desktop.node.fallback_for_tests(),
        Some("silence"),
        "no notice: the takeover delay, not a leaving notice, started the fallback"
    );
}
