use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use rowboat_api::cursor::{self, Position};
use rowboat_api::*;
use rowboat_discover::Domain;
use skein_core::{BlobHash, Command, CommandBody, Flags, ItemRef, SendEnvelope, Timestamp};
use skein_engine::{MAX_ITEMS, SubmitError, cancel_command, submit_command, wake_topic};
use skein_storage::{Expect, ObjectKey, StorageError};
use skein_view::{Filter, Store};

use crate::boot::Core;
use crate::errors;
use crate::overlay::Expect as Change;
use crate::providers;
use crate::random;
use crate::records::{self, AccountMeta, DraftRecord};

pub(crate) struct Api(pub Arc<Core>);

fn meta_path(account: &AccountId) -> String {
    format!("rowboat/accounts/{account}")
}

fn draft_key(id: &str) -> ObjectKey {
    ObjectKey::parse(&format!("system/drafts/{id}")).expect("ULIDs are valid segments")
}

fn skein_id(account: &AccountId) -> Result<skein_core::AccountId, NodeError> {
    skein_core::AccountId::new(account.as_str()).map_err(|_| NodeError::Internal)
}

async fn db<T: Send + 'static>(
    store: &Arc<Store>,
    f: impl FnOnce(&Store) -> Result<T, skein_view::StoreError> + Send + 'static,
) -> Result<T, NodeError> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || f(&store))
        .await
        .map_err(|_| NodeError::Internal)?
        .map_err(errors::view)
}

/// Every account record of the node, removing ones included, by id.
pub(crate) async fn all_metas(core: &Core) -> Result<Vec<AccountMeta>, NodeError> {
    let mut out = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = core
            .storage
            .control
            .list(&core.tenant, "rowboat/accounts", after.as_deref(), 1000)
            .await
            .map_err(errors::storage)?;
        for path in &page {
            if let Some((bytes, _)) = core
                .storage
                .control
                .get(&core.tenant, path)
                .await
                .map_err(errors::storage)?
                && let Ok(meta) = records::decode_account_meta(&bytes)
            {
                out.push(meta);
            }
        }
        if page.len() < 1000 {
            return Ok(out);
        }
        after = page.last().cloned();
    }
}

pub(crate) async fn put_meta(core: &Core, meta: &AccountMeta) -> Result<(), NodeError> {
    core.storage
        .control
        .put(
            &core.tenant,
            &meta_path(&meta.account),
            Bytes::from(records::encode_account_meta(meta)),
            Expect::Any,
        )
        .await
        .map_err(errors::storage)?;
    Ok(())
}

/// The account's record, `None` when missing or unreadable.
pub(crate) async fn meta_of(core: &Core, account: &AccountId) -> Option<AccountMeta> {
    let (bytes, _) = core
        .storage
        .control
        .get(&core.tenant, &meta_path(account))
        .await
        .ok()??;
    records::decode_account_meta(&bytes).ok()
}

pub(crate) async fn delete_meta(core: &Core, account: &AccountId) -> Result<(), NodeError> {
    core.storage
        .control
        .delete(&core.tenant, &meta_path(account), Expect::Any)
        .await
        .map_err(errors::storage)
}

async fn draft_records(core: &Core) -> Result<Vec<DraftRecord>, NodeError> {
    let prefix = ObjectKey::parse("system/drafts").expect("constant");
    let keys = core
        .objects
        .list(&prefix, None, MAX_DRAFTS * 2)
        .await
        .map_err(errors::storage)?;
    let mut out = Vec::new();
    for key in keys {
        if let Some((bytes, _)) = core.objects.get(&key).await.map_err(errors::storage)?
            && let Ok(r) = records::decode_draft_record(&bytes)
        {
            out.push(r);
        }
    }
    Ok(out)
}

async fn put_draft(core: &Core, record: &DraftRecord) -> Result<(), NodeError> {
    let id = record.draft.id.as_ref().ok_or(NodeError::Internal)?;
    core.objects
        .put(
            &draft_key(id.as_str()),
            Bytes::from(records::encode_draft_record(record)),
            Expect::Any,
        )
        .await
        .map_err(errors::storage)?;
    Ok(())
}

/// A send settled: its draft goes away when sent, comes back when it failed.
pub(crate) async fn settle_draft(core: &Core, command: &str, sent: bool) -> Result<(), NodeError> {
    for mut r in draft_records(core).await? {
        if r.sending.as_deref() != Some(command) {
            continue;
        }
        let id = r.draft.id.clone().ok_or(NodeError::Internal)?;
        if sent {
            core.objects
                .delete(&draft_key(id.as_str()), Expect::Any)
                .await
                .map_err(errors::storage)?;
        } else {
            r.sending = None;
            put_draft(core, &r).await?;
        }
    }
    Ok(())
}

fn submit_error(e: SubmitError) -> NodeError {
    match e {
        SubmitError::Invalid { .. } | SubmitError::BlobMissing | SubmitError::IdConflict => {
            NodeError::InvalidInput
        }
        SubmitError::AlreadyStarted => NodeError::AlreadyStarted,
        SubmitError::NotQueued => NodeError::NotFound,
        SubmitError::Storage(e) => errors::storage(e),
    }
}

fn addresses(list: &[skein_view::Addr]) -> Vec<Address> {
    list.iter()
        .map(|a| Address {
            name: a.name.clone(),
            address: a.address.clone(),
        })
        .collect()
}

fn envelope(account: &AccountId, e: skein_view::Envelope) -> Option<Envelope> {
    Some(Envelope {
        account: account.clone(),
        id: MessageId::new(e.id).ok()?,
        thread: ThreadId::new(e.thread).ok()?,
        subject: e.subject,
        from: addresses(&e.from),
        to: addresses(&e.to),
        cc: addresses(&e.cc),
        date: e.date,
        received_at: e.received_at,
        sort_date: e.sort_date,
        size: e.size,
        has_attachments: e.has_attachments,
        snippet: e.snippet,
        unread: e.unread,
        flagged: e.flagged,
        mailboxes: e
            .mailboxes
            .into_iter()
            .filter_map(|m| MailboxId::new(m).ok())
            .collect(),
        tags: e
            .tags
            .into_iter()
            .filter_map(|t| Tag::new(t).ok())
            .collect(),
        available: e.available,
    })
}

/// The scope of a list in one account: the database filter and the mailboxes it covers.
/// `None` when the account has nothing in the scope (no mailbox with the role).
struct Narrowed {
    filter: Filter,
    mailboxes: Option<Vec<MailboxId>>,
}

/// Rows of several accounts ordered by `(sort desc, account desc, id desc)`.
fn before_message(p: &Position, account: &str) -> Option<(i64, String)> {
    let a = p.account.as_deref().unwrap_or(account);
    Some(match account.cmp(a) {
        std::cmp::Ordering::Less => (p.sort, "g".into()),
        std::cmp::Ordering::Equal => (p.sort, p.id.clone()),
        std::cmp::Ordering::Greater => (p.sort, String::new()),
    })
}

fn before_thread(p: &Position, account: &str) -> Result<(i64, i64), NodeError> {
    let a = p.account.as_deref().unwrap_or(account);
    Ok(match account.cmp(a) {
        std::cmp::Ordering::Less => (p.sort, i64::MAX),
        std::cmp::Ordering::Equal => (
            p.sort,
            p.id.parse::<i64>().map_err(|_| NodeError::InvalidInput)?,
        ),
        std::cmp::Ordering::Greater => (p.sort, 0),
    })
}

struct Resolved {
    by_account: BTreeMap<AccountId, BTreeMap<String, Vec<(ItemRef, MessageId)>>>,
    skipped: Vec<MessageRef>,
}

impl Api {
    fn core(&self) -> &Core {
        &self.0
    }

    async fn meta(&self, account: &AccountId) -> Result<AccountMeta, NodeError> {
        self.meta_for(account, None).await
    }

    /// The account's record, when this node may read it and, with `class`, issue that class.
    async fn meta_for(
        &self,
        account: &AccountId,
        class: Option<CommandClass>,
    ) -> Result<AccountMeta, NodeError> {
        let core = self.core();
        core.group.check(account, class)?;
        let Some((bytes, _)) = core
            .storage
            .control
            .get(&core.tenant, &meta_path(account))
            .await
            .map_err(errors::storage)?
        else {
            return Err(NodeError::NotFound);
        };
        let meta = records::decode_account_meta(&bytes).map_err(|_| NodeError::Storage)?;
        if meta.removing {
            return Err(NodeError::NotFound);
        }
        Ok(meta)
    }

    async fn pair(
        &self,
        code: &str,
        address: Option<&str>,
        grants: Option<&[AccountId]>,
    ) -> Result<PairingResult, NodeError> {
        let core = self.core();
        let may_join = self.live_metas().await?.is_empty();
        let (result, joined) = core.group.accept(code, address, may_join, grants).await?;
        if let Some(joined) = joined {
            crate::boot::switch_group(core, joined).await?;
        }
        Ok(result)
    }

    async fn live_metas(&self) -> Result<Vec<AccountMeta>, NodeError> {
        let mut metas: Vec<AccountMeta> = all_metas(self.core())
            .await?
            .into_iter()
            .filter(|m| !m.removing)
            .collect();
        metas.sort_by(|a, b| a.account.cmp(&b.account));
        Ok(metas)
    }

    async fn accounts_of(&self, account: Option<&AccountId>) -> Result<Vec<AccountId>, NodeError> {
        match account {
            Some(a) => {
                self.meta(a).await?;
                Ok(vec![a.clone()])
            }
            None => Ok(self
                .live_metas()
                .await?
                .into_iter()
                .map(|m| m.account)
                .collect()),
        }
    }

    async fn mailboxes(
        &self,
        account: &AccountId,
    ) -> Result<Vec<skein_view::MailboxRow>, NodeError> {
        let name = account.to_string();
        db(&self.core().store, move |s| s.mailboxes(&name)).await
    }

    async fn role_mailboxes(
        &self,
        account: &AccountId,
        role: MailboxRole,
    ) -> Result<Vec<MailboxId>, NodeError> {
        Ok(self
            .mailboxes(account)
            .await?
            .into_iter()
            .filter(|m| m.role.as_deref() == Some(role.as_str()))
            .filter_map(|m| MailboxId::new(m.id).ok())
            .collect())
    }

    async fn narrow(
        &self,
        scope: &Scope,
        account: &AccountId,
        unread_only: bool,
    ) -> Result<Option<Narrowed>, NodeError> {
        let mut filter = Filter::default();
        let mut mailboxes = None;
        match scope {
            Scope::Mailbox { mailbox, .. } => {
                let known = self
                    .mailboxes(account)
                    .await?
                    .iter()
                    .any(|m| m.id == mailbox.as_str());
                if !known {
                    return Err(NodeError::NotFound);
                }
                filter.mailboxes = Some(vec![mailbox.to_string()]);
                mailboxes = Some(vec![mailbox.clone()]);
            }
            Scope::Role { role, .. } => {
                let list = self.role_mailboxes(account, *role).await?;
                if list.is_empty() {
                    return Ok(None);
                }
                filter.mailboxes = Some(list.iter().map(|m| m.to_string()).collect());
                mailboxes = Some(list);
            }
            Scope::Flagged { .. } => filter.flagged = Some(true),
            Scope::Tagged { tag, .. } => filter.tag = Some(tag.to_string()),
            Scope::All { .. } => {}
        }
        if unread_only {
            filter.unread = Some(true);
        }
        Ok(Some(Narrowed { filter, mailboxes }))
    }

    async fn resolve(&self, targets: &Targets, class: CommandClass) -> Result<Resolved, NodeError> {
        check::targets(targets)?;
        let mut out = Resolved {
            by_account: BTreeMap::new(),
            skipped: Vec::new(),
        };
        let mut checked = BTreeMap::new();
        for t in &targets.0 {
            if !checked.contains_key(&t.account) {
                self.meta_for(&t.account, Some(class)).await?;
                checked.insert(t.account.clone(), ());
            }
            let name = t.account.to_string();
            let id = t.message.to_string();
            let detail = db(&self.core().store, move |s| s.message(&name, &id)).await?;
            let Some(detail) = detail else {
                out.skipped.push(t.clone());
                continue;
            };
            let per = out.by_account.entry(t.account.clone()).or_default();
            for m in detail.memberships {
                per.entry(m.mailbox).or_default().push((
                    ItemRef {
                        id: m.item,
                        uid: m.uid,
                    },
                    t.message.clone(),
                ));
            }
        }
        Ok(out)
    }

    async fn submit(&self, account: &AccountId, body: CommandBody) -> Result<CommandId, NodeError> {
        let core = self.core();
        if !core.leads(account.as_str()) {
            let id = core
                .replication()?
                .submit(&skein_id(account)?, body)
                .await
                .map_err(crate::sync::err)?;
            return CommandId::new(id.to_string());
        }
        let id = skein_core::CommandId::generate();
        let command = Command {
            id: id.clone(),
            account: skein_id(account)?,
            created_at: Timestamp::now(),
            trace: None,
            body,
        };
        submit_command(&core.storage, &*core.signal, &core.tenant, &command)
            .await
            .map_err(submit_error)?;
        CommandId::new(id.to_string())
    }

    /// Queues one command per account, mailbox and chunk of items, and records the expected
    /// change of every message in the overlay.
    async fn queue(
        &self,
        resolved: Resolved,
        change: impl Fn(&AccountId, &str) -> Option<(CommandBodyFn, Change)>,
    ) -> Result<Queued, NodeError> {
        let now = self.core().clock.now_ms();
        let mut queued = Queued {
            commands: Vec::new(),
            skipped: resolved.skipped,
        };
        for (account, mailboxes) in resolved.by_account {
            for (mailbox, items) in mailboxes {
                let Some((make, expect)) = change(&account, &mailbox) else {
                    continue;
                };
                for chunk in items.chunks(MAX_ITEMS) {
                    let refs: Vec<ItemRef> = chunk.iter().map(|(i, _)| i.clone()).collect();
                    let command = self.submit(&account, make(&mailbox, refs)).await?;
                    for (_, message) in chunk {
                        self.core().overlay.expect(
                            account.as_str(),
                            message.as_str(),
                            &expect,
                            command.as_str(),
                            now,
                        );
                    }
                    queued.commands.push(command);
                }
            }
        }
        Ok(queued)
    }

    fn wake(&self, account: &AccountId) {
        let core = self.0.clone();
        let account = account.clone();
        self.0.background.spawn(async move {
            if !core.leads(account.as_str()) {
                if let (Ok(r), Ok(id)) = (
                    core.replication(),
                    skein_core::AccountId::new(account.as_str()),
                ) {
                    let _ = r.sync_now(&id).await;
                }
                return;
            }
            if let Ok(id) = skein_core::AccountId::new(account.as_str()) {
                let _ = core
                    .signal
                    .publish(
                        &skein_core::coordination::group(&core.tenant),
                        &wake_topic(&id),
                        Bytes::from_static(b"wake"),
                    )
                    .await;
            }
        });
    }
}

type CommandBodyFn = Box<dyn Fn(&str, Vec<ItemRef>) -> CommandBody + Send + Sync>;

fn file_size(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[async_trait]
impl NodeApi for Api {
    async fn node_info(&self) -> Result<NodeInfo, NodeError> {
        let core = self.core();
        let view = core.data_dir.join("view");
        let database = ["view.sqlite", "view.sqlite-wal", "view.sqlite-shm"]
            .iter()
            .map(|f| file_size(&view.join(f)))
            .sum();
        Ok(NodeInfo {
            node_id: core.node_id.clone(),
            group_id: core.tenant.to_string(),
            profile: core.profile.name().into(),
            version: env!("CARGO_PKG_VERSION").into(),
            objects_bytes: None,
            database_bytes: Some(database),
        })
    }

    async fn discover(&self, address: &EmailAddress) -> Result<Vec<Candidate>, NodeError> {
        let domain = Domain::of_address(address.as_str()).map_err(|_| NodeError::InvalidInput)?;
        let core = self.core();
        Ok(crate::discovery::discover(&core.discovery, core.prober.as_deref(), &domain).await)
    }

    async fn add_account(
        &self,
        setup: AccountSetup,
        secret: Secret,
    ) -> Result<AccountId, NodeError> {
        check::setup(&setup)?;
        check::password(&secret)?;
        let core = self.core();
        let address = setup.address.as_str().to_ascii_lowercase();
        if self
            .live_metas()
            .await?
            .iter()
            .any(|m| m.address.as_str().eq_ignore_ascii_case(&address))
        {
            return Err(NodeError::AccountExists);
        }
        let account = AccountId::new(random::base32_id('a'))?;
        let id = skein_id(&account)?;
        let record = providers::record_for(&id, &setup);
        skein_accounts::admin::check_record(&record, &skein_accounts::OAuthClients::new())
            .map_err(|_| NodeError::InvalidInput)?;
        providers::sign_in(&core.providers, &core.tenant, &record, &secret).await?;
        let password = secret.expose_str().ok_or(NodeError::InvalidInput)?;
        core.group.add_account(&account).await?;
        core.led
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(account.to_string());
        core.accounts
            .set_password(&core.tenant, &id, password)
            .await
            .map_err(|_| NodeError::Storage)?;
        put_meta(
            core,
            &AccountMeta {
                v: records::FORMAT,
                account: account.clone(),
                address: setup.address.clone(),
                display_name: setup.display_name.clone(),
                archive: None,
                removing: false,
                notify: true,
                created_at: core.clock.now_ms(),
                owner: None,
            },
        )
        .await?;
        core.accounts
            .put(&core.tenant, &record)
            .await
            .map_err(|_| NodeError::Storage)?;
        self.wake(&account);
        core.hub.send(NodeEvent::AccountsChanged);
        tracing::info!(account = %account, "account added");
        Ok(account)
    }

    async fn update_password(&self, account: &AccountId, secret: Secret) -> Result<(), NodeError> {
        let meta = self
            .meta_for(account, Some(CommandClass::AccountPassword))
            .await?;
        if meta.owner.is_some() {
            return Err(NodeError::Unavailable);
        }
        check::password(&secret)?;
        let core = self.core();
        let id = skein_id(account)?;
        let record = core
            .accounts
            .get(&core.tenant, &id)
            .await
            .map_err(|_| NodeError::Storage)?
            .ok_or(NodeError::NotFound)?;
        providers::sign_in(&core.providers, &core.tenant, &record, &secret).await?;
        let password = secret.expose_str().ok_or(NodeError::InvalidInput)?;
        core.accounts
            .set_password(&core.tenant, &id, password)
            .await
            .map_err(|_| NodeError::Storage)?;
        self.wake(account);
        core.hub.send(NodeEvent::AccountsChanged);
        Ok(())
    }

    async fn update_account(
        &self,
        account: &AccountId,
        patch: AccountPatch,
    ) -> Result<(), NodeError> {
        let mut meta = self
            .meta_for(account, Some(CommandClass::AccountUpdate))
            .await?;
        if meta.owner.is_some() {
            return Err(NodeError::Unavailable);
        }
        check::patch(&patch)?;
        let core = self.core();
        let id = skein_id(account)?;
        let mut record = core
            .accounts
            .get(&core.tenant, &id)
            .await
            .map_err(|_| NodeError::Storage)?
            .ok_or(NodeError::NotFound)?;
        if let Some(name) = patch.display_name {
            meta.display_name = name;
        }
        if let Some(archive) = patch.archive_mailbox {
            meta.archive = archive;
        }
        if let Some(paused) = patch.paused {
            record.paused = paused;
        }
        if let Some(notify) = patch.notify {
            meta.notify = notify;
        }
        if let Some(skip) = patch.skip_mailboxes {
            record.exclude = skip.into_iter().map(String::from).collect();
        }
        put_meta(core, &meta).await?;
        core.accounts
            .put(&core.tenant, &record)
            .await
            .map_err(|_| NodeError::Storage)?;
        core.hub.send(NodeEvent::AccountsChanged);
        Ok(())
    }

    async fn remove_account(&self, account: &AccountId) -> Result<(), NodeError> {
        let mut meta = self
            .meta_for(account, Some(CommandClass::AccountRemove))
            .await?;
        if meta.owner.is_some() {
            return Err(NodeError::Unavailable);
        }
        let core = self.core();
        core.led
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(account.as_str());
        let id = skein_id(account)?;
        meta.removing = true;
        put_meta(core, &meta).await?;
        if let Some(mut record) = core
            .accounts
            .get(&core.tenant, &id)
            .await
            .map_err(|_| NodeError::Storage)?
        {
            record.paused = true;
            core.accounts
                .put(&core.tenant, &record)
                .await
                .map_err(|_| NodeError::Storage)?;
        }
        core.hub.send(NodeEvent::AccountsChanged);
        crate::run::spawn_removal(self.0.clone(), account.clone());
        Ok(())
    }

    async fn list_accounts(&self) -> Result<Vec<AccountInfo>, NodeError> {
        let core = self.core();
        let rows = db(&core.store, |s| s.accounts()).await?;
        let mut out = Vec::new();
        for meta in self.live_metas().await? {
            let id = skein_id(&meta.account)?;
            let record = core
                .accounts
                .get(&core.tenant, &id)
                .await
                .map_err(|_| NodeError::Storage)?;
            let paused = record.as_ref().is_some_and(|r| r.paused);
            let skipped_mailboxes = record
                .map(|r| {
                    r.exclude
                        .into_iter()
                        .filter_map(|m| MailboxId::new(m).ok())
                        .collect()
                })
                .unwrap_or_default();
            let (health, mail, send) = crate::run::status_of(core, &meta.account).await;
            let boxes = self.mailboxes(&meta.account).await?;
            out.push(AccountInfo {
                id: meta.account.clone(),
                address: meta.address.clone(),
                display_name: meta.display_name.clone(),
                provider: ProviderKind::Imap,
                paused,
                health,
                mail,
                send,
                first_sync_completed: rows
                    .iter()
                    .any(|r| r.account == meta.account.as_str() && r.first_sync_completed),
                messages: boxes.iter().map(|b| b.total).sum(),
                unread: boxes
                    .iter()
                    .filter(|b| b.role.as_deref() == Some("inbox"))
                    .map(|b| b.unread)
                    .sum(),
                skipped_mailboxes,
                archive_mailbox: meta.archive.clone(),
                notify: meta.notify,
            });
        }
        out.sort_by(|a, b| a.address.as_str().cmp(b.address.as_str()));
        Ok(out)
    }

    async fn sync_now(&self, account: Option<&AccountId>) -> Result<(), NodeError> {
        for a in self.accounts_of(account).await? {
            if self
                .core()
                .group
                .check(&a, Some(CommandClass::Sync))
                .is_ok()
            {
                self.wake(&a);
            } else if account.is_some() {
                return Err(NodeError::NotFound);
            }
        }
        Ok(())
    }

    async fn list_mailboxes(&self, account: &AccountId) -> Result<Vec<MailboxInfo>, NodeError> {
        self.meta(account).await?;
        Ok(self
            .mailboxes(account)
            .await?
            .into_iter()
            .filter_map(|m| {
                Some(MailboxInfo {
                    id: MailboxId::new(m.id).ok()?,
                    path: m.path,
                    role: m.role.as_deref().and_then(MailboxRole::from_name),
                    selectable: m.selectable,
                    total: m.total,
                    unread: m.unread,
                })
            })
            .collect())
    }

    async fn list_threads(&self, query: ListQuery) -> Result<Page<ThreadSummary>, NodeError> {
        check::list(&query)?;
        let position = query.cursor.as_ref().map(cursor::decode).transpose()?;
        let accounts = self.accounts_of(query.scope.account()).await?;
        let limit = query.limit as usize;
        let mut rows: Vec<(i64, String, i64, ThreadSummary)> = Vec::new();
        for account in &accounts {
            let Some(n) = self
                .narrow(&query.scope, account, query.unread_only)
                .await?
            else {
                continue;
            };
            let before = position
                .as_ref()
                .map(|p| before_thread(p, account.as_str()))
                .transpose()?;
            let name = account.to_string();
            let filter = n.filter;
            let page = db(&self.core().store, move |s| {
                s.threads_where(&name, &filter, before, limit + 1)
            })
            .await?;
            for t in page {
                let Ok(id) = ThreadId::new(t.id) else {
                    continue;
                };
                let Some(latest) = envelope(account, t.latest) else {
                    continue;
                };
                let latest = self
                    .core()
                    .overlay
                    .apply(latest.clone(), None)
                    .unwrap_or(latest);
                rows.push((
                    latest.sort_date,
                    account.to_string(),
                    t.id,
                    ThreadSummary {
                        account: account.clone(),
                        id,
                        count: t.count,
                        unread: t.unread,
                        latest,
                    },
                ));
            }
        }
        rows.sort_by(|a, b| (b.0, &b.1, b.2).cmp(&(a.0, &a.1, a.2)));
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next = if more {
            rows.last().map(|(sort, account, id, _)| {
                cursor::encode(&Position {
                    sort: *sort,
                    id: id.to_string(),
                    account: Some(account.clone()),
                })
            })
        } else {
            None
        };
        Ok(Page {
            items: rows.into_iter().map(|r| r.3).collect(),
            next,
        })
    }

    async fn get_thread(
        &self,
        account: &AccountId,
        thread: ThreadId,
    ) -> Result<ThreadDetail, NodeError> {
        self.meta(account).await?;
        let name = account.to_string();
        let messages = db(&self.core().store, move |s| {
            s.thread(&name, thread.get(), 1000)
        })
        .await?;
        if messages.is_empty() {
            return Err(NodeError::NotFound);
        }
        let links: Vec<skein_view::Link<'_>> = messages
            .iter()
            .map(|m| skein_view::Link {
                id: &m.envelope.id,
                message_id: m.envelope.message_id.as_deref(),
                references: &m.references,
                in_reply_to: &m.in_reply_to,
                sort_date: m.envelope.sort_date,
            })
            .collect();
        fn node(n: skein_view::Node) -> TreeNode {
            TreeNode {
                message: n.id.and_then(|i| MessageId::new(i).ok()),
                children: n.children.into_iter().map(node).collect(),
            }
        }
        let tree = skein_view::tree(&links).into_iter().map(node).collect();
        let envelopes = messages
            .into_iter()
            .filter_map(|m| envelope(account, m.envelope))
            .map(|e| self.core().overlay.apply(e.clone(), None).unwrap_or(e))
            .collect();
        Ok(ThreadDetail {
            account: account.clone(),
            id: thread,
            messages: envelopes,
            tree,
        })
    }

    async fn list_messages(&self, query: ListQuery) -> Result<Page<Envelope>, NodeError> {
        check::list(&query)?;
        let position = query.cursor.as_ref().map(cursor::decode).transpose()?;
        let accounts = self.accounts_of(query.scope.account()).await?;
        let limit = query.limit as usize;
        let mut rows: Vec<(i64, String, String, Option<Envelope>)> = Vec::new();
        for account in &accounts {
            let Some(n) = self
                .narrow(&query.scope, account, query.unread_only)
                .await?
            else {
                continue;
            };
            let before = position
                .as_ref()
                .and_then(|p| before_message(p, account.as_str()));
            let name = account.to_string();
            let filter = n.filter;
            let page = db(&self.core().store, move |s| {
                s.messages_where(&name, &filter, before, limit + 1)
            })
            .await?;
            for e in page {
                let (sort, id) = (e.sort_date, e.id.clone());
                let shown = envelope(account, e)
                    .and_then(|e| self.core().overlay.apply(e, n.mailboxes.as_deref()));
                let shown = shown.filter(|e| !query.unread_only || e.unread);
                rows.push((sort, account.to_string(), id, shown));
            }
        }
        rows.sort_by(|a, b| (b.0, &b.1, &b.2).cmp(&(a.0, &a.1, &a.2)));
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next = if more {
            rows.last().map(|(sort, account, id, _)| {
                cursor::encode(&Position {
                    sort: *sort,
                    id: id.clone(),
                    account: Some(account.clone()),
                })
            })
        } else {
            None
        };
        Ok(Page {
            items: rows.into_iter().filter_map(|r| r.3).collect(),
            next,
        })
    }

    async fn get_message(
        &self,
        account: &AccountId,
        message: &MessageId,
    ) -> Result<MessageDetail, NodeError> {
        self.meta(account).await?;
        let name = account.to_string();
        let id = message.to_string();
        let detail = db(&self.core().store, move |s| s.message(&name, &id))
            .await?
            .ok_or(NodeError::NotFound)?;
        let message_id = detail.envelope.message_id.clone();
        let env = envelope(account, detail.envelope).ok_or(NodeError::Internal)?;
        let env = self.core().overlay.apply(env.clone(), None).unwrap_or(env);
        Ok(MessageDetail {
            envelope: env,
            message_id,
            in_reply_to: detail.in_reply_to,
            references: detail.references,
            memberships: detail
                .memberships
                .into_iter()
                .filter_map(|m| {
                    Some(Membership {
                        mailbox: MailboxId::new(m.mailbox).ok()?,
                        flags: m.flags,
                    })
                })
                .collect(),
            attachments: detail
                .attachments
                .into_iter()
                .map(|a| AttachmentInfo {
                    part: a.part,
                    name: a.name,
                    content_type: a.content_type,
                    size: a.size,
                })
                .collect(),
        })
    }

    async fn message_raw(
        &self,
        account: &AccountId,
        message: &MessageId,
    ) -> Result<Bytes, NodeError> {
        self.meta(account).await?;
        let name = account.to_string();
        let id = message.to_string();
        if !db(&self.core().store, move |s| s.has_message(&name, &id)).await? {
            return Err(NodeError::NotFound);
        }
        let hash = BlobHash::parse(message.as_str()).map_err(|_| NodeError::InvalidInput)?;
        match self
            .core()
            .storage
            .blobs
            .get(&self.core().tenant, &hash)
            .await
        {
            Ok(Some(bytes)) if hash.matches(&bytes) => Ok(bytes),
            Ok(_) | Err(StorageError::Corrupt(_)) => Err(NodeError::Unavailable),
            Err(e) => Err(errors::storage(e)),
        }
    }

    async fn set_read(&self, targets: Targets, read: bool) -> Result<Queued, NodeError> {
        let resolved = self.resolve(&targets, CommandClass::Flags).await?;
        let seen = Flags::new(["\\Seen"]);
        self.queue(resolved, move |_, _| {
            let seen = seen.clone();
            Some((
                Box::new(move |mailbox: &str, items| CommandBody::SetFlags {
                    mailbox: mailbox.to_owned(),
                    items,
                    add: if read { seen.clone() } else { Flags::default() },
                    remove: if read { Flags::default() } else { seen.clone() },
                }) as CommandBodyFn,
                Change {
                    read: Some(read),
                    ..Change::default()
                },
            ))
        })
        .await
    }

    async fn set_flagged(&self, targets: Targets, flagged: bool) -> Result<Queued, NodeError> {
        let resolved = self.resolve(&targets, CommandClass::Flags).await?;
        let flag = Flags::new(["\\Flagged"]);
        self.queue(resolved, move |_, _| {
            let flag = flag.clone();
            Some((
                Box::new(move |mailbox: &str, items| CommandBody::SetFlags {
                    mailbox: mailbox.to_owned(),
                    items,
                    add: if flagged {
                        flag.clone()
                    } else {
                        Flags::default()
                    },
                    remove: if flagged {
                        Flags::default()
                    } else {
                        flag.clone()
                    },
                }) as CommandBodyFn,
                Change {
                    flagged: Some(flagged),
                    ..Change::default()
                },
            ))
        })
        .await
    }

    async fn move_to(&self, targets: Targets, mailbox: &MailboxId) -> Result<Queued, NodeError> {
        check::targets_of_one_account(&targets)?;
        let account = targets.0[0].account.clone();
        self.meta_for(&account, Some(CommandClass::Move)).await?;
        if !self
            .mailboxes(&account)
            .await?
            .iter()
            .any(|m| m.id == mailbox.as_str())
        {
            return Err(NodeError::NotFound);
        }
        let resolved = self.resolve(&targets, CommandClass::Move).await?;
        let to = mailbox.clone();
        self.queue(resolved, move |_, from| {
            (from != to.as_str()).then(|| {
                let target = to.to_string();
                (
                    Box::new(move |from: &str, items| CommandBody::Move {
                        from: from.to_owned(),
                        to: target.clone(),
                        items,
                    }) as CommandBodyFn,
                    Change {
                        moved_to: Some(to.clone()),
                        ..Change::default()
                    },
                )
            })
        })
        .await
    }

    async fn archive(&self, targets: Targets) -> Result<Queued, NodeError> {
        check::targets(&targets)?;
        let mut archives: BTreeMap<AccountId, MailboxId> = BTreeMap::new();
        for t in &targets.0 {
            if archives.contains_key(&t.account) {
                continue;
            }
            let meta = self.meta_for(&t.account, Some(CommandClass::Move)).await?;
            let by_role = self
                .role_mailboxes(&t.account, MailboxRole::Archive)
                .await?
                .into_iter()
                .next();
            let archive = by_role.or(meta.archive).ok_or(NodeError::NoArchive)?;
            archives.insert(t.account.clone(), archive);
        }
        let resolved = self.resolve(&targets, CommandClass::Move).await?;
        self.queue(resolved, move |account, from| {
            let to = archives.get(account)?.clone();
            (from != to.as_str()).then(|| {
                let target = to.to_string();
                (
                    Box::new(move |from: &str, items| CommandBody::Move {
                        from: from.to_owned(),
                        to: target.clone(),
                        items,
                    }) as CommandBodyFn,
                    Change {
                        moved_to: Some(to.clone()),
                        ..Change::default()
                    },
                )
            })
        })
        .await
    }

    async fn delete(&self, targets: Targets, permanent: bool) -> Result<Queued, NodeError> {
        check::targets(&targets)?;
        let class = if permanent {
            CommandClass::DeleteForever
        } else {
            CommandClass::Delete
        };
        let mut trash: BTreeMap<AccountId, Option<MailboxId>> = BTreeMap::new();
        for t in &targets.0 {
            if trash.contains_key(&t.account) {
                continue;
            }
            self.meta_for(&t.account, Some(class)).await?;
            let box_ = self
                .role_mailboxes(&t.account, MailboxRole::Trash)
                .await?
                .into_iter()
                .next();
            if !permanent && box_.is_none() {
                return Err(NodeError::NoTrash);
            }
            trash.insert(t.account.clone(), box_);
        }
        let resolved = self.resolve(&targets, class).await?;
        self.queue(resolved, move |account, _| {
            let change = if permanent {
                Change {
                    gone: true,
                    ..Change::default()
                }
            } else {
                Change {
                    moved_to: trash.get(account).cloned().flatten(),
                    ..Change::default()
                }
            };
            Some((
                Box::new(move |mailbox: &str, items| CommandBody::Delete {
                    mailbox: mailbox.to_owned(),
                    items,
                    to_trash: !permanent,
                }) as CommandBodyFn,
                change,
            ))
        })
        .await
    }

    async fn save_draft(&self, mut draft: Draft) -> Result<DraftId, NodeError> {
        check::draft(&draft)?;
        self.meta_for(&draft.account, Some(CommandClass::Draft))
            .await?;
        let core = self.core();
        let existing = draft_records(core).await?;
        let id = match &draft.id {
            Some(id) => {
                if let Some(r) = existing.iter().find(|r| r.draft.id.as_ref() == Some(id))
                    && r.sending.is_some()
                {
                    return Err(NodeError::Busy);
                }
                id.clone()
            }
            None => {
                if existing.len() >= MAX_DRAFTS {
                    return Err(NodeError::QuotaFull);
                }
                DraftId::new(skein_core::CommandId::generate().to_string())?
            }
        };
        draft.id = Some(id.clone());
        put_draft(
            core,
            &DraftRecord {
                v: records::FORMAT,
                updated_at: core.clock.now_ms(),
                sending: None,
                draft,
            },
        )
        .await?;
        Ok(id)
    }

    async fn list_drafts(&self) -> Result<Vec<DraftSummary>, NodeError> {
        let mut out: Vec<DraftSummary> = draft_records(self.core())
            .await?
            .into_iter()
            .filter(|r| r.sending.is_none())
            .filter_map(|r| {
                let d = r.draft;
                Some(DraftSummary {
                    id: d.id?,
                    account: d.account,
                    subject: d.subject,
                    recipients: (d.to.len() + d.cc.len() + d.bcc.len()) as u32,
                    attachments: d.attachments.len() as u32,
                    updated_at: r.updated_at,
                })
            })
            .collect();
        out.sort_by(|a, b| (b.updated_at, &b.id).cmp(&(a.updated_at, &a.id)));
        Ok(out)
    }

    async fn get_draft(&self, id: &DraftId) -> Result<Draft, NodeError> {
        let core = self.core();
        let Some((bytes, _)) = core
            .objects
            .get(&draft_key(id.as_str()))
            .await
            .map_err(errors::storage)?
        else {
            return Err(NodeError::NotFound);
        };
        let r = records::decode_draft_record(&bytes).map_err(|_| NodeError::Storage)?;
        if r.sending.is_some() {
            return Err(NodeError::NotFound);
        }
        Ok(r.draft)
    }

    async fn delete_draft(&self, id: &DraftId) -> Result<bool, NodeError> {
        let core = self.core();
        let key = draft_key(id.as_str());
        let exists = core
            .objects
            .get(&key)
            .await
            .map_err(errors::storage)?
            .is_some();
        if exists {
            core.objects
                .delete(&key, Expect::Any)
                .await
                .map_err(errors::storage)?;
        }
        Ok(exists)
    }

    async fn send(&self, mut draft: Draft) -> Result<SendQueued, NodeError> {
        check::sendable(&draft)?;
        let meta = self
            .meta_for(&draft.account, Some(CommandClass::Send))
            .await?;
        let core = self.core();
        let local = skein_core::CommandId::generate().to_string();
        let seed = random::alnum(24);
        let composed = rowboat_compose::compose(
            &draft,
            &rowboat_compose::Identity {
                from: &meta.address,
                from_name: meta.display_name.as_deref(),
                date_ms: core.clock.now_ms(),
                message_id_local: &local,
                boundary_seed: &seed,
            },
        )?;
        let envelope = SendEnvelope {
            from: composed.envelope_from.clone(),
            to: composed.recipients.clone(),
            dsn: None,
        };
        envelope.check().map_err(|_| NodeError::InvalidInput)?;
        let blob = core
            .storage
            .blobs
            .put(&core.tenant, Bytes::from(composed.bytes))
            .await
            .map_err(errors::storage)?;
        let sent = self
            .role_mailboxes(&draft.account, MailboxRole::Sent)
            .await?
            .into_iter()
            .next()
            .map(String::from);
        let created = Timestamp::now();
        let command = self
            .submit(
                &draft.account,
                CommandBody::Send {
                    blob,
                    envelope,
                    save_to_sent: sent,
                    send_at: None,
                    dry_run: false,
                },
            )
            .await?;
        core.sends.add(command.as_str());
        let draft_id = match &draft.id {
            Some(id) => id.clone(),
            None => DraftId::new(skein_core::CommandId::generate().to_string())?,
        };
        draft.id = Some(draft_id.clone());
        let account = draft.account.clone();
        put_draft(
            core,
            &DraftRecord {
                v: records::FORMAT,
                updated_at: core.clock.now_ms(),
                sending: Some(command.to_string()),
                draft,
            },
        )
        .await?;
        let due_at = created.0 + core.profile.timing().undo_ms.max(0);
        core.hub.send(NodeEvent::SendSettled {
            account: account.clone(),
            command: command.clone(),
            outcome: SendOutcome::Waiting { due_at },
        });
        Ok(SendQueued {
            account,
            command,
            draft: draft_id,
            due_at,
        })
    }

    async fn cancel_send(&self, account: &AccountId, command: &CommandId) -> Result<(), NodeError> {
        self.meta_for(account, Some(CommandClass::SendCancel))
            .await?;
        let core = self.core();
        let id =
            skein_core::CommandId::new(command.as_str()).map_err(|_| NodeError::InvalidInput)?;
        if !core.leads(account.as_str()) {
            core.replication()?
                .cancel(&skein_id(account)?, &id)
                .await
                .map_err(crate::sync::err)?;
            core.sends.remove(command.as_str());
            settle_draft(core, command.as_str(), false).await?;
            core.hub.send(NodeEvent::CommandSettled {
                account: account.clone(),
                command: command.clone(),
                outcome: CommandOutcome::Cancelled,
            });
            return Ok(());
        }
        cancel_command(&core.storage, &core.tenant, &skein_id(account)?, &id)
            .await
            .map_err(submit_error)?;
        core.sends.remove(command.as_str());
        settle_draft(core, command.as_str(), false).await?;
        core.hub.send(NodeEvent::CommandSettled {
            account: account.clone(),
            command: command.clone(),
            outcome: CommandOutcome::Cancelled,
        });
        Ok(())
    }

    async fn outbox(&self) -> Result<Vec<OutboxItem>, NodeError> {
        let core = self.core();
        let undo = core.profile.timing().undo_ms.max(0);
        let mut out = Vec::new();
        for meta in self.live_metas().await? {
            let id = skein_id(&meta.account)?;
            for c in core
                .storage
                .commands
                .pending(&core.tenant, &id, 1000)
                .await
                .map_err(errors::storage)?
            {
                if let CommandBody::Send { send_at, .. } = &c.body {
                    let Ok(command) = CommandId::new(c.id.to_string()) else {
                        continue;
                    };
                    let due = send_at.map(|t| t.0).unwrap_or(0).max(c.created_at.0 + undo);
                    out.push(OutboxItem {
                        account: meta.account.clone(),
                        command,
                        due_at: Some(due),
                        created_at: c.created_at.0,
                    });
                }
            }
        }
        Ok(out)
    }

    async fn search(&self, query: SearchQuery) -> Result<Vec<Envelope>, NodeError> {
        check::search(&query)?;
        let Some(fts) = skein_view::fts_query(&query.text) else {
            return Ok(Vec::new());
        };
        let accounts = self.accounts_of(query.account.as_ref()).await?;
        let single = accounts.len() == 1;
        let limit = query.limit as usize;
        let mut out = Vec::new();
        for account in &accounts {
            let mut filter = Filter {
                unread: query.filter.unread,
                flagged: query.filter.flagged,
                has_attachments: query.filter.has_attachments,
                tag: query.filter.tag.as_ref().map(|t| t.to_string()),
                mailboxes: None,
            };
            if let Some(m) = &query.filter.mailbox {
                filter.mailboxes = Some(vec![m.to_string()]);
            }
            if let Some(role) = query.filter.role {
                let list = self.role_mailboxes(account, role).await?;
                if list.is_empty() {
                    continue;
                }
                let names: Vec<String> = list.iter().map(|m| m.to_string()).collect();
                filter.mailboxes = Some(match filter.mailboxes.take() {
                    Some(given) => given.into_iter().filter(|m| names.contains(m)).collect(),
                    None => names,
                });
            }
            let scope: Option<Vec<MailboxId>> = filter.mailboxes.as_ref().map(|m| {
                m.iter()
                    .filter_map(|x| MailboxId::new(x.clone()).ok())
                    .collect()
            });
            let name = account.to_string();
            let q = fts.clone();
            let found = db(&self.core().store, move |s| {
                s.search_where(&name, &q, &filter, limit)
            })
            .await?;
            out.extend(
                found
                    .into_iter()
                    .filter_map(|e| envelope(account, e))
                    .filter_map(|e| self.core().overlay.apply(e, scope.as_deref())),
            );
        }
        if !single {
            out.sort_by(|a, b| {
                (b.sort_date, &b.account, &b.id).cmp(&(a.sort_date, &a.account, &a.id))
            });
        }
        out.truncate(limit);
        Ok(out)
    }

    async fn suggest_addresses(
        &self,
        prefix: &str,
        limit: u32,
    ) -> Result<Vec<AddressSuggestion>, NodeError> {
        check::suggest(prefix, limit)?;
        let live: Vec<AccountId> = self
            .live_metas()
            .await?
            .into_iter()
            .map(|m| m.account)
            .collect();
        let p = prefix.to_owned();
        let rows = db(&self.core().store, move |s| {
            s.suggest_addresses(None, &p, skein_view::MAX_SUGGESTIONS)
        })
        .await?;
        let mut out: Vec<AddressSuggestion> = Vec::new();
        for r in rows {
            let Ok(account) = AccountId::new(r.account) else {
                continue;
            };
            if !live.contains(&account) || out.iter().any(|s| s.address == r.address) {
                continue;
            }
            out.push(AddressSuggestion {
                account,
                address: r.address,
                name: r.name,
            });
            if out.len() == limit as usize {
                break;
            }
        }
        Ok(out)
    }

    async fn knows_address(
        &self,
        account: &AccountId,
        address: &EmailAddress,
    ) -> Result<bool, NodeError> {
        self.meta(account).await?;
        let name = account.to_string();
        let a = address.to_string();
        db(&self.core().store, move |s| s.knows_address(&name, &a)).await
    }

    async fn create_invite(&self) -> Result<PairingInvite, NodeError> {
        self.core().group.create_invite().await
    }

    async fn cancel_invite(&self, invite: &str) -> Result<(), NodeError> {
        group::invite_id(invite)?;
        self.core().group.cancel_invite(invite)
    }

    async fn inspect_invite(
        &self,
        code: &str,
        address: Option<&str>,
    ) -> Result<InviteInfo, NodeError> {
        self.core().group.inspect(code, address)
    }

    async fn accept_invite(
        &self,
        code: &str,
        address: Option<&str>,
    ) -> Result<PairingResult, NodeError> {
        self.pair(code, address, None).await
    }

    async fn adopt_server(
        &self,
        code: &str,
        address: Option<&str>,
        accounts: &[AccountId],
    ) -> Result<PairingResult, NodeError> {
        if accounts.len() > group::MAX_GRANTS {
            return Err(NodeError::InvalidInput);
        }
        self.pair(code, address, Some(accounts)).await
    }

    async fn grant_to_server(&self, server: &str, accounts: &[AccountId]) -> Result<(), NodeError> {
        group::node_id(server)?;
        if accounts.len() > group::MAX_GRANTS {
            return Err(NodeError::InvalidInput);
        }
        self.core().group.grant_to_server(server, accounts).await
    }

    async fn confirm_pairing(&self, pairing: &str, matches: bool) -> Result<(), NodeError> {
        group::invite_id(pairing)?;
        self.core().group.confirm(pairing, matches)
    }

    async fn list_nodes(&self) -> Result<Vec<NodeSummary>, NodeError> {
        self.core().group.list().await
    }

    async fn rename_node(&self, node_id: &str, label: Option<&str>) -> Result<(), NodeError> {
        group::node_id(node_id)?;
        if let Some(l) = label {
            group::node_label(l)?;
        }
        self.core().group.rename(node_id, label).await
    }

    async fn revoke_node(&self, node_id: &str) -> Result<Revoked, NodeError> {
        group::node_id(node_id)?;
        self.core().group.revoke(node_id).await
    }

    async fn group_status(&self) -> Result<GroupStatus, NodeError> {
        let core = self.core();
        let m = core.group.membership()?;
        let me = m.node();
        let has_server = m
            .counting_peers()
            .iter()
            .any(|p| m.class_of(p) == Some(baton_lease::NodeClass::Server));
        let server = if !has_server {
            ServerState::None
        } else if core.arbiter.in_fallback() {
            ServerState::Silent
        } else {
            ServerState::Answering
        };
        let mut leaders = Vec::new();
        for meta in self.live_metas().await? {
            let account = meta.account;
            let node = crate::leases::leader_of(core, account.as_str(), &me).await;
            leaders.push(AccountLeader { account, node });
        }
        Ok(GroupStatus { server, leaders })
    }

    fn group_events(&self) -> GroupEventStream {
        self.core().group.subscribe()
    }

    fn events(&self) -> EventStream {
        self.core().hub.subscribe()
    }
}
