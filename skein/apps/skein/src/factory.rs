use std::sync::Arc;

use skein_accounts::{AccountRecord, ProviderFactory, ProviderKind, SenderFactory, SenderKind};
use skein_core::{AccountId, Credentials, TenantId};
use skein_mail::{MailError, MailProvider};
use skein_send::{SendError, Sender};
use skein_throttle::{Throttle, Throttles};

/// The Graph throttle of one account, shared by its mail, calendar and contacts providers and
/// its sender, since Graph limits requests per mailbox across all of them.
fn graph_throttle(
    throttles: &Throttles,
    tenant: Option<&TenantId>,
    account: &AccountId,
) -> Option<Throttle> {
    tenant.map(|tenant| throttles.get(&format!("{tenant}/{account}")))
}

/// Builds providers from account records: the only place that knows every provider crate.
#[derive(Clone, Default)]
pub struct Providers {
    throttles: Throttles,
}

impl Providers {
    /// Providers whose Graph requests go through `throttles`, keyed by tenant and account.
    pub fn new(throttles: Throttles) -> Self {
        Self { throttles }
    }

    fn make(
        &self,
        tenant: Option<&TenantId>,
        record: &AccountRecord,
        credentials: Credentials,
    ) -> Result<Arc<dyn MailProvider>, MailError> {
        Ok(match record.provider {
            ProviderKind::Imap => Arc::new(skein_mail_imap::ImapProvider::new(
                skein_mail_imap::ImapSettings::from_json(&record.settings)?,
                credentials,
            )?),
            ProviderKind::Jmap => Arc::new(skein_mail_jmap::JmapProvider::new(
                skein_mail_jmap::JmapSettings::from_json(&record.settings)?,
                credentials,
            )?),
            ProviderKind::Gmail => Arc::new(skein_mail_gmail::GmailProvider::new(
                skein_mail_gmail::GmailSettings::from_json(&record.settings)?,
                credentials,
            )?),
            ProviderKind::Graph => {
                let provider = skein_mail_graph::GraphProvider::new(
                    skein_mail_graph::GraphSettings::from_json(&record.settings)?,
                    credentials,
                )?;
                Arc::new(
                    match graph_throttle(&self.throttles, tenant, &record.account) {
                        Some(throttle) => provider.with_throttle(throttle),
                        None => provider,
                    },
                )
            }
        })
    }
}

impl ProviderFactory for Providers {
    fn build(
        &self,
        record: &AccountRecord,
        credentials: Credentials,
    ) -> Result<Arc<dyn MailProvider>, MailError> {
        self.make(None, record, credentials)
    }

    fn build_in(
        &self,
        tenant: &TenantId,
        record: &AccountRecord,
        credentials: Credentials,
    ) -> Result<Arc<dyn MailProvider>, MailError> {
        self.make(Some(tenant), record, credentials)
    }
}

/// Builds senders from account records: the only place that knows every sender crate.
#[derive(Clone, Default)]
pub struct SenderBuilder {
    throttles: Throttles,
}

impl SenderBuilder {
    /// Senders whose Graph requests go through `throttles`, keyed by tenant and account.
    pub fn new(throttles: Throttles) -> Self {
        Self { throttles }
    }

    fn make(
        &self,
        tenant: Option<&TenantId>,
        record: &AccountRecord,
        kind: SenderKind,
        settings: &serde_json::Value,
        credentials: Credentials,
    ) -> Result<Arc<dyn Sender>, SendError> {
        Ok(match kind {
            SenderKind::Smtp => Arc::new(skein_send_smtp::SmtpSender::new(
                skein_send_smtp::SmtpSettings::from_json(settings)?,
                Some(credentials),
            )?),
            SenderKind::Gmail => Arc::new(skein_send_gmail::GmailSender::new(
                skein_send_gmail::GmailSendSettings::from_json(settings)?,
                credentials,
            )?),
            SenderKind::Graph => {
                let sender = skein_send_graph::GraphSender::new(
                    skein_send_graph::GraphSendSettings::from_json(settings)?,
                    credentials,
                )?;
                Arc::new(
                    match graph_throttle(&self.throttles, tenant, &record.account) {
                        Some(throttle) => sender.with_throttle(throttle),
                        None => sender,
                    },
                )
            }
            SenderKind::Jmap => Arc::new(skein_send_jmap::JmapSender::new(
                skein_send_jmap::JmapSendSettings::from_json(settings)?,
                credentials,
            )?),
            SenderKind::Ses => Arc::new(skein_send_ses::SesSender::new(
                skein_send_ses::SesSettings::from_json(settings)?,
                credentials,
            )?),
        })
    }
}

impl SenderFactory for SenderBuilder {
    fn build(
        &self,
        record: &AccountRecord,
        kind: SenderKind,
        settings: &serde_json::Value,
        credentials: Credentials,
    ) -> Result<Arc<dyn Sender>, SendError> {
        self.make(None, record, kind, settings, credentials)
    }

    fn build_in(
        &self,
        tenant: &TenantId,
        record: &AccountRecord,
        kind: SenderKind,
        settings: &serde_json::Value,
        credentials: Credentials,
    ) -> Result<Arc<dyn Sender>, SendError> {
        self.make(Some(tenant), record, kind, settings, credentials)
    }
}

fn own_or_empty(settings: &serde_json::Value) -> serde_json::Value {
    if settings.is_null() {
        serde_json::json!({})
    } else {
        settings.clone()
    }
}

/// Builds calendars and contacts providers from account records.
#[derive(Clone, Default)]
pub struct PimProviders {
    throttles: Throttles,
}

impl PimProviders {
    /// Providers whose Graph requests go through `throttles`, keyed by tenant and account.
    pub fn new(throttles: Throttles) -> Self {
        Self { throttles }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DavSettings {
    #[serde(default)]
    calendars: Option<String>,
    #[serde(default)]
    contacts: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    allow_insecure_plain: bool,
    #[serde(default)]
    schedule_inbox: bool,
}

impl skein_accounts::PimFactory for PimProviders {
    fn build(
        &self,
        record: &AccountRecord,
        settings: &skein_accounts::PimSettings,
        credentials: Credentials,
    ) -> Result<Arc<dyn skein_pim::PimProvider>, skein_pim::PimError> {
        self.make(None, record, settings, credentials)
    }

    fn build_in(
        &self,
        tenant: &TenantId,
        record: &AccountRecord,
        settings: &skein_accounts::PimSettings,
        credentials: Credentials,
    ) -> Result<Arc<dyn skein_pim::PimProvider>, skein_pim::PimError> {
        self.make(Some(tenant), record, settings, credentials)
    }
}

impl PimProviders {
    fn make(
        &self,
        tenant: Option<&TenantId>,
        record: &AccountRecord,
        settings: &skein_accounts::PimSettings,
        credentials: Credentials,
    ) -> Result<Arc<dyn skein_pim::PimProvider>, skein_pim::PimError> {
        match settings.kind {
            skein_accounts::PimKind::Dav => {
                let dav: DavSettings = serde_json::from_value(settings.settings.clone())
                    .map_err(|e| skein_pim::PimError::Config(format!("pim settings: {e}")))?;
                if dav.calendars.is_none() && dav.contacts.is_none() {
                    return Err(skein_pim::PimError::Config(
                        "pim settings name neither calendars nor contacts".into(),
                    ));
                }
                let username = dav
                    .username
                    .or_else(|| {
                        record
                            .settings
                            .get("username")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    })
                    .unwrap_or_default();
                let mut config = skein_pim_dav::DavConfig::at("", &username, credentials);
                config.calendars = dav.calendars;
                config.contacts = dav.contacts;
                config.allow_insecure_plain = dav.allow_insecure_plain;
                config.schedule_inbox = dav.schedule_inbox;
                Ok(Arc::new(skein_pim_dav::DavProvider::new(config)?))
            }
            skein_accounts::PimKind::Google => Ok(Arc::new(skein_pim_google::GoogleProvider::new(
                skein_pim_google::GoogleSettings::from_json(&own_or_empty(&settings.settings))?,
                credentials,
            )?)),
            skein_accounts::PimKind::Graph => {
                let provider = skein_pim_graph::GraphPimProvider::new(
                    skein_pim_graph::GraphPimSettings::from_json(&own_or_empty(
                        &settings.settings,
                    ))?,
                    credentials,
                )?;
                Ok(Arc::new(
                    match graph_throttle(&self.throttles, tenant, &record.account) {
                        Some(throttle) => provider.with_throttle(throttle),
                        None => provider,
                    },
                ))
            }
            skein_accounts::PimKind::Jmap => {
                let own = own_or_empty(&settings.settings);
                let source = if own.as_object().is_some_and(|o| o.is_empty()) {
                    &record.settings
                } else {
                    &own
                };
                Ok(Arc::new(skein_pim_jmap::JmapPimProvider::new(
                    skein_pim_jmap::JmapPimSettings::from_json(source)?,
                    credentials,
                )?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use skein_accounts::Auth;
    use skein_core::AccountId;

    use super::*;

    fn record(provider: ProviderKind, settings: serde_json::Value) -> AccountRecord {
        AccountRecord {
            account: AccountId::new("a").unwrap(),
            provider,
            settings,
            auth: Auth::Password,
            include: None,
            exclude: vec![],
            paused: false,
            send: None,
            pim: None,
        }
    }

    #[test]
    fn builds_every_provider_and_refuses_bad_settings() {
        let password = || Credentials::Password { secret: "x".into() };
        let token = || Credentials::AccessToken { token: "t".into() };
        assert!(Providers::default()
            .build(
                &record(
                    ProviderKind::Imap,
                    serde_json::json!({"host": "imap.example.com", "username": "ada@example.com"})
                ),
                password()
            )
            .is_ok());
        assert!(
            Providers::default()
                .build(&record(ProviderKind::Gmail, serde_json::json!({})), token())
                .is_ok()
        );
        assert!(
            Providers::default()
                .build(&record(ProviderKind::Graph, serde_json::json!({})), token())
                .is_ok()
        );
        assert!(
            Providers::default()
                .build(
                    &record(ProviderKind::Imap, serde_json::json!({"nonsense": true})),
                    password()
                )
                .is_err()
        );
        assert!(
            Providers::default()
                .build(
                    &record(
                        ProviderKind::Imap,
                        serde_json::json!({"host": "imap.example.com", "username": "ada@example.com", "security": "plain"})
                    ),
                    password()
                )
                .is_err(),
            "plain text to a remote host is refused"
        );
    }

    #[test]
    fn builds_every_sender_and_refuses_plain_text_to_remote_hosts() {
        let password = || Credentials::Password { secret: "x".into() };
        let token = || Credentials::AccessToken { token: "t".into() };
        let r = record(ProviderKind::Imap, serde_json::json!({}));
        let smtp = |settings: serde_json::Value| {
            SenderBuilder::default().build(&r, SenderKind::Smtp, &settings, password())
        };
        assert!(smtp(serde_json::json!({"host": "smtp.example.com", "username": "ada"})).is_ok());
        assert!(
            smtp(serde_json::json!({"host": "smtp.example.com", "security": "plain"})).is_err()
        );
        assert!(smtp(serde_json::json!({"nonsense": true})).is_err());
        let empty = serde_json::json!({});
        assert!(
            SenderBuilder::default()
                .build(&r, SenderKind::Gmail, &empty, token())
                .is_ok()
        );
        assert!(
            SenderBuilder::default()
                .build(&r, SenderKind::Graph, &empty, token())
                .is_ok()
        );
        assert!(
            SenderBuilder::default()
                .build(&r, SenderKind::Gmail, &empty, password())
                .is_err()
        );
        assert!(
            SenderBuilder::default()
                .build(
                    &r,
                    SenderKind::Jmap,
                    &serde_json::json!({"url": "https://jmap.example.com", "username": "ada"}),
                    password()
                )
                .is_ok()
        );
        let key = || Credentials::AccessKey {
            id: "AKIDEXAMPLE".into(),
            secret: "ses-secret".into(),
            session_token: None,
        };
        let ses = serde_json::json!({"region": "eu-west-1", "configuration_set": "transactional"});
        let builder = SenderBuilder::default();
        let built = builder.build(&r, SenderKind::Ses, &ses, key()).unwrap();
        assert!(!built.saves_to_sent());
        assert!(
            builder
                .build(&r, SenderKind::Ses, &ses, password())
                .is_err()
        );
        assert!(builder.build(&r, SenderKind::Ses, &empty, key()).is_err());
        assert!(
            builder
                .build(
                    &r,
                    SenderKind::Ses,
                    &serde_json::json!({"region": "eu-west-1", "endpoint": "http://ses.example.com"}),
                    key()
                )
                .is_err()
        );
    }
}

#[cfg(test)]
mod pim_tests {
    use skein_accounts::{Auth, PimFactory, PimKind, PimSettings};
    use skein_core::AccountId;

    use super::*;

    fn record(pim: PimSettings) -> AccountRecord {
        AccountRecord {
            account: AccountId::new("a").unwrap(),
            provider: ProviderKind::Jmap,
            settings: serde_json::json!({"url": "https://jmap.example.com/.well-known/jmap", "username": "ada@example.com"}),
            auth: Auth::Password,
            include: None,
            exclude: vec![],
            paused: false,
            send: None,
            pim: Some(pim),
        }
    }

    #[test]
    fn builds_every_calendar_and_contacts_provider() {
        let token = || Credentials::AccessToken { token: "t".into() };
        for kind in [PimKind::Google, PimKind::Graph] {
            let settings = PimSettings {
                kind,
                settings: serde_json::Value::Null,
                auth: None,
            };
            assert!(
                PimProviders::default()
                    .build(&record(settings.clone()), &settings, token())
                    .is_ok(),
                "{kind:?}"
            );
        }
        let jmap = PimSettings {
            kind: PimKind::Jmap,
            settings: serde_json::json!({}),
            auth: None,
        };
        assert!(
            PimProviders::default()
                .build(
                    &record(jmap.clone()),
                    &jmap,
                    Credentials::Password { secret: "x".into() }
                )
                .is_ok(),
            "JMAP falls back to the account's mail settings"
        );
        let google = PimSettings {
            kind: PimKind::Google,
            settings: serde_json::Value::Null,
            auth: None,
        };
        assert!(
            PimProviders::default()
                .build(
                    &record(google.clone()),
                    &google,
                    Credentials::Password { secret: "x".into() }
                )
                .is_err(),
            "Google needs a token"
        );
    }
}

#[cfg(test)]
mod throttle_tests {
    use skein_accounts::{Auth, PimFactory, PimKind, PimSettings};

    use super::*;

    fn graph(account: &str) -> AccountRecord {
        AccountRecord {
            account: AccountId::new(account).unwrap(),
            provider: ProviderKind::Graph,
            settings: serde_json::json!({}),
            auth: Auth::OAuth {
                client: "microsoft".into(),
            },
            include: None,
            exclude: vec![],
            paused: false,
            send: None,
            pim: None,
        }
    }

    #[test]
    fn graph_mail_calendars_and_sending_of_one_account_share_one_throttle() {
        let throttles = Throttles::default();
        let token = || Credentials::AccessToken { token: "t".into() };
        let tenant = TenantId::new("t1").unwrap();
        let pim = PimSettings {
            kind: PimKind::Graph,
            settings: serde_json::Value::Null,
            auth: None,
        };
        let empty = serde_json::json!({});
        let a = graph("a");
        Providers::new(throttles.clone())
            .build_in(&tenant, &a, token())
            .unwrap();
        PimProviders::new(throttles.clone())
            .build_in(&tenant, &a, &pim, token())
            .unwrap();
        SenderBuilder::new(throttles.clone())
            .build_in(&tenant, &a, SenderKind::Graph, &empty, token())
            .unwrap();
        assert_eq!(throttles.len(), 1);
        Providers::new(throttles.clone())
            .build_in(&tenant, &graph("b"), token())
            .unwrap();
        Providers::new(throttles.clone())
            .build_in(&TenantId::new("t2").unwrap(), &a, token())
            .unwrap();
        assert_eq!(throttles.len(), 3);
        SenderBuilder::new(throttles.clone())
            .build_in(&tenant, &graph("c"), SenderKind::Gmail, &empty, token())
            .unwrap();
        Providers::new(throttles.clone())
            .build(&graph("d"), token())
            .unwrap();
        assert_eq!(
            throttles.len(),
            3,
            "only Graph built for a tenant is throttled"
        );
    }
}
