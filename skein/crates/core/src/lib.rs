//! Ids, hashes, timestamps, events and commands shared by every Skein module.
//!
//! Everything here is plain data: no I/O, no provider code. Events and commands are the journal's
//! wire format, so their serialized form is a public contract with a schema version.

mod command;
pub mod coordination;
mod event;
mod hash;
mod id;
mod schedule;
mod status;
mod time;
pub mod tls;

pub use baton_core::{FencingToken, GroupId, InvalidId, LeaseKey, NodeId};
pub use command::{
    Command, CommandBody, CommandId, Dsn, DsnNotify, DsnReturn, InvalidEnvelope, MAX_RECIPIENTS,
    SendEnvelope, plausible_address,
};
pub use event::{
    AccountHealth, CollectionInfo, CollectionKind, CollectionRole, Event, EventBody, Flags,
    ItemRef, MailCapabilities, MailboxInfo, MailboxRole, RefusedRecipient, SCHEMA_VERSION,
    SentCopy,
};
pub use hash::{BlobHash, InvalidHash};
pub use id::{AccountId, TenantId};
pub use schedule::{
    ItipAttendee, ItipSummary, PartStat, ScheduleMessage, ScheduleStatus, ScheduleVia,
};
pub use status::{AccountStatus, DomainStatus, SyncOutcome};
pub use time::Timestamp;
pub use tls::{InvalidRoots, TlsRoots};

/// Position of an event in one account's log. The first event is `Seq(1)`; numbers never repeat
/// and never leave gaps in a committed log.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(transparent)]
pub struct Seq(pub u64);

impl Seq {
    /// The position after this one.
    pub fn next(self) -> Seq {
        Seq(self.0 + 1)
    }
}

/// The kinds of data an account can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    /// Messages and mailboxes.
    Mail,
    /// Events and calendars.
    Calendar,
    /// Contacts and address books.
    Contacts,
}

/// What an account signs in with. `Debug` never shows the secret.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Credentials {
    /// A password or app password.
    Password {
        /// The secret.
        secret: String,
    },
    /// An OAuth access token, used as a bearer or with `XOAUTH2`.
    AccessToken {
        /// The token.
        token: String,
    },
    /// A cloud access key pair, used to sign requests (AWS Signature Version 4), with a session
    /// token when the key is temporary.
    AccessKey {
        /// The access key id.
        id: String,
        /// The secret access key.
        secret: String,
        /// The session token of temporary credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
    },
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { .. } => f.write_str("Credentials::Password(<redacted>)"),
            Self::AccessToken { .. } => f.write_str("Credentials::AccessToken(<redacted>)"),
            Self::AccessKey { .. } => f.write_str("Credentials::AccessKey(<redacted>)"),
        }
    }
}

#[cfg(test)]
mod credential_tests {
    use super::*;

    #[test]
    fn debug_never_shows_secrets() {
        let c = Credentials::Password {
            secret: "hunter2".into(),
        };
        assert!(!format!("{c:?}").contains("hunter2"));
        let t = Credentials::AccessToken {
            token: "ya29.secret".into(),
        };
        assert!(!format!("{t:?}").contains("ya29"));
        let k = Credentials::AccessKey {
            id: "AKIDEXAMPLE".into(),
            secret: "wJalrXUtnFEMI".into(),
            session_token: Some("session".into()),
        };
        let shown = format!("{k:?}");
        assert!(!shown.contains("AKID") && !shown.contains("wJal") && !shown.contains("session"));
    }
}

#[cfg(test)]
mod baton_id_tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn fences_keep_their_serialized_form() {
        assert_eq!(serde_json::to_string(&FencingToken(7)).unwrap(), "7");
        let stored: AccountStatus = serde_json::from_str(r#"{"fence":7}"#).unwrap();
        assert_eq!(stored.fence, FencingToken(7));
        assert_eq!(AccountStatus::default().fence, FencingToken(0));
    }

    #[test]
    fn node_ids_keep_their_serialized_form() {
        let id: NodeId = serde_json::from_str("\"node-a\"").unwrap();
        assert_eq!(id.as_str(), "node-a");
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"node-a\"");
        assert!(serde_json::from_str::<NodeId>("\"../x\"").is_err());
    }

    #[test]
    fn ids_refuse_windows_device_names() {
        for name in ["con", "nul", "com1", "lpt9", "aux", "prn"] {
            assert_eq!(TenantId::new(name), Err(InvalidId), "{name}");
            assert_eq!(NodeId::new(name), Err(InvalidId), "{name}");
            assert!(serde_json::from_str::<NodeId>(&format!("\"{name}\"")).is_err());
        }
    }

    proptest! {
        #[test]
        fn every_former_node_id_reads_unless_it_is_a_device_name(s in "[a-z0-9_-]{1,64}") {
            if !s.starts_with('-') {
                prop_assert_eq!(NodeId::new(s.clone()).is_ok(), !baton_core::reserved_name(&s));
                prop_assert_eq!(TenantId::new(s.clone()).is_ok(), !baton_core::reserved_name(&s) && !s.starts_with('_'));
            }
        }
    }
}
