//! The node's own stored records and their decoders. Every decoder reads bytes that came out of
//! storage (sealed, but storage is not trusted to be well-formed), refuses anything over its cap
//! or of another format version, never panics, and has a fuzz target.

use rowboat_api::{AccountId, Draft, EmailAddress, MailboxId, check};
use serde::{Deserialize, Serialize};

/// The format version of every record below.
pub const FORMAT: u16 = 1;
/// Most bytes of a node record or account record.
pub const MAX_SMALL_RECORD: usize = 64 * 1024;
/// Most bytes of a draft record: the attachment cap, base64-sized in JSON, plus text.
pub const MAX_DRAFT_RECORD: usize = 40 * 1024 * 1024;

/// Why a record did not decode. Carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the record does not decode")]
pub struct BadRecord;

/// `system/node`: written last on the first run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    /// [`FORMAT`].
    pub v: u16,
    /// The node id.
    pub node: String,
    /// The group id, also Skein's tenant.
    pub group: String,
    /// The profile name the directory was created with.
    pub profile: String,
    /// When it was created, milliseconds since the epoch.
    pub created_at: i64,
}

fn small_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Encodes a node record.
pub fn encode_node_record(record: &NodeRecord) -> Vec<u8> {
    serde_json::to_vec(record).unwrap_or_default()
}

/// Decodes a node record: at most [`MAX_SMALL_RECORD`] bytes, version [`FORMAT`], ids of
/// `[a-z0-9_-]{1,64}`.
pub fn decode_node_record(bytes: &[u8]) -> Result<NodeRecord, BadRecord> {
    if bytes.len() > MAX_SMALL_RECORD {
        return Err(BadRecord);
    }
    let r: NodeRecord = serde_json::from_slice(bytes).map_err(|_| BadRecord)?;
    if r.v != FORMAT || !small_id(&r.node) || !small_id(&r.group) || !small_id(&r.profile) {
        return Err(BadRecord);
    }
    Ok(r)
}

/// What the node keeps about an account beyond Skein's account record:
/// `rowboat/accounts/{account}` in the group's control records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountMeta {
    /// [`FORMAT`].
    pub v: u16,
    /// The account.
    pub account: AccountId,
    /// Its address.
    pub address: EmailAddress,
    /// Its display name.
    pub display_name: Option<String>,
    /// The mailbox `archive` moves to when the provider names no archive mailbox.
    #[serde(default)]
    pub archive: Option<MailboxId>,
    /// Removal started; the node finishes it.
    #[serde(default)]
    pub removing: bool,
    /// New mail may notify.
    #[serde(default = "notify_default")]
    pub notify: bool,
    /// When it was added.
    pub created_at: i64,
}

fn notify_default() -> bool {
    true
}

/// Encodes an account record.
pub fn encode_account_meta(meta: &AccountMeta) -> Vec<u8> {
    serde_json::to_vec(meta).unwrap_or_default()
}

/// Decodes an account record: at most [`MAX_SMALL_RECORD`] bytes, version [`FORMAT`], every id
/// checked by its type, a one-line display name.
pub fn decode_account_meta(bytes: &[u8]) -> Result<AccountMeta, BadRecord> {
    if bytes.len() > MAX_SMALL_RECORD {
        return Err(BadRecord);
    }
    let m: AccountMeta = serde_json::from_slice(bytes).map_err(|_| BadRecord)?;
    if m.v != FORMAT
        || m.display_name
            .as_deref()
            .is_some_and(|n| !check::one_line(n, rowboat_api::MAX_NAME_CHARS))
    {
        return Err(BadRecord);
    }
    Ok(m)
}

/// A local draft: `system/drafts/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftRecord {
    /// [`FORMAT`].
    pub v: u16,
    /// When it was last saved.
    pub updated_at: i64,
    /// The send command it is waiting behind, while it is being sent; hidden from lists then.
    #[serde(default)]
    pub sending: Option<String>,
    /// The draft, with its id set.
    pub draft: Draft,
}

/// Encodes a draft record.
pub fn encode_draft_record(record: &DraftRecord) -> Vec<u8> {
    serde_json::to_vec(record).unwrap_or_default()
}

/// Decodes a draft record: at most [`MAX_DRAFT_RECORD`] bytes, version [`FORMAT`], an id, the
/// draft passing `rowboat_api::check::draft`, and a ULID for `sending`.
pub fn decode_draft_record(bytes: &[u8]) -> Result<DraftRecord, BadRecord> {
    if bytes.len() > MAX_DRAFT_RECORD {
        return Err(BadRecord);
    }
    let r: DraftRecord = serde_json::from_slice(bytes).map_err(|_| BadRecord)?;
    if r.v != FORMAT
        || r.draft.id.is_none()
        || check::draft(&r.draft).is_err()
        || r.sending
            .as_deref()
            .is_some_and(|s| !rowboat_api::is_ulid(s))
    {
        return Err(BadRecord);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rowboat_api::DraftId;

    use super::*;

    fn draft() -> Draft {
        Draft {
            id: Some(DraftId::new("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap()),
            account: AccountId::new(format!("a{}", "b".repeat(26))).unwrap(),
            to: vec![],
            cc: vec![],
            bcc: vec![],
            subject: "s".into(),
            text: "t".into(),
            reply: None,
            attachments: vec![],
        }
    }

    #[test]
    fn records_round_trip_and_refuse_other_versions() {
        let n = NodeRecord {
            v: FORMAT,
            node: "abc".into(),
            group: "gabc".into(),
            profile: "desktop".into(),
            created_at: 1,
        };
        assert_eq!(decode_node_record(&encode_node_record(&n)).unwrap(), n);
        let mut old = n.clone();
        old.v = 2;
        assert!(decode_node_record(&encode_node_record(&old)).is_err());
        let mut bad = n;
        bad.group = "../x".into();
        assert!(decode_node_record(&encode_node_record(&bad)).is_err());

        let d = DraftRecord {
            v: FORMAT,
            updated_at: 5,
            sending: None,
            draft: draft(),
        };
        assert_eq!(decode_draft_record(&encode_draft_record(&d)).unwrap(), d);
        let mut no_id = d.clone();
        no_id.draft.id = None;
        assert!(decode_draft_record(&encode_draft_record(&no_id)).is_err());
        let mut injected = d.clone();
        injected.draft.subject = "a\r\nBcc: x@example.net".into();
        assert!(decode_draft_record(&encode_draft_record(&injected)).is_err());
        let mut sending = d;
        sending.sending = Some("not-a-ulid".into());
        assert!(decode_draft_record(&encode_draft_record(&sending)).is_err());

        let m = AccountMeta {
            v: FORMAT,
            account: draft().account,
            address: EmailAddress::new("pat@example.com").unwrap(),
            display_name: Some("Pat".into()),
            archive: None,
            removing: false,
            notify: false,
            created_at: 3,
        };
        assert_eq!(decode_account_meta(&encode_account_meta(&m)).unwrap(), m);
        let older = format!(
            r#"{{"v":1,"account":"{}","address":"pat@example.com","created_at":1}}"#,
            draft().account
        );
        assert!(decode_account_meta(older.as_bytes()).unwrap().notify);
        let forged = br#"{"v":1,"account":"a","address":"pat@example.com","created_at":1}"#;
        assert!(decode_account_meta(forged).is_err());
    }

    proptest! {
        #[test]
        fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = decode_node_record(&bytes);
            let _ = decode_draft_record(&bytes);
            let _ = decode_account_meta(&bytes);
        }
    }
}
