//! Tenants on disk: their ids, where their pieces live, their record and their binding.
//!
//! ```text
//! <data_dir>/tenants/<id>/tenant.json    the tenant's record (id, creation time, link port)
//! <data_dir>/tenants/<id>/binding.json   the group it is bound to, written once adopted
//! <data_dir>/tenants/<id>/stop           asks a running `serve` to stop the tenant
//! <data_dir>/tenants/<id>/node/          the node's data directory (sealed objects, lock)
//! <secrets_dir>/tenants/<id>/            the node's keys (rowboat-keystore-file)
//! <cache_dir>/tenants/<id>/view/         the mail database, cleared on every start
//! ```
//!
//! Records are JSON with a version, at most [`MAX_RECORD`] bytes, read strictly: a file that does
//! not decode is an error, never a default.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{Config, Ports};

/// The largest record file read.
pub const MAX_RECORD: usize = 4096;
/// The version of [`TenantRecord`] and [`Binding`].
pub const RECORD_VERSION: u32 = 1;

/// Why a tenant operation failed. Carries ids, never paths or secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TenantError {
    /// The id breaks [`TenantId`]'s rules.
    #[error(
        "a tenant id is 1 to 32 characters of [a-z0-9-], starting with a letter or digit, and not `new`"
    )]
    InvalidId,
    /// No such tenant.
    #[error("no tenant {0}")]
    Unknown(String),
    /// The tenant is bound to a group already; only `--rebind` releases it.
    #[error("tenant {0} is bound to a group; another adoption is refused")]
    Bound(String),
    /// The tenant's node is in use (a running `serve` or another command).
    #[error("tenant {0} is in use by another process")]
    Busy(String),
    /// A record does not decode, or does not match the tenant it sits in.
    #[error("a record of tenant {0} is damaged")]
    Damaged(String),
    /// The tenant's node does not belong to the group its binding names, or its directory holds
    /// another tenant's data.
    #[error("tenant {0} does not match its binding")]
    Mismatch(String),
    /// No port of the range is free for another tenant.
    #[error("no free port is left in link.ports")]
    NoPort,
    /// The invite expired or failed before a device adopted the tenant.
    #[error("the invite ended without an adoption")]
    NotAdopted,
    /// The node could not be built or used.
    #[error("the node of tenant {0} failed: {1}")]
    Node(String, String),
    /// A file could not be read or written.
    #[error("storage of tenant {0} failed")]
    Io(String),
}

/// A tenant id: 1 to 32 characters of `[a-z0-9-]`, starting with a letter or digit, never `new`
/// (which asks for a fresh one). It is a directory name, so nothing in it can leave the
/// tenants directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

impl TenantId {
    /// Checks `text`.
    pub fn parse(text: &str) -> Result<Self, TenantError> {
        let ok = !text.is_empty()
            && text.len() <= 32
            && text != "new"
            && text
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && text
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            Err(TenantError::InvalidId)
        }
    }

    /// A fresh random id: `t` and 12 base32 characters.
    pub fn random() -> Self {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("the system's randomness");
        let mut text = data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase();
        text.truncate(12);
        Self(format!("t{text}"))
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TenantId {
    type Error = TenantError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<TenantId> for String {
    fn from(value: TenantId) -> Self {
        value.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A tenant's record, written when it is created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRecord {
    /// [`RECORD_VERSION`].
    pub v: u32,
    /// The tenant.
    pub id: TenantId,
    /// When it was created, milliseconds since the epoch.
    pub created_ms: i64,
    /// The UDP port its link keeps; `0` with `link.ports = "any"`.
    pub port: u16,
}

/// The group a tenant serves, written once a device adopted it and never changed but by a
/// rebind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    /// [`RECORD_VERSION`].
    pub v: u32,
    /// The tenant.
    pub tenant: TenantId,
    /// The group id.
    pub group: String,
    /// The group's genesis hash, hex.
    pub genesis: String,
    /// The tenant's node id in that group.
    pub node: String,
    /// When it was bound, milliseconds since the epoch.
    pub bound_ms: i64,
}

impl Binding {
    /// The genesis hash.
    pub fn genesis_bytes(&self) -> Option<[u8; 32]> {
        let bytes = data_encoding::HEXLOWER
            .decode(self.genesis.as_bytes())
            .ok()?;
        bytes.try_into().ok()
    }
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Option<T> {
    if bytes.len() > MAX_RECORD {
        return None;
    }
    serde_json::from_slice(bytes).ok()
}

/// Decodes a tenant record; `None` when it is oversized, malformed or of another version.
pub fn decode_record(bytes: &[u8]) -> Option<TenantRecord> {
    decode::<TenantRecord>(bytes).filter(|r| r.v == RECORD_VERSION)
}

/// Decodes a binding; `None` when it is oversized, malformed, of another version or its genesis
/// is not 32 bytes of lowercase hex.
pub fn decode_binding(bytes: &[u8]) -> Option<Binding> {
    decode::<Binding>(bytes)
        .filter(|b| b.v == RECORD_VERSION && b.genesis_bytes().is_some() && b.group.len() <= 64)
}

/// Where everything of the host lives.
#[derive(Debug, Clone)]
pub struct Layout {
    /// The data directory.
    pub data: PathBuf,
    /// The secrets directory.
    pub secrets: PathBuf,
    /// The cache directory.
    pub cache: PathBuf,
    /// The link's port range; `None` for random ports.
    pub ports: Option<Ports>,
}

impl Layout {
    /// The layout of `config`.
    pub fn of(config: &Config) -> Self {
        Self {
            data: config.data_dir.clone(),
            secrets: config.secrets_dir.clone(),
            cache: config.cache(),
            ports: config.link.port_range().ok().flatten(),
        }
    }

    /// `<data>/host`: the host's lock, push registry and status file.
    pub fn host(&self) -> PathBuf {
        self.data.join("host")
    }

    /// The status file `serve` writes.
    pub fn status_file(&self) -> PathBuf {
        self.host().join("status.json")
    }

    fn tenants(&self) -> PathBuf {
        self.data.join("tenants")
    }

    /// The tenant's directory.
    pub fn tenant(&self, id: &TenantId) -> PathBuf {
        self.tenants().join(id.as_str())
    }

    /// The node's data directory.
    pub fn node(&self, id: &TenantId) -> PathBuf {
        self.tenant(id).join("node")
    }

    /// The node's keys.
    pub fn keys(&self, id: &TenantId) -> PathBuf {
        self.secrets.join("tenants").join(id.as_str())
    }

    /// The node's mail database.
    pub fn view(&self, id: &TenantId) -> PathBuf {
        self.cache.join("tenants").join(id.as_str()).join("view")
    }

    /// The stop marker.
    pub fn stop_marker(&self, id: &TenantId) -> PathBuf {
        self.tenant(id).join("stop")
    }

    fn record_path(&self, id: &TenantId) -> PathBuf {
        self.tenant(id).join("tenant.json")
    }

    fn binding_path(&self, id: &TenantId) -> PathBuf {
        self.tenant(id).join("binding.json")
    }

    /// Every tenant directory with a valid id, in id order. Entries with invalid names are
    /// skipped.
    pub fn ids(&self) -> Vec<TenantId> {
        let Ok(entries) = std::fs::read_dir(self.tenants()) else {
            return Vec::new();
        };
        let mut ids: Vec<TenantId> = entries
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().to_str().and_then(|n| TenantId::parse(n).ok()))
            .collect();
        ids.sort();
        ids
    }

    /// The tenant's record.
    pub fn record(&self, id: &TenantId) -> Result<TenantRecord, TenantError> {
        let bytes = read_capped(&self.record_path(id))
            .map_err(|_| TenantError::Unknown(id.to_string()))?
            .ok_or_else(|| TenantError::Unknown(id.to_string()))?;
        decode_record(&bytes)
            .filter(|r| &r.id == id)
            .ok_or_else(|| TenantError::Damaged(id.to_string()))
    }

    /// The tenant's binding, `None` while it is not bound.
    pub fn binding(&self, id: &TenantId) -> Result<Option<Binding>, TenantError> {
        match read_capped(&self.binding_path(id)).map_err(|_| TenantError::Io(id.to_string()))? {
            None => Ok(None),
            Some(bytes) => decode_binding(&bytes)
                .filter(|b| &b.tenant == id)
                .map(Some)
                .ok_or_else(|| TenantError::Damaged(id.to_string())),
        }
    }

    /// Writes the binding (atomically, mode 0600).
    pub fn write_binding(&self, binding: &Binding) -> Result<(), TenantError> {
        let id = binding.tenant.to_string();
        let bytes = serde_json::to_vec_pretty(binding).map_err(|_| TenantError::Io(id.clone()))?;
        write_atomic(&self.binding_path(&binding.tenant), &bytes).map_err(|_| TenantError::Io(id))
    }

    /// Creates a tenant: its directories (mode 0700) and its record with the lowest free port of
    /// the range. `id` defaults to a random one.
    pub fn create(&self, id: Option<TenantId>, now_ms: i64) -> Result<TenantRecord, TenantError> {
        let id = id.unwrap_or_else(TenantId::random);
        if self.record_path(&id).exists() {
            return Err(TenantError::Bound(id.to_string()));
        }
        let port = match self.ports {
            None => 0,
            Some(range) => {
                let taken: std::collections::BTreeSet<u16> = self
                    .ids()
                    .iter()
                    .filter_map(|t| self.record(t).ok())
                    .map(|r| r.port)
                    .collect();
                range
                    .iter()
                    .find(|p| !taken.contains(p))
                    .ok_or(TenantError::NoPort)?
            }
        };
        let io = |_| TenantError::Io(id.to_string());
        private_dir(&self.tenant(&id)).map_err(io)?;
        private_dir(&self.keys(&id)).map_err(io)?;
        let record = TenantRecord {
            v: RECORD_VERSION,
            id: id.clone(),
            created_ms: now_ms,
            port,
        };
        let bytes =
            serde_json::to_vec_pretty(&record).map_err(|_| TenantError::Io(id.to_string()))?;
        write_atomic(&self.record_path(&id), &bytes).map_err(io)?;
        Ok(record)
    }

    /// The link ports every tenant keeps, so pairing endpoints stay off them.
    pub fn reserved_ports(&self) -> std::collections::BTreeSet<u16> {
        self.ids()
            .iter()
            .filter_map(|t| self.record(t).ok())
            .map(|r| r.port)
            .filter(|p| *p != 0)
            .collect()
    }

    /// Deletes the tenant's node data, keys, cache and binding, keeping its record (a rebind),
    /// or everything with `all` (a removal).
    pub fn wipe(&self, id: &TenantId, all: bool) -> Result<(), TenantError> {
        let io = |_| TenantError::Io(id.to_string());
        for dir in [self.node(id), self.keys(id), self.view(id)] {
            remove_dir(&dir).map_err(io)?;
        }
        remove_file(&self.binding_path(id)).map_err(io)?;
        if all {
            remove_dir(&self.tenant(id)).map_err(io)?;
            if let Some(parent) = self.view(id).parent() {
                remove_dir(parent).map_err(io)?;
            }
        } else {
            private_dir(&self.keys(id)).map_err(io)?;
        }
        Ok(())
    }
}

fn read_capped(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
        Ok(m) if !m.is_file() || m.len() > MAX_RECORD as u64 => {
            return Err(std::io::Error::other("not a record"));
        }
        Ok(_) => {}
    }
    std::fs::read(path).map(Some)
}

pub(crate) fn private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent"))?;
    let mut suffix = [0u8; 6];
    getrandom::fill(&mut suffix).map_err(|_| std::io::Error::other("no randomness"))?;
    let temp = dir.join(format!(
        ".{}.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("record"),
        data_encoding::HEXLOWER.encode(&suffix)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn remove_dir(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn remove_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(dir: &Path, ports: Option<Ports>) -> Layout {
        Layout {
            data: dir.join("data"),
            secrets: dir.join("secrets"),
            cache: dir.join("cache"),
            ports,
        }
    }

    #[test]
    fn ids_cannot_leave_the_tenants_directory() {
        for good in ["a", "t0abc", "acme-1", &"a".repeat(32)] {
            assert!(TenantId::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "new",
            "..",
            ".",
            "../b",
            "a/b",
            "A",
            "-a",
            "a b",
            "a\0",
            &"a".repeat(33),
            "ä",
        ] {
            assert_eq!(TenantId::parse(bad), Err(TenantError::InvalidId), "{bad:?}");
        }
        let fresh = TenantId::random();
        assert!(TenantId::parse(fresh.as_str()).is_ok());
        assert_ne!(fresh, TenantId::random());
    }

    #[test]
    fn records_decode_strictly() {
        let binding = Binding {
            v: 1,
            tenant: TenantId::parse("acme").unwrap(),
            group: "gabc".into(),
            genesis: "00".repeat(32),
            node: "n".into(),
            bound_ms: 1,
        };
        let bytes = serde_json::to_vec(&binding).unwrap();
        assert_eq!(decode_binding(&bytes), Some(binding.clone()));
        let mut other = binding.clone();
        other.v = 2;
        assert_eq!(decode_binding(&serde_json::to_vec(&other).unwrap()), None);
        other = binding.clone();
        other.genesis = "zz".repeat(32);
        assert_eq!(decode_binding(&serde_json::to_vec(&other).unwrap()), None);
        other = binding.clone();
        other.genesis = "00".repeat(31);
        assert_eq!(decode_binding(&serde_json::to_vec(&other).unwrap()), None);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert_eq!(
            decode_binding(text.replace("acme", "../x").as_bytes()),
            None
        );
        assert_eq!(
            decode_binding(text.replace("}", ",\"extra\":1}").as_bytes()),
            None
        );
        assert_eq!(decode_binding(&vec![b' '; MAX_RECORD + 1]), None);
        for n in 0..bytes.len() {
            let _ = decode_binding(&bytes[..n]);
            let _ = decode_record(&bytes[..n]);
        }
    }

    #[test]
    fn tenants_get_their_own_directories_and_ports() {
        let dir = tempfile::tempdir().unwrap();
        let l = layout(
            dir.path(),
            Some(Ports {
                first: 5000,
                last: 5001,
            }),
        );
        let a = l.create(Some(TenantId::parse("a").unwrap()), 1).unwrap();
        let b = l.create(None, 2).unwrap();
        assert_eq!((a.port, b.port), (5000, 5001));
        assert_eq!(
            l.create(None, 3).unwrap_err(),
            TenantError::NoPort,
            "a full range refuses another tenant"
        );
        assert_eq!(l.ids(), {
            let mut v = vec![a.id.clone(), b.id.clone()];
            v.sort();
            v
        });
        assert_eq!(l.record(&a.id).unwrap(), a);
        assert_eq!(l.binding(&a.id).unwrap(), None);
        assert!(matches!(
            l.create(Some(a.id.clone()), 4),
            Err(TenantError::Bound(_))
        ));
        assert!(!l.keys(&a.id).starts_with(&l.data));
        assert_eq!(l.reserved_ports().len(), 2);
        std::fs::create_dir_all(l.data.join("tenants").join("Not-An-Id")).unwrap();
        assert_eq!(l.ids().len(), 2, "foreign names are skipped");
    }

    #[test]
    fn a_record_from_another_tenant_is_damage() {
        let dir = tempfile::tempdir().unwrap();
        let l = layout(dir.path(), None);
        let a = l.create(Some(TenantId::parse("a").unwrap()), 1).unwrap();
        let b = l.create(Some(TenantId::parse("b").unwrap()), 1).unwrap();
        std::fs::copy(
            l.tenant(&b.id).join("tenant.json"),
            l.tenant(&a.id).join("tenant.json"),
        )
        .unwrap();
        assert_eq!(l.record(&a.id), Err(TenantError::Damaged("a".into())));
        let binding = Binding {
            v: 1,
            tenant: b.id.clone(),
            group: "g".into(),
            genesis: "11".repeat(32),
            node: "n".into(),
            bound_ms: 1,
        };
        l.write_binding(&binding).unwrap();
        std::fs::copy(
            l.tenant(&b.id).join("binding.json"),
            l.tenant(&a.id).join("binding.json"),
        )
        .unwrap();
        assert_eq!(l.binding(&a.id), Err(TenantError::Damaged("a".into())));
        assert_eq!(l.binding(&b.id).unwrap(), Some(binding));
    }

    #[test]
    fn wiping_keeps_the_record_until_removal() {
        let dir = tempfile::tempdir().unwrap();
        let l = layout(dir.path(), None);
        let a = l.create(None, 1).unwrap();
        std::fs::create_dir_all(l.node(&a.id).join("objects")).unwrap();
        std::fs::write(l.keys(&a.id).join("rowboat.master"), b"k").unwrap();
        l.wipe(&a.id, false).unwrap();
        assert!(!l.node(&a.id).exists());
        assert!(l.keys(&a.id).exists() && std::fs::read_dir(l.keys(&a.id)).unwrap().count() == 0);
        assert!(l.record(&a.id).is_ok());
        l.wipe(&a.id, true).unwrap();
        assert!(!l.tenant(&a.id).exists() && !l.keys(&a.id).exists());
        assert!(l.ids().is_empty());
    }
}
