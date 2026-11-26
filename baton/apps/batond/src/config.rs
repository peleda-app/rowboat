//! batond's configuration: a TOML file.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use baton_core::{GroupId, NodeId};
use baton_identity::PublicKey;
use baton_link::RelayUrl;
use serde::Deserialize;

use crate::BatondError;

/// The whole configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The data directory (default `./batond-data`): holds `node.key` and `state.redb`.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// The groups whose logs batond holds; at least one.
    #[serde(rename = "group")]
    pub groups: Vec<GroupSection>,
    /// The iroh endpoint.
    #[serde(default)]
    pub iroh: IrohSection,
    /// Lease arbiter settings.
    #[serde(default)]
    pub lease: LeaseSection,
    /// The drop service, run in the same process when present.
    #[serde(default)]
    pub drop: Option<baton_drop_service::Config>,
}

/// One held group.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSection {
    /// The group id.
    pub id: GroupId,
    /// The hash of its genesis entry (64 hex digits): the fingerprint from the recovery sheet.
    pub genesis: String,
    /// Node ids admitted to this group's log before they count in it: the founding node until
    /// genesis is pushed, a recovering device. Remove them once they are certified.
    #[serde(default)]
    pub bootstrap: Vec<NodeId>,
}

/// The iroh endpoint.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IrohSection {
    /// Local addresses to bind (default: every interface, random ports).
    pub bind: Vec<SocketAddr>,
    /// Relays to keep a home connection to (default none: direct paths only).
    pub relays: Vec<String>,
    /// Accept classical key exchange when a peer cannot do X25519MLKEM768 (default false).
    pub allow_classical: bool,
}

/// Lease arbiter settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LeaseSection {
    /// The liveness time-to-live in milliseconds (default 15,000).
    pub ttl_ms: u64,
}

impl Default for LeaseSection {
    fn default() -> Self {
        Self {
            ttl_ms: baton_lease_server::ServerConfig::default().ttl_ms,
        }
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("batond-data")
}

/// The most groups one batond holds.
pub const MAX_GROUPS: usize = 1024;

impl Config {
    /// Parses and checks a TOML configuration.
    pub fn parse(text: &str) -> Result<Self, BatondError> {
        let c: Self =
            toml::from_str(text).map_err(|e| BatondError::Config(e.message().to_owned()))?;
        c.check()?;
        Ok(c)
    }

    /// Reads, parses and checks a TOML file.
    pub fn load(path: &Path) -> Result<Self, BatondError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| BatondError::Config(format!("cannot read config: {e}")))?;
        Self::parse(&text)
    }

    fn check(&self) -> Result<(), BatondError> {
        if self.groups.is_empty() || self.groups.len() > MAX_GROUPS {
            return Err(BatondError::Config(format!(
                "between 1 and {MAX_GROUPS} [[group]] sections are needed"
            )));
        }
        let mut seen = BTreeSet::new();
        for g in &self.groups {
            if !seen.insert(&g.id) {
                return Err(BatondError::Config(format!(
                    "group {} is listed twice",
                    g.id
                )));
            }
            g.genesis_hash()?;
            g.bootstrap_keys()?;
        }
        for r in &self.iroh.relays {
            RelayUrl::new(r).map_err(|_| BatondError::Config(format!("bad relay URL {r}")))?;
        }
        if self.lease.ttl_ms < 1000 {
            return Err(BatondError::Config(
                "lease.ttl_ms must be at least 1000".into(),
            ));
        }
        Ok(())
    }

    /// Each group with its genesis hash.
    pub fn genesis(&self) -> Result<Vec<(GroupId, [u8; 32])>, BatondError> {
        self.groups
            .iter()
            .map(|g| Ok((g.id.clone(), g.genesis_hash()?)))
            .collect()
    }

    /// Each group's bootstrap keys.
    pub fn bootstrap(&self) -> Result<BTreeMap<GroupId, BTreeSet<PublicKey>>, BatondError> {
        self.groups
            .iter()
            .map(|g| Ok((g.id.clone(), g.bootstrap_keys()?)))
            .collect()
    }
}

impl GroupSection {
    /// The genesis hash.
    pub fn genesis_hash(&self) -> Result<[u8; 32], BatondError> {
        let raw = data_encoding::HEXLOWER_PERMISSIVE
            .decode(self.genesis.as_bytes())
            .map_err(|_| BatondError::Config(format!("group {}: genesis is not hex", self.id)))?;
        raw.try_into().map_err(|_| {
            BatondError::Config(format!("group {}: genesis must be 32 bytes", self.id))
        })
    }

    /// The bootstrap node keys.
    pub fn bootstrap_keys(&self) -> Result<BTreeSet<PublicKey>, BatondError> {
        self.bootstrap
            .iter()
            .map(|n| {
                PublicKey::from_node_id(n).map_err(|_| {
                    BatondError::Config(format!("group {}: {n} is not a node key", self.id))
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use baton_identity::Identity;

    use super::*;

    fn hex() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn minimal_and_full_files() {
        let c = Config::parse(&format!(
            "[[group]]\nid = \"family\"\ngenesis = \"{}\"",
            hex()
        ))
        .unwrap();
        assert_eq!(c.data_dir, PathBuf::from("batond-data"));
        assert_eq!(c.genesis().unwrap()[0].1, [0xab; 32]);
        assert!(c.drop.is_none());
        assert_eq!(c.lease.ttl_ms, 15_000);
        let node = Identity::generate().node_id();
        let full = format!(
            r#"
            data_dir = "/var/lib/batond"
            [[group]]
            id = "family"
            genesis = "{h}"
            bootstrap = ["{node}"]
            [[group]]
            id = "team"
            genesis = "{H}"
            [iroh]
            bind = ["0.0.0.0:7843"]
            relays = ["https://relay.example.com"]
            [lease]
            ttl_ms = 20000
            [drop]
            realm = "drop.example.com"
            data_dir = "/var/lib/batond/drop"
            [drop.admission]
            work_difficulty = 12
            "#,
            h = hex(),
            H = hex().to_uppercase()
        );
        let c = Config::parse(&full).unwrap();
        assert_eq!(c.groups.len(), 2);
        assert_eq!(c.bootstrap().unwrap()[&c.groups[0].id].len(), 1);
        assert_eq!(c.drop.unwrap().admission.work_difficulty, 12);
    }

    #[test]
    fn bad_files_are_refused() {
        let g = |extra: &str| {
            format!(
                "[[group]]\nid = \"family\"\ngenesis = \"{}\"\n{extra}",
                hex()
            )
        };
        assert!(Config::parse("").is_err(), "no group");
        assert!(Config::parse(&g("bogus = 1")).is_err());
        assert!(
            Config::parse("[[group]]\nid = \"family\"\ngenesis = \"abcd\"").is_err(),
            "short genesis"
        );
        assert!(
            Config::parse(&format!(
                "[[group]]\nid = \"Family\"\ngenesis = \"{}\"",
                hex()
            ))
            .is_err(),
            "bad group id"
        );
        assert!(Config::parse(&g("bootstrap = [\"nope\"]")).is_err());
        assert!(
            Config::parse(&format!("{}\n{}", g(""), g(""))).is_err(),
            "twice"
        );
        assert!(Config::parse(&format!("{}[iroh]\nrelays = [\"ftp://x\"]", g(""))).is_err());
        assert!(Config::parse(&format!("{}[lease]\nttl_ms = 10", g(""))).is_err());
    }
}
