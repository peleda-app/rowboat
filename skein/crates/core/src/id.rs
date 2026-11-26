use std::fmt;

use baton_core::{InvalidId, MAX_ID_LEN, reserved_name};
use serde::{Deserialize, Deserializer, Serialize};

fn check(value: &str) -> Result<(), InvalidId> {
    let ok = !value.is_empty()
        && value.len() <= MAX_ID_LEN
        && !value.starts_with('-')
        && !reserved_name(value)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if ok { Ok(()) } else { Err(InvalidId) }
}

fn check_tenant(value: &str) -> Result<(), InvalidId> {
    check(value)?;
    if value.starts_with('_') {
        Err(InvalidId)
    } else {
        Ok(())
    }
}

macro_rules! id {
    ($(#[$doc:meta])* $name:ident, $check:ident) => {
        $(#[$doc])*
        ///
        /// Ids are 1 to 64 characters of `[a-z0-9_-]`, never start with `-` and are never a Windows
        /// device name (`con`, `nul`, `com1`, ...), so they are safe as a single path segment in any
        /// storage key or file system: no separators, no `.` or `..`, no case folding, no reserved
        /// names. These are the rules of Baton's ids, so every tenant is a valid group and every
        /// account a valid lease key (see `skein_core::coordination`).
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Checks and wraps `value`.
            pub fn new(value: impl Into<String>) -> Result<Self, InvalidId> {
                let value = value.into();
                $check(&value)?;
                Ok(Self(value))
            }

            /// The id as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = InvalidId;
            fn from_str(s: &str) -> Result<Self, InvalidId> {
                Self::new(s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::new(s).map_err(serde::de::Error::custom)
            }
        }
    };
}

id!(
    /// A tenant: an id from the integrator's side that owns accounts, keys and data.
    ///
    /// A tenant id never starts with `_`: those ids are reserved for Skein's own coordination
    /// records (the group every node heartbeats in), so no tenant can be registered, purged,
    /// exported or read under them. Only [`crate::coordination::tenant`] yields such a value.
    TenantId,
    check_tenant
);
id!(
    /// An account within a tenant.
    AccountId,
    check
);

impl TenantId {
    pub(crate) fn of_group(group: &str) -> Self {
        debug_assert!(check(group).is_ok());
        Self(group.to_owned())
    }

    /// Whether this is one of Skein's own reserved groups rather than an integrator's tenant (it
    /// starts with `_`).
    pub fn is_reserved(&self) -> bool {
        self.0.starts_with('_')
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn accepts_safe_ids() {
        for ok in ["a", "acme", "user_1", "x-y", "0", &"a".repeat(64)] {
            assert!(TenantId::new(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn refuses_anything_that_could_escape_a_path_segment() {
        for bad in [
            "",
            "..",
            ".",
            "a/b",
            "a\\b",
            "A",
            "a b",
            "-a",
            "é",
            "a.b",
            "a\0",
            &"a".repeat(65),
        ] {
            assert!(TenantId::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn refuses_device_names() {
        for bad in ["con", "nul", "aux", "prn", "com1", "lpt9"] {
            assert!(TenantId::new(bad).is_err(), "{bad}");
            assert!(AccountId::new(bad).is_err(), "{bad}");
            assert!(serde_json::from_str::<TenantId>(&format!("\"{bad}\"")).is_err());
        }
        for ok in ["con1", "console", "com10", "nul_", "lpt"] {
            assert!(TenantId::new(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn tenants_starting_with_an_underscore_are_reserved() {
        for bad in ["_nodes", "_", "_x"] {
            assert!(TenantId::new(bad).is_err(), "{bad}");
            assert!(bad.parse::<TenantId>().is_err(), "{bad}");
            assert!(serde_json::from_str::<TenantId>(&format!("\"{bad}\"")).is_err());
            assert!(AccountId::new(bad).is_ok(), "{bad}");
        }
        assert!(TenantId::new("a_").is_ok());
    }

    #[test]
    fn deserializing_checks_too() {
        assert!(serde_json::from_str::<AccountId>("\"../x\"").is_err());
        assert_eq!(
            serde_json::from_str::<AccountId>("\"ok\"")
                .unwrap()
                .as_str(),
            "ok"
        );
    }

    proptest! {
        #[test]
        fn same_rules_as_baton_ids(s in "[a-z0-9_-]{0,66}|con|nul|com[0-9]|lpt[0-9]|aux|prn") {
            prop_assert_eq!(TenantId::new(s.clone()).is_ok(), baton_core::GroupId::new(s.clone()).is_ok() && !s.starts_with('_'));
            prop_assert_eq!(AccountId::new(s.clone()).is_ok(), baton_core::LeaseKey::new(s).is_ok());
        }

        #[test]
        fn valid_ids_never_contain_separators(s in "\\PC{0,80}") {
            if let Ok(id) = TenantId::new(s) {
                prop_assert!(!id.as_str().contains('/'));
                prop_assert!(!id.as_str().contains('.'));
                prop_assert!(!id.as_str().starts_with('-'));
            }
        }
    }
}
