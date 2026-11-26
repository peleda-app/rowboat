use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::StorageError;

/// A control record in its envelope: the schema version it was written with and the data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record<T> {
    /// Schema version of `data`.
    pub v: u16,
    /// The record.
    pub data: T,
}

/// A record type with a current version and a way to read every older one.
pub trait Migrate: Serialize + DeserializeOwned {
    /// The version this build writes.
    const VERSION: u16;

    /// Reads data written with version `v` (older than [`Self::VERSION`]). The default refuses
    /// every older version.
    fn migrate(v: u16, data: serde_json::Value) -> Result<Self, String> {
        let _ = data;
        Err(format!("no migration from version {v}"))
    }
}

/// Encodes `data` with the current version.
pub fn encode_record<T: Migrate>(data: &T) -> Result<bytes::Bytes, StorageError> {
    let record = Record {
        v: T::VERSION,
        data,
    };
    serde_json::to_vec(&record)
        .map(bytes::Bytes::from)
        .map_err(|e| StorageError::Corrupt(e.to_string()))
}

/// Decodes a record of any known version, upgrading older ones. A version newer than this
/// build's is refused rather than read wrongly.
pub fn decode_record<T: Migrate>(bytes: &[u8]) -> Result<T, StorageError> {
    let record: Record<serde_json::Value> =
        serde_json::from_slice(bytes).map_err(|e| StorageError::Corrupt(e.to_string()))?;
    match record.v {
        v if v == T::VERSION => {
            serde_json::from_value(record.data).map_err(|e| StorageError::Corrupt(e.to_string()))
        }
        v if v > T::VERSION => Err(StorageError::Corrupt(format!(
            "record version {v} is newer than this build's {}",
            T::VERSION
        ))),
        v => T::migrate(v, record.data).map_err(StorageError::Corrupt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Account {
        name: String,
        interval_s: u32,
    }

    impl Migrate for Account {
        const VERSION: u16 = 2;
        fn migrate(v: u16, data: serde_json::Value) -> Result<Self, String> {
            match v {
                1 => Ok(Account {
                    name: data["name"].as_str().ok_or("name")?.to_owned(),
                    interval_s: 300,
                }),
                _ => Err(format!("unknown version {v}")),
            }
        }
    }

    #[test]
    fn upgrades_old_versions_and_refuses_newer_ones() {
        let old = br#"{"v":1,"data":{"name":"x"}}"#;
        assert_eq!(
            decode_record::<Account>(old).unwrap(),
            Account {
                name: "x".into(),
                interval_s: 300
            }
        );
        let current = encode_record(&Account {
            name: "y".into(),
            interval_s: 5,
        })
        .unwrap();
        assert_eq!(decode_record::<Account>(&current).unwrap().interval_s, 5);
        assert!(decode_record::<Account>(br#"{"v":3,"data":{}}"#).is_err());
    }
}
