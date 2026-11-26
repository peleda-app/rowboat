//! [`Objects`] in S3-compatible object storage.
//!
//! Compare-and-swap relies on conditional writes (`If-None-Match: *` and `If-Match`), which the
//! store must support: AWS S3, Cloudflare R2, RustFS and Versity S3 Gateway do. Any other store must pass the
//! conformance suite before it is trusted.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path;
use object_store::{
    GetResult, ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion,
};
use skein_storage::{Expect, ObjectKey, Objects, StorageError, Version};

/// Connection settings for an S3-compatible store.
///
/// `Debug` never prints the secret access key.
#[derive(Clone)]
pub struct S3Config {
    /// Endpoint URL for stores other than AWS S3, such as `https://<account>.r2.cloudflarestorage.com`
    /// or `http://127.0.0.1:9000`; `None` means AWS S3 in `region`.
    pub endpoint: Option<String>,
    /// The bucket; it must exist.
    pub bucket: String,
    /// The region, such as `us-east-1`; S3-compatible stores usually accept any value.
    pub region: String,
    /// Path inside the bucket under which every key is stored, such as `skein/prod`.
    pub prefix: Option<String>,
    /// Access key id.
    pub access_key_id: String,
    /// Secret access key.
    pub secret_access_key: String,
    /// Allows a plain `http://` endpoint. Honoured only when the endpoint host is a loopback
    /// address or `localhost`; any other plain-HTTP endpoint is refused.
    pub allow_http: bool,
}

impl fmt::Debug for S3Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("prefix", &self.prefix)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("allow_http", &self.allow_http)
            .finish()
    }
}

/// Why a configuration was refused.
#[derive(Debug, thiserror::Error)]
pub enum S3ConfigError {
    /// A plain-HTTP endpoint that is not loopback, or one given without `allow_http`.
    #[error("plain http is allowed only for loopback endpoints with allow_http set")]
    PlainHttp,
    /// The endpoint is not an `http://` or `https://` URL with a host.
    #[error("the endpoint is not a valid http(s) URL")]
    InvalidEndpoint,
    /// The prefix holds an empty, `.`/`..` or otherwise unusable segment.
    #[error("the prefix is not a valid object path")]
    InvalidPrefix,
    /// The client could not be built from the configuration.
    #[error("cannot build the S3 client: {0}")]
    Build(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// An object store in an S3-compatible bucket.
///
/// Guarantees, beyond the [`Objects`] contract:
///
/// - Writes are single requests; compare-and-swap is enforced by the store's conditional writes,
///   so it holds across processes and machines.
/// - The version is the store's ETag; compare-and-swap is `If-Match` on it. Object version ids
///   are ignored, since stores disagree on when they return them (Garage sends one on `PUT` but
///   not on `GET`) and `If-Match` only needs the ETag. Stores whose ETag is a content hash return the same version when identical bytes
///   are written again.
/// - Deletes with an expectation read the version first and then delete, leaving the short race
///   the contract allows.
/// - `list` relies on the store listing keys in ascending byte order, as S3 does.
pub struct S3Objects {
    store: Arc<dyn ObjectStore>,
    prefix: Option<Path>,
}

fn loopback(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The host of an `http(s)://` URL and whether it is plain HTTP.
fn endpoint_host(endpoint: &str) -> Result<(bool, &str), S3ConfigError> {
    let lower = endpoint.to_ascii_lowercase();
    let (plain, rest) = if lower.starts_with("http://") {
        (true, &endpoint[7..])
    } else if lower.starts_with("https://") {
        (false, &endpoint[8..])
    } else {
        return Err(S3ConfigError::InvalidEndpoint);
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Err(S3ConfigError::InvalidEndpoint);
    }
    let host = if authority.starts_with('[') {
        authority
            .find(']')
            .map(|i| &authority[..=i])
            .ok_or(S3ConfigError::InvalidEndpoint)?
    } else {
        authority.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        return Err(S3ConfigError::InvalidEndpoint);
    }
    Ok((plain, host))
}

fn parse_prefix(prefix: Option<&str>) -> Result<Option<Path>, S3ConfigError> {
    let Some(p) = prefix
        .map(|p| p.trim_matches('/'))
        .filter(|p| !p.is_empty())
    else {
        return Ok(None);
    };
    if p.split('/').any(|s| s.is_empty() || s == "." || s == "..") {
        return Err(S3ConfigError::InvalidPrefix);
    }
    Path::parse(p)
        .map(Some)
        .map_err(|_| S3ConfigError::InvalidPrefix)
}

impl S3Objects {
    /// Connects to the store described by `config`. No request is made until the first
    /// operation; a missing bucket or wrong credentials show up as backend errors then.
    pub fn new(config: &S3Config) -> Result<Self, S3ConfigError> {
        let mut allow_http = false;
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&config.bucket)
            .with_region(&config.region)
            .with_access_key_id(&config.access_key_id)
            .with_secret_access_key(&config.secret_access_key);
        if let Some(endpoint) = &config.endpoint {
            let (plain, host) = endpoint_host(endpoint)?;
            if plain {
                if !config.allow_http || !loopback(host) {
                    return Err(S3ConfigError::PlainHttp);
                }
                allow_http = true;
            }
            builder = builder.with_endpoint(endpoint);
        }
        let store = builder
            .with_allow_http(allow_http)
            .build()
            .map_err(|e| S3ConfigError::Build(Box::new(e)))?;
        Self::with_store(Arc::new(store), config.prefix.as_deref())
    }

    /// Uses any object store, such as `object_store::memory::InMemory` in tests. The store must
    /// support conditional puts ([`PutMode::Create`] and [`PutMode::Update`]).
    pub fn with_store(
        store: Arc<dyn ObjectStore>,
        prefix: Option<&str>,
    ) -> Result<Self, S3ConfigError> {
        Ok(Self {
            store,
            prefix: parse_prefix(prefix)?,
        })
    }

    fn path(&self, key: &ObjectKey) -> Path {
        let mut path = self.prefix.clone().unwrap_or_default();
        for segment in key.segments() {
            path = path.join(segment);
        }
        path
    }

    fn key_of(&self, path: &Path) -> Option<ObjectKey> {
        let text = path.as_ref();
        let rest = match &self.prefix {
            Some(p) => text.strip_prefix(p.as_ref())?.strip_prefix('/')?,
            None => text,
        };
        ObjectKey::parse(rest).ok()
    }

    async fn head_version(&self, path: &Path) -> Result<Option<Version>, StorageError> {
        match self.store.head(path).await {
            Ok(meta) => Ok(Some(encode_version(meta.e_tag, meta.version))),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(backend(e)),
        }
    }
}

fn encode_version(e_tag: Option<String>, _version: Option<String>) -> Version {
    Version(e_tag.unwrap_or_default())
}

fn decode_version(v: &Version) -> Option<UpdateVersion> {
    if v.0.is_empty() {
        return None;
    }
    Some(UpdateVersion {
        e_tag: Some(v.0.clone()),
        version: None,
    })
}

#[derive(Debug, thiserror::Error)]
#[error("object store request failed: {0}")]
struct RequestFailed(&'static str);

fn backend(e: object_store::Error) -> StorageError {
    use object_store::Error as E;
    let kind = match &e {
        E::Generic { .. } => "generic",
        E::NotFound { .. } => "not found",
        E::InvalidPath { .. } => "invalid path",
        E::JoinError { .. } => "join",
        E::NotSupported { .. } => "not supported",
        E::AlreadyExists { .. } => "already exists",
        E::Precondition { .. } => "precondition",
        E::NotModified { .. } => "not modified",
        E::NotImplemented { .. } => "not implemented",
        E::PermissionDenied { .. } => "permission denied",
        E::Unauthenticated { .. } => "unauthenticated",
        E::UnknownConfigurationKey { .. } => "configuration",
        _ => "other",
    };
    tracing::debug!(error = %e, "object store request failed");
    StorageError::backend(RequestFailed(kind))
}

async fn read_body(result: GetResult) -> Result<(Bytes, Version), StorageError> {
    let version = encode_version(result.meta.e_tag.clone(), result.meta.version.clone());
    let body = result.bytes().await.map_err(backend)?;
    Ok((body, version))
}

#[async_trait]
impl Objects for S3Objects {
    async fn get(&self, key: &ObjectKey) -> Result<Option<(Bytes, Version)>, StorageError> {
        match self.store.get(&self.path(key)).await {
            Ok(result) => read_body(result).await.map(Some),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(backend(e)),
        }
    }

    async fn put(
        &self,
        key: &ObjectKey,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StorageError> {
        let mode = match expect {
            Expect::Any => PutMode::Overwrite,
            Expect::Absent => PutMode::Create,
            Expect::Version(v) => {
                PutMode::Update(decode_version(&v).ok_or(StorageError::Conflict)?)
            }
        };
        let options = PutOptions {
            mode,
            ..Default::default()
        };
        match self
            .store
            .put_opts(&self.path(key), PutPayload::from_bytes(value), options)
            .await
        {
            Ok(r) => Ok(encode_version(r.e_tag, r.version)),
            Err(
                object_store::Error::AlreadyExists { .. }
                | object_store::Error::Precondition { .. }
                | object_store::Error::NotFound { .. },
            ) => Err(StorageError::Conflict),
            Err(e) => Err(backend(e)),
        }
    }

    async fn delete(&self, key: &ObjectKey, expect: Expect) -> Result<(), StorageError> {
        let path = self.path(key);
        if !matches!(expect, Expect::Any) {
            let current = self.head_version(&path).await?;
            match (&expect, current) {
                (Expect::Absent, None) => return Ok(()),
                (Expect::Version(v), Some(c)) if *v == c => {}
                _ => return Err(StorageError::Conflict),
            }
        }
        match self.store.delete(&path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(backend(e)),
        }
    }

    async fn list(
        &self,
        prefix: &ObjectKey,
        start_after: Option<&ObjectKey>,
        limit: usize,
    ) -> Result<Vec<ObjectKey>, StorageError> {
        let mut out = Vec::new();
        if limit == 0 {
            return Ok(out);
        }
        let base = self.path(prefix);
        let mut stream = match start_after {
            Some(after) => self.store.list_with_offset(Some(&base), &self.path(after)),
            None => self.store.list(Some(&base)),
        };
        while let Some(meta) = stream.try_next().await.map_err(backend)? {
            if meta.location == base {
                continue;
            }
            let Some(key) = self.key_of(&meta.location) else {
                continue;
            };
            if start_after.is_some_and(|a| key <= *a) || !key.starts_with(prefix) {
                continue;
            }
            out.push(key);
            if out.len() == limit {
                break;
            }
        }
        out.sort_unstable();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use object_store::memory::InMemory;

    use super::*;

    fn config(endpoint: Option<&str>, allow_http: bool) -> S3Config {
        S3Config {
            endpoint: endpoint.map(str::to_owned),
            bucket: "skein-test".into(),
            region: "us-east-1".into(),
            prefix: None,
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "very-secret-example".into(),
            allow_http,
        }
    }

    #[tokio::test]
    async fn conformance() {
        let store = S3Objects::with_store(Arc::new(InMemory::new()), None).unwrap();
        skein_storage::testing::all_over_objects(Arc::new(store)).await;
    }

    #[tokio::test]
    async fn conformance_under_a_prefix() {
        let inner = Arc::new(InMemory::new());
        let other = S3Objects::with_store(inner.clone(), Some("other")).unwrap();
        let k = ObjectKey::parse("conf-objects/l/zz").unwrap();
        other.put(&k, Bytes::new(), Expect::Any).await.unwrap();
        let store = S3Objects::with_store(inner, Some("/skein/prod/")).unwrap();
        skein_storage::testing::all_over_objects(Arc::new(store)).await;
    }

    #[test]
    fn debug_redacts_the_secret() {
        let text = format!("{:?}", config(None, false));
        assert!(!text.contains("very-secret-example"));
        assert!(text.contains("<redacted>"));
    }

    #[test]
    fn plain_http_only_to_loopback() {
        for ok in [
            "http://127.0.0.1:9000",
            "http://localhost:9000/",
            "http://[::1]:9000",
            "https://s3.example.com",
        ] {
            assert!(S3Objects::new(&config(Some(ok), true)).is_ok(), "{ok}");
        }
        for bad in [
            "http://s3.example.com",
            "http://10.0.0.5:9000",
            "http://127.0.0.1.example.com",
            "http://user@127.0.0.1:9000",
        ] {
            assert!(S3Objects::new(&config(Some(bad), true)).is_err(), "{bad}");
        }
        assert!(matches!(
            S3Objects::new(&config(Some("http://127.0.0.1:9000"), false)),
            Err(S3ConfigError::PlainHttp)
        ));
        assert!(matches!(
            S3Objects::new(&config(Some("ftp://127.0.0.1"), true)),
            Err(S3ConfigError::InvalidEndpoint)
        ));
    }

    #[test]
    fn bad_prefixes_are_refused() {
        for bad in ["a//b", "a/../b", "./a"] {
            assert!(
                S3Objects::with_store(Arc::new(InMemory::new()), Some(bad)).is_err(),
                "{bad}"
            );
        }
    }
}
