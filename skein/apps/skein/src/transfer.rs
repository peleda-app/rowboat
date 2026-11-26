use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_core::TenantId;
use skein_storage::{Expect, ObjectKey, Objects, StorageError};

/// One object in an export file.
#[derive(Serialize, Deserialize)]
struct Line {
    key: String,
    value: String,
}

/// What a copy or import did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Objects written.
    pub copied: u64,
    /// Objects already there with the same bytes.
    pub same: u64,
    /// Objects already there with other bytes, left alone.
    pub different: u64,
}

fn prefixes(tenant: &TenantId) -> anyhow::Result<Vec<ObjectKey>> {
    Ok(vec![
        ObjectKey::tenant(tenant),
        ObjectKey::root("system")?
            .join("tenants")?
            .join(tenant.as_str())?,
    ])
}

async fn each_object(
    objects: &dyn Objects,
    tenant: &TenantId,
    mut f: impl AsyncFnMut(ObjectKey, Bytes) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    for prefix in prefixes(tenant)? {
        if let Some((value, _)) = objects.get(&prefix).await? {
            f(prefix.clone(), value).await?;
        }
        let mut after = None;
        loop {
            let page = objects.list(&prefix, after.as_ref(), 1000).await?;
            for key in &page {
                if let Some((value, _)) = objects.get(key).await? {
                    f(key.clone(), value).await?;
                }
            }
            if page.len() < 1000 {
                break;
            }
            after = page.last().cloned();
        }
    }
    Ok(())
}

async fn put_new(
    target: &dyn Objects,
    key: &ObjectKey,
    value: Bytes,
    counts: &mut Counts,
) -> anyhow::Result<()> {
    match target.put(key, value.clone(), Expect::Absent).await {
        Ok(_) => counts.copied += 1,
        Err(StorageError::Conflict) => match target.get(key).await? {
            Some((existing, _)) if existing == value => counts.same += 1,
            _ => counts.different += 1,
        },
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Copies every object of `tenant` from `source` to `target`. Objects already in the target are
/// never overwritten: identical ones are counted as the same, others as different. Run it while
/// no node writes the tenant on either side; sealed records stay readable only with the same
/// master key.
pub async fn copy(
    source: Arc<dyn Objects>,
    target: Arc<dyn Objects>,
    tenant: &TenantId,
) -> anyhow::Result<Counts> {
    let mut counts = Counts::default();
    let target = target.clone();
    each_object(&*source, tenant, async |key, value| {
        put_new(&*target, &key, value, &mut counts).await
    })
    .await?;
    Ok(counts)
}

/// Writes every object of `tenant` to `path` as zstd-compressed NDJSON (`{key, value}` with the
/// value in base64). Sealed records stay sealed in the file.
pub async fn export(
    source: Arc<dyn Objects>,
    tenant: &TenantId,
    path: &Path,
) -> anyhow::Result<u64> {
    if path.exists() {
        bail!("{} exists; refusing to overwrite it", path.display());
    }
    let file = std::fs::File::create_new(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    let mut encoder = zstd::Encoder::new(file, 3)?;
    let mut n = 0;
    each_object(&*source, tenant, async |key, value| {
        let line = Line {
            key: key.as_str().to_owned(),
            value: STANDARD.encode(&value),
        };
        serde_json::to_writer(&mut encoder, &line)?;
        encoder.write_all(b"\n")?;
        n += 1;
        Ok(())
    })
    .await?;
    encoder.finish()?.sync_all()?;
    Ok(n)
}

/// Longest line of an export file: an object of up to 192 MiB in base64 plus its key. Longer
/// lines stop the import, so a crafted file cannot exhaust memory while it is decompressed.
pub const MAX_LINE: usize = 256 * 1024 * 1024;

/// Reads an export file into `target`, never overwriting objects that exist. Every key must
/// belong to `tenant`, so a file cannot write another tenant's objects.
pub async fn import(
    target: Arc<dyn Objects>,
    tenant: &TenantId,
    path: &Path,
) -> anyhow::Result<Counts> {
    import_lines(target, tenant, path, MAX_LINE).await
}

async fn import_lines(
    target: Arc<dyn Objects>,
    tenant: &TenantId,
    path: &Path,
    max_line: usize,
) -> anyhow::Result<Counts> {
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut reader = BufReader::new(zstd::Decoder::new(file)?);
    let allowed = prefixes(tenant)?;
    let mut counts = Counts::default();
    let mut line = Vec::new();
    for i in 0.. {
        line.clear();
        let n = (&mut reader)
            .take(max_line as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        if line.len() > max_line {
            bail!(
                "line {} is longer than {max_line} bytes; nothing after it was imported",
                i + 1
            );
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let parsed: Line = serde_json::from_slice(&line)
            .with_context(|| format!("line {} is not an export line", i + 1))?;
        let key = ObjectKey::parse(&parsed.key)
            .with_context(|| format!("line {} has an invalid key", i + 1))?;
        if !allowed.iter().any(|p| key.starts_with(p)) {
            bail!(
                "line {} holds an object of another tenant; nothing after it was imported",
                i + 1
            );
        }
        let value = STANDARD
            .decode(parsed.value)
            .with_context(|| format!("line {} has an invalid value", i + 1))?;
        put_new(&*target, &key, Bytes::from(value), &mut counts).await?;
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use skein_storage::Storage;
    use skein_storage_memory::MemoryObjects;

    use super::*;

    async fn seed(objects: &Arc<dyn Objects>, tenant: &str) {
        let storage = Storage::over(objects.clone());
        let t = TenantId::new(tenant).unwrap();
        storage
            .control
            .put(&t, "accounts/a", Bytes::from_static(b"{}"), Expect::Any)
            .await
            .unwrap();
        storage
            .blobs
            .put(&t, Bytes::from_static(b"message"))
            .await
            .unwrap();
        objects
            .put(
                &ObjectKey::parse(&format!("system/tenants/{tenant}")).unwrap(),
                Bytes::new(),
                Expect::Any,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn copies_and_round_trips_one_tenant_without_overwriting() {
        let a: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        seed(&a, "acme").await;
        seed(&a, "globex").await;
        let b: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        let acme = TenantId::new("acme").unwrap();
        let counts = copy(a.clone(), b.clone(), &acme).await.unwrap();
        assert_eq!(counts.copied, 3);
        assert!(
            b.get(&ObjectKey::parse("tenants/globex/control/accounts/a").unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(copy(a.clone(), b.clone(), &acme).await.unwrap().same, 3);

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("acme.ndjson.zst");
        assert_eq!(export(a.clone(), &acme, &file).await.unwrap(), 3);
        assert!(
            export(a.clone(), &acme, &file).await.is_err(),
            "never overwrites a file"
        );
        let c: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        c.put(
            &ObjectKey::parse("tenants/acme/control/accounts/a").unwrap(),
            Bytes::from_static(b"newer"),
            Expect::Any,
        )
        .await
        .unwrap();
        let counts = import(c.clone(), &acme, &file).await.unwrap();
        assert_eq!((counts.copied, counts.different), (2, 1));
        assert_eq!(
            &c.get(&ObjectKey::parse("tenants/acme/control/accounts/a").unwrap())
                .await
                .unwrap()
                .unwrap()
                .0[..],
            b"newer",
            "existing objects are left alone"
        );
        assert!(
            import(c.clone(), &TenantId::new("globex").unwrap(), &file)
                .await
                .is_err(),
            "a file of one tenant cannot be imported as another"
        );
    }

    #[tokio::test]
    async fn imports_a_file_written_by_zstd_0_13() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("old.ndjson.zst");
        std::fs::write(
            &file,
            [
                0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58, 0x91, 0x01, 0x00, 0x7b, 0x22, 0x6b, 0x65, 0x79,
                0x22, 0x3a, 0x22, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x73, 0x2f, 0x61, 0x63, 0x6d,
                0x65, 0x2f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x2f, 0x6f, 0x6e, 0x65, 0x22,
                0x2c, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x3a, 0x22, 0x62, 0x32, 0x78, 0x6b,
                0x22, 0x7d, 0x0a,
            ],
        )
        .unwrap();
        let target: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        let counts = import(target.clone(), &TenantId::new("acme").unwrap(), &file)
            .await
            .unwrap();
        assert_eq!(counts.copied, 1);
        assert_eq!(
            &target
                .get(&ObjectKey::parse("tenants/acme/objects/one").unwrap())
                .await
                .unwrap()
                .unwrap()
                .0[..],
            b"old"
        );
    }

    #[tokio::test]
    async fn a_file_that_decompresses_into_one_huge_line_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bomb.ndjson.zst");
        let mut encoder = zstd::Encoder::new(std::fs::File::create(&file).unwrap(), 3).unwrap();
        encoder.write_all(&vec![b'a'; 64 * 1024 * 1024]).unwrap();
        encoder.finish().unwrap();
        assert!(std::fs::metadata(&file).unwrap().len() < 64 * 1024);
        let target: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        let error = import_lines(target, &TenantId::new("acme").unwrap(), &file, 1024 * 1024)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("longer than"), "{error}");
    }
}
