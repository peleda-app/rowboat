//! [`Objects`] as files under one root directory.
//!
//! One process per directory: [`FsObjects::open`] takes an exclusive advisory lock on
//! `<root>/.lock` and fails with [`OpenError::Locked`] while another handle holds it.

use std::collections::hash_map::DefaultHasher;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use skein_storage::{Expect, InvalidKey, ObjectKey, Objects, StorageError, Version};
use tokio::sync::Mutex;
use ulid::Ulid;

const MAGIC: &[u8; 9] = b"skein-fs\x01";
const VERSION_LEN: usize = 26;
const HEADER_LEN: usize = MAGIC.len() + VERSION_LEN;
const FILE_SUFFIX: &str = "~obj";
const LOCK_FILE: &str = ".lock";
const TEMP_PREFIX: &str = ".tmp-";
const STRIPES: usize = 64;
const MAX_NAME: usize = 255;

/// Why a store could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// Another handle, in this process or another one, already holds the directory.
    #[error("storage directory {root} is in use by another process (one process per directory)")]
    Locked {
        /// The root directory.
        root: PathBuf,
    },
    /// The directory or its lock file could not be created or opened.
    #[error("cannot open storage directory: {0}")]
    Io(#[from] io::Error),
}

/// An object store in a directory.
///
/// Guarantees, beyond the [`Objects`] contract:
///
/// - Every write replaces the object file atomically and is flushed to disk (file and directory)
///   before `put` returns, so a crash leaves either the old or the new value, never a mix.
/// - Every write gets a fresh random version, even when the bytes are the same; a read returns the
///   value and the version written together.
/// - Compare-and-swap holds between all tasks sharing this handle. Other processes are kept out by
///   the lock taken in [`FsObjects::open`], which lives as long as the handle.
/// - Symbolic links inside the root are never followed: reads and writes through them fail and
///   `list` skips them.
pub struct FsObjects {
    inner: Arc<Inner>,
}

struct Inner {
    root: PathBuf,
    stripes: Box<[Mutex<()>]>,
    _lock: File,
}

impl FsObjects {
    /// Opens the store at `root`, creating the directory (mode `0700` on unix) when missing, and
    /// takes the directory lock. Fails with [`OpenError::Locked`] when another handle holds it.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, OpenError> {
        let root = root.as_ref();
        dir_builder(true).create(root)?;
        let root = root.canonicalize()?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        file_mode(&mut options);
        let lock = options.open(root.join(LOCK_FILE))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(OpenError::Locked { root }),
            Err(TryLockError::Error(e)) => return Err(OpenError::Io(e)),
        }
        let stripes = (0..STRIPES).map(|_| Mutex::new(())).collect();
        Ok(Self {
            inner: Arc::new(Inner {
                root,
                stripes,
                _lock: lock,
            }),
        })
    }

    /// The canonical root directory.
    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    fn stripe(&self, key: &ObjectKey) -> &Mutex<()> {
        let mut h = DefaultHasher::new();
        key.as_str().hash(&mut h);
        &self.inner.stripes[(h.finish() as usize) % STRIPES]
    }

    async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Inner) -> Result<T, StorageError> + Send + 'static,
    ) -> Result<T, StorageError> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || f(&inner))
            .await
            .map_err(StorageError::backend)?
    }
}

#[cfg(unix)]
fn dir_builder(recursive: bool) -> fs::DirBuilder {
    use std::os::unix::fs::DirBuilderExt;
    let mut b = fs::DirBuilder::new();
    b.recursive(recursive).mode(0o700);
    b
}

#[cfg(not(unix))]
fn dir_builder(recursive: bool) -> fs::DirBuilder {
    let mut b = fs::DirBuilder::new();
    b.recursive(recursive);
    b
}

#[cfg(unix)]
fn file_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn file_mode(_: &mut OpenOptions) {}

fn symlink_refused() -> StorageError {
    StorageError::backend(io::Error::other(
        "refusing a symbolic link inside the storage root",
    ))
}

fn io(e: io::Error) -> StorageError {
    StorageError::backend(e)
}

/// File system name of a key segment. Upper-case letters become `^` plus the lower-case letter so
/// keys differing only in case stay apart on case-insensitive file systems.
fn encode(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len() + 4);
    for c in segment.chars() {
        if c.is_ascii_uppercase() {
            out.push('^');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn decode(name: &str) -> Option<String> {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        match c {
            '^' => match chars.next() {
                Some(l) if l.is_ascii_lowercase() => out.push(l.to_ascii_uppercase()),
                _ => return None,
            },
            c if c.is_ascii_uppercase() => return None,
            c => out.push(c),
        }
    }
    Some(out)
}

struct Location {
    dirs: Vec<String>,
    file: String,
}

impl Location {
    fn of(key: &ObjectKey) -> Result<Self, StorageError> {
        let mut segments: Vec<String> = key.segments().map(encode).collect();
        let last = segments.pop().ok_or(InvalidKey)?;
        let file = format!("{last}{FILE_SUFFIX}");
        if file.len() > MAX_NAME || segments.iter().any(|s| s.len() > MAX_NAME) {
            return Err(InvalidKey.into());
        }
        Ok(Self {
            dirs: segments,
            file,
        })
    }

    fn dir(&self, root: &Path) -> PathBuf {
        let mut p = root.to_path_buf();
        p.extend(&self.dirs);
        p
    }
}

/// Whether every directory on the way exists and none is a symlink.
fn dirs_exist(root: &Path, dirs: &[String]) -> Result<bool, StorageError> {
    let mut p = root.to_path_buf();
    for d in dirs {
        p.push(d);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_symlink() => return Err(symlink_refused()),
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(io(e)),
        }
    }
    Ok(true)
}

fn ensure_dirs(root: &Path, dirs: &[String]) -> io::Result<()> {
    let mut p = root.to_path_buf();
    for d in dirs {
        p.push(d);
        match dir_builder(false).create(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let m = fs::symlink_metadata(&p)?;
                if !m.is_dir() || m.file_type().is_symlink() {
                    return Err(io::Error::other(
                        "refusing a non-directory inside the storage root",
                    ));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn open_object(path: &Path) -> Result<Option<File>, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => return Err(symlink_refused()),
        Ok(m) if !m.is_file() => return Err(StorageError::Corrupt("object is not a file".into())),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
    }
    match File::open(path) {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io(e)),
    }
}

fn parse_header(header: &[u8]) -> Result<String, StorageError> {
    let corrupt = || StorageError::Corrupt("object file header".into());
    if header.len() < HEADER_LEN || &header[..MAGIC.len()] != MAGIC {
        return Err(corrupt());
    }
    let v = std::str::from_utf8(&header[MAGIC.len()..HEADER_LEN]).map_err(|_| corrupt())?;
    Ulid::from_string(v).map_err(|_| corrupt())?;
    Ok(v.to_owned())
}

fn read_object(path: &Path) -> Result<Option<(Vec<u8>, String)>, StorageError> {
    let Some(mut f) = open_object(path)? else {
        return Ok(None);
    };
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(io)?;
    let version = parse_header(&buf)?;
    buf.drain(..HEADER_LEN);
    Ok(Some((buf, version)))
}

fn read_version(path: &Path) -> Result<Option<String>, StorageError> {
    let Some(f) = open_object(path)? else {
        return Ok(None);
    };
    let mut header = Vec::with_capacity(HEADER_LEN);
    f.take(HEADER_LEN as u64)
        .read_to_end(&mut header)
        .map_err(io)?;
    parse_header(&header).map(Some)
}

fn holds(current: Option<&str>, expect: &Expect) -> bool {
    match (expect, current) {
        (Expect::Any, _) | (Expect::Absent, None) => true,
        (Expect::Version(v), Some(c)) => v.0 == c,
        _ => false,
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_: &Path) -> io::Result<()> {
    Ok(())
}

fn write_atomic(dir: &Path, file: &str, version: &str, value: &[u8]) -> io::Result<()> {
    let temp = dir.join(format!("{TEMP_PREFIX}{}", Ulid::generate()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    file_mode(&mut options);
    let mut f = options.open(&temp)?;
    let result = (|| {
        f.write_all(MAGIC)?;
        f.write_all(version.as_bytes())?;
        f.write_all(value)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&temp, dir.join(file))?;
        sync_dir(dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

impl Inner {
    fn put(&self, key: &ObjectKey, value: &[u8], expect: &Expect) -> Result<String, StorageError> {
        let loc = Location::of(key)?;
        let current = if dirs_exist(&self.root, &loc.dirs)? {
            read_version(&loc.dir(&self.root).join(&loc.file))?
        } else {
            None
        };
        if !holds(current.as_deref(), expect) {
            return Err(StorageError::Conflict);
        }
        let version = Ulid::generate().to_string();
        let dir = loc.dir(&self.root);
        let mut attempts = 0;
        loop {
            let result = ensure_dirs(&self.root, &loc.dirs)
                .and_then(|()| write_atomic(&dir, &loc.file, &version, value));
            match result {
                Ok(()) => return Ok(version),
                Err(e) if e.kind() == io::ErrorKind::NotFound && attempts < 5 => attempts += 1,
                Err(e) => return Err(io(e)),
            }
        }
    }

    fn delete(&self, key: &ObjectKey, expect: &Expect) -> Result<(), StorageError> {
        let loc = Location::of(key)?;
        if !dirs_exist(&self.root, &loc.dirs)? {
            return if holds(None, expect) || matches!(expect, Expect::Any) {
                Ok(())
            } else {
                Err(StorageError::Conflict)
            };
        }
        let dir = loc.dir(&self.root);
        let path = dir.join(&loc.file);
        let current = read_version(&path)?;
        if current.is_none() && matches!(expect, Expect::Any | Expect::Absent) {
            return Ok(());
        }
        if !holds(current.as_deref(), expect) {
            return Err(StorageError::Conflict);
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(io(e)),
        }
        sync_dir(&dir).map_err(io)?;
        self.prune(&dir);
        Ok(())
    }

    fn prune(&self, dir: &Path) {
        let mut p = dir.to_path_buf();
        while p != self.root && p.starts_with(&self.root) {
            if fs::remove_dir(&p).is_err() {
                break;
            }
            if !p.pop() {
                break;
            }
        }
    }

    fn list(
        &self,
        prefix: &ObjectKey,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectKey>, StorageError> {
        let mut out = Vec::new();
        if limit == 0 {
            return Ok(out);
        }
        let dirs: Vec<String> = prefix.segments().map(encode).collect();
        if !dirs_exist(&self.root, &dirs)? {
            return Ok(out);
        }
        let mut dir = self.root.clone();
        dir.extend(&dirs);
        walk(
            &dir,
            &format!("{}/", prefix.as_str()),
            start_after,
            limit,
            &mut out,
        )?;
        Ok(out)
    }
}

/// Appends keys under `dir` in ascending byte order of the full key. Children sort by what they
/// contribute to the key: a file by its segment, a directory by its segment plus `/`.
fn walk(
    dir: &Path,
    base: &str,
    after: Option<&str>,
    limit: usize,
    out: &mut Vec<ObjectKey>,
) -> Result<(), StorageError> {
    let mut children = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io(e)),
    };
    for entry in entries {
        let entry = entry.map_err(io)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with('.') {
            continue;
        }
        let Ok(ft) = entry.file_type() else { continue };
        let child = if ft.is_dir() {
            decode(name).map(|seg| (format!("{base}{seg}/"), true))
        } else if ft.is_file() {
            name.strip_suffix(FILE_SUFFIX)
                .and_then(decode)
                .map(|seg| (format!("{base}{seg}"), false))
        } else {
            None
        };
        if let Some((full, is_dir)) = child {
            children.push((full, is_dir, entry.path()));
        }
    }
    children.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    for (full, is_dir, path) in children {
        if is_dir {
            if let Some(a) = after
                && full.as_str() < a
                && !a.starts_with(&full)
            {
                continue;
            }
            walk(&path, &full, after, limit, out)?;
        } else {
            if after.is_some_and(|a| full.as_str() <= a) {
                continue;
            }
            let Ok(key) = ObjectKey::parse(&full) else {
                continue;
            };
            out.push(key);
        }
        if out.len() >= limit {
            return Ok(());
        }
    }
    Ok(())
}

#[async_trait]
impl Objects for FsObjects {
    async fn get(&self, key: &ObjectKey) -> Result<Option<(Bytes, Version)>, StorageError> {
        let key = key.clone();
        self.blocking(move |inner| {
            let loc = Location::of(&key)?;
            if !dirs_exist(&inner.root, &loc.dirs)? {
                return Ok(None);
            }
            Ok(read_object(&loc.dir(&inner.root).join(&loc.file))?
                .map(|(value, v)| (Bytes::from(value), Version(v))))
        })
        .await
    }

    async fn put(
        &self,
        key: &ObjectKey,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StorageError> {
        let _guard = self.stripe(key).lock().await;
        let key = key.clone();
        self.blocking(move |inner| inner.put(&key, &value, &expect).map(Version))
            .await
    }

    async fn delete(&self, key: &ObjectKey, expect: Expect) -> Result<(), StorageError> {
        let _guard = self.stripe(key).lock().await;
        let key = key.clone();
        self.blocking(move |inner| inner.delete(&key, &expect))
            .await
    }

    async fn list(
        &self,
        prefix: &ObjectKey,
        start_after: Option<&ObjectKey>,
        limit: usize,
    ) -> Result<Vec<ObjectKey>, StorageError> {
        let prefix = prefix.clone();
        let after = start_after.map(|k| k.as_str().to_owned());
        self.blocking(move |inner| inner.list(&prefix, after.as_deref(), limit))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(text: &str) -> ObjectKey {
        ObjectKey::parse(text).unwrap()
    }

    #[tokio::test]
    async fn conformance() {
        let dir = tempfile::tempdir().unwrap();
        skein_storage::testing::all_over_objects(Arc::new(FsObjects::open(dir.path()).unwrap()))
            .await;
    }

    #[tokio::test]
    async fn second_open_of_the_same_root_fails() {
        let dir = tempfile::tempdir().unwrap();
        let first = FsObjects::open(dir.path()).unwrap();
        assert!(matches!(
            FsObjects::open(dir.path()),
            Err(OpenError::Locked { .. })
        ));
        drop(first);
        FsObjects::open(dir.path()).unwrap();
    }

    #[tokio::test]
    async fn data_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let k = key("t/a/b");
        let v = {
            let store = FsObjects::open(dir.path()).unwrap();
            store
                .put(&k, Bytes::from_static(b"kept"), Expect::Absent)
                .await
                .unwrap()
        };
        let store = FsObjects::open(dir.path()).unwrap();
        let (value, version) = store.get(&k).await.unwrap().unwrap();
        assert_eq!(&value[..], b"kept");
        assert_eq!(version, v);
    }

    #[tokio::test]
    async fn same_bytes_get_a_new_version() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsObjects::open(dir.path()).unwrap();
        let k = key("t/same");
        let v1 = store
            .put(&k, Bytes::from_static(b"x"), Expect::Any)
            .await
            .unwrap();
        let v2 = store
            .put(&k, Bytes::from_static(b"x"), Expect::Any)
            .await
            .unwrap();
        assert_ne!(v1, v2);
    }

    #[tokio::test]
    async fn keys_differing_in_case_stay_apart() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsObjects::open(dir.path()).unwrap();
        for (k, v) in [("t/Ab/X", "1"), ("t/ab/x", "2"), ("t/AB/x", "3")] {
            store
                .put(&key(k), Bytes::from(v.to_owned()), Expect::Absent)
                .await
                .unwrap();
        }
        assert_eq!(
            &store.get(&key("t/ab/x")).await.unwrap().unwrap().0[..],
            b"2"
        );
        let names: Vec<_> = store
            .list(&key("t"), None, 10)
            .await
            .unwrap()
            .into_iter()
            .map(|k| k.as_str().to_owned())
            .collect();
        assert_eq!(names, ["t/AB/x", "t/Ab/X", "t/ab/x"]);
    }

    #[tokio::test]
    async fn a_key_can_also_be_a_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsObjects::open(dir.path()).unwrap();
        for k in ["t/a", "t/a/b", "t/a-b", "t/a.c"] {
            store.put(&key(k), Bytes::new(), Expect::Any).await.unwrap();
        }
        let names: Vec<_> = store
            .list(&key("t"), None, 10)
            .await
            .unwrap()
            .into_iter()
            .map(|k| k.as_str().to_owned())
            .collect();
        assert_eq!(names, ["t/a", "t/a-b", "t/a.c", "t/a/b"]);
        let page = store
            .list(&key("t"), Some(&key("t/a.c")), 10)
            .await
            .unwrap();
        assert_eq!(page, [key("t/a/b")]);
    }

    #[tokio::test]
    async fn delete_prunes_empty_directories() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsObjects::open(dir.path()).unwrap();
        let k = key("t/deep/er/x");
        store.put(&k, Bytes::new(), Expect::Any).await.unwrap();
        store.delete(&k, Expect::Any).await.unwrap();
        assert!(!store.root().join("t").exists());
    }

    #[tokio::test]
    async fn stray_files_are_not_listed() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsObjects::open(dir.path()).unwrap();
        store
            .put(&key("t/x/a"), Bytes::new(), Expect::Any)
            .await
            .unwrap();
        let x = store.root().join("t").join("x");
        fs::write(x.join(".tmp-leftover"), b"").unwrap();
        fs::write(x.join("plain"), b"").unwrap();
        let names = store.list(&key("t"), None, 10).await.unwrap();
        assert_eq!(names, [key("t/x/a")]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let store = FsObjects::open(dir.path()).unwrap();
        std::os::unix::fs::symlink(outside.path(), store.root().join("t")).unwrap();
        assert!(store.get(&key("t/a")).await.is_err());
        assert!(
            store
                .put(&key("t/a"), Bytes::new(), Expect::Any)
                .await
                .is_err()
        );
        assert!(store.list(&key("t"), None, 10).await.is_err());
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn files_and_directories_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = FsObjects::open(dir.path().join("root")).unwrap();
        store
            .put(&key("t/a"), Bytes::new(), Expect::Any)
            .await
            .unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(store.root()), 0o700);
        assert_eq!(mode(&store.root().join("t")), 0o700);
        assert_eq!(mode(&store.root().join("t").join("a~obj")), 0o600);
    }

    #[test]
    fn segment_names_round_trip() {
        for s in ["abc", "01JABCXYZ", "a-B.c_D"] {
            assert_eq!(decode(&encode(s)).as_deref(), Some(s));
        }
        assert_eq!(decode("Abc"), None);
        assert_eq!(decode("a^"), None);
    }
}
