//! A [`Keystore`] in a directory of files, for the headless server (GROUP.md: "the host keeps its
//! node keys in a file secret store, separate from the data directory").
//!
//! Each item is one file named after the item, mode `0600`, in a directory of mode `0700`.
//! Writes go to a temporary file (named with a leading `.`, which no item name may have), are
//! synced and renamed over the item, so a failed or interrupted `put` leaves the previous item.
//! A symbolic link, a file readable by the group or others, or anything but a regular file
//! where an item should be is refused with [`KeystoreError::Denied`]. Both classes are readable
//! whenever the process runs: a server has no screen lock.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use rowboat_keystore::{KeyClass, KeyName, Keystore, KeystoreError, MAX_SECRET, Secret};

/// A keystore over one directory. Clones and other instances over the same directory share
/// their items.
#[derive(Clone, Debug)]
pub struct FileKeystore {
    dir: Arc<PathBuf>,
    #[cfg(test)]
    fail_next_put: Arc<std::sync::atomic::AtomicBool>,
}

impl FileKeystore {
    /// The keystore in `dir`, created with mode `0700` (with its parents) when missing. An
    /// existing directory is used as it is, but must be a directory and not a link.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, KeystoreError> {
        let dir = dir.as_ref();
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|_| KeystoreError::Backend)?;
            restrict(dir, 0o700)?;
        }
        let meta = fs::symlink_metadata(dir).map_err(|_| KeystoreError::Backend)?;
        if !meta.is_dir() {
            return Err(KeystoreError::Denied);
        }
        Ok(Self {
            dir: Arc::new(dir.to_path_buf()),
            #[cfg(test)]
            fail_next_put: Arc::default(),
        })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, name: &KeyName) -> PathBuf {
        self.dir.join(name.as_str())
    }
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<(), KeystoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|_| KeystoreError::Backend)
}

#[cfg(not(unix))]
fn restrict(_: &Path, _: u32) -> Result<(), KeystoreError> {
    Ok(())
}

fn private(meta: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        true
    }
}

fn read(path: &Path) -> Result<Option<Secret>, KeystoreError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(KeystoreError::Backend),
    };
    if !meta.is_file() || !private(&meta) {
        return Err(KeystoreError::Denied);
    }
    if meta.len() > MAX_SECRET as u64 {
        return Err(KeystoreError::Unsupported);
    }
    let bytes = fs::read(path).map_err(|_| KeystoreError::Backend)?;
    Ok(Some(Secret::new(bytes)))
}

fn write(dir: &Path, path: &Path, secret: &Secret) -> Result<(), KeystoreError> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && !meta.is_file()
    {
        return Err(KeystoreError::Denied);
    }
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| KeystoreError::Backend)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(KeystoreError::Backend)?;
    let temp = dir.join(format!(".{name}.{}", hex(&suffix)));
    let written = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(secret.expose())?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok::<_, std::io::Error>(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
        return Err(KeystoreError::Backend);
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, KeystoreError> + Send + 'static,
) -> Result<T, KeystoreError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| KeystoreError::Backend)?
}

#[async_trait]
impl Keystore for FileKeystore {
    async fn get(&self, name: &KeyName) -> Result<Option<Secret>, KeystoreError> {
        let path = self.path(name);
        blocking(move || read(&path)).await
    }

    async fn put(&self, name: &KeyName, secret: &Secret, _: KeyClass) -> Result<(), KeystoreError> {
        if secret.len() > MAX_SECRET {
            return Err(KeystoreError::Unsupported);
        }
        #[cfg(test)]
        if self
            .fail_next_put
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(KeystoreError::Backend);
        }
        let dir = self.dir.clone();
        let path = self.path(name);
        let secret = secret.clone();
        blocking(move || write(&dir, &path, &secret)).await
    }

    async fn delete(&self, name: &KeyName) -> Result<bool, KeystoreError> {
        let path = self.path(name);
        blocking(move || match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(_) => Err(KeystoreError::Backend),
            Ok(_) => match fs::remove_file(&path) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
                Err(_) => Err(KeystoreError::Backend),
            },
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> KeyName {
        KeyName::new(text).unwrap()
    }

    #[tokio::test]
    async fn conformance() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        rowboat_keystore::testing::keystore(&|| {
            Arc::new(FileKeystore::open(&path).unwrap()) as Arc<dyn Keystore>
        })
        .await;
        let store = FileKeystore::open(&path).unwrap();
        let fault = store.clone();
        rowboat_keystore::testing::failed_put_keeps_the_old_item(Arc::new(store), &move || {
            fault
                .fail_next_put
                .store(true, std::sync::atomic::Ordering::SeqCst)
        })
        .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn items_and_the_directory_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("keys");
        let store = FileKeystore::open(&path).unwrap();
        store
            .put(
                &name("rowboat.master"),
                &Secret::from_text("k"),
                KeyClass::Background,
            )
            .await
            .unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o700);
        assert_eq!(mode(&path.join("rowboat.master")), 0o600);
        let leftovers: Vec<_> = fs::read_dir(&path)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "no temporary file stays behind");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_planted_link_or_a_readable_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeystore::open(dir.path().join("keys")).unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, b"attacker").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&outside, store.dir().join("rowboat.identity")).unwrap();
        let identity = name("rowboat.identity");
        assert_eq!(store.get(&identity).await, Err(KeystoreError::Denied));
        assert_eq!(
            store
                .put(&identity, &Secret::from_text("new"), KeyClass::Background)
                .await,
            Err(KeystoreError::Denied)
        );
        assert_eq!(
            fs::read(&outside).unwrap(),
            b"attacker",
            "the link target is untouched"
        );

        let open = name("rowboat.master");
        store
            .put(&open, &Secret::from_text("k"), KeyClass::Background)
            .await
            .unwrap();
        fs::set_permissions(
            store.dir().join("rowboat.master"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_eq!(store.get(&open).await, Err(KeystoreError::Denied));
    }

    #[tokio::test]
    async fn an_oversized_item_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeystore::open(dir.path()).unwrap();
        let big = Secret::new(vec![0; MAX_SECRET + 1]);
        assert_eq!(
            store.put(&name("a"), &big, KeyClass::Background).await,
            Err(KeystoreError::Unsupported)
        );
        fs::write(dir.path().join("b"), vec![0; MAX_SECRET + 1]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path().join("b"), fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(store.get(&name("b")).await, Err(KeystoreError::Unsupported));
    }

    #[test]
    fn a_file_where_the_directory_should_be_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("keys");
        fs::write(&file, b"").unwrap();
        assert_eq!(
            FileKeystore::open(&file).unwrap_err(),
            KeystoreError::Denied
        );
    }
}
