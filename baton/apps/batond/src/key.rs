//! The node key file.

use std::io::Write;
use std::path::Path;

use baton_identity::Identity;
use zeroize::Zeroizing;

use crate::BatondError;

/// The node key file inside the data directory.
pub const KEY_FILE: &str = "node.key";

/// Reads the node's identity from `path` (32 raw secret bytes), creating it with a fresh key,
/// mode `0600`, when it does not exist. Refuses a file readable by group or others, or of the
/// wrong length.
pub fn load_or_create(path: &Path) -> Result<Identity, BatondError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(BatondError::Config(format!(
                    "{} is not a regular file",
                    path.display()
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err(BatondError::Config(format!(
                        "{} must not be readable by group or others (chmod 600)",
                        path.display()
                    )));
                }
            }
            let raw = Zeroizing::new(std::fs::read(path)?);
            let secret: Zeroizing<[u8; 32]> =
                Zeroizing::new(raw.as_slice().try_into().map_err(|_| {
                    BatondError::Config(format!("{} does not hold a node key", path.display()))
                })?);
            Ok(Identity::from_secret_bytes(&secret))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let id = Identity::generate();
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut f = options.open(path)?;
            f.write_all(&id.secret_bytes()[..])?;
            f.sync_all()?;
            Ok(id)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_created_private_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEY_FILE);
        let a = load_or_create(&path).unwrap();
        let b = load_or_create(&path).unwrap();
        assert_eq!(a.public(), b.public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(load_or_create(&path).is_err(), "a group-readable key");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(&path, [1u8; 31]).unwrap();
        assert!(load_or_create(&path).is_err(), "a short key");
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        assert!(load_or_create(&sub).is_err(), "a directory");
    }
}
