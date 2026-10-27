//! Private acceptance roots are owned directories, never caller-supplied public resources.
use devres_domain::{Error, Result};
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub fn owned_root(value: &Path, marker: &[u8]) -> Result<PathBuf> {
    let invalid = || Error::invalid("Acceptance requires an owned directory below /tmp.");
    let input = std::fs::symlink_metadata(value).map_err(|_| invalid())?;
    // Linux may assign root ownership to a nondumpable process's proc directory;
    // the kernel's effective UID field remains the actual caller identity.
    let status = std::fs::read_to_string("/proc/self/status").map_err(|_| invalid())?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(invalid)?;
    if !input.is_dir()
        || input.file_type().is_symlink()
        || input.uid() != uid
        || input.mode() & 0o022 != 0
    {
        return Err(invalid());
    }
    let root = std::fs::canonicalize(value).map_err(|_| invalid())?;
    if root == Path::new("/tmp") || !root.starts_with("/tmp/") {
        return Err(invalid());
    }
    let path = root.join("owner-v1");
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| invalid())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.len() != marker.len() as u64
        || metadata.mode() & 0o022 != 0
        || std::fs::read(path).map_err(|_| invalid())? != marker
    {
        return Err(invalid());
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_acceptance_rejects_symlinked_or_unowned_markers() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let root = temporary.path();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(root.join("owner-v1"), b"fixture\n").unwrap();
        std::fs::set_permissions(
            root.join("owner-v1"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(owned_root(root, b"fixture\n").unwrap(), root);
        let alias = root.join("alias");
        symlink(root, &alias).unwrap();
        assert!(owned_root(&alias, b"fixture\n").is_err());
        std::fs::remove_file(root.join("owner-v1")).unwrap();
        symlink(root.join("other"), root.join("owner-v1")).unwrap();
        std::fs::write(root.join("other"), b"fixture\n").unwrap();
        assert!(owned_root(root, b"fixture\n").is_err());
        std::fs::remove_file(root.join("owner-v1")).unwrap();
        std::fs::write(root.join("owner-v1"), b"fixture\n").unwrap();
        std::fs::set_permissions(
            root.join("owner-v1"),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(owned_root(root, b"fixture\n").is_err());
    }
}
