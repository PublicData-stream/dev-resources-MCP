//! Descriptor-confined reads for operator-supplied local evidence, never provider I/O.
use devres_domain::{Error, Result};
use nix::{
    fcntl::{OFlag, open, openat},
    sys::stat::{Mode, fstat},
};
use std::{
    fs::File,
    io::Read,
    path::{Component, Path},
};

fn invalid() -> Error {
    Error::invalid("Evidence requires a private owned regular file below /tmp.")
}

pub fn open_private_input(path: &Path, maximum: u64) -> Result<File> {
    let relative = path.strip_prefix("/tmp").map_err(|_| invalid())?;
    let parts = relative
        .components()
        .map(|p| match p {
            Component::Normal(name) => Ok(name),
            _ => Err(invalid()),
        })
        .collect::<Result<Vec<_>>>()?;
    if parts.len() < 2 {
        return Err(invalid());
    }
    let status = std::fs::read_to_string("/proc/self/status").map_err(|_| invalid())?;
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|s| s.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(invalid)?;
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut dir = open(Path::new("/tmp"), flags, Mode::empty()).map_err(|_| invalid())?;
    for name in &parts[..parts.len() - 1] {
        dir = openat(&dir, *name, flags, Mode::empty()).map_err(|_| invalid())?;
        let info = fstat(&dir).map_err(|_| invalid())?;
        if info.st_uid != uid || info.st_mode & 0o077 != 0 {
            return Err(invalid());
        }
    }
    let info = fstat(&dir).map_err(|_| invalid())?;
    if info.st_uid != uid || info.st_mode & 0o077 != 0 {
        return Err(invalid());
    }
    let fd = openat(
        &dir,
        parts[parts.len() - 1],
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| invalid())?;
    let info = fstat(&fd).map_err(|_| invalid())?;
    if info.st_mode & nix::libc::S_IFMT != nix::libc::S_IFREG
        || info.st_uid != uid
        || info.st_mode & 0o077 != 0
        || info.st_nlink != 1
        || info.st_size < 0
        || info.st_size as u64 > maximum
    {
        return Err(invalid());
    }
    Ok(File::from(fd))
}

pub fn read_private_input(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut file = open_private_input(path, maximum)?;
    let before = file.metadata().map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let after = file.metadata().map_err(|_| invalid())?;
    if bytes.len() as u64 != before.len()
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
        || bytes.len() as u64 > maximum
    {
        return Err(invalid());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn rejects_links_public_files_and_excess_without_echoing_input() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("input");
        std::fs::write(&path, b"credential-sentinel").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_private_input(&path, 64).unwrap(),
            b"credential-sentinel"
        );
        assert!(read_private_input(&path, 2).is_err());
        let link = root.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_private_input(&link, 64).is_err());
        let hard = root.path().join("hard");
        std::fs::hard_link(&path, &hard).unwrap();
        assert!(read_private_input(&path, 64).is_err());
        std::fs::remove_file(hard).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_input(&path, 64).is_err());
        assert!(read_private_input(Path::new("/tmp/input"), 64).is_err());
    }
}
