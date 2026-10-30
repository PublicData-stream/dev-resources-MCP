//! A depth-bounded retained tree walk without a pending path per sibling.
use super::{canceled, storage_error};
use devres_domain::{Error, Result};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

pub(super) enum Item {
    File(PathBuf),
    Integrity(PathBuf),
}

pub(super) struct Tree {
    root_components: usize,
    frames: Vec<(PathBuf, tokio::fs::ReadDir)>,
}

impl Tree {
    pub async fn new(root: &Path) -> Result<Self> {
        Ok(Self {
            root_components: root.components().count(),
            frames: vec![(
                root.to_owned(),
                tokio::fs::read_dir(root)
                    .await
                    .map_err(|_| storage_error())?,
            )],
        })
    }

    pub async fn next(&mut self, cancel: &CancellationToken) -> Result<Option<Item>> {
        while let Some((directory, entries)) = self.frames.last_mut() {
            canceled(cancel)?;
            let directory = directory.clone();
            let Some(entry) = entries.next_entry().await.map_err(|_| storage_error())? else {
                self.frames.pop();
                continue;
            };
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| Error::integrity("Invalid retained path encoding."))?;
            if name == ".devres-integrity" {
                return Ok(Some(Item::Integrity(directory)));
            }
            if name == ".devres-git-owned"
                || name.starts_with(".stage-")
                || name.starts_with(".bulk-stage-")
                || name.ends_with(".lock")
            {
                continue;
            }
            let kind = entry.file_type().await.map_err(|_| storage_error())?;
            if kind.is_symlink() {
                return Err(Error::integrity("Unexpected retained storage link."));
            }
            let path = entry.path();
            if kind.is_dir() {
                if name.ends_with(".git") || name == "git-index" || name == "mirrors" {
                    continue;
                }
                // Preserve the existing depth bound. Only one directory iterator
                // per ancestor is retained, regardless of sibling fan-out.
                if self.frames.len() >= 1024
                    || path.components().count() > self.root_components + 32
                {
                    return Err(Error::capacity("Storage traversal bound exceeded."));
                }
                let entries = tokio::fs::read_dir(&path)
                    .await
                    .map_err(|_| storage_error())?;
                self.frames.push((path, entries));
            } else if kind.is_file() {
                return Ok(Some(Item::File(path)));
            } else {
                return Err(Error::integrity("Unsupported retained filesystem member."));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wide_tree_keeps_only_ancestor_iterators_and_preserves_all_files() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        for index in 0..1500 {
            let directory = root.path().join(format!("generation-{index}"));
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join("retained"), b"public evidence").unwrap();
        }
        let mut walk = Tree::new(root.path()).await.unwrap();
        let mut found = 0;
        while let Some(item) = walk.next(&CancellationToken::new()).await.unwrap() {
            assert!(walk.frames.len() <= 2);
            if let Item::File(_) = item {
                found += 1;
            }
        }
        assert_eq!(found, 1500);
    }

    #[tokio::test]
    async fn depth_symlink_and_cancellation_bounds_remain_enforced() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let mut directory = root.path().to_owned();
        for _ in 0..33 {
            directory = directory.join("nested");
            std::fs::create_dir(&directory).unwrap();
        }
        let mut walk = Tree::new(root.path()).await.unwrap();
        assert_eq!(
            walk.next(&CancellationToken::new())
                .await
                .err()
                .unwrap()
                .code,
            "capacity"
        );
        let links = tempfile::tempdir_in("/tmp").unwrap();
        std::os::unix::fs::symlink(root.path(), links.path().join("link")).unwrap();
        let mut walk = Tree::new(links.path()).await.unwrap();
        assert_eq!(
            walk.next(&CancellationToken::new())
                .await
                .err()
                .unwrap()
                .code,
            "integrity"
        );
        let token = CancellationToken::new();
        token.cancel();
        let mut walk = Tree::new(links.path()).await.unwrap();
        assert_eq!(walk.next(&token).await.err().unwrap().code, "cancelled");
    }

    #[tokio::test]
    async fn disposable_layouts_are_skipped_and_integrity_roots_are_reported() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        for name in [".devres-integrity", "mirrors", "source.git", "git-index"] {
            let path = root.path().join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("ignored"), b"disposable").unwrap();
        }
        std::fs::write(root.path().join(".stage-1-2"), b"stage").unwrap();
        let mut walk = Tree::new(root.path()).await.unwrap();
        let mut roots = 0;
        while let Some(item) = walk.next(&CancellationToken::new()).await.unwrap() {
            match item {
                Item::Integrity(path) => {
                    assert_eq!(path, root.path());
                    roots += 1;
                }
                Item::File(_) => panic!("disposable path escaped its admission boundary"),
            }
        }
        assert_eq!(roots, 1);
    }
}
