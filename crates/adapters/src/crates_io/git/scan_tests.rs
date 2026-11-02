use super::{GitScanMode, directory_size, directory_size_with_metadata};
use std::{fs, io, os::unix::fs::symlink};

const MODES: [GitScanMode; 2] = [GitScanMode::Settled, GitScanMode::ActiveFetch];

#[test]
fn disappearing_enumerated_file_is_tolerated_only_during_fetch() {
    for mode in MODES {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        fs::write(root.path().join("temporary-pack"), b"temporary").unwrap();
        let mut observed = 0;
        let result = directory_size_with_metadata(root.path(), 1024, mode, 10, |entry| {
            observed += 1;
            fs::remove_file(entry.path()).unwrap();
            entry.metadata()
        });
        assert_eq!(observed, 1);
        match mode {
            GitScanMode::ActiveFetch => assert_eq!(result.unwrap(), 0),
            GitScanMode::Settled => assert_eq!(result.unwrap_err().code, "unavailable"),
        }
    }
}

#[test]
fn disappearing_queued_directory_is_tolerated_only_during_fetch() {
    for mode in MODES {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        fs::create_dir(root.path().join("temporary-objects")).unwrap();
        let mut observed = 0;
        let result = directory_size_with_metadata(root.path(), 1024, mode, 10, |entry| {
            observed += 1;
            let metadata = entry.metadata()?;
            fs::remove_dir(entry.path()).unwrap();
            Ok(metadata)
        });
        assert_eq!(observed, 1);
        match mode {
            GitScanMode::ActiveFetch => assert_eq!(result.unwrap(), 0),
            GitScanMode::Settled => assert_eq!(result.unwrap_err().code, "unavailable"),
        }
    }
}

#[test]
fn metadata_errors_other_than_not_found_fail_in_both_modes() {
    for mode in MODES {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        fs::write(root.path().join("pack"), b"evidence").unwrap();
        let result = directory_size_with_metadata(root.path(), 1024, mode, 10, |_| {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        });
        assert_eq!(result.unwrap_err().code, "unavailable");
    }
}

#[test]
fn missing_roots_and_non_directory_roots_fail_in_both_modes() {
    for mode in MODES {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        assert_eq!(
            directory_size(&root.path().join("missing"), 1024, mode)
                .unwrap_err()
                .code,
            "unavailable"
        );
        let file = root.path().join("file");
        fs::write(&file, b"evidence").unwrap();
        assert_eq!(
            directory_size(&file, 1024, mode).unwrap_err().code,
            "integrity"
        );
    }
}

#[test]
fn root_disappearing_during_traversal_fails_in_both_modes() {
    for mode in MODES {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        fs::write(root.path().join("temporary-pack"), b"temporary").unwrap();
        let mut observed = 0;
        let result = directory_size_with_metadata(root.path(), 1024, mode, 10, |entry| {
            observed += 1;
            fs::remove_file(entry.path()).unwrap();
            fs::remove_dir(root.path()).unwrap();
            entry.metadata()
        });
        assert_eq!(observed, 1);
        assert!(!root.path().exists());
        assert_eq!(result.unwrap_err().code, "unavailable");
        // TempDir's drop cleanup safely ignores an already removed fixture root.
    }
}

#[test]
fn symlink_roots_and_descendants_fail_in_both_modes() {
    for mode in MODES {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let outside = tempfile::tempdir_in("/tmp").unwrap();
        let link = root.path().join("linked-objects");
        symlink(outside.path(), &link).unwrap();
        assert_eq!(
            directory_size(&link, 1024, mode).unwrap_err().code,
            "integrity"
        );
        assert_eq!(
            directory_size(root.path(), 1024, mode).unwrap_err().code,
            "integrity"
        );
    }
}

#[test]
fn queued_directory_replaced_by_symlink_is_not_traversed() {
    for mode in MODES {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let outside = tempfile::tempdir_in("/tmp").unwrap();
        fs::write(outside.path().join("outside-evidence"), b"outside").unwrap();
        fs::create_dir(root.path().join("objects")).unwrap();
        let mut observed = 0;
        let result = directory_size_with_metadata(root.path(), 1024, mode, 10, |entry| {
            observed += 1;
            let metadata = entry.metadata()?;
            fs::remove_dir(entry.path()).unwrap();
            symlink(outside.path(), entry.path()).unwrap();
            Ok(metadata)
        });
        assert_eq!(observed, 1);
        assert_eq!(result.unwrap_err().code, "integrity");
    }
}

#[test]
fn unsupported_filesystem_members_fail_in_both_modes() {
    for mode in MODES {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        nix::unistd::mkfifo(
            &root.path().join("fifo"),
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert_eq!(
            directory_size(root.path(), 1024, mode).unwrap_err().code,
            "integrity"
        );
    }
}

#[test]
fn nested_regular_files_are_counted_with_the_same_byte_budget_in_both_modes() {
    for mode in MODES {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        fs::create_dir(root.path().join("objects")).unwrap();
        fs::write(root.path().join("objects/pack"), b"pack").unwrap();
        fs::write(root.path().join("HEAD"), b"ref").unwrap();
        assert_eq!(directory_size(root.path(), 7, mode).unwrap(), 7);
        assert_eq!(
            directory_size(root.path(), 6, mode).unwrap_err().code,
            "capacity"
        );
    }
}

#[test]
fn member_limits_are_enforced_in_both_modes() {
    for mode in MODES {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        fs::write(root.path().join("first"), b"a").unwrap();
        fs::write(root.path().join("second"), b"b").unwrap();
        assert_eq!(
            directory_size_with_metadata(root.path(), 1024, mode, 1, fs::DirEntry::metadata)
                .unwrap_err()
                .code,
            "capacity"
        );
    }
}

#[test]
fn disappearing_members_still_consume_the_active_fetch_member_budget() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    fs::write(root.path().join("first"), b"a").unwrap();
    fs::write(root.path().join("second"), b"b").unwrap();
    let mut observed = 0;
    let result =
        directory_size_with_metadata(root.path(), 1024, GitScanMode::ActiveFetch, 1, |entry| {
            observed += 1;
            fs::remove_file(entry.path()).unwrap();
            entry.metadata()
        });
    assert_eq!(observed, 1);
    assert_eq!(result.unwrap_err().code, "capacity");
}
