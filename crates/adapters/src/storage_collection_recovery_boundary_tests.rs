use super::*;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;

#[test]
fn future_scanner_does_not_reinterpret_registered_recipe_metadata() {
    let body = crate::integrity::hash(b"x");
    let job = json!({"snapshot":crate::integrity::hash(b"retained job"),"artifact":{"body_hash":body,"bytes":1,"relative_path":crate::integrity::relative_path(&body).unwrap().to_string_lossy()},"validated_at":devres_domain::unix_now(),"next":0,"records":0,"gaps":0,"done":true,"failed":"capacity","processor_version":1,"failure_context":{"version":1,"code":"capacity","materialization_deadline":true}});
    assert_eq!(NPM_RECOVERY_PROCESSOR_VERSION, 1);
    assert_eq!(eligibility(&job).unwrap(), "eligible");
    assert!(require_available_processor(1).is_ok());
    assert!(require_available_processor(2).is_err());
    // The same retained metadata still verifies after refusing the newer engine.
    assert_eq!(eligibility(&job).unwrap(), "eligible");
}

/// Called by the required disposable PostgreSQL script after stopping its sole
/// recovery owner; archive bytes stay fixed while the complete SQL graph restores.
pub(super) async fn restore_nonempty_recovery_fixture(
    container: &str,
    database: &str,
    root: &Path,
    operation: &str,
    published: &Value,
    export: &BulkArtifact,
    states: &[(&str, Option<Value>)],
) {
    use std::process::{Command, Stdio};
    assert!(
        container.len() <= 100
            && container
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric())
            && container
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    );
    let mut restored = url::Url::parse(database).unwrap();
    let original = restored.path().trim_start_matches('/').to_owned();
    assert!(
        original
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    let new_name = format!("{original}_restored");
    restored.set_path(&format!("/{new_name}"));
    let temporary = tempfile::tempdir_in("/tmp").unwrap();
    let dump = temporary.path().join("fixture.dump");
    let file = std::fs::File::create(&dump).unwrap();
    let status = Command::new("docker")
        .args([
            "exec", container, "pg_dump", "-U", "devres", "-Fc", &original,
        ])
        .stdout(Stdio::from(file))
        .status()
        .unwrap();
    assert!(status.success(), "fixture pg_dump failed");
    let mut conn = PgConnection::connect(database).await.unwrap();
    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "CREATE DATABASE {new_name}"
    )))
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    let input = std::fs::File::open(dump).unwrap();
    let status = Command::new("docker")
        .args([
            "exec",
            "-i",
            container,
            "pg_restore",
            "-U",
            "devres",
            "--exit-on-error",
            "-d",
            &new_name,
        ])
        .stdin(Stdio::from(input))
        .status()
        .unwrap();
    assert!(status.success(), "fixture pg_restore failed");
    let store = PgBlobStore::connect_archive_for_recovery(restored.as_str(), root, None)
        .await
        .unwrap();
    {
        let mut owner = store.owner.lock().await;
        verify_history(&mut owner, &CancellationToken::new())
            .await
            .unwrap();
        let work = load_work(&mut owner, operation).await.unwrap();
        assert_eq!(work["status"], "complete");
        assert_eq!(work["publication_snapshot"], published["id"]);
    }
    assert_eq!(
        store
            .npm_get("snapshots", published["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .data,
        *published
    );
    for (key, value) in states {
        assert_eq!(store.npm_state(key).await.unwrap(), *value);
    }
    let raw = BulkArtifactStore::new(root.join("npm/raw-artifacts"), 64 * 1024 * 1024).unwrap();
    let mut file = raw
        .open(
            &export.body_hash,
            MAX_ARTIFACT_BYTES,
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut file, &mut bytes)
        .await
        .unwrap();
    assert_eq!(crate::integrity::hash(&bytes), export.body_hash);
    println!("recovery_nonempty_dump_restore_passed");
}

#[tokio::test]
async fn snapshot_survives_external_path_replacement_and_in_place_mutation() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("external.zip");
    let original = b"retained-original-byte-sentinel";
    std::fs::write(&path, original).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let body = crate::integrity::hash(original);
    let expected = BulkArtifact {
        body_hash: body.clone(),
        bytes: original.len() as u64,
        relative_path: crate::integrity::relative_path(&body)
            .unwrap()
            .to_string_lossy()
            .into(),
    };
    let mut snapshot = snapshot_artifact(
        &path,
        &expected,
        &CancellationToken::new(),
        Instant::now() + Duration::from_secs(5),
    )
    .await
    .unwrap();
    // Mutate the verified external inode, then replace its path entirely. The
    // scanner consumes the anonymous snapshot, not either external file.
    let mut source = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    source.write_all(b"different-member-byte-sentinel").unwrap();
    let replacement = root.path().join("replacement");
    std::fs::write(&replacement, b"replacement-export").unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    let mut read = Vec::new();
    snapshot.read_to_end(&mut read).unwrap();
    assert_eq!(read, original);
    assert!(
        snapshot_artifact(
            &path,
            &expected,
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(5)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
#[ignore = "requires disposable DEVRES_TEST_DATABASE_URL PostgreSQL"]
async fn recovery_attachment_rejects_schema18_without_running_migration() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
    let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
    let name = format!("devres_recovery_attachment_{}", std::process::id());
    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "CREATE DATABASE {name}"
    )))
    .execute(&admin)
    .await
    .unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&format!("/{name}"));
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = PgBlobStore::connect(url.as_str(), root.path())
        .await
        .unwrap();
    sqlx_core::query::query("UPDATE devres_schema SET version=18 WHERE singleton")
        .execute(&store.pool)
        .await
        .unwrap();
    drop(store);
    assert!(
        PgBlobStore::connect_archive_for_recovery(url.as_str(), root.path(), None)
            .await
            .is_err()
    );
    let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
    let version: i32 =
        sqlx_core::query_scalar::query_scalar("SELECT version FROM devres_schema WHERE singleton")
            .fetch_one(&mut conn)
            .await
            .unwrap();
    assert_eq!(version, 18);
    sqlx_core::query::query("UPDATE devres_schema SET version=19 WHERE singleton")
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let recovery = PgBlobStore::connect_archive_for_recovery(url.as_str(), root.path(), None)
        .await
        .unwrap();
    let statement: String = sqlx_core::query_scalar::query_scalar("SHOW statement_timeout")
        .fetch_one(&recovery.pool)
        .await
        .unwrap();
    assert_eq!(statement, "3s");
    let mut owner = recovery.owner.lock().await;
    let lock: String = sqlx_core::query_scalar::query_scalar("SHOW lock_timeout")
        .fetch_one(&mut *owner)
        .await
        .unwrap();
    assert_eq!(lock, "1s");
}
