//! Integrity of immutable occurrence ordering and admission of new content IDs.
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row, postgres::PgRow};

const TABLES: &[&str] = &[
    "devres_mdn_evidence",
    "devres_whatwg_evidence",
    "devres_w3c_evidence",
    "devres_chromium_evidence",
    "devres_npm_evidence",
    "devres_advisory_rows",
];
fn failure() -> Error {
    Error::integrity("Retained occurrence ordering integrity failed.")
}
fn allowed(table: &str) -> Result<()> {
    if TABLES.contains(&table) {
        Ok(())
    } else {
        Err(failure())
    }
}
pub(super) fn digest(table: &str, kind: &str, key: &str, sequence: i64) -> Result<String> {
    allowed(table)?;
    if sequence <= 0 {
        return Err(failure());
    }
    crate::integrity::canonical_hash(
        &json!({"version":1,"namespace":table,"kind":kind,"key":key,"sequence":sequence}),
    )
}
pub(super) fn verify_row(table: &str, row: &PgRow) -> Result<()> {
    let sequence: i64 = row.try_get("sequence").map_err(|_| failure())?;
    let kind: String = row.try_get("kind").map_err(|_| failure())?;
    let key: String = row.try_get("key").map_err(|_| failure())?;
    let expected: String = row.try_get("sequence_integrity").map_err(|_| failure())?;
    if digest(table, &kind, &key, sequence)? != expected {
        return Err(failure());
    }
    Ok(())
}
pub(super) async fn reserve(
    conn: &mut PgConnection,
    table: &str,
    count: usize,
) -> Result<Vec<i64>> {
    allowed(table)?;
    if count > 1000 {
        return Err(Error::capacity("Occurrence allocation exceeds its bound."));
    }
    sqlx::query_scalar("SELECT nextval(pg_get_serial_sequence($1,'sequence')::regclass) FROM generate_series(1,$2::bigint)")
        .bind(table).bind(count as i64).fetch_all(conn).await.map_err(|_| failure())
}
pub(super) async fn reserve_one(conn: &mut PgConnection, table: &str) -> Result<i64> {
    reserve(conn, table, 1)
        .await?
        .into_iter()
        .next()
        .ok_or_else(failure)
}
fn content_kind(kind: &str) -> bool {
    matches!(
        kind,
        "nodes"
            | "changes"
            | "ref-pages"
            | "tree-pages"
            | "freezes"
            | "projections"
            | "projection-headers"
            | "index-documents"
            | "projection-chunks"
            | "projection-sequences"
            | "projection-sections"
            | "projection-symbols"
            | "projection-references"
            | "snapshots"
            | "views"
            | "catalogs"
            | "publications"
            | "observations"
            | "documents"
            | "versions"
            | "package-snapshots"
            | "metadata-captures"
            | "advisories"
            | "advisory-raw"
            | "members"
            | "advisory-members"
            | "advisory-packages"
    )
}
/// A legacy content key can only replay an already sealed, identical record.
/// Normal BLAKE3 writes need no admission query.
pub(super) async fn admit(
    conn: &mut PgConnection,
    table: &str,
    kind: &str,
    key: &str,
    data: &Value,
) -> Result<Option<i64>> {
    allowed(table)?;
    if !content_kind(kind) || (key.starts_with("blake3:") && crate::integrity::valid_hash(key)) {
        return Ok(None);
    }
    let sql = format!(
        "SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM {table} WHERE kind=$1 AND key=$2"
    );
    let retained = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(kind)
        .bind(key)
        .fetch_optional(conn)
        .await
        .map_err(|_| failure())?
        .ok_or_else(|| {
            Error::integrity("New immutable content requires a tagged BLAKE3 identity.")
        })?;
    if super::payload_integrity::row(table, &retained)? != *data {
        return Err(failure());
    }
    Ok(Some(retained.try_get("sequence").map_err(|_| failure())?))
}
/// Check retained duplicate ordering without loading batch payloads again.
pub(super) async fn verify_keys(
    conn: &mut PgConnection,
    table: &str,
    kinds: &[String],
    keys: &[String],
) -> Result<()> {
    allowed(table)?;
    if keys.len() > 1000 || kinds.len() != keys.len() {
        return Err(failure());
    }
    let sql = format!(
        "SELECT retained.sequence,retained.kind,retained.key,retained.sequence_integrity FROM {table} retained JOIN UNNEST($1::text[],$2::text[]) requested(kind,key) ON retained.kind=requested.kind AND retained.key=requested.key"
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(kinds)
        .bind(keys)
        .fetch_all(conn)
        .await
        .map_err(|_| failure())?;
    if rows.len() != keys.len() {
        return Err(failure());
    }
    for row in rows {
        verify_row(table, &row)?;
    }
    Ok(())
}
pub(super) async fn backfill(
    store: &super::PgBlobStore,
    cancel: &tokio_util::sync::CancellationToken,
    verify_only: bool,
) -> Result<()> {
    for &table in TABLES {
        // Include invalid sequence values rather than silently skipping corrupt rows.
        let mut after: Option<i64> = None;
        loop {
            if cancel.is_cancelled() {
                return Err(Error::new(
                    "cancelled",
                    "Occurrence integrity qualification canceled.",
                ));
            }
            let sql = format!(
                "SELECT sequence,kind,key,sequence_integrity FROM {table} WHERE ($1::bigint IS NULL OR sequence>$1) ORDER BY sequence LIMIT 1000"
            );
            let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(after)
                .fetch_all(&store.pool)
                .await
                .map_err(|_| failure())?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let sequence: i64 = row.try_get("sequence").map_err(|_| failure())?;
                let kind: String = row.try_get("kind").map_err(|_| failure())?;
                let key: String = row.try_get("key").map_err(|_| failure())?;
                let expected: Option<String> =
                    row.try_get("sequence_integrity").map_err(|_| failure())?;
                let seal = digest(table, &kind, &key, sequence)?;
                after = Some(sequence);
                match expected {
                    Some(expected) if expected == seal => {}
                    Some(_) => return Err(failure()),
                    None if verify_only => return Err(failure()),
                    None => {
                        let sql = format!(
                            "UPDATE {table} SET sequence_integrity=$2 WHERE sequence=$1 AND kind=$3 AND key=$4 AND sequence_integrity IS NULL"
                        );
                        let changed = sqlx::query(sqlx::AssertSqlSafe(sql))
                            .bind(sequence)
                            .bind(&seal)
                            .bind(&kind)
                            .bind(&key)
                            .execute(&mut *store.owner.lock().await)
                            .await
                            .map_err(|_| failure())?;
                        if changed.rows_affected() != 1 {
                            return Err(failure());
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; occurrence ordering and legacy admission fixture"]
    async fn sql_occurrence_order_and_new_content_admission_fail_closed() {
        use devres_application::{
            chromium::ChromiumStore,
            mdn::{MdnStore, MdnWrite},
            npm::NpmStore,
            w3c::W3cStore,
            whatwg::WhatwgStore,
        };
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let database = format!("devres_sequence_fixture_{suffix}");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{database}"));
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = super::super::PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let key = crate::integrity::hash(b"ordering fixture");
        let legacy = crate::integrity::legacy_hash(b"retained legacy fixture");
        let value = json!({"public":"fixture"});
        macro_rules! provider {
            ($table:literal,$put:ident,$get:ident,$page:ident) => {{
                assert_eq!(store.$put("projections", &legacy, &value).await.unwrap_err().code, "integrity");
                assert!(store.$get("projections", &legacy).await.unwrap().is_none());
                let sequence = store.$put("projections", &key, &value).await.unwrap();
                assert_eq!(store.$put("projections", &key, &value).await.unwrap(),sequence);
                assert_eq!(store.$get("projections", &key).await.unwrap().unwrap().sequence, sequence);
                let shifted = sequence + 100_000;
                sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE {} SET sequence=$1 WHERE kind='projections' AND key=$2",$table))).bind(shifted).bind(&key).execute(&store.pool).await.unwrap();
                assert_eq!(store.$get("projections", &key).await.unwrap_err().code,"integrity");
                assert_eq!(store.$put("projections", &key, &value).await.unwrap_err().code,"integrity");
                assert_eq!(store.$page("projections",0,10,None).await.unwrap_err().code,"integrity");
                sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE {} SET sequence=$1 WHERE kind='projections' AND key=$2",$table))).bind(sequence).bind(&key).execute(&store.pool).await.unwrap();
                // Simulate an original, qualified row: replay is supported without creating a new occurrence.
                let mut owner = store.owner.lock().await;
                let retained_sequence = reserve_one(&mut owner,$table).await.unwrap();
                sqlx::query(sqlx::AssertSqlSafe(format!("INSERT INTO {}(sequence,kind,key,data,data_integrity,sequence_integrity) VALUES($1,'projections',$2,$3,$4,$5)",$table)))
                    .bind(retained_sequence).bind(&legacy).bind(sqlx::types::Json(&value))
                    .bind(super::super::payload_integrity::digest($table,"projections",&legacy,&value).unwrap())
                    .bind(digest($table,"projections",&legacy,retained_sequence).unwrap()).execute(&mut *owner).await.unwrap();
                drop(owner);
                assert_eq!(store.$put("projections",&legacy,&value).await.unwrap(),retained_sequence);
                assert_eq!(store.$put("projections",&legacy,&json!({"changed":true})).await.unwrap_err().code,"integrity");
            }};
        }
        provider!("devres_mdn_evidence", mdn_put, mdn_get, mdn_rows);
        provider!(
            "devres_whatwg_evidence",
            whatwg_put,
            whatwg_get,
            whatwg_rows
        );
        provider!("devres_w3c_evidence", w3c_put, w3c_get, w3c_rows);
        provider!(
            "devres_chromium_evidence",
            chromium_put,
            chromium_get,
            chromium_rows
        );
        let sequence = store.npm_put("documents", &key, &value).await.unwrap();
        sqlx::query("UPDATE devres_npm_evidence SET sequence=sequence+100000 WHERE kind='documents' AND key=$1").bind(&key).execute(&store.pool).await.unwrap();
        assert_eq!(
            store.npm_get("documents", &key).await.unwrap_err().code,
            "integrity"
        );
        assert_eq!(
            store
                .npm_rows("documents", 0, 10, None, None)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert_eq!(
            store
                .npm_put("documents", &key, &value)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        sqlx::query("UPDATE devres_npm_evidence SET sequence=$2 WHERE kind='documents' AND key=$1")
            .bind(&key)
            .bind(sequence)
            .execute(&store.pool)
            .await
            .unwrap();
        let rows = [MdnWrite {
            kind: "projections".into(),
            key: key.clone(),
            data: value.clone(),
        }];
        sqlx::query("UPDATE devres_mdn_evidence SET sequence=sequence+200000 WHERE kind='projections' AND key=$1").bind(&key).execute(&store.pool).await.unwrap();
        assert_eq!(
            store
                .mdn_get_many("projections", std::slice::from_ref(&key))
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert_eq!(
            store.mdn_put_many(&rows).await.unwrap_err().code,
            "integrity"
        );
        assert_eq!(
            backfill(&store, &tokio_util::sync::CancellationToken::new(), true)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        drop(store);
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {database} WITH (FORCE)"
        )))
        .execute(&admin)
        .await
        .unwrap();
    }
    #[test]
    fn occurrence_seal_binds_namespace_key_kind_and_order() -> Result<()> {
        let original = digest("devres_mdn_evidence", "snapshots", "a", 1)?;
        for (table, kind, key, seq) in [
            ("devres_npm_evidence", "snapshots", "a", 1),
            ("devres_mdn_evidence", "views", "a", 1),
            ("devres_mdn_evidence", "snapshots", "b", 1),
            ("devres_mdn_evidence", "snapshots", "a", 2),
        ] {
            assert_ne!(original, digest(table, kind, key, seq)?);
        }
        assert!(digest("devres_mdn_evidence", "snapshots", "a", 0).is_err());
        assert!(digest("other", "snapshots", "a", 1).is_err());
        Ok(())
    }
}
