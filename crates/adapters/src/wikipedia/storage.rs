//! Owner-fenced Wikipedia evidence with atomic private work/checkpoint publication.
use super::{PgBlobStore, payload_integrity, sequence_integrity, storage_error};
use async_trait::async_trait;
use devres_application::wikipedia::{Row, State, WikipediaStore, Write, validate_writes};
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, row::Row as _, types::Json};
use sqlx_postgres::{PgConnection, PgRow};

const EVIDENCE: &str = "devres_wikipedia_evidence";
const STATE: &str = "devres_wikipedia_state";
const READ_BYTES: i64 = 64 * 1024 * 1024;

fn key(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(Error::invalid("Invalid Wikipedia evidence key."));
    }
    Ok(())
}
fn kind(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
    {
        return Err(Error::invalid("Invalid Wikipedia evidence kind."));
    }
    Ok(())
}
fn page(after: i64, limit: usize, cutoff: Option<i64>) -> Result<()> {
    if after < 0 || !(1..=100).contains(&limit) || cutoff.is_some_and(|value| value < 0) {
        return Err(Error::invalid("Invalid Wikipedia evidence page."));
    }
    Ok(())
}
fn evidence(row: PgRow) -> Result<Row> {
    Ok(Row {
        sequence: row.try_get("sequence").map_err(|_| storage_error())?,
        key: row.try_get("key").map_err(|_| storage_error())?,
        data: payload_integrity::row(EVIDENCE, &row)?,
    })
}
fn state(row: PgRow) -> Result<State> {
    let key: String = row.try_get("key").map_err(|_| storage_error())?;
    let data: Json<Value> = row.try_get("data").map_err(|_| storage_error())?;
    let due_at: Option<i64> = row.try_get("due_at").map_err(|_| storage_error())?;
    let expected: String = row.try_get("data_integrity").map_err(|_| storage_error())?;
    payload_integrity::checked(STATE, "", &key, state_payload(&data.0, due_at), &expected)?;
    Ok(State {
        key,
        data: data.0,
        due_at,
    })
}
fn state_payload(data: &Value, due_at: Option<i64>) -> Value {
    json!({"data":data,"due_at":due_at})
}
fn read_bound(bytes: i64) -> Result<()> {
    if bytes > READ_BYTES {
        return Err(Error::capacity(
            "Wikipedia evidence page exceeds its memory bound.",
        ));
    }
    Ok(())
}
async fn commit_rows(conn: &mut PgConnection, rows: &[Write], states: &[State]) -> Result<()> {
    for write in rows {
        let existing = sqlx_core::query::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_wikipedia_evidence WHERE kind=$1 AND key=$2")
            .bind(&write.kind).bind(&write.key).fetch_optional(&mut *conn).await.map_err(|_|storage_error())?;
        if let Some(existing) = existing {
            if evidence(existing)?.data != write.data {
                return Err(Error::integrity(
                    "Wikipedia immutable evidence identity collision.",
                ));
            }
            continue;
        }
        let sequence = sequence_integrity::reserve_one(conn, EVIDENCE).await?;
        sqlx_core::query::query("INSERT INTO devres_wikipedia_evidence(sequence,kind,key,data,data_integrity,sequence_integrity) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(sequence).bind(&write.kind).bind(&write.key).bind(Json(&write.data))
            .bind(payload_integrity::digest(EVIDENCE,&write.kind,&write.key,&write.data)?)
            .bind(sequence_integrity::digest(EVIDENCE,&write.kind,&write.key,sequence)?)
            .execute(&mut *conn).await.map_err(|_|storage_error())?;
    }
    for write in states {
        let expected = payload_integrity::digest(
            STATE,
            "",
            &write.key,
            &state_payload(&write.data, write.due_at),
        )?;
        sqlx_core::query::query("INSERT INTO devres_wikipedia_state(key,data,due_at,data_integrity) VALUES($1,$2,$3,$4) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,due_at=EXCLUDED.due_at,data_integrity=EXCLUDED.data_integrity")
            .bind(&write.key).bind(Json(&write.data)).bind(write.due_at).bind(expected)
            .execute(&mut *conn).await.map_err(|_|storage_error())?;
    }
    Ok(())
}

#[async_trait]
impl WikipediaStore for PgBlobStore {
    async fn wiki_get(&self, selected_kind: &str, selected_key: &str) -> Result<Option<Row>> {
        kind(selected_kind)?;
        key(selected_key)?;
        self.fence().await?;
        sqlx_core::query::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_wikipedia_evidence WHERE kind=$1 AND key=$2")
            .bind(selected_kind).bind(selected_key).fetch_optional(&self.pool).await.map_err(|_|storage_error())?
            .map(evidence).transpose()
    }
    async fn wiki_rows(
        &self,
        selected_kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
    ) -> Result<Vec<Row>> {
        kind(selected_kind)?;
        page(after, limit, cutoff)?;
        self.fence().await?;
        let mut tx = self.wiki_read_transaction().await?;
        let bytes: i64 = sqlx_core::query_scalar::query_scalar("SELECT COALESCE(sum(bytes),0)::bigint FROM (SELECT octet_length(data::text) AS bytes FROM devres_wikipedia_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) ORDER BY sequence LIMIT $4) selected")
            .bind(selected_kind).bind(after).bind(cutoff).bind(limit as i64).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        read_bound(bytes)?;
        sqlx_core::query::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_wikipedia_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) ORDER BY sequence LIMIT $4")
            .bind(selected_kind).bind(after).bind(cutoff).bind(limit as i64).fetch_all(&mut *tx).await.map_err(|_|storage_error())?
            .into_iter().map(evidence).collect()
    }
    async fn wiki_cutoff(&self) -> Result<i64> {
        self.fence().await?;
        sqlx_core::query_scalar::query_scalar(
            "SELECT COALESCE(max(sequence),0) FROM devres_wikipedia_evidence",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| storage_error())
    }
    async fn wiki_catalog(
        &self,
        after_page_id: u64,
        limit: usize,
        cutoff: i64,
    ) -> Result<Vec<Row>> {
        page(0, limit, Some(cutoff))?;
        self.fence().await?;
        let mut tx = self.wiki_read_transaction().await?;
        let bytes: i64 = sqlx_core::query_scalar::query_scalar("SELECT COALESCE(sum(bytes),0)::bigint FROM (SELECT DISTINCT ON ((data->>'page_id')::numeric) (data->>'page_id')::numeric AS page_id,octet_length(data::text) AS bytes FROM devres_wikipedia_evidence WHERE kind='captures' AND data->>'representation'='html' AND sequence<=$2 AND (data->>'page_id')::numeric>$1::text::numeric ORDER BY (data->>'page_id')::numeric,sequence DESC LIMIT $3) selected")
            .bind(after_page_id.to_string()).bind(cutoff).bind(limit as i64).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        read_bound(bytes)?;
        sqlx_core::query::query("SELECT DISTINCT ON ((data->>'page_id')::numeric) sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_wikipedia_evidence WHERE kind='captures' AND data->>'representation'='html' AND sequence<=$2 AND (data->>'page_id')::numeric>$1::text::numeric ORDER BY (data->>'page_id')::numeric,sequence DESC LIMIT $3")
            .bind(after_page_id.to_string()).bind(cutoff).bind(limit as i64).fetch_all(&mut *tx).await.map_err(|_|storage_error())?
            .into_iter().map(evidence).collect()
    }
    async fn wiki_page_captures(
        &self,
        page_id: u64,
        after: i64,
        limit: usize,
        cutoff: i64,
    ) -> Result<Vec<Row>> {
        page(after, limit, Some(cutoff))?;
        self.fence().await?;
        let mut tx = self.wiki_read_transaction().await?;
        let bytes: i64 = sqlx_core::query_scalar::query_scalar("SELECT COALESCE(sum(bytes),0)::bigint FROM (SELECT octet_length(data::text) AS bytes FROM devres_wikipedia_evidence WHERE kind='captures' AND data->>'page_id'=$1 AND sequence>$2 AND sequence<=$3 ORDER BY sequence LIMIT $4) selected")
            .bind(page_id.to_string()).bind(after).bind(cutoff).bind(limit as i64).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        read_bound(bytes)?;
        sqlx_core::query::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_wikipedia_evidence WHERE kind='captures' AND data->>'page_id'=$1 AND sequence>$2 AND sequence<=$3 ORDER BY sequence LIMIT $4")
            .bind(page_id.to_string()).bind(after).bind(cutoff).bind(limit as i64).fetch_all(&mut *tx).await.map_err(|_|storage_error())?
            .into_iter().map(evidence).collect()
    }
    async fn wiki_state(&self, selected_key: &str) -> Result<Option<Value>> {
        key(selected_key)?;
        self.fence().await?;
        sqlx_core::query::query(
            "SELECT key,data,due_at,data_integrity FROM devres_wikipedia_state WHERE key=$1",
        )
        .bind(selected_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| storage_error())?
        .map(|row| state(row).map(|row| row.data))
        .transpose()
    }
    async fn wiki_states(&self, prefix: &str, after: &str, limit: usize) -> Result<Vec<State>> {
        key(prefix)?;
        page(0, limit, None)?;
        if !after.is_empty() {
            key(after)?;
        }
        self.fence().await?;
        let mut tx = self.wiki_read_transaction().await?;
        let bytes: i64 = sqlx_core::query_scalar::query_scalar("SELECT COALESCE(sum(bytes),0)::bigint FROM (SELECT octet_length(data::text) AS bytes FROM devres_wikipedia_state WHERE starts_with(key,$1) AND key COLLATE \"C\">$2 COLLATE \"C\" ORDER BY key COLLATE \"C\" LIMIT $3) selected")
            .bind(prefix).bind(after).bind(limit as i64).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        read_bound(bytes)?;
        sqlx_core::query::query("SELECT key,data,due_at,data_integrity FROM devres_wikipedia_state WHERE starts_with(key,$1) AND key COLLATE \"C\">$2 COLLATE \"C\" ORDER BY key COLLATE \"C\" LIMIT $3")
            .bind(prefix).bind(after).bind(limit as i64).fetch_all(&mut *tx).await.map_err(|_|storage_error())?
            .into_iter().map(state).collect()
    }
    async fn wiki_due(&self, prefix: &str, now: i64, limit: usize) -> Result<Vec<State>> {
        key(prefix)?;
        page(0, limit, None)?;
        self.fence().await?;
        let mut tx = self.wiki_read_transaction().await?;
        let bytes: i64 = sqlx_core::query_scalar::query_scalar("SELECT COALESCE(sum(bytes),0)::bigint FROM (SELECT octet_length(data::text) AS bytes FROM devres_wikipedia_state WHERE starts_with(key,$1) AND due_at<=$2 ORDER BY due_at,key COLLATE \"C\" LIMIT $3) selected")
            .bind(prefix).bind(now).bind(limit as i64).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        read_bound(bytes)?;
        sqlx_core::query::query("SELECT key,data,due_at,data_integrity FROM devres_wikipedia_state WHERE starts_with(key,$1) AND due_at<=$2 ORDER BY due_at,key COLLATE \"C\" LIMIT $3")
            .bind(prefix).bind(now).bind(limit as i64).fetch_all(&mut *tx).await.map_err(|_|storage_error())?
            .into_iter().map(state).collect()
    }
    async fn wiki_commit(&self, rows: &[Write], states: &[State]) -> Result<()> {
        validate_writes(rows, states)?;
        for row in rows {
            kind(&row.kind)?;
            key(&row.key)?;
            if row.kind == "captures"
                && (row.data["page_id"].as_u64().is_none_or(|id| id == 0)
                    || row.data["revision_id"].as_u64().is_none_or(|id| id == 0)
                    || !matches!(
                        row.data["representation"].as_str(),
                        Some("html" | "wikitext")
                    ))
            {
                return Err(Error::invalid("Invalid Wikipedia capture identity."));
            }
        }
        for state in states {
            key(&state.key)?;
        }
        self.owner_fence().await?;
        let mut owner = self.owner.lock().await;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        if let Err(error) = commit_rows(&mut tx, rows, states).await {
            tx.rollback().await.map_err(|_| storage_error())?;
            return Err(error);
        }
        tx.commit().await.map_err(|_| storage_error())
    }
}

impl PgBlobStore {
    async fn wiki_read_transaction(
        &self,
    ) -> Result<sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>> {
        let mut tx = self.pool.begin().await.map_err(|_| storage_error())?;
        sqlx_core::query::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        Ok(tx)
    }
    /// Verify the new source's seals during offline verify/restore without requiring
    /// these additive tables to exist in an inspected pre-fourteen store.
    pub(super) async fn verify_wikipedia_storage(
        &self,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        use futures::TryStreamExt;
        let version: i32 = sqlx_core::query_scalar::query_scalar(
            "SELECT version FROM devres_schema WHERE singleton",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| storage_error())?;
        if version < 14 {
            return Ok(());
        }
        let mut rows = sqlx_core::query::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_wikipedia_evidence").fetch(&self.pool);
        while let Some(row) = rows.try_next().await.map_err(|_| storage_error())? {
            payload_integrity::seal_not_cancelled(cancel)?;
            evidence(row)?;
        }
        drop(rows);
        let mut rows = sqlx_core::query::query(
            "SELECT key,data,due_at,data_integrity FROM devres_wikipedia_state",
        )
        .fetch(&self.pool);
        while let Some(row) = rows.try_next().await.map_err(|_| storage_error())? {
            payload_integrity::seal_not_cancelled(cancel)?;
            state(row)?;
        }
        Ok(())
    }
}

pub(super) const SCHEMA_V14: &str = r#"
CREATE TABLE IF NOT EXISTS devres_wikipedia_evidence(
 sequence bigserial PRIMARY KEY, kind text NOT NULL, key text NOT NULL, data jsonb NOT NULL,
 data_integrity text NOT NULL CHECK(data_integrity ~ '^blake3:[0-9a-f]{64}$'),
 sequence_integrity text NOT NULL CHECK(sequence_integrity ~ '^blake3:[0-9a-f]{64}$'), UNIQUE(kind,key));
CREATE INDEX IF NOT EXISTS devres_wikipedia_evidence_page ON devres_wikipedia_evidence(kind,sequence);
CREATE INDEX IF NOT EXISTS devres_wikipedia_capture_page ON devres_wikipedia_evidence((data->>'page_id'),sequence) WHERE kind='captures';
CREATE INDEX IF NOT EXISTS devres_wikipedia_catalog_page ON devres_wikipedia_evidence(((data->>'page_id')::numeric),sequence DESC) WHERE kind='captures' AND data->>'representation'='html';
CREATE TABLE IF NOT EXISTS devres_wikipedia_state(key text PRIMARY KEY,data jsonb NOT NULL,due_at bigint,
 data_integrity text NOT NULL CHECK(data_integrity ~ '^blake3:[0-9a-f]{64}$'));
CREATE INDEX IF NOT EXISTS devres_wikipedia_state_key ON devres_wikipedia_state(key COLLATE "C");
CREATE INDEX IF NOT EXISTS devres_wikipedia_state_due ON devres_wikipedia_state(due_at,key COLLATE "C") WHERE due_at IS NOT NULL;
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn wikipedia_qualification_requires_exact_acquisition_and_is_withdrawn_separately() {
        use devres_application::attribution::AttributionStore;
        use devres_domain::attribution::{
            ATTRIBUTION_POLICY_EPOCH, ATTRIBUTION_POLICY_FINGERPRINT,
        };
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_wikipedia_qualification_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_wikipedia_qualification_fixture");
        let root = tempfile::tempdir().unwrap();
        let store = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let id = crate::integrity::hash(b"fixture Wikipedia acquisition");
        let data = json!({"id":id,"page_id":12,"revision_id":34,"title":"RISC-V","representation":"html",
            "source_url":"https://en.wikipedia.org/w/rest.php/v1/page/RISC-V/with_html?redirect=no",
            "artifact":{"body_hash":crate::integrity::hash(b"fixture raw article")},"observed_at":devres_domain::unix_now(),
            "license":{"url":"https://creativecommons.org/licenses/by-sa/4.0/deed.en"},
            "acquisition_policy_epoch":ATTRIBUTION_POLICY_EPOCH,"acquisition_policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT});
        store
            .wiki_commit(
                &[Write {
                    kind: "captures".into(),
                    key: id.clone(),
                    data: data.clone(),
                }],
                &[State {
                    key: "visibility:epoch".into(),
                    data: json!(0),
                    due_at: None,
                }],
            )
            .await
            .unwrap();
        let target = crate::wikipedia::attribution::target(&data)
            .unwrap()
            .unwrap();
        let generation = crate::wikipedia::attribution::repair(
            &store,
            &target,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(generation.notices[0].text.contains("derived"));
        store.attribution_enqueue(&target, 1).await.unwrap();
        let job = store
            .attribution_claim(&["wikipedia".into()], devres_domain::unix_now())
            .await
            .unwrap()
            .unwrap();
        store.attribution_complete(&job, &generation).await.unwrap();
        assert!(
            store
                .attribution_ready(&target.subject)
                .await
                .unwrap()
                .is_some()
        );
        crate::wikipedia::attribution::ensure_public(&store, &target.subject)
            .await
            .unwrap();
        store
            .wiki_commit(
                &[],
                &[
                    State {
                        key: "visibility:revision:12:34".into(),
                        data: json!({"blocked":true}),
                        due_at: None,
                    },
                    State {
                        key: "visibility:epoch".into(),
                        data: json!(1),
                        due_at: None,
                    },
                ],
            )
            .await
            .unwrap();
        assert_eq!(
            crate::wikipedia::attribution::ensure_public(&store, &target.subject)
                .await
                .unwrap_err()
                .code,
            "wikipedia_withheld"
        );
        assert!(
            store
                .attribution_ready(&target.subject)
                .await
                .unwrap()
                .is_some(),
            "withholding does not rewrite immutable qualification"
        );
        for (label, field, value) in [
            ("old-policy", "acquisition_policy_epoch", json!(0)),
            (
                "wrong-license",
                "license",
                json!({"url":"https://attacker.invalid/license"}),
            ),
        ] {
            let mut invalid = data.clone();
            let id = crate::integrity::hash(label.as_bytes());
            invalid["id"] = json!(id);
            invalid[field] = value;
            store
                .wiki_commit(
                    &[Write {
                        kind: "captures".into(),
                        key: id,
                        data: invalid.clone(),
                    }],
                    &[],
                )
                .await
                .unwrap();
            let target = crate::wikipedia::attribution::target(&invalid)
                .unwrap()
                .unwrap();
            assert!(
                crate::wikipedia::attribution::repair(
                    &store,
                    &target,
                    tokio_util::sync::CancellationToken::new()
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn atomic_checkpoints_catalog_history_and_seals_survive_reopen() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_wikipedia_storage_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_wikipedia_storage_fixture");
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        let capture = |id: u64, rev: u64, representation: &str| Write {
            kind: "captures".into(),
            key: crate::integrity::hash(format!("{id}/{rev}/{representation}").as_bytes()),
            data: json!({"page_id":id,"revision_id":rev,"representation":representation}),
        };
        let first = capture(11, 100, "html");
        let other = capture(22, 101, "html");
        let stream = State {
            key: "stream".into(),
            data: json!({"id":"event-one"}),
            due_at: None,
        };
        let pending = State {
            key: "page:11".into(),
            data: json!({"revision":100}),
            due_at: Some(10),
        };
        store
            .wiki_commit(
                &[first.clone(), other.clone()],
                &[stream.clone(), pending.clone()],
            )
            .await
            .unwrap();
        let cutoff = store.wiki_cutoff().await.unwrap();
        store
            .wiki_commit(std::slice::from_ref(&first), std::slice::from_ref(&stream))
            .await
            .unwrap();
        assert_eq!(store.wiki_cutoff().await.unwrap(), cutoff);
        let next = capture(11, 102, "html");
        let source = capture(11, 102, "wikitext");
        store
            .wiki_commit(&[next.clone(), source], &[])
            .await
            .unwrap();
        let all_cutoff = store.wiki_cutoff().await.unwrap();
        assert_eq!(
            store.wiki_catalog(0, 100, cutoff).await.unwrap()[0].key,
            first.key
        );
        let catalog = store.wiki_catalog(0, 1, all_cutoff).await.unwrap();
        assert_eq!(catalog[0].key, next.key);
        assert_eq!(
            store.wiki_catalog(11, 100, all_cutoff).await.unwrap()[0].key,
            other.key
        );
        assert_eq!(
            store
                .wiki_page_captures(11, 0, 100, all_cutoff)
                .await
                .unwrap()
                .len(),
            3
        );
        assert!(store.wiki_due("page:", 9, 100).await.unwrap().is_empty());
        assert_eq!(
            store.wiki_due("page:", 10, 100).await.unwrap()[0].key,
            pending.key
        );
        let mut collision = first.clone();
        collision.data["revision_id"] = json!(999);
        assert!(
            store
                .wiki_commit(
                    &[capture(33, 103, "html"), collision],
                    &[State {
                        key: "stream".into(),
                        data: json!({"id":"must-not-commit"}),
                        due_at: None
                    }]
                )
                .await
                .is_err()
        );
        assert_eq!(store.wiki_state("stream").await.unwrap(), Some(stream.data));
        assert!(
            store
                .wiki_get("captures", &capture(33, 103, "html").key)
                .await
                .unwrap()
                .is_none()
        );
        store
            .verify_wikipedia_storage(&tokio_util::sync::CancellationToken::new())
            .await
            .unwrap();
        let reader = PgBlobStore::connect_reader(url.as_str(), root.path(), None)
            .await
            .unwrap();
        assert!(
            reader
                .wiki_commit(&[], std::slice::from_ref(&pending))
                .await
                .is_err()
        );
        assert_eq!(
            reader.wiki_catalog(0, 100, all_cutoff).await.unwrap().len(),
            2
        );
        drop(reader);
        drop(store);
        let store = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        assert_eq!(
            store.wiki_catalog(0, 100, all_cutoff).await.unwrap()[0].key,
            next.key
        );
        sqlx_core::query::query("UPDATE devres_wikipedia_state SET due_at=11 WHERE key='page:11'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            store.wiki_state("page:11").await.unwrap_err().code,
            "integrity"
        );
        assert_eq!(
            store.wiki_due("page:", 12, 100).await.unwrap_err().code,
            "integrity"
        );
        sqlx_core::query::query("UPDATE devres_wikipedia_state SET due_at=10 WHERE key='page:11'")
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx_core::query::query("UPDATE devres_wikipedia_evidence SET data=jsonb_set(data,'{revision_id}','999') WHERE key=$1").bind(&first.key).execute(&store.pool).await.unwrap();
        assert_eq!(
            store
                .wiki_get("captures", &first.key)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert_eq!(
            store
                .verify_wikipedia_storage(&tokio_util::sync::CancellationToken::new())
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn additive_upgrade_requires_new_reader_and_keeps_existing_provider_evidence() {
        use devres_application::Store;
        use devres_domain::{FetchRequest, FetchResponse, Validators};
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_wikipedia_upgrade_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_wikipedia_upgrade_fixture");
        let root = tempfile::tempdir().unwrap();
        let store = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let request = FetchRequest {
            key: "fixture:before-wikipedia".into(),
            url: "https://fixtures.invalid/article".into(),
            ttl_secs: 60,
            max_bytes: 128,
            media_type: "text/plain".into(),
        };
        let capture = store
            .publish(
                &request,
                FetchResponse {
                    status: 200,
                    body: b"retained before additive upgrade".to_vec(),
                    validators: Validators::default(),
                },
                10,
            )
            .await
            .unwrap();
        let old_reader = PgBlobStore::connect_reader(url.as_str(), root.path(), None)
            .await
            .unwrap();
        sqlx_core::raw_sql::raw_sql("DROP TABLE devres_wikipedia_evidence; DROP TABLE devres_wikipedia_state; UPDATE devres_schema SET version=13 WHERE singleton").execute(&store.pool).await.unwrap();
        assert!(
            PgBlobStore::connect_reader(url.as_str(), root.path(), None)
                .await
                .is_err()
        );
        drop(store);
        assert!(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .is_err(),
            "schema upgrade must not run while an old reader holds lifecycle authority"
        );
        drop(old_reader);
        let upgraded = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        assert_eq!(upgraded.wiki_cutoff().await.unwrap(), 0);
        assert_eq!(
            &*upgraded.capture(&capture.capture.id).await.unwrap().body,
            b"retained before additive upgrade"
        );
        let reader = PgBlobStore::connect_reader(url.as_str(), root.path(), None)
            .await
            .unwrap();
        assert_eq!(reader.wiki_cutoff().await.unwrap(), 0);
    }
}
