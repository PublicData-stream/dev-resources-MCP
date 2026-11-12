//! Additive immutable v2 derivations. Legacy artifact-only enrichment stays untouched.
use super::*;
use sqlx_postgres::PgConnection;

pub(super) const SCHEMA_V15: &str = r#"
CREATE TABLE devres_crate_enrichment_v2(derivation text NOT NULL,artifact text NOT NULL REFERENCES devres_crate_artifacts(capture_id),kind text NOT NULL,external_id text NOT NULL,data jsonb NOT NULL,data_integrity text NOT NULL,PRIMARY KEY(derivation,kind,external_id));
CREATE INDEX devres_crate_enrichment_v2_name ON devres_crate_enrichment_v2(derivation,kind,(data->>'name'));
CREATE INDEX devres_crate_enrichment_v2_version ON devres_crate_enrichment_v2(derivation,kind,(data->>'crate_id'),(data->>'num'));
CREATE TABLE devres_crate_enrichment_heads_v2(derivation text PRIMARY KEY,artifact text NOT NULL REFERENCES devres_crate_artifacts(capture_id),sequence bigint NOT NULL UNIQUE DEFAULT nextval('devres_crate_enrichment_heads_sequence_seq'),processor text NOT NULL CHECK(processor='crates-dump-v2'),summary jsonb NOT NULL,membership jsonb NOT NULL,head_integrity text NOT NULL);
CREATE TABLE devres_crate_dump_failures(id text PRIMARY KEY,artifact text NOT NULL REFERENCES devres_crate_artifacts(capture_id),observed_at bigint NOT NULL,processor text NOT NULL CHECK(processor='crates-dump-v2'),diagnostic jsonb NOT NULL,diagnostic_integrity text NOT NULL);
CREATE INDEX devres_crate_dump_failures_latest ON devres_crate_dump_failures(observed_at DESC,id DESC);
CREATE FUNCTION devres_crate_enrichment_v2_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'immutable enrichment evidence'; END IF;
IF EXISTS(SELECT 1 FROM devres_crate_enrichment_heads_v2 WHERE derivation=NEW.derivation) THEN RAISE EXCEPTION 'published enrichment membership is immutable'; END IF;
RETURN NEW; END $$;
CREATE TRIGGER devres_crate_enrichment_v2_immutable BEFORE INSERT OR UPDATE OR DELETE ON devres_crate_enrichment_v2 FOR EACH ROW EXECUTE FUNCTION devres_crate_enrichment_v2_immutable();
CREATE FUNCTION devres_crate_enrichment_head_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable enrichment publication'; END $$;
CREATE TRIGGER devres_crate_enrichment_head_immutable BEFORE UPDATE OR DELETE ON devres_crate_enrichment_heads_v2 FOR EACH ROW EXECUTE FUNCTION devres_crate_enrichment_head_immutable();
CREATE VIEW devres_crate_enrichment_all AS SELECT artifact AS selection,artifact,kind,external_id,data,data_integrity FROM devres_crate_enrichment UNION ALL SELECT derivation AS selection,artifact,kind,external_id,data,data_integrity FROM devres_crate_enrichment_v2;
"#;

fn head_payload(sequence: i64, artifact: &str, summary: &Value, membership: &Value) -> Value {
    json!({"sequence":sequence,"artifact":artifact,"processor":crate::crates_io::dump::PROCESSOR,"summary":summary,"membership":membership})
}
pub(crate) fn checked_head(row: &sqlx_postgres::PgRow) -> Result<EnrichmentSelection> {
    let artifact: String = row.try_get("artifact").map_err(|_| storage_error())?;
    let derivation: String = row.try_get("derivation").map_err(|_| storage_error())?;
    let processor: String = row.try_get("processor").map_err(|_| storage_error())?;
    let summary: Json<Value> = row.try_get("summary").map_err(|_| storage_error())?;
    let membership: Json<Value> = row.try_get("membership").map_err(|_| storage_error())?;
    validate_counts(&summary.0, &membership.0)?;
    if processor != crate::crates_io::dump::PROCESSOR
        || summary.0["artifact"] != artifact
        || summary.0["processor"] != processor
    {
        return Err(Error::integrity(
            "Enrichment publication metadata differs from its processor.",
        ));
    }
    let selection = EnrichmentSelection {
        capture: artifact,
        derivation: Some(derivation.clone()),
    };
    crate::crates_io::enrichment::validate_selection(&selection)?;
    payload_integrity::checked(
        "devres_crate_enrichment_heads_v2",
        "",
        &derivation,
        head_payload(
            row.try_get("sequence").map_err(|_| storage_error())?,
            &selection.capture,
            &summary.0,
            &membership.0,
        ),
        &row.try_get::<String, _>("head_integrity")
            .map_err(|_| storage_error())?,
    )?;
    Ok(selection)
}
pub(super) async fn latest_selection(
    connection: &mut PgConnection,
) -> Result<Option<EnrichmentSelection>> {
    let row = sqlx_core::query::query("SELECT artifact,derivation,sequence,processor,summary,membership,head_integrity FROM (SELECT artifact,NULL::text AS derivation,sequence,NULL::text AS processor,NULL::jsonb AS summary,NULL::jsonb AS membership,NULL::text AS head_integrity FROM devres_crate_enrichment_heads UNION ALL SELECT artifact,derivation,sequence,processor,summary,membership,head_integrity FROM devres_crate_enrichment_heads_v2) heads ORDER BY sequence DESC LIMIT 1")
        .fetch_optional(connection).await.map_err(|_| storage_error())?;
    row.map(|row| {
        let derivation: Option<String> = row.try_get("derivation").map_err(|_| storage_error())?;
        if derivation.is_some() {
            checked_head(&row)
        } else {
            let capture = row.try_get("artifact").map_err(|_| storage_error())?;
            let selection = EnrichmentSelection {
                capture,
                derivation: None,
            };
            crate::crates_io::enrichment::validate_selection(&selection)?;
            Ok(selection)
        }
    })
    .transpose()
}
pub(super) async fn require_published(
    store: &PgBlobStore,
    selection: &EnrichmentSelection,
) -> Result<()> {
    if let Some(derivation) = &selection.derivation {
        let row = sqlx_core::query::query(
            "SELECT * FROM devres_crate_enrichment_heads_v2 WHERE derivation=$1",
        )
        .bind(derivation)
        .fetch_optional(&store.pool)
        .await
        .map_err(|_| storage_error())?
        .ok_or_else(|| Error::unavailable("Selected enrichment is not published."))?;
        if checked_head(&row)? != *selection {
            return Err(Error::integrity(
                "Enrichment publication selection changed.",
            ));
        }
        let mut verified = store.enrichment_membership.lock().await;
        if !verified.contains(derivation) {
            let expected = row
                .try_get::<Json<Value>, _>("membership")
                .map_err(|_| storage_error())?
                .0;
            let actual = tokio::time::timeout(std::time::Duration::from_secs(300), async {
                let mut connection = store.pool.acquire().await.map_err(|_| storage_error())?;
                membership(&mut connection, selection).await
            })
            .await
            .map_err(|_| {
                Error::capacity("Enrichment membership verification deadline exceeded.")
            })??;
            if actual != expected {
                return Err(Error::integrity("Published enrichment membership changed."));
            }
            if verified.len() >= 256 {
                verified.clear();
            }
            verified.insert(derivation.to_owned());
        }
    }
    Ok(())
}
pub(crate) async fn initialize_membership(store: &PgBlobStore) -> Result<()> {
    let mut connection = store.pool.acquire().await.map_err(|_| storage_error())?;
    let selection = latest_selection(&mut connection).await?;
    drop(connection);
    if let Some(selection) = selection {
        require_published(store, &selection).await?;
    }
    Ok(())
}
impl PgBlobStore {
    pub(super) async fn save_dump_failure(&self, artifact: &str, diagnostic: &Value) -> Result<()> {
        self.owner_fence().await?;
        checked_id(artifact)?;
        let diagnostic: crate::crates_io::dump::CsvDiagnostic =
            serde_json::from_value(diagnostic.clone())
                .map_err(|_| Error::integrity("Invalid private CSV diagnostic."))?;
        if diagnostic.version != 1 || diagnostic.column > 128 {
            return Err(Error::integrity(
                "Invalid private CSV diagnostic version or position.",
            ));
        }
        let observed_at = devres_domain::unix_now();
        let payload = json!({"artifact":artifact,"observed_at":observed_at,"processor":crate::crates_io::dump::PROCESSOR,"diagnostic":diagnostic});
        let id = hash(&serde_json::to_vec(&payload).map_err(|_| storage_error())?);
        let seal = payload_integrity::digest("devres_crate_dump_failures", "", &id, &payload)?;
        let mut owner = self.owner.lock().await;
        sqlx_core::query::query("INSERT INTO devres_crate_dump_failures(id,artifact,observed_at,processor,diagnostic,diagnostic_integrity) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
            .bind(id).bind(artifact).bind(observed_at).bind(crate::crates_io::dump::PROCESSOR).bind(Json(json_limit(&payload["diagnostic"], 4096)?)).bind(seal)
            .execute(&mut *owner).await.map_err(|_| storage_error())?;
        Ok(())
    }
    pub(super) async fn put_v2_enrichment(
        &self,
        selection: &EnrichmentSelection,
        kind: &str,
        rows: &[(String, Value)],
    ) -> Result<()> {
        self.owner_fence().await?;
        crate::crates_io::enrichment::validate_selection(selection)?;
        let derivation = selection.derivation.as_deref().ok_or_else(storage_error)?;
        if rows.len() > crate::crates_io::enrichment::MAX_ROWS
            || !matches!(
                kind,
                "crates"
                    | "versions"
                    | "keywords"
                    | "categories"
                    | "crates_keywords"
                    | "crates_categories"
                    | "dependencies"
                    | "crate_downloads"
            )
        {
            return Err(Error::invalid("Invalid metadata enrichment batch."));
        }
        let mut unique = std::collections::HashSet::new();
        let values = rows
            .iter()
            .map(|(key, value)| {
                if !unique.insert(key) {
                    return Err(Error::integrity("Duplicate enrichment identity."));
                }
                crate::crates_io::enrichment::row(
                    key,
                    value,
                    &payload_integrity::digest(
                        "devres_crate_enrichment_v2",
                        &format!("{derivation}:{kind}"),
                        key,
                        value,
                    )?,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let value = json_limit(&values, crate::crates_io::enrichment::MAX_BYTES)?;
        let mut owner = self.owner.lock().await;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let outcome: Result<()> = async {
        sqlx_core::query::query("INSERT INTO devres_crate_enrichment_v2(derivation,artifact,kind,external_id,data,data_integrity) SELECT $1,$2,$3,r.id,r.value,r.integrity FROM jsonb_to_recordset($4::jsonb) AS r(id text,value jsonb,integrity text) WHERE NOT EXISTS(SELECT 1 FROM devres_crate_enrichment_heads_v2 WHERE derivation=$1) ON CONFLICT DO NOTHING")
            .bind(derivation).bind(&selection.capture).bind(kind).bind(Json(value)).execute(&mut *tx).await.map_err(|_| storage_error())?;
        let ids = rows.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
        let retained = sqlx_core::query::query("SELECT artifact,external_id,data,data_integrity FROM devres_crate_enrichment_v2 WHERE derivation=$1 AND kind=$2 AND external_id=ANY($3::text[])")
            .bind(derivation).bind(kind).bind(&ids).fetch_all(&mut *tx).await.map_err(|_| storage_error())?;
        if retained.len() != rows.len() { return Err(Error::integrity("Published enrichment cannot acquire additional rows.")); }
        for row in retained {
            let key: String = row.try_get("external_id").map_err(|_| storage_error())?;
            if row.try_get::<String, _>("artifact").map_err(|_| storage_error())? != selection.capture {
                return Err(Error::integrity("Enrichment derivation capture changed."));
            }
            let data = checked_selected_enrichment(selection, kind, &row)?;
            if rows.iter().find(|(id, _)| *id == key).is_none_or(|(_, expected)| *expected != data) {
                return Err(Error::integrity("Immutable enrichment identity collision."));
            }
        }
        Ok(())
        }.await;
        if let Err(error) = outcome {
            tx.rollback().await.map_err(|_| storage_error())?;
            return Err(error);
        }
        tx.commit().await.map_err(|_| storage_error())
    }
    pub(super) async fn commit_v2_enrichment(
        &self,
        selection: &EnrichmentSelection,
        summary: &Value,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        tokio::select! { biased;
            _ = cancel.cancelled() => return Err(Error::new("cancelled", "Enrichment publication canceled.")),
            result = self.owner_fence() => result?,
        }
        crate::crates_io::enrichment::validate_selection(selection)?;
        let derivation = selection.derivation.as_deref().ok_or_else(storage_error)?;
        if summary["artifact"] != selection.capture
            || summary["processor"] != crate::crates_io::dump::PROCESSOR
        {
            return Err(Error::integrity(
                "Enrichment publication summary differs from its derivation.",
            ));
        }
        let summary = json_limit(summary, 1024 * 1024)?;
        let mut owner = tokio::select! { biased;
            _ = cancel.cancelled() => return Err(Error::new("cancelled", "Enrichment publication canceled.")),
            owner = self.owner.lock() => owner,
        };
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx_core::query::query("SET LOCAL statement_timeout='300s'")
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        sqlx_core::query::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        let outcome: Result<()> = {
            let work = async {
                let membership = membership(&mut tx, selection).await?;
                validate_counts(&summary, &membership)?;
                let existing = sqlx_core::query::query(
                    "SELECT * FROM devres_crate_enrichment_heads_v2 WHERE derivation=$1",
                )
                .bind(derivation)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
                if let Some(row) = existing {
                    if checked_head(&row)? != *selection
                        || row
                            .try_get::<Json<Value>, _>("summary")
                            .map_err(|_| storage_error())?
                            .0
                            != summary
                        || row
                            .try_get::<Json<Value>, _>("membership")
                            .map_err(|_| storage_error())?
                            .0
                            != membership
                    {
                        return Err(Error::integrity(
                            "Immutable enrichment publication changed.",
                        ));
                    }
                } else {
                    let sequence: i64 = sqlx_core::query_scalar::query_scalar(
                        "SELECT nextval('devres_crate_enrichment_heads_sequence_seq')",
                    )
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| storage_error())?;
                    let seal = payload_integrity::digest(
                        "devres_crate_enrichment_heads_v2",
                        "",
                        derivation,
                        &head_payload(sequence, &selection.capture, &summary, &membership),
                    )?;
                    sqlx_core::query::query("INSERT INTO devres_crate_enrichment_heads_v2(derivation,artifact,sequence,processor,summary,membership,head_integrity) VALUES($1,$2,$3,$4,$5,$6,$7)")
                .bind(derivation).bind(&selection.capture).bind(sequence).bind(crate::crates_io::dump::PROCESSOR).bind(Json(summary)).bind(Json(membership)).bind(seal)
                .execute(&mut *tx).await.map_err(|_| storage_error())?;
                }
                Ok(())
            };
            tokio::pin!(work);
            tokio::select! { biased;
                _ = cancel.cancelled() => Err(Error::new("cancelled", "Enrichment publication canceled.")),
                _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => Err(Error::capacity("Enrichment publication deadline exceeded.")),
                result = &mut work => result,
            }
        };
        if let Err(error) = outcome {
            tx.rollback().await.map_err(|_| storage_error())?;
            return Err(error);
        }
        tx.commit().await.map_err(|_| storage_error())
    }
}

/// Complete storage verification remains read-only and checks staged rows as well as heads.
pub(crate) async fn verify(
    store: &PgBlobStore,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<()> {
    let mut after = (String::new(), String::new(), String::new());
    loop {
        if cancel.is_cancelled() {
            return Err(Error::new("cancelled", "Enrichment verification canceled."));
        }
        let size: Option<i64> = sqlx_core::query_scalar::query_scalar("SELECT octet_length(data::text)::bigint FROM devres_crate_enrichment_v2 WHERE (derivation,kind,external_id)>($1,$2,$3) ORDER BY derivation,kind,external_id LIMIT 1")
            .bind(&after.0).bind(&after.1).bind(&after.2).fetch_optional(&store.pool).await.map_err(|_| storage_error())?;
        let Some(size) = size else {
            break;
        };
        if !(0..=crate::crates_io::enrichment::MAX_BYTES as i64).contains(&size) {
            return Err(Error::capacity(
                "Enrichment verification row exceeds its byte bound.",
            ));
        }
        let row = sqlx_core::query::query("SELECT * FROM devres_crate_enrichment_v2 WHERE (derivation,kind,external_id)>($1,$2,$3) ORDER BY derivation,kind,external_id LIMIT 1")
            .bind(&after.0).bind(&after.1).bind(&after.2).fetch_one(&store.pool).await.map_err(|_| storage_error())?;
        let derivation = row.try_get("derivation").map_err(|_| storage_error())?;
        let kind: String = row.try_get("kind").map_err(|_| storage_error())?;
        let key = row.try_get("external_id").map_err(|_| storage_error())?;
        let selection = EnrichmentSelection {
            capture: row.try_get("artifact").map_err(|_| storage_error())?,
            derivation: Some(derivation),
        };
        crate::crates_io::enrichment::validate_selection(&selection)?;
        checked_selected_enrichment(&selection, &kind, &row)?;
        after = (selection.derivation.ok_or_else(storage_error)?, kind, key);
    }
    let mut after = String::new();
    loop {
        if cancel.is_cancelled() {
            return Err(Error::new("cancelled", "Enrichment verification canceled."));
        }
        let size: Option<i64> = sqlx_core::query_scalar::query_scalar("SELECT octet_length(summary::text)::bigint FROM devres_crate_enrichment_heads_v2 WHERE derivation>$1 ORDER BY derivation LIMIT 1")
            .bind(&after).fetch_optional(&store.pool).await.map_err(|_| storage_error())?;
        let Some(size) = size else {
            break;
        };
        if !(0..=1024 * 1024).contains(&size) {
            return Err(Error::capacity(
                "Enrichment verification summary exceeds its byte bound.",
            ));
        }
        let row = sqlx_core::query::query("SELECT * FROM devres_crate_enrichment_heads_v2 WHERE derivation>$1 ORDER BY derivation LIMIT 1")
            .bind(&after).fetch_one(&store.pool).await.map_err(|_| storage_error())?;
        let selection = checked_head(&row)?;
        let mut connection = store.pool.acquire().await.map_err(|_| storage_error())?;
        let actual = tokio::select! { biased;
            _ = cancel.cancelled() => return Err(Error::new("cancelled", "Enrichment verification canceled.")),
            result = membership(&mut connection, &selection) => result?,
        };
        if row
            .try_get::<Json<Value>, _>("membership")
            .map_err(|_| storage_error())?
            .0
            != actual
        {
            return Err(Error::integrity("Published enrichment membership changed."));
        }
        after = selection.derivation.ok_or_else(storage_error)?;
    }
    let mut after = String::new();
    loop {
        if cancel.is_cancelled() {
            return Err(Error::new("cancelled", "Enrichment verification canceled."));
        }
        let size: Option<i64> = sqlx_core::query_scalar::query_scalar("SELECT octet_length(diagnostic::text)::bigint FROM devres_crate_dump_failures WHERE id>$1 ORDER BY id LIMIT 1")
            .bind(&after).fetch_optional(&store.pool).await.map_err(|_| storage_error())?;
        let Some(size) = size else {
            break;
        };
        if !(0..=4096).contains(&size) {
            return Err(Error::capacity(
                "Private CSV diagnostic exceeds its byte bound.",
            ));
        }
        let row = sqlx_core::query::query(
            "SELECT * FROM devres_crate_dump_failures WHERE id>$1 ORDER BY id LIMIT 1",
        )
        .bind(&after)
        .fetch_one(&store.pool)
        .await
        .map_err(|_| storage_error())?;
        after = checked_dump_failure(&row)?.0;
    }
    Ok(())
}

pub(crate) fn checked_dump_failure(row: &sqlx_postgres::PgRow) -> Result<(String, Value)> {
    let id: String = row.try_get("id").map_err(|_| storage_error())?;
    let artifact: String = row.try_get("artifact").map_err(|_| storage_error())?;
    checked_id(&artifact)?;
    let processor: String = row.try_get("processor").map_err(|_| storage_error())?;
    let diagnostic: Json<Value> = row.try_get("diagnostic").map_err(|_| storage_error())?;
    let typed: crate::crates_io::dump::CsvDiagnostic =
        serde_json::from_value(diagnostic.0.clone()).map_err(|_| storage_error())?;
    if typed.version != 1 || typed.column > 128 || processor != crate::crates_io::dump::PROCESSOR {
        return Err(Error::integrity("Invalid retained CSV diagnostic."));
    }
    let payload = json!({"artifact":artifact,"observed_at":row.try_get::<i64, _>("observed_at").map_err(|_| storage_error())?,"processor":processor,"diagnostic":diagnostic.0});
    if hash(&serde_json::to_vec(&payload).map_err(|_| storage_error())?) != id {
        return Err(Error::integrity("CSV diagnostic identity changed."));
    }
    payload_integrity::checked(
        "devres_crate_dump_failures",
        "",
        &id,
        payload.clone(),
        &row.try_get::<String, _>("diagnostic_integrity")
            .map_err(|_| storage_error())?,
    )?;
    Ok((id, payload))
}

async fn membership(
    connection: &mut PgConnection,
    selection: &EnrichmentSelection,
) -> Result<Value> {
    use futures::TryStreamExt;
    let derivation = selection.derivation.as_deref().ok_or_else(storage_error)?;
    let mut rows = sqlx_core::query::query("SELECT artifact,kind,external_id,data_integrity FROM devres_crate_enrichment_v2 WHERE derivation=$1 ORDER BY kind,external_id")
        .bind(derivation).fetch(connection);
    let mut counts = std::collections::BTreeMap::<String, u64>::new();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crate-enrichment-membership-v1\0");
    let mut visited = 0u64;
    while let Some(row) = rows.try_next().await.map_err(|_| storage_error())? {
        visited += 1;
        if visited.is_multiple_of(1000) {
            tokio::task::yield_now().await;
        }
        let artifact: String = row.try_get("artifact").map_err(|_| storage_error())?;
        let kind: String = row.try_get("kind").map_err(|_| storage_error())?;
        let key: String = row.try_get("external_id").map_err(|_| storage_error())?;
        let seal: String = row.try_get("data_integrity").map_err(|_| storage_error())?;
        if artifact != selection.capture
            || !crate::integrity::valid_hash(&seal)
            || key.len() > 128
            || kind.len() > 64
        {
            return Err(Error::integrity("Invalid enrichment membership identity."));
        }
        let count = counts.entry(kind.clone()).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| Error::capacity("Enrichment membership count exceeded."))?;
        let encoded = serde_json::to_vec(&json!([kind, key, seal])).map_err(|_| storage_error())?;
        hasher.update(&(encoded.len() as u64).to_le_bytes());
        hasher.update(&encoded);
    }
    Ok(json!({"version":1,"counts":counts,"root":format!("blake3:{}",hasher.finalize().to_hex())}))
}
fn validate_counts(summary: &Value, membership: &Value) -> Result<()> {
    let tables = summary["tables"]
        .as_object()
        .ok_or_else(|| Error::integrity("Enrichment summary lacks complete table counts."))?;
    let counts = membership["counts"].as_object().ok_or_else(storage_error)?;
    if membership["version"] != 1
        || membership["root"]
            .as_str()
            .is_none_or(|root| !root.starts_with("blake3:") || !crate::integrity::valid_hash(root))
        || !tables.contains_key("crates")
        || !tables.contains_key("versions")
    {
        return Err(Error::integrity("Invalid enrichment membership proof."));
    }
    for (kind, table) in tables {
        let expected = table["rows"].as_u64().ok_or_else(storage_error)?;
        if counts.get(kind).and_then(Value::as_u64).unwrap_or(0) != expected {
            return Err(Error::integrity(
                "Enrichment table count differs from complete parser output.",
            ));
        }
    }
    if counts.keys().any(|kind| !tables.contains_key(kind)) {
        return Err(Error::integrity("Unexpected staged enrichment table."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn snapshot_identity_verification_preserves_sha_and_canonical_successors() {
        let fixture = crate::crates_io::index::tests::fixture();
        let mut snapshot = fixture.snapshot.lock().unwrap().clone();
        let bytes = super::super::snapshot_identity_bytes(&snapshot).unwrap();
        snapshot.id = crate::integrity::legacy_hash(&bytes);
        crate::integrity::verify(
            &snapshot.id,
            &super::super::snapshot_identity_bytes(&snapshot).unwrap(),
        )
        .unwrap();
        let legacy = snapshot.id.clone();
        snapshot.id = super::super::snapshot_identity(&snapshot).unwrap();
        assert_ne!(snapshot.id, legacy);
        crate::integrity::verify(&snapshot.id, &bytes).unwrap();
        snapshot.enrichment_derivation =
            crate::crates_io::enrichment::selection(snapshot.enrichment.as_deref().unwrap())
                .unwrap()
                .derivation;
        let changed = super::super::snapshot_identity_bytes(&snapshot).unwrap();
        assert_ne!(changed, bytes);
        assert!(crate::integrity::verify(&legacy, &changed).is_err());
    }
    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn crate_corpus_captured_inventory_acquisition_research_and_restart_v2_enrichment() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_enrichment_v2_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_enrichment_v2_fixture");
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = std::sync::Arc::new(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        let now = devres_domain::unix_now();
        let raw = store
            .save_text(
                "cargo:derived:dump-fixture",
                "https://static.crates.io/db-dump.tar.gz",
                "inert retained evidence",
                json!({"transport":"https"}),
                now,
            )
            .await
            .unwrap();
        let inventory = store.begin_inventory(&"a".repeat(40), now).await.unwrap();
        let record = json!({"name":"synthetic","vers":"1.0.0","deps":[],"features":{},"cksum":"a".repeat(64),"yanked":false});
        let metadata = store
            .import_metadata(
                "synthetic",
                &"a".repeat(40),
                "sy/nt/synthetic",
                &"b".repeat(40),
                format!("{record}\n").as_bytes(),
                now,
            )
            .await
            .unwrap();
        store
            .stage_crate(
                &inventory.id,
                "synthetic",
                &[devres_application::crate_corpus::VersionRecord {
                    name: "synthetic".into(),
                    version: "1.0.0".into(),
                    metadata_capture: metadata.id,
                    record,
                    metadata_status: None,
                }],
                "sy/nt/synthetic",
            )
            .await
            .unwrap();
        store
            .commit_inventory(&inventory.id, &raw.id)
            .await
            .unwrap();
        let rows = vec![(
            "1".to_owned(),
            json!({"id":"1","name":"synthetic","description":"exact selected value"}),
        )];
        store
            .put_enrichment(&raw.id, "crates", &rows)
            .await
            .unwrap();
        store.commit_enrichment(&raw.id).await.unwrap();
        let old_snapshot = store
            .commit_snapshot(store.prepare_snapshot(&inventory.id, now).await.unwrap())
            .await
            .unwrap();
        let old_id = old_snapshot.id.clone();
        assert!(old_snapshot.enrichment_derivation.is_none());
        let selection = crate::crates_io::enrichment::selection(&raw.id).unwrap();
        store
            .put_selected_enrichment(&selection, "crates", &rows)
            .await
            .unwrap();
        assert!(
            store
                .prepare_snapshot(&inventory.id, now)
                .await
                .unwrap()
                .enrichment_derivation
                .is_none()
        );
        let summary = json!({"artifact":raw.id,"processor":crate::crates_io::dump::PROCESSOR,"tables":{"crates":{"rows":1},"versions":{"rows":0}},"sql_executed":false});
        let mut missing = summary.clone();
        missing["tables"]["versions"]["rows"] = json!(1);
        assert_eq!(
            store
                .commit_selected_enrichment(&selection, &missing)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert!(
            store
                .prepare_snapshot(&inventory.id, now)
                .await
                .unwrap()
                .enrichment_derivation
                .is_none()
        );
        store
            .commit_selected_enrichment(&selection, &summary)
            .await
            .unwrap();
        store
            .put_selected_enrichment(&selection, "crates", &rows)
            .await
            .unwrap();
        store
            .commit_selected_enrichment(&selection, &summary)
            .await
            .unwrap();
        let changed = vec![(
            "1".to_owned(),
            json!({"id":"1","name":"synthetic","description":"changed"}),
        )];
        assert_eq!(
            store
                .put_selected_enrichment(&selection, "crates", &changed)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        let appended = vec![("2".to_owned(), json!({"id":"2","name":"other"}))];
        assert_eq!(
            store
                .put_selected_enrichment(&selection, "crates", &appended)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        let new_snapshot = store
            .commit_snapshot(store.prepare_snapshot(&inventory.id, now).await.unwrap())
            .await
            .unwrap();
        assert_ne!(new_snapshot.id, old_id);
        assert_eq!(new_snapshot.enrichment_derivation, selection.derivation);
        assert_eq!(new_snapshot.enrichment, old_snapshot.enrichment);
        assert_eq!(
            store
                .selected_enrichment(
                    new_snapshot.enrichment_selection().as_ref(),
                    "synthetic",
                    "1.0.0"
                )
                .await
                .unwrap(),
            store
                .selected_enrichment(
                    old_snapshot.enrichment_selection().as_ref(),
                    "synthetic",
                    "1.0.0"
                )
                .await
                .unwrap()
        );
        assert!(
            store.status().await.unwrap()["snapshot"]
                .get("enrichment_derivation")
                .is_none()
        );
        let diagnostic = json!({"version":1,"table":"crates","row":1,"column":2,"selected":true,"reason":"field_bytes","observed":1048577,"maximum":1048576});
        store
            .record_dump_failure(&raw.id, &diagnostic)
            .await
            .unwrap();
        verify(&store, &CancellationToken::new()).await.unwrap();
        drop(store);
        let reopened = std::sync::Arc::new(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        let retained = reopened.snapshot(Some(&old_id)).await.unwrap().unwrap();
        assert_eq!(retained.id, old_id);
        assert!(retained.enrichment_derivation.is_none());
        assert_eq!(
            reopened
                .snapshot(Some(&new_snapshot.id))
                .await
                .unwrap()
                .unwrap()
                .enrichment_derivation,
            selection.derivation
        );
        verify(&reopened, &CancellationToken::new()).await.unwrap();

        // A selected decoded field can expand beyond the read cap while remaining a valid staged row.
        let selected = "\x01".repeat(800_000);
        let ignored = "x".repeat(1_108_848);
        let csv = format!("id,name,description,ignored\n1,synthetic,{selected},{ignored}\n");
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(gzip);
        for (path, bytes) in [
            ("data/crates.csv", csv.as_bytes()),
            (
                "data/versions.csv",
                b"id,crate_id,num\n2,1,1.0.0\n".as_slice(),
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, path, std::io::Cursor::new(bytes))
                .unwrap();
        }
        let compressed = archive.into_inner().unwrap().finish().unwrap();
        let body_hash = hash(&compressed);
        reopened.write_blob(&body_hash, &compressed).await.unwrap();
        let mut capture = raw.clone();
        capture.key = "cargo:database-dump".into();
        capture.media_type = "application/gzip".into();
        capture.body_hash = body_hash.clone();
        capture.id = hash(
            format!(
                "{}\0{}\0{}\0{}",
                capture.key, capture.source_url, capture.media_type, capture.body_hash
            )
            .as_bytes(),
        );
        reopened
            .save_artifact(
                &Artifact {
                    capture: capture.clone(),
                    bytes: compressed.len() as u64,
                    provenance: json!({"transport":"https"}),
                },
                true,
            )
            .await
            .unwrap();
        let path = reopened
            .root
            .join(crate::integrity::relative_path(&body_hash).unwrap());
        crate::crates_io::dump::import_dump(
            path,
            capture.id.clone(),
            reopened.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let rich_selection = crate::crates_io::enrichment::selection(&capture.id).unwrap();
        let row: Json<Value> = sqlx_core::query_scalar::query_scalar("SELECT data FROM devres_crate_enrichment_v2 WHERE derivation=$1 AND kind='crates' AND external_id='1'").bind(&rich_selection.derivation).fetch_one(&reopened.pool).await.unwrap();
        assert_eq!(row.0["description"], selected);
        assert!(row.0.get("ignored").is_none());
        let error = reopened
            .selected_enrichment(Some(&rich_selection), "synthetic", "1.0.0")
            .await
            .unwrap_err();
        assert_eq!(
            crate::crates_io::enrichment::read_gap(&error),
            Some("metadata_enrichment_exceeds_2MiB")
        );
        let snapshot = reopened.prepare_snapshot(&inventory.id, now).await.unwrap();
        let retrieval = std::sync::Arc::new(devres_application::Retrieval::new(
            reopened.clone(),
            std::sync::Arc::new(crate::crates_io::index::tests::NoNetwork),
        ));
        let index = crate::crates_io::index::build(
            reopened.clone(),
            retrieval,
            root.path().to_owned(),
            snapshot.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(index["skipped_documents"], 1);
        assert_eq!(index["complete_search_coverage"], false);
        assert_eq!(
            index["gap_samples"][0]["reason"],
            "metadata_enrichment_exceeds_2MiB"
        );
        let mut snapshot = snapshot;
        snapshot.index_manifest = index;
        reopened.commit_snapshot(snapshot).await.unwrap();
        assert_eq!(
            reopened.snapshot(Some(&old_id)).await.unwrap().unwrap().id,
            old_id
        );
        // SQL rejects ordinary published-row mutation; simulate missing storage only with fixture-superuser trigger bypass.
        assert!(
            sqlx_core::query::query("DELETE FROM devres_crate_enrichment_v2 WHERE derivation=$1")
                .bind(&selection.derivation)
                .execute(&reopened.pool)
                .await
                .is_err()
        );
        sqlx_core::query::query("ALTER TABLE devres_crate_enrichment_v2 DISABLE TRIGGER USER")
            .execute(&reopened.pool)
            .await
            .unwrap();
        sqlx_core::query::query("DELETE FROM devres_crate_enrichment_v2 WHERE derivation=$1")
            .bind(&selection.derivation)
            .execute(&reopened.pool)
            .await
            .unwrap();
        assert!(verify(&reopened, &CancellationToken::new()).await.is_err());
        sqlx_core::query::query(
            "ALTER TABLE devres_crate_enrichment_heads_v2 DISABLE TRIGGER USER",
        )
        .execute(&reopened.pool)
        .await
        .unwrap();
        let bad = sqlx_core::query::query("UPDATE devres_crate_enrichment_heads_v2 SET summary=jsonb_set(summary,'{sql_executed}','true') WHERE derivation=$1").bind(selection.derivation).execute(&reopened.pool).await.unwrap();
        assert_eq!(bad.rows_affected(), 1);
        assert!(verify(&reopened, &CancellationToken::new()).await.is_err());
        drop(reopened);
        sqlx_core::query::query("DROP DATABASE devres_enrichment_v2_fixture WITH(FORCE)")
            .execute(&admin)
            .await
            .unwrap();
    }
}
