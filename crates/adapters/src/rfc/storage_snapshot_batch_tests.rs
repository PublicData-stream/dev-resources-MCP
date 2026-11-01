//! Real PostgreSQL parity checks for owner-fenced RFC snapshot capture batches.
use super::*;
use devres_application::Store;
use devres_domain::{FetchRequest, FetchResponse, Validators};
use sqlx::PgPool;

async fn published(
    store: &PgBlobStore,
    key: String,
    url: String,
    body: Vec<u8>,
    now: i64,
) -> Capture {
    store
        .publish(
            &FetchRequest {
                key,
                url,
                ttl_secs: 3600,
                max_bytes: 1024,
                media_type: "text/plain".into(),
            },
            FetchResponse {
                status: 200,
                body,
                validators: Validators::default(),
            },
            now,
        )
        .await
        .unwrap()
        .capture
}

fn manifest(catalogue: &Capture, documents: &[Document], seed: &str) -> Snapshot {
    Snapshot {
        id: crate::integrity::hash(seed.as_bytes()),
        catalogue_capture: catalogue.id.clone(),
        errata_capture: None,
        documents: documents.to_vec(),
        search_documents: Vec::new(),
        coverage: json!({"fixture":"RFC snapshot capture batch"}),
        created_at: 10,
        complete: true,
        index_path: None,
        processor_version: 1,
    }
}

async fn head_state(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT COALESCE(jsonb_agg(to_jsonb(head) ORDER BY source_key),'[]'::jsonb) FROM devres_heads AS head")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn assert_unpublished(
    store: &PgBlobStore,
    pool: &PgPool,
    candidate: &Snapshot,
    previous: &Snapshot,
    expected_count: i64,
    heads: &Value,
    expected: Error,
) {
    let error = store.save_snapshot(candidate).await.unwrap_err();
    assert_eq!(error.code, expected.code);
    assert_eq!(error.message, expected.message);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM devres_rfc_snapshots")
            .fetch_one(pool)
            .await
            .unwrap(),
        expected_count,
        "failed validation must not publish even a partial snapshot"
    );
    assert!(store.snapshot(Some(&candidate.id)).await.unwrap().is_none());
    assert_eq!(
        store.snapshot(None).await.unwrap().unwrap().id,
        previous.id,
        "failed validation must keep the previous selected snapshot"
    );
    assert_eq!(&head_state(pool).await, heads, "capture heads stay exact");
}

async fn scalar_result(connection: &mut sqlx::PgConnection, captures: &[&Capture]) -> Result<()> {
    for capture in captures {
        check_capture(connection, capture).await?;
    }
    Ok(())
}

async fn assert_capture_check_parity(store: &PgBlobStore, captures: &[&Capture], succeeds: bool) {
    let mut owner = store.owner.lock().await;
    owner.ping().await.unwrap();
    let scalar = scalar_result(&mut owner, captures).await;
    let batched = check_captures(&mut owner, captures).await;
    assert_eq!(scalar.is_ok(), succeeds);
    assert_eq!(batched.is_ok(), succeeds);
    if let (Err(scalar), Err(batched)) = (scalar, batched) {
        assert_eq!(scalar.code, batched.code);
        assert_eq!(scalar.message, batched.message);
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn snapshot_capture_batches_preserve_scalar_identity_nulls_boundaries_and_publication() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
    let admin = PgPool::connect(&base).await.unwrap();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let database = format!("devres_rfc_snapshot_batches_{suffix}");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
        .execute(&admin)
        .await
        .unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&format!("/{database}"));
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = PgBlobStore::connect(url.as_str(), root.path())
        .await
        .unwrap();
    let pool = PgPool::connect(url.as_str()).await.unwrap();
    let catalogue = published(
        &store,
        "rfc:index".into(),
        "https://www.rfc-editor.org/rfc-index.xml".into(),
        b"<rfc-index/>".to_vec(),
        1,
    )
    .await;
    store
        .save_dataset(
            "catalogue",
            &Dataset {
                capture: catalogue.clone(),
                records: Vec::new(),
            },
        )
        .await
        .unwrap();
    let mut documents = Vec::new();
    for number in 1..=201 {
        let capture = published(
            &store,
            format!("rfc:text:{number}"),
            format!("https://www.rfc-editor.org/rfc/rfc{number}.txt"),
            format!("Retained public RFC capture fixture {number}").into_bytes(),
            1000 + i64::from(number),
        )
        .await;
        documents.push(Document {
            number,
            format: "txt".into(),
            capture,
            assurance: "https".into(),
        });
    }

    let mut previous = manifest(&catalogue, &[], "initial empty snapshot");
    store.save_snapshot(&previous).await.unwrap();
    for boundary in [99, 100, 101, 200, 201] {
        let candidate = manifest(
            &catalogue,
            &documents[..boundary],
            &format!("size-{boundary}"),
        );
        store.save_snapshot(&candidate).await.unwrap();
        assert_eq!(
            store.snapshot(None).await.unwrap().unwrap().id,
            candidate.id
        );
        previous = candidate;
    }
    // Replaying an identical snapshot and repeated capture inputs retain the
    // previous scalar check's occurrence semantics.
    store.save_snapshot(&previous).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM devres_rfc_snapshots")
        .fetch_one(&pool)
        .await
        .unwrap();
    let heads = head_state(&pool).await;
    let first = &documents[0].capture;
    let mut revalidated = first.clone();
    revalidated.validated_at += 500;
    assert_capture_check_parity(&store, &[first, first, &revalidated], true).await;
    for field in 0..6 {
        let mut changed = first.clone();
        match field {
            0 => changed.id = crate::integrity::hash(b"missing RFC capture row"),
            1 => changed.key.push_str(":changed"),
            2 => changed.source_url.push_str("?changed"),
            3 => changed.body_hash = crate::integrity::hash(b"different source body"),
            4 => changed.media_type = "application/xml".into(),
            5 => changed.retrieved_at += 1,
            _ => unreachable!(),
        }
        assert_capture_check_parity(&store, &[first, &changed, first], false).await;
    }
    let mismatch = || Error::integrity("RFC projection references a different or missing capture");
    for position in [99, 100, 199, 200] {
        let mut candidate = manifest(&catalogue, &documents, &format!("missing-{position}"));
        candidate.documents[position].capture.id =
            crate::integrity::hash(format!("missing capture {position}").as_bytes());
        assert_unpublished(
            &store,
            &pool,
            &candidate,
            &previous,
            count,
            &heads,
            mismatch(),
        )
        .await;

        let mut duplicate = manifest(&catalogue, &documents, &format!("duplicate-{position}"));
        duplicate.documents[position] = duplicate.documents[position - 1].clone();
        assert_unpublished(
            &store,
            &pool,
            &duplicate,
            &previous,
            count,
            &heads,
            Error::invalid("Duplicate RFC snapshot representation"),
        )
        .await;
    }

    for later_local in ["job", "capture", "duplicate"] {
        let mut candidate = manifest(&catalogue, &documents, later_local);
        candidate.documents[10].capture.id = crate::integrity::hash(b"earlier missing capture");
        match later_local {
            "job" => candidate.documents[20].format = "unsupported".into(),
            "capture" => candidate.documents[20].capture.body_hash = "invalid".into(),
            "duplicate" => candidate.documents[20] = candidate.documents[19].clone(),
            _ => unreachable!(),
        }
        assert_unpublished(
            &store,
            &pool,
            &candidate,
            &previous,
            count,
            &heads,
            mismatch(),
        )
        .await;
    }
    let mut early_local = manifest(&catalogue, &documents, "earlier local error");
    early_local.documents[5].format = "unsupported".into();
    early_local.documents[10].capture.id = crate::integrity::hash(b"later missing capture");
    assert_unpublished(
        &store,
        &pool,
        &early_local,
        &previous,
        count,
        &heads,
        Error::invalid("Invalid RFC job identity"),
    )
    .await;

    let mut bad_search = manifest(&catalogue, &documents, "search metadata differs");
    bad_search.search_documents = vec![documents[0].clone()];
    bad_search.search_documents[0].capture.validated_at += 1;
    assert_unpublished(
        &store,
        &pool,
        &bad_search,
        &previous,
        count,
        &heads,
        Error::invalid("Invalid RFC searchable representation"),
    )
    .await;
    let mut absent_dataset = manifest(&catalogue, &documents, "dataset absent");
    absent_dataset.catalogue_capture = crate::integrity::hash(b"missing catalogue");
    assert_unpublished(
        &store,
        &pool,
        &absent_dataset,
        &previous,
        count,
        &heads,
        Error::integrity("RFC snapshot references an absent dataset"),
    )
    .await;

    // Only this owned disposable fixture relaxes NOT NULL to simulate damaged
    // retained rows. SQL unknown must fail exactly as the scalar EXISTS check.
    for column in [
        "source_key",
        "source_url",
        "body_hash",
        "media_type",
        "retrieved_at",
    ] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE devres_captures ALTER COLUMN {column} DROP NOT NULL"
        )))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE devres_captures SET {column}=NULL WHERE id=$1"
        )))
        .bind(&documents[100].capture.id)
        .execute(&pool)
        .await
        .unwrap();
        assert_capture_check_parity(&store, &[&documents[100].capture], false).await;
        let candidate = manifest(&catalogue, &documents, &format!("null-{column}"));
        assert_unpublished(
            &store,
            &pool,
            &candidate,
            &previous,
            count,
            &heads,
            mismatch(),
        )
        .await;
        let capture = &documents[100].capture;
        sqlx::query("UPDATE devres_captures SET source_key=$2,source_url=$3,body_hash=$4,media_type=$5,retrieved_at=$6 WHERE id=$1")
            .bind(&capture.id).bind(&capture.key).bind(&capture.source_url)
            .bind(&capture.body_hash).bind(&capture.media_type).bind(capture.retrieved_at)
            .execute(&pool).await.unwrap();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE devres_captures ALTER COLUMN {column} SET NOT NULL"
        )))
        .execute(&pool)
        .await
        .unwrap();
    }
    assert_capture_check_parity(&store, &[first, &documents[100].capture], true).await;
    assert_eq!(head_state(&pool).await, heads);
    assert_eq!(store.snapshot(None).await.unwrap().unwrap().id, previous.id);
    drop(store);
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE {database} WITH (FORCE)"
    )))
    .execute(&admin)
    .await
    .unwrap();
    admin.close().await;
}
