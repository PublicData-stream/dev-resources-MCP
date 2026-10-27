//! Isolated public-fixture acceptance. Every artifact and database is task owned under /tmp.
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use devres_adapters::{
    bulk::{BulkBroker, BulkConfig},
    npm::NpmConfig,
    npm::NpmCorpus,
    npm::research::NpmResearch,
};
use devres_application::npm::{NpmStore, Row};
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha512};
use std::{collections::BTreeMap, io::Write, sync::Arc};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

type MemoryState = (
    i64,
    BTreeMap<(String, String), Row>,
    BTreeMap<String, Value>,
);
#[derive(Default)]
struct Memory {
    data: Mutex<MemoryState>,
}

#[async_trait]
impl NpmStore for Memory {
    async fn npm_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
        Ok(self
            .data
            .lock()
            .await
            .1
            .get(&(kind.into(), key.into()))
            .cloned())
    }
    async fn npm_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
        let mut state = self.data.lock().await;
        let identity = (kind.into(), key.into());
        if let Some(row) = state.1.get(&identity) {
            return if row.data == *data {
                Ok(row.sequence)
            } else {
                Err(Error::integrity("fixture identity collision"))
            };
        }
        state.0 += 1;
        let sequence = state.0;
        state.1.insert(
            identity,
            Row {
                sequence,
                key: key.into(),
                data: data.clone(),
            },
        );
        Ok(sequence)
    }
    async fn npm_cutoff(&self) -> Result<i64> {
        Ok(self.data.lock().await.0)
    }
    async fn npm_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
        filter: Option<&Value>,
    ) -> Result<Vec<Row>> {
        let state = self.data.lock().await;
        let mut rows: Vec<_> = state
            .1
            .iter()
            .filter(|((k, _), row)| {
                k == kind
                    && row.sequence > after
                    && cutoff.is_none_or(|v| row.sequence <= v)
                    && filter.is_none_or(|filter| {
                        filter.as_object().is_some_and(|filter| {
                            filter.iter().all(|(k, v)| row.data.get(k) == Some(v))
                        })
                    })
            })
            .map(|(_, r)| r.clone())
            .collect();
        rows.sort_by_key(|r| r.sequence);
        rows.truncate(limit);
        Ok(rows)
    }
    async fn npm_state(&self, key: &str) -> Result<Option<Value>> {
        Ok(self.data.lock().await.2.get(key).cloned())
    }
    async fn npm_set_state(&self, key: &str, data: &Value) -> Result<()> {
        self.data.lock().await.2.insert(key.into(), data.clone());
        Ok(())
    }
    async fn npm_commit_index(&self, index: &Value, ids: &[String]) -> Result<()> {
        let mut state = self.data.lock().await;
        for id in ids {
            if let Some(old) = state.1.get(&("indexed".into(), id.clone()))
                && old.data != json!({"id":id})
            {
                return Err(Error::integrity("Fixture marker collision."));
            }
        }
        let (sequence, rows, heads) = &mut *state;
        for id in ids {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                rows.entry(("indexed".into(), id.clone()))
            {
                *sequence += 1;
                entry.insert(Row {
                    sequence: *sequence,
                    key: id.clone(),
                    data: json!({"id":id}),
                });
            }
        }
        heads.insert("index".into(), index.clone());
        Ok(())
    }
    async fn npm_commit_rebuilt_index(&self, index: &Value, build: &str) -> Result<()> {
        let rows = self
            .npm_rows(
                "rebuild-index-members",
                0,
                1000,
                None,
                Some(&json!({"build":build})),
            )
            .await?;
        let ids = rows
            .iter()
            .map(|r| r.data["record"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        self.npm_commit_index(index, &ids).await
    }
    async fn npm_publish(&self, lane: &str, data: &Value) -> Result<()> {
        self.npm_put("snapshots", data["id"].as_str().unwrap(), data)
            .await?;
        self.npm_set_state(&format!("default-{lane}"), data).await
    }
    async fn npm_statistics(&self) -> Result<Value> {
        Ok(json!({"rows":self.data.lock().await.0}))
    }
}

fn package(version: &str, text: &str) -> (Value, Vec<u8>) {
    let manifest = json!({"name":"npm-fixture","version":version,"description":"Synthetic fixture only","license":"MIT","types":"index.d.ts",
        "exports":{".":{"types":"./index.d.ts","default":"./index.js"}},"dependencies":{"aliased":"npm:@demo/real@^1.0.0"}});
    let mut archive = tar::Builder::new(Vec::new());
    for (path, bytes) in [
        (
            "package/package.json",
            serde_json::to_vec(&manifest).unwrap(),
        ),
        ("package/README.md", text.as_bytes().to_vec()),
        (
            "package/index.d.ts",
            b"export declare function fixture(value: string): string;\n".to_vec(),
        ),
        (
            "package/LICENSE",
            b"Synthetic fixture; first-party MIT test content.\n".to_vec(),
        ),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        archive
            .append_data(&mut header, path, bytes.as_slice())
            .unwrap();
    }
    let archive = archive.into_inner().unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&archive).unwrap();
    let bytes = gzip.finish().unwrap();
    let mut metadata = manifest;
    metadata["dist"] = json!({"tarball":format!("https://registry.npmjs.org/npm-fixture/-/npm-fixture-{version}.tgz"),"integrity":format!("sha512-{}",STANDARD.encode(Sha512::digest(&bytes)))});
    (metadata, bytes)
}
fn packument(releases: &[(Value, Vec<u8>)]) -> (Value, BTreeMap<String, Vec<u8>>) {
    let mut versions = serde_json::Map::new();
    let mut archives = BTreeMap::new();
    for (metadata, archive) in releases {
        let version = metadata["version"].as_str().unwrap().to_owned();
        versions.insert(version.clone(), metadata.clone());
        archives.insert(version, archive.clone());
    }
    (
        json!({"name":"npm-fixture","versions":versions,"dist-tags":{"latest":releases.last().unwrap().0["version"]}}),
        archives,
    )
}
fn config() -> NpmConfig {
    NpmConfig {
        enabled: false,
        packages: vec!["npm-fixture".into()],
        ..NpmConfig::default()
    }
}
fn broker() -> Arc<BulkBroker> {
    Arc::new(
        BulkBroker::new(BulkConfig::default())
            .unwrap()
            .with_attempt_budget(1)
            .unwrap(),
    )
}
fn advisory() -> Value {
    json!({"schema_version":"1.7.3","id":"GHSA-2345-6789-cfgh","modified":"2026-10-27T00:00:00Z","published":"2026-10-01T00:00:00Z",
    "summary":"Synthetic npm fixture advisory","affected":[{"package":{"ecosystem":"npm","name":"npm-fixture"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]}]})
}

#[tokio::test]
async fn frozen_membership_resources_cursor_audits_and_offline_rebuild() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(Memory::default());
    let broker = broker();
    let corpus =
        Arc::new(NpmCorpus::new(store.clone(), broker.clone(), root.path(), config()).unwrap());
    let time = devres_domain::unix_now() - 2;
    let first = package("1.0.0", "# Synthetic fixture\nfirst release needle\n");
    let (metadata, archives) = packument(std::slice::from_ref(&first));
    let old = corpus
        .import_fixture_package(metadata, archives, time, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        corpus.selection("research", None).await.unwrap()["historical"],
        false
    );
    assert_eq!(
        corpus
            .selection("research", old["id"].as_str())
            .await
            .unwrap()["historical"],
        false
    );
    corpus
        .import_fixture_advisories(vec![advisory()], time)
        .await
        .unwrap();
    let research = NpmResearch::new(corpus.clone());
    let advisory_source = research
        .call("npm.advisory_get", json!({"id":"GHSA-2345-6789-cfgh"}))
        .await
        .unwrap();
    assert_eq!(
        advisory_source["page"]["text"],
        serde_json::to_string(&advisory()).unwrap(),
        "source is retained bytes, not pretty-rendered normalized JSON"
    );
    let source_uri = advisory_source["resource_uri"].as_str().unwrap();
    assert_eq!(
        research.read_resource(source_uri).await.unwrap()["contents"][0]["text"],
        advisory_source["page"]["text"]
    );
    let current_lookup = research
        .call(
            "npm.advisory_lookup",
            json!({"name":"npm-fixture","version":"1.0.0"}),
        )
        .await
        .unwrap();
    let pinned_lookup=research.call("npm.advisory_lookup",json!({"name":"npm-fixture","version":"1.0.0","snapshot":current_lookup["snapshot"]["id"]})).await.unwrap();
    assert_eq!(current_lookup["complete"], pinned_lookup["complete"]);
    let document = research
        .call(
            "npm.document_get",
            json!({"name":"npm-fixture","version":"1.0.0","path":"README.md"}),
        )
        .await
        .unwrap();
    let uri = document["resource_uri"].as_str().unwrap();
    assert_eq!(
        research.read_resource(uri).await.unwrap()["contents"][0]["text"],
        document["page"]["text"]
    );
    assert!(research.call("npm.document_get",json!({"name":"npm-fixture","version":"1.0.0","path":"README.md","offset":1,"limit":0})).await.is_err());
    let second = package("1.0.1", "# Synthetic fixture\nsecond release needle\n");
    let (metadata, archives) = packument(&[first, second]);
    let new = corpus
        .import_fixture_package(metadata, archives, time + 1, CancellationToken::new())
        .await
        .unwrap();
    assert_ne!(old["id"], new["id"]);
    let old_versions = research
        .call(
            "npm.versions",
            json!({"name":"npm-fixture","snapshot":old["id"]}),
        )
        .await
        .unwrap();
    assert_eq!(old_versions["total"], 1);
    let first_page = research
        .call("npm.versions", json!({"name":"npm-fixture","limit":1}))
        .await
        .unwrap();
    assert_eq!(first_page["items"][0]["version"], "1.0.1");
    assert!(
        research
            .call(
                "npm.catalog_search",
                json!({"name":"npm-fixture","limit":2,"cursor":first_page["next_cursor"]})
            )
            .await
            .is_err(),
        "same arguments cannot move a cursor to another tool"
    );
    let continuation = research
        .call(
            "npm.versions",
            json!({"name":"npm-fixture","cursor":first_page["next_cursor"],"limit":2}),
        )
        .await
        .unwrap();
    assert_eq!(continuation["items"][0]["version"], "1.0.0");
    assert!(
        research
            .call(
                "npm.catalog_search",
                json!({"query":"different","cursor":first_page["next_cursor"]})
            )
            .await
            .is_err()
    );
    let comparison=research.call("npm.compare",json!({"name":"npm-fixture","from_version":"1.0.0","to_version":"1.0.1","path":"README.md","limit":12})).await.unwrap();
    assert_eq!(comparison["text_diff"]["identical"], false);
    assert!(comparison["text_diff"]["page"]["next_offset"].is_number());
    let evidence = corpus
        .advisory_snapshot_for_names(None, &["npm-fixture".into()])
        .await
        .unwrap();
    assert_eq!(evidence["records"].as_array().unwrap().len(), 1);
    let none = corpus
        .advisory_snapshot_for_names(None, &["unrelated".into()])
        .await
        .unwrap();
    assert_eq!(none["records"], json!([]));
    let lookup = research
        .call(
            "npm.advisory_lookup",
            json!({"name":"npm-fixture","version":"1.0.0"}),
        )
        .await
        .unwrap();
    assert_eq!(lookup["total"], 1);
    let before_validation =
        corpus.selection("research", None).await.unwrap()["validated_at"].clone();
    corpus
        .rebuild_index(CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        corpus.selection("research", None).await.unwrap()["validated_at"],
        before_validation
    );
    let old_versions = research
        .call(
            "npm.versions",
            json!({"name":"npm-fixture","snapshot":old["id"]}),
        )
        .await
        .unwrap();
    assert_eq!(old_versions["total"], 1);
    let search = research
        .call(
            "npm.content_search",
            json!({"query":"needle","snapshot":old["id"]}),
        )
        .await
        .unwrap();
    assert_eq!(search["results"].as_array().unwrap().len(), 1);
    assert_eq!(
        broker.attempt_count(),
        0,
        "fixture import, research and rebuild make no provider requests"
    );
}

#[tokio::test]
async fn explicit_expired_history_is_readable_without_complete_assessment() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(Memory::default());
    let corpus = Arc::new(NpmCorpus::new(store.clone(), broker(), root.path(), config()).unwrap());
    let now = devres_domain::unix_now();
    let current = corpus
        .import_fixture_advisories(vec![advisory()], now)
        .await
        .unwrap();
    let mut old = store
        .npm_get("snapshots", current["id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap()
        .data;
    old["id"] = json!("b".repeat(64));
    old["validated_at"] = json!(now - 8 * 86400);
    store
        .npm_put("snapshots", old["id"].as_str().unwrap(), &old)
        .await
        .unwrap();
    let research = NpmResearch::new(corpus.clone());
    let result = research
        .call(
            "npm.advisory_lookup",
            json!({"name":"npm-fixture","version":"1.0.0","snapshot":old["id"]}),
        )
        .await
        .unwrap();
    assert_eq!(result["total"], 1);
    assert_eq!(result["complete"], false);
    assert_eq!(result["snapshot"]["historical"], true);
    store
        .npm_set_state("default-advisories", &old)
        .await
        .unwrap();
    assert!(corpus.advisory_selection(None).await.is_err());
    let mut future = old;
    future["id"] = json!("c".repeat(64));
    future["validated_at"] = json!(now + 86400);
    store
        .npm_put("snapshots", future["id"].as_str().unwrap(), &future)
        .await
        .unwrap();
    assert!(
        corpus
            .advisory_selection(future["id"].as_str())
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn npm_schema_publication_restart_immutability_and_owner_fence() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
    let admin = sqlx::PgPool::connect(&base).await.unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let database = format!("devres_npm_fixture_{}_{nonce}", std::process::id());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
        .execute(&admin)
        .await
        .unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&format!("/{database}"));
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(
        devres_adapters::PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap(),
    );
    let inspection = sqlx::PgPool::connect(url.as_str()).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT version FROM devres_schema WHERE singleton")
            .fetch_one(&inspection)
            .await
            .unwrap(),
        9
    );
    assert!(
        devres_adapters::PgBlobStore::connect(url.as_str(), root.path())
            .await
            .is_err()
    );
    let corpus = Arc::new(NpmCorpus::new(store.clone(), broker(), root.path(), config()).unwrap());
    let (metadata, archives) =
        packument(&[package("1.0.0", "# Durable npm fixture\nretained text\n")]);
    let snapshot = corpus
        .import_fixture_package(
            metadata,
            archives,
            devres_domain::unix_now(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let old_index = store.npm_state("index").await.unwrap().unwrap();
    let documents = store.npm_rows("documents", 0, 2, None, None).await.unwrap();
    let ids: Vec<String> = documents.iter().map(|r| r.key.clone()).collect();
    assert_eq!(ids.len(), 2);
    assert!(
        ids.iter()
            .all(|id| id.len() == 64 && id.bytes().all(|v| v.is_ascii_hexdigit()))
    );
    sqlx::query("DELETE FROM devres_npm_evidence WHERE kind='indexed' AND key=ANY($1::text[])")
        .bind(&ids)
        .execute(&inspection)
        .await
        .unwrap();
    let ddl = format!(
        "CREATE FUNCTION npm_fixture_interrupt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='indexed' AND NEW.key='{}' THEN RAISE EXCEPTION 'fixture interrupt'; END IF; RETURN NEW; END $$; CREATE TRIGGER npm_fixture_interrupt BEFORE INSERT ON devres_npm_evidence FOR EACH ROW EXECUTE FUNCTION npm_fixture_interrupt();",
        ids[1]
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(ddl))
        .execute(&inspection)
        .await
        .unwrap();
    assert!(
        store
            .npm_commit_index(&json!({"uncommitted":"fixture-root"}), &ids)
            .await
            .is_err()
    );
    assert_eq!(store.npm_state("index").await.unwrap().unwrap(), old_index);
    for id in &ids {
        assert!(
            store.npm_get("indexed", id).await.unwrap().is_none(),
            "partial markers roll back with the pointer"
        );
    }
    sqlx::raw_sql("DROP TRIGGER npm_fixture_interrupt ON devres_npm_evidence; DROP FUNCTION npm_fixture_interrupt()").execute(&inspection).await.unwrap();
    store.npm_commit_index(&old_index, &ids).await.unwrap();
    for id in &ids {
        assert!(store.npm_get("indexed", id).await.unwrap().is_some());
    }
    let cutoff = store.npm_cutoff().await.unwrap();
    store
        .npm_put("fixtures", "later", &json!({"public":true}))
        .await
        .unwrap();
    assert!(
        store
            .npm_put("fixtures", "later", &json!({"changed":true}))
            .await
            .is_err()
    );
    assert!(
        store
            .npm_rows("fixtures", 0, 10, Some(cutoff), None)
            .await
            .unwrap()
            .is_empty()
    );
    let retained = store
        .npm_get("snapshots", snapshot["id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap()
        .data;
    let mut invalid = retained.clone();
    invalid["validated_at"] = json!(1);
    assert!(store.npm_publish("research", &invalid).await.is_err());
    drop(corpus);
    drop(store);
    for _ in 0..100 {
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database())").fetch_one(&inspection).await.unwrap();
        if count == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let store = Arc::new(
        devres_adapters::PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap(),
    );
    let corpus = Arc::new(NpmCorpus::new(store.clone(), broker(), root.path(), config()).unwrap());
    corpus.initialize_status().await.unwrap();
    let research = NpmResearch::new(corpus.clone());
    let document=research.call("npm.document_get",json!({"name":"npm-fixture","version":"1.0.0","path":"README.md","snapshot":snapshot["id"]})).await.unwrap();
    assert!(
        document["page"]["text"]
            .as_str()
            .unwrap()
            .contains("retained text")
    );
    drop(research);
    drop(corpus);
    drop(store);
    inspection.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE {database} WITH (FORCE)"
    )))
    .execute(&admin)
    .await
    .unwrap();
    admin.close().await;
}
