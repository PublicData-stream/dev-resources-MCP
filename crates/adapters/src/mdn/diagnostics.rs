//! Selected sealed MDN metadata and commit-order bytes, without collection or caches.
use super::*;
use crate::{
    bulk::BulkArtifact,
    mdn::git::{Observation, Repo, parse_commit_order},
};
use devres_application::mdn::{PROCESSOR_VERSION, Snapshot, View};

fn oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(value: &str) -> bool {
    integrity::valid_hash(value)
}
fn string(value: &Value) -> Result<&str> {
    value.as_str().filter(|s| digest(s)).ok_or_else(failed)
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| failed())
}
fn observation_id(value: &Observation) -> String {
    integrity::hash(format!("{}:{}", value.repo.as_str(), value.manifest.body_hash).as_bytes())
}

/// Resolve the alias before selecting a row: natural MDN keys can themselves alias.
async fn alias(reader: &mut Reader, kind: &str, selected: &str) -> Result<String> {
    let namespace = format!("mdn:{kind}");
    let bytes: Option<i64> = sqlx_core::query_scalar::query_scalar("SELECT octet_length(canonical)::bigint+COALESCE(octet_length(mapping_integrity),0)::bigint FROM devres_content_aliases WHERE namespace=$1 AND legacy=$2")
        .bind(&namespace).bind(selected).fetch_optional(&mut reader.conn).await.map_err(|_|unavailable())?;
    let Some(bytes) = bytes else {
        return Ok(selected.into());
    };
    if bytes > 8192 {
        return Err(failed());
    }
    reader.row_admit(bytes)?;
    let row = sqlx_core::query::query("SELECT canonical,mapping_integrity FROM devres_content_aliases WHERE namespace=$1 AND legacy=$2")
        .bind(&namespace).bind(selected).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
    let canonical: String = row.try_get("canonical").map_err(|_| failed())?;
    let seal: String = row.try_get("mapping_integrity").map_err(|_| failed())?;
    if !canonical.starts_with("blake3:")
        || !digest(&canonical)
        || super::super::events::event_digest(
            "devres_content_aliases",
            &super::super::events::mapping_key(&namespace, selected)?,
            &json!({"namespace":namespace,"legacy":selected,"canonical":canonical}),
        )? != seal
    {
        return Err(failed());
    }
    Ok(canonical)
}

async fn evidence(
    reader: &mut Reader,
    report: &mut CollectionDiagnosis,
    kind: &str,
    selected: &str,
) -> Result<Option<(String, Value)>> {
    let canonical = alias(reader, kind, selected).await?;
    let size: Option<i64> = sqlx_core::query_scalar::query_scalar("SELECT octet_length(data::text)::bigint FROM devres_mdn_evidence WHERE kind=$1 AND key=$2 AND sequence<=$3")
        .bind(kind).bind(&canonical).bind(report.cutoff).fetch_optional(&mut reader.conn).await.map_err(|_|unavailable())?;
    let Some(size) = size else {
        if canonical != selected {
            return Err(failed());
        }
        return Ok(None);
    };
    reader.row_admit(size)?;
    let row = sqlx_core::query::query("SELECT sequence,sequence_integrity,kind,key,data,data_integrity FROM devres_mdn_evidence WHERE kind=$1 AND key=$2 AND sequence<=$3")
        .bind(kind).bind(&canonical).bind(report.cutoff).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
    let value = payload_integrity::row("devres_mdn_evidence", &row)?;
    let sequence = row.try_get("sequence").map_err(|_| failed())?;
    report
        .evidence
        .push(summary(kind, sequence, &canonical, &value)?);
    Ok(Some((canonical, value)))
}

fn artifact_relative(repo: Repo, artifact: &BulkArtifact) -> Result<String> {
    if !digest(&artifact.body_hash) {
        return Err(failed());
    }
    let suffix = integrity::relative_path(&artifact.body_hash)?
        .to_string_lossy()
        .into_owned();
    if artifact.relative_path != suffix {
        return Err(failed());
    }
    Ok(format!("mdn/{}/artifacts/{suffix}", repo.as_str()))
}
fn validate_observation(value: &Observation, repo: Repo) -> Result<()> {
    if value.repo != repo
        || value.observed_at < 0
        || value.total_commits > 1_000_000
        || value.refs.len() > 10_000
        || value.roots.len() > 100_000
        || value.main_revision.as_deref().is_some_and(|s| !oid(s))
        || value.roots.iter().any(|s| !oid(s))
        || value.refs.iter().any(|r| {
            !oid(&r.oid)
                || r.peeled_commit.as_deref().is_some_and(|s| !oid(s))
                || !matches!(r.object_type.as_str(), "commit" | "tag" | "tree" | "blob")
        })
    {
        return Err(failed());
    }
    artifact_relative(repo, &value.manifest)?;
    artifact_relative(repo, &value.commits)?;
    Ok(())
}
async fn observed(
    reader: &mut Reader,
    report: &mut CollectionDiagnosis,
    value: Value,
    repo: Repo,
) -> Result<Observation> {
    let observation: Observation = decode(value)?;
    validate_observation(&observation, repo)?;
    let expected = observation_id(&observation);
    let (canonical, retained) = evidence(reader, report, "observations", &expected)
        .await?
        .ok_or_else(unavailable)?;
    if canonical != expected
        || retained != serde_json::to_value(&observation).map_err(|_| failed())?
    {
        return Err(failed());
    }
    Ok(observation)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    observation: Observation,
    offset: u64,
    processed: usize,
    complete: bool,
    #[serde(default)]
    processor_version: u32,
}
/// Validate every line and the completed prefix, never reinterpret bytes as commits.
fn cursor(bytes: &[u8], history: &History, budget: &Budget) -> Result<()> {
    if history.offset > bytes.len() as u64
        || history.processed > history.observation.total_commits
        || (history.offset > 0 && bytes.get(history.offset as usize - 1) != Some(&b'\n'))
        || (!bytes.is_empty() && bytes.last() != Some(&b'\n'))
    {
        return Err(failed());
    }
    let mut offset = 0u64;
    let mut count = 0usize;
    let mut prefix = 0usize;
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        budget.check()?;
        if line.len() > 64 * 1024 + 1 {
            return Err(failed());
        }
        parse_commit_order(&line[..line.len() - 1])?;
        offset += line.len() as u64;
        count += 1;
        if offset <= history.offset {
            prefix += 1;
        }
    }
    if count != history.observation.total_commits
        || prefix != history.processed
        || history.complete && history.offset != bytes.len() as u64
    {
        return Err(failed());
    }
    Ok(())
}

async fn history(
    reader: &mut Reader,
    report: &mut CollectionDiagnosis,
    repo: Repo,
) -> Result<Value> {
    let Some(value) = reader
        .state(
            DiagnosisProvider::Mdn,
            &format!("{}-history", repo.as_str()),
        )
        .await?
    else {
        return Ok(json!({"repository":repo,"state":"not_started"}));
    };
    let history: History = decode(value)?;
    observed(
        reader,
        report,
        serde_json::to_value(&history.observation).map_err(|_| failed())?,
        repo,
    )
    .await?;
    let artifact = &history.observation.commits;
    if artifact.bytes > 128 * 1024 * 1024 {
        return Err(failed());
    }
    // Whole-artifact verification stays under the shared budget; no remote cache.
    let bytes = reader
        .file(&artifact_relative(repo, artifact)?, artifact.bytes)
        .await?;
    if bytes.len() as u64 != artifact.bytes {
        return Err(failed());
    }
    integrity::verify(&artifact.body_hash, &bytes)?;
    cursor(&bytes, &history, &reader.budget)?;
    Ok(
        json!({"repository":repo,"observation":observation_id(&history.observation),"processor_version":history.processor_version,
        "offset_bytes":history.offset,"commit_order_bytes":artifact.bytes,"processed_commits":history.processed,
        "total_commits":history.observation.total_commits,"complete":history.complete,"commit_order_digest":"verified","cursor_boundary":"verified",
        "git_objects":"not_checked"}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Work {
    root: String,
    previous: Option<String>,
    offset: usize,
    changed: Vec<String>,
}
fn work(value: Value) -> Result<Value> {
    let work: Work = decode(value)?;
    if !digest(&work.root)
        || work.previous.as_deref().is_some_and(|s| !oid(s))
        || work.changed.len() > 100_000
    {
        return Err(failed());
    }
    Ok(
        json!({"inventory":work.root,"previous_revision":work.previous,"inventory_offset_entries":work.offset,"changed_entries":work.changed.len(),"inventory_members":"not_checked"}),
    )
}

fn snapshot(value: Value, canonical: &str, repo: Repo, revision: Option<&str>) -> Result<Snapshot> {
    let snapshot: Snapshot = decode(value)?;
    if snapshot.id != canonical
        || !digest(&snapshot.id)
        || snapshot.repository != repo.as_str()
        || !oid(&snapshot.revision)
        || !oid(&snapshot.tree)
        || !digest(&snapshot.inventory)
        || revision.is_some_and(|s| s != snapshot.revision)
        || snapshot.parents.len() > 1024
        || snapshot.parents.iter().any(|s| !oid(s))
        || snapshot.processor_version == 0
    {
        return Err(failed());
    }
    Ok(snapshot)
}

async fn snapshot_identity(reader: &mut Reader, snapshot: &Snapshot) -> Result<()> {
    let bytes = serde_json::to_vec(&(
        &snapshot.repository,
        &snapshot.revision,
        snapshot.processor_version,
        &snapshot.inventory,
    ))
    .map_err(|_| failed())?;
    if (snapshot.id.starts_with("blake3:") && integrity::hash(&bytes) == snapshot.id)
        || (!snapshot.id.starts_with("blake3:") && integrity::legacy_hash(&bytes) == snapshot.id)
    {
        return Ok(());
    }
    if let (Some(previous), Some(generation)) = (
        snapshot.coverage["rebuild_of"].as_str(),
        snapshot.coverage["derived_generation"].as_str(),
    ) {
        if !digest(previous) || generation.len() > 128 || generation.chars().any(char::is_control) {
            return Err(failed());
        }
        let bytes =
            serde_json::to_vec(&(previous, generation, &snapshot.index)).map_err(|_| failed())?;
        if integrity::hash(&bytes) == snapshot.id {
            return Ok(());
        }
    }
    // The storage migration derives a new identity from one sealed legacy alias
    // and the canonical snapshot with its id cleared, rather than its ordinary tuple.
    let sizes: Vec<(Option<String>,i64)>=sqlx_core::query_as::query_as("SELECT CASE WHEN octet_length(legacy)<=128 THEN legacy ELSE NULL END,octet_length(legacy)::bigint+COALESCE(octet_length(mapping_integrity),0)::bigint FROM devres_content_aliases WHERE namespace='mdn:snapshots' AND canonical=$1 ORDER BY legacy LIMIT 2")
        .bind(&snapshot.id).fetch_all(&mut reader.conn).await.map_err(|_|unavailable())?;
    for (legacy, size) in sizes {
        let legacy = legacy.ok_or_else(failed)?;
        if size > 8192 || !digest(&legacy) || legacy.starts_with("blake3:") {
            return Err(failed());
        }
        reader.row_admit(size)?;
        if alias(reader, "snapshots", &legacy).await? != snapshot.id {
            return Err(failed());
        }
        let mut candidate = snapshot.clone();
        candidate.id.clear();
        let bytes = serde_json::to_vec(&(
            "devres:storage-migration:mdn-snapshot:v1",
            &legacy,
            &candidate,
        ))
        .map_err(|_| failed())?;
        if integrity::hash(&bytes) == snapshot.id {
            return Ok(());
        }
    }
    Err(failed())
}

/// Verify one exact manifest descriptor and digest. Engines/shard members are omitted.
async fn index(reader: &mut Reader, reference: &Value) -> Result<Value> {
    if reference.is_null() {
        return Ok(json!({"state":"missing"}));
    }
    let id = match (reference.get("digest"), reference.get("sha256")) {
        (Some(id), None) if string(id)?.starts_with("blake3:") => string(id)?,
        (None, Some(id)) if !string(id)?.starts_with("blake3:") => string(id)?,
        _ => return Err(failed()),
    };
    let path = format!(
        "mdn-indexes/manifests/{}.json",
        integrity::relative_path(id)?.to_string_lossy()
    );
    if reference["path"].as_str() != Some(path.as_str()) {
        return Err(failed());
    }
    let bytes = reader.file(&path, 2 * 1024 * 1024).await?;
    integrity::verify(id, &bytes)?;
    let manifest: Value = serde_json::from_slice(&bytes).map_err(|_| failed())?;
    if !matches!(manifest["version"].as_u64(), Some(2 | 3)) || !manifest.is_object() {
        return Err(failed());
    }
    Ok(
        json!({"state":"retained","manifest":id,"manifest_digest":"verified","parent_manifests":"not_checked","shard_members":"not_checked","engine_readability":"not_checked"}),
    )
}

async fn main_state(
    reader: &mut Reader,
    report: &mut CollectionDiagnosis,
    repo: Repo,
) -> Result<Value> {
    let Some(value) = reader
        .state(
            DiagnosisProvider::Mdn,
            &format!("{}-observation", repo.as_str()),
        )
        .await?
    else {
        return Ok(json!({"repository":repo,"state":"no_observation"}));
    };
    let observation = observed(reader, report, value, repo).await?;
    let mut result = json!({"repository":repo,"observation":observation_id(&observation),"observed_at":observation.observed_at,"latest_total_commits":observation.total_commits,"main_revision":observation.main_revision});
    let Some(revision) = observation.main_revision.as_deref() else {
        result["state"] = json!("no_main_revision");
        return Ok(result);
    };
    let key = format!("{}:{revision}:{PROCESSOR_VERSION}", repo.as_str());
    result["work"] = match reader
        .state(DiagnosisProvider::Mdn, &format!("work:{key}"))
        .await?
        .filter(|v| !v.is_null())
    {
        Some(value) => work(value)?,
        None => json!({"state":"absent"}),
    };
    let prepared = reader
        .state(DiagnosisProvider::Mdn, &format!("prepared:{key}"))
        .await?
        .filter(|v| !v.is_null());
    result["prepared"] = if let Some(value) = prepared {
        let id = string(&value["id"])?.to_owned();
        let prepared = snapshot(value, &id, repo, Some(revision))?;
        snapshot_identity(reader, &prepared).await?;
        json!({"snapshot":prepared.id,"index_present":!prepared.index.is_null(),"accounted":prepared.coverage["accounted"].as_bool()})
    } else {
        json!({"state":"absent"})
    };
    let binding = evidence(reader, report, "snapshot-keys", &key).await?;
    let selected = reader
        .state(DiagnosisProvider::Mdn, &format!("rebuild-alias:{key}"))
        .await?;
    let selected = selected
        .as_ref()
        .or_else(|| binding.as_ref().map(|(_, value)| value));
    if let Some(selected) = selected {
        let id = string(selected)?;
        let (canonical, value) = evidence(reader, report, "snapshots", id)
            .await?
            .ok_or_else(unavailable)?;
        let selected = snapshot(value, &canonical, repo, Some(revision))?;
        snapshot_identity(reader, &selected).await?;
        result["published"] = json!({"snapshot":selected.id,"processor_version":selected.processor_version,"accounted":selected.coverage["accounted"].as_bool(),"index":index(reader,&selected.index).await?});
    } else {
        result["published"] = json!({"state":"absent"});
    }
    Ok(result)
}

async fn default_view(reader: &mut Reader, report: &mut CollectionDiagnosis) -> Result<Value> {
    let Some(value) = reader.state(DiagnosisProvider::Mdn, "default-view").await? else {
        return Ok(json!({"state":"unpublished"}));
    };
    let (canonical, value) = evidence(reader, report, "views", string(&value)?)
        .await?
        .ok_or_else(unavailable)?;
    let view: View = decode(value)?;
    let identity = serde_json::to_vec(&(
        &view.content,
        &view.compatibility,
        &view.content_observation,
        &view.compatibility_observation,
        view.validated_at,
    ))
    .map_err(|_| failed())?;
    if view.id != canonical || integrity::hash(&identity) != view.id || view.validated_at <= 0 {
        return Err(failed());
    }
    for (repo, snapshot_id, observation_id) in [
        (Repo::Content, &view.content, &view.content_observation),
        (
            Repo::Compat,
            &view.compatibility,
            &view.compatibility_observation,
        ),
    ] {
        if !digest(snapshot_id) || !digest(observation_id) {
            return Err(failed());
        }
        let (canonical, value) = evidence(reader, report, "snapshots", snapshot_id)
            .await?
            .ok_or_else(unavailable)?;
        let selected = snapshot(value, &canonical, repo, None)?;
        snapshot_identity(reader, &selected).await?;
        let (canonical_observation, value) =
            evidence(reader, report, "observations", observation_id)
                .await?
                .ok_or_else(unavailable)?;
        let observation: Observation = decode(value)?;
        validate_observation(&observation, repo)?;
        if self::observation_id(&observation) != canonical_observation {
            return Err(failed());
        }
        if observation.main_revision.as_deref() != Some(&selected.revision)
            || observation.observed_at < view.validated_at
            || selected.coverage["accounted"] != true
            || selected.coverage["synthetic"] == true
            || selected.index.is_null()
        {
            return Err(failed());
        }
        index(reader, &selected.index).await?;
    }
    Ok(
        json!({"state":"published","view":view.id,"content":view.content,"compatibility":view.compatibility,"validated_at":view.validated_at,"paired_metadata":"verified","engine_readability":"not_checked","qualification":"not_checked"}),
    )
}

pub(super) async fn inspect(reader: &mut Reader, report: &mut CollectionDiagnosis) -> Result<()> {
    for key in [
        "diagnostics-current",
        "diagnostics-history",
        "diagnostics-acquisition-content",
        "diagnostics-acquisition-compat",
        "diagnostics-recovery",
    ] {
        let value = match reader.state(DiagnosisProvider::Mdn, key).await? {
            Some(value) => crate::mdn::corpus::diagnostics::private_summary(value)?,
            None => json!({"state":"legacy_unknown"}),
        };
        report
            .diagnostics
            .push(json!({"record":key,"diagnostic":value}));
    }
    let legacy = reader.state(DiagnosisProvider::Mdn, "failure").await?;
    if let Some(value) = legacy {
        report.diagnostics.push(json!({"record":"legacy_failure","data":{
            "lane":value["lane"].as_str().filter(|s|matches!(*s,"current"|"history"|"acquisition"|"recovery")),
            "code":value["code"].as_str().map(safe_code),"at":value["at"].as_i64(),"phase":"legacy_unknown"}}));
    }
    for repo in [Repo::Content, Repo::Compat] {
        let main = main_state(reader, report, repo).await?;
        report
            .diagnostics
            .push(json!({"record":"main","data":main}));
        let history = history(reader, report, repo).await?;
        report
            .diagnostics
            .push(json!({"record":"history","data":history}));
    }
    // Size-admit only this one pending row; never enumerate its snapshot targets.
    let pending = reader.state(DiagnosisProvider::Mdn, "pending").await?;
    let pending = if let Some(value) = pending {
        let snapshots = value["snapshots"].as_array().ok_or_else(failed)?;
        let started_at = value["started_at"]
            .as_i64()
            .filter(|v| *v >= 0)
            .ok_or_else(failed)?;
        json!({"count":snapshots.len(),"started_at":started_at})
    } else {
        json!({"count":0})
    };
    report
        .diagnostics
        .push(json!({"record":"pending","data":pending}));
    let reference = reader
        .state(DiagnosisProvider::Mdn, "index")
        .await?
        .unwrap_or(Value::Null);
    report
        .diagnostics
        .push(json!({"record":"index","data":index(reader,&reference).await?}));
    let checkpoint = reader
        .state(DiagnosisProvider::Mdn, "index-checkpoint")
        .await?
        .filter(|v| !v.is_null());
    let checkpoint = if let Some(value) = checkpoint {
        json!({"sequence":value["sequence"].as_i64().filter(|v|*v>=0).ok_or_else(failed)?,"index":index(reader,&value["manifest"]).await?})
    } else {
        json!({"state":"absent"})
    };
    report
        .diagnostics
        .push(json!({"record":"index_checkpoint","data":checkpoint}));
    let default = default_view(reader, report).await?;
    report
        .diagnostics
        .push(json!({"record":"default_view","data":default}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use devres_application::mdn::MdnStore;

    fn options() -> DiagnosisOptions {
        DiagnosisOptions {
            provider: DiagnosisProvider::Mdn,
            max_total_bytes: MAX_BYTES,
            timeout_secs: 30,
            scan_retained_dump: false,
            snapshot: None,
            job_keys: Vec::new(),
            commit: None,
            attribution_target: None,
        }
    }
    fn artifact(bytes: &[u8]) -> BulkArtifact {
        let body_hash = integrity::hash(bytes);
        BulkArtifact {
            relative_path: integrity::relative_path(&body_hash)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            body_hash,
            bytes: bytes.len() as u64,
        }
    }
    fn order() -> (Vec<u8>, u64) {
        let first = format!("1700000000 {}\n", "a".repeat(40));
        let second = format!("1700000001 {} {}\n", "b".repeat(40), "a".repeat(40));
        (
            [first.as_bytes(), second.as_bytes()].concat(),
            first.len() as u64,
        )
    }
    fn observation(bytes: &[u8]) -> Observation {
        Observation {
            repo: Repo::Content,
            observed_at: 10,
            refs: Vec::new(),
            roots: Vec::new(),
            manifest: artifact(b"synthetic manifest descriptor"),
            commits: artifact(bytes),
            total_commits: 2,
            main_revision: None,
        }
    }
    fn budget() -> Budget {
        Budget {
            remaining: MAX_BYTES,
            read: 0,
            deadline: Instant::now() + Duration::from_secs(30),
            cancel: CancellationToken::new(),
        }
    }
    #[test]
    fn commit_order_cursor_checks_actual_git_grammar_and_completed_prefix() {
        let (bytes, offset) = order();
        let mut history = History {
            observation: observation(&bytes),
            offset,
            processed: 1,
            complete: false,
            processor_version: PROCESSOR_VERSION,
        };
        assert!(offset > history.observation.total_commits as u64);
        cursor(&bytes, &history, &budget()).unwrap();
        history.offset = 1;
        assert_eq!(
            cursor(&bytes, &history, &budget()).unwrap_err().code,
            "integrity"
        );
        history.offset = bytes.len() as u64 + 1;
        assert!(cursor(&bytes, &history, &budget()).is_err());
        history.offset = offset;
        history.processed = 2;
        assert!(cursor(&bytes, &history, &budget()).is_err());
        history.processed = 1;
        history.complete = true;
        assert!(cursor(&bytes, &history, &budget()).is_err());
        history.complete = false;
        assert!(cursor(&bytes[..bytes.len() - 1], &history, &budget()).is_err());
        let stopped = budget();
        stopped.cancel.cancel();
        assert_eq!(
            cursor(&bytes, &history, &stopped).unwrap_err().code,
            "cancelled"
        );
    }
    #[test]
    fn work_metadata_never_emits_paths_and_rejects_untyped_identities() {
        let secret = "private-untrusted-source-path";
        let summary = work(
            json!({"root":integrity::hash(b"root"),"previous":null,"offset":1,"changed":[secret]}),
        )
        .unwrap();
        assert_eq!(summary["changed_entries"], 1);
        assert!(!serde_json::to_string(&summary).unwrap().contains(secret));
        assert!(work(json!({"root":secret,"previous":null,"offset":1,"changed":[]})).is_err());
    }

    async fn database(name: &str) -> url::Url {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let mut admin = PgConnection::connect(&base).await.unwrap();
        sqlx_core::raw_sql::raw_sql(sqlx_core::sql_str::AssertSqlSafe(format!(
            "CREATE DATABASE {name}"
        )))
        .execute(&mut admin)
        .await
        .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{name}"));
        url
    }
    async fn seed(
        writer: &crate::PgBlobStore,
        root: &Path,
        remote: bool,
    ) -> (Observation, PathBuf, PathBuf) {
        let (bytes, offset) = order();
        let observation = observation(&bytes);
        let relative = artifact_relative(Repo::Content, &observation.commits).unwrap();
        let path = root.join(&relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let manifest_bytes =
            br#"{"version":3,"generation":"synthetic","parent":null,"shard":null}"#;
        let manifest = artifact(manifest_bytes);
        let index_path = format!("mdn-indexes/manifests/{}.json", manifest.relative_path);
        let index_file = root.join(&index_path);
        std::fs::create_dir_all(index_file.parent().unwrap()).unwrap();
        std::fs::write(&index_file, manifest_bytes).unwrap();
        if remote {
            tokio::task::block_in_place(|| {
                crate::durable_archive::publish_file(
                    &path,
                    &observation.commits.body_hash,
                    observation.commits.bytes,
                )
                .unwrap();
                crate::durable_archive::publish_file(
                    &index_file,
                    &manifest.body_hash,
                    manifest.bytes,
                )
                .unwrap();
            });
        }
        writer
            .mdn_put(
                "observations",
                &observation_id(&observation),
                &serde_json::to_value(&observation).unwrap(),
            )
            .await
            .unwrap();
        writer
            .mdn_set_state(
                "content-observation",
                &serde_json::to_value(&observation).unwrap(),
            )
            .await
            .unwrap();
        writer.mdn_set_state("content-history",&json!({"observation":observation,"offset":offset,"processed":1,"complete":false,"processor_version":PROCESSOR_VERSION})).await.unwrap();
        writer
            .mdn_set_state(
                "pending",
                &json!({"snapshots":["untrusted-source-path-not-emitted"],"started_at":10}),
            )
            .await
            .unwrap();
        writer
            .mdn_set_state(
                "index",
                &json!({"version":3,"path":index_path,"digest":manifest.body_hash}),
            )
            .await
            .unwrap();
        (observation, path, index_file)
    }
    async fn counts(conn: &mut PgConnection) -> (i64, i64, i64) {
        sqlx_core::query_as::query_as("SELECT (SELECT count(*) FROM devres_mdn_evidence),(SELECT count(*) FROM devres_mdn_state),(SELECT count(*) FROM devres_attribution_targets)").fetch_one(conn).await.unwrap()
    }
    fn record<'a>(report: &'a CollectionDiagnosis, name: &str) -> &'a Value {
        &report
            .diagnostics
            .iter()
            .find(|v| v["record"] == name)
            .unwrap()["data"]
    }
    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn mdn_inspection_verifies_prepared_and_published_pair_with_pinned_old_history() {
        let url = database("devres_mdn_paired_diagnosis_fixture").await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let writer = crate::PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let (old, _, _) = seed(&writer, root.path(), false).await;
        let mut snapshots = Vec::new();
        let mut observations = Vec::new();
        for (repo, character) in [(Repo::Content, "a"), (Repo::Compat, "b")] {
            let mut observation = old.clone();
            observation.repo = repo;
            observation.observed_at = 11;
            observation.main_revision = Some(character.repeat(40));
            observation.manifest =
                artifact(format!("synthetic current {} manifest", repo.as_str()).as_bytes());
            let observation_id = observation_id(&observation);
            writer
                .mdn_put(
                    "observations",
                    &observation_id,
                    &serde_json::to_value(&observation).unwrap(),
                )
                .await
                .unwrap();
            writer
                .mdn_set_state(
                    &format!("{}-observation", repo.as_str()),
                    &serde_json::to_value(&observation).unwrap(),
                )
                .await
                .unwrap();
            let revision = observation.main_revision.unwrap();
            let inventory = integrity::hash(format!("{} inventory", repo.as_str()).as_bytes());
            let id = integrity::hash(
                &serde_json::to_vec(&(repo.as_str(), &revision, PROCESSOR_VERSION, &inventory))
                    .unwrap(),
            );
            let snapshot = Snapshot {
                id,
                repository: repo.as_str().into(),
                revision,
                tree: "c".repeat(40),
                parents: Vec::new(),
                committed_at: 10,
                inventory,
                processor_version: PROCESSOR_VERSION,
                index: Value::Null,
                coverage: json!({"accounted":true,"members":1,"projection_gaps":0}),
            };
            let key = format!(
                "{}:{}:{PROCESSOR_VERSION}",
                repo.as_str(),
                snapshot.revision
            );
            writer
                .mdn_set_state(
                    &format!("prepared:{key}"),
                    &serde_json::to_value(&snapshot).unwrap(),
                )
                .await
                .unwrap();
            snapshots.push(snapshot);
            observations.push(observation_id);
        }
        let prepared = diagnose_collection(
            url.as_str(),
            root.path(),
            None,
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(prepared.complete);
        let mains: Vec<_> = prepared
            .diagnostics
            .iter()
            .filter(|v| v["record"] == "main")
            .collect();
        assert_eq!(mains.len(), 2);
        assert!(
            mains
                .iter()
                .all(|v| v["data"]["prepared"]["index_present"] == false
                    && v["data"]["published"]["state"] == "absent")
        );
        assert_eq!(record(&prepared, "default_view")["state"], "unpublished");
        let reference = writer.mdn_state("index").await.unwrap().unwrap();
        for snapshot in &mut snapshots {
            snapshot.index = reference.clone();
            let key = format!(
                "{}:{}:{PROCESSOR_VERSION}",
                snapshot.repository, snapshot.revision
            );
            writer
                .mdn_put(
                    "snapshots",
                    &snapshot.id,
                    &serde_json::to_value(&snapshot).unwrap(),
                )
                .await
                .unwrap();
            writer
                .mdn_put("snapshot-keys", &key, &json!(snapshot.id))
                .await
                .unwrap();
        }
        let mut view = View {
            id: String::new(),
            content: snapshots[0].id.clone(),
            compatibility: snapshots[1].id.clone(),
            content_observation: observations[0].clone(),
            compatibility_observation: observations[1].clone(),
            validated_at: 11,
        };
        view.id = integrity::hash(
            &serde_json::to_vec(&(
                &view.content,
                &view.compatibility,
                &view.content_observation,
                &view.compatibility_observation,
                view.validated_at,
            ))
            .unwrap(),
        );
        writer.mdn_publish_view(&view).await.unwrap();
        let published = diagnose_collection(
            url.as_str(),
            root.path(),
            None,
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(published.complete);
        let selected = record(&published, "default_view");
        assert_eq!(selected["view"], view.id);
        assert_eq!(selected["paired_metadata"], "verified");
        assert_eq!(selected["engine_readability"], "not_checked");
        assert_eq!(selected["qualification"], "not_checked");
        assert_eq!(
            record(&published, "history")["observation"],
            observation_id(&old)
        );
        assert_eq!(record(&published, "history")["complete"], false);
        assert_eq!(
            writer.mdn_state("default-view").await.unwrap().unwrap(),
            json!(view.id)
        );
        // A sealed view with a valid tuple identity must still link each
        // repository to its own observation, not merely two retained hashes.
        let mut mismatched = view.clone();
        mismatched.compatibility_observation = mismatched.content_observation.clone();
        mismatched.id = integrity::hash(
            &serde_json::to_vec(&(
                &mismatched.content,
                &mismatched.compatibility,
                &mismatched.content_observation,
                &mismatched.compatibility_observation,
                mismatched.validated_at,
            ))
            .unwrap(),
        );
        writer
            .mdn_put(
                "views",
                &mismatched.id,
                &serde_json::to_value(&mismatched).unwrap(),
            )
            .await
            .unwrap();
        writer
            .mdn_set_state("default-view", &json!(mismatched.id))
            .await
            .unwrap();
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                options(),
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::IntegrityFailed
        );
        writer
            .mdn_set_state("default-view", &json!(view.id))
            .await
            .unwrap();

        // Exercise retained derivation identities as well as ordinary current
        // snapshots. Their identities intentionally do not hash the whole row.
        let mut rebuilt = snapshots[0].clone();
        let generation = "synthetic-rebuild-generation";
        rebuilt.coverage["rebuild_of"] = json!(rebuilt.id);
        rebuilt.coverage["derived_generation"] = json!(generation);
        rebuilt.id = integrity::hash(
            &serde_json::to_vec(&(&snapshots[0].id, generation, &rebuilt.index)).unwrap(),
        );
        let legacy = "d".repeat(64);
        let mut migrated = snapshots[0].clone();
        migrated.id.clear();
        migrated.id = integrity::hash(
            &serde_json::to_vec(&(
                "devres:storage-migration:mdn-snapshot:v1",
                &legacy,
                &migrated,
            ))
            .unwrap(),
        );
        let namespace = "mdn:snapshots";
        let seal = super::super::super::events::event_digest(
            "devres_content_aliases",
            &super::super::super::events::mapping_key(namespace, &legacy).unwrap(),
            &json!({"namespace":namespace,"legacy":legacy,"canonical":migrated.id}),
        )
        .unwrap();
        let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
        sqlx_core::query::query("INSERT INTO devres_content_aliases(namespace,legacy,canonical,mapping_integrity) VALUES($1,$2,$3,$4)").bind(namespace).bind(&legacy).bind(&migrated.id).bind(seal).execute(&mut conn).await.unwrap();
        let (mut reader, _) = Reader::open(
            url.as_str(),
            root.path(),
            None,
            &options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        snapshot_identity(&mut reader, &rebuilt).await.unwrap();
        snapshot_identity(&mut reader, &migrated).await.unwrap();
        migrated.inventory = integrity::hash(b"wrong migrated inventory");
        assert_eq!(
            snapshot_identity(&mut reader, &migrated)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
    }
    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn mdn_inspection_is_read_only_bounded_and_rejects_tampered_evidence() {
        let url = database("devres_mdn_diagnosis_fixture").await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let writer = crate::PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let (observation, path, _) = seed(&writer, root.path(), false).await;
        let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
        let before = counts(&mut conn).await;
        let report = diagnose_collection(
            url.as_str(),
            root.path(),
            None,
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.complete);
        assert_eq!(record(&report, "history")["cursor_boundary"], "verified");
        assert_eq!(record(&report, "default_view")["state"], "unpublished");
        assert_eq!(
            record(&report, "index")["engine_readability"],
            "not_checked"
        );
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("untrusted-source-path-not-emitted")
        );
        assert_eq!(before, counts(&mut conn).await);
        // The serving reader admits a reference without a version field; the
        // retained manifest still has its independently verified format version.
        let mut reference = writer.mdn_state("index").await.unwrap().unwrap();
        reference.as_object_mut().unwrap().remove("version");
        writer.mdn_set_state("index", &reference).await.unwrap();
        let report = diagnose_collection(
            url.as_str(),
            root.path(),
            None,
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.complete);
        assert_eq!(record(&report, "index")["state"], "retained");
        assert_eq!(record(&report, "index")["manifest_digest"], "verified");
        let (mut reader, _) = Reader::open(
            url.as_str(),
            root.path(),
            None,
            &options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let error = sqlx_core::query::query("DELETE FROM devres_mdn_state")
            .execute(&mut reader.conn)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("25006")
        );
        drop(reader);
        let mut tiny = options();
        tiny.max_total_bytes = 1;
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                tiny,
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::BudgetExhausted
        );
        let key = format!("content:{}:{PROCESSOR_VERSION}", "c".repeat(40));
        let canonical = integrity::hash(b"aliased natural snapshot key");
        let value = json!(integrity::hash(b"selected snapshot"));
        writer.mdn_put("snapshot-keys", &key, &value).await.unwrap();
        writer
            .mdn_put("snapshot-keys", &canonical, &value)
            .await
            .unwrap();
        let namespace = "mdn:snapshot-keys";
        let seal = super::super::super::events::event_digest(
            "devres_content_aliases",
            &super::super::super::events::mapping_key(namespace, &key).unwrap(),
            &json!({"namespace":namespace,"legacy":key,"canonical":canonical}),
        )
        .unwrap();
        sqlx_core::query::query("INSERT INTO devres_content_aliases(namespace,legacy,canonical,mapping_integrity) VALUES($1,$2,$3,$4)").bind(namespace).bind(&key).bind(&canonical).bind(seal).execute(&mut conn).await.unwrap();
        // Resolve the alias first even when the original natural row also exists.
        let mut report = diagnose_collection(
            url.as_str(),
            root.path(),
            None,
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let (mut reader, _) = Reader::open(
            url.as_str(),
            root.path(),
            None,
            &options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let selected = evidence(&mut reader, &mut report, "snapshot-keys", &key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.0, canonical);
        drop(reader);
        sqlx_core::query::query("UPDATE devres_content_aliases SET mapping_integrity=$1 WHERE namespace=$2 AND legacy=$3").bind(integrity::hash(b"bad seal")).bind(namespace).bind(&key).execute(&mut conn).await.unwrap();
        let (mut reader, _) = Reader::open(
            url.as_str(),
            root.path(),
            None,
            &options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            evidence(&mut reader, &mut report, "snapshot-keys", &key)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        drop(reader);
        sqlx_core::query::query(
            "DELETE FROM devres_content_aliases WHERE namespace=$1 AND legacy=$2",
        )
        .bind(namespace)
        .bind(&key)
        .execute(&mut conn)
        .await
        .unwrap();
        let (_, offset) = order();
        let correct_history = json!({"observation":observation,"offset":offset,"processed":1,"complete":false,"processor_version":PROCESSOR_VERSION});
        let mut wrong_history = correct_history.clone();
        wrong_history["offset"] = json!(1);
        writer
            .mdn_set_state("content-history", &wrong_history)
            .await
            .unwrap();
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                options(),
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::IntegrityFailed
        );
        writer
            .mdn_set_state("content-history", &correct_history)
            .await
            .unwrap();
        sqlx_core::query::query("UPDATE devres_mdn_state SET data=jsonb_set(data,'{offset}','1') WHERE key='content-history'").execute(&mut conn).await.unwrap();
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                options(),
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::IntegrityFailed
        );
        writer
            .mdn_set_state("content-history", &correct_history)
            .await
            .unwrap();
        let missing = path.with_extension("held");
        std::fs::rename(&path, &missing).unwrap();
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                options(),
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::SelectedEvidenceUnavailable
        );
        std::fs::rename(missing, &path).unwrap();
        std::fs::write(path, b"tampered").unwrap();
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                options(),
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::IntegrityFailed
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable PostgreSQL and RustFS; run scripts/test-s3.sh"]
    async fn s3_mdn_inspection_verifies_committed_bindings_without_cache_or_writer_effects() {
        let url = database("devres_s3_mdn_diagnosis_fixture").await;
        let writer_path = std::env::var("DEVRES_TEST_S3_CONFIG").unwrap();
        let reader_path = std::env::var("DEVRES_TEST_S3_READER_CONFIG").unwrap();
        let mut writer_config: S3Config =
            toml::from_str(&std::fs::read_to_string(writer_path).unwrap()).unwrap();
        let mut reader_config: S3Config =
            toml::from_str(&std::fs::read_to_string(reader_path).unwrap()).unwrap();
        writer_config.prefix.push_str("/mdn-diagnosis");
        reader_config.prefix.push_str("/mdn-diagnosis");
        let writer_root = tempfile::tempdir_in("/tmp").unwrap();
        let reader_root = tempfile::tempdir_in("/tmp").unwrap();
        let writer = crate::PgBlobStore::connect_archive(
            url.as_str(),
            writer_root.path(),
            Some(writer_config),
        )
        .await
        .unwrap();
        let (observation, path, _) = seed(&writer, writer_root.path(), true).await;
        let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
        let before = counts(&mut conn).await;
        let report = diagnose_collection(
            url.as_str(),
            reader_root.path(),
            Some(reader_config.clone()),
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.complete);
        assert_eq!(
            record(&report, "history")["commit_order_digest"],
            "verified"
        );
        assert_eq!(record(&report, "index")["manifest_digest"], "verified");
        assert_eq!(before, counts(&mut conn).await);
        assert_eq!(std::fs::read_dir(reader_root.path()).unwrap().count(), 0);
        // Identical bytes at a different repository path still require that
        // path's own committed archive binding; a digest cache cannot admit it.
        let mut compatibility = observation.clone();
        compatibility.repo = Repo::Compat;
        writer
            .mdn_put(
                "observations",
                &observation_id(&compatibility),
                &serde_json::to_value(&compatibility).unwrap(),
            )
            .await
            .unwrap();
        let (order_bytes, offset) = order();
        writer.mdn_set_state("compat-history",&json!({"observation":compatibility,"offset":offset,"processed":1,"complete":false,"processor_version":PROCESSOR_VERSION})).await.unwrap();
        let report = diagnose_collection(
            url.as_str(),
            reader_root.path(),
            Some(reader_config.clone()),
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            report.outcome,
            DiagnosisOutcome::SelectedEvidenceUnavailable
        );
        let compat_path = writer_root
            .path()
            .join(artifact_relative(Repo::Compat, &compatibility.commits).unwrap());
        std::fs::create_dir_all(compat_path.parent().unwrap()).unwrap();
        std::fs::write(&compat_path, &order_bytes).unwrap();
        tokio::task::block_in_place(|| {
            crate::durable_archive::publish_file(
                &compat_path,
                &compatibility.commits.body_hash,
                compatibility.commits.bytes,
            )
            .unwrap()
        });
        let report = diagnose_collection(
            url.as_str(),
            reader_root.path(),
            Some(reader_config.clone()),
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.complete);
        let relative = path
            .strip_prefix(writer_root.path())
            .unwrap()
            .to_string_lossy();
        sqlx_core::query::query("UPDATE devres_archive_file SET evidence=jsonb_set(evidence::jsonb,'{bytes}',to_jsonb(bytes+1))::text WHERE path=$1").bind(relative.as_ref()).execute(&mut conn).await.unwrap();
        let report = diagnose_collection(
            url.as_str(),
            reader_root.path(),
            Some(reader_config.clone()),
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(report.outcome, DiagnosisOutcome::IntegrityFailed);
        sqlx_core::query::query("DELETE FROM devres_archive_file WHERE path=$1")
            .bind(relative.as_ref())
            .execute(&mut conn)
            .await
            .unwrap();
        let report = diagnose_collection(
            url.as_str(),
            reader_root.path(),
            Some(reader_config),
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            report.outcome,
            DiagnosisOutcome::SelectedEvidenceUnavailable
        );
        assert_eq!(std::fs::read_dir(reader_root.path()).unwrap().count(), 0);
    }
}
