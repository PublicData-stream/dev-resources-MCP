//! Selected sealed metadata only. No corpus materialization, acquisition or repair.
use super::*;
use devres_application::{advisory::ADVISORY_PROCESSOR_VERSION, collection::Failure};
use devres_domain::Capture;

pub(super) fn valid_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|value| value.starts_with("blake3:") && integrity::valid_hash(value))
}

fn finite(value: &Value, allowed: &[&str]) -> Value {
    value
        .as_str()
        .filter(|value| allowed.contains(value))
        .map_or(Value::Null, |value| json!(value))
}

fn failure(value: &Value) -> Result<Value> {
    if value.is_null() {
        return Ok(Value::Null);
    }
    let mut failure: Failure = serde_json::from_value(value.clone()).map_err(|_| failed())?;
    if failure
        .http_status
        .is_some_and(|status| !(100..=599).contains(&status))
    {
        return Err(failed());
    }
    failure.code = safe_code(&failure.code).into();
    serde_json::to_value(failure).map_err(|_| failed())
}

fn diagnostic(value: &Value) -> Result<Value> {
    if value["version"] != 1 {
        return Err(failed());
    }
    let mut result = json!({
        "version":1,"attempt":hash(&value["attempt"]),
        "operation":finite(&value["operation"], &["current_refresh","synchronize","restore","projection"]),
        "stage":finite(&value["stage"], &["head","bundle","normalization","snapshot_lookup","publication","synchronize","restore","projection"]),
        "outcome":finite(&value["outcome"], &["running","succeeded","failed","unknown","deferred","idle"]),
        "started_at":value["started_at"].as_i64(),"finished_at":value["finished_at"].as_i64(),
        "head_capture":hash(&value["head_capture"]),"bundle_capture":hash(&value["bundle_capture"]),
        "snapshot":hash(&value["snapshot"]),"observation":hash(&value["observation"]),
        "checkpoint":value["checkpoint"].as_u64(),
        "revision":value["revision"].as_str().filter(|value|valid_oid(value)),
        "failure":failure(&value["failure"])?
    });
    if let Some(failures) = value["failures"].as_array() {
        if failures.len() > 3 {
            return Err(failed());
        }
        let mut selected = Vec::new();
        for old in failures {
            selected.push(json!({"attempt":hash(&old["attempt"]),
                "operation":finite(&old["operation"], &["synchronize","restore","projection"]),
                "observation":hash(&old["observation"]),"failure":failure(&old["failure"])?,
                "checkpoint":old["checkpoint"].as_u64(),
                "resolved_at":old["resolved_at"].as_i64()}));
        }
        result["failures"] = json!(selected);
    }
    Ok(result)
}

fn state_summary(value: &Value) -> Value {
    json!({"last_attempt":value["last_attempt"].as_i64(),"last_success":value["last_success"].as_i64(),
        "snapshot":hash(&value["snapshot"]),"error":value["error"].as_str().map(safe_code),
        "previous_snapshot_preserved":value["previous_snapshot_preserved"].as_bool(),
        "at":value["at"].as_i64(),"code":value["code"].as_str().map(safe_code),
        "next_attempt":value["next_attempt"].as_i64(),"observation_id":hash(&value["observation_id"]),
        "observed_at":value["observed_at"].as_i64(),"processor_version":value["processor_version"].as_u64(),
        "complete":value["complete"].as_bool(),"projection_complete":value["projection_complete"].as_bool(),
        "processed":value["processed"].as_u64(),"total":value["total"].as_u64()})
}

fn coverage(value: &Value) -> Result<Value> {
    let gaps = value["gaps"].as_array();
    let mut samples = Vec::new();
    for gap in gaps.into_iter().flatten().take(2) {
        samples.push(json!({"path":gap["path"].as_str().filter(|path| path.len()<=4096 && crate::archive::valid_relative_path(path)),
            "code":gap["code"].as_str().map(safe_code)}));
    }
    Ok(
        json!({"complete":value["complete"].as_bool(),"graph_complete":value["graph_complete"].as_bool(),
        "matching_complete":value["matching_complete"].as_bool(),"enumerated":value["enumerated"].as_u64(),
        "processed":value["processed"].as_u64(),"parsed":value["parsed"].as_u64(),
        "retained_records":value["retained_records"].as_u64(),"omitted":value["omitted"].as_u64(),
        "processor_version":value["processor_version"].as_u64(),
        "gap_count":value["gap_count"].as_u64().or_else(||gaps.map(|gaps|gaps.len() as u64)),
        "gap_samples":samples,"gap_sample_limit":2}),
    )
}

async fn alias(reader: &mut Reader, namespace: &str, key: &str) -> Result<String> {
    let size: Option<i64> = sqlx_core::query_scalar::query_scalar("SELECT octet_length(canonical)::bigint+COALESCE(octet_length(mapping_integrity),0)::bigint FROM devres_content_aliases WHERE namespace=$1 AND legacy=$2")
        .bind(namespace).bind(key).fetch_optional(&mut reader.conn).await.map_err(|_|unavailable())?;
    let Some(size) = size else {
        return Ok(key.into());
    };
    if size > 8192 {
        return Err(failed());
    }
    reader.row_admit(size)?;
    let row = sqlx_core::query::query("SELECT canonical,mapping_integrity FROM devres_content_aliases WHERE namespace=$1 AND legacy=$2")
        .bind(namespace).bind(key).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
    let canonical: String = row.try_get("canonical").map_err(|_| failed())?;
    let seal: String = row.try_get("mapping_integrity").map_err(|_| failed())?;
    if !canonical.starts_with("blake3:")
        || !integrity::valid_hash(&canonical)
        || super::super::events::event_digest(
            "devres_content_aliases",
            &super::super::events::mapping_key(namespace, key)?,
            &json!({"namespace":namespace,"legacy":key,"canonical":canonical}),
        )? != seal
    {
        return Err(failed());
    }
    Ok(canonical)
}

async fn row(
    reader: &mut Reader,
    kind: &str,
    key: &str,
    cutoff: i64,
) -> Result<Option<(i64, Value)>> {
    let key = alias(reader, &format!("advisory:{kind}"), key).await?;
    let size: Option<i64> = sqlx_core::query_scalar::query_scalar("SELECT octet_length(data::text)::bigint FROM devres_advisory_rows WHERE kind=$1 AND key=$2 AND sequence<=$3")
        .bind(kind).bind(&key).bind(cutoff).fetch_optional(&mut reader.conn).await.map_err(|_|unavailable())?;
    let Some(size) = size else {
        return Ok(None);
    };
    reader.row_admit(size)?;
    let row = sqlx_core::query::query("SELECT sequence,sequence_integrity,kind,key,data,data_integrity FROM devres_advisory_rows WHERE kind=$1 AND key=$2 AND sequence<=$3")
        .bind(kind).bind(&key).bind(cutoff).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
    let data = payload_integrity::row("devres_advisory_rows", &row)?;
    Ok(Some((row.try_get("sequence").map_err(|_| failed())?, data)))
}

async fn capture(reader: &mut Reader, selected: &Capture) -> Result<Value> {
    let id = alias(reader, "capture", &selected.id).await?;
    let size: Option<i64> = sqlx_core::query_scalar::query_scalar(
        "SELECT octet_length(to_jsonb(c)::text)::bigint FROM devres_captures c WHERE id=$1",
    )
    .bind(&id)
    .fetch_optional(&mut reader.conn)
    .await
    .map_err(|_| unavailable())?;
    reader.row_admit(size.ok_or_else(unavailable)?)?;
    let row = sqlx_core::query::query("SELECT id,source_key,source_url,body_hash,media_type,retrieved_at,metadata_integrity FROM devres_captures WHERE id=$1")
        .bind(&id).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
    let retained = Capture {
        id: row.try_get("id").map_err(|_| failed())?,
        key: row.try_get("source_key").map_err(|_| failed())?,
        source_url: row.try_get("source_url").map_err(|_| failed())?,
        body_hash: row.try_get("body_hash").map_err(|_| failed())?,
        media_type: row.try_get("media_type").map_err(|_| failed())?,
        retrieved_at: row.try_get("retrieved_at").map_err(|_| failed())?,
        validated_at: selected.validated_at,
    };
    let seal: String = row.try_get("metadata_integrity").map_err(|_| failed())?;
    let selected_body = alias(reader, "body", &selected.body_hash).await?;
    if capture_metadata_digest(&retained)? != seal
        || retained.body_hash != selected_body
        || retained.key != selected.key
        || retained.source_url != selected.source_url
        || retained.media_type != selected.media_type
        || retained.retrieved_at != selected.retrieved_at
    {
        return Err(failed());
    }
    let kind = if retained.key == "rustsec:head"
        && retained.source_url == crate::rustsec::corpus::HEAD_URL
    {
        "head"
    } else if retained
        .key
        .strip_prefix("rustsec:bundle:")
        .is_some_and(valid_oid)
        && retained.source_url
            == format!(
                "https://codeload.github.com/RustSec/advisory-db/tar.gz/{}",
                &retained.key[15..]
            )
    {
        "bundle"
    } else {
        return Err(failed());
    };
    Ok(
        json!({"id":retained.id,"kind":kind,"body_hash":retained.body_hash,"retrieved_at":retained.retrieved_at,
        "selected_validated_at":selected.validated_at,"sealed_metadata":"verified","body_bytes":"not_checked"}),
    )
}

async fn snapshot(reader: &mut Reader, id: &str, format: &str) -> Result<Value> {
    let id = alias(reader, "advisory:snapshots", id).await?;
    let size: Option<i64> = sqlx_core::query_scalar::query_scalar("SELECT octet_length(data::text)::bigint FROM devres_advisory_snapshots WHERE id=$1 AND format=$2")
        .bind(&id).bind(format).fetch_optional(&mut reader.conn).await.map_err(|_|unavailable())?;
    reader.row_admit(size.ok_or_else(unavailable)?)?;
    let row=sqlx_core::query::query("SELECT sequence,format,revision,''::text AS kind,id AS key,data,data_integrity FROM devres_advisory_snapshots WHERE id=$1 AND format=$2")
        .bind(&id).bind(format).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
    let data = payload_integrity::row("devres_advisory_snapshots", &row)?;
    // row() verifies the descriptor seal over its sequence, format and revision.
    if data["id"] != id
        || data["format"] != format
        || !data["revision"].as_str().is_some_and(valid_oid)
    {
        return Err(failed());
    }
    let mut captures = Vec::new();
    let selected = data["captures"].as_array().ok_or_else(failed)?;
    if selected.len() > 2 {
        return Err(failed());
    }
    for selected in selected {
        let selected: Capture = serde_json::from_value(selected.clone()).map_err(|_| failed())?;
        if selected.key.starts_with("rustsec:bundle:")
            && selected.key
                != format!(
                    "rustsec:bundle:{}",
                    data["revision"].as_str().ok_or_else(failed)?
                )
        {
            return Err(failed());
        }
        captures.push(capture(reader, &selected).await?);
    }
    Ok(
        json!({"id":id,"format":format,"revision":data["revision"],"complete":data["complete"].as_bool(),
        "created_at":data["created_at"].as_i64(),"validated_at":data["validated_at"].as_i64(),
        "historical":data["historical"].as_bool(),"record_count":data["record_count"].as_u64(),
        "membership_hash":hash(&data["membership_hash"]),"coverage":coverage(&data["coverage"])?,
        "captures":captures,"sealed_metadata":"verified","membership_bytes":"not_checked","attribution_qualified":"not_checked"}),
    )
}

pub(super) async fn inspect(
    reader: &mut Reader,
    report: &mut CollectionDiagnosis,
    options: &DiagnosisOptions,
) -> Result<()> {
    let mut selected = json!({"operation":"rustsec_metadata","states":{},"diagnostics":{},"defaults":[],"commit":null,"attribution_target":null,
        "provider_requests":0,"body_bytes":"not_checked","scope":"selected_sealed_metadata"});
    for key in ["current", "history", "history-error", "history-retry"] {
        if let Some(value) = reader.state(DiagnosisProvider::Rustsec, key).await? {
            selected["states"][key] = state_summary(&value);
        }
    }
    for key in ["diagnostics-current", "diagnostics-history"] {
        selected["diagnostics"][key] = match reader.state(DiagnosisProvider::Rustsec, key).await? {
            Some(value) => {
                let mut info = diagnostic(&value)?;
                if key == "diagnostics-current" {
                    let mut refs = Vec::new();
                    for field in ["head_capture", "bundle_capture"] {
                        if let Some(id) = hash(&value[field]) {
                            let info =
                                capture_reference(reader, id, value["revision"].as_str()).await?;
                            let expected = if field == "head_capture" {
                                "head"
                            } else {
                                "bundle"
                            };
                            if info["kind"] != expected {
                                return Err(failed());
                            }
                            refs.push(info);
                        }
                    }
                    let linked = refs.len() == 2 && refs[0]["id"] != refs[1]["id"];
                    info["capture_metadata"] = json!(refs);
                    info["capture_linkage"] = json!(if linked {
                        "verified_metadata"
                    } else {
                        "unlinked"
                    });
                    if !linked {
                        report.complete = false;
                    }
                }
                info
            }
            None => {
                report.complete = false;
                json!({"outcome":"legacy_unknown","failure_phase_known":false})
            }
        };
    }
    // Defaults are selectors, not qualification evidence. Verify every referenced descriptor.
    reader.budget.admit(1024)?;
    let defaults: Vec<(String, String)> = sqlx_core::query_as::query_as(
        "SELECT format,snapshot FROM devres_advisory_defaults ORDER BY format LIMIT 3",
    )
    .fetch_all(&mut reader.conn)
    .await
    .map_err(|_| unavailable())?;
    if defaults.len() > 2 {
        return Err(failed());
    }
    for (format, id) in defaults {
        if !matches!(format.as_str(), "rustsec" | "osv") || !integrity::valid_hash(&id) {
            return Err(failed());
        }
        selected["defaults"]
            .as_array_mut()
            .ok_or_else(failed)?
            .push(snapshot(reader, &id, &format).await?);
    }
    if let Some(commit) = &options.commit {
        let Some((sequence, raw)) = row(reader, "commits", commit, report.cutoff).await? else {
            return Err(unavailable());
        };
        if raw["revision"] != *commit {
            return Err(failed());
        }
        let mut latest: Option<(i64, Value)> = None;
        for version in 1..=ADVISORY_PROCESSOR_VERSION {
            if let Some((sequence, data)) = row(
                reader,
                "processing",
                &format!("{commit}:{version}"),
                report.cutoff,
            )
            .await?
            {
                if data["revision"] != *commit || data["processor_version"] != version {
                    return Err(failed());
                }
                if latest.as_ref().is_none_or(|(old, _)| *old < sequence) {
                    latest = Some((sequence, data));
                }
            }
        }
        let mut projections = Vec::new();
        if let Some((_, data)) = &latest {
            let snapshots = data["snapshots"].as_object().ok_or_else(failed)?;
            if snapshots.len() > 2 {
                return Err(failed());
            }
            for (format, id) in snapshots {
                if !matches!(format.as_str(), "rustsec" | "osv") {
                    return Err(failed());
                }
                projections.push(
                    snapshot(
                        reader,
                        id.as_str()
                            .filter(|id| integrity::valid_hash(id))
                            .ok_or_else(failed)?,
                        format,
                    )
                    .await?,
                );
            }
        } else {
            report.complete = false;
        }
        selected["commit"] = json!({"revision":commit,"sequence":sequence,"processor_version":latest.as_ref().and_then(|(_,v)|v["processor_version"].as_u64()),
            "projection_complete":latest.as_ref().and_then(|(_,v)|v["projection_complete"].as_bool()),"projections":projections,"sealed_metadata":"verified"});
    }
    if let Some(id) = &options.attribution_target {
        let size:Option<i64>=sqlx_core::query_scalar::query_scalar("SELECT octet_length(data::text)::bigint FROM devres_attribution_targets WHERE id=$1 AND provider='rustsec'")
            .bind(id).fetch_optional(&mut reader.conn).await.map_err(|_|unavailable())?;
        reader.row_admit(size.ok_or_else(unavailable)?)?;
        let row=sqlx_core::query::query("SELECT id,provider,policy_epoch,status,priority,retry_at,data,data_integrity FROM devres_attribution_targets WHERE id=$1 AND provider='rustsec'")
            .bind(id).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
        selected["attribution_target"] =
            super::super::attribution_storage::recovery::checked_target_summary(&row)?;
    }
    if !report.complete {
        report.outcome = DiagnosisOutcome::AttemptedPayloadUnlinked;
    }
    report.diagnostics.push(selected);
    Ok(())
}

async fn capture_reference(reader: &mut Reader, id: &str, revision: Option<&str>) -> Result<Value> {
    let id = alias(reader, "capture", id).await?;
    let size: Option<i64> = sqlx_core::query_scalar::query_scalar(
        "SELECT octet_length(to_jsonb(c)::text)::bigint FROM devres_captures c WHERE id=$1",
    )
    .bind(&id)
    .fetch_optional(&mut reader.conn)
    .await
    .map_err(|_| unavailable())?;
    reader.row_admit(size.ok_or_else(unavailable)?)?;
    let row=sqlx_core::query::query("SELECT id,source_key,source_url,body_hash,media_type,retrieved_at,metadata_integrity FROM devres_captures WHERE id=$1")
        .bind(&id).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
    let retained = Capture {
        id: row.try_get("id").map_err(|_| failed())?,
        key: row.try_get("source_key").map_err(|_| failed())?,
        source_url: row.try_get("source_url").map_err(|_| failed())?,
        body_hash: row.try_get("body_hash").map_err(|_| failed())?,
        media_type: row.try_get("media_type").map_err(|_| failed())?,
        retrieved_at: row.try_get("retrieved_at").map_err(|_| failed())?,
        validated_at: 0,
    };
    if capture_metadata_digest(&retained)?
        != row
            .try_get::<String, _>("metadata_integrity")
            .map_err(|_| failed())?
    {
        return Err(failed());
    }
    let kind = if retained.key == "rustsec:head"
        && retained.source_url == crate::rustsec::corpus::HEAD_URL
    {
        "head"
    } else if let Some(revision) = revision.filter(|value| valid_oid(value)) {
        if retained.key != format!("rustsec:bundle:{revision}")
            || retained.source_url
                != format!("https://codeload.github.com/RustSec/advisory-db/tar.gz/{revision}")
        {
            return Err(failed());
        }
        "bundle"
    } else {
        return Err(failed());
    };
    Ok(
        json!({"id":retained.id,"body_hash":retained.body_hash,"kind":kind,"retrieved_at":retained.retrieved_at,
        "sealed_metadata":"verified","body_bytes":"not_checked","validation_provenance":"not_checked"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use devres_application::{
        Store,
        advisory::{AdvisorySnapshot, AdvisoryStore},
        attribution::AttributionStore,
    };
    use devres_domain::{FetchRequest, FetchResponse, Validators, attribution::*};
    #[test]
    fn reports_only_closed_metadata_and_bounded_gap_samples() {
        let private = "private-input-canary";
        let value = json!({"last_attempt":12,"error":private,"text":private,"source_url":private});
        let selected = state_summary(&value);
        assert_eq!(selected["error"], "other");
        assert!(!selected.to_string().contains(private));
        let selected=coverage(&json!({"complete":false,"gaps":[{"path":"crates/a/RUSTSEC-0000-0000.toml","code":"integrity","body":private},{"path":"../private","code":private},{"path":"third","code":"integrity"}]})).unwrap();
        assert_eq!(selected["gap_count"], 3);
        assert_eq!(selected["gap_samples"].as_array().unwrap().len(), 2);
        assert!(selected["gap_samples"][1]["path"].is_null());
        assert!(!selected.to_string().contains(private));
    }
    #[test]
    fn exact_selectors_are_canonical_and_provider_scoped() {
        let mut options = DiagnosisOptions {
            provider: DiagnosisProvider::Rustsec,
            max_total_bytes: MAX_BYTES,
            timeout_secs: 30,
            scan_retained_dump: false,
            snapshot: None,
            job_keys: vec![],
            commit: Some("a".repeat(40)),
            attribution_target: Some(integrity::hash(b"target")),
        };
        assert!(options.validate().is_ok());
        options.commit = Some("A".repeat(40));
        assert!(options.validate().is_err());
        options.commit = None;
        options.provider = DiagnosisProvider::W3c;
        assert!(options.validate().is_err());
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn selected_rustsec_metadata_is_sealed_read_only_and_keeps_projection_gaps() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let mut admin = PgConnection::connect(&base).await.unwrap();
        sqlx_core::raw_sql::raw_sql("CREATE DATABASE devres_rustsec_diagnosis_fixture")
            .execute(&mut admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_rustsec_diagnosis_fixture");
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let writer = crate::PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let revision = "a".repeat(40);
        let mut captures = Vec::new();
        for (key, url, body, media_type) in [
            (
                "rustsec:head".into(),
                crate::rustsec::corpus::HEAD_URL.into(),
                format!("{{\"sha\":\"{revision}\"}}").into_bytes(),
                "application/json",
            ),
            (
                format!("rustsec:bundle:{revision}"),
                format!("https://codeload.github.com/RustSec/advisory-db/tar.gz/{revision}"),
                b"inert bundle metadata fixture".to_vec(),
                "application/gzip",
            ),
        ] {
            let stored = writer
                .publish(
                    &FetchRequest {
                        key,
                        url,
                        ttl_secs: 60,
                        max_bytes: 1024,
                        media_type: media_type.into(),
                    },
                    FetchResponse {
                        status: 200,
                        body,
                        validators: Validators::default(),
                    },
                    10,
                )
                .await
                .unwrap();
            captures.push(stored.capture);
        }
        let canonical = integrity::hash(b"rustsec diagnosis canonical");
        let osv = integrity::hash(b"rustsec diagnosis osv");
        for (id, format, complete, selected) in [
            (&canonical, "rustsec", false, captures.clone()),
            (&osv, "osv", true, vec![]),
        ] {
            writer.publish_advisory_snapshot(&AdvisorySnapshot{id:id.clone(),revision:revision.clone(),format:format.into(),created_at:10,validated_at:Some(10),historical:false,complete,records:vec![],captures:selected,
                coverage:json!({"complete":complete,"processor_version":2,"enumerated":1,"parsed":if complete{1}else{0},"gaps":if complete{vec![]}else{vec![json!({"path":"crates/a/RUSTSEC-0000-0000.toml","code":"integrity","text":"private-input-canary"})]}}),parents:vec![],committed_at:10},complete).await.unwrap();
        }
        writer
            .put_advisory_row(
                "commits",
                &revision,
                &json!({"revision":revision,"parents":[],"committed_at":10}),
            )
            .await
            .unwrap();
        writer.put_advisory_row("processing",&format!("{revision}:2"),&json!({"revision":revision,"processor_version":2,"snapshots":{"rustsec":canonical,"osv":osv},"projection_complete":false,"parent_snapshots":{}})).await.unwrap();
        writer.set_advisory_state("current",&json!({"error":"unavailable","last_attempt":20,"last_success":10,"snapshot":canonical,"source_url":"private-input-canary"})).await.unwrap();
        let target = crate::attribution_providers::targets(
            "rustsec",
            &serde_json::to_value(&captures[1]).unwrap(),
        )
        .unwrap()
        .pop()
        .unwrap();
        writer.attribution_enqueue(&target, 1).await.unwrap();
        let job = writer
            .attribution_claim(&["rustsec".into()], devres_domain::unix_now(), 0)
            .await
            .unwrap()
            .unwrap();
        writer
            .attribution_fail_classified(
                &job,
                None,
                "blocked",
                &AttributionFailure::new(
                    AttributionPhase::Mapping,
                    AttributionFailureReason::UnsupportedSource,
                    AttributionDisposition::Blocked,
                ),
            )
            .await
            .unwrap();
        // Resolve target by its exact subject instead of relying on a private target-ID recipe.
        let mut connection = PgConnection::connect(url.as_str()).await.unwrap();
        let target_id:String=sqlx_core::query_scalar::query_scalar("SELECT id FROM devres_attribution_targets WHERE provider='rustsec' AND data->'target'->'subject'->>'key'=$1 LIMIT 1")
            .bind(&target.subject.key).fetch_one(&mut connection).await.unwrap();
        let options = DiagnosisOptions {
            provider: DiagnosisProvider::Rustsec,
            max_total_bytes: MAX_BYTES,
            timeout_secs: 30,
            scan_retained_dump: false,
            snapshot: None,
            job_keys: vec![],
            commit: Some(revision.clone()),
            attribution_target: Some(target_id.clone()),
        };
        let before = writer.advisory_status().await.unwrap();
        let report = diagnose_collection(
            url.as_str(),
            root.path(),
            None,
            options.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!report.complete); // Legacy stage-less failure stays explicitly unlinked.
        let value = &report.diagnostics[0];
        assert_eq!(value["commit"]["projection_complete"], false);
        assert_eq!(value["attribution_target"]["eligible"], true);
        assert_eq!(
            value["commit"]["projections"][1]["coverage"]["gap_samples"][0]["path"],
            "crates/a/RUSTSEC-0000-0000.toml"
        );
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("private-input-canary")
        );
        assert_eq!(writer.advisory_status().await.unwrap(), before);
        let mut missing = options.clone();
        missing.commit = Some("b".repeat(40));
        let absent = diagnose_collection(
            url.as_str(),
            root.path(),
            None,
            missing,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!absent.complete);
        assert_eq!(
            absent.outcome,
            DiagnosisOutcome::SelectedEvidenceUnavailable
        );
        let mut missing = options.clone();
        missing.attribution_target = Some(integrity::hash(b"absent target"));
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                missing,
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::SelectedEvidenceUnavailable
        );
        let mut limited = options.clone();
        limited.max_total_bytes = 1;
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                limited,
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::BudgetExhausted
        );
        let private = json!({"version":1,"attempt":integrity::hash(b"failed attempt"),"operation":"current_refresh","stage":"publication","outcome":"failed","started_at":20,"finished_at":21,
            "head_capture":captures[0].id,"bundle_capture":captures[1].id,"revision":revision,"snapshot":canonical,
            "failure":Failure::from_error(&Error::unavailable("private-input-canary"),devres_application::collection::Phase::ViewPublication,21)});
        writer
            .set_advisory_state("diagnostics-current", &private)
            .await
            .unwrap();
        let attempt = diagnose_collection(
            url.as_str(),
            root.path(),
            None,
            options.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            attempt.diagnostics[0]["diagnostics"]["diagnostics-current"]["capture_linkage"],
            "verified_metadata"
        );
        assert!(
            !serde_json::to_string(&attempt)
                .unwrap()
                .contains("private-input-canary")
        );
        let mut wrong = private.clone();
        wrong["revision"] = json!("b".repeat(40));
        writer
            .set_advisory_state("diagnostics-current", &wrong)
            .await
            .unwrap();
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                options.clone(),
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::IntegrityFailed
        );
        writer
            .set_advisory_state("diagnostics-current", &private)
            .await
            .unwrap();
        for (head, bundle) in [
            (&captures[1].id, &captures[0].id),
            (&captures[0].id, &captures[0].id),
        ] {
            let mut wrong = private.clone();
            wrong["head_capture"] = json!(head);
            wrong["bundle_capture"] = json!(bundle);
            writer
                .set_advisory_state("diagnostics-current", &wrong)
                .await
                .unwrap();
            assert_eq!(
                diagnose_collection(
                    url.as_str(),
                    root.path(),
                    None,
                    options.clone(),
                    CancellationToken::new()
                )
                .await
                .unwrap()
                .outcome,
                DiagnosisOutcome::IntegrityFailed
            );
        }
        writer
            .set_advisory_state("diagnostics-current", &private)
            .await
            .unwrap();
        // Selected state seals are verified before metadata is trusted.
        let mut connection = PgConnection::connect(url.as_str()).await.unwrap();
        sqlx_core::query::query("UPDATE devres_advisory_state SET data=data || '{\"last_attempt\":999}'::jsonb WHERE key='current'")
            .execute(&mut connection).await.unwrap();
        let report = diagnose_collection(
            url.as_str(),
            root.path(),
            None,
            options,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(report.outcome, DiagnosisOutcome::IntegrityFailed);
    }
}
