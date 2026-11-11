//! Fixed, resumable Wikimedia acceptance; no collector bootstrap or raw event archive.
use devres_adapters::{
    bulk::{BulkBroker, BulkConfig},
    wikipedia::{
        cache::CacheMetadata,
        events::SseParser,
        processing,
        source::{Operation, Response, WikipediaSource},
    },
};
use devres_domain::{Error, Result, Validators};
use futures::StreamExt;
use serde_json::{Value, json};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
#[path = "../support/root.rs"]
mod root;
const MARKER: &[u8] = b"devres-wikipedia-live-v1\n";
const RECORDS: [(&str, &str); 2] = [("llm", "Large language model"), ("riscv", "RISC-V")];
fn unavailable() -> Error {
    Error::unavailable("Wikipedia live evidence unavailable.")
}
fn invalid() -> Error {
    Error::integrity("Invalid retained Wikipedia live evidence.")
}
fn file(root: &Path, name: &str) -> Result<PathBuf> {
    let path = root.join(name);
    if let Ok(metadata) = std::fs::symlink_metadata(&path)
        && (!metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 1024 * 1024)
    {
        return Err(invalid());
    }
    Ok(path)
}
fn read(root: &Path, name: &str) -> Result<Option<Value>> {
    match std::fs::read(file(root, name)?) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| invalid()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(unavailable()),
    }
}
fn persist(root: &Path, name: &str, value: &Value) -> Result<()> {
    let destination = file(root, name)?;
    let stage = root.join(format!("{name}.stage-{}", std::process::id()));
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)
        .map_err(|_| unavailable())?;
    serde_json::to_writer_pretty(&mut output, value).map_err(|_| unavailable())?;
    output
        .write_all(b"\n")
        .and_then(|()| output.sync_all())
        .map_err(|_| unavailable())?;
    std::fs::rename(stage, destination).map_err(|_| unavailable())?;
    std::fs::File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| unavailable())
}
fn counted_broker(root: &Path) -> Result<Arc<BulkBroker>> {
    let initial = read(root, "attempt-state.json")?.unwrap_or(json!({"attempts":0,"not_before":0}));
    let count = initial["attempts"]
        .as_u64()
        .filter(|count| *count <= 20)
        .ok_or_else(invalid)? as usize;
    let owned = root.to_owned();
    Ok(Arc::new(BulkBroker::new(BulkConfig::default())?.with_attempt_budget(20)?.with_attempt_observer(count, Arc::new(move |count| {
        let old = read(&owned, "attempt-state.json")?.unwrap_or(json!({"attempts":0,"not_before":0}));
        let previous = old["attempts"].as_u64().ok_or_else(invalid)?;
        if count as u64 != previous.saturating_add(1) || count > 20 { return Err(invalid()); }
        let not_before = old["not_before"].as_i64().unwrap_or(0);
        if not_before > devres_domain::unix_now() { return Err(Error::unavailable("Retained Wikipedia live admission is not due.")); }
        // Both accounting and next-attempt admission are fsynced BEFORE I/O.
        persist(&owned, "attempt-state.json", &json!({"attempts":count,"not_before":devres_domain::unix_now().saturating_add(1)}))
    }))?))
}
fn cooldown(root: &Path, until: Option<i64>) -> Result<()> {
    if let Some(until) = until {
        let mut state = read(root, "attempt-state.json")?.ok_or_else(invalid)?;
        state["not_before"] = json!(state["not_before"].as_i64().unwrap_or(0).max(until));
        persist(root, "attempt-state.json", &state)?;
    }
    Ok(())
}
async fn admitted(root: &Path) -> Result<()> {
    let state = read(root, "attempt-state.json")?.unwrap_or(json!({"attempts":0,"not_before":0}));
    let until = state["not_before"].as_i64().ok_or_else(invalid)?;
    let delay = until.saturating_sub(devres_domain::unix_now()).max(0) as u64;
    if delay > 5 {
        return Err(Error::unavailable(
            "Wikipedia live evidence deferred by retained cooldown.",
        ));
    }
    tokio::time::sleep(Duration::from_secs(delay)).await;
    Ok(())
}
fn metadata(response: &Response) -> Result<Value> {
    Ok(
        json!({"source_url":response.effective_url,"status":response.status,"decoded_bytes":response.body.len(),"body_hash":devres_adapters::integrity::hash(&response.body),"cache":response.cache,"fresh_until":response.cache.freshness_deadline()?,"retry_at":response.retry_at,"action_slow_until":response.action_slow_until,"api_error":response.api_error}),
    )
}
async fn fetch_step(
    root: &Path,
    source: &WikipediaSource,
    name: &str,
    operation: Operation,
    receipt: &mut Value,
    validators: Validators,
) -> Result<()> {
    if receipt["steps"].get(name).is_some() {
        return Ok(());
    }
    admitted(root).await?;
    let response = source
        .fetch(operation.clone(), validators, CancellationToken::new())
        .await?;
    cooldown(
        root,
        response
            .retry_at
            .into_iter()
            .chain(response.action_slow_until)
            .max(),
    )?;
    let mut evidence = metadata(&response)?;
    // Status/policy evidence is durable even if parsing or projection fails.
    receipt["steps"][name] = evidence.clone();
    persist(root, "receipt.json", receipt)?;
    if response.status == 200
        && response.api_error.is_none()
        && response.cache.retention_allowed()?
    {
        let value: Value = serde_json::from_slice(&response.body)
            .map_err(|_| Error::integrity("Fixed Wikipedia record returned invalid JSON."))?;
        match operation {
            Operation::ArticleHtml { .. } => {
                let html = value["html"].as_str().ok_or_else(invalid)?;
                let projection =
                    processing::process_html(html.as_bytes(), CancellationToken::new())?;
                evidence["page_id"] = value["id"].clone();
                evidence["revision_id"] = value["latest"]["id"].clone();
                evidence["license"] = value["license"].clone();
                evidence["projection"] = json!({"text_bytes":projection.text.len(),"markdown_bytes":projection.markdown.len(),"sections":projection.sections.len(),"references":projection.references.len(),"gaps":projection.gaps,"complete":!projection.text.is_empty()&&!projection.markdown.is_empty()});
            }
            Operation::ArticleSource { .. } => {
                evidence["page_id"] = value["id"].clone();
                evidence["revision_id"] = value["latest"]["id"].clone();
                evidence["license"] = value["license"].clone();
                evidence["content_model"] = value["content_model"].clone();
                evidence["wikitext_bytes"] =
                    json!(value["source"].as_str().ok_or_else(invalid)?.len());
            }
            Operation::Category { .. } => {
                evidence["members"] = json!(
                    value["query"]["categorymembers"]
                        .as_array()
                        .map(Vec::len)
                        .unwrap_or(0)
                );
                evidence["continuation_present"] = json!(value.get("continue").is_some());
            }
            Operation::CurrentAliases { .. } => {
                evidence["alias_pages"] = json!(
                    value["query"]["pages"]
                        .as_array()
                        .map(Vec::len)
                        .unwrap_or(0)
                );
                evidence["continuation_present"] = json!(value.get("continue").is_some());
            }
            Operation::Metadata { .. } => {
                evidence["pages"] = json!(
                    value["query"]["pages"]
                        .as_array()
                        .map(Vec::len)
                        .unwrap_or(0)
                );
                evidence["continuation_present"] = json!(value.get("continue").is_some());
            }
            Operation::Search { .. } => {
                evidence["matches"] = json!(value["pages"].as_array().map(Vec::len).unwrap_or(0));
            }
        }
    }
    receipt["steps"][name] = evidence;
    persist(root, "receipt.json", receipt)
}
async fn stream_step(root: &Path, source: &WikipediaSource, receipt: &mut Value) -> Result<()> {
    if receipt["steps"].get("eventstream").is_some() {
        return Ok(());
    }
    admitted(root).await?;
    receipt["steps"]["eventstream"] =
        json!({"started":true,"complete":false,"raw_events_retained":false});
    persist(root, "receipt.json", receipt)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut connection = source.stream(None, CancellationToken::new()).await?;
    cooldown(root, connection.retry_at)?;
    let mut frames = 0usize;
    let mut changes = 0usize;
    let mut resume_available = false;
    let mut parse_failed = false;
    let mut failure_code = None;
    let mut failure_stage = None;
    let mut parser = SseParser::new();
    if connection.status == 200 {
        while let Ok(Some(chunk)) =
            tokio::time::timeout_at(deadline, connection.stream.next()).await
        {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    parse_failed = true;
                    failure_code = Some(error.code);
                    failure_stage = Some("stream_transfer");
                    break;
                }
            };
            let events = match parser.push(&chunk) {
                Ok(events) => events,
                Err(error) => {
                    parse_failed = true;
                    failure_code = Some(error.code);
                    failure_stage = Some("sse_frame");
                    break;
                }
            };
            for event in events {
                frames += 1;
                changes += usize::from(event.change.is_some());
                resume_available |= event.id.is_some();
            }
        }
    }
    receipt["steps"]["eventstream"] = json!({"started":true,"status":connection.status,"retry_at":connection.retry_at,"maximum_seconds":30,"frames":frames,"english_changes":changes,"resume_available":resume_available,"parse_failed":parse_failed,"failure_code":failure_code,"failure_stage":failure_stage,"raw_events_retained":false,"complete":connection.status==200&&!parse_failed&&frames>0});
    persist(root, "receipt.json", receipt)
}
async fn steps(root: &Path, source: &WikipediaSource, receipt: &mut Value) -> Result<()> {
    for (key, title) in RECORDS {
        fetch_step(
            root,
            source,
            &format!("{key}_html"),
            Operation::ArticleHtml {
                title: title.into(),
            },
            receipt,
            Validators::default(),
        )
        .await?;
        fetch_step(
            root,
            source,
            &format!("{key}_source"),
            Operation::ArticleSource {
                title: title.into(),
            },
            receipt,
            Validators::default(),
        )
        .await?;
        let conditional = format!("{key}_conditional");
        if receipt["steps"].get(&conditional).is_none() {
            let html = &receipt["steps"][format!("{key}_html")];
            let cache: CacheMetadata =
                serde_json::from_value(html["cache"].clone()).map_err(|_| invalid())?;
            if cache.freshness_deadline()? > devres_domain::unix_now() || html["status"] != 200 {
                receipt["steps"][&conditional] = json!({"outcome":"skipped_upstream_ttl_or_unavailable","fresh_until":cache.freshness_deadline()?,"forced_early_validation":false});
                persist(root, "receipt.json", receipt)?;
            } else {
                fetch_step(
                    root,
                    source,
                    &conditional,
                    Operation::ArticleHtml {
                        title: title.into(),
                    },
                    receipt,
                    cache.validators(),
                )
                .await?;
            }
        }
    }
    fetch_step(
        root,
        source,
        "science_category",
        Operation::Category {
            title: "Category:Science".into(),
            continuation: None,
        },
        receipt,
        Validators::default(),
    )
    .await?;
    fetch_step(
        root,
        source,
        "current_aliases",
        Operation::CurrentAliases { continuation: None },
        receipt,
        Validators::default(),
    )
    .await?;
    fetch_step(
        root,
        source,
        "search",
        Operation::Search {
            query: "RISC-V".into(),
            limit: 5,
        },
        receipt,
        Validators::default(),
    )
    .await?;
    let ids: Vec<_> = RECORDS
        .iter()
        .filter_map(|(key, _)| receipt["steps"][format!("{key}_html")]["page_id"].as_u64())
        .collect();
    if !ids.is_empty() {
        fetch_step(
            root,
            source,
            "article_metadata",
            Operation::Metadata {
                titles: vec![],
                page_ids: ids,
            },
            receipt,
            Validators::default(),
        )
        .await?;
    }
    stream_step(root, source, receipt).await
}
fn accepted(receipt: &Value) -> bool {
    RECORDS.iter().all(|(key, _)| {
        let html = &receipt["steps"][format!("{key}_html")];
        let source = &receipt["steps"][format!("{key}_source")];
        html["status"] == 200
            && source["status"] == 200
            && html["page_id"].as_u64().is_some()
            && html["page_id"] == source["page_id"]
            && html["revision_id"].as_u64().is_some()
            && html["revision_id"] == source["revision_id"]
            && html["license"]["url"].as_str().is_some()
            && html["projection"]["complete"] == true
            && source["content_model"] == "wikitext"
            && source["wikitext_bytes"]
                .as_u64()
                .is_some_and(|bytes| bytes > 0)
    }) && [
        "science_category",
        "current_aliases",
        "search",
        "article_metadata",
    ]
    .iter()
    .all(|key| {
        receipt["steps"][key]["status"] == 200 && receipt["steps"][key]["api_error"].is_null()
    }) && receipt["steps"]["eventstream"]["complete"] == true
}
async fn run(path: &Path) -> Result<Value> {
    let root = root::owned_root(path, MARKER)?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(file(&root, "probe.lock")?)
        .map_err(|_| unavailable())?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .map_err(|_| Error::unavailable("Wikipedia live evidence is already in use."))?;
    let mut receipt = read(&root, "receipt.json")?.unwrap_or(json!({"version":1,"provider":"wikipedia","request_limit":20,"started_at":devres_domain::unix_now(),"steps":{},"complete":false,"evidence_boundary":"fixed records only; no full corpus, history, cluster or production acceptance"}));
    if receipt["version"] != 1
        || receipt["provider"] != "wikipedia"
        || receipt["request_limit"] != 20
        || !receipt["steps"].is_object()
        || !receipt["complete"].is_boolean()
    {
        return Err(invalid());
    }
    if receipt["complete"] == true {
        if !accepted(&receipt) {
            return Err(invalid());
        }
        return Ok(receipt);
    }
    let broker = counted_broker(&root)?;
    let source = WikipediaSource::new(broker.clone());
    if let Err(error) = steps(&root, &source, &mut receipt).await {
        receipt["failure_code"] = json!(error.code);
    }
    receipt["attempts"] = json!(broker.attempt_count());
    receipt["complete"] = json!(accepted(&receipt));
    receipt["observed_at"] = json!(devres_domain::unix_now());
    persist(&root, "receipt.json", &receipt)?;
    Ok(receipt)
}
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 || args[1] != "--live" {
        eprintln!("usage: wikipedia-live-probe --live OWNED_ROOT");
        std::process::exit(2);
    }
    match run(Path::new(&args[2])).await {
        Ok(receipt) => {
            println!("{receipt}");
            if receipt["complete"] != true {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_counter_does_not_reset_and_rejects_over_budget() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir_in("/tmp").expect("temporary");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("permissions");
        persist(
            temporary.path(),
            "attempt-state.json",
            &json!({"attempts":7,"not_before":0}),
        )
        .expect("persist");
        assert_eq!(
            counted_broker(temporary.path())
                .expect("resumed")
                .attempt_count(),
            7
        );
        persist(
            temporary.path(),
            "attempt-state.json",
            &json!({"attempts":21,"not_before":0}),
        )
        .expect("persist");
        assert!(counted_broker(temporary.path()).is_err());
    }
}
