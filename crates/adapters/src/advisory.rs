//! Immutable official RustSec snapshots and request-local lockfile analysis.

use crate::{
    archive,
    cargo::{validate_name, validate_version},
    research::{Page, capture_json, ensure_capture, list_limit, now},
};
use devres_application::Retrieval;
use devres_domain::{Capture, Error, FetchRequest, Result};
use rustsec::{Advisory, Collection, Lockfile, database::Query};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{str::FromStr, sync::Arc};
use tokio::sync::Mutex;

const HEAD_KEY: &str = "rustsec:head";
const HEAD_URL: &str = "https://api.github.com/repos/RustSec/advisory-db/commits/main";
const MAX_LOCKFILE: usize = 1024 * 1024;

pub struct Advisories {
    retrieval: Arc<Retrieval>,
    parsed: Mutex<Option<Arc<Snapshot>>>,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    head: Capture,
    bundle: Capture,
    revision: String,
    advisories: Vec<Advisory>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupInput {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub advisory_snapshot: Option<String>,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "list_limit")]
    pub limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditInput {
    pub lockfile: String,
    #[serde(default)]
    pub advisory_snapshot: Option<String>,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "list_limit")]
    pub limit: usize,
}

impl Advisories {
    pub fn new(retrieval: Arc<Retrieval>) -> Self {
        Self {
            retrieval,
            parsed: Mutex::new(None),
        }
    }

    async fn snapshot(&self, selected: Option<&str>, force: bool) -> Result<Arc<Snapshot>> {
        let head = match selected {
            Some(id) => {
                let stored = self.retrieval.read_capture(id).await?;
                ensure_capture(&stored, HEAD_KEY)?;
                stored
            }
            None => {
                self.retrieval
                    .get(FetchRequest {
                        key: HEAD_KEY.into(),
                        url: HEAD_URL.into(),
                        ttl_secs: if force { 0 } else { 86400 },
                        max_bytes: 4 * 1024 * 1024,
                        media_type: "application/json".into(),
                    })
                    .await?
            }
        };
        if now().saturating_sub(head.capture.validated_at) > 7 * 86400 {
            return Err(Error::unavailable(
                "RustSec snapshot validation is older than seven days.",
            ));
        }
        let metadata: Value = serde_json::from_slice(&head.body)
            .map_err(|_| Error::integrity("Malformed RustSec revision metadata."))?;
        let revision = metadata["sha"]
            .as_str()
            .filter(|v| {
                v.len() == 40
                    && v.bytes()
                        .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
            })
            .ok_or_else(|| Error::integrity("Invalid RustSec immutable revision."))?
            .to_owned();
        // The mutex contains public advisory metadata only, never caller packages.
        // Cancellation drops refresh work; no background task survives the caller.
        let mut parsed = self.parsed.lock().await;
        if let Some(snapshot) = parsed.as_ref()
            && snapshot.head.id == head.capture.id
            && snapshot.head.validated_at == head.capture.validated_at
        {
            return Ok(snapshot.clone());
        }
        let permit = archive::admit()?;
        let bundle = self
            .retrieval
            .get(FetchRequest {
                key: format!("rustsec:bundle:{revision}"),
                url: format!("https://codeload.github.com/RustSec/advisory-db/tar.gz/{revision}"),
                ttl_secs: 365 * 86400,
                max_bytes: archive::MAX_COMPRESSED,
                media_type: "application/gzip".into(),
            })
            .await?;
        let root = format!("advisory-db-{revision}");
        let checksum = bundle.capture.body_hash.clone();
        let bytes = bundle.body;
        let advisories = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            let files = archive::advisory_files(&bytes, &checksum, &root, deadline)?;
            parse_files(files, deadline)
        })
        .await
        .map_err(|_| Error::unavailable("RustSec parser worker failed."))??;
        let snapshot = Arc::new(Snapshot {
            head: head.capture,
            bundle: bundle.capture,
            revision,
            advisories,
        });
        *parsed = Some(snapshot.clone());
        Ok(snapshot)
    }

    /// Private administrative operation; not registered as a public MCP tool.
    pub async fn refresh(&self) -> Result<Value> {
        let snapshot = self.snapshot(None, true).await?;
        Ok(json!({"snapshot":snapshot.metadata(),"advisories":snapshot.advisories.len()}))
    }

    pub async fn lookup(&self, input: LookupInput) -> Result<Value> {
        validate_name(&input.name)?;
        let version = validate_version(&input.version)?;
        let page = Page {
            offset: input.offset,
            limit: input.limit,
        }
        .checked()?;
        let snapshot = match self
            .snapshot(input.advisory_snapshot.as_deref(), false)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) if error.code == "unavailable" => {
                return Ok(
                    json!({"complete":false,"status":"incomplete","reason":"advisory_data_unavailable_or_too_old","items":[]}),
                );
            }
            Err(error) => return Err(error),
        };
        let name = input
            .name
            .parse()
            .map_err(|_| Error::invalid("Invalid RustSec package name."))?;
        let query = Query::new()
            .collection(Collection::Crates)
            .package_name(name)
            .package_version(version)
            .package_source(rustsec::SourceId::default());
        let found = snapshot
            .advisories
            .iter()
            .filter(|advisory| query.matches(advisory))
            .collect::<Vec<_>>();
        let items = found
            .iter()
            .skip(page.offset)
            .take(page.limit)
            .map(|advisory| summary(advisory))
            .collect::<Vec<_>>();
        Ok(
            json!({"complete":true,"name":input.name,"version":input.version,"items":items,"total":found.len(),"offset":page.offset,"next_offset":next_offset(page,found.len()),"snapshot":snapshot.metadata(),"assessment_scope":"known RustSec advisories in the identified snapshot; not a safety certification"}),
        )
    }

    pub async fn search(&self, query: &str, page: Page) -> Result<Value> {
        if query.trim().is_empty() || query.len() > 256 {
            return Err(Error::invalid(
                "Advisory search query must contain 1..256 bytes.",
            ));
        }
        let page = page.checked()?;
        let snapshot = self.snapshot(None, false).await?;
        let terms = query
            .to_lowercase()
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let found = snapshot
            .advisories
            .iter()
            .filter(|advisory| {
                let text = format!(
                    "{} {} {} {}",
                    advisory.metadata.id,
                    advisory.metadata.package,
                    advisory.title(),
                    advisory.description()
                )
                .to_lowercase();
                terms.iter().all(|term| text.contains(term))
            })
            .collect::<Vec<_>>();
        Ok(
            json!({"items":found.iter().skip(page.offset).take(page.limit).map(|advisory|summary(advisory)).collect::<Vec<_>>(),"total":found.len(),"offset":page.offset,"next_offset":next_offset(page,found.len()),"snapshot":snapshot.metadata()}),
        )
    }

    pub async fn audit(&self, input: AuditInput) -> Result<Value> {
        if input.lockfile.len() > MAX_LOCKFILE {
            return Err(Error::invalid(
                "Cargo.lock must contain at most 1048576 UTF-8 bytes.",
            ));
        }
        let page = Page {
            offset: input.offset,
            limit: input.limit,
        }
        .checked()?;
        let snapshot = match self
            .snapshot(input.advisory_snapshot.as_deref(), false)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) if error.code == "unavailable" => {
                return Ok(
                    json!({"complete":false,"status":"incomplete","reason":"advisory_data_unavailable_or_too_old","findings":[],"input_retention":"request_lifetime_only"}),
                );
            }
            Err(error) => return Err(error),
        };
        run_worker(&input.lockfile, &snapshot, page).await
    }
}

fn next_offset(page: Page, total: usize) -> Option<usize> {
    let next = page.offset.saturating_add(page.limit);
    if next < total { Some(next) } else { None }
}

impl Snapshot {
    fn metadata(&self) -> Value {
        json!({"id":self.head.id,"revision":self.revision,"validated_at":self.head.validated_at,"stale":now().saturating_sub(self.head.validated_at)>86400,"head_capture":capture_json(&self.head,86400),"bundle_capture":capture_json(&self.bundle,365*86400),"source_url":format!("https://github.com/RustSec/advisory-db/tree/{}",self.revision),"license_notice":"RustSec CC0-1.0, except explicitly attributed imported GHSA content under CC-BY-4.0; each advisory retains its license and URL."})
    }
}

fn parse_files(
    files: Vec<(String, Vec<u8>)>,
    deadline: std::time::Instant,
) -> Result<Vec<Advisory>> {
    if files.is_empty() {
        return Err(Error::integrity("Empty RustSec advisory snapshot."));
    }
    let mut advisories = Vec::new();
    let mut ids = std::collections::HashSet::new();
    for (path, body) in files {
        if std::time::Instant::now() >= deadline {
            return Err(Error::capacity("RustSec parser time budget exceeded."));
        }
        let text = std::str::from_utf8(&body)
            .map_err(|_| Error::integrity("RustSec advisory Markdown is not UTF-8."))?;
        let mut advisory = Advisory::from_str(text).map_err(|_| {
            Error::integrity("RustSec advisory does not match the supported schema.")
        })?;
        advisory.metadata.collection = Some(Collection::Crates);
        let parts = path.split('/').collect::<Vec<_>>();
        if parts.len() != 3
            || advisory.metadata.package.as_str() != parts[1]
            || format!("{}.md", advisory.metadata.id) != parts[2]
            || !ids.insert(advisory.metadata.id.to_string())
        {
            return Err(Error::integrity(
                "RustSec advisory path, identity, or uniqueness mismatch.",
            ));
        }
        advisories.push(advisory);
    }
    advisories.sort_by(|a, b| a.metadata.id.cmp(&b.metadata.id));
    Ok(advisories)
}

fn parse_lockfile(text: &str) -> Result<Lockfile> {
    if text.is_empty() || text.len() > MAX_LOCKFILE {
        return Err(Error::invalid(
            "Cargo.lock must contain 1..1048576 UTF-8 bytes.",
        ));
    }
    let lockfile = Lockfile::from_str(text).map_err(|_| {
        Error::invalid("Malformed or unsupported Cargo.lock; input details are not logged.")
    })?;
    if lockfile.packages.len() > 10_000 {
        return Err(Error::capacity("Cargo.lock exceeds 10000 packages."));
    }
    Ok(lockfile)
}

const MAX_WORKER_INPUT: usize = 128 * 1024 * 1024;
const MAX_WORKER_OUTPUT: usize = 256 * 1024;

#[derive(Serialize)]
struct WorkerRequestRef<'a> {
    lockfile: &'a str,
    snapshot: &'a Snapshot,
    page: Page,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerRequest {
    lockfile: String,
    snapshot: Snapshot,
    page: Page,
}

struct BoundedBytes {
    bytes: Vec<u8>,
    maximum: usize,
}
impl std::io::Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other(
                "bounded analysis message exceeds limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn run_worker(lockfile: &str, snapshot: &Snapshot, page: Page) -> Result<Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _permit = archive::admit()?;
    let mut input = BoundedBytes {
        bytes: Vec::new(),
        maximum: MAX_WORKER_INPUT,
    };
    serde_json::to_writer(
        &mut input,
        &WorkerRequestRef {
            lockfile,
            snapshot,
            page,
        },
    )
    .map_err(|_| Error::capacity("Audit worker input exceeds its bounded message size."))?;
    let executable = std::env::current_exe()
        .map_err(|_| Error::unavailable("Audit worker location unavailable."))?;
    let executable = executable
        .parent()
        .ok_or_else(|| Error::unavailable("Audit worker location unavailable."))?
        .join("devres-audit-worker");
    let mut child = tokio::process::Command::new(executable)
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| {
            Error::unavailable("Audit worker could not start; install the matching sibling binary.")
        })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::unavailable("Audit worker input unavailable."))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::unavailable("Audit worker output unavailable."))?;
    let operation = async {
        // No detached I/O task: dropping this future drops stdin and kills child.
        stdin
            .write_all(&input.bytes)
            .await
            .map_err(|_| Error::unavailable("Audit worker input failed."))?;
        stdin
            .shutdown()
            .await
            .map_err(|_| Error::unavailable("Audit worker input failed."))?;
        drop(stdin);
        let mut output = Vec::new();
        stdout
            .take(MAX_WORKER_OUTPUT as u64 + 1)
            .read_to_end(&mut output)
            .await
            .map_err(|_| Error::unavailable("Audit worker output failed."))?;
        if output.len() > MAX_WORKER_OUTPUT {
            return Err(Error::capacity("Audit worker output exceeds 256 KiB."));
        }
        let status = child
            .wait()
            .await
            .map_err(|_| Error::unavailable("Audit worker wait failed."))?;
        if !status.success() {
            return Err(Error::unavailable("Audit worker failed."));
        }
        let result: Result<Value> = serde_json::from_slice(&output)
            .map_err(|_| Error::integrity("Audit worker returned an invalid result."))?;
        result
    };
    tokio::time::timeout(std::time::Duration::from_secs(15), operation)
        .await
        .map_err(|_| Error::capacity("Audit worker deadline exceeded."))?
}

/// Entry point for the fixed sibling executable. It has no network/storage path,
/// receives no inherited credentials, and never writes submitted bytes to stderr.
pub fn audit_worker_main() -> std::io::Result<()> {
    use std::io::{Read, Write};
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_WORKER_INPUT as u64 + 1)
        .read_to_end(&mut bytes)?;
    let result: Result<Value> = if bytes.len() > MAX_WORKER_INPUT {
        Err(Error::capacity("Audit worker input exceeds limit."))
    } else {
        serde_json::from_slice::<WorkerRequest>(&bytes)
            .map_err(|_| Error::invalid("Invalid audit worker request."))
            .and_then(|request| {
                let page = request.page.checked()?;
                if request.snapshot.advisories.is_empty()
                    || now().saturating_sub(request.snapshot.head.validated_at) > 7 * 86400
                {
                    return Err(Error::unavailable(
                        "RustSec snapshot is missing or too old.",
                    ));
                }
                let lockfile = parse_lockfile(&request.lockfile)?;
                audit_with_snapshot(&lockfile, &request.snapshot, page)
            })
    };
    let mut output = BoundedBytes {
        bytes: Vec::new(),
        maximum: MAX_WORKER_OUTPUT,
    };
    if serde_json::to_writer(&mut output, &result).is_err() {
        output.bytes.clear();
        let error: Result<Value> = Err(Error::capacity(
            "Audit result exceeds 256 KiB; reduce the page limit.",
        ));
        serde_json::to_writer(&mut output, &error).map_err(std::io::Error::other)?;
    }
    std::io::stdout().lock().write_all(&output.bytes)
}

fn summary(advisory: &Advisory) -> Value {
    let classification = if advisory.withdrawn() {
        "withdrawn"
    } else if advisory.metadata.informational.is_some() {
        "informational"
    } else {
        "vulnerability"
    };
    json!({"id":advisory.metadata.id,"package":advisory.metadata.package,"title":advisory.title().chars().take(1024).collect::<String>(),"classification":classification,"date":advisory.metadata.date,"withdrawn":advisory.metadata.withdrawn,"informational":advisory.metadata.informational,"aliases":advisory.metadata.aliases,"patched":advisory.versions.patched(),"unaffected":advisory.versions.unaffected(),"url":format!("https://rustsec.org/advisories/{}.html",advisory.metadata.id),"attribution_url":advisory.metadata.url,"license":advisory.metadata.license})
}

/// Count the complete bounded assessment while materializing only its requested
/// page. A duplicated lockfile entry must not multiply retained JSON reports.
struct FindingPage {
    page: Page,
    total: usize,
    values: Vec<Value>,
    remaining_bytes: usize,
}
impl FindingPage {
    fn new(page: Page) -> Self {
        Self {
            page,
            total: 0,
            values: Vec::with_capacity(page.limit),
            remaining_bytes: MAX_WORKER_OUTPUT - 4096,
        }
    }
    fn record(&mut self, make: impl FnOnce() -> Value) -> Result<()> {
        if self.total >= 50_000 {
            return Err(Error::capacity("Audit exceeds 50000 findings."));
        }
        if self.total >= self.page.offset && self.values.len() < self.page.limit {
            let finding = make();
            // Count serialization without allocating a second copy, and leave
            // space for the envelope. Retained JSON is page-count and byte bounded.
            struct Counter(usize);
            impl std::io::Write for Counter {
                fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                    self.0 = self
                        .0
                        .checked_sub(bytes.len())
                        .ok_or_else(|| std::io::Error::other("audit page exceeds limit"))?;
                    Ok(bytes.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let mut counter = Counter(self.remaining_bytes);
            serde_json::to_writer(&mut counter, &finding).map_err(|_| {
                Error::capacity("Audit page exceeds 256 KiB; reduce the page limit.")
            })?;
            self.remaining_bytes = counter.0.saturating_sub(1);
            self.values.push(finding);
        }
        self.total += 1;
        Ok(())
    }
}

fn audit_with_snapshot(lockfile: &Lockfile, snapshot: &Snapshot, page: Page) -> Result<Value> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut findings = FindingPage::new(page);
    let mut assessed = 0usize;
    let mut unassessed = 0usize;
    let mut vulnerabilities = 0usize;
    let mut informational = 0usize;
    let mut withdrawn = 0usize;
    // Index public advisories by package to avoid package*database unbounded work.
    let mut index = std::collections::HashMap::<&str, Vec<&Advisory>>::new();
    for advisory in &snapshot.advisories {
        index
            .entry(advisory.metadata.package.as_str())
            .or_default()
            .push(advisory);
    }
    for package in &lockfile.packages {
        if std::time::Instant::now() >= deadline {
            return Err(Error::capacity("Audit time budget exceeded."));
        }
        if package
            .source
            .as_ref()
            .is_none_or(|source| !source.is_default_registry())
        {
            unassessed += 1;
            findings.record(||json!({"package":package.name,"version":package.version,"classification":"unassessed","reason":"path_git_or_alternative_registry"}))?;
            continue;
        }
        assessed += 1;
        let query = Query::new()
            .collection(Collection::Crates)
            .package(package)
            .package_source(rustsec::SourceId::default());
        for advisory in index
            .get(package.name.as_str())
            .into_iter()
            .flatten()
            .filter(|advisory| query.matches(advisory))
        {
            if std::time::Instant::now() >= deadline {
                return Err(Error::capacity("Audit time budget exceeded."));
            }
            if advisory.withdrawn() {
                withdrawn += 1;
            } else if advisory.metadata.informational.is_some() {
                informational += 1;
            } else {
                vulnerabilities += 1;
            }
            findings.record(||json!({"package":package.name,"version":package.version,"advisory":summary(advisory)}))?;
        }
    }
    let stale = now().saturating_sub(snapshot.head.validated_at) > 86400;
    let complete = unassessed == 0;
    let status = if vulnerabilities > 0 {
        "known_vulnerabilities"
    } else if !complete {
        "incomplete"
    } else if stale {
        "no_known_vulnerabilities_in_stale_snapshot"
    } else {
        "no_known_vulnerabilities_in_snapshot"
    };
    let total = findings.total;
    Ok(
        json!({"complete":complete,"status":status,"package_count":lockfile.packages.len(),"assessed_count":assessed,"unassessed_count":unassessed,"vulnerability_count":vulnerabilities,"informational_count":informational,"withdrawn_count":withdrawn,"findings":findings.values,"total_findings":total,"offset":page.offset,"next_offset":next_offset(page,total),"snapshot":snapshot.metadata(),"input_retention":"request_lifetime_only","assessment_scope":"known advisories for crates.io entries; no dependency resolution, package execution, or safety certification"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn advisory(withdrawn: bool, informational: bool) -> Advisory {
        let fields = format!(
            "{}{}",
            if withdrawn {
                "withdrawn = \"2024-01-02\"\n"
            } else {
                ""
            },
            if informational {
                "informational = \"unmaintained\"\n"
            } else {
                ""
            }
        );
        let text = format!(
            "```toml\n[advisory]\nid = \"RUSTSEC-2024-0001\"\npackage = \"example\"\ndate = \"2024-01-01\"\n{fields}\n[versions]\npatched = [\">= 1.0.1\"]\n```\n\n# Test advisory\n\nSynthetic fixture only.\n"
        );
        let mut advisory: Advisory = text.parse().unwrap();
        advisory.metadata.collection = Some(Collection::Crates);
        advisory
    }
    fn snapshot(advisories: Vec<Advisory>) -> Snapshot {
        let capture = Capture {
            id: "a".repeat(64),
            key: HEAD_KEY.into(),
            source_url: HEAD_URL.into(),
            body_hash: "b".repeat(64),
            media_type: "application/json".into(),
            retrieved_at: now(),
            validated_at: now(),
        };
        Snapshot {
            head: capture.clone(),
            bundle: capture,
            revision: "c".repeat(40),
            advisories,
        }
    }
    #[test]
    fn canonical_matching_excludes_patched_and_classifies_withdrawn() {
        let vulnerable = advisory(false, false);
        assert!(vulnerable.versions.is_vulnerable(&"1.0.0".parse().unwrap()));
        assert!(!vulnerable.versions.is_vulnerable(&"1.0.1".parse().unwrap()));
        assert_eq!(
            summary(&advisory(true, false))["classification"],
            "withdrawn"
        );
        assert_eq!(
            summary(&advisory(false, true))["classification"],
            "informational"
        );
    }
    #[test]
    fn audits_only_registry_entries_and_never_persists_input() {
        let text = "version = 4\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n[[package]]\nname = \"private-project\"\nversion = \"1.0.0\"\n";
        let lockfile = parse_lockfile(text).unwrap();
        let result = audit_with_snapshot(
            &lockfile,
            &snapshot(vec![advisory(false, false)]),
            Page::default(),
        )
        .unwrap();
        assert_eq!(result["vulnerability_count"], 1);
        assert_eq!(result["assessed_count"], 1);
        assert_eq!(result["unassessed_count"], 1);
        assert_eq!(result["complete"], false);
        assert_eq!(result["input_retention"], "request_lifetime_only");
        assert!(result.get("lockfile").is_none());
    }
    #[test]
    fn parse_errors_do_not_echo_private_input() {
        let error = parse_lockfile("private-secret = not valid toml").unwrap_err();
        assert!(!error.to_string().contains("private-secret"));
        assert!(parse_lockfile(&"a".repeat(MAX_LOCKFILE + 1)).is_err());
    }

    #[test]
    fn duplicate_lockfile_rows_keep_totals_and_order_across_bounded_pages() {
        let entry = "[[package]]\nname=\"example\"\nversion=\"1.0.0\"\nsource=\"sparse+https://index.crates.io/\"\n";
        let text = format!("version=4\n{}", entry.repeat(5000));
        let lockfile = parse_lockfile(&text).unwrap();
        // cargo-lock accepts duplicate package rows; this is a reachable input,
        // not a synthetic Lockfile that its public parser would reject.
        assert_eq!(lockfile.packages.len(), 5000);
        let mut informative = advisory(false, true);
        informative.metadata.id = "RUSTSEC-2024-0002".parse().unwrap();
        let mut withdrawn = advisory(true, false);
        withdrawn.metadata.id = "RUSTSEC-2024-0003".parse().unwrap();
        let snapshot = snapshot(vec![advisory(false, false), informative, withdrawn]);
        for (offset, expected_len, next) in [(0, 4, Some(4)), (14998, 2, None), (15000, 0, None)] {
            let result =
                audit_with_snapshot(&lockfile, &snapshot, Page { offset, limit: 4 }).unwrap();
            assert_eq!(result["total_findings"], 15000);
            assert_eq!(result["vulnerability_count"], 5000);
            assert_eq!(result["informational_count"], 5000);
            assert_eq!(result["withdrawn_count"], 5000);
            assert_eq!(result["findings"].as_array().unwrap().len(), expected_len);
            assert_eq!(result["next_offset"], json!(next));
            if offset == 0 {
                assert_eq!(result["findings"][0]["advisory"]["id"], "RUSTSEC-2024-0001");
                assert_eq!(result["findings"][3]["advisory"]["id"], "RUSTSEC-2024-0001");
            } else if offset == 14998 {
                assert_eq!(result["findings"][0]["advisory"]["id"], "RUSTSEC-2024-0002");
                assert_eq!(result["findings"][1]["advisory"]["id"], "RUSTSEC-2024-0003");
            }
        }
        let patched =
            parse_lockfile(&text.replace("version=\"1.0.0\"", "version=\"1.0.1\"")).unwrap();
        let empty = audit_with_snapshot(&patched, &snapshot, Page::default()).unwrap();
        assert_eq!(empty["total_findings"], 0);
        assert!(empty["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn finding_pages_materialize_only_selected_rows_and_enforce_byte_budget() {
        let mut page = FindingPage::new(Page {
            offset: 49996,
            limit: 4,
        });
        let mut materialized = 0;
        for ordinal in 0..50_000 {
            page.record(|| {
                materialized += 1;
                json!({"ordinal":ordinal})
            })
            .unwrap();
        }
        assert_eq!(materialized, 4);
        assert_eq!(page.total, 50_000);
        assert_eq!(page.values.len(), 4);
        assert_eq!(page.values[0]["ordinal"], 49996);
        assert!(
            page.record(|| panic!("Beyond-ceiling finding must not be materialized"))
                .is_err()
        );
        let mut oversized = FindingPage::new(Page::default());
        assert!(
            oversized
                .record(|| json!({"large":"x".repeat(MAX_WORKER_OUTPUT)}))
                .is_err()
        );
        assert!(oversized.values.is_empty());
    }
}
