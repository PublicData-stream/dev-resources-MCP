//! Public OSV npm normalization and isolated, request-only lockfile assessment.
use crate::npm::lockfile::{self as npm_lockfile, Inventory, RegistryContext};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

const MAX_WORKER_INPUT: usize = 128 * 1024 * 1024;
const MAX_WORKER_OUTPUT: usize = 256 * 1024;
const MAX_FINDINGS: usize = 50_000;
const MAX_RECORD_ITEMS: usize = 10_000;
static AUDIT_REQUESTS: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(2)));

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditInput {
    lockfile: String,
    lockfile_format: String,
    #[serde(default)]
    advisory_snapshot: Option<String>,
    #[serde(default)]
    registry_context: RegistryContext,
    #[serde(default)]
    offset: usize,
    #[serde(default = "twenty")]
    limit: usize,
}
fn twenty() -> usize {
    20
}
impl AuditInput {
    fn validate(&self) -> Result<()> {
        if self.lockfile.is_empty() || self.lockfile.len() > npm_lockfile::MAX_LOCKFILE {
            return Err(Error::invalid(
                "npm lockfile must contain 1..1048576 UTF-8 bytes.",
            ));
        }
        if !matches!(
            self.lockfile_format.as_str(),
            "npm" | "pnpm" | "yarn_classic" | "yarn_berry"
        ) || self.limit == 0
            || self.limit > 100
            || self.offset > MAX_FINDINGS
            || self.advisory_snapshot.as_ref().is_some_and(|id| {
                id.len() != 64
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(Error::invalid(
                "Invalid npm audit format, snapshot, or page.",
            ));
        }
        self.registry_context.validate()
    }
    fn inventory(&self) -> Result<Inventory> {
        npm_lockfile::parse(
            &self.lockfile,
            &self.lockfile_format,
            &self.registry_context,
        )
    }
}

pub fn schemas() -> Vec<Value> {
    vec![
        json!({"name":"npm.audit_lockfile","description":"Locally assess a supplied npm, pnpm, or Yarn lockfile against captured OSV npm evidence. Input, inventory, and report exist only for the request; no resolution, package execution, uploads, or enrollment occurs.","inputSchema":{"type":"object","additionalProperties":false,"properties":{
        "lockfile":{"type":"string","minLength":1,"maxLength":1048576},
        "lockfile_format":{"enum":["npm","pnpm","yarn_classic","yarn_berry"]},
        "advisory_snapshot":{"type":"string","pattern":"^[a-f0-9]{64}$"},
        "registry_context":{"type":"object","additionalProperties":false,"properties":{"default":{"enum":["npmjs","other","unknown"]},"scopes":{"type":"object","maxProperties":1000,"propertyNames":{"pattern":"^@[A-Za-z0-9][A-Za-z0-9._~-]*$"},"additionalProperties":{"enum":["npmjs","other","unknown"]}}}},
        "offset":{"type":"integer","minimum":0,"maximum":50000},"limit":{"type":"integer","minimum":1,"maximum":100}
    },"required":["lockfile","lockfile_format"]},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
    ]
}

/// Public-source evidence only; original JSON is never a supplied lockfile.
pub fn parse_advisory(bytes: &[u8]) -> Result<Value> {
    let original = npm_lockfile::bounded_json(bytes).map_err(|error| {
        if error.code == "capacity" {
            Error::capacity("npm OSV record exceeds processing bounds.")
        } else {
            Error::integrity("Malformed or unsupported npm OSV record.")
        }
    })?;
    let id = original["id"]
        .as_str()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 256
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
        .ok_or_else(|| Error::integrity("Invalid npm OSV record identity."))?;
    let affected = original["affected"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 1024)
        .ok_or_else(|| Error::integrity("Invalid npm OSV affected inventory."))?;
    let mut packages = BTreeSet::new();
    for entry in affected {
        if entry.pointer("/package/ecosystem").and_then(Value::as_str) == Some("npm") {
            if let Some(name) = entry
                .pointer("/package/name")
                .and_then(Value::as_str)
                .filter(|name| *name == "*" || npm_lockfile::valid_name(name))
            {
                packages.insert(name.to_owned());
            } else {
                return Err(Error::integrity("Invalid npm OSV package identity."));
            }
        }
    }
    if packages.is_empty() {
        return Err(Error::integrity("OSV record contains no npm package."));
    }
    let mut matching_complete = schema_known(&original) && metadata_known(&original);
    for name in &packages {
        matching_complete &= match_record(
            &original,
            if name == "*" {
                "npm-global-probe"
            } else {
                name
            },
            "0.0.0",
        )?["complete"]
            == true;
    }
    let (license, attribution) = if id.starts_with("GHSA-") {
        (
            Some("CC-BY-4.0"),
            Some(format!("https://github.com/advisories/{id}")),
        )
    } else if id.starts_with("MAL-") {
        (
            Some("Apache-2.0"),
            Some("https://github.com/ossf/malicious-packages".to_owned()),
        )
    } else {
        (None, None)
    };
    Ok(
        json!({"id":id,"packages":packages,"classification":classification(&original),"matching_complete":matching_complete,"license":license,"attribution_url":attribution,"rights_gap":license.is_none(),"original":original}),
    )
}
fn original(value: &Value) -> &Value {
    value.get("original").unwrap_or(value)
}
fn schema_known(value: &Value) -> bool {
    value.get("schema_version").is_none_or(|v| {
        v.as_str()
            .and_then(|v| semver::Version::parse(v).ok())
            .is_some_and(|v| v.major == 1)
    })
}
fn metadata_known(value: &Value) -> bool {
    value
        .get("modified")
        .and_then(Value::as_str)
        .is_some_and(timestamp)
        && ["published", "withdrawn"].iter().all(|key| {
            value
                .get(*key)
                .is_none_or(|v| v.is_null() || v.as_str().is_some_and(timestamp))
        })
        && value.get("aliases").is_none_or(|aliases| {
            aliases.as_array().is_some_and(|items| {
                items.len() <= MAX_RECORD_ITEMS
                    && items
                        .iter()
                        .all(|v| v.as_str().is_some_and(|v| !v.is_empty() && v.len() <= 1024))
            })
        })
        && ["summary", "details"]
            .iter()
            .all(|key| value.get(*key).is_none_or(Value::is_string))
        && value
            .get("database_specific")
            .is_none_or(informational_known)
}
fn informational_known(value: &Value) -> bool {
    value.is_object()
        && value.get("informational").is_none_or(|v| {
            v.is_null() || v.as_str().is_some_and(|v| !v.is_empty() && v.len() <= 256)
        })
}
fn timestamp(value: &str) -> bool {
    // RFC3339 shape and calendar checks; avoid accepting arbitrary strings as
    // withdrawal/validation evidence. No dates are inferred from import time.
    let bytes = value.as_bytes();
    if !value.is_ascii()
        || bytes.len() < 20
        || bytes.len() > 128
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    let number = |start: usize, end: usize| {
        value
            .get(start..end)
            .filter(|p| p.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|p| p.parse::<u32>().ok())
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 60 {
        return false;
    }
    let mut end = 19;
    if bytes.get(end) == Some(&b'.') {
        end += 1;
        let start = end;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if start == end {
            return false;
        }
    }
    match bytes.get(end) {
        Some(b'Z' | b'z') => end + 1 == bytes.len(),
        Some(b'+' | b'-') => {
            end + 6 == bytes.len()
                && bytes[end + 3] == b':'
                && number(end + 1, end + 3).is_some_and(|v| v <= 23)
                && number(end + 4, end + 6).is_some_and(|v| v <= 59)
        }
        _ => false,
    }
}
fn classification(value: &Value) -> &'static str {
    let value = original(value);
    if value.get("withdrawn").is_some_and(|v| !v.is_null()) {
        "withdrawn"
    } else if value["id"]
        .as_str()
        .is_some_and(|id| id.starts_with("MAL-"))
    {
        "malicious"
    } else if value
        .pointer("/database_specific/informational")
        .is_some_and(|v| !v.is_null() && v != false)
    {
        "informational"
    } else {
        "vulnerability"
    }
}

#[derive(Clone, Copy)]
struct Match {
    matched: bool,
    complete: bool,
}
impl Match {
    fn incomplete() -> Self {
        Self {
            matched: false,
            complete: false,
        }
    }
}

/// Match supported npm constraints, retaining unsupported constraints as gaps.
pub fn match_record(record: &Value, name: &str, version: &str) -> Result<Value> {
    let record = original(record);
    let version = npm_lockfile::version(version)
        .ok_or_else(|| Error::invalid("Invalid exact npm version."))?;
    let mut result = Match {
        matched: false,
        complete: schema_known(record) && metadata_known(record),
    };
    let Some(affected) = record["affected"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 1024)
    else {
        return Ok(json!({"matched":false,"complete":false}));
    };
    for entry in affected {
        let Some(package) = entry["package"].as_object() else {
            result.complete = false;
            continue;
        };
        if package.get("ecosystem").and_then(Value::as_str) != Some("npm") {
            continue;
        }
        let Some(package_name) = package.get("name").and_then(Value::as_str) else {
            result.complete = false;
            continue;
        };
        if package_name != name && package_name != "*" {
            continue;
        }
        let matched = match_entry(entry, &version);
        result.matched |= matched.matched;
        result.complete &= matched.complete;
    }
    Ok(
        json!({"matched":result.matched,"complete":result.complete,"id":record["id"],"classification":classification(record)}),
    )
}
fn match_entry(entry: &Value, version: &semver::Version) -> Match {
    let mut result = Match {
        matched: false,
        complete: true,
    };
    let mut constraints = false;
    if let Some(versions) = entry.get("versions") {
        if let Some(versions) = versions.as_array().filter(|v| v.len() <= MAX_RECORD_ITEMS) {
            constraints |= !versions.is_empty();
            for candidate in versions {
                if let Some(candidate) = candidate.as_str().and_then(npm_lockfile::version) {
                    result.matched |= candidate.cmp_precedence(version) == Ordering::Equal;
                } else {
                    result.complete = false;
                }
            }
        } else {
            result.complete = false;
        }
    }
    if let Some(ranges) = entry.get("ranges") {
        if let Some(ranges) = ranges.as_array().filter(|v| v.len() <= MAX_RECORD_ITEMS) {
            constraints |= !ranges.is_empty();
            for range in ranges {
                if !matches!(range["type"].as_str(), Some("SEMVER" | "ECOSYSTEM")) {
                    result.complete = false;
                    continue;
                }
                let matched = match_range(range, version);
                result.matched |= matched.matched;
                result.complete &= matched.complete;
            }
        } else {
            result.complete = false;
        }
    }
    // Unknown applicability restrictions cannot produce a complete assessment.
    if entry
        .get("ecosystem_specific")
        .is_some_and(|v| !v.is_object())
        || entry
            .pointer("/ecosystem_specific/affects")
            .is_some_and(|v| !v.is_null())
        || entry
            .get("database_specific")
            .is_some_and(|v| !informational_known(v))
    {
        result.complete = false;
    }
    result.complete &= constraints;
    result
}
fn match_range(range: &Value, version: &semver::Version) -> Match {
    let Some(events) = range["events"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= MAX_RECORD_ITEMS)
    else {
        return Match::incomplete();
    };
    let mut timeline = Vec::<(Option<semver::Version>, u8)>::new();
    let mut introduced = false;
    let mut fixed = false;
    let mut last = false;
    let mut limited = false;
    let mut before_limit = false;
    for event in events {
        let Some(fields) = event.as_object().filter(|v| v.len() == 1) else {
            return Match::incomplete();
        };
        let Some((kind, raw)) = fields.iter().next() else {
            return Match::incomplete();
        };
        let Some(raw) = raw.as_str() else {
            return Match::incomplete();
        };
        if kind == "introduced" && raw == "0" {
            timeline.push((None, 0));
            introduced = true;
            continue;
        }
        if kind == "limit" && raw == "*" {
            limited = true;
            before_limit = true;
            continue;
        }
        let Some(boundary) = npm_lockfile::version(raw) else {
            return Match::incomplete();
        };
        match kind.as_str() {
            "introduced" => {
                introduced = true;
                timeline.push((Some(boundary), 0));
            }
            "fixed" => {
                fixed = true;
                timeline.push((Some(boundary), 1));
            }
            "last_affected" => {
                last = true;
                timeline.push((Some(boundary), 2));
            }
            "limit" => {
                limited = true;
                before_limit |= version.cmp_precedence(&boundary) == Ordering::Less;
            }
            _ => return Match::incomplete(),
        }
    }
    if !introduced || fixed && last {
        return Match::incomplete();
    }
    let cmp = |a: &Option<semver::Version>, b: &Option<semver::Version>| match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(a), Some(b)) => a.cmp_precedence(b),
    };
    timeline.sort_by(|a, b| cmp(&a.0, &b.0).then(a.1.cmp(&b.1)));
    let mut open = false;
    let mut start = 0;
    while start < timeline.len() {
        let mut end = start + 1;
        while end < timeline.len() && cmp(&timeline[start].0, &timeline[end].0) == Ordering::Equal {
            end += 1;
        }
        let group = &timeline[start..end];
        let introductions = group.iter().filter(|(_, kind)| *kind == 0).count();
        let fixes = group.iter().filter(|(_, kind)| *kind == 1).count();
        if introductions > 0 && fixes > 0 && fixes != introductions + usize::from(open) {
            return Match::incomplete();
        }
        if introductions > 0 {
            open = true;
        }
        if group.iter().any(|(_, kind)| *kind != 0) {
            open = false;
        }
        start = end;
    }
    let mut matched = false;
    for (boundary, kind) in timeline {
        let order = boundary.as_ref().map_or(Ordering::Greater, |boundary| {
            version.cmp_precedence(boundary)
        });
        match kind {
            0 if order != Ordering::Less => matched = true,
            1 if order != Ordering::Less => matched = false,
            2 if order == Ordering::Greater => matched = false,
            _ => {}
        }
    }
    Match {
        matched: matched && (!limited || before_limit),
        complete: true,
    }
}

/// Parent-side orchestration never parses the submitted document or stores its
/// graph. Phase one returns bounded names; only public advisory evidence is read.
pub async fn audit(input: Value, corpus: Arc<crate::npm::corpus::NpmCorpus>) -> Result<Value> {
    let input: AuditInput = serde_json::from_value(input)
        .map_err(|_| Error::invalid("Arguments do not match the npm audit schema."))?;
    input.validate()?;
    // Retain admission across BOTH worker phases and the intervening public
    // evidence read, so many callers cannot each stage a maximum-size snapshot.
    let _request = AUDIT_REQUESTS
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::capacity("npm audit request capacity exhausted."))?;
    let inventory = run_worker("inventory", &input, None).await?;
    let names: Vec<String> = serde_json::from_value(inventory["names"].clone())
        .map_err(|_| Error::integrity("Invalid npm audit inventory response."))?;
    if names.len() > 10_000 || names.iter().any(|name| !npm_lockfile::valid_name(name)) {
        return Err(Error::integrity("Invalid npm audit candidate inventory."));
    }
    let snapshot = match corpus
        .advisory_snapshot_for_names(input.advisory_snapshot.as_deref(), &names)
        .await
    {
        Ok(snapshot) => snapshot,
        Err(error) if error.code == "unavailable" => {
            json!({"snapshot":null,"records":[],"complete":false,"reason":"advisory_data_unavailable_or_too_old"})
        }
        Err(error) => return Err(error),
    };
    run_worker("audit", &input, Some(&snapshot)).await
}

struct BoundedBytes {
    bytes: Vec<u8>,
    maximum: usize,
}
impl std::io::Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("bounded npm analysis message"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
async fn run_worker(phase: &str, input: &AuditInput, snapshot: Option<&Value>) -> Result<Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _permit = crate::archive::admit()?;
    let mut message = BoundedBytes {
        bytes: Vec::new(),
        maximum: MAX_WORKER_INPUT,
    };
    #[derive(Serialize)]
    struct Request<'a> {
        operation: &'static str,
        phase: &'a str,
        input: &'a AuditInput,
        snapshot: Option<&'a Value>,
    }
    serde_json::to_writer(
        &mut message,
        &Request {
            operation: "npm",
            phase,
            input,
            snapshot,
        },
    )
    .map_err(|_| Error::capacity("npm audit evidence exceeds the worker message bound."))?;
    let executable = std::env::current_exe()
        .map_err(|_| Error::unavailable("npm audit worker location unavailable."))?;
    let executable = executable
        .parent()
        .ok_or_else(|| Error::unavailable("npm audit worker location unavailable."))?
        .join("devres-audit-worker");
    let mut child = tokio::process::Command::new(executable)
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| {
            Error::unavailable(
                "npm audit worker could not start; install the matching sibling binary.",
            )
        })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::unavailable("npm audit worker input unavailable."))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::unavailable("npm audit worker output unavailable."))?;
    let operation = async {
        stdin
            .write_all(&message.bytes)
            .await
            .map_err(|_| Error::unavailable("npm audit worker input failed."))?;
        stdin
            .shutdown()
            .await
            .map_err(|_| Error::unavailable("npm audit worker input failed."))?;
        drop(stdin);
        let mut bytes = Vec::new();
        stdout
            .take(MAX_WORKER_OUTPUT as u64 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| Error::unavailable("npm audit worker output failed."))?;
        if bytes.len() > MAX_WORKER_OUTPUT {
            return Err(Error::capacity("npm audit worker output exceeds 256 KiB."));
        }
        if !child
            .wait()
            .await
            .map_err(|_| Error::unavailable("npm audit worker wait failed."))?
            .success()
        {
            return Err(Error::unavailable("npm audit worker failed."));
        }
        serde_json::from_slice::<Result<Value>>(&bytes)
            .map_err(|_| Error::integrity("Invalid npm audit worker response."))?
    };
    tokio::time::timeout(Duration::from_secs(15), operation)
        .await
        .map_err(|_| Error::capacity("npm audit worker deadline exceeded."))?
}

/// Called only from the fixed private helper after its bounded stdin read.
pub(crate) fn worker_request(value: Value) -> Result<Value> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        operation: String,
        phase: String,
        input: AuditInput,
        #[serde(default)]
        snapshot: Option<Value>,
    }
    let request: Request = serde_json::from_value(value)
        .map_err(|_| Error::invalid("Invalid npm audit worker request."))?;
    if request.operation != "npm" {
        return Err(Error::invalid("Invalid npm audit worker operation."));
    }
    request.input.validate()?;
    let inventory = request.input.inventory()?;
    match request.phase.as_str() {
        "inventory" => {
            let names: BTreeSet<_> = inventory
                .entries
                .iter()
                .filter(|entry| entry.reason.is_none())
                .map(|entry| entry.name.clone())
                .collect();
            Ok(json!({"names":names,"format_version":inventory.format_version}))
        }
        "audit" => assess(
            &request.input,
            inventory,
            request
                .snapshot
                .as_ref()
                .ok_or_else(|| Error::invalid("npm audit snapshot is required."))?,
        ),
        _ => Err(Error::invalid("Invalid npm audit worker phase.")),
    }
}

struct Findings {
    items: Vec<Value>,
    total: usize,
    offset: usize,
    limit: usize,
    bytes: usize,
}
impl Findings {
    fn push(&mut self, make: impl FnOnce() -> Value) -> Result<()> {
        if self.total >= MAX_FINDINGS {
            return Err(Error::capacity("npm audit exceeds 50000 findings."));
        }
        if self.total >= self.offset && self.items.len() < self.limit {
            let item = make();
            let size = serde_json::to_vec(&item)
                .map_err(|_| Error::integrity("Invalid npm audit finding."))?
                .len();
            self.bytes = self
                .bytes
                .checked_add(size)
                .filter(|v| *v <= MAX_WORKER_OUTPUT - 16 * 1024)
                .ok_or_else(|| {
                    Error::capacity("npm audit page exceeds its output budget; reduce limit.")
                })?;
            self.items.push(item);
        }
        self.total += 1;
        Ok(())
    }
}
fn assess(input: &AuditInput, inventory: Inventory, evidence: &Value) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let snapshot = evidence.get("snapshot").unwrap_or(&Value::Null);
    let records = evidence["records"]
        .as_array()
        .ok_or_else(|| Error::integrity("Invalid public npm advisory inventory."))?;
    let mut index = BTreeMap::<&str, Vec<&Value>>::new();
    let mut wildcard = Vec::new();
    let mut data_complete = evidence["complete"] == true;
    for record in records {
        let record_original = original(record);
        let Some(entries) = record_original["affected"].as_array() else {
            data_complete = false;
            continue;
        };
        let mut names = BTreeSet::new();
        for affected in entries {
            if affected
                .pointer("/package/ecosystem")
                .and_then(Value::as_str)
                == Some("npm")
            {
                if let Some(name) = affected.pointer("/package/name").and_then(Value::as_str) {
                    names.insert(name);
                } else {
                    data_complete = false;
                }
            }
        }
        for name in names {
            if name == "*" {
                wildcard.push(record);
            } else {
                index.entry(name).or_default().push(record);
            }
        }
        if Instant::now() >= deadline {
            return Err(Error::capacity("npm audit time budget exceeded."));
        }
    }
    let mut groups = BTreeMap::<(&str, &str), Vec<&npm_lockfile::Entry>>::new();
    let mut findings = Findings {
        items: Vec::new(),
        total: 0,
        offset: input.offset,
        limit: input.limit,
        bytes: 0,
    };
    let mut unassessed = 0_usize;
    let mut modified = 0_usize;
    for entry in &inventory.entries {
        if let Some(reason) = &entry.reason {
            unassessed += 1;
            findings.push(||json!({"package":entry.name,"version":entry.version,"classification":"unassessed","reason":reason,"occurrence":entry.occurrence}))?;
        } else if snapshot.is_null() {
            unassessed += 1;
            modified += usize::from(entry.modified);
            findings.push(||json!({"package":entry.name,"version":entry.version,"classification":"unassessed","reason":"advisory_data_unavailable","occurrence":entry.occurrence,"modified_source":entry.modified}))?;
        } else {
            if entry.modified {
                modified += 1;
                unassessed += 1;
                findings.push(||json!({"package":entry.name,"version":entry.version,"classification":"unassessed","reason":"modified_source","occurrence":entry.occurrence,"base_release_matching":true}))?;
            }
            groups
                .entry((&entry.name, &entry.version))
                .or_default()
                .push(entry);
        }
    }
    let mut vulnerabilities = 0;
    let mut malicious = 0;
    let mut informational = 0;
    let mut withdrawn = 0;
    let mut matching_complete = true;
    for ((name, version), occurrences) in &groups {
        let mut matched_records = Vec::new();
        let mut group_complete = true;
        for record in index.get(name).into_iter().flatten().chain(wildcard.iter()) {
            if Instant::now() >= deadline {
                return Err(Error::capacity("npm audit time budget exceeded."));
            }
            let matched = match_record(record, name, version)?;
            matching_complete &= matched["complete"] == true;
            group_complete &= matched["complete"] == true;
            if matched["matched"] != true {
                continue;
            }
            if matched_records.len() >= MAX_FINDINGS {
                return Err(Error::capacity(
                    "npm audit matching inventory exceeds its bound.",
                ));
            }
            matched_records.push(*record);
        }
        if !group_complete {
            unassessed += occurrences.iter().filter(|entry| !entry.modified).count();
            findings.push(||json!({"package":name,"version":version,"classification":"unassessed","reason":"unsupported_advisory_constraints_or_metadata","occurrence_count":occurrences.len()}))?;
        }
        for records in alias_groups(&matched_records)? {
            let record = records[0];
            let class = classification(record);
            match class {
                "withdrawn" => withdrawn += 1,
                "informational" => informational += 1,
                "malicious" => malicious += 1,
                _ => vulnerabilities += 1,
            }
            findings.push(||json!({"package":name,"version":version,"classification":class,"advisory":advisory_summary(record),"source_advisory_ids":records.iter().map(|record|original(record)["id"].clone()).collect::<Vec<_>>(),"occurrence_count":occurrences.len(),"registry_attribution":"caller_asserted_public_npm","modified_source":occurrences.iter().any(|entry|entry.modified)}))?;
        }
    }
    let now = crate::research::now();
    let validated = snapshot["validated_at"].as_i64();
    let fresh = validated.is_some_and(|time| time <= now && now.saturating_sub(time) <= 7 * 86400);
    let stale = validated.is_none_or(|time| time > now || now.saturating_sub(time) > 86400);
    let complete = data_complete
        && snapshot["complete"] == true
        && snapshot["historical"] != true
        && fresh
        && matching_complete
        && unassessed == 0;
    let assessed = inventory.entries.len().saturating_sub(unassessed);
    Ok(
        json!({"lockfile_format":input.lockfile_format,"format_version":inventory.format_version,"snapshot":snapshot,"complete":complete,"status":if complete{"complete"}else{"incomplete"},"stale":stale,"matching_complete":matching_complete,"entry_count":inventory.entries.len(),"assessed_count":assessed,"base_release_count":groups.len(),"unassessed_count":unassessed,"modified_count":modified,"vulnerability_count":vulnerabilities,"malicious_count":malicious,"informational_count":informational,"withdrawn_count":withdrawn,"findings":findings.items,"total":findings.total,"offset":input.offset,"next_offset":(input.offset.saturating_add(input.limit)<findings.total).then_some(input.offset.saturating_add(input.limit)),"input_retention":"request_lifetime_only","reason":evidence.get("reason")}),
    )
}

/// Alias equivalence is transitive. Preserve each source identity and keep
/// withdrawn/informational observations separate from active assessments.
fn alias_groups<'a>(records: &[&'a Value]) -> Result<Vec<Vec<&'a Value>>> {
    let mut parents: Vec<usize> = (0..records.len()).collect();
    let mut aliases = BTreeMap::<String, usize>::new();
    fn root(parents: &mut [usize], mut index: usize) -> usize {
        while parents[index] != index {
            let next = parents[index];
            parents[index] = parents[next];
            index = next;
        }
        index
    }
    let mut alias_bytes = 0_usize;
    for (index, record) in records.iter().enumerate() {
        let original = original(record);
        let class = classification(record);
        let identities = std::iter::once(original["id"].as_str()).chain(
            original["aliases"]
                .as_array()
                .into_iter()
                .flatten()
                .map(Value::as_str),
        );
        for id in identities.flatten() {
            let key = format!("{class}:{id}");
            if let Some(previous) = aliases.get(&key) {
                let left = root(&mut parents, index);
                let right = root(&mut parents, *previous);
                parents[left] = right;
            } else {
                alias_bytes = alias_bytes
                    .checked_add(key.len())
                    .filter(|size| *size <= 8 * 1024 * 1024)
                    .ok_or_else(|| {
                        Error::capacity("npm advisory alias grouping exceeds its bound.")
                    })?;
                aliases.insert(key, index);
            }
        }
    }
    let mut groups = BTreeMap::<usize, Vec<&Value>>::new();
    for (index, record) in records.iter().enumerate() {
        let root = root(&mut parents, index);
        groups.entry(root).or_default().push(record);
    }
    let mut groups: Vec<_> = groups.into_values().collect();
    for group in &mut groups {
        group.sort_by(|a, b| original(a)["id"].as_str().cmp(&original(b)["id"].as_str()));
    }
    groups.sort_by(|a, b| {
        original(a[0])["id"]
            .as_str()
            .cmp(&original(b[0])["id"].as_str())
    });
    Ok(groups)
}

pub fn advisory_summary(record: &Value) -> Value {
    let value = original(record);
    let rights_gap = record["rights_gap"] == true;
    json!({"id":value["id"],"aliases":value["aliases"],"summary":if rights_gap {None} else {value["summary"].as_str().map(|v|v.chars().take(1024).collect::<String>())},"classification":classification(record),"published":value["published"],"modified":value["modified"],"withdrawn":value["withdrawn"],"severity":if rights_gap {Value::Null} else {value["severity"].clone()},"github_reviewed":value.pointer("/database_specific/github_reviewed"),"license":record["license"],"attribution_url":record["attribution_url"],"rights_gap":rights_gap})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(events: Value) -> Value {
        json!({"schema_version":"1.9.2","id":"GHSA-synthetic-0001","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example"},"ranges":[{"type":"ECOSYSTEM","events":events}]}]})
    }
    fn matched(record: &Value, version: &str) -> Value {
        match_record(record, "example", version).unwrap()
    }
    #[test]
    fn ecosystem_intervals_prerelease_build_and_zero_sentinel() {
        let record = record(json!([{"introduced":"0"},{"fixed":"2.0.0"}]));
        assert_eq!(matched(&record, "0.0.0-alpha")["matched"], true);
        assert_eq!(matched(&record, "2.0.0-alpha")["matched"], true);
        assert_eq!(matched(&record, "2.0.0")["matched"], false);
        assert_eq!(matched(&record, "1.0.0+build")["matched"], true);
    }
    #[test]
    fn last_affected_limit_explicit_versions_and_global_package() {
        let record =
            record(json!([{"introduced":"1.0.0"},{"last_affected":"2.0.0"},{"limit":"1.5.0"}]));
        assert_eq!(matched(&record, "1.4.9")["matched"], true);
        assert_eq!(matched(&record, "1.5.0")["matched"], false);
        let mut record = record.clone();
        record["affected"][0]["package"]["name"] = json!("*");
        record["affected"][0]["versions"] = json!(["4.0.0+one"]);
        assert_eq!(
            match_record(&record, "other", "4.0.0+two").unwrap()["matched"],
            true
        );
    }
    #[test]
    fn unsupported_constraints_preserve_supported_matches_and_gap() {
        let mut record = record(json!([{"introduced":"0"}]));
        record["affected"][0]["ranges"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"GIT","events":[]}));
        let result = matched(&record, "1.0.0");
        assert_eq!(result["matched"], true);
        assert_eq!(result["complete"], false);
        record["schema_version"] = json!("2.0.0");
        assert_eq!(matched(&record, "1.0.0")["complete"], false);
    }
    #[test]
    fn source_normalization_preserves_attribution_and_unknown_rights() {
        let value = record(json!([{"introduced":"0"}]));
        let normalized = parse_advisory(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(normalized["license"], "CC-BY-4.0");
        assert_eq!(normalized["packages"], json!(["example"]));
        let mut value = value;
        value["id"] = json!("UNKNOWN-1");
        let normalized = parse_advisory(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(normalized["rights_gap"], true);
        let mut normalized = normalized;
        normalized["original"]["summary"] = json!("SOURCE_RIGHTS_SENTINEL");
        normalized["original"]["severity"] =
            json!([{"type":"CVSS_V3","score":"SOURCE_RIGHTS_SENTINEL"}]);
        let public = advisory_summary(&normalized);
        assert_eq!(public["summary"], Value::Null);
        assert_eq!(public["severity"], Value::Null);
        assert!(!public.to_string().contains("SOURCE_RIGHTS_SENTINEL"));
    }
    fn input(lockfile: Value) -> Value {
        json!({"operation":"npm","phase":"audit","input":{"lockfile":lockfile.to_string(),"lockfile_format":"npm","registry_context":{"default":"npmjs"}},"snapshot":{"snapshot":{"id":"a".repeat(64),"validated_at":crate::research::now(),"complete":true,"historical":false},"records":[parse_advisory(&serde_json::to_vec(&record(json!([{"introduced":"0"},{"fixed":"2.0.0"}]))).unwrap()).unwrap()],"complete":true}})
    }
    #[test]
    fn audited_inventory_deduplicates_matching_and_marks_patches_and_unknowns() {
        let request = input(
            json!({"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"},"node_modules/nested/node_modules/example":{"version":"1.0.0"},"node_modules/patched":{"name":"example","version":"1.0.0","inBundle":true},"node_modules/local":{"version":"file:private"}}}),
        );
        let result = worker_request(request).unwrap();
        assert_eq!(result["vulnerability_count"], 1);
        assert_eq!(result["unassessed_count"], 2);
        assert_eq!(result["complete"], false);
        assert_eq!(result["base_release_count"], 1);
    }
    #[test]
    fn private_malformed_input_is_sanitized_and_paging_is_stable() {
        let mut request = input(json!({"lockfileVersion":3,"packages":{}}));
        request["input"]["lockfile"] = json!("PRIVATE_SYNTHETIC_SENTINEL");
        assert!(
            !worker_request(request)
                .unwrap_err()
                .to_string()
                .contains("PRIVATE_SYNTHETIC_SENTINEL")
        );
        let request = input(
            json!({"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}),
        );
        let result = worker_request(request).unwrap();
        assert_eq!(result["complete"], true);
        assert_eq!(result["input_retention"], "request_lifetime_only");
    }
    #[test]
    fn alias_groups_are_transitive_and_keep_withdrawals_separate() {
        let mut first = record(json!([{"introduced":"0"}]));
        first["id"] = json!("GHSA-first");
        first["aliases"] = json!(["CVE-A"]);
        let mut second = first.clone();
        second["id"] = json!("GHSA-second");
        second["aliases"] = json!(["CVE-B"]);
        let mut bridge = first.clone();
        bridge["id"] = json!("GHSA-bridge");
        bridge["aliases"] = json!(["CVE-A", "CVE-B"]);
        let mut withdrawn = first.clone();
        withdrawn["id"] = json!("GHSA-withdrawn");
        withdrawn["withdrawn"] = json!("2026-01-02T00:00:00Z");
        let mut request = input(
            json!({"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}),
        );
        request["snapshot"]["records"] = json!([first, second, bridge, withdrawn]);
        let report = worker_request(request).unwrap();
        assert_eq!(report["vulnerability_count"], 1);
        assert_eq!(report["withdrawn_count"], 1);
        assert_eq!(
            report["findings"][0]["source_advisory_ids"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }
    #[test]
    fn absent_advisories_and_unsupported_matching_count_unassessed_entries() {
        let mut request = input(
            json!({"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}),
        );
        request["snapshot"] = json!({"snapshot":null,"records":[],"complete":false});
        let report = worker_request(request).unwrap();
        assert_eq!(report["assessed_count"], 0);
        assert_eq!(report["unassessed_count"], 1);
        assert_eq!(report["complete"], false);
        let mut request = input(
            json!({"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}),
        );
        request["snapshot"]["records"][0]["original"]["affected"][0]["ranges"][0]["type"] =
            json!("GIT");
        let report = worker_request(request).unwrap();
        assert_eq!(report["unassessed_count"], 1);
        assert_eq!(report["matching_complete"], false);
        assert_eq!(report["complete"], false);
    }
}
