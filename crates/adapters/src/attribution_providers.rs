//! Source-bound attribution recipes. Source text is inert evidence, never authority
//! to fetch a URL or to execute a package. Unknown historical scope fails closed.
use crate::bulk::{BulkBroker, BulkRequest, BulkSource};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use devres_application::Fetcher;
use devres_domain::attribution::{
    ATTRIBUTION_POLICY_EPOCH, ATTRIBUTION_POLICY_FINGERPRINT, AttributionGeneration,
    AttributionNotice, AttributionSubject, AttributionTarget,
};
use devres_domain::{Error, Result, Validators};
use futures::StreamExt as _;
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, io::Read, sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const MAX_SOURCE: usize = 32 * 1024 * 1024;
const MAX_NOTICE: usize = 1024 * 1024;
const MAX_TARGETS: usize = 256;

/// Extra fixed-source operations needed to re-request an exact retained Git file.
/// Dynamic repositories are constructed by catalog-qualified provider adapters.
#[derive(Clone, Debug)]
pub enum AttributionSource {
    Mdn {
        compatibility: bool,
        revision: String,
        path: String,
    },
    RustSec {
        revision: String,
        path: String,
    },
    Whatwg {
        repository: crate::whatwg::git::Repo,
        revision: String,
        path: String,
    },
    W3c {
        repository: crate::w3c::git::Repo,
        revision: String,
        path: String,
    },
    Rfc {
        number: u32,
        format: String,
    },
    NpmAdvisory {
        id: String,
    },
}
impl AttributionSource {
    pub fn url(&self) -> Result<String> {
        let (repository, revision, path) = match self {
            Self::Mdn {
                compatibility,
                revision,
                path,
            } => (
                if *compatibility {
                    "mdn/browser-compat-data"
                } else {
                    "mdn/content"
                }
                .to_owned(),
                revision,
                path,
            ),
            Self::RustSec { revision, path } => ("rustsec/advisory-db".into(), revision, path),
            Self::Whatwg {
                repository,
                revision,
                path,
            } => {
                crate::whatwg::git::Repo::new(&repository.as_str())?;
                (repository.as_str(), revision, path)
            }
            Self::W3c {
                repository,
                revision,
                path,
            } => {
                repository.validate()?;
                let identity = repository.source_url();
                let identity = identity.strip_prefix("https://github.com/")
                    .ok_or_else(|| Error::unavailable("Exact historical Git source requires its qualified repository transport."))?;
                let identity = identity.trim_end_matches(".git");
                crate::whatwg::git::Repo::new(identity)?;
                (identity.to_owned(), revision, path)
            }
            Self::Rfc { number, format } => {
                if *number == 0
                    || !matches!(format.as_str(), "txt" | "html" | "xml" | "pdf" | "json")
                {
                    return Err(invalid());
                }
                return Ok(format!(
                    "https://www.rfc-editor.org/rfc/rfc{number}.{format}"
                ));
            }
            Self::NpmAdvisory { id } => {
                if !valid_advisory_id(id) {
                    return Err(invalid());
                }
                return Ok(format!(
                    "https://osv-vulnerabilities.storage.googleapis.com/npm/{id}.json"
                ));
            }
        };
        if !oid(revision)
            || !crate::archive::valid_relative_path(path)
            || path.contains(['?', '#', '%'])
        {
            return Err(invalid());
        }
        let mut url = url::Url::parse("https://api.github.com/").map_err(|_| invalid())?;
        url.set_path(&format!("/repos/{repository}/contents/{path}"));
        url.query_pairs_mut().append_pair("ref", revision);
        Ok(url.to_string())
    }
    pub fn host(&self) -> &'static str {
        if matches!(self, Self::NpmAdvisory { .. }) {
            "osv-vulnerabilities.storage.googleapis.com"
        } else if matches!(self, Self::Rfc { .. }) {
            "www.rfc-editor.org"
        } else {
            "api.github.com"
        }
    }
    pub fn media_type(&self) -> &'static str {
        match self {
            Self::Rfc { format, .. } => match format.as_str() {
                "pdf" => "application/pdf",
                "html" => "text/html",
                "xml" => "application/xml",
                "json" => "application/json",
                _ => "text/plain",
            },
            Self::NpmAdvisory { .. } => "application/json",
            _ => "application/vnd.github.raw+json",
        }
    }
}

fn invalid() -> Error {
    Error::invalid("Invalid attribution source identity.")
}
fn incomplete() -> Error {
    Error::unavailable("Exact source or applicable notice evidence is unavailable.")
}
fn oid(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn string<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty())
}
fn provider(value: &str) -> Result<&'static str> {
    match value {
        "rfc" => Ok("rfc"),
        "crate" | "crates" | "cargo" | "docs" => Ok("crates"),
        "advisory" | "rustsec" => Ok("rustsec"),
        "mdn" | "mdn-compat" => Ok("mdn"),
        "whatwg" => Ok("whatwg"),
        "w3c" => Ok("w3c"),
        "chromium" => Ok("chromium"),
        "npm" => Ok("npm"),
        "wikipedia" => Ok("wikipedia"),
        _ => Err(invalid()),
    }
}

fn inferred_provider(value: &Value) -> Option<&'static str> {
    if let Some(key) = string(value, "source_key").or_else(|| string(value, "key"))
        && let Some(prefix) = key.split(':').next()
        && let Ok(p) = provider(prefix)
    {
        return Some(p);
    }
    let url = url::Url::parse(string(value, "source_url")?).ok()?;
    match url.host_str()? {
        "www.rfc-editor.org" | "rfc-editor.org" => Some("rfc"),
        "crates.io" | "index.crates.io" | "static.crates.io" | "docs.rs" => Some("crates"),
        "registry.npmjs.org" | "osv-vulnerabilities.storage.googleapis.com" => Some("npm"),
        "en.wikipedia.org" => Some("wikipedia"),
        "www.w3.org" | "w3.org" | "api.w3.org" => Some("w3c"),
        "chromium.googlesource.com" | "www.chromium.org" | "developer.chrome.com" => {
            Some("chromium")
        }
        "github.com" => {
            let path = url.path().to_ascii_lowercase();
            if path.starts_with("/mdn/") {
                Some("mdn")
            } else if path.starts_with("/rustsec/advisory-db/") {
                Some("rustsec")
            } else if path.starts_with("/whatwg/") {
                Some("whatwg")
            } else if path.starts_with("/googlechrome/developer.chrome.com/") {
                Some("chromium")
            } else {
                None
            }
        }
        h if crate::whatwg::catalog::publication_host(h) => Some("whatwg"),
        _ => None,
    }
}

/// Extract only exact public provenance. Request text, snippets, dependency
/// inventories, result shapes and audit associations never become repair keys.
pub fn targets(source: &str, value: &Value) -> Result<Vec<AttributionTarget>> {
    if matches!(source, "wikipedia" | "mixed")
        && crate::wikipedia::attribution::is_metadata_only_discovery(value)
    {
        return Ok(Vec::new());
    }
    targets_v1(source, value)
}

// This compiler and its normalization helpers are part of the persisted v1
// policy. A future qualification policy must preserve this implementation and
// dispatch historical checks to it, rather than changing its source mapping.
fn targets_v1(source: &str, value: &Value) -> Result<Vec<AttributionTarget>> {
    let mut out = BTreeMap::new();
    let original = value.pointer("/_meta/source_evidence").unwrap_or(value);
    validate_coverage(source, original, false, 0)?;
    // Projections inherit their exact originating archive, not an independently
    // copied registry response or a locally generated capture masquerading as raw.
    if let Ok(p) = provider(source) {
        if p == "npm"
            && let Some(target) = npm_advisory_target(original)?
        {
            return Ok(vec![target]);
        }
        if matches!(p, "crates" | "npm") {
            if let Some(target) = package_target(p, original)? {
                return Ok(vec![target]);
            }
            if let Some(raw) = original.get("source_capture").filter(|x| x.is_object()) {
                visit(p, raw, &Value::Null, 0, &mut out)?;
                if !out.is_empty() {
                    return Ok(out.into_values().collect());
                }
            }
        }
    }
    visit(source, value, &Value::Null, 0, &mut out)?;
    Ok(out.into_values().collect())
}

/// A qualified sibling never supplies provenance for unidentified copied text.
/// Only an object's own exact source/capture may cover its child fields.
fn validate_coverage(source: &str, value: &Value, inherited: bool, depth: usize) -> Result<()> {
    if depth > 24 {
        return Err(Error::capacity(
            "Attribution content nesting bound exceeded.",
        ));
    }
    match value {
        Value::Object(map) => {
            if let Some(evidence) = value.pointer("/_meta/source_evidence") {
                validate_coverage(source, evidence, false, depth + 1)?;
                let mut origins = BTreeMap::new();
                visit(source, evidence, &Value::Null, depth + 1, &mut origins)?;
                if origins.is_empty() {
                    return Err(Error::unavailable(
                        "Resource content lacks exact originating attribution evidence.",
                    ));
                }
                // This application-owned slot binds this item's copied page to
                // its originating tool. It cannot qualify a sibling item.
                return Ok(());
            }
            let p = if matches!(source, "mixed" | "capture") {
                string(value, "source")
                    .and_then(|p| provider(p).ok())
                    .or_else(|| inferred_provider(value))
            } else {
                provider(source).ok()
            };
            let exact = if let Some(p) = p {
                target_from(p, value, value.get("license").unwrap_or(&Value::Null))?.is_some()
            } else {
                false
            };
            let referenced = if let Some(p) = p {
                [
                    "capture",
                    "source_capture",
                    "archive_capture",
                    "metadata_capture",
                ]
                .iter()
                .any(|key| {
                    map.get(*key)
                        .and_then(|v| target_from(p, v, &Value::Null).ok().flatten())
                        .is_some()
                })
            } else {
                false
            };
            let archive_origin = p
                .map(|p| package_target(p, value))
                .transpose()?
                .flatten()
                .is_some();
            let advisory_origin = p == Some("npm") && npm_advisory_target(value)?.is_some();
            let own = exact || referenced || archive_origin || advisory_origin;
            let covered = inherited || own;
            if [
                "text",
                "excerpt",
                "snippet",
                "summary",
                "description",
                "abstract",
                "abstract_text",
                "title",
                "details",
            ]
            .iter()
            .any(|key| {
                map.get(*key)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
            }) && !covered
            {
                return Err(Error::unavailable(
                    "Copied content lacks exact attribution source evidence.",
                ));
            }
            for (key, child) in map {
                if matches!(
                    key.as_str(),
                    "license"
                        | "source_metadata"
                        | "citation"
                        | "_meta"
                        | "query"
                        | "filters"
                        | "input"
                        | "dependencies"
                ) {
                    continue;
                }
                if child.is_array() || child.is_object() {
                    let context = if matches!(key.as_str(), "left" | "right" | "from" | "to")
                        || source == "mixed"
                    {
                        own
                    } else {
                        covered
                    };
                    validate_coverage(p.unwrap_or(source), child, context, depth + 1)?;
                }
            }
        }
        Value::Array(items) => {
            for child in items {
                validate_coverage(source, child, inherited, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn package_target(p: &str, value: &Value) -> Result<Option<AttributionTarget>> {
    let archive = value
        .get("archive_capture")
        .filter(|x| x.is_object())
        .or_else(|| {
            value
                .pointer("/provenance/archive")
                .filter(|x| x.is_object())
        });
    let Some(archive) = archive else {
        return Ok(None);
    };
    let mut source = archive.clone();
    if string(&source, "source_url").is_none() {
        let name = string(value, "name");
        let version = string(value, "version");
        let (Some(name), Some(version)) = (name, version) else {
            return Ok(None);
        };
        let url = if p == "npm" {
            crate::npm::processing::validate_name(name)?;
            crate::npm::processing::parse_version(version)?;
            format!(
                "https://registry.npmjs.org/{name}/-/{}-{version}.tgz",
                name.rsplit('/').next().ok_or_else(invalid)?
            )
        } else {
            BulkSource::CrateArchive {
                name: name.into(),
                version: version.into(),
            }
            .url()?
        };
        source["source_url"] = json!(url);
    }
    // Preserve the selected member identity; its header may carry a separate
    // original notice even when the requested byte page starts after it.
    if let Some(path) = string(value, "path") {
        source["member_path"] = json!(path);
    }
    target_from(p, &source, &Value::Null)
}

fn metadata_target(p: &str, value: &Value) -> Result<Option<AttributionTarget>> {
    let Some(capture) = value.get("capture").filter(|v| v.is_object()) else {
        return Ok(None);
    };
    let record = value.get("metadata").unwrap_or(value);
    let name = string(record, "name");
    let version = string(record, "vers").or_else(|| string(record, "version"));
    let (Some(name), Some(version)) = (name, version) else {
        return Ok(None);
    };
    let mut source = capture.clone();
    source["name"] = json!(name);
    source["version"] = json!(version);
    target_from(p, &source, &Value::Null)
}

fn valid_advisory_id(id: &str) -> bool {
    if let Some(rest) = id.strip_prefix("GHSA-") {
        let pieces = rest.split('-').collect::<Vec<_>>();
        pieces.len() == 3
            && pieces.iter().all(|p| {
                p.len() == 4
                    && p.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            })
    } else if let Some(rest) = id.strip_prefix("MAL-") {
        rest.len() <= 64
            && !rest.is_empty()
            && rest
                .split('-')
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    } else {
        false
    }
}

fn npm_advisory_target(value: &Value) -> Result<Option<AttributionTarget>> {
    let record = value.get("advisory").unwrap_or(value);
    let Some(id) = string(record, "id").filter(|id| valid_advisory_id(id)) else {
        return Ok(None);
    };
    if record["rights_gap"] == true {
        return Ok(None);
    }
    let provenance = value.get("provenance").unwrap_or(value);
    let Some(original_url) = string(provenance, "source_url") else {
        return Ok(None);
    };
    let Some(hash) = provenance
        .pointer("/artifact/body_hash")
        .and_then(Value::as_str)
        .or_else(|| string(provenance, "body_hash"))
    else {
        return Ok(None);
    };
    let url = if original_url == crate::npm::source::OSV_EXPORT {
        AttributionSource::NpmAdvisory { id: id.into() }.url()?
    } else {
        original_url.into()
    };
    let source = json!({"id":id,"source_url":url,"body_hash":hash,"advisory":record});
    target_from("npm", &source, &Value::Null)
}
fn visit(
    source: &str,
    value: &Value,
    inherited: &Value,
    depth: usize,
    out: &mut BTreeMap<String, AttributionTarget>,
) -> Result<()> {
    if depth > 24 || out.len() > MAX_TARGETS {
        return Err(Error::capacity("Attribution subject bound exceeded."));
    }
    match value {
        Value::Object(map) => {
            // Resource wrappers retain only public, inert originating provenance.
            if let Some(evidence) = value.pointer("/_meta/source_evidence") {
                return visit(source, evidence, inherited, depth + 1, out);
            }
            let actual = if matches!(source, "mixed" | "capture") {
                string(value, "source")
                    .or_else(|| string(value, "provider"))
                    .and_then(|p| provider(p).ok())
                    .or_else(|| inferred_provider(value))
                    .unwrap_or(source)
            } else {
                source
            };
            let local_license = map
                .get("license")
                .filter(|x| x.is_object())
                .or_else(|| value.pointer("/source_metadata/license"))
                .or_else(|| value.pointer("/selection/coverage/license"))
                .or_else(|| value.pointer("/coverage/license"))
                .unwrap_or(inherited);
            let mut normalized = false;
            if let Ok(p) = provider(actual) {
                let target = if p == "npm" {
                    npm_advisory_target(value)?
                        .or(package_target(p, value)?)
                        .or(metadata_target(p, value)?)
                } else if p == "crates" {
                    package_target(p, value)?.or(metadata_target(p, value)?)
                } else {
                    None
                };
                if let Some(target) = target {
                    out.insert(target.subject.fingerprint.clone(), target);
                    normalized = true;
                } else if matches!(p, "crates" | "npm")
                    && let Some(raw) = value.get("source_capture").filter(|v| v.is_object())
                {
                    visit(p, raw, local_license, depth + 1, out)?;
                    normalized = true;
                }
            }
            if !normalized
                && let Ok(p) = provider(actual)
                && let Some(target) = target_from(p, value, local_license)?
            {
                out.insert(target.subject.fingerprint.clone(), target);
                normalized = true;
            }
            for (key, child) in map {
                if normalized
                    && matches!(
                        key.as_str(),
                        "capture"
                            | "metadata_capture"
                            | "archive_capture"
                            | "source_capture"
                            | "provenance"
                            | "snapshot"
                            | "selection"
                    )
                {
                    continue;
                }
                if matches!(
                    key.as_str(),
                    "page"
                        | "original"
                        | "resolved"
                        | "metadata"
                        | "manifest"
                        | "advisory"
                        | "license"
                        | "source_metadata"
                        | "citation"
                        | "_meta"
                        | "contracts"
                        | "query"
                        | "filters"
                        | "input"
                        | "dependencies"
                ) {
                    continue;
                }
                if child.is_object() || child.is_array() {
                    visit(actual, child, local_license, depth + 1, out)?;
                }
            }
        }
        Value::Array(items) => {
            if items.len() > 1000 {
                return Err(Error::capacity("Attribution result bound exceeded."));
            }
            for child in items {
                visit(source, child, inherited, depth + 1, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn target_from(p: &str, value: &Value, license: &Value) -> Result<Option<AttributionTarget>> {
    if p == "wikipedia" {
        return crate::wikipedia::attribution::target(value);
    }
    let url = string(value, "source_url")
        .or_else(|| {
            value
                .pointer("/citation/source_url")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            value
                .pointer("/source_metadata/source_url")
                .and_then(Value::as_str)
        });
    let Some(url) = url else {
        return Ok(None);
    };
    if url.len() > 4096 {
        return Err(invalid());
    }
    let revision = string(value, "revision")
        .or_else(|| {
            value
                .pointer("/provenance/revision")
                .and_then(Value::as_str)
        })
        .or_else(|| value.pointer("/selection/revision").and_then(Value::as_str))
        .or_else(|| value.pointer("/snapshot/revision").and_then(Value::as_str))
        .or_else(|| value.pointer("/citation/revision").and_then(Value::as_str));
    let hash = string(value, "body_hash")
        .or_else(|| value.pointer("/evidence/body_hash").and_then(Value::as_str));
    let object = string(value, "oid")
        .or_else(|| string(value, "object_hash"))
        .or_else(|| {
            value
                .pointer("/citation/object_hash")
                .and_then(Value::as_str)
        });
    let mut identity = Map::new();
    identity.insert("source_url".into(), json!(url));
    for field in [
        "id",
        "body_hash",
        "oid",
        "revision",
        "path",
        "source_path",
        "repository",
        "component",
        "name",
        "version",
        "representation",
        "member_path",
        "media_type",
    ] {
        if let Some(v) = value.get(field).filter(|v| v.is_string()) {
            identity.insert(field.into(), v.clone());
        }
    }
    if let Some(metadata) = value.get("source_metadata") {
        for field in ["component", "revision", "source_path", "repository"] {
            if let Some(v) = metadata.get(field).filter(|v| v.is_string()) {
                identity.entry(field).or_insert_with(|| v.clone());
            }
        }
    }
    for (key, val) in [("revision", revision), ("body_hash", hash), ("oid", object)] {
        if let Some(val) = val {
            identity.insert(key.into(), json!(val));
        }
    }
    if let Some(object) = object.filter(|s| devres_domain::valid_content_id(s)) {
        identity.remove("oid");
        identity.entry("body_hash").or_insert_with(|| json!(object));
    }
    if !identity.contains_key("path")
        && let Some(path) = value.pointer("/citation/path").and_then(Value::as_str)
    {
        identity.insert("path".into(), json!(path));
    }
    if let Some(repository) = value
        .pointer("/selection/repository")
        .or_else(|| value.pointer("/provenance/repository"))
        .filter(|x| x.is_string())
    {
        identity
            .entry("repository")
            .or_insert_with(|| repository.clone());
    }
    // A current URL without exact immutable identity cannot qualify historical bytes.
    if hash.is_none() && object.is_none() {
        return Ok(None);
    }
    let source = Value::Object(identity);
    let fingerprint = crate::integrity::canonical_hash(&json!({"provider":p,"source":source}))?;
    let key = string(&source, "id")
        .map(str::to_owned)
        .unwrap_or_else(|| fingerprint.clone());
    let retained_license = if license.is_object() {
        license.clone()
    } else {
        Value::Null
    };
    let mut evidence = json!({"version":1,"source":source,"license":retained_license});
    // These are original public advisory fields, not package inventory/report
    // data. The GHSA exception must travel with the exact advisory occurrence.
    if p == "rustsec" || p == "npm" {
        let record = value.get("advisory").unwrap_or(value);
        let mut attribution = Map::new();
        for field in ["id", "license", "url", "attribution_url"] {
            if let Some(s) = string(record, field) {
                attribution.insert(field.into(), json!(s));
            }
        }
        if !attribution.is_empty() {
            evidence["record"] = Value::Object(attribution);
        }
    }
    let fingerprint = crate::integrity::canonical_hash(&evidence)?;
    Ok(Some(AttributionTarget {
        subject: AttributionSubject {
            provider: p.into(),
            namespace: "source".into(),
            key,
            fingerprint,
        },
        evidence,
    }))
}

/// Storage scans use the same exact-subject compiler as public readers. Non-source
/// structural records are enumerated but never assigned an invented upstream URL.
pub fn candidate(
    source: &str,
    namespace: &str,
    key: &str,
    data: &Value,
) -> Result<Option<AttributionTarget>> {
    retained_candidate(
        ATTRIBUTION_POLICY_EPOCH,
        ATTRIBUTION_POLICY_FINGERPRINT,
        source,
        namespace,
        key,
        data,
    )
}

/// Reproduce the immutable source mapping recorded by a registered policy.
/// Retaining this v1 recipe includes `targets_v1` and its normalization helpers;
/// policy changes require a separate recipe instead of altering old evidence.
pub fn retained_candidate(
    policy_epoch: u32,
    policy_fingerprint: &str,
    source: &str,
    namespace: &str,
    key: &str,
    data: &Value,
) -> Result<Option<AttributionTarget>> {
    match (policy_epoch, policy_fingerprint) {
        (1, "devres-attribution-v1:exact-reacquisition:member-scopes:readable-notices") => {
            candidate_v1(source, namespace, key, data)
        }
        _ => Err(Error::integrity("Unknown retained attribution recipe.")),
    }
}

/// Compile only the source represented by the sealed retained occurrence.
/// Application repair and storage publication/verification share this extraction.
pub fn retained_target(
    policy_epoch: u32,
    policy_fingerprint: &str,
    target: &AttributionTarget,
) -> Result<Option<AttributionTarget>> {
    let Some(table) = target.evidence.get("table").and_then(Value::as_str) else {
        return Ok(None);
    };
    let namespace = string(&target.evidence, "kind").unwrap_or(table);
    let key = string(&target.evidence, "key").unwrap_or(&target.subject.key);
    let data = target.evidence.get("data").unwrap_or(&target.evidence);
    retained_candidate(
        policy_epoch,
        policy_fingerprint,
        &target.subject.provider,
        namespace,
        key,
        data,
    )
}

fn candidate_v1(
    source: &str,
    namespace: &str,
    key: &str,
    data: &Value,
) -> Result<Option<AttributionTarget>> {
    if namespace.len() > 128 || key.len() > 4096 {
        return Err(invalid());
    }
    let p = provider(source)?;
    if p == "wikipedia" {
        return if namespace == "captures" {
            crate::wikipedia::attribution::target(data)
        } else {
            Ok(None)
        };
    }
    let mut value = normalize_candidate(p, data, None)?;
    if let Some(v) = value.as_object_mut()
        && !v.contains_key("id")
        && devres_domain::valid_content_id(key)
    {
        v.insert("id".into(), json!(key));
    }
    let mut compiled = targets_v1(p, &value)?;
    if compiled.len() == 1 {
        Ok(compiled.pop())
    } else if compiled.len() > 1 {
        let evidence = json!({"version":1,"dependencies":compiled});
        Ok(Some(AttributionTarget {
            subject: AttributionSubject {
                provider: p.into(),
                namespace: "source".into(),
                key: key.into(),
                fingerprint: crate::integrity::canonical_hash(&evidence)?,
            },
            evidence,
        }))
    } else {
        Ok(None)
    }
}

fn normalize_candidate(p: &str, data: &Value, context: Option<(&str, &str)>) -> Result<Value> {
    // A history record supplies the exact parent/current revision for member
    // objects. An isolated inventory blob without that linkage stays a gap.
    if data.get("before").is_some() || data.get("after").is_some() {
        let repository = string(data, "repository").unwrap_or("");
        let mut sources = Vec::new();
        for (side, rev) in [
            ("before", string(data, "parent")),
            ("after", string(data, "revision")),
        ] {
            if let (Some(member), Some(rev)) = (data.get(side).filter(|v| !v.is_null()), rev) {
                sources.push(normalize_candidate(p, member, Some((repository, rev)))?);
            }
        }
        return Ok(json!({"sources":sources}));
    }
    if matches!(p, "crates" | "npm")
        && data.get("artifact").is_some_and(Value::is_object)
        && string(data, "name").is_some()
        && string(data, "version").is_some()
    {
        return Ok(
            json!({"name":data["name"],"version":data["version"],"path":data["path"],"provenance":{"archive":data["artifact"]}}),
        );
    }
    let mut result = data.clone();
    let original = data.get("raw").filter(|v| v.is_object()).unwrap_or(data);
    if let Some(map) = result.as_object_mut() {
        for field in [
            "source_url",
            "oid",
            "source_path",
            "repository",
            "component",
            "license",
        ] {
            if let Some(value) = original.get(field) {
                map.insert(field.into(), value.clone());
            }
        }
        if let Some((repository, revision)) = context {
            if !repository.is_empty() {
                map.entry("repository").or_insert_with(|| json!(repository));
            }
            map.insert("revision".into(), json!(revision));
        }
    }
    if string(&result, "source_url").is_some() {
        return Ok(result);
    }
    let path = string(&result, "source_path").or_else(|| string(&result, "path"));
    let revision = string(&result, "revision");
    let (Some(path), Some(revision)) = (path, revision) else {
        return Ok(result);
    };
    if !oid(revision) || !crate::archive::valid_relative_path(path) {
        return Ok(result);
    }
    let repository = string(&result, "repository").unwrap_or("");
    let repository = match p {
        "mdn" => match repository {
            "content" => "mdn/content",
            "compat" => "mdn/browser-compat-data",
            r => r,
        },
        "rustsec" => "rustsec/advisory-db",
        _ => repository,
    };
    let source_url = if p == "chromium" {
        let Some(component) = string(&result, "component") else {
            return Ok(result);
        };
        crate::chromium::source::Operation::Blob {
            component: component.into(),
            revision: revision.into(),
            path: path.into(),
        }
        .url()?
    } else {
        let repository = repository
            .strip_prefix("https://github.com/")
            .unwrap_or(repository)
            .trim_end_matches(".git");
        let repository = crate::whatwg::git::Repo::new(repository)?;
        format!(
            "https://github.com/{}/blob/{revision}/{path}",
            repository.as_str()
        )
    };
    result["source_url"] = json!(source_url);
    Ok(result)
}

fn git_source(p: &str, source: &Value, path: &str) -> Result<AttributionSource> {
    let url = string(source, "source_url").ok_or_else(incomplete)?;
    let parsed = url::Url::parse(url).map_err(|_| invalid())?;
    let parts = parsed
        .path()
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let revision = string(source, "revision")
        .or_else(|| parts.get(3).copied().filter(|x| oid(x)))
        .ok_or_else(incomplete)?;
    if !oid(revision) {
        return Err(incomplete());
    }
    let repository = string(source, "repository")
        .map(str::to_owned)
        .or_else(|| {
            if parsed.host_str() == Some("github.com") && parts.len() >= 4 {
                Some(format!("{}/{}", parts[0], parts[1]))
            } else {
                None
            }
        })
        .ok_or_else(incomplete)?;
    match p {
        "mdn" => {
            let compatibility = matches!(repository.as_str(), "compat" | "mdn/browser-compat-data");
            if !compatibility && !matches!(repository.as_str(), "content" | "mdn/content") {
                return Err(incomplete());
            }
            Ok(AttributionSource::Mdn {
                compatibility,
                revision: revision.into(),
                path: path.into(),
            })
        }
        "rustsec" if repository.eq_ignore_ascii_case("rustsec/advisory-db") => {
            Ok(AttributionSource::RustSec {
                revision: revision.into(),
                path: path.into(),
            })
        }
        "whatwg" => Ok(AttributionSource::Whatwg {
            repository: crate::whatwg::git::Repo::new(&repository)?,
            revision: revision.into(),
            path: path.into(),
        }),
        "w3c" => Ok(AttributionSource::W3c {
            repository: crate::w3c::git::Repo::new(&repository)?,
            revision: revision.into(),
            path: path.into(),
        }),
        _ => Err(incomplete()),
    }
}
fn source_path(source: &Value) -> Result<String> {
    if let Some(path) = string(source, "source_path").or_else(|| string(source, "path")) {
        return Ok(path.into());
    }
    let url = url::Url::parse(string(source, "source_url").ok_or_else(incomplete)?)
        .map_err(|_| invalid())?;
    let parts = url
        .path()
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    if url.host_str() == Some("github.com")
        && parts.len() > 4
        && parts[2] == "blob"
        && oid(parts[3])
    {
        return Ok(parts[4..].join("/"));
    }
    Err(incomplete())
}

async fn acquire(
    broker: &BulkBroker,
    source: BulkSource,
    cancel: CancellationToken,
) -> Result<(Vec<u8>, Value)> {
    acquire_exact(broker, source, None, cancel).await
}
fn expected_hash(source: &Value) -> Option<&str> {
    string(source, "body_hash")
        .or_else(|| string(source, "oid"))
        .or_else(|| string(source, "sha256"))
}
async fn acquire_exact(
    broker: &BulkBroker,
    source: BulkSource,
    expected: Option<&str>,
    cancel: CancellationToken,
) -> Result<(Vec<u8>, Value)> {
    let url = source.url()?;
    let fixed_git_notice = matches!(
        &source,
        BulkSource::Attribution(
            AttributionSource::Mdn { .. }
                | AttributionSource::RustSec { .. }
                | AttributionSource::Whatwg { .. }
                | AttributionSource::W3c { .. }
        )
    );
    let cache_key = expected
        .map(|hash| format!("{url}#expected={hash}"))
        .or_else(|| fixed_git_notice.then(|| url.clone()));
    if let Some(key) = &cache_key
        && let Some(cached) = broker.attribution_cached(key).await
    {
        return Ok(cached);
    }
    let response = broker
        .open(
            BulkRequest {
                source,
                validators: Validators::default(),
                max_bytes: MAX_SOURCE as u64,
                deadline: Instant::now() + Duration::from_secs(120),
                body: Vec::new(),
            },
            cancel.clone(),
        )
        .await?;
    // No validators are sent by this path: missing evidence always needs 200.
    if matches!(response.status, 404 | 410) {
        return Err(Error::not_found(
            "Exact historical source is no longer available upstream.",
        ));
    }
    if response.status != 200 {
        return Err(incomplete());
    }
    let mut stream = response.stream;
    let mut bytes = Vec::new();
    while let Some(chunk) = tokio::select! {biased;_=cancel.cancelled()=>return Err(Error::new("cancelled","Attribution acquisition canceled.")),v=stream.next()=>v}
    {
        let chunk = chunk?;
        if chunk.len() > MAX_SOURCE.saturating_sub(bytes.len()) {
            return Err(Error::capacity(
                "Attribution source exceeds its byte bound.",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let receipt = json!({"version":1,"source_url":url,"status":200,"body_hash":crate::integrity::hash(&bytes),"validated_at":devres_domain::unix_now(),"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT});
    if let Some(key) = cache_key {
        broker.attribution_cache(&key, &bytes, &receipt).await;
    }
    Ok((bytes, receipt))
}
fn decode_git(bytes: Vec<u8>, expected: Option<&str>) -> Result<Vec<u8>> {
    // GitHub may send its JSON envelope despite the raw-media Accept header.
    let bytes = if let Ok(data) = serde_json::from_slice::<Value>(&bytes) {
        if data["encoding"] == "base64" {
            let content = data["content"].as_str().ok_or_else(incomplete)?;
            let compact = content
                .bytes()
                .filter(|b| !b.is_ascii_whitespace())
                .collect::<Vec<_>>();
            STANDARD
                .decode(compact)
                .map_err(|_| Error::integrity("Malformed Git source encoding."))?
        } else {
            bytes
        }
    } else {
        bytes
    };
    if let Some(expected) = expected
        && (!oid(expected) || crate::chromium::source::object_oid("blob", &bytes) != expected)
    {
        return Err(Error::integrity(
            "Re-requested Git blob does not match retained evidence.",
        ));
    }
    Ok(bytes)
}
fn verify_hash(bytes: &[u8], source: &Value) -> Result<()> {
    if let Some(expected) = string(source, "body_hash") {
        let actual = if expected.starts_with("blake3:") {
            crate::integrity::hash(bytes)
        } else {
            crate::archive::sha256(bytes)
        };
        if actual != expected {
            return Err(Error::integrity(
                "Re-requested source differs from the retained representation.",
            ));
        }
    } else if let Some(expected) = string(source, "sha256") {
        if crate::archive::sha256(bytes) != expected {
            return Err(Error::integrity(
                "Published package checksum differs from acquired bytes.",
            ));
        }
    } else if let Some(expected) = string(source, "oid") {
        if crate::chromium::source::object_oid("blob", bytes) != expected {
            return Err(Error::integrity(
                "Re-requested Git object differs from the retained representation.",
            ));
        }
    } else {
        return Err(incomplete());
    }
    Ok(())
}
fn notice(
    url: &str,
    bytes: &[u8],
    license: Option<String>,
    evidence: Value,
) -> Result<AttributionNotice> {
    if bytes.is_empty() || bytes.len() > MAX_NOTICE {
        return Err(Error::capacity(
            "Required attribution notice exceeds its bound.",
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| incomplete())?;
    if text.contains('\0') {
        return Err(incomplete());
    }
    let copyright = text
        .lines()
        .find(|l| l.to_ascii_lowercase().contains("copyright"))
        .map(str::to_owned);
    Ok(AttributionNotice {
        source_url: url.into(),
        license,
        copyright,
        text: text.into(),
        evidence,
    })
}

/// Re-request exact public evidence and build an immutable notice generation.
/// No generic instruction, guessed SPDX label, or current moving head completes it.
pub async fn repair(
    target: &AttributionTarget,
    broker: &Arc<BulkBroker>,
    cancel: CancellationToken,
) -> Result<AttributionGeneration> {
    let p = provider(&target.subject.provider)?;
    if target.evidence["version"] != 1 {
        return Err(incomplete());
    }
    if let Some(dependencies) = target
        .evidence
        .get("dependencies")
        .and_then(Value::as_array)
    {
        if dependencies.is_empty() || dependencies.len() > 128 {
            return Err(incomplete());
        }
        let mut notices = Vec::new();
        let mut receipts = Vec::new();
        for dependency in dependencies {
            let dependency: AttributionTarget =
                serde_json::from_value(dependency.clone()).map_err(|_| incomplete())?;
            if dependency.evidence.get("dependencies").is_some() {
                return Err(incomplete());
            }
            let generation = Box::pin(repair(&dependency, broker, cancel.child_token())).await?;
            receipts.push(
                json!({"kind":"dependency_generation","target":dependency,"generation":generation}),
            );
            notices.extend(generation.notices);
            receipts.extend(
                generation
                    .receipts
                    .into_iter()
                    .filter(|receipt| receipt["kind"] != "dependency_generation"),
            );
        }
        if notices.len() > 128
            || receipts.len() > 256
            || notices.iter().map(|n| n.text.len()).sum::<usize>() > MAX_NOTICE
        {
            return Err(Error::capacity("Attribution dependency bound exceeded."));
        }
        return Ok(AttributionGeneration {
            subject: target.subject.clone(),
            policy_epoch: ATTRIBUTION_POLICY_EPOCH,
            policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
            notices,
            receipts,
        });
    }
    let source = &target.evidence["source"];
    let source_url = string(source, "source_url").ok_or_else(incomplete)?;
    if inferred_provider(source).is_some_and(|actual| actual != p) {
        return Err(invalid());
    }
    let mut receipts = Vec::new();
    let git_path = source_path(source)
        .ok()
        .filter(|path| git_source(p, source, path).is_ok());
    let notices = if let Some(path) = git_path {
        let operation = git_source(p, source, &path)?;
        let (bytes, receipt) = acquire_exact(
            broker,
            BulkSource::Attribution(operation),
            expected_hash(source),
            cancel.clone(),
        )
        .await?;
        let bytes = decode_git(bytes, string(source, "oid"))?;
        verify_hash(&bytes, source)?;
        receipts.push(receipt);
        let mut paths = license_paths(p, &path, &target.evidence["license"])?;
        if p == "mdn" {
            let scope = target.evidence["license"]
                .get("evidence")
                .unwrap_or(&target.evidence["license"]);
            if string(scope, "notice_path").is_none()
                && string(scope, "license_path").is_none()
                && let AttributionSource::Mdn { compatibility, .. } = git_source(p, source, &path)?
            {
                paths = vec![
                    if compatibility {
                        "LICENSE"
                    } else {
                        "LICENSE.md"
                    }
                    .into(),
                ];
            }
        }
        let mut notices = Vec::new();
        for path in paths {
            let operation = git_source(p, source, &path)?;
            let url = operation.url()?;
            let (bytes, receipt) =
                acquire(broker, BulkSource::Attribution(operation), cancel.clone()).await?;
            let bytes = decode_git(bytes, None)?;
            notices.push(notice(&url,&bytes,None,json!({"version":1,"path":path,"source":source,"body_hash":crate::integrity::hash(&bytes)}))?);
            receipts.push(receipt);
        }
        if let Ok(text) = std::str::from_utf8(&bytes) {
            for original in original_member_notices(text)? {
                notices.push(notice(source_url,original.as_bytes(),None,json!({"version":1,"scope":"original_member_notice","source":source,"body_hash":crate::integrity::hash(original.as_bytes())}))?);
            }
        }
        let record = &target.evidence["record"];
        if let Some(terms) = string(record, "license") {
            let attribution = string(record, "attribution_url")
                .or_else(|| string(record, "url"))
                .unwrap_or(source_url);
            let text = format!(
                "Original advisory attribution: {attribution}\nOriginal advisory license: {terms}"
            );
            notices.push(notice(
                attribution,
                text.as_bytes(),
                Some(terms.into()),
                json!({"version":1,"record":record,"source":source}),
            )?);
        }
        notices
    } else if p == "npm" && string(source, "id").is_some_and(valid_advisory_id) {
        let id = string(source, "id").ok_or_else(incomplete)?;
        let operation = AttributionSource::NpmAdvisory { id: id.into() };
        if operation.url()? != source_url {
            return Err(incomplete());
        }
        let (bytes, receipt) = acquire_exact(
            broker,
            BulkSource::Attribution(operation),
            expected_hash(source),
            cancel.clone(),
        )
        .await?;
        verify_hash(&bytes, source)?;
        receipts.push(receipt);
        let original: Value = serde_json::from_slice(&bytes).map_err(|_| incomplete())?;
        if original["id"] != id {
            return Err(Error::integrity(
                "Re-requested advisory identity differs from retained evidence.",
            ));
        }
        let record = &target.evidence["record"];
        let license = string(record, "license").ok_or_else(incomplete)?;
        let attribution = string(record, "attribution_url")
            .or_else(|| string(record, "url"))
            .ok_or_else(incomplete)?;
        let expected = if id.starts_with("GHSA-") {
            "CC-BY-4.0"
        } else {
            "Apache-2.0"
        };
        if license != expected {
            return Err(incomplete());
        }
        let mut text = format!(
            "Original advisory: {id}\nAttribution: {attribution}\nSource-specific record license: {license}"
        );
        if license == "CC-BY-4.0" {
            text.push_str("\nLicense terms: https://creativecommons.org/licenses/by/4.0/");
        } else {
            text.push_str("\n\n");
            text.push_str(include_str!("../../../deploy/staging/Apache-2.0.txt"));
        }
        vec![notice(
            attribution,
            text.as_bytes(),
            Some(license.into()),
            json!({"version":1,"record":record,"body_hash":crate::integrity::hash(&bytes),"source_url":source_url}),
        )?]
    } else if (p == "crates" || p == "npm") && package_archive_url(source_url) {
        repair_package(p, source, broker, cancel.clone(), &mut receipts).await?
    } else if p == "crates" && source_url.starts_with("https://docs.rs/crate/") {
        repair_documentation(source, broker, cancel.clone(), &mut receipts).await?
    } else if matches!(p, "crates" | "npm") || (p == "rfc" && rfc_source(source_url).is_err()) {
        let (bytes, receipt) = acquire_core(source, broker, cancel.clone()).await?;
        verify_hash(&bytes, source)?;
        receipts.push(receipt);
        if let Some(mut package_notices) =
            metadata_dependencies(p, source, &bytes, broker, cancel.clone(), &mut receipts).await?
        {
            package_notices.insert(0, metadata_notice_inner(p, source_url, &bytes, true)?);
            package_notices
        } else {
            vec![metadata_notice(p, source_url, &bytes)?]
        }
    } else if p == "rfc" {
        let operation = rfc_source(source_url)?;
        let (bytes, receipt) = acquire_exact(
            broker,
            BulkSource::Attribution(operation),
            expected_hash(source),
            cancel.clone(),
        )
        .await?;
        verify_hash(&bytes, source)?;
        receipts.push(receipt);
        let text_source = match rfc_source(source_url)? {
            AttributionSource::Rfc { number, format } if format != "txt" => {
                Some(AttributionSource::Rfc {
                    number,
                    format: "txt".into(),
                })
            }
            _ => None,
        };
        if let Some(text_source) = text_source {
            let url = text_source.url()?;
            let (text, receipt) =
                acquire(broker, BulkSource::Attribution(text_source), cancel.clone()).await?;
            receipts.push(receipt);
            let mut notice = rfc_notice(&url, &text)?;
            notice.evidence["represented_source"] = source.clone();
            vec![notice]
        } else {
            vec![rfc_notice(source_url, &bytes)?]
        }
    } else if p == "w3c" {
        let publication = crate::w3c::catalog::PublicationUrl::new(source_url)?;
        let (bytes, receipt) = acquire_exact(
            broker,
            BulkSource::W3cPublication(publication.clone()),
            expected_hash(source),
            cancel.clone(),
        )
        .await?;
        verify_hash(&bytes, source)?;
        receipts.push(receipt);
        let qualified = crate::w3c::catalog::publication_license(&publication, &bytes);
        if qualified["decision"] != "approved" {
            return Err(incomplete());
        }
        let text = string(&qualified, "notice").ok_or_else(incomplete)?;
        vec![notice(
            source_url,
            text.as_bytes(),
            string(&qualified, "license_url").map(str::to_owned),
            qualified.clone(),
        )?]
    } else if p == "whatwg" {
        let publication = crate::whatwg::catalog::PublicationUrl::new(source_url)?;
        let (bytes, receipt) = acquire_exact(
            broker,
            BulkSource::WhatwgPublication(publication),
            expected_hash(source),
            cancel.clone(),
        )
        .await?;
        verify_hash(&bytes, source)?;
        receipts.push(receipt);
        vec![whatwg_publication_notice(
            source_url,
            &bytes,
            &target.evidence["license"],
            cancel.clone(),
        )?]
    } else if p == "chromium" {
        repair_chromium(
            source,
            &target.evidence["license"],
            broker,
            cancel.clone(),
            &mut receipts,
        )
        .await?
    } else {
        return Err(incomplete());
    };
    if notices.is_empty() || notices.iter().map(|n| n.text.len()).sum::<usize>() > MAX_NOTICE {
        return Err(incomplete());
    }
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "Attribution repair canceled."));
    }
    Ok(AttributionGeneration {
        subject: target.subject.clone(),
        policy_epoch: ATTRIBUTION_POLICY_EPOCH,
        policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
        notices,
        receipts,
    })
}

fn license_paths(p: &str, path: &str, license: &Value) -> Result<Vec<String>> {
    let evidence = license.get("evidence").unwrap_or(license);
    if evidence["decision"]
        .as_str()
        .is_some_and(|s| s != "approved")
    {
        return Err(incomplete());
    }
    // Nested scope must name its actual governing path. A root notice is not a
    // substitute for qualified third-party scope.
    if let Some(notice_path) =
        string(evidence, "notice_path").or_else(|| string(evidence, "license_path"))
    {
        if !crate::archive::valid_relative_path(notice_path) {
            return Err(invalid());
        }
        return Ok(vec![notice_path.into()]);
    }
    let lower = path.to_ascii_lowercase();
    if lower.split('/').any(|s| {
        matches!(
            s,
            "third_party" | "third-party" | "vendor" | "vendors" | "node_modules"
        )
    }) {
        return Err(incomplete());
    }
    Ok(vec![
        match p {
            "mdn" if path.ends_with(".json") => "LICENSE",
            "mdn" => "LICENSE.md",
            "rustsec" => "LICENSE.txt",
            "whatwg" | "w3c" => "LICENSE",
            _ => return Err(incomplete()),
        }
        .into(),
    ])
}
fn rfc_source(value: &str) -> Result<AttributionSource> {
    let tail = value
        .strip_prefix("https://www.rfc-editor.org/rfc/rfc")
        .or_else(|| value.strip_prefix("https://rfc-editor.org/rfc/rfc"))
        .ok_or_else(incomplete)?;
    let (number, format) = tail.split_once('.').ok_or_else(incomplete)?;
    let operation = AttributionSource::Rfc {
        number: number.parse().map_err(|_| invalid())?,
        format: format.into(),
    };
    operation.url()?;
    Ok(operation)
}
fn rfc_notice(url: &str, bytes: &[u8]) -> Result<AttributionNotice> {
    let text = std::str::from_utf8(bytes).map_err(|_| incomplete())?;
    let start = text
        .find("Copyright Notice")
        .or_else(|| text.find("Full Copyright Statement"))
        .ok_or_else(incomplete)?;
    let tail = &text[start..];
    let end = tail
        .find("Table of Contents")
        .or_else(|| tail.find("\n1. "))
        .unwrap_or(tail.len());
    let notice_text = tail[..end].trim();
    if !notice_text.to_ascii_lowercase().contains("copyright") || notice_text.len() < 100 {
        return Err(incomplete());
    }
    notice(
        url,
        notice_text.as_bytes(),
        None,
        json!({"version":1,"source_body_hash":crate::integrity::hash(bytes),"publication_terms":"embedded_versioned_rfc_notice"}),
    )
}
fn qualified_retained_notice(
    url: &str,
    bytes: &[u8],
    license: &Value,
) -> Result<AttributionNotice> {
    let evidence = license.get("evidence").unwrap_or(license);
    if evidence["decision"] != "approved" {
        return Err(incomplete());
    }
    let text = string(evidence, "notice").ok_or_else(incomplete)?;
    // A capped excerpt is never silently accepted as a complete original notice.
    let expected = string(evidence, "notice_hash").ok_or_else(incomplete)?;
    if crate::integrity::hash(text.as_bytes()) != expected {
        return Err(incomplete());
    }
    let source_text = std::str::from_utf8(bytes).map_err(|_| incomplete())?;
    if !source_text.contains(text) {
        return Err(incomplete());
    }
    notice(
        url,
        text.as_bytes(),
        string(evidence, "license_url").map(str::to_owned),
        evidence.clone(),
    )
}

fn package_archive_url(url: &str) -> bool {
    (url.starts_with("https://static.crates.io/crates/") && url.ends_with(".crate"))
        || (url.starts_with("https://registry.npmjs.org/")
            && url.contains("/-/")
            && url.ends_with(".tgz"))
}

async fn acquire_core(
    source: &Value,
    broker: &Arc<BulkBroker>,
    cancel: CancellationToken,
) -> Result<(Vec<u8>, Value)> {
    let url = string(source, "source_url").ok_or_else(incomplete)?;
    let fetcher = crate::HttpFetcher::with_broker(broker.clone())?;
    let request = devres_domain::FetchRequest {
        key: "attribution:exact-public-source".into(),
        url: url.into(),
        ttl_secs: 0,
        max_bytes: MAX_SOURCE,
        media_type: string(source, "media_type")
            .unwrap_or("application/json")
            .into(),
    };
    let response = tokio::select! {biased;_=cancel.cancelled()=>return Err(Error::new("cancelled","Attribution acquisition canceled.")),r=fetcher.fetch(&request,None)=>r?};
    if matches!(response.status, 404 | 410) {
        return Err(Error::not_found(
            "Exact historical source is no longer available upstream.",
        ));
    }
    if response.status != 200 {
        return Err(incomplete());
    }
    let receipt = json!({"version":1,"source_url":url,"status":200,"body_hash":crate::integrity::hash(&response.body),"validated_at":devres_domain::unix_now(),"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT});
    Ok((response.body, receipt))
}

fn metadata_notice(p: &str, url: &str, bytes: &[u8]) -> Result<AttributionNotice> {
    metadata_notice_inner(p, url, bytes, false)
}

async fn metadata_dependencies(
    p: &str,
    source: &Value,
    body: &[u8],
    broker: &Arc<BulkBroker>,
    cancel: CancellationToken,
    receipts: &mut Vec<Value>,
) -> Result<Option<Vec<AttributionNotice>>> {
    if !matches!(p, "crates" | "npm") {
        return Ok(None);
    }
    let document = serde_json::from_slice::<Value>(body).ok();
    let mut selected = BTreeMap::new();
    if let (Some(name), Some(version)) = (string(source, "name"), string(source, "version")) {
        selected.insert((name.to_owned(), version.to_owned()), ());
    } else if let Some(rows) = document.as_ref().and_then(|v| v["crates"].as_array()) {
        for row in rows {
            if let (Some(name), Some(version)) = (string(row, "name"), string(row, "max_version")) {
                selected.insert((name.into(), version.into()), ());
            }
        }
    } else if let Some(rows) = document.as_ref().and_then(|v| v["objects"].as_array()) {
        for row in rows {
            let package = &row["package"];
            if let (Some(name), Some(version)) =
                (string(package, "name"), string(package, "version"))
            {
                selected.insert((name.into(), version.into()), ());
            }
        }
    }
    if selected.is_empty() {
        return Ok(None);
    }
    if selected.len() > 100 {
        return Err(Error::capacity(
            "Metadata package dependency count exceeds its bound.",
        ));
    }
    let mut notices = Vec::new();
    for ((name, version), ()) in selected {
        if p == "crates" {
            let mut record = None;
            if let Ok(text) = std::str::from_utf8(body) {
                for line in text.lines() {
                    if let Ok(row) = serde_json::from_str::<Value>(line)
                        && row["name"] == name
                        && row["vers"] == version
                    {
                        record = Some(row);
                        break;
                    }
                }
            }
            if record.is_none() {
                let index = json!({"source_url":format!("https://index.crates.io/{}",crate::crates_io::packages::sparse_path(&name)?),"media_type":"text/plain"});
                let (bytes, receipt) = acquire_core(&index, broker, cancel.clone()).await?;
                receipts.push(receipt);
                let text = std::str::from_utf8(&bytes).map_err(|_| incomplete())?;
                for line in text.lines() {
                    let row: Value = serde_json::from_str(line).map_err(|_| incomplete())?;
                    if row["name"] == name && row["vers"] == version {
                        record = Some(row);
                        break;
                    }
                }
            }
            let record = record.ok_or_else(incomplete)?;
            let checksum = string(&record, "cksum").ok_or_else(incomplete)?;
            let archive = json!({"source_url":BulkSource::CrateArchive{name:name.clone(),version:version.clone()}.url()?,"sha256":checksum});
            notices.extend(
                repair_package("crates", &archive, broker, cancel.clone(), receipts).await?,
            );
        } else {
            crate::npm::processing::validate_name(&name)?;
            crate::npm::processing::parse_version(&version)?;
            let mut manifest = document
                .as_ref()
                .and_then(|v| v["versions"].get(&version))
                .cloned();
            if manifest.is_none() {
                let metadata = json!({"source_url":crate::npm::source::Operation::Metadata{name:name.clone()}.url()?,"media_type":"application/json"});
                let (bytes, receipt) = acquire_core(&metadata, broker, cancel.clone()).await?;
                receipts.push(receipt);
                let value: Value = serde_json::from_slice(&bytes).map_err(|_| incomplete())?;
                manifest = value["versions"].get(&version).cloned();
            }
            let manifest = manifest.ok_or_else(incomplete)?;
            if manifest["name"] != name || manifest["version"] != version {
                return Err(incomplete());
            }
            let tarball = string(&manifest["dist"], "tarball").ok_or_else(incomplete)?;
            let operation = BulkSource::Npm(crate::npm::source::Operation::Archive {
                name: name.clone(),
                version: version.clone(),
                url: tarball.into(),
            });
            let expected = string(&manifest["dist"], "integrity")
                .or_else(|| string(&manifest["dist"], "shasum"))
                .ok_or_else(incomplete)?;
            let (bytes, mut receipt) =
                acquire_exact(broker, operation, Some(expected), cancel.clone()).await?;
            receipt["published_integrity"] =
                crate::npm::processing::verify_integrity(&bytes, &manifest)?;
            receipts.push(receipt);
            let tarball = tarball.to_owned();
            notices.extend(
                tokio::task::spawn_blocking(move || {
                    package_notices(&bytes, "package", &tarball, None)
                })
                .await
                .map_err(|_| Error::unavailable("Attribution archive worker failed."))??,
            );
        }
        if notices.len() > 128 || notices.iter().map(|n| n.text.len()).sum::<usize>() > MAX_NOTICE {
            return Err(Error::capacity(
                "Metadata package notices exceed their bound.",
            ));
        }
    }
    Ok(Some(notices))
}
fn metadata_notice_inner(
    p: &str,
    url: &str,
    bytes: &[u8],
    qualified_package: bool,
) -> Result<AttributionNotice> {
    let publisher = match p {
        "rfc" => "RFC Editor",
        "crates" => "crates.io",
        "npm" => "npm public registry",
        _ => "docs.rs",
    };
    let mut text = format!(
        "Metadata source: {publisher}\nOriginal source: {url}\nExact representation: {}\nPackage/document content has its separately recorded source notices.",
        crate::integrity::hash(bytes)
    );
    // Package prose is not automatically covered by the API publisher's name.
    // Without its own exact archive/notice dependency it remains withheld.
    let mut originals = Vec::new();
    if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
        originals.push(v);
    } else if p == "crates" {
        let lines = std::str::from_utf8(bytes).map_err(|_| incomplete())?;
        for line in lines.lines().filter(|s| !s.trim().is_empty()) {
            if originals.len() >= 100000 {
                return Err(Error::capacity("Metadata record count bound exceeded."));
            }
            originals.push(serde_json::from_str(line).map_err(|_| incomplete())?);
        }
    } else if p == "npm" {
        return Err(incomplete());
    }
    let mut notices = Vec::new();
    for v in &originals {
        metadata_markings(v, 0, &mut notices, qualified_package)?;
    }
    for original in notices {
        if text.len().saturating_add(original.len()) > MAX_NOTICE {
            return Err(Error::capacity("Metadata notices exceed their byte bound."));
        }
        text.push('\n');
        text.push_str(original);
    }
    notice(
        url,
        text.as_bytes(),
        None,
        json!({"version":1,"scope":"public_metadata_source_attribution","body_hash":crate::integrity::hash(bytes)}),
    )
}

fn metadata_markings<'a>(
    value: &'a Value,
    depth: usize,
    notices: &mut Vec<&'a str>,
    qualified_package: bool,
) -> Result<()> {
    if depth > 24 {
        return Err(Error::capacity("Metadata notice nesting bound exceeded."));
    }
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(
                    key.to_ascii_lowercase().as_str(),
                    "readme"
                        | "description"
                        | "summary"
                        | "details"
                        | "documentation"
                        | "documents"
                        | "abstract"
                        | "abstract_text"
                        | "orig_text"
                        | "correct_text"
                ) && !qualified_package
                    && (value.as_str().is_some_and(|s| !s.is_empty())
                        || value.is_object()
                        || value.is_array())
                {
                    return Err(Error::new(
                        "attribution_blocked",
                        "Copied package prose needs its exact source notice dependency.",
                    ));
                }
                if matches!(
                    key.as_str(),
                    "copyright" | "attribution" | "license_notice" | "notice"
                ) && let Some(text) = value.as_str().filter(|s| !s.is_empty())
                {
                    notices.push(text);
                    if notices.len() > 128 {
                        return Err(Error::capacity("Metadata notice count bound exceeded."));
                    }
                }
                if value.is_object() || value.is_array() {
                    metadata_markings(value, depth + 1, notices, qualified_package)?;
                }
            }
        }
        Value::Array(items) => {
            for value in items {
                metadata_markings(value, depth + 1, notices, qualified_package)?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn repair_documentation(
    source: &Value,
    broker: &Arc<BulkBroker>,
    cancel: CancellationToken,
    receipts: &mut Vec<Value>,
) -> Result<Vec<AttributionNotice>> {
    let url = string(source, "source_url").ok_or_else(incomplete)?;
    let tail = url
        .strip_prefix("https://docs.rs/crate/")
        .ok_or_else(invalid)?;
    let mut parts = tail.split('/');
    let name = parts.next().ok_or_else(invalid)?;
    let version = parts.next().ok_or_else(invalid)?;
    let suffix = parts.collect::<Vec<_>>().join("/");
    use crate::bulk::DocsOperation;
    let operation = match suffix.as_str() {
        "download" => DocsOperation::Html,
        "status.json" => DocsOperation::Status,
        "menus/platforms/" => DocsOperation::Platforms,
        "builds" => DocsOperation::Builds,
        _ => {
            let segments = suffix.split('/').collect::<Vec<_>>();
            if segments.len() != 2 && segments.len() != 3 {
                return Err(invalid());
            }
            if segments[1] == "json.gz" && segments.len() == 2 {
                DocsOperation::Json {
                    target: segments[0].into(),
                    format: None,
                }
            } else if segments[1] == "json" && segments.len() == 3 {
                DocsOperation::Json {
                    target: segments[0].into(),
                    format: Some(
                        segments[2]
                            .strip_suffix(".gz")
                            .ok_or_else(invalid)?
                            .parse()
                            .map_err(|_| invalid())?,
                    ),
                }
            } else {
                return Err(invalid());
            }
        }
    };
    let metadata = matches!(
        operation,
        DocsOperation::Status | DocsOperation::Platforms | DocsOperation::Builds
    );
    let (bytes, receipt) = acquire_exact(
        broker,
        BulkSource::Documentation {
            name: name.into(),
            version: version.into(),
            operation,
        },
        expected_hash(source),
        cancel.clone(),
    )
    .await?;
    verify_hash(&bytes, source)?;
    receipts.push(receipt);
    if metadata {
        return Ok(vec![metadata_notice("docs", url, &bytes)?]);
    }
    let lower = name.to_ascii_lowercase();
    let path = match lower.len() {
        0 => return Err(invalid()),
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", &lower[..1]),
        _ => format!("{}/{}/{lower}", &lower[..2], &lower[2..4]),
    };
    let index =
        json!({"source_url":format!("https://index.crates.io/{path}"),"media_type":"text/plain"});
    let (index, receipt) = acquire_core(&index, broker, cancel.clone()).await?;
    receipts.push(receipt);
    let index = std::str::from_utf8(&index).map_err(|_| incomplete())?;
    let mut checksum = None;
    for line in index.lines() {
        let row: Value = serde_json::from_str(line).map_err(|_| incomplete())?;
        if row["name"]
            .as_str()
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
            && row["vers"] == version
        {
            checksum = string(&row, "cksum").map(str::to_owned);
            break;
        }
    }
    let checksum = checksum.ok_or_else(incomplete)?;
    let archive = json!({"source_url":BulkSource::CrateArchive{name:name.into(),version:version.into()}.url()?,"sha256":checksum});
    repair_package("crates", &archive, broker, cancel, receipts).await
}

fn whatwg_publication_notice(
    url: &str,
    bytes: &[u8],
    retained: &Value,
    cancel: CancellationToken,
) -> Result<AttributionNotice> {
    if let Ok(notice) = qualified_retained_notice(url, bytes, retained) {
        return Ok(notice);
    }
    // WHATWG publication formats have edition-specific notices. Project the
    // fetched original inertly, then retain only actual copyright/license prose.
    let path = url::Url::parse(url)
        .map_err(|_| invalid())?
        .path()
        .to_owned();
    let path = if path.ends_with('/') {
        format!("{path}index.html")
    } else {
        path
    };
    let document = crate::standards_processing::process_document(&path, bytes, cancel)?;
    let text = &document.text;
    let lower = text.to_ascii_lowercase();
    let start = lower.find("copyright").ok_or_else(incomplete)?;
    let tail = &text[start..];
    let end = tail.find("\n\n").filter(|n| *n > 100).unwrap_or(tail.len());
    let original = tail[..end].trim();
    let l = original.to_ascii_lowercase();
    if !(l.contains("whatwg")
        && (l.contains("creative commons") || l.contains("cc by") || l.contains("attribution 4.0")))
    {
        return Err(incomplete());
    }
    notice(
        url,
        original.as_bytes(),
        None,
        json!({"version":1,"scope":"embedded_publication_notice","body_hash":crate::integrity::hash(bytes),"retained_evidence":retained}),
    )
}

async fn repair_package(
    p: &str,
    source: &Value,
    broker: &BulkBroker,
    cancel: CancellationToken,
    receipts: &mut Vec<Value>,
) -> Result<Vec<AttributionNotice>> {
    let url = string(source, "source_url").ok_or_else(incomplete)?;
    let (operation, root) = if p == "crates" {
        let tail = url
            .strip_prefix("https://static.crates.io/crates/")
            .ok_or_else(incomplete)?;
        let (name, file) = tail.split_once('/').ok_or_else(invalid)?;
        let version = file
            .strip_prefix(&format!("{name}-"))
            .and_then(|x| x.strip_suffix(".crate"))
            .ok_or_else(invalid)?;
        (
            BulkSource::CrateArchive {
                name: name.into(),
                version: version.into(),
            },
            format!("{name}-{version}"),
        )
    } else {
        let tail = url
            .strip_prefix("https://registry.npmjs.org/")
            .ok_or_else(incomplete)?;
        let (name, file) = tail.split_once("/-/").ok_or_else(incomplete)?;
        let base = name.rsplit('/').next().ok_or_else(invalid)?;
        let version = file
            .strip_prefix(&format!("{base}-"))
            .and_then(|x| x.strip_suffix(".tgz"))
            .ok_or_else(invalid)?;
        (
            BulkSource::Npm(crate::npm::source::Operation::Archive {
                name: name.into(),
                version: version.into(),
                url: url.into(),
            }),
            "package".into(),
        )
    };
    let (bytes, receipt) = acquire_exact(broker, operation, expected_hash(source), cancel).await?;
    verify_hash(&bytes, source)?;
    receipts.push(receipt);
    let url = url.to_owned();
    let member = string(source, "member_path").map(str::to_owned);
    tokio::task::spawn_blocking(move || package_notices(&bytes, &root, &url, member.as_deref()))
        .await
        .map_err(|_| Error::unavailable("Attribution archive worker failed."))?
}
fn package_notices(
    bytes: &[u8],
    root: &str,
    url: &str,
    selected: Option<&str>,
) -> Result<Vec<AttributionNotice>> {
    let _permit = crate::archive::admit()?;
    // Existing validation checks every member, path, duplicate, link, expansion
    // and entry bound before a notice is inspected. Nothing is extracted.
    crate::archive::inspect(bytes, &crate::archive::sha256(bytes), root, None)?;
    let mut custom = std::collections::BTreeSet::new();
    let mut manifests = tar::Archive::new(flate2::read::MultiGzDecoder::new(bytes));
    for member in manifests.entries().map_err(|_| incomplete())? {
        let mut member = member.map_err(|_| incomplete())?;
        let path = member
            .path()
            .map_err(|_| incomplete())?
            .to_str()
            .ok_or_else(incomplete)?
            .to_owned();
        let name = path.rsplit('/').next().unwrap_or_default();
        if !matches!(name, "Cargo.toml" | "Cargo.toml.orig" | "package.json") {
            continue;
        }
        if member.size() > 4 * 1024 * 1024 {
            return Err(Error::capacity(
                "Package manifest exceeds attribution bounds.",
            ));
        }
        let mut text = String::new();
        member.read_to_string(&mut text).map_err(|_| incomplete())?;
        let declared = if name == "package.json" {
            let value: Value = serde_json::from_str(&text).map_err(|_| incomplete())?;
            string(&value, "license")
                .and_then(|s| s.strip_prefix("SEE LICENSE IN "))
                .map(str::to_owned)
        } else {
            let value: toml::Value = toml::from_str(&text).map_err(|_| incomplete())?;
            value
                .get("package")
                .and_then(|p| p.get("license-file").or_else(|| p.get("license_file")))
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        };
        if let Some(declared) = declared {
            if !crate::archive::valid_relative_path(&declared) {
                return Err(incomplete());
            }
            let parent = path.rsplit_once('/').map(|(p, _)| p).unwrap_or(root);
            custom.insert(format!("{parent}/{declared}"));
            if custom.len() > 128 {
                return Err(Error::capacity("Package notice path bound exceeded."));
            }
        }
    }
    let mut archive = tar::Archive::new(flate2::read::MultiGzDecoder::new(bytes));
    let mut notices = Vec::new();
    let mut total = 0_usize;
    for member in archive.entries().map_err(|_| incomplete())? {
        let mut member = member.map_err(|_| incomplete())?;
        let path = member
            .path()
            .map_err(|_| incomplete())?
            .to_str()
            .ok_or_else(incomplete)?
            .to_owned();
        let name = path
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let custom_notice = custom.remove(&path);
        let is_notice = name.starts_with("license")
            || name.starts_with("licence")
            || name.starts_with("copying")
            || name.starts_with("notice")
            || name == "authors"
            || name == "copyright"
            || custom_notice;
        let selected = selected.is_some_and(|s| path == format!("{root}/{s}"));
        if !is_notice && !selected {
            continue;
        }
        let size = usize::try_from(member.size()).map_err(|_| incomplete())?;
        total = total
            .checked_add(size)
            .filter(|n| *n <= MAX_NOTICE)
            .ok_or_else(|| Error::capacity("Package notices exceed their byte bound."))?;
        let mut text = Vec::with_capacity(size);
        member.read_to_end(&mut text).map_err(|_| incomplete())?;
        if is_notice {
            notices.push(notice(url,&text,None,json!({"version":1,"archive_hash":crate::integrity::hash(bytes),"path":path,"body_hash":crate::integrity::hash(&text)}))?);
        } else if let Ok(text) = std::str::from_utf8(&text)
            && let Some(header) = original_header(text)?
        {
            notices.push(notice(url,header.as_bytes(),None,json!({"version":1,"archive_hash":crate::integrity::hash(bytes),"path":path,"scope":"original_member_header"}))?);
        }
    }
    if !custom.is_empty() {
        return Err(incomplete());
    }
    if notices.is_empty() {
        return Err(incomplete());
    }
    Ok(notices)
}

fn original_header(text: &str) -> Result<Option<&str>> {
    let start = text.trim_start();
    let header = if start.starts_with("/*") {
        let Some(end) = start.find("*/") else {
            return Err(incomplete());
        };
        &start[..end + 2]
    } else if start.starts_with("<!--") {
        let Some(end) = start.find("-->") else {
            return Err(incomplete());
        };
        &start[..end + 3]
    } else {
        let end = start
            .split_inclusive('\n')
            .take_while(|l| {
                l.trim().is_empty()
                    || ["//", "#", ";"]
                        .iter()
                        .any(|p| l.trim_start().starts_with(p))
            })
            .map(str::len)
            .sum::<usize>()
            .min(start.len());
        &start[..end]
    };
    if header.len() > 65536 {
        return Err(Error::capacity(
            "Original member notice exceeds its byte bound.",
        ));
    }
    let lower = header.to_ascii_lowercase();
    Ok((lower.contains("copyright")
        || lower.contains("spdx-license-identifier")
        || lower.contains("licensed under"))
    .then_some(header))
}

fn original_member_notices(text: &str) -> Result<Vec<&str>> {
    let mut notices = std::collections::BTreeSet::new();
    if let Some(header) = original_header(text)? {
        notices.insert(header);
    }
    for (start, end) in [("/*", "*/"), ("<!--", "-->")] {
        let mut cursor = 0;
        while let Some(offset) = text[cursor..].find(start) {
            let begin = cursor + offset;
            let Some(offset) = text[begin + start.len()..].find(end) else {
                break;
            };
            let finish = begin + start.len() + offset + end.len();
            let block = &text[begin..finish];
            let lower = block.to_ascii_lowercase();
            if lower.contains("copyright")
                || lower.contains("spdx-license-identifier")
                || lower.contains("licensed under")
            {
                if block.len() > MAX_NOTICE {
                    return Err(Error::capacity(
                        "Original member notice exceeds its byte bound.",
                    ));
                }
                if [
                    "no redistribution",
                    "no copying",
                    "proprietary",
                    "not licensed for",
                ]
                .iter()
                .any(|term| lower.contains(term))
                {
                    return Err(incomplete());
                }
                notices.insert(block);
            }
            cursor = finish;
            if notices.len() > 128 {
                return Err(Error::capacity("Original member notice count exceeded."));
            }
        }
    }
    if notices.iter().map(|n| n.len()).sum::<usize>() > MAX_NOTICE {
        return Err(Error::capacity(
            "Original member notices exceed their aggregate bound.",
        ));
    }
    Ok(notices.into_iter().collect())
}

async fn repair_chromium(
    source: &Value,
    license: &Value,
    broker: &BulkBroker,
    cancel: CancellationToken,
    receipts: &mut Vec<Value>,
) -> Result<Vec<AttributionNotice>> {
    let source_url = string(source, "source_url").ok_or_else(incomplete)?;
    let parsed = url::Url::parse(source_url).map_err(|_| invalid())?;
    if matches!(
        parsed.host_str(),
        Some("developer.chrome.com" | "www.chromium.org")
    ) {
        let (component, operation) = if parsed.host_str() == Some("developer.chrome.com") {
            (
                "chrome",
                crate::chromium::source::Operation::Page {
                    path: parsed.path().trim_start_matches('/').into(),
                },
            )
        } else {
            (
                "site",
                crate::chromium::source::Operation::SitePage {
                    path: parsed.path().trim_matches('/').into(),
                },
            )
        };
        let (bytes, receipt) = acquire_exact(
            broker,
            BulkSource::Chromium(operation),
            expected_hash(source),
            cancel,
        )
        .await?;
        verify_hash(&bytes, source)?;
        receipts.push(receipt);
        let text = std::str::from_utf8(&bytes).map_err(|_| incomplete())?;
        let qualified = crate::chromium::corpus::attribution_license(component, text, source_url);
        if qualified["decision"] != "approved" {
            return Err(incomplete());
        }
        let text = string(&qualified, "notice").ok_or_else(incomplete)?;
        return Ok(vec![notice(
            source_url,
            text.as_bytes(),
            None,
            json!({"version":1,"complete_notice_hash":crate::integrity::hash(text.as_bytes()),"source_body_hash":crate::integrity::hash(&bytes),"qualification":qualified}),
        )?]);
    }
    let component = string(source, "component").ok_or_else(incomplete)?;
    let revision = string(source, "revision").ok_or_else(incomplete)?;
    let path = source_path(source)?;
    let object = string(source, "oid").ok_or_else(incomplete)?;
    let operation = crate::chromium::source::Operation::Blob {
        component: component.into(),
        revision: revision.into(),
        path,
    };
    let (bytes, receipt) = acquire_exact(
        broker,
        BulkSource::Chromium(operation),
        expected_hash(source),
        cancel.clone(),
    )
    .await?;
    let bytes = crate::chromium::source::decode_blob(component, &bytes, object)?;
    verify_hash(&bytes, source)?;
    receipts.push(receipt);
    let evidence = license.get("evidence").unwrap_or(license);
    if evidence["decision"] != "approved" {
        return Err(incomplete());
    }
    let notice_url = string(evidence, "source_url").ok_or_else(incomplete)?;
    let parsed = url::Url::parse(notice_url).map_err(|_| invalid())?;
    let marker = format!("/+/{revision}/");
    let notice_path = if component == "chrome-archive" {
        string(evidence, "notice_path")
            .or_else(|| string(evidence, "path"))
            .or_else(|| {
                parsed
                    .path()
                    .strip_prefix("/repos/GoogleChrome/developer.chrome.com/contents/")
            })
            .ok_or_else(incomplete)?
    } else {
        parsed
            .path()
            .split_once(&marker)
            .map(|(_, p)| p)
            .ok_or_else(incomplete)?
    };
    let notice_oid = string(evidence, "notice_oid").ok_or_else(incomplete)?;
    let operation = crate::chromium::source::Operation::Blob {
        component: component.into(),
        revision: revision.into(),
        path: notice_path.into(),
    };
    if operation.url()? != notice_url {
        return Err(incomplete());
    }
    let (bytes, receipt) = acquire_exact(
        broker,
        BulkSource::Chromium(operation),
        Some(notice_oid),
        cancel,
    )
    .await?;
    let bytes = crate::chromium::source::decode_blob(component, &bytes, notice_oid)?;
    if let Some(expected) = string(evidence, "notice_hash")
        && crate::integrity::hash(&bytes) != expected
    {
        return Err(Error::integrity(
            "Re-requested notice differs from retained scope evidence.",
        ));
    }
    receipts.push(receipt);
    Ok(vec![notice(notice_url, &bytes, None, evidence.clone())?])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wikipedia_exact_article_evidence_covers_only_its_own_copied_content() {
        let capture = json!({"id":crate::integrity::hash(b"wiki capture"),"page_id":12,"revision_id":34,"representation":"html","source_url":"https://en.wikipedia.org/w/rest.php/v1/page/RISC-V/with_html?redirect=no","body_hash":crate::integrity::hash(b"wiki raw")});
        let document = json!({"title":"RISC-V","capture":capture,"page":{"text":"captured article"},"source_evidence":{"provider":"wikipedia","wikipedia_evidence":capture}});
        let targets = targets("wikipedia", &document).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].subject.provider, "wikipedia");
        let mixed = json!({"results":[{"source":"wikipedia","result":document}]});
        assert_eq!(super::targets("mixed", &mixed).unwrap(), targets);
        let unbound = json!({"items":[document,{"title":"unbound copied title"}]});
        assert!(super::targets("wikipedia", &unbound).is_err());
        let retained = candidate("wikipedia", "captures", "fixture", &capture)
            .unwrap()
            .unwrap();
        assert_eq!(retained, targets[0]);
    }
    #[test]
    fn wikipedia_discovery_exception_rejects_copied_titles() {
        let mut value = json!({"metadata_only_discovery":true,"source":"wikipedia","coverage":"upstream_discovery","items":[{"page_id":12,"fetch_id":"wikipedia:RISC-V","url":"https://en.wikipedia.org/wiki/RISC-V"}]});
        assert!(targets("wikipedia", &value).unwrap().is_empty());
        value["items"][0]["title"] = json!("unqualified copied title");
        assert!(targets("wikipedia", &value).is_err());
    }
    #[test]
    fn exact_git_destinations_reject_traversal_and_moving_revisions() {
        for revision in ["main".into(), "a".repeat(40)] {
            let source = AttributionSource::Mdn {
                compatibility: false,
                revision: revision.clone(),
                path: "../secret".into(),
            };
            assert!(source.url().is_err());
        }
        let source = AttributionSource::Mdn {
            compatibility: true,
            revision: "a".repeat(40),
            path: "LICENSE".into(),
        };
        assert_eq!(
            source.url().unwrap(),
            format!(
                "https://api.github.com/repos/mdn/browser-compat-data/contents/LICENSE?ref={}",
                "a".repeat(40)
            )
        );
    }
    #[test]
    fn identities_ignore_pages_queries_and_private_inventory() {
        let make = |page: &str| json!({"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt","body_hash":format!("blake3:{}","a".repeat(64)),"id":format!("blake3:{}","b".repeat(64)),"page":{"text":page},"query":page,"dependencies":[{"source_url":"https://evil.invalid/private","body_hash":"private"}]});
        let a = targets("rfc", &make("first private text")).unwrap();
        let b = targets("rfc", &make("second private text")).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 1);
        assert!(!serde_json::to_string(&a).unwrap().contains("private"));
    }
    #[test]
    fn resource_and_tool_share_the_exact_subject() {
        let v = json!({"source_url":"https://github.com/mdn/content/blob/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/files/en-us/web/a/index.md","revision":"a".repeat(40),"oid":"b".repeat(40),"path":"files/en-us/web/a/index.md","page":{"text":"excerpt"},"license":{"notice":"actual original"}});
        assert_eq!(
            targets("mdn", &v).unwrap(),
            targets(
                "mdn",
                &json!({"_meta":{"source_evidence":v},"contents":[{"text":"excerpt"}]})
            )
            .unwrap()
        );
    }
    #[test]
    fn every_family_retains_distinct_source_and_notice_scope() {
        for p in [
            "rfc", "crates", "rustsec", "npm", "mdn", "whatwg", "w3c", "chromium",
        ] {
            let v = json!({"source_url":"https://example.org/exact","body_hash":format!("blake3:{}","a".repeat(64)),"license":{"decision":"approved","notice":"actual original notice","notice_path":"vendor/NOTICE"}});
            let found = targets(p, &v).unwrap();
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].subject.provider, p);
            assert_eq!(found[0].evidence["license"]["notice_path"], "vendor/NOTICE");
        }
    }
    #[test]
    fn incomplete_current_urls_and_generic_notices_never_qualify() {
        assert!(targets("mdn",&json!({"source_url":"https://developer.mozilla.org/en-US/docs/A","page":{"text":"x"}})).is_err());
        assert!(
            qualified_retained_notice(
                "https://example.org",
                b"source",
                &json!({"notice":"Preserve original notices"})
            )
            .is_err()
        );
        assert!(license_paths("whatwg", "third_party/a/code.idl", &Value::Null).is_err());
    }
    #[test]
    fn changed_immutable_bytes_and_truncated_notices_fail_closed() {
        assert!(
            verify_hash(
                b"changed",
                &json!({"body_hash":crate::integrity::hash(b"original")})
            )
            .is_err()
        );
        assert!(qualified_retained_notice("https://example.org",b"complete notice",&json!({"decision":"approved","notice":"notice","notice_hash":crate::integrity::hash(b"complete notice")})).is_err());
    }

    #[test]
    fn qualified_sibling_never_covers_unknown_copied_content() {
        let identified = json!({"source":"rfc","result":{"capture":{"id":format!("blake3:{}","a".repeat(64)),"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt","body_hash":crate::integrity::hash(b"original")},"page":{"text":"known"}}});
        let unknown = json!({"source":"unknown","result":{"snippet":"unidentified copied text"}});
        assert!(targets("mixed", &json!({"sources":[identified,unknown]})).is_err());
    }

    #[test]
    fn different_member_scope_produces_different_qualification_subject() {
        let make = |notice: &str| json!({"source_url":"https://github.com/mdn/content/blob/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/files/en-us/web/a/index.md","oid":"b".repeat(40),"license":{"notice":notice}});
        let a = targets("mdn", &make("first scope")).unwrap();
        let b = targets("mdn", &make("other scope")).unwrap();
        assert_ne!(a[0].subject.fingerprint, b[0].subject.fingerprint);
        assert_eq!(
            a[0].subject.fingerprint,
            crate::integrity::canonical_hash(&a[0].evidence).unwrap()
        );
    }

    #[test]
    fn original_headers_are_exact_utf8_crlf_and_never_truncated() {
        let input = "// Copyright © 原作者\r\n// SPDX-License-Identifier: MIT\r\nfn main() {}";
        assert_eq!(
            original_header(input).unwrap(),
            Some("// Copyright © 原作者\r\n// SPDX-License-Identifier: MIT\r\n")
        );
        assert!(original_header(&format!("/* Copyright {} */", "é".repeat(40000))).is_err());
    }

    fn archive_fixture(entries: &[(&str, &str)]) -> Vec<u8> {
        use flate2::{Compression, write::GzEncoder};
        let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (path, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, path, body.as_bytes())
                .unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn declared_custom_notice_must_exist_even_if_another_license_is_present() {
        let bytes = archive_fixture(&[
            (
                "example-1.0.0/Cargo.toml",
                "[package]\nname='example'\nversion='1.0.0'\nlicense-file='legal/terms.txt'\n",
            ),
            ("example-1.0.0/LICENSE", "Unrelated root license"),
        ]);
        assert!(
            package_notices(
                &bytes,
                "example-1.0.0",
                "https://static.crates.io/crates/example/example-1.0.0.crate",
                None
            )
            .is_err()
        );
    }

    #[test]
    fn retained_mdn_history_maps_parent_and_current_member_revisions() {
        let member = |object: &str| json!({"path":"files/en-us/web/a/index.md","oid":object,"kind":"document","raw":{"repository":"content","source_path":"files/en-us/web/a/index.md","oid":object}});
        let row = json!({"repository":"content","revision":"a".repeat(40),"parent":"b".repeat(40),"path":"files/en-us/web/a/index.md","before":member(&"c".repeat(40)),"after":member(&"d".repeat(40))});
        let target = candidate("mdn", "history", "history-occurrence", &row)
            .unwrap()
            .unwrap();
        let dependencies = target.evidence["dependencies"].as_array().unwrap();
        assert_eq!(dependencies.len(), 2);
        let urls = dependencies
            .iter()
            .map(|d| d["evidence"]["source"]["source_url"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(
            urls.iter()
                .any(|u| u.contains(&format!("/blob/{}/", "a".repeat(40))))
        );
        assert!(
            urls.iter()
                .any(|u| u.contains(&format!("/blob/{}/", "b".repeat(40))))
        );
    }

    #[test]
    fn retained_recipe_is_policy_bound_and_matches_the_original_occurrence() {
        let data = json!({"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt","body_hash":crate::integrity::hash(b"original")});
        let evidence = json!({"table":"devres_captures","kind":"capture","key":"original-occurrence","data":data});
        let raw = AttributionTarget {
            subject: AttributionSubject {
                provider: "rfc".into(),
                namespace: "retained".into(),
                key: "original-occurrence".into(),
                fingerprint: crate::integrity::canonical_hash(&evidence).unwrap(),
            },
            evidence,
        };
        let expected = candidate("rfc", "capture", "original-occurrence", &data).unwrap();
        assert_eq!(
            retained_target(
                ATTRIBUTION_POLICY_EPOCH,
                ATTRIBUTION_POLICY_FINGERPRINT,
                &raw
            )
            .unwrap(),
            expected
        );
        assert!(retained_target(2, ATTRIBUTION_POLICY_FINGERPRINT, &raw).is_err());
        assert!(retained_target(1, "other-manifest", &raw).is_err());
    }

    #[test]
    fn retained_npm_projection_uses_the_exact_published_archive() {
        let row = json!({"name":"@scope/example","version":"1.0.0","artifact":{"body_hash":crate::integrity::hash(b"archive"),"bytes":7},"members":[],"contracts":{},"release":"retained-release"});
        let target = candidate("npm", "package-projections", "projection-occurrence", &row)
            .unwrap()
            .unwrap();
        assert_eq!(
            target.evidence["source"]["source_url"],
            "https://registry.npmjs.org/@scope/example/-/example-1.0.0.tgz"
        );
        assert_eq!(
            target.evidence["source"]["body_hash"],
            crate::integrity::hash(b"archive")
        );
    }

    #[test]
    fn chromium_member_output_does_not_create_an_incomplete_citation_sibling() {
        let output = json!({"selection":{"component":"src","revision":"a".repeat(40)},"path":"docs/example.md","source_metadata":{"component":"src","revision":"a".repeat(40),"source_path":"docs/example.md"},"citation":{"source_url":format!("https://chromium.googlesource.com/chromium/src/+/{}/docs/example.md","a".repeat(40)),"revision":"a".repeat(40),"path":"docs/example.md","object_hash":"b".repeat(40)},"page":{"text":"exact excerpt"},"license":{"evidence":{"decision":"approved","notice":"retained original"}}});
        let found = targets("chromium", &output).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].evidence["source"]["component"], "src");
    }

    #[test]
    fn resource_item_wrapper_retains_the_generic_capture_source() {
        let capture = json!({"id":format!("blake3:{}","a".repeat(64)),"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt","body_hash":crate::integrity::hash(b"original")});
        let output = json!({"contents":[{"text":"excerpt","_meta":{"source_evidence":{"capture":capture,"source_key":"rfc:text:9000"}}}]});
        let found = targets("capture", &output).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].subject.provider, "rfc");
    }

    #[test]
    fn nested_package_prose_cannot_inherit_only_the_api_publishers_name() {
        for payload in [
            json!({"versions":{"1.0.0":{"description":"Original package prose"}}}),
            json!({"readme":"Package authors' original README"}),
            json!({"documents":[{"text":"Original document"}]}),
        ] {
            assert!(
                metadata_notice(
                    "npm",
                    "https://registry.npmjs.org/example",
                    &serde_json::to_vec(&payload).unwrap()
                )
                .is_err()
            );
        }
        let body=serde_json::to_vec(&json!({"name":"example","version":"1.0.0","nested":{"license_notice":"Actual required metadata notice"}})).unwrap();
        let notice = metadata_notice("npm", "https://registry.npmjs.org/example", &body).unwrap();
        assert!(notice.text.contains("Actual required metadata notice"));
    }

    #[tokio::test]
    async fn immutable_repair_reuses_one_successful_upstream_receipt_per_policy() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let body = "RFC 9000\n\nCopyright Notice\nCopyright (c) IETF Trust and the persons identified as the document authors. All rights reserved. This document is subject to the versioned provisions identified in the original publication.\n\nTable of Contents\n1. Introduction\n";
        let app = axum::Router::new().fallback(move || {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                body
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let stop = CancellationToken::new();
        let done = stop.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(done.cancelled_owned())
                .await
                .unwrap();
        });
        let broker = Arc::new(
            BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap()).unwrap(),
        );
        let value = json!({"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt","body_hash":crate::integrity::hash(body.as_bytes()),"page":{"text":"selected excerpt"}});
        let target = targets("rfc", &value).unwrap().pop().unwrap();
        let first = repair(&target, &broker, CancellationToken::new())
            .await
            .unwrap();
        let second = repair(&target, &broker, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(first.receipts, second.receipts);
        assert!(first.notices[0].text.contains("IETF Trust"));
        stop.cancel();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn same_url_with_new_expected_hash_requires_another_upstream_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let first = "RFC first version\nCopyright Notice\nCopyright (c) IETF Trust and the persons identified as the document authors. All rights reserved. The original publication carries its applicable versioned legal provisions.\nTable of Contents\n";
        let second = "RFC second version\nCopyright Notice\nCopyright (c) IETF Trust and the persons identified as the document authors. All rights reserved. The original publication carries its applicable versioned legal provisions.\nTable of Contents\n";
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let app = axum::Router::new().fallback(move || {
            let seen = seen.clone();
            async move {
                if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                    first
                } else {
                    second
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let stop = CancellationToken::new();
        let done = stop.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(done.cancelled_owned())
                .await
                .unwrap();
        });
        let broker = Arc::new(
            BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap()).unwrap(),
        );
        for body in [first, second] {
            let value = json!({"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt","body_hash":crate::integrity::hash(body.as_bytes()),"page":{"text":"selected excerpt"}});
            let target = targets("rfc", &value).unwrap().pop().unwrap();
            let generation = repair(&target, &broker, CancellationToken::new())
                .await
                .unwrap();
            assert_eq!(
                generation.receipts[0]["body_hash"],
                crate::integrity::hash(body.as_bytes())
            );
        }
        assert_eq!(count.load(Ordering::SeqCst), 2);
        stop.cancel();
        server.await.unwrap();
    }

    #[test]
    fn npm_document_tool_and_resource_item_normalize_the_same_archive() {
        let origin = json!({"name":"example","version":"1.0.0","path":"README.md","provenance":{"archive":{"body_hash":crate::integrity::hash(b"archive"),"bytes":7},"metadata":"exact-release"},"page":{"text":"copied package prose"}});
        let mut evidence = origin.clone();
        evidence.as_object_mut().unwrap().remove("page");
        let resource = json!({"contents":[{"text":"copied package prose","_meta":{"source_evidence":evidence}}]});
        assert_eq!(
            targets("npm", &origin).unwrap(),
            targets("npm", &resource).unwrap()
        );
    }
}
