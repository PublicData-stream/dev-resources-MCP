//! Bounded OSV import and crates.io SEMVER matching. No resolution or network I/O.
use devres_application::advisory::AdvisoryRecord;
use devres_domain::{Error, Result};
use semver::Version;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, collections::BTreeSet};

const MAX_RECORD: usize = 1024 * 1024;
const MAX_AFFECTED: usize = 1024;
const MAX_ITEMS: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MatchResult {
    pub matched: bool,
    pub complete: bool,
}

fn original(value: &Value) -> &Value {
    value.get("original").unwrap_or(value)
}

fn supported_schema(value: &Value) -> bool {
    match value.get("schema_version") {
        None => true, // OSV specifies 1.0.0 when this field is omitted.
        Some(Value::String(version)) => Version::parse(version).is_ok_and(|v| v.major == 1),
        _ => false,
    }
}

fn timestamp(value: &Value) -> bool {
    let Some(text) = value
        .as_str()
        .filter(|text| text.len() <= 128 && text.is_ascii())
    else {
        return false;
    };
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    let number = |start, end| {
        text.get(start..end)
            .filter(|part| part.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|part| part.parse::<u32>().ok())
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
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
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
        if end == start {
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

fn metadata_known(value: &Value) -> bool {
    value.get("modified").is_some_and(timestamp)
        && ["published", "withdrawn"]
            .into_iter()
            .all(|key| value.get(key).is_none_or(|v| v.is_null() || timestamp(v)))
        && ["summary", "details"]
            .into_iter()
            .all(|key| value.get(key).is_none_or(Value::is_string))
        && string_list(value.get("aliases")).is_some()
        && value.get("database_specific").is_none_or(|v| {
            v.is_object()
                && v.get("informational").is_none_or(|v| {
                    v.is_null() || v.as_str().is_some_and(|v| !v.is_empty() && v.len() <= 256)
                })
        })
}

pub(crate) fn normalize(path: &str, body: &str) -> Result<AdvisoryRecord> {
    if body.len() > MAX_RECORD {
        return Err(Error::capacity("OSV advisory exceeds 1 MiB."));
    }
    let record: Value =
        serde_json::from_str(body).map_err(|_| Error::integrity("Malformed OSV advisory JSON."))?;
    if !record.is_object() || !supported_schema(&record) {
        return Err(Error::integrity("Unsupported OSV advisory schema."));
    }
    let id = record["id"]
        .as_str()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 256
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
        .ok_or_else(|| Error::integrity("Invalid OSV advisory identity."))?;
    let affected = record["affected"]
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= MAX_AFFECTED)
        .ok_or_else(|| Error::integrity("Invalid OSV affected-package inventory."))?;
    let mut packages = BTreeSet::new();
    for entry in affected {
        if entry.pointer("/package/ecosystem").and_then(Value::as_str) == Some("crates.io") {
            let name = entry
                .pointer("/package/name")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::integrity("Invalid OSV package identity."))?;
            crate::cargo::validate_name(name)
                .map_err(|_| Error::integrity("Invalid OSV package identity."))?;
            packages.insert(name.to_owned());
        }
    }
    let package = packages
        .first()
        .cloned()
        .ok_or_else(|| Error::integrity("OSV record contains no supported crates.io package."))?;
    let mut metadata = summary(&record);
    metadata["packages"] = json!(packages);
    let probe = Version::new(0, 0, 0);
    metadata["matching_complete"] = json!(
        packages
            .iter()
            .all(|name| matches(&record, name, &probe).complete)
    );
    metadata["original"] = record.clone();
    Ok(AdvisoryRecord {
        id: id.to_owned(),
        package,
        format: "osv".into(),
        path: path.into(),
        body: body.into(),
        body_hash: hex::encode(Sha256::digest(body.as_bytes())),
        metadata,
    })
}

fn string_list(value: Option<&Value>) -> Option<Vec<String>> {
    match value {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) if items.len() <= MAX_ITEMS => items
            .iter()
            .map(|item| {
                item.as_str()
                    .filter(|v| !v.is_empty() && v.len() <= 1024)
                    .map(str::to_owned)
            })
            .collect(),
        _ => None,
    }
}

fn platform_known(entry: &Value) -> bool {
    let Some(ecosystem) = entry.get("ecosystem_specific") else {
        return true;
    };
    if !ecosystem.is_object() {
        return false;
    }
    let Some(affects) = ecosystem.get("affects") else {
        return true;
    };
    if !affects.is_object() {
        return false;
    }
    ["os", "arch"]
        .into_iter()
        .all(|field| match affects.get(field) {
            None => true,
            Some(Value::Array(items)) if items.len() <= MAX_ITEMS => items.iter().all(|item| {
                item.as_str()
                    .is_some_and(|text| !text.is_empty() && text.len() <= 1024)
            }),
            _ => false,
        })
}

/// A research projection, retaining absent values rather than manufacturing fixes.
pub(crate) fn summary(value: &Value) -> Value {
    summary_selected(value, None, None)
}

/// Classification is specific to the package and affected version. A notice for
/// one affected block must not hide a vulnerability in another block.
pub(crate) fn summary_for_match(value: &Value, name: &str, version: &Version) -> Value {
    summary_selected(value, Some(name), Some(version))
}

fn summary_selected(
    value: &Value,
    selected_name: Option<&str>,
    selected_version: Option<&Version>,
) -> Value {
    let value = original(value);
    let affected = value["affected"].as_array();
    let mut categories = BTreeSet::new();
    let mut packages = BTreeSet::new();
    let mut os = BTreeSet::new();
    let mut arch = BTreeSet::new();
    let mut unrestricted_os = false;
    let mut unrestricted_arch = false;
    let mut applicability_known = affected.is_some();
    let global_informational = value
        .pointer("/database_specific/informational")
        .and_then(Value::as_str);
    let mut informational_kinds = BTreeSet::new();
    let mut has_active_block = false;
    let mut functions = Vec::new();
    if let Some(items) = affected {
        for entry in items.iter().take(MAX_AFFECTED) {
            if entry.pointer("/package/ecosystem").and_then(Value::as_str) != Some("crates.io") {
                continue;
            }
            if selected_name.is_some_and(|name| {
                entry.pointer("/package/name").and_then(Value::as_str) != Some(name)
            }) || selected_version
                .is_some_and(|version| !affected_matches(entry, version).matched)
            {
                continue;
            }
            if let Some(name) = entry.pointer("/package/name").and_then(Value::as_str) {
                packages.insert(name);
            }
            if let Some(values) = string_list(entry.pointer("/database_specific/categories")) {
                categories.extend(values);
            }
            if let Some(kind) = global_informational.or_else(|| {
                entry
                    .pointer("/database_specific/informational")
                    .and_then(Value::as_str)
            }) {
                informational_kinds.insert(kind);
            } else {
                has_active_block = true;
            }
            let ecosystem = entry.get("ecosystem_specific");
            let affects = ecosystem.and_then(|v| v.get("affects"));
            applicability_known &= platform_known(entry);
            for (field, set, unrestricted) in [
                ("os", &mut os, &mut unrestricted_os),
                ("arch", &mut arch, &mut unrestricted_arch),
            ] {
                match string_list(affects.and_then(|v| v.get(field))) {
                    Some(values) if values.is_empty() => *unrestricted = true,
                    Some(values) => set.extend(values),
                    None => applicability_known = false,
                }
            }
            if let Some(items) = affects.and_then(|v| v.get("functions")) {
                functions.push(items.clone());
            }
            if let Some(items) = entry.pointer("/ecosystem_specific/affected_functions") {
                functions.push(items.clone());
            }
        }
        if items.len() > MAX_AFFECTED {
            applicability_known = false;
        }
    }
    if unrestricted_os {
        os.clear();
    }
    if unrestricted_arch {
        arch.clear();
    }
    let informational = if has_active_block {
        None
    } else {
        informational_kinds.first().copied()
    };
    let withdrawn = value.get("withdrawn").filter(|v| timestamp(v));
    let classification = if withdrawn.is_some() {
        "withdrawn"
    } else if informational.is_some() {
        "informational"
    } else {
        "vulnerability"
    };
    let references = value["references"].as_array();
    let source_attribution = value
        .pointer("/database_specific/url")
        .filter(|v| v.is_string())
        .cloned()
        .or_else(|| {
            references.and_then(|items| {
                items.iter().find_map(|item| {
                    item.get("url")
                        .and_then(Value::as_str)
                        .filter(|url| url.starts_with("https://github.com/advisories/GHSA-"))
                        .map(|url| json!(url))
                })
            })
        })
        .unwrap_or(Value::Null);
    let attribution = value["references"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["type"] == "ADVISORY"))
        .and_then(|item| item.get("url"))
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "id": value["id"], "package": packages.first(), "packages": packages,
        "title": value.get("summary").unwrap_or(&Value::Null), "classification": classification,
        "date": value.get("published").and_then(Value::as_str).and_then(|s| s.get(..10)),
        "published":value["published"], "modified":value["modified"], "withdrawn":value["withdrawn"],
        "informational":informational, "informational_kinds":informational_kinds,
        "aliases":value.get("aliases").cloned().unwrap_or(json!([])),
        "categories":categories, "affected":{"os":os,"arch":arch,"functions":functions},
        "applicability_known":applicability_known, "patched":Value::Null,"unaffected":Value::Null,
        "url":attribution, "attribution_url":source_attribution,
        "license":value.pointer("/database_specific/license").unwrap_or(&Value::Null),
        "severity":value.get("severity").cloned().unwrap_or(json!([])), "format":"osv"
    })
}

/// Only default crates.io package identities are admitted by the caller. This
/// function additionally checks each OSV package ecosystem and exact name.
pub(crate) fn matches(value: &Value, name: &str, version: &Version) -> MatchResult {
    let value = original(value);
    let mut result = MatchResult {
        matched: false,
        complete: supported_schema(value) && metadata_known(value),
    };
    let Some(affected) = value["affected"].as_array() else {
        result.complete = false;
        return result;
    };
    if affected.is_empty() || affected.len() > MAX_AFFECTED {
        result.complete = false;
    }
    for entry in affected.iter().take(MAX_AFFECTED) {
        let (Some(ecosystem), Some(package)) = (
            entry.pointer("/package/ecosystem").and_then(Value::as_str),
            entry.pointer("/package/name").and_then(Value::as_str),
        ) else {
            result.complete = false;
            continue;
        };
        if ecosystem != "crates.io" || package != name {
            continue;
        }
        let matched = affected_matches(entry, version);
        result.matched |= matched.matched;
        result.complete &= matched.complete;
    }
    result
}

fn affected_matches(entry: &Value, version: &Version) -> MatchResult {
    let mut result = MatchResult {
        matched: false,
        complete: platform_known(entry),
    };
    result.complete &= entry.get("database_specific").is_none_or(|v| {
        v.is_object()
            && v.get("informational").is_none_or(|v| {
                v.is_null() || v.as_str().is_some_and(|v| !v.is_empty() && v.len() <= 256)
            })
    });
    let mut has_constraint = false;
    if let Some(versions) = entry.get("versions") {
        match versions.as_array() {
            Some(items) if items.len() <= MAX_ITEMS => {
                has_constraint |= !items.is_empty();
                for item in items {
                    match item.as_str().and_then(|v| Version::parse(v).ok()) {
                        Some(candidate) => {
                            result.matched |= candidate.cmp_precedence(version) == Ordering::Equal
                        }
                        None => result.complete = false,
                    }
                }
            }
            _ => result.complete = false,
        }
    }
    if let Some(ranges) = entry.get("ranges") {
        match ranges.as_array() {
            Some(items) if items.len() <= MAX_ITEMS => {
                has_constraint |= !items.is_empty();
                for range in items {
                    if range["type"] != "SEMVER" {
                        result.complete = false;
                        continue;
                    }
                    let matched = range_matches(range, version);
                    result.matched |= matched.matched;
                    result.complete &= matched.complete;
                }
            }
            _ => result.complete = false,
        }
    }
    if !has_constraint {
        result.complete = false;
    }
    result
}

/// Follow OSV's Evaluation algorithm: limits are a separate global OR predicate,
/// while non-limit events are evaluated in semantic precedence order. Inputs need
/// not be sorted or alternate introduction/fix events. See the authoritative OSV
/// schema's `affected[].ranges[].events` requirements and Evaluation section.
fn range_matches(range: &Value, version: &Version) -> MatchResult {
    let incomplete = MatchResult {
        matched: false,
        complete: false,
    };
    let Some(events) = range["events"]
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= MAX_ITEMS)
    else {
        return incomplete;
    };
    // Event kinds: introduction=0, fixed=1, last_affected=2. An introduction's
    // special "0" boundary is None and precedes every semantic version.
    let mut timeline: Vec<(Option<Version>, u8)> = Vec::new();
    let mut has_introduction = false;
    let mut has_fixed = false;
    let mut has_last_affected = false;
    let mut has_limit = false;
    let mut before_limits = false;
    for event in events {
        let Some(fields) = event.as_object().filter(|fields| fields.len() == 1) else {
            return incomplete;
        };
        let Some((kind, raw)) = fields.iter().next() else {
            return incomplete;
        };
        let Some(raw) = raw.as_str() else {
            return incomplete;
        };
        if kind == "introduced" && raw == "0" {
            has_introduction = true;
            timeline.push((None, 0));
            continue;
        }
        if kind == "limit" && raw.contains('*') {
            has_limit = true;
            before_limits = true;
            continue;
        }
        let Ok(boundary) = Version::parse(raw) else {
            return incomplete;
        };
        match kind.as_str() {
            "introduced" => {
                has_introduction = true;
                timeline.push((Some(boundary), 0));
            }
            "fixed" => {
                has_fixed = true;
                timeline.push((Some(boundary), 1));
            }
            "last_affected" => {
                has_last_affected = true;
                timeline.push((Some(boundary), 2));
            }
            "limit" => {
                has_limit = true;
                before_limits |= version.cmp_precedence(&boundary) == Ordering::Less;
            }
            _ => return incomplete,
        }
    }
    if !has_introduction || has_fixed && has_last_affected {
        return incomplete;
    }
    let boundary_order = |a: &Option<Version>, b: &Option<Version>| match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(a), Some(b)) => a.cmp_precedence(b),
    };
    timeline.sort_by(|a, b| boundary_order(&a.0, &b.0).then_with(|| a.1.cmp(&b.1)));
    // Equal introduction/fix boundaries can encode empty [v,v) intervals. Such
    // pairs are usable when balanced; an already-open interval needs its own
    // closing event. Otherwise a shared boundary may instead mean closing one
    // range and reopening another, whose ambiguous order must remain a gap.
    let mut open = false;
    let mut start = 0;
    while start < timeline.len() {
        let mut end = start + 1;
        while end < timeline.len()
            && boundary_order(&timeline[start].0, &timeline[end].0) == Ordering::Equal
        {
            end += 1;
        }
        let group = &timeline[start..end];
        let introduced = group.iter().filter(|(_, kind)| *kind == 0).count();
        let fixed = group.iter().filter(|(_, kind)| *kind == 1).count();
        if introduced > 0 && fixed > 0 && fixed != introduced + usize::from(open) {
            return incomplete;
        }
        if introduced > 0 {
            open = true;
        }
        if group.iter().any(|(_, kind)| *kind != 0) {
            open = false;
        }
        start = end;
    }
    let mut matched = false;
    for (boundary, kind) in timeline {
        let order = boundary
            .as_ref()
            .map_or(Ordering::Greater, |bound| version.cmp_precedence(bound));
        match kind {
            0 if order != Ordering::Less => matched = true,
            1 if order != Ordering::Less => matched = false,
            2 if order == Ordering::Greater => matched = false,
            _ => {}
        }
    }
    MatchResult {
        matched: matched && (!has_limit || before_limits),
        complete: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(events: Value) -> Value {
        json!({"id":"RUSTSEC-2024-0001", "published":"2024-01-01T00:00:00Z", "modified":"2024-01-02T00:00:00Z",
            "summary":"Synthetic fixture", "affected":[{"package":{"ecosystem":"crates.io","name":"example"},
            "ranges":[{"type":"SEMVER","events":events}]}]})
    }
    fn matched(record: &Value, version: &str) -> MatchResult {
        matches(record, "example", &Version::parse(version).unwrap())
    }
    #[test]
    fn semver_interval_boundaries_and_disjoint_ranges() {
        let mut record = record(json!([{"introduced":"1.0.0"},{"fixed":"1.2.0"},
            {"introduced":"2.0.0"},{"fixed":"2.1.1"}]));
        record["affected"][0]["ranges"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"SEMVER",
            "events":[{"introduced":"3.0.0"},{"limit":"3.2.0"}]}));
        for version in ["1.0.0", "1.1.9", "2.0.0", "2.1.0", "3.0.0", "3.1.9"] {
            assert_eq!(
                matched(&record, version),
                MatchResult {
                    matched: true,
                    complete: true
                },
                "{version}"
            );
        }
        for version in ["0.9.9", "1.2.0", "2.1.1", "3.2.0"] {
            assert_eq!(
                matched(&record, version),
                MatchResult {
                    matched: false,
                    complete: true
                },
                "{version}"
            );
        }
    }
    #[test]
    fn zero_open_ranges_prereleases_and_build_metadata() {
        let record =
            record(json!([{"introduced":"0"},{"fixed":"1.0.0"},{"introduced":"2.0.0-alpha.1"}]));
        for version in [
            "0.0.0-0",
            "0.0.0",
            "1.0.0-rc.1",
            "2.0.0-alpha.1",
            "2.0.0",
            "9.0.0+build",
        ] {
            assert!(matched(&record, version).matched, "{version}");
        }
        for version in ["1.0.0", "2.0.0-alpha.0"] {
            assert!(!matched(&record, version).matched, "{version}");
        }
    }
    #[test]
    fn explicit_versions_and_multiple_affected_blocks_are_unioned() {
        let mut value = record(json!([{"introduced":"1.0.0"},{"fixed":"1.1.0"}]));
        value["affected"].as_array_mut().unwrap().push(
            json!({"package":{"ecosystem":"crates.io","name":"example"},"versions":["3.0.0-rc.1"]}),
        );
        assert!(matched(&value, "1.0.1").matched);
        assert!(matched(&value, "3.0.0-rc.1").matched);
        assert!(!matched(&value, "3.0.0").matched);
        value["affected"][1]["versions"] = json!(["1.1.0+other"]);
        assert!(matched(&value, "1.1.0+build").matched);
    }
    #[test]
    fn last_affected_can_describe_a_single_version() {
        let value = record(json!([{"introduced":"1.0.0"},{"last_affected":"1.0.0"}]));
        assert_eq!(
            matched(&value, "1.0.0"),
            MatchResult {
                matched: true,
                complete: true
            }
        );
        assert_eq!(
            matched(&value, "1.0.1"),
            MatchResult {
                matched: false,
                complete: true
            }
        );
    }
    #[test]
    fn observed_zero_width_event_shapes_preserve_real_affected_intervals() {
        // Synthetic metadata with the event shapes observed in the official OSV
        // export. These are matcher fixtures, not complete provider captures.
        type Case<'a> = (&'a str, &'a str, Value, &'a [&'a str], &'a [&'a str]);
        let cases: [Case<'_>; 5] = [
            (
                "RUSTSEC-2022-0012",
                "arrow2",
                json!([{"introduced":"0.0.0-0"},{"fixed":"0.7.1"},{"introduced":"0.8.0"},{"fixed":"0.8.2"},{"introduced":"0.9.0"},{"fixed":"0.9.2"},{"introduced":"0.10.0"},{"fixed":"0.10.0"}]),
                &["0.0.0-0", "0.7.0", "0.8.0", "0.8.1", "0.9.1"],
                &["0.7.1", "0.8.2", "0.9.2", "0.10.0", "0.10.1"],
            ),
            (
                "RUSTSEC-2023-0039",
                "buffered-reader",
                json!([{"introduced":"0"},{"fixed":"1.0.2"},{"introduced":"1.1.0"},{"fixed":"1.1.5"},{"introduced":"1.2.0"},{"fixed":"1.2.0"}]),
                &["0.0.0-0", "1.0.1", "1.1.0", "1.1.4"],
                &["1.0.2", "1.1.5", "1.2.0", "1.3.0"],
            ),
            (
                "RUSTSEC-2024-0399",
                "rustls",
                json!([{"introduced":"0.23.0"},{"fixed":"0.23.0"},{"introduced":"0.23.13"},{"fixed":"0.23.18"}]),
                &["0.23.13", "0.23.17"],
                &["0.22.99", "0.23.0", "0.23.1", "0.23.12", "0.23.18"],
            ),
            (
                "RUSTSEC-2026-0149",
                "wasmtime-wasi",
                json!([{"introduced":"0"},{"fixed":"24.0.9"},{"introduced":"25.0.0"},{"fixed":"36.0.10"},{"introduced":"37.0.0"},{"fixed":"44.0.2"},{"introduced":"45.0.0"},{"fixed":"45.0.0"}]),
                &["23.0.0", "24.0.8", "25.0.0", "36.0.9", "37.0.0", "44.0.1"],
                &[
                    "24.0.9", "24.1.0", "36.0.10", "36.9.9", "44.0.2", "45.0.0", "46.0.0",
                ],
            ),
            (
                "RUSTSEC-2026-0276",
                "apimock",
                json!([{"introduced":"0"},{"fixed":"4.8.1"},{"introduced":"5.0.0"},{"fixed":"5.0.0"}]),
                &["4.0.0", "4.8.0"],
                &["4.8.1", "4.9.0", "5.0.0", "5.1.0"],
            ),
        ];
        for (id, name, events, affected, unaffected) in cases {
            let mut value = record(events);
            value["id"] = json!(id);
            value["summary"] = json!("Synthetic metadata using observed OSV event shape");
            value["affected"][0]["package"]["name"] = json!(name);
            let normalized = normalize(&format!("crates/{id}.json"), &value.to_string()).unwrap();
            assert_eq!(normalized.metadata["matching_complete"], true, "{id}");
            for version in affected {
                assert_eq!(
                    matches(
                        &normalized.metadata,
                        name,
                        &Version::parse(version).unwrap()
                    ),
                    MatchResult {
                        matched: true,
                        complete: true
                    },
                    "{id} {version}"
                );
            }
            for version in unaffected {
                assert_eq!(
                    matches(
                        &normalized.metadata,
                        name,
                        &Version::parse(version).unwrap()
                    ),
                    MatchResult {
                        matched: false,
                        complete: true
                    },
                    "{id} {version}"
                );
            }
        }
    }
    #[test]
    fn isolated_equal_introduction_and_fix_are_empty_even_when_unsorted() {
        for events in [
            json!([{"introduced":"1.0.0"},{"fixed":"1.0.0"}]),
            json!([{"fixed":"1.0.0"},{"introduced":"1.0.0"}]),
            json!([{"introduced":"1.0.0-alpha.1+first"},{"fixed":"1.0.0-alpha.1+second"}]),
        ] {
            let value = record(events);
            for version in ["0.9.0", "1.0.0-alpha.1", "1.0.0", "1.0.1"] {
                assert_eq!(
                    matched(&value, version),
                    MatchResult {
                        matched: false,
                        complete: true
                    }
                );
            }
        }
        // One fix closes the earlier interval; the equal pair contributes no
        // affected versions at or after that shared boundary.
        let value = record(
            json!([{"introduced":"0"},{"fixed":"1.0.0"},{"introduced":"1.0.0"},{"fixed":"1.0.0"}]),
        );
        assert_eq!(
            matched(&value, "0.9.0"),
            MatchResult {
                matched: true,
                complete: true
            }
        );
        assert_eq!(
            matched(&value, "1.0.0"),
            MatchResult {
                matched: false,
                complete: true
            }
        );
        assert_eq!(
            matched(&value, "1.0.1"),
            MatchResult {
                matched: false,
                complete: true
            }
        );
    }
    #[test]
    fn ambiguous_overlapping_boundaries_and_mixed_event_objects_remain_incomplete() {
        for events in [
            json!([{"introduced":"0"},{"fixed":"1.0.0"},{"introduced":"1.0.0"},{"fixed":"2.0.0"}]),
            json!([{"introduced":"1.0.0"},{"introduced":"1.0.0"},{"fixed":"1.0.0"}]),
            json!([{"introduced":"0"},{"fixed":"1.0.0"},{"last_affected":"2.0.0"}]),
            json!([{"introduced":"1.0.0","limit":"2.0.0"}]),
        ] {
            assert_eq!(
                matched(&record(events), "1.5.0"),
                MatchResult {
                    matched: false,
                    complete: false
                }
            );
        }
    }
    #[test]
    fn multiple_package_names_remain_queryable() {
        let mut value = record(json!([{"introduced":"0"}]));
        value["affected"]
            .as_array_mut()
            .unwrap()
            .push(json!({"package":{"ecosystem":"crates.io","name":"other"},"versions":["2.0.0"]}));
        let normalized = normalize("crates/RUSTSEC-2024-0001.json", &value.to_string()).unwrap();
        assert_eq!(normalized.metadata["packages"], json!(["example", "other"]));
        assert!(matches(&normalized.metadata, "other", &Version::new(2, 0, 0)).matched);
        assert!(!matches(&normalized.metadata, "other", &Version::new(1, 0, 0)).matched);
    }
    #[test]
    fn informational_classification_is_specific_to_the_matched_version() {
        let mut value = record(json!([{"introduced":"1.0.0"},{"fixed":"2.0.0"}]));
        value["affected"][0]["database_specific"] = json!({"informational":"notice"});
        value["affected"].as_array_mut().unwrap().push(
            json!({"package":{"ecosystem":"crates.io","name":"example"},"versions":["3.0.0"]}),
        );
        assert_eq!(summary(&value)["classification"], "vulnerability");
        assert_eq!(
            summary_for_match(&value, "example", &Version::new(1, 1, 0))["classification"],
            "informational"
        );
        assert_eq!(
            summary_for_match(&value, "example", &Version::new(3, 0, 0))["classification"],
            "vulnerability"
        );
        value["withdrawn"] = json!("2024-02-01T00:00:00Z");
        assert_eq!(
            summary_for_match(&value, "example", &Version::new(1, 1, 0))["classification"],
            "withdrawn"
        );
    }
    #[test]
    fn other_ecosystems_and_package_names_never_match() {
        let mut value = record(json!([{"introduced":"0"}]));
        value["affected"][0]["package"]["ecosystem"] = json!("npm");
        assert!(!matched(&value, "1.0.0").matched);
        value["affected"][0]["package"]["ecosystem"] = json!("crates.io");
        assert!(!matches(&value, "different", &Version::new(1, 0, 0)).matched);
    }
    #[test]
    fn unsupported_ranges_preserve_supported_findings_but_make_coverage_incomplete() {
        let mut value = record(json!([{"introduced":"0"}]));
        value["affected"][0]["ranges"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"GIT","events":[{"introduced":"0"}]}));
        assert_eq!(
            matched(&value, "1.0.0"),
            MatchResult {
                matched: true,
                complete: false
            }
        );
        value["affected"][0]["ranges"][1]["type"] = json!("ECOSYSTEM");
        assert!(!matched(&value, "1.0.0").complete);
    }
    #[test]
    fn malformed_ranges_do_not_create_matches() {
        for events in [
            json!([]),
            json!([{"fixed":"1.0.0"}]),
            json!([{"introduced":"0"},{"fixed":"1.0.0"},{"last_affected":"2.0.0"}]),
            json!([{"introduced":"0"},{"fixed":"1.0.0"},{"introduced":"1.0.0"},{"fixed":"2.0.0"}]),
            json!([{"introduced":"0","fixed":"1.0.0"}]),
            json!([{"introduced":"0"},{"mystery":"1.0.0"}]),
            json!([{"introduced":"0"},{"fixed":"garbage"}]),
        ] {
            assert_eq!(
                matched(&record(events), "1.0.0"),
                MatchResult {
                    matched: false,
                    complete: false
                }
            );
        }
    }
    #[test]
    fn limits_bound_the_whole_range_and_cannot_be_reopened() {
        let value =
            record(json!([{"introduced":"1.0.0"},{"limit":"2.0.0"},{"introduced":"3.0.0"}]));
        assert_eq!(
            matched(&value, "1.5.0"),
            MatchResult {
                matched: true,
                complete: true
            }
        );
        for version in ["2.0.0", "3.0.0", "3.1.0"] {
            assert_eq!(
                matched(&value, version),
                MatchResult {
                    matched: false,
                    complete: true
                }
            );
        }
    }
    #[test]
    fn multiple_limits_are_alternatives_and_star_means_infinity() {
        let mut value = record(json!([{"introduced":"0"},{"limit":"1.0.0"},{"limit":"2.0.0"}]));
        assert_eq!(
            matched(&value, "1.5.0"),
            MatchResult {
                matched: true,
                complete: true
            }
        );
        assert_eq!(
            matched(&value, "2.0.0"),
            MatchResult {
                matched: false,
                complete: true
            }
        );
        value["affected"][0]["ranges"][0]["events"]
            .as_array_mut()
            .unwrap()
            .push(json!({"limit":"*"}));
        assert_eq!(
            matched(&value, "999.0.0"),
            MatchResult {
                matched: true,
                complete: true
            }
        );
        value["affected"][0]["ranges"][0]["events"][3] = json!({"limit":"1.*"});
        assert_eq!(
            matched(&value, "999.0.0"),
            MatchResult {
                matched: true,
                complete: true
            }
        );
    }
    #[test]
    fn event_order_and_non_alternating_introductions_follow_the_timeline() {
        for events in [
            json!([{"fixed":"2.0.0"},{"introduced":"1.0.0"}]),
            json!([{"introduced":"1.0.0"},{"introduced":"1.1.0"},{"fixed":"2.0.0"}]),
            json!([{"fixed":"0.9.0"},{"introduced":"1.0.0"},{"fixed":"2.0.0"}]),
        ] {
            let value = record(events);
            assert_eq!(
                matched(&value, "1.5.0"),
                MatchResult {
                    matched: true,
                    complete: true
                }
            );
            assert_eq!(
                matched(&value, "2.0.0"),
                MatchResult {
                    matched: false,
                    complete: true
                }
            );
        }
        let value = record(json!([{"last_affected":"1.2.0"},{"introduced":"1.0.0"}]));
        assert_eq!(
            matched(&value, "1.2.0"),
            MatchResult {
                matched: true,
                complete: true
            }
        );
        assert_eq!(
            matched(&value, "1.2.1"),
            MatchResult {
                matched: false,
                complete: true
            }
        );
    }
    #[test]
    fn explicit_versions_remain_an_alternative_to_limited_ranges() {
        let mut value = record(json!([{"introduced":"0"},{"limit":"2.0.0"}]));
        value["affected"][0]["versions"] = json!(["3.0.0"]);
        assert_eq!(
            matched(&value, "3.0.0"),
            MatchResult {
                matched: true,
                complete: true
            }
        );
    }
    #[test]
    fn normalization_preserves_extensions_and_license() {
        let mut value = record(json!([{"introduced":"0"}]));
        value["database_specific"] = json!({"license":"CC-BY-4.0","url":"https://github.com/advisories/GHSA-test","extra":{"kept":true}});
        value["affected"][0]["database_specific"] =
            json!({"informational":"unmaintained","categories":["memory-corruption"]});
        let body = serde_json::to_string(&value).unwrap();
        let record = normalize("crates/RUSTSEC-2024-0001.json", &body).unwrap();
        assert_eq!(record.body, body);
        assert_eq!(record.metadata["original"], value);
        assert_eq!(record.metadata["classification"], "informational");
        assert_eq!(record.metadata["license"], "CC-BY-4.0");
        assert_eq!(
            record.metadata["attribution_url"],
            "https://github.com/advisories/GHSA-test"
        );
        assert!(matches(&record.metadata, "example", &Version::new(1, 0, 0)).matched);
        value["withdrawn"] = json!("2024-02-01T00:00:00Z");
        assert_eq!(summary(&value)["classification"], "withdrawn");
    }
    #[test]
    fn platform_constraints_distinguish_unrestricted_unknown_and_union() {
        let mut value = record(json!([{"introduced":"0"}]));
        assert_eq!(summary(&value)["applicability_known"], true);
        assert_eq!(summary(&value)["affected"]["os"], json!([]));
        value["affected"][0]["ecosystem_specific"] =
            json!({"affects":{"os":["windows"],"arch":["x86_64"]}});
        assert_eq!(summary(&value)["affected"]["os"], json!(["windows"]));
        value["affected"][0]["ecosystem_specific"]["affects"]["os"] = json!("windows");
        assert_eq!(summary(&value)["applicability_known"], false);
        assert!(!matched(&value, "1.0.0").complete);
        value["affected"][0]["ecosystem_specific"]["affects"]["os"] = Value::Null;
        assert_eq!(summary(&value)["applicability_known"], false);
        value["affected"][0]["ecosystem_specific"] = Value::Null;
        assert_eq!(summary(&value)["applicability_known"], false);
    }
    #[test]
    fn unsupported_schema_and_excessive_or_recursive_records_fail_closed() {
        let mut value = record(json!([{"introduced":"0"}]));
        value["schema_version"] = json!("2.0.0");
        assert!(normalize("crates/test.json", &value.to_string()).is_err());
        assert!(!matched(&value, "1.0.0").complete);
        assert!(normalize("crates/test.json", &" ".repeat(MAX_RECORD + 1)).is_err());
        let nested = format!("{}0{}", "[".repeat(200), "]".repeat(200));
        assert!(normalize("crates/test.json", &nested).is_err());
    }
    #[test]
    fn malformed_metadata_never_establishes_complete_assessment() {
        for modified in [
            Value::Null,
            json!("2024-02-30T12:00:00Z"),
            json!("2024-01-01T25:00:00Z"),
            json!("2024-01-01T12:00:00+99:00"),
        ] {
            let mut value = record(json!([{"introduced":"0"}]));
            value["modified"] = modified;
            assert_eq!(
                matched(&value, "1.0.0"),
                MatchResult {
                    matched: true,
                    complete: false
                }
            );
        }
        for text in [
            "2024-02-29T23:59:59Z",
            "2024-01-01T12:00:00.123456+05:30",
            "2024-01-01t12:00:00z",
        ] {
            assert!(timestamp(&json!(text)), "{text}");
        }
    }
}
