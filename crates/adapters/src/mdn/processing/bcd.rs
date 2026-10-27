//! Inert BCD records and a versioned Rust interpretation of upstream mirror rules.
//!
//! Mirroring follows MDN's CC0 scripts/build/mirror.js, inspected 2026-10-25.
//! Original statements are retained alongside derived values; unsupported historical
//! semantics remain explicit gaps rather than inferred browser-version verdicts.
use super::{ProcessingBudget, ProcessingGap, limit, malformed, structured, valid_identity};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
};

const MAX_NORMALIZED_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_NORMALIZED_GAPS: usize = 256;

struct NormalizedBudget {
    bytes: usize,
}
impl NormalizedBudget {
    fn account(&mut self, item: &impl Serialize) -> Result<()> {
        // Include a separator per emitted entry; the initial envelope reservation
        // covers the document's field names, brackets and empty vectors.
        self.bytes = self
            .bytes
            .checked_add(1)
            .filter(|n| *n <= MAX_NORMALIZED_OUTPUT)
            .ok_or_else(limit)?;
        struct Counter<'a>(&'a mut usize);
        impl Write for Counter<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let total = self
                    .0
                    .checked_add(bytes.len())
                    .filter(|n| *n <= MAX_NORMALIZED_OUTPUT)
                    .ok_or_else(|| io::Error::other("normalized output limit"))?;
                *self.0 = total;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(Counter(&mut self.bytes), item).map_err(|_| limit())
    }
    fn record(&mut self, key: &str, data: &Value) -> Result<()> {
        #[derive(Serialize)]
        struct Record<'a> {
            key: &'a str,
            data: &'a Value,
        }
        self.account(&Record { key, data })
    }
    fn gap(&mut self, out: &mut BcdDocument, gap: ProcessingGap) -> Result<()> {
        if out.gaps.len() >= MAX_NORMALIZED_GAPS {
            return Err(limit());
        }
        self.account(&gap)?;
        out.gaps.push(gap);
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BcdFeature {
    pub key: String,
    pub data: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BcdBrowser {
    pub key: String,
    pub data: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BcdDocument {
    pub features: Vec<BcdFeature>,
    pub browsers: Vec<BcdBrowser>,
    pub gaps: Vec<ProcessingGap>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedSupport {
    pub original: Value,
    pub resolved: Value,
    pub gaps: Vec<ProcessingGap>,
}

pub fn process_bcd(path: &str, bytes: &[u8], budget: &ProcessingBudget) -> Result<BcdDocument> {
    if !valid_identity(path) || !path.ends_with(".json") {
        return Err(malformed());
    }
    let root = structured::json(bytes, budget)?;
    if !root.is_object() {
        return Err(malformed());
    }
    let mut result = BcdDocument {
        features: Vec::new(),
        browsers: Vec::new(),
        gaps: Vec::new(),
    };
    let mut output = NormalizedBudget { bytes: 64 };
    if path.starts_with("browsers/") {
        let browsers = root
            .get("browsers")
            .and_then(Value::as_object)
            .ok_or_else(malformed)?;
        for (key, data) in browsers {
            budget.check()?;
            if !valid_key_component(key) {
                output.gap(
                    &mut result,
                    ProcessingGap::new(
                        "unsupported_browser_identifier",
                        "Captured browser identifier cannot form a canonical inventory member.",
                    ),
                )?;
                continue;
            }
            if !data.is_object() {
                output.gap(
                    &mut result,
                    ProcessingGap::new("unsupported_browser_metadata", key),
                )?;
                continue;
            }
            if data.get("releases").is_none_or(|v| !v.is_object()) {
                output.gap(
                    &mut result,
                    ProcessingGap::new("unsupported_browser_metadata", key),
                )?;
            }
            output.record(key, data)?;
            result.browsers.push(BcdBrowser {
                key: key.clone(),
                data: data.clone(),
            });
        }
    } else {
        collect_features(&root, &mut Vec::new(), &mut result, &mut output, budget)?;
    }
    Ok(result)
}
fn valid_key_component(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 512
        && !key.contains(['.', '/', '\\'])
        && !key.chars().any(char::is_control)
}
fn collect_features(
    value: &Value,
    path: &mut Vec<String>,
    out: &mut BcdDocument,
    output: &mut NormalizedBudget,
    budget: &ProcessingBudget,
) -> Result<()> {
    budget.check()?;
    if path.len() > 64 {
        return Err(limit());
    }
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    if let Some(data) = object.get("__compat") {
        if out.features.len() >= 100_000 {
            return Err(limit());
        }
        let key = path.join(".");
        if key.is_empty() || key.len() + "@features/".len() > 4096 {
            output.gap(
                out,
                ProcessingGap::new("unsupported_feature_identifier", key),
            )?;
        } else if !data.is_object() {
            output.gap(out, ProcessingGap::new("unsupported_compat_record", key))?;
        } else {
            if data.get("support").is_none_or(|v| !v.is_object()) {
                output.gap(out, ProcessingGap::new("unsupported_support", key.clone()))?;
            }
            output.record(&key, data)?;
            out.features.push(BcdFeature {
                key,
                data: data.clone(),
            });
        }
    }
    for (key, data) in object {
        if key.starts_with("__") {
            continue;
        }
        if !valid_key_component(key) {
            output.gap(
                out,
                ProcessingGap::new("unsupported_feature_identifier", path.join(".")),
            )?;
            continue;
        }
        if data.is_object() {
            path.push(key.clone());
            collect_features(data, path, out, output, budget)?;
            path.pop();
        }
    }
    Ok(())
}

pub fn resolve_support(
    feature: &Value,
    browsers: &BTreeMap<String, Value>,
    budget: &ProcessingBudget,
) -> Result<ResolvedSupport> {
    budget.check()?;
    let original = feature.get("support").cloned().unwrap_or(Value::Null);
    let Some(statements) = original.as_object() else {
        return Ok(ResolvedSupport {
            resolved: original.clone(),
            original,
            gaps: vec![ProcessingGap::new(
                "unsupported_support",
                "Missing or unsupported support object.",
            )],
        });
    };
    if statements.len() > 128 || browsers.len() > 128 {
        return Err(limit());
    }
    let mut resolved = Map::new();
    let mut gaps = Vec::new();
    for (browser, value) in statements {
        budget.check()?;
        if value.as_str() != Some("mirror") {
            resolved.insert(browser.clone(), value.clone());
            continue;
        }
        match mirror(browser, statements, browsers, &mut BTreeSet::new(), budget) {
            Ok(value) => {
                resolved.insert(browser.clone(), value);
            }
            Err(error) if error.code == "capacity" || error.code == "cancelled" => {
                return Err(error);
            }
            Err(_) => {
                resolved.insert(browser.clone(), value.clone());
                gaps.push(ProcessingGap::new("unresolved_mirror", browser));
            }
        }
    }
    Ok(ResolvedSupport {
        original,
        resolved: Value::Object(resolved),
        gaps,
    })
}
fn unsupported() -> Error {
    Error::integrity("Unsupported captured BCD mirror semantics.")
}
fn mirror(
    destination: &str,
    data: &Map<String, Value>,
    browsers: &BTreeMap<String, Value>,
    stack: &mut BTreeSet<String>,
    budget: &ProcessingBudget,
) -> Result<Value> {
    budget.check()?;
    if stack.len() >= 64 || !stack.insert(destination.to_owned()) {
        return Err(unsupported());
    }
    let upstream = browsers
        .get(destination)
        .and_then(|b| b.get("upstream"))
        .and_then(Value::as_str)
        .ok_or_else(unsupported)?;
    let raw = data
        .get(upstream)
        .filter(|v| !v.is_null())
        .ok_or_else(unsupported)?;
    let source = if raw.as_str() == Some("mirror") {
        mirror(upstream, data, browsers, stack, budget)?
    } else {
        raw.clone()
    };
    let result = bump(&source, upstream, destination, browsers, budget);
    stack.remove(destination);
    result
}
fn bump(
    source: &Value,
    source_browser: &str,
    destination: &str,
    browsers: &BTreeMap<String, Value>,
    budget: &ProcessingBudget,
) -> Result<Value> {
    budget.check()?;
    if let Some(statements) = source.as_array() {
        if statements.len() > 1000 {
            return Err(limit());
        }
        let mut out = Vec::new();
        for statement in statements {
            let mapped = bump(statement, source_browser, destination, browsers, budget)?;
            if mapped.get("version_added").is_some_and(truthy) {
                out.push(mapped);
            }
        }
        return Ok(match out.len() {
            0 => json!({"version_added":false}),
            1 => out.remove(0),
            _ => Value::Array(out),
        });
    }
    let source = source.as_object().ok_or_else(unsupported)?;
    let mut out = source.clone();
    let source_meta = browsers.get(source_browser).ok_or_else(unsupported)?;
    let target_meta = browsers.get(destination).ok_or_else(unsupported)?;
    if source_meta.get("type").and_then(Value::as_str) == Some("desktop")
        && target_meta.get("type").and_then(Value::as_str) == Some("mobile")
        && source.get("partial_implementation") == Some(&Value::Bool(true))
    {
        let notes = match source.get("notes") {
            Some(Value::String(n)) => vec![Value::String(n.clone())],
            Some(Value::Array(a)) => a.clone(),
            None => Vec::new(),
            _ => return Err(unsupported()),
        };
        let filtered: Vec<_> = notes
            .into_iter()
            .filter(|n| n.as_str().is_some_and(|s| !os_limitation(s)))
            .collect();
        match filtered.len() {
            0 => {
                out.remove("notes");
                out.remove("partial_implementation");
            }
            1 => {
                out.insert("notes".into(), filtered[0].clone());
            }
            _ => {
                out.insert("notes".into(), Value::Array(filtered));
            }
        }
    }
    if target_meta.get("accepts_flags") == Some(&Value::Bool(false))
        && out.get("flags").is_some_and(truthy)
    {
        return Ok(json!({"version_added":false}));
    }
    let added = source.get("version_added").ok_or_else(unsupported)?;
    if let Some(version) = added.as_str() {
        out.insert(
            "version_added".into(),
            matching(destination, version, browsers, budget)?,
        );
    } else if !added.is_boolean() && !added.is_null() {
        return Err(unsupported());
    }
    if out.get("version_added") == Some(&Value::Bool(false)) && added != &Value::Bool(false) {
        return Ok(json!({"version_added":false}));
    }
    if let Some(removed) = source.get("version_removed").and_then(Value::as_str) {
        let mapped = matching(destination, removed, browsers, budget)?;
        if mapped.is_string() {
            out.insert("version_removed".into(), mapped);
        } else {
            out.remove("version_removed");
        }
    }
    if out.contains_key("version_removed") && out.get("version_added") == out.get("version_removed")
    {
        return Ok(json!({"version_added":false}));
    }
    if source.get("notes").is_some_and(truthy) && out.contains_key("notes") {
        // Upstream transforms the original notes after removing OS restrictions.
        let source_name = source_meta
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(unsupported)?;
        let target_name = target_meta
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(unsupported)?;
        let notes = update_notes(
            source.get("notes").ok_or_else(unsupported)?,
            source_browser,
            source_name,
            target_name,
            destination,
            browsers,
            budget,
        )?;
        if let Some(notes) = notes {
            out.insert("notes".into(), notes);
        } else {
            out.remove("notes");
        }
    }
    Ok(Value::Object(out))
}
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(v) => *v,
        Value::String(v) => !v.is_empty(),
        Value::Number(n) => n.as_f64() != Some(0.0),
        _ => true,
    }
}
fn version(s: &str) -> Option<Vec<u64>> {
    if s.is_empty() || s.len() > 128 {
        return None;
    }
    s.split('.')
        .map(|s| {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                None
            } else {
                s.parse::<u64>().ok()
            }
        })
        .collect()
}
fn compare(a: &[u64], b: &[u64]) -> Ordering {
    for at in 0..a.len().max(b.len()) {
        let order = a
            .get(at)
            .copied()
            .unwrap_or(0)
            .cmp(&b.get(at).copied().unwrap_or(0));
        if order != Ordering::Equal {
            return order;
        }
    }
    Ordering::Equal
}
fn matching(
    destination: &str,
    source_version: &str,
    browsers: &BTreeMap<String, Value>,
    budget: &ProcessingBudget,
) -> Result<Value> {
    budget.check()?;
    let target = browsers.get(destination).ok_or_else(unsupported)?;
    let upstream = target
        .get("upstream")
        .and_then(Value::as_str)
        .ok_or_else(unsupported)?;
    if source_version == "preview" {
        return Ok(if target.get("preview_name").is_some_and(truthy) {
            json!("preview")
        } else {
            json!(false)
        });
    }
    let range = source_version.starts_with('≤');
    let plain = source_version.strip_prefix('≤').unwrap_or(source_version);
    let releases = target
        .get("releases")
        .and_then(Value::as_object)
        .ok_or_else(unsupported)?;
    if destination == "safari_ios" {
        const MAP: [(&str, &str); 16] = [
            ("1", "1"),
            ("1.1", "1"),
            ("1.2", "1"),
            ("1.3", "1"),
            ("2", "1"),
            ("3", "2"),
            ("3.1", "2"),
            ("4", "3.2"),
            ("5", "4.2"),
            ("5.1", "5"),
            ("9.1", "9.3"),
            ("10.1", "10.3"),
            ("11.1", "11.3"),
            ("12.1", "12.2"),
            ("13.1", "13.4"),
            ("14.1", "14.5"),
        ];
        if let Some((_, mapped)) = MAP.iter().find(|(key, _)| *key == plain) {
            return Ok(json!(format!("{}{mapped}", if range { "≤" } else { "" })));
        }
        if releases.contains_key(plain) {
            return Ok(json!(source_version));
        }
        return Err(unsupported());
    }
    version(plain).ok_or_else(unsupported)?;
    let source = browsers
        .get(upstream)
        .and_then(|b| b.get("releases"))
        .and_then(|r| r.get(plain))
        .ok_or_else(unsupported)?;
    let mut candidates = Vec::new();
    for (key, release) in releases {
        let numeric = version(key).ok_or_else(unsupported)?;
        candidates.push((numeric, key, release));
    }
    if candidates.len() > 10_000 {
        return Err(limit());
    }
    candidates.sort_by(|a, b| compare(&a.0, &b.0));
    let mut previous_engine = None;
    for (_, key, release) in candidates {
        budget.check()?;
        let engine = release.get("engine").and_then(Value::as_str);
        let source_engine = source.get("engine").and_then(Value::as_str);
        let range_delimiter =
            range && previous_engine.is_some() && previous_engine == source_engine;
        let webkit_to_blink = matches!(upstream, "chrome" | "chrome_android")
            && destination != "chrome_android"
            && engine == Some("Blink")
            && source_engine == Some("WebKit");
        let matching_engine = engine.is_some()
            && engine == source_engine
            && match (
                release.get("engine_version").and_then(Value::as_str),
                source.get("engine_version").and_then(Value::as_str),
            ) {
                (Some(a), Some(b)) => {
                    compare(
                        &version(a).ok_or_else(unsupported)?,
                        &version(b).ok_or_else(unsupported)?,
                    ) != Ordering::Less
                }
                _ => false,
            };
        if webkit_to_blink || matching_engine {
            return Ok(json!(format!(
                "{}{key}",
                if range_delimiter { "≤" } else { "" }
            )));
        }
        previous_engine = engine;
    }
    Ok(json!(false))
}
fn os_limitation(s: &str) -> bool {
    const NOTES: [&str; 21] = [
        "available on macos and windows only.",
        "available only on macos.",
        "chromeos only",
        "chromeos and windows",
        "fully supported on windows and linux, no support on chromeos.",
        "linux support is not enabled by default.",
        "not supported on macos.",
        "not supported on windows.",
        "only on macos and windows.",
        "only on windows.",
        "only supported on chromeos",
        "only supported on macos.",
        "only supported on windows.",
        "only works on macos.",
        "supported on chromeos, macos, and windows only.",
        "supported on chromeos and macos only.",
        "supported on macos only.",
        "supported on macos catalina 10.15.1+, windows, and chromeos. not yet supported on linux.",
        "supported on windows only, in all contexts except for service workers.",
        "supported only on macos 10.12 (sierra) and later.",
        "this cursor is only supported on macos and linux.",
    ];
    NOTES.contains(&s.to_lowercase().as_str())
}
fn replace_words(text: &str, sources: &[&str], target: &str) -> String {
    if sources.iter().any(|s| s.is_empty()) {
        return text.to_owned();
    }
    let mut out = String::new();
    let mut offset = 0;
    while let Some((at, source)) = sources
        .iter()
        .filter_map(|source| text[offset..].find(source).map(|at| (offset + at, *source)))
        .min_by_key(|(at, source)| (*at, std::cmp::Reverse(source.len())))
    {
        let end = at + source.len();
        let boundary = |c: char| !c.is_ascii_alphanumeric() && c != '_';
        if text[..at].chars().next_back().is_none_or(boundary)
            && text[end..].chars().next().is_none_or(boundary)
        {
            out.push_str(&text[offset..at]);
            out.push_str(target);
            offset = end;
        } else {
            out.push_str(&text[offset..end]);
            offset = end;
        }
    }
    out.push_str(&text[offset..]);
    out
}
fn update_notes(
    value: &Value,
    source_browser: &str,
    source_name: &str,
    target_name: &str,
    destination: &str,
    browsers: &BTreeMap<String, Value>,
    budget: &ProcessingBudget,
) -> Result<Option<Value>> {
    budget.check()?;
    if let Some(items) = value.as_array() {
        let mut out = Vec::new();
        for item in items {
            if let Some(note) = update_notes(
                item,
                source_browser,
                source_name,
                target_name,
                destination,
                browsers,
                budget,
            )? {
                out.push(note);
            }
        }
        return Ok(match out.len() {
            0 => None,
            1 => Some(out.remove(0)),
            _ => Some(Value::Array(out)),
        });
    }
    let text = value.as_str().ok_or_else(unsupported)?;
    let text = if source_browser == "chrome" {
        replace_words(text, &["Google Chrome", "Chrome"], target_name)
    } else {
        replace_words(text, &[source_name], target_name)
    };
    let mut replacements = Vec::new();
    for prefix in [format!("{target_name} "), "version ".to_owned()] {
        let mut offset = 0;
        while let Some(at) = text[offset..].find(&prefix).map(|at| offset + at) {
            let start = at + prefix.len();
            let end = start + text[start..].bytes().take_while(u8::is_ascii_digit).count();
            offset = end.max(start);
            if end == start {
                continue;
            }
            let mapped = matching(destination, &text[start..end], browsers, budget)?;
            let Some(mapped) = mapped.as_str() else {
                return Ok(None);
            };
            replacements.push((start, end, mapped.to_owned()));
        }
    }
    replacements.sort_by_key(|r| r.0);
    replacements.dedup_by_key(|r| r.0);
    let mut out = String::new();
    let mut offset = 0;
    for (start, end, text_part) in replacements {
        if start < offset {
            continue;
        }
        out.push_str(&text[offset..start]);
        out.push_str(&text_part);
        offset = end;
    }
    out.push_str(&text[offset..]);
    Ok(Some(Value::String(out)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;
    fn budget() -> ProcessingBudget {
        ProcessingBudget::new(CancellationToken::new())
    }
    fn browsers() -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                "chrome".into(),
                json!({"name":"Chrome","type":"desktop","releases":{"1":{"engine":"WebKit","engine_version":"500"},"80":{"engine":"Blink","engine_version":"80"},"100":{"engine":"Blink","engine_version":"100"}}}),
            ),
            (
                "edge".into(),
                json!({"name":"Edge","type":"desktop","upstream":"chrome","accepts_flags":true,"releases":{"12":{"engine":"EdgeHTML","engine_version":"12"},"79":{"engine":"Blink","engine_version":"79"},"80":{"engine":"Blink","engine_version":"80"},"100":{"engine":"Blink","engine_version":"100"}}}),
            ),
            (
                "chrome_android".into(),
                json!({"name":"Chrome Android","type":"mobile","upstream":"chrome","accepts_flags":false,"releases":{"18":{"engine":"WebKit","engine_version":"500"},"80":{"engine":"Blink","engine_version":"80"},"100":{"engine":"Blink","engine_version":"100"}}}),
            ),
        ])
    }
    #[test]
    fn parse_feature_hierarchy_and_browser_metadata() {
        let doc=process_bcd("css/properties/test.json",br#"{"css":{"properties":{"test":{"__compat":{"support":{"chrome":{"version_added":false}},"status":{"experimental":true}},"nested":{"__compat":{"support":{}}}}}}}"#,&budget()).expect("fixture");
        assert_eq!(
            doc.features
                .iter()
                .map(|f| f.key.as_str())
                .collect::<Vec<_>>(),
            ["css.properties.test", "css.properties.test.nested"]
        );
        let browser = process_bcd(
            "browsers/test.json",
            br#"{"browsers":{"test":{"name":"Test","releases":{}}}}"#,
            &budget(),
        )
        .expect("browser");
        assert_eq!(browser.browsers[0].key, "test");
    }
    #[test]
    fn duplicates_deep_nesting_and_invalid_json_fail() {
        assert!(process_bcd("api/a.json", br#"{"a":{},"a":{}}"#, &budget()).is_err());
        let deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
        assert!(process_bcd("api/a.json", deep.as_bytes(), &budget()).is_err());
    }
    #[test]
    fn mirror_maps_engines_and_preserves_source() {
        let data = json!({"support":{"chrome":{"version_added":"1","notes":"Available."},"edge":"mirror"}});
        let mapped = resolve_support(&data, &browsers(), &budget()).expect("mirror");
        assert_eq!(mapped.original["edge"], "mirror");
        assert_eq!(mapped.resolved["edge"]["version_added"], "79");
        assert!(mapped.gaps.is_empty());
    }
    #[test]
    fn mirror_flags_partial_ranges_and_removals() {
        let data = json!({"support":{"chrome":{"version_added":"≤80","version_removed":"100","partial_implementation":true,"notes":"Not supported on Windows."},"chrome_android":"mirror","edge":"mirror"}});
        let mapped = resolve_support(&data, &browsers(), &budget()).expect("mirror");
        assert_eq!(mapped.resolved["edge"]["version_added"], "≤80");
        assert_eq!(mapped.resolved["chrome_android"]["version_removed"], "100");
        assert!(
            mapped.resolved["chrome_android"]
                .get("partial_implementation")
                .is_none()
        );
        let flags = json!({"support":{"chrome":{"version_added":"80","flags":[{"type":"preference","name":"test"}]},"chrome_android":"mirror"}});
        assert_eq!(
            resolve_support(&flags, &browsers(), &budget())
                .expect("flags")
                .resolved["chrome_android"],
            json!({"version_added":false})
        );
    }
    #[test]
    fn unresolved_mirror_is_visible_and_not_guessed() {
        let data = json!({"support":{"edge":"mirror"}});
        let mapped = resolve_support(&data, &browsers(), &budget()).expect("explicit gap");
        assert_eq!(mapped.resolved["edge"], "mirror");
        assert_eq!(mapped.gaps[0].code, "unresolved_mirror");
        let mut cycle = browsers();
        cycle.insert("chrome".into(), json!({"upstream":"edge"}));
        let data = json!({"support":{"chrome":"mirror","edge":"mirror"}});
        assert_eq!(
            resolve_support(&data, &cycle, &budget())
                .expect("cycle gap")
                .gaps
                .len(),
            2
        );
    }
    #[test]
    fn notes_replace_google_chrome_once_and_map_versions() {
        let data = json!({"support":{"chrome":{"version_added":"80","notes":"Google Chrome 80 and Chrome 80 behave differently."},"chrome_android":"mirror"}});
        let mapped = resolve_support(&data, &browsers(), &budget()).expect("notes");
        assert_eq!(
            mapped.resolved["chrome_android"]["notes"],
            "Chrome Android 80 and Chrome Android 80 behave differently."
        );
    }
    #[test]
    fn safari_manual_mapping_and_same_version_removal() {
        let mut b = browsers();
        b.insert("safari".into(), json!({"name":"Safari","type":"desktop"}));
        b.insert("safari_ios".into(),json!({"name":"Safari on iOS","type":"mobile","upstream":"safari","releases":{"9.3":{}}}));
        let data = json!({"support":{"safari":{"version_added":"9.1"},"safari_ios":"mirror"}});
        assert_eq!(
            resolve_support(&data, &b, &budget())
                .expect("safari")
                .resolved["safari_ios"]["version_added"],
            "9.3"
        );
        let data = json!({"support":{"chrome":{"version_added":"1","version_removed":"1"},"edge":"mirror"}});
        assert_eq!(
            resolve_support(&data, &b, &budget())
                .expect("removed")
                .resolved["edge"],
            json!({"version_added":false})
        );
    }
}

#[cfg(test)]
mod identifier_tests {
    use super::*;
    use tokio_util::sync::CancellationToken;
    #[test]
    fn malformed_feature_and_browser_identifiers_are_visible_gaps() {
        let budget = ProcessingBudget::new(CancellationToken::new());
        let features=process_bcd("api/test.json",br#"{"api":{"bad//key":{"__compat":{"support":{}}},"bad\\key":{"__compat":{"support":{}}},"good":{"__compat":{"support":{}}}}}"#,&budget).expect("accounted identifiers");
        assert_eq!(features.features.len(), 1);
        assert_eq!(features.features[0].key, "api.good");
        assert!(
            features
                .gaps
                .iter()
                .all(|gap| gap.code == "unsupported_feature_identifier")
        );
        assert_eq!(features.gaps.len(), 2);
        let browsers=process_bcd("browsers/test.json",br#"{"browsers":{"bad/key":{"releases":{}},"bad\\key":{"releases":{}},"good":{"name":"Good","releases":{}}}}"#,&budget).expect("accounted browser identifiers");
        assert_eq!(browsers.browsers.len(), 1);
        assert_eq!(browsers.browsers[0].key, "good");
        assert_eq!(browsers.gaps.len(), 2);
        assert!(
            browsers
                .gaps
                .iter()
                .all(|gap| gap.code == "unsupported_browser_identifier")
        );
    }
}

#[cfg(test)]
mod normalization_budget_tests {
    use super::*;
    use tokio_util::sync::CancellationToken;
    #[test]
    fn repeated_long_feature_prefixes_reject_expanded_output_before_publication() {
        let mut leaves = Map::new();
        for index in 0..4_000 {
            leaves.insert(
                format!("feature_{index:04}"),
                json!({"__compat":{"support":{}}}),
            );
        }
        let mut root = Value::Object(leaves);
        for index in 0..7 {
            root = Value::Object(Map::from_iter([(
                format!("p{index}{}", "x".repeat(470)),
                root,
            )]));
        }
        root = Value::Object(Map::from_iter([("api".into(), root)]));
        let bytes = serde_json::to_vec(&root).expect("synthetic source");
        assert!(bytes.len() < super::super::MAX_MEMBER);
        assert_eq!(
            process_bcd(
                "api/expansion.json",
                &bytes,
                &ProcessingBudget::new(CancellationToken::new())
            )
            .expect_err("expanded keys exceed normalized budget")
            .code,
            "capacity"
        );
        let neighbor = process_bcd(
            "api/valid.json",
            br#"{"api":{"valid":{"__compat":{"support":{}}}}}"#,
            &ProcessingBudget::new(CancellationToken::new()),
        )
        .expect("independent ordinary record");
        assert_eq!(neighbor.features[0].key, "api.valid");
    }
    #[test]
    fn unsupported_identifier_diagnostics_are_bounded_during_emission() {
        let mut browsers = Map::new();
        for index in 0..257 {
            browsers.insert(format!("bad/{index}"), json!({"releases":{}}));
        }
        let bytes =
            serde_json::to_vec(&json!({"browsers":browsers})).expect("synthetic diagnostics");
        assert_eq!(
            process_bcd(
                "browsers/invalid.json",
                &bytes,
                &ProcessingBudget::new(CancellationToken::new())
            )
            .expect_err("diagnostic limit")
            .code,
            "capacity"
        );
    }
}
