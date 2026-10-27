//! Request-local, bounded npm/pnpm/Yarn inventories. Never resolves dependencies.
use devres_domain::{Error, Result};
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::{Duration, Instant},
};
use yaml_rust2::{
    parser::{Event, Parser},
    scanner::TScalarStyle,
};

pub const MAX_LOCKFILE: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;
const MAX_NODES: usize = 100_000;

fn invalid() -> Error {
    Error::invalid("Malformed or unsupported npm lockfile; input details are not logged.")
}
fn capacity() -> Error {
    Error::capacity("npm lockfile processing limit exceeded.")
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RegistryIdentity {
    Npmjs,
    Other,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegistryContext {
    pub default: RegistryIdentity,
    pub scopes: BTreeMap<String, RegistryIdentity>,
}
impl RegistryContext {
    pub fn validate(&self) -> Result<()> {
        if self.scopes.len() > 1000
            || self.scopes.keys().any(|scope| {
                !scope.starts_with('@') || scope.len() > 214 || !valid_component(&scope[1..])
            })
        {
            return Err(Error::invalid("Invalid npm registry context."));
        }
        Ok(())
    }
    fn identity(&self, name: &str) -> RegistryIdentity {
        name.split_once('/')
            .filter(|(scope, _)| scope.starts_with('@'))
            .and_then(|(scope, _)| self.scopes.get(scope))
            .copied()
            .unwrap_or(self.default)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub name: String,
    pub version: String,
    pub occurrence: String,
    pub modified: bool,
    pub reason: Option<String>,
    pub registry_attribution: Option<String>,
}
#[derive(Debug)]
pub struct Inventory {
    pub format_version: String,
    pub entries: Vec<Entry>,
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && !value.starts_with(['.', '_'])
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.~".contains(&b))
}
pub(crate) fn valid_name(name: &str) -> bool {
    crate::npm_processing::validate_name(name).is_ok()
}

/// npm exact-version parsing, deliberately excluding range/coercion semantics.
pub(crate) fn version(value: &str) -> Option<semver::Version> {
    crate::npm_processing::parse_version(value).ok()
}

struct Budget {
    nodes: Cell<usize>,
    deadline: Instant,
}
impl Budget {
    fn new() -> Self {
        Self {
            nodes: Cell::new(0),
            deadline: Instant::now() + Duration::from_secs(15),
        }
    }
    fn node(&self) -> Result<()> {
        let next = self.nodes.get().saturating_add(1);
        self.nodes.set(next);
        if next > MAX_NODES || Instant::now() >= self.deadline {
            Err(capacity())
        } else {
            Ok(())
        }
    }
}
struct Seed<'a> {
    budget: &'a Budget,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        de: D,
    ) -> std::result::Result<Value, D::Error> {
        self.budget
            .node()
            .map_err(|_| D::Error::custom("processing bound"))?;
        if self.depth > 64 {
            return Err(D::Error::custom("nesting bound"));
        }
        de.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON data")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(value.into())
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(value.into())
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(value.into())
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Value, E> {
        if value.len() > 64 * 1024 {
            return Err(E::custom("scalar bound"));
        }
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> std::result::Result<Value, E> {
        if value.len() > 64 * 1024 {
            return Err(E::custom("scalar bound"));
        }
        Ok(Value::String(value))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            if out.len() >= MAX_NODES {
                return Err(A::Error::custom("array bound"));
            }
            out.push(value);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 4096 || out.contains_key(&key) || out.len() >= MAX_NODES {
                return Err(A::Error::custom("invalid mapping"));
            }
            out.insert(
                key,
                map.next_value_seed(Seed {
                    budget: self.budget,
                    depth: self.depth + 1,
                })?,
            );
        }
        Ok(Value::Object(out))
    }
}
pub(crate) fn bounded_json(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_LOCKFILE {
        return Err(capacity());
    }
    let budget = Budget::new();
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = Seed {
        budget: &budget,
        depth: 0,
    }
    .deserialize(&mut de)
    .map_err(|_| invalid())?;
    de.end().map_err(|_| invalid())?;
    Ok(value)
}

enum Container {
    Array(Vec<Value>),
    Object(Map<String, Value>, Option<String>),
}
fn insert(stack: &mut [Container], root: &mut Option<Value>, value: Value) -> Result<()> {
    match stack.last_mut() {
        Some(Container::Array(items)) => items.push(value),
        Some(Container::Object(items, key)) => {
            if let Some(key) = key.take() {
                if items.insert(key, value).is_some() {
                    return Err(invalid());
                }
            } else {
                let name = value
                    .as_str()
                    .filter(|s| s.len() <= 4096)
                    .ok_or_else(invalid)?;
                if name == "<<" || items.contains_key(name) {
                    return Err(invalid());
                }
                *key = Some(name.into());
            }
        }
        None => {
            if root.replace(value).is_some() {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
fn yaml_documents(source: &str) -> Result<Vec<Value>> {
    let mut parser = Parser::new_from_str(source);
    let budget = Budget::new();
    let mut stack = Vec::new();
    let mut root = None;
    let mut documents = Vec::new();
    loop {
        budget.node()?;
        let (event, _) = parser.next_token().map_err(|_| invalid())?;
        match event {
            Event::StreamEnd => break,
            Event::DocumentEnd => {
                if !stack.is_empty() || documents.len() >= 16 {
                    return Err(invalid());
                }
                documents.push(root.take().ok_or_else(invalid)?);
            }
            Event::MappingStart(anchor, tag) => {
                if anchor != 0 || tag.is_some() {
                    return Err(invalid());
                }
                stack.push(Container::Object(Map::new(), None));
            }
            Event::SequenceStart(anchor, tag) => {
                if anchor != 0 || tag.is_some() {
                    return Err(invalid());
                }
                stack.push(Container::Array(Vec::new()));
            }
            Event::MappingEnd => {
                let Some(Container::Object(map, None)) = stack.pop() else {
                    return Err(invalid());
                };
                insert(&mut stack, &mut root, Value::Object(map))?;
            }
            Event::SequenceEnd => {
                let Some(Container::Array(items)) = stack.pop() else {
                    return Err(invalid());
                };
                insert(&mut stack, &mut root, Value::Array(items))?;
            }
            Event::Alias(_) => return Err(invalid()),
            Event::Scalar(s, style, anchor, tag) => {
                if anchor != 0 || tag.is_some() {
                    return Err(invalid());
                }
                if s.len() > 64 * 1024 {
                    return Err(capacity());
                }
                let key = matches!(stack.last(), Some(Container::Object(_, None)));
                let value = if style == TScalarStyle::Plain && !key {
                    match yaml_rust2::Yaml::from_str(&s) {
                        yaml_rust2::Yaml::String(value) => Value::String(value),
                        yaml_rust2::Yaml::Integer(value) => value.into(),
                        yaml_rust2::Yaml::Boolean(value) => value.into(),
                        yaml_rust2::Yaml::Null => Value::Null,
                        yaml_rust2::Yaml::Real(value) => value
                            .parse::<f64>()
                            .ok()
                            .and_then(serde_json::Number::from_f64)
                            .map(Value::Number)
                            .ok_or_else(invalid)?,
                        _ => return Err(invalid()),
                    }
                } else {
                    Value::String(s)
                };
                insert(&mut stack, &mut root, value)?;
            }
            _ => {}
        }
        if stack.len() > 64 {
            return Err(capacity());
        }
    }
    if documents.is_empty() || !stack.is_empty() || root.is_some() {
        return Err(invalid());
    }
    Ok(documents)
}

struct Builder<'a> {
    context: &'a RegistryContext,
    entries: Vec<Entry>,
    occurrences: BTreeSet<String>,
}
impl<'a> Builder<'a> {
    fn new(context: &'a RegistryContext) -> Self {
        Self {
            context,
            entries: Vec::new(),
            occurrences: BTreeSet::new(),
        }
    }
    fn add(
        &mut self,
        name: &str,
        raw_version: &str,
        occurrence: String,
        resolved: Option<&str>,
        modified: bool,
        reason: Option<&str>,
    ) -> Result<()> {
        if self.entries.len() >= MAX_ENTRIES || occurrence.len() > 4096 {
            return Err(capacity());
        }
        if !self.occurrences.insert(occurrence.clone()) {
            return Err(invalid());
        }
        let (name, raw_version) = alias(name, raw_version);
        let mut reason = reason.map(str::to_owned);
        if !valid_name(name) || version(raw_version).is_none() {
            reason = Some("unsupported_package_identity".into());
        }
        if let Some(source) = resolved
            && !public_registry_url(source, name, raw_version)
        {
            reason = Some("path_git_or_alternative_registry".into());
        }
        let registry = self.context.identity(name);
        if reason.is_none() && registry != RegistryIdentity::Npmjs {
            reason = Some(
                if registry == RegistryIdentity::Other {
                    "alternative_registry"
                } else {
                    "registry_identity_unproven"
                }
                .into(),
            );
        }
        self.entries.push(Entry {
            name: name.chars().take(214).collect(),
            version: raw_version.chars().take(256).collect(),
            occurrence,
            modified,
            registry_attribution: (reason.is_none()).then(|| "caller_asserted_public_npm".into()),
            reason,
        });
        Ok(())
    }
}
fn public_registry_url(source: &str, name: &str, exact: &str) -> bool {
    let Ok(url) = url::Url::parse(source) else {
        return false;
    };
    let Some(base) = name.rsplit('/').next() else {
        return false;
    };
    let canonical = version(exact).map(|version| version.to_string());
    let expected = format!("/{name}/-/{base}-{exact}.tgz");
    let normalized = canonical
        .as_ref()
        .map(|version| format!("/{name}/-/{base}-{version}.tgz"));
    url.scheme() == "https"
        && matches!(
            url.host_str(),
            Some("registry.npmjs.org" | "registry.yarnpkg.com")
        )
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && (url.path() == expected || normalized.as_ref().is_some_and(|path| url.path() == path))
        && !url.path().contains(['\\', '\0'])
        && !url.path().contains("%2e")
        && !url.path().contains("%2E")
}
fn alias<'a>(name: &'a str, raw_version: &'a str) -> (&'a str, &'a str) {
    if let Some(target) = raw_version.strip_prefix("npm:")
        && let Some((real, exact)) = target
            .rsplit_once('@')
            .filter(|(real, exact)| !real.is_empty() && !exact.is_empty())
    {
        return (real, exact);
    }
    (name, raw_version)
}
fn path_name(path: &str) -> Option<&str> {
    path.rsplit_once("node_modules/")
        .map(|(_, name)| name)
        .filter(|name| valid_name(name))
}
fn optional_text(value: Option<&Value>) -> Result<Option<&str>> {
    value
        .map(|value| value.as_str().ok_or_else(invalid))
        .transpose()
}
fn optional_flag(value: Option<&Value>) -> Result<bool> {
    value
        .map(|value| value.as_bool().ok_or_else(invalid))
        .transpose()
        .map(|value| value.unwrap_or(false))
}
fn npm_v1(
    map: &Map<String, Value>,
    prefix: &str,
    builder: &mut Builder<'_>,
    depth: usize,
) -> Result<()> {
    if depth > 64 {
        return Err(capacity());
    }
    for (name, descriptor) in map {
        let descriptor = descriptor.as_object().ok_or_else(invalid)?;
        let occurrence = format!("{prefix}node_modules/{name}");
        let raw_version = optional_text(descriptor.get("version"))?.unwrap_or("");
        let reason = optional_flag(descriptor.get("link"))?.then_some("local_link");
        builder.add(
            name,
            raw_version,
            occurrence.clone(),
            optional_text(descriptor.get("resolved"))?,
            optional_flag(descriptor.get("bundled"))?,
            reason,
        )?;
        if let Some(children) = descriptor.get("dependencies") {
            npm_v1(
                children.as_object().ok_or_else(invalid)?,
                &format!("{occurrence}/"),
                builder,
                depth + 1,
            )?;
        }
    }
    Ok(())
}
fn parse_npm(text: &str, builder: &mut Builder<'_>) -> Result<String> {
    let document = bounded_json(text.as_bytes())?;
    let schema = document["lockfileVersion"].as_u64().ok_or_else(invalid)?;
    match schema {
        1 => {
            let empty = Map::new();
            let dependencies = match document.get("dependencies") {
                Some(value) => value.as_object().ok_or_else(invalid)?,
                None => &empty,
            };
            npm_v1(dependencies, "", builder, 0)?;
        }
        2 | 3 => {
            let packages = document["packages"].as_object().ok_or_else(invalid)?;
            for (path, descriptor) in packages {
                if path.is_empty() {
                    continue;
                }
                let descriptor = descriptor.as_object().ok_or_else(invalid)?;
                let local =
                    !path.contains("node_modules/") || optional_flag(descriptor.get("link"))?;
                let inferred_name = path_name(path);
                let name = optional_text(descriptor.get("name"))?
                    .or(inferred_name)
                    .unwrap_or("unknown");
                let raw_version = optional_text(descriptor.get("version"))?.unwrap_or("");
                let safe_location = !path.starts_with('/')
                    && !path.contains('\\')
                    && path.split('/').all(|part| !matches!(part, "" | "." | ".."));
                let reason = if local {
                    Some("local_or_workspace")
                } else if inferred_name.is_none() || !safe_location {
                    Some("unsupported_package_location")
                } else {
                    None
                };
                builder.add(
                    name,
                    raw_version,
                    path.clone(),
                    optional_text(descriptor.get("resolved"))?,
                    optional_flag(descriptor.get("inBundle"))?,
                    reason,
                )?;
            }
        }
        _ => return Err(Error::invalid("Unsupported npm lockfile schema version.")),
    }
    Ok(schema.to_string())
}

fn schema_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}
fn pnpm_identity<'a>(key: &'a str, schema: &str) -> Option<(&'a str, &'a str)> {
    let key = key.strip_prefix('/').unwrap_or(key);
    let (base, _) = key.split_once('(').unwrap_or((key, ""));
    // Validate nested peer context syntax without interpreting a dependency graph.
    let mut depth = 0_u32;
    for byte in key.as_bytes().iter().copied().skip(base.len()) {
        match byte {
            b'(' => {
                depth += 1;
                if depth > 64 {
                    return None;
                }
            }
            b')' => {
                depth = depth.checked_sub(1)?;
            }
            _ if depth == 0 => return None,
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    let (name, exact) = if schema == "5.4" {
        let (name, exact) = base.rsplit_once('/')?;
        (name, exact.split_once('_').map_or(exact, |(head, _)| head))
    } else {
        base.rsplit_once('@')?
    };
    if valid_name(name) && version(exact).is_some() {
        Some((name, exact))
    } else {
        None
    }
}
fn parse_pnpm(text: &str, builder: &mut Builder<'_>) -> Result<String> {
    let documents = yaml_documents(text)?;
    let mut selected = None;
    for (document_index, document) in documents.iter().enumerate() {
        let raw_schema = schema_text(&document["lockfileVersion"]).ok_or_else(invalid)?;
        let schema = match raw_schema.as_str() {
            "5.4" => "5.4",
            "6" | "6.0" => "6.0",
            "9" | "9.0" => "9.0",
            _ => return Err(Error::invalid("Unsupported pnpm lockfile schema version.")),
        };
        if selected.as_ref().is_some_and(|previous| previous != schema)
            || document_index > 0 && schema != "9.0"
        {
            return Err(invalid());
        }
        selected = Some(schema.to_owned());
        let empty = Map::new();
        let packages = match document.get("packages") {
            Some(value) => value.as_object().ok_or_else(invalid)?,
            None => &empty,
        };
        let snapshots = match document.get("snapshots") {
            Some(value) => value.as_object().ok_or_else(invalid)?,
            None => &empty,
        };
        let mut represented = BTreeSet::new();
        if schema == "9.0" {
            for (key, snapshot) in snapshots {
                if !snapshot.is_object() {
                    return Err(invalid());
                }
                let base = key.split_once('(').map_or(key.as_str(), |(base, _)| base);
                let descriptor = packages.get(base).unwrap_or(snapshot);
                pnpm_entry(key, descriptor, schema, document_index, document, builder)?;
                represented.insert(base);
            }
        }
        for (key, descriptor) in packages {
            if !represented.contains(key.as_str()) {
                pnpm_entry(key, descriptor, schema, document_index, document, builder)?;
            }
        }
        // Workspace importers are not public packages. Retain their direct local
        // dependencies as explicit unassessed inventory, never walk a file path.
        if let Some(importers) = document.get("importers") {
            for (importer, data) in importers.as_object().ok_or_else(invalid)? {
                for kind in ["dependencies", "devDependencies", "optionalDependencies"] {
                    if let Some(dependencies) = data.get(kind) {
                        for (name, value) in dependencies.as_object().ok_or_else(invalid)? {
                            let spec = value
                                .as_str()
                                .or_else(|| value["version"].as_str())
                                .unwrap_or("");
                            if ["link:", "file:", "workspace:"]
                                .iter()
                                .any(|prefix| spec.starts_with(prefix))
                            {
                                builder.add(name, spec, format!("document:{document_index}:importer:{importer}:{kind}:{name}"), None, false, Some("local_or_workspace"))?;
                            }
                        }
                    }
                }
            }
        }
    }
    selected.ok_or_else(invalid)
}
fn pnpm_entry(
    key: &str,
    descriptor: &Value,
    schema: &str,
    document_index: usize,
    document: &Value,
    builder: &mut Builder<'_>,
) -> Result<()> {
    if !descriptor.is_object() {
        return Err(invalid());
    }
    let parsed = pnpm_identity(key, schema);
    let (name, exact) = parsed.unwrap_or((
        descriptor["name"].as_str().unwrap_or("unknown"),
        descriptor["version"].as_str().unwrap_or(""),
    ));
    let resolution = descriptor.get("resolution");
    if resolution.is_some_and(|value| !value.is_object()) {
        return Err(invalid());
    }
    let nonzero_revision = resolution
        .and_then(|v| v.get("revision"))
        .is_some_and(|v| !v.is_null() && v != 0 && v != "0");
    let custom_source = resolution.is_some_and(|v| {
        v.get("repo").is_some()
            || v.get("directory").is_some()
            || v.get("type").is_some()
            || v.get("commit").is_some()
    });
    let reason = if nonzero_revision {
        Some("unsupported_registry_revision")
    } else if custom_source || parsed.is_none() {
        Some("path_git_or_unsupported_locator")
    } else {
        None
    };
    let modified = key.contains("patch_hash=")
        || descriptor.get("patched").and_then(Value::as_bool) == Some(true)
        || descriptor.get("bundledDependencies").is_some()
        || document
            .get("patchedDependencies")
            .and_then(Value::as_object)
            .is_some_and(|patches| patches.contains_key(&format!("{name}@{exact}")));
    builder.add(
        name,
        exact,
        format!("document:{document_index}:package:{key}"),
        optional_text(resolution.and_then(|value| value.get("tarball")))?,
        modified,
        reason,
    )
}

fn descriptor_name(descriptor: &str) -> Option<(&str, &str)> {
    let index = if let Some(scoped) = descriptor.strip_prefix('@') {
        scoped.find('@').map(|i| i + 1)
    } else {
        descriptor.find('@')
    }?;
    let (name, range) = descriptor.split_at(index);
    valid_name(name).then_some((name, &range[1..]))
}
fn unwrap_locator(reference: &str, depth: usize) -> Option<(String, String, bool)> {
    if depth > 16 {
        return None;
    }
    let (name, protocol) = descriptor_name(reference)?;
    if let Some(inner) = protocol
        .strip_prefix("virtual:")
        .and_then(|v| v.split_once('#').map(|(_, inner)| inner))
    {
        return unwrap_locator(&format!("{name}@{inner}"), depth + 1);
    }
    if let Some(inner) = protocol
        .strip_prefix("patch:")
        .and_then(|v| v.split_once('#').map(|(inner, _)| inner))
    {
        let decoded = percent_decode(inner)?;
        let (real, exact, _) = unwrap_locator(&decoded, depth + 1)?;
        return Some((real, exact, true));
    }
    let exact = protocol.strip_prefix("npm:")?;
    if let Some((real, exact)) = exact.rsplit_once('@').filter(|(real, _)| valid_name(real))
        && version(exact).is_some()
    {
        return Some((real.into(), exact.into(), false));
    }
    version(exact).map(|_| (name.into(), exact.into(), false))
}
fn percent_decode(value: &str) -> Option<String> {
    if value.len() > 4096 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = (char::from(*bytes.get(index + 1)?)).to_digit(16)?;
            let low = (char::from(*bytes.get(index + 2)?)).to_digit(16)?;
            out.push((high * 16 + low) as u8);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}
fn parse_berry(text: &str, builder: &mut Builder<'_>) -> Result<String> {
    let documents = yaml_documents(text)?;
    if documents.len() != 1 {
        return Err(invalid());
    }
    let document = &documents[0];
    let schema = document["__metadata"]["version"]
        .as_u64()
        .ok_or_else(invalid)?;
    if ![4, 6, 8, 10].contains(&schema) {
        return Err(Error::invalid(
            "Unsupported Yarn Berry lockfile schema version.",
        ));
    }
    for (key, descriptor) in document.as_object().ok_or_else(invalid)? {
        if key == "__metadata" {
            continue;
        }
        if !descriptor.is_object() {
            return Err(invalid());
        }
        let resolution = descriptor["resolution"].as_str().ok_or_else(invalid)?;
        if let Some((name, exact, modified)) = unwrap_locator(resolution, 0) {
            let inconsistent = descriptor
                .get("version")
                .and_then(Value::as_str)
                .is_some_and(|v| {
                    version(v)
                        .zip(version(&exact))
                        .is_none_or(|(a, b)| a.cmp_precedence(&b) != std::cmp::Ordering::Equal)
                });
            builder.add(
                &name,
                &exact,
                key.clone(),
                None,
                modified,
                inconsistent.then_some("locator_version_mismatch"),
            )?;
        } else {
            let name = descriptor_name(resolution).map_or("unknown", |(name, _)| name);
            builder.add(
                name,
                descriptor["version"].as_str().unwrap_or(""),
                key.clone(),
                None,
                false,
                Some("path_git_or_unsupported_locator"),
            )?;
        }
    }
    Ok(schema.to_string())
}

fn classic_strings(line: &str) -> Result<Vec<String>> {
    let mut rest = line.trim();
    let mut out = Vec::new();
    while !rest.is_empty() {
        if rest.starts_with('"') {
            let mut escape = false;
            let mut end = None;
            for (index, ch) in rest.char_indices().skip(1) {
                if escape {
                    escape = false;
                    continue;
                }
                if ch == '\\' {
                    escape = true;
                } else if ch == '"' {
                    end = Some(index + 1);
                    break;
                }
            }
            let end = end.ok_or_else(invalid)?;
            let value: String = serde_json::from_str(&rest[..end]).map_err(|_| invalid())?;
            out.push(value);
            rest = rest[end..].trim_start();
        } else {
            let end = rest.find([',', ' ', '\t']).unwrap_or(rest.len());
            if end == 0 {
                return Err(invalid());
            }
            out.push(rest[..end].to_owned());
            rest = rest[end..].trim_start();
        }
        if let Some(after) = rest.strip_prefix(',') {
            rest = after.trim_start();
        } else if !rest.is_empty() {
            return Err(invalid());
        }
    }
    if out.is_empty() {
        return Err(invalid());
    }
    Ok(out)
}
fn parse_classic(text: &str, builder: &mut Builder<'_>) -> Result<String> {
    if !text.lines().any(|line| line.trim() == "# yarn lockfile v1") {
        return Err(Error::invalid(
            "Unsupported Yarn Classic lockfile schema version.",
        ));
    }
    let mut records = Vec::<(Vec<String>, BTreeMap<String, String>)>::new();
    let mut fields = None;
    let mut keys_by_depth = BTreeMap::<usize, BTreeSet<String>>::new();
    let mut objects = BTreeSet::from([0_usize]);
    for line in text.lines() {
        let line = line.trim_end_matches([' ', '\r']);
        if line.len() > 64 * 1024 {
            return Err(capacity());
        }
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if line.contains('\t') {
            return Err(invalid());
        }
        if !line.starts_with(' ') {
            let header = line.strip_suffix(':').ok_or_else(invalid)?;
            let descriptors = classic_strings(header)?;
            if descriptors.iter().any(|v| descriptor_name(v).is_none()) {
                return Err(invalid());
            }
            if records.len() >= MAX_ENTRIES {
                return Err(capacity());
            }
            records.push((descriptors, BTreeMap::new()));
            fields = records.len().checked_sub(1);
            keys_by_depth.clear();
            objects.clear();
            objects.insert(0);
        } else {
            let Some(index) = fields else {
                return Err(invalid());
            };
            let indent = line.len() - line.trim_start_matches(' ').len();
            if indent > 64 {
                return Err(capacity());
            }
            if indent < 2 || indent % 2 != 0 || !objects.contains(&(indent - 2)) {
                return Err(invalid());
            }
            keys_by_depth.retain(|depth, _| *depth <= indent);
            objects.retain(|depth| *depth < indent);
            let (key, rest) = classic_field(line.trim_start())?;
            if !keys_by_depth.entry(indent).or_default().insert(key.clone()) {
                return Err(invalid());
            }
            if rest == ":" {
                objects.insert(indent);
            } else {
                if !rest.starts_with(' ') {
                    return Err(invalid());
                }
                let value = rest.trim_start();
                if value.is_empty() {
                    return Err(invalid());
                }
                // Nested requirements remain inert, but their syntax and
                // duplicate mappings are still checked. Integrity can contain
                // multiple whitespace-separated digest tokens.
                let values = if key == "integrity" && !value.starts_with('"') {
                    vec![value.to_owned()]
                } else {
                    classic_strings(value)?
                };
                if values.len() != 1 {
                    return Err(invalid());
                }
                if indent == 2 && matches!(key.as_str(), "version" | "resolved" | "integrity") {
                    records[index].1.insert(key, values[0].clone());
                }
            }
        }
    }
    let mut descriptors = BTreeSet::new();
    for (keys, data) in records {
        for key in &keys {
            if !descriptors.insert(key.clone()) {
                return Err(invalid());
            }
        }
        let first = keys.first().ok_or_else(invalid)?;
        let (install_name, range) = descriptor_name(first).ok_or_else(invalid)?;
        let name = range
            .strip_prefix("npm:")
            .and_then(|v| v.rsplit_once('@'))
            .map_or(install_name, |(real, _)| real);
        let exact = data.get("version").ok_or_else(invalid)?;
        let inconsistent_group = keys.iter().any(|key| {
            descriptor_name(key).is_none_or(|(name, range)| {
                let real = range
                    .strip_prefix("npm:")
                    .and_then(|v| v.rsplit_once('@'))
                    .map_or(name, |(real, _)| real);
                real != name_of(first).unwrap_or(name)
            })
        });
        let foreign_source = keys.iter().any(|key| {
            let Some((_, range)) = descriptor_name(key) else {
                return true;
            };
            let range = if let Some(alias) = range.strip_prefix("npm:") {
                alias.rsplit_once('@').map_or(alias, |(_, range)| range)
            } else {
                range
            };
            range.contains(':') || range.contains('/') || range.starts_with('.')
        });
        let reason = if foreign_source {
            Some("path_git_or_alternative_registry")
        } else if inconsistent_group {
            Some("ambiguous_grouped_identity")
        } else {
            None
        };
        builder.add(
            name,
            exact,
            keys.join(", "),
            data.get("resolved").map(String::as_str),
            false,
            reason,
        )?;
    }
    Ok("1".into())
}
fn classic_field(body: &str) -> Result<(String, &str)> {
    if body.starts_with('"') {
        let mut escaped = false;
        for (index, ch) in body.char_indices().skip(1) {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                let end = index + 1;
                let key = serde_json::from_str::<String>(&body[..end]).map_err(|_| invalid())?;
                return Ok((key, &body[end..]));
            }
        }
        Err(invalid())
    } else {
        let end = body.find([' ', ':']).ok_or_else(invalid)?;
        if end == 0 {
            return Err(invalid());
        }
        Ok((body[..end].to_owned(), &body[end..]))
    }
}
fn name_of(value: &str) -> Option<&str> {
    let (name, range) = descriptor_name(value)?;
    Some(
        range
            .strip_prefix("npm:")
            .and_then(|v| v.rsplit_once('@'))
            .map_or(name, |(real, _)| real),
    )
}

pub fn parse(text: &str, format: &str, context: &RegistryContext) -> Result<Inventory> {
    if text.is_empty() || text.len() > MAX_LOCKFILE {
        return Err(Error::invalid(
            "npm lockfile must contain 1..1048576 UTF-8 bytes.",
        ));
    }
    context.validate()?;
    let mut builder = Builder::new(context);
    let format_version = match format {
        "npm" => parse_npm(text, &mut builder)?,
        "pnpm" => parse_pnpm(text, &mut builder)?,
        "yarn_classic" => parse_classic(text, &mut builder)?,
        "yarn_berry" => parse_berry(text, &mut builder)?,
        _ => return Err(Error::invalid("Unsupported npm lockfile format.")),
    };
    builder.entries.sort_by(|a, b| {
        (&a.name, &a.version, &a.occurrence).cmp(&(&b.name, &b.version, &b.occurrence))
    });
    Ok(Inventory {
        format_version,
        entries: builder.entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> RegistryContext {
        RegistryContext {
            default: RegistryIdentity::Npmjs,
            ..Default::default()
        }
    }
    #[test]
    fn npm_versions_aliases_and_v2_compatibility_tree() {
        for schema in [2, 3] {
            let text = serde_json::json!({"lockfileVersion":schema,"packages":{"":{},"node_modules/alias":{"name":"@scope/real","version":"1.2.3","resolved":"https://registry.npmjs.org/@scope/real/-/real-1.2.3.tgz"}},"dependencies":{"ignored":{"version":"9.9.9"}}}).to_string();
            let inventory = parse(&text, "npm", &context()).unwrap();
            assert_eq!(inventory.entries.len(), 1);
            assert_eq!(inventory.entries[0].name, "@scope/real");
            assert!(inventory.entries[0].reason.is_none());
        }
        let text = r#"{"lockfileVersion":1,"dependencies":{"alias":{"version":"npm:@scope/real@1.2.3","dependencies":{"nested":{"version":"2.0.0"}}}}}"#;
        let inventory = parse(text, "npm", &context()).unwrap();
        assert_eq!(inventory.entries.len(), 2);
        assert_eq!(inventory.entries[0].name, "@scope/real");
    }
    #[test]
    fn registry_assertions_and_source_conflicts_are_explicit() {
        let text =
            r#"{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}"#;
        assert_eq!(
            parse(text, "npm", &RegistryContext::default())
                .unwrap()
                .entries[0]
                .reason
                .as_deref(),
            Some("registry_identity_unproven")
        );
        let text = text.replace(
            "\"version\":\"1.0.0\"",
            "\"version\":\"1.0.0\",\"resolved\":\"https://private.example/example.tgz\"",
        );
        assert_eq!(
            parse(&text, "npm", &context()).unwrap().entries[0]
                .reason
                .as_deref(),
            Some("path_git_or_alternative_registry")
        );
    }
    #[test]
    fn pnpm_formats_peers_multiple_documents_and_revisions() {
        for (schema, key) in [
            ("5.4", "/@scope/example/1.2.3_peer@1.0.0"),
            ("6.0", "/@scope/example@1.2.3(peer@1.0.0)"),
            ("9.0", "@scope/example@1.2.3(peer@1.0.0(nested@2.0.0))"),
        ] {
            let text = format!(
                "lockfileVersion: '{schema}'\npackages:\n  '{key}':\n    resolution: {{integrity: sha512-test}}\n"
            );
            let inventory = parse(&text, "pnpm", &context()).unwrap();
            assert_eq!(inventory.entries[0].name, "@scope/example");
            assert!(inventory.entries[0].reason.is_none());
        }
        let text = "lockfileVersion: '9.0'\npackages:\n  first@1.0.0: {}\n---\nlockfileVersion: '9.0'\npackages:\n  second@2.0.0:\n    resolution: {revision: 2}\n";
        let inventory = parse(text, "pnpm", &context()).unwrap();
        assert_eq!(inventory.entries.len(), 2);
        assert_eq!(
            inventory.entries[1].reason.as_deref(),
            Some("unsupported_registry_revision")
        );
    }
    #[test]
    fn yarn_classic_grouped_aliases_and_berry_wrappers() {
        let text = "# yarn lockfile v1\n\n\"alias@npm:real@^1\", \"alias@npm:real@~1\":\n  version \"1.2.3\"\n  resolved \"https://registry.yarnpkg.com/real/-/real-1.2.3.tgz#hash\"\n  dependencies:\n    nested \"^2\"\n";
        let inventory = parse(text, "yarn_classic", &context()).unwrap();
        assert_eq!(inventory.entries.len(), 1);
        assert_eq!(inventory.entries[0].name, "real");
        assert!(inventory.entries[0].reason.is_none());
        for schema in [4, 6, 8, 10] {
            let text = format!(
                "__metadata:\n  version: {schema}\n\n\"alias@npm:real@^1\":\n  version: 1.2.3\n  resolution: \"real@virtual:abcd#npm:1.2.3\"\n\n\"real@patch:real@npm%3A1.2.3#patch\":\n  version: 1.2.3\n  resolution: \"real@patch:real@npm%3A1.2.3#patch\"\n"
            );
            let inventory = parse(&text, "yarn_berry", &context()).unwrap();
            assert_eq!(inventory.entries.len(), 2);
            assert!(inventory.entries.iter().all(|e| e.reason.is_none()));
            assert!(inventory.entries.iter().any(|e| e.modified));
        }
    }
    #[test]
    fn duplicate_keys_yaml_aliases_tags_and_unknown_formats_fail_without_input() {
        for text in [
            "lockfileVersion: 9\npackages: &private {}\ncopy: *private",
            "lockfileVersion: 9\npackages: !!map {}",
            "lockfileVersion: 9\npackages: {}\npackages: {}",
        ] {
            assert!(parse(text, "pnpm", &context()).is_err());
        }
        assert!(
            parse(
                r#"{"lockfileVersion":3,"lockfileVersion":2,"packages":{}}"#,
                "npm",
                &context()
            )
            .is_err()
        );
        let error = parse("PRIVATE_SENTINEL", "pnpm", &context()).unwrap_err();
        assert!(!error.to_string().contains("PRIVATE_SENTINEL"));
        assert!(parse("lockfileVersion: 99", "pnpm", &context()).is_err());
    }
    #[test]
    fn exact_version_bounds_preserve_precedence() {
        assert_eq!(version("v1.2.3").unwrap().to_string(), "1.2.3");
        assert!(version("1.2").is_none());
        assert!(version("9007199254740992.0.0").is_none());
        assert_eq!(
            version("1.2.3+first")
                .unwrap()
                .cmp_precedence(&version("1.2.3+second").unwrap()),
            std::cmp::Ordering::Equal
        );
    }
    #[test]
    fn pnpm_underscore_names_and_malformed_peer_suffixes() {
        let inventory = parse(
            "lockfileVersion: 5.4\npackages:\n  /foo_bar/1.0.0_peer@2.0.0: {}\n",
            "pnpm",
            &context(),
        )
        .unwrap();
        assert_eq!(inventory.entries[0].name, "foo_bar");
        assert!(inventory.entries[0].reason.is_none());
        let inventory = parse(
            "lockfileVersion: '9.0'\npackages:\n  'example@1.0.0(peer@2.0.0)unexpected': {}\n",
            "pnpm",
            &context(),
        )
        .unwrap();
        assert!(inventory.entries[0].reason.is_some());
    }
    #[test]
    fn classic_nested_duplicates_fail_and_multiple_integrity_tokens_are_inert() {
        let text = "# yarn lockfile v1\nexample@^1:\n  version \"1.0.0\"\n  integrity sha512-one sha1-two\n  dependencies:\n    nested \"^2\"\n";
        assert_eq!(
            parse(text, "yarn_classic", &context())
                .unwrap()
                .entries
                .len(),
            1
        );
        assert!(
            parse(
                &format!("{text}    nested \"^3\"\n"),
                "yarn_classic",
                &context()
            )
            .is_err()
        );
    }
    #[test]
    fn classic_explicit_nonregistry_descriptors_do_not_need_resolved_fields() {
        for descriptor in [
            "example@file:../local",
            "example@link:../local",
            "example@https://private.example/example.tgz",
            "example@owner/repository",
        ] {
            let text = format!("# yarn lockfile v1\n\"{descriptor}\":\n  version \"1.0.0\"\n");
            let inventory = parse(&text, "yarn_classic", &context()).unwrap();
            assert_eq!(
                inventory.entries[0].reason.as_deref(),
                Some("path_git_or_alternative_registry")
            );
        }
    }
    #[test]
    fn registry_tarballs_cannot_assert_a_conflicting_name_or_version() {
        for source in [
            "https://registry.npmjs.org/other/-/other-1.0.0.tgz",
            "https://registry.npmjs.org/example/-/example-2.0.0.tgz",
        ] {
            let text=serde_json::json!({"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0","resolved":source}}}).to_string();
            assert!(
                parse(&text, "npm", &context()).unwrap().entries[0]
                    .reason
                    .is_some()
            );
        }
    }
}
