//! Pure, bounded docs.rs projections. Callback rows are provisional until success.
//!
//! Readers never fetch URLs, extract files, or run package code. The caller owns
//! raw-capture retention and commits a processing generation only after success.
use devres_domain::{Error, Result};
use html5ever::{
    tendril::StrTendril,
    tokenizer::{
        BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
        states::RawKind,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub const MAX_EXPANDED: u64 = 256 * 1024 * 1024;
pub const MAX_ITEM: usize = 1024 * 1024;
pub const MAX_ITEMS: usize = 1_000_000;
const MAX_DOCUMENT: usize = 4 * 1024 * 1024;
const MAX_MEMBERS: usize = 20_000;
const MAX_TARGETS: usize = 1_000;
const MAX_GRAPH: usize = 64 * 1024 * 1024;

pub struct ProcessingBudget {
    pub deadline: Instant,
    pub cancel: CancellationToken,
}
impl ProcessingBudget {
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(15),
            cancel,
        }
    }
    fn check(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            return Err(Error::new(
                "cancelled",
                "Documentation processing was canceled.",
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(Error::capacity(
                "Documentation processing deadline exceeded.",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DocTarget {
    pub triple: String,
    pub is_default: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HtmlDocument {
    pub target: Option<String>,
    pub path: String,
    pub text: String,
    pub headings: Vec<String>,
    /// Inert references, never destinations to fetch.
    pub links: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiItem {
    pub format_version: u32,
    pub version_asserted: bool,
    pub target_asserted: bool,
    pub public_paths: Vec<String>,
    pub kind: String,
    pub signature: Value,
    /// Capture-local IDs only; resolve against the same JSON capture.
    pub relationships: Vec<String>,
    pub docs: Option<String>,
    pub local_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonSummary {
    pub format_version: u32,
    pub target: Option<String>,
    pub version_asserted: bool,
    pub target_asserted: bool,
    pub total_items: usize,
    pub public_items: usize,
    pub unresolved_references: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZipSummary {
    pub members: usize,
    pub documents: usize,
    pub expanded_bytes: u64,
}

fn malformed() -> Error {
    Error::integrity("Malformed documentation representation.")
}
fn limit() -> Error {
    Error::capacity("Documentation processing bounds exceeded.")
}
fn valid_target(s: &str) -> bool {
    crate::bulk::valid_target(s) && s.contains('-')
}

fn local_id(v: &Value) -> Result<String> {
    v.as_u64()
        .filter(|n| *n <= u32::MAX as u64)
        .map(|n| n.to_string())
        .ok_or_else(malformed)
}
fn parse_value(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice(bytes).map_err(|_| malformed())
}

/// A small JSON framing reader bounds a value *before* allocating its Value.
/// Only one index/path entry is materialized; the index map is never a Value.
struct JsonReader<'a, R> {
    input: BufReader<R>,
    bytes: u64,
    budget: &'a ProcessingBudget,
}
impl<'a, R: Read> JsonReader<'a, R> {
    fn new(input: R, budget: &'a ProcessingBudget) -> Self {
        Self {
            input: BufReader::new(input),
            bytes: 0,
            budget,
        }
    }
    fn peek(&mut self) -> Result<Option<u8>> {
        self.budget.check()?;
        self.input
            .fill_buf()
            .map(|b| b.first().copied())
            .map_err(|_| malformed())
    }
    fn byte(&mut self) -> Result<u8> {
        let b = self.peek()?.ok_or_else(malformed)?;
        self.input.consume(1);
        self.bytes += 1;
        if self.bytes > MAX_EXPANDED {
            return Err(limit());
        }
        Ok(b)
    }
    fn ws(&mut self) -> Result<()> {
        while self.peek()?.is_some_and(|b| b.is_ascii_whitespace()) {
            self.byte()?;
        }
        Ok(())
    }
    fn expect(&mut self, b: u8) -> Result<()> {
        self.ws()?;
        if self.byte()? != b {
            return Err(malformed());
        }
        Ok(())
    }
    fn value(&mut self, max: usize) -> Result<Value> {
        self.ws()?;
        let mut out = Vec::new();
        let mut stack = Vec::new();
        let mut quoted = false;
        let mut escaped = false;
        loop {
            let b = self.peek()?.ok_or_else(malformed)?;
            if !quoted
                && stack.is_empty()
                && !out.is_empty()
                && (b.is_ascii_whitespace() || b == b',' || b == b'}' || b == b']')
            {
                break;
            }
            let b = self.byte()?;
            if out.len() == max {
                return Err(limit());
            }
            out.push(b);
            if quoted {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    quoted = false;
                    if stack.is_empty() {
                        break;
                    }
                }
            } else {
                match b {
                    b'"' => quoted = true,
                    b'{' | b'[' => {
                        stack.push(b);
                        if stack.len() > 64 {
                            return Err(limit());
                        }
                    }
                    b'}' | b']' => {
                        let expected = if b == b'}' { b'{' } else { b'[' };
                        if stack.pop() != Some(expected) {
                            return Err(malformed());
                        }
                        if stack.is_empty() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if self.peek()?.is_none() {
                if quoted || !stack.is_empty() {
                    return Err(malformed());
                }
                break;
            }
        }
        parse_value(&out)
    }
    fn key(&mut self) -> Result<String> {
        let value = self.value(4096)?;
        let key = value.as_str().ok_or_else(malformed)?.to_owned();
        self.expect(b':')?;
        Ok(key)
    }
    fn separator(&mut self) -> Result<bool> {
        self.ws()?;
        match self.byte()? {
            b'}' => Ok(false),
            b',' => Ok(true),
            _ => Err(malformed()),
        }
    }
    fn map(&mut self, mut item: impl FnMut(String, Value) -> Result<()>) -> Result<usize> {
        self.expect(b'{')?;
        self.ws()?;
        if self.peek()? == Some(b'}') {
            self.byte()?;
            return Ok(0);
        }
        let mut keys = HashSet::new();
        loop {
            let key = self.key()?;
            if keys.len() >= MAX_ITEMS {
                return Err(limit());
            }
            if !keys.insert(key.clone()) {
                return Err(malformed());
            }
            item(key, self.value(MAX_ITEM)?)?;
            if !self.separator()? {
                break;
            }
        }
        Ok(keys.len())
    }
}

#[derive(Default)]
struct Envelope {
    root: Option<String>,
    version: Option<String>,
    target: Option<String>,
    format: Option<u32>,
    private: Option<bool>,
    index_count: usize,
}
fn document<R: Read>(
    input: R,
    budget: &ProcessingBudget,
    mut item: impl FnMut(String, Value) -> Result<()>,
    mut path: impl FnMut(String, Value) -> Result<()>,
) -> Result<Envelope> {
    let mut reader = JsonReader::new(input, budget);
    reader.expect(b'{')?;
    let mut seen = HashSet::new();
    let mut envelope = Envelope::default();
    loop {
        let key = reader.key()?;
        if !seen.insert(key.clone()) {
            return Err(malformed());
        }
        match key.as_str() {
            "index" => envelope.index_count = reader.map(&mut item)?,
            "paths" => {
                reader.map(&mut path)?;
            }
            "external_crates" => {
                reader.map(|_, _| Ok(()))?;
            }
            "root" => envelope.root = Some(local_id(&reader.value(MAX_ITEM)?)?),
            "crate_version" => {
                let v = reader.value(MAX_ITEM)?;
                envelope.version = if v.is_null() {
                    None
                } else {
                    Some(v.as_str().ok_or_else(malformed)?.to_owned())
                };
            }
            "target" => {
                let v = reader.value(MAX_ITEM)?;
                envelope.target = Some(
                    v["triple"]
                        .as_str()
                        .filter(|s| valid_target(s))
                        .ok_or_else(malformed)?
                        .to_owned(),
                );
            }
            "format_version" => {
                envelope.format = Some(
                    reader
                        .value(MAX_ITEM)?
                        .as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(malformed)?,
                )
            }
            "includes_private" => {
                envelope.private = Some(reader.value(MAX_ITEM)?.as_bool().ok_or_else(malformed)?)
            }
            _ => {
                reader.value(MAX_ITEM)?;
            }
        }
        if !reader.separator()? {
            break;
        }
    }
    reader.ws()?;
    if reader.peek()?.is_some()
        || !seen.contains("index")
        || !seen.contains("paths")
        || envelope.root.is_none()
        || envelope.format.is_none()
        || envelope.private.is_none()
    {
        return Err(malformed());
    }
    Ok(envelope)
}

#[derive(Clone)]
struct Node {
    name: Option<String>,
    kind: String,
    public: bool,
    crate_id: u64,
    children: Vec<String>,
    referent: Option<String>,
    glob: bool,
}
static UNIT_INNER: Value = Value::Null;
fn item_shape<'a>(id: &str, value: &'a Value) -> Result<(&'a str, &'a Value)> {
    if local_id(&value["id"])? != id
        || value["crate_id"].as_u64().is_none()
        || !(value["name"].is_null() || value["name"].is_string())
        || !(value["docs"].is_null() || value["docs"].is_string())
    {
        return Err(malformed());
    }
    if value["inner"] == "extern_type" {
        return Ok(("extern_type", &UNIT_INNER));
    }
    let inner = value["inner"]
        .as_object()
        .filter(|v| v.len() == 1)
        .ok_or_else(malformed)?;
    let (kind, data) = inner.iter().next().ok_or_else(malformed)?;
    if !matches!(
        kind.as_str(),
        "module"
            | "extern_crate"
            | "use"
            | "union"
            | "struct"
            | "struct_field"
            | "enum"
            | "variant"
            | "function"
            | "trait"
            | "trait_alias"
            | "impl"
            | "type_alias"
            | "constant"
            | "static"
            | "macro"
            | "proc_macro"
            | "primitive"
            | "assoc_const"
            | "assoc_type"
    ) {
        return Err(malformed());
    }
    if kind == "macro" || (kind == "struct_field" && data.is_string()) {
        if !data.is_string() {
            return Err(malformed());
        }
    } else if !data.is_object() {
        return Err(malformed());
    }
    if kind == "function"
        && (!data["sig"]["inputs"].is_array()
            || !data["sig"]["is_c_variadic"].is_boolean()
            || !data["generics"].is_object()
            || !data["header"]["is_const"].is_boolean()
            || !data["header"]["is_async"].is_boolean()
            || !data["header"]["is_unsafe"].is_boolean()
            || !data["has_body"].is_boolean())
    {
        return Err(malformed());
    }
    if !value["attrs"].is_array() || !value["links"].is_object() {
        return Err(malformed());
    }
    Ok((kind.as_str(), data))
}
fn graph_charge(bytes: &Cell<usize>, amount: usize) -> Result<()> {
    let next = bytes.get().checked_add(amount).ok_or_else(limit)?;
    if next > MAX_GRAPH {
        return Err(limit());
    }
    bytes.set(next);
    Ok(())
}
fn node(id: &str, value: &Value, graph_bytes: &Cell<usize>) -> Result<Node> {
    let (kind, data) = item_shape(id, value)?;
    let visibility = &value["visibility"];
    if visibility != "public" && visibility != "default" && !visibility.is_object() {
        return Err(malformed());
    }
    let sources = [
        data.get("items"),
        data.get("impls"),
        data.get("implementations"),
        data.get("variants"),
        data.get("kind")
            .and_then(|v| v.get("plain"))
            .and_then(|v| v.get("fields")),
        data.get("kind").and_then(|v| v.get("tuple")),
        data.get("kind")
            .and_then(|v| v.get("struct"))
            .and_then(|v| v.get("fields")),
    ];
    let mut arrays: [Option<&[Value]>; 7] = [None; 7];
    let mut count = 0usize;
    for (slot, source) in arrays.iter_mut().zip(sources) {
        if let Some(source) = source {
            let values = source.as_array().ok_or_else(malformed)?;
            for value in values.iter().filter(|v| !v.is_null()) {
                if value.as_u64().filter(|v| *v <= u32::MAX as u64).is_none() {
                    return Err(malformed());
                }
                count = count.checked_add(1).ok_or_else(limit)?;
            }
            *slot = Some(values);
        }
    }
    // Charge vector slots and each short-ID heap allocation *before* creating
    // any child String. Conservative heap/tree overhead also covers rounding.
    let child_storage = count
        .checked_mul(std::mem::size_of::<String>() + 32 + 32)
        .ok_or_else(limit)?;
    let base = std::mem::size_of::<Node>()
        + std::mem::size_of::<String>()
        + 256
        + id.len()
        + 32
        + kind.len()
        + 32
        + value["name"].as_str().map_or(0, str::len)
        + 32
        + 64;
    graph_charge(
        graph_bytes,
        base.checked_add(child_storage).ok_or_else(limit)?,
    )?;
    let mut children = Vec::new();
    children.try_reserve_exact(count).map_err(|_| limit())?;
    for values in arrays.into_iter().flatten() {
        for value in values.iter().filter(|v| !v.is_null()) {
            children.push(local_id(value)?);
        }
    }
    let referent = if kind == "use" && !data["id"].is_null() {
        Some(local_id(&data["id"])?)
    } else {
        None
    };
    Ok(Node {
        name: value["name"].as_str().map(str::to_owned),
        kind: kind.to_owned(),
        public: visibility == "public",
        crate_id: value["crate_id"].as_u64().ok_or_else(malformed)?,
        children,
        referent,
        glob: data["is_glob"].as_bool().unwrap_or(false),
    })
}

type PathWork = (String, String, Vec<String>, bool);
fn enqueue(
    queue: &mut VecDeque<PathWork>,
    id: &str,
    path: String,
    ancestors: &[String],
    inherited: bool,
    scheduled: &mut usize,
    bytes: &mut usize,
) -> Result<()> {
    let cost = id.len()
        + 32
        + path.capacity()
        + 32
        + (ancestors.len() + 1) * std::mem::size_of::<String>() * 2
        + ancestors.iter().map(|s| s.capacity() + 32).sum::<usize>()
        + std::mem::size_of::<PathWork>() * 2
        + id.len()
        + path.len()
        + 256; // Retained public-path tree entries/clones.
    let next = bytes.checked_add(cost).ok_or_else(limit)?;
    if *scheduled >= MAX_ITEMS || next > MAX_GRAPH || path.len() > 4096 || ancestors.len() > 64 {
        return Err(limit());
    }
    *bytes = next;
    *scheduled += 1;
    queue.push_back((id.to_owned(), path, ancestors.to_vec(), inherited));
    Ok(())
}

fn exported_paths(
    nodes: &BTreeMap<String, Node>,
    root: &str,
    budget: &ProcessingBudget,
) -> Result<(BTreeMap<String, BTreeSet<String>>, usize)> {
    let root_node = nodes
        .get(root)
        .filter(|n| n.kind == "module")
        .ok_or_else(malformed)?;
    let name = root_node.name.as_deref().ok_or_else(malformed)?;
    let mut paths: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if name.len() > 4096 {
        return Err(limit());
    }
    let mut queue = VecDeque::new();
    let mut scheduled = 0usize;
    let mut traversal_bytes = 0usize;
    enqueue(
        &mut queue,
        root,
        name.to_owned(),
        &[],
        true,
        &mut scheduled,
        &mut traversal_bytes,
    )?;
    let mut visits = 0usize;
    let mut missing = 0;
    while let Some((id, path, mut ancestors, inherited)) = queue.pop_front() {
        budget.check()?;
        visits += 1;
        if visits > MAX_ITEMS || path.len() > 4096 || ancestors.len() > 64 {
            return Err(limit());
        }
        if ancestors.contains(&id) {
            continue;
        }
        let Some(n) = nodes.get(&id) else {
            missing += 1;
            continue;
        };
        if n.crate_id != root_node.crate_id {
            continue;
        }
        if id != root && !n.public && !inherited && n.kind != "impl" {
            continue;
        }
        ancestors.push(id.clone());
        if n.kind == "use" {
            if let Some(target) = &n.referent {
                if n.glob {
                    if let Some(target) = nodes.get(target) {
                        for child in &target.children {
                            if let Some(child_node) = nodes.get(child)
                                && let Some(name) = &child_node.name
                            {
                                let parent = path.rsplit_once("::").map_or(path.as_str(), |v| v.0);
                                if parent.len().saturating_add(name.len() + 2) > 4096 {
                                    return Err(limit());
                                }
                                enqueue(
                                    &mut queue,
                                    child,
                                    format!("{parent}::{name}"),
                                    &ancestors,
                                    false,
                                    &mut scheduled,
                                    &mut traversal_bytes,
                                )?;
                            }
                        }
                    } else {
                        missing += 1;
                    }
                } else {
                    enqueue(
                        &mut queue,
                        target,
                        path,
                        &ancestors,
                        true,
                        &mut scheduled,
                        &mut traversal_bytes,
                    )?;
                }
            }
            continue;
        }
        if n.kind != "impl" {
            let entry = paths.entry(id.clone()).or_default();
            if entry.len() >= 256 {
                return Err(limit());
            }
            entry.insert(path.clone());
        }
        for child in &n.children {
            if let Some(c) = nodes.get(child) {
                let child_path = match &c.name {
                    Some(name) => {
                        if path.len().saturating_add(name.len() + 2) > 4096 {
                            return Err(limit());
                        }
                        format!("{path}::{name}")
                    }
                    None if c.kind == "impl" => path.clone(),
                    _ => continue,
                };
                let default_public = matches!(n.kind.as_str(), "trait" | "enum" | "variant");
                enqueue(
                    &mut queue,
                    child,
                    child_path,
                    &ancestors,
                    default_public,
                    &mut scheduled,
                    &mut traversal_bytes,
                )?;
            } else {
                missing += 1;
            }
        }
    }
    Ok((paths, missing))
}
fn module_signature(
    id: &str,
    inner: &Value,
    nodes: &BTreeMap<String, Node>,
    public: &BTreeMap<String, BTreeSet<String>>,
    budget: &ProcessingBudget,
) -> Result<(Value, BTreeSet<String>)> {
    let parents = public.get(id).ok_or_else(malformed)?;
    let mut exports = BTreeSet::new();
    let mut references = BTreeSet::new();
    let mut bytes = 0usize;
    let mut add = |reference: &str| -> Result<()> {
        budget.check()?;
        if let Some(aliases) = public.get(reference) {
            for alias in aliases {
                let Some((parent, _)) = alias.rsplit_once("::") else {
                    continue;
                };
                if parents.contains(parent) && !exports.contains(alias) {
                    bytes = bytes.saturating_add(alias.len() + 128);
                    if bytes > MAX_ITEM {
                        return Err(limit());
                    }
                    exports.insert(alias.clone());
                    references.insert(reference.to_owned());
                }
            }
        }
        Ok(())
    };
    for child_id in &nodes.get(id).ok_or_else(malformed)?.children {
        let Some(child) = nodes.get(child_id) else {
            continue;
        };
        if !child.public {
            continue;
        }
        if child.kind == "use" {
            if let Some(target) = &child.referent {
                if child.glob {
                    if let Some(target) = nodes.get(target) {
                        for child in &target.children {
                            add(child)?;
                        }
                    }
                } else {
                    add(target)?;
                }
            }
        } else {
            add(child_id)?;
        }
    }
    let mut data = Value::Object(
        inner
            .as_object()
            .ok_or_else(malformed)?
            .iter()
            .filter(|(key, _)| key.as_str() != "items")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    let map = data.as_object_mut().ok_or_else(malformed)?;
    map.insert(
        "exports".into(),
        Value::Array(exports.into_iter().map(Value::String).collect()),
    );
    Ok((data, references))
}

fn charge(remaining: &mut usize, bytes: usize) -> Result<()> {
    *remaining = remaining.checked_sub(bytes).ok_or_else(limit)?;
    Ok(())
}
fn normalize(
    value: &Value,
    paths: &BTreeMap<String, String>,
    relationships: &mut BTreeSet<String>,
    reference: bool,
    remaining: &mut usize,
) -> Result<Value> {
    charge(remaining, 16)?;
    if reference && let Ok(id) = local_id(value) {
        relationships.insert(id.clone());
        return if let Some(path) = paths.get(&id) {
            charge(remaining, path.len() + 16)?;
            Ok(json!({"path":path}))
        } else {
            Ok(json!({"unresolved_reference":true}))
        };
    }
    Ok(match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, value) in map {
                if matches!(key.as_str(), "span" | "crate_id") {
                    continue;
                }
                charge(remaining, key.len())?;
                out.insert(
                    key.clone(),
                    normalize(
                        value,
                        paths,
                        relationships,
                        key == "id"
                            || matches!(
                                key.as_str(),
                                "items" | "impls" | "implementations" | "variants" | "fields"
                            ),
                        remaining,
                    )?,
                );
            }
            Value::Object(out)
        }
        Value::Array(values) => {
            let mut out = Vec::new();
            for value in values {
                out.push(normalize(
                    value,
                    paths,
                    relationships,
                    reference,
                    remaining,
                )?);
            }
            Value::Array(out)
        }
        Value::String(s) => {
            charge(remaining, s.len())?;
            value.clone()
        }
        _ => value.clone(),
    })
}

/// `reader` is expanded JSON (the collector retains/decompresses raw gzip).
/// Two passes establish the envelope and public paths before streaming API rows.
pub fn parse_rustdoc_json<R: Read + Seek>(
    mut reader: R,
    expected_version: &str,
    expected_target: Option<&str>,
    budget: &ProcessingBudget,
    mut emit: impl FnMut(ApiItem) -> Result<()>,
) -> Result<JsonSummary> {
    budget.check()?;
    let start = reader.stream_position().map_err(|_| malformed())?;
    let mut nodes = BTreeMap::new();
    let mut stable = BTreeMap::new();
    let graph_bytes = Cell::new(0usize);
    let shape_error = RefCell::new(None);
    let first = document(
        &mut reader,
        budget,
        |id, value| {
            let n = match node(&id, &value, &graph_bytes) {
                Ok(n) => n,
                Err(error) if error.code == "capacity" => return Err(error),
                Err(error) => {
                    *shape_error.borrow_mut() = Some(error);
                    return Ok(());
                }
            };
            nodes.insert(id, n);
            Ok(())
        },
        |id, value| {
            let Some(path) = value["path"]
                .as_array()
                .filter(|v| !v.is_empty() && v.len() <= 64)
            else {
                *shape_error.borrow_mut() = Some(malformed());
                return Ok(());
            };
            let segments = path
                .iter()
                .map(|v| v.as_str().ok_or_else(malformed))
                .collect::<Result<Vec<_>>>()?;
            let path_len = segments.iter().map(|s| s.len()).sum::<usize>()
                + segments.len().saturating_sub(1) * 2;
            if path_len > 4096 {
                return Err(limit());
            }
            graph_charge(
                &graph_bytes,
                id.capacity() + path_len + std::mem::size_of::<String>() * 2 + 256 + 64,
            )?;
            stable.insert(id, segments.join("::"));
            Ok(())
        },
    )?;
    let format = first.format.ok_or_else(malformed)?;
    if !matches!(format, 43 | 55 | 56 | 61) {
        return Err(Error::new(
            "unsupported_format",
            "Rustdoc JSON format is not supported; raw capture remains available.",
        ));
    }
    if let Some(error) = shape_error.into_inner() {
        return Err(error);
    }
    if first
        .version
        .as_deref()
        .is_some_and(|v| v != expected_version)
        || first
            .target
            .as_deref()
            .zip(expected_target)
            .is_some_and(|(a, b)| a != b)
    {
        return Err(Error::integrity(
            "Rustdoc JSON version or target identity mismatch.",
        ));
    }
    // Format43 predates the target envelope; later schemas require it.
    if format != 43 && first.target.is_none() {
        return Err(malformed());
    }
    let root = first.root.as_deref().ok_or_else(malformed)?;
    let (public, unresolved) = exported_paths(&nodes, root, budget)?;
    for (id, aliases) in &public {
        if let Some(path) = aliases.first() {
            stable.insert(id.clone(), path.clone());
        }
    }
    reader
        .seek(SeekFrom::Start(start))
        .map_err(|_| malformed())?;
    let mut public_items = 0usize;
    let mut unresolved_references = unresolved;
    let second = document(
        &mut reader,
        budget,
        |id, value| {
            let Some(aliases) = public.get(&id) else {
                return Ok(());
            };
            let (kind, inner) = item_shape(&id, &value)?;
            let (inner, mut relationships) = if kind == "module" {
                module_signature(&id, inner, &nodes, &public, budget)?
            } else {
                (inner.clone(), BTreeSet::new())
            };
            if let Some(links) = value["links"].as_object() {
                for id in links.values() {
                    relationships.insert(local_id(id)?);
                }
            }
            let mut remaining = MAX_ITEM;
            let signature = normalize(
                &json!({"kind":kind,"inner":inner,"attrs":value["attrs"],"deprecation":value["deprecation"]}),
                &stable,
                &mut relationships,
                false,
                &mut remaining,
            )?;
            unresolved_references = unresolved_references.saturating_add(
                relationships
                    .iter()
                    .filter(|id| !stable.contains_key(*id))
                    .count(),
            );
            public_items += 1;
            emit(ApiItem {
                format_version: format,
                version_asserted: first.version.is_some(),
                target_asserted: first.target.is_some() && expected_target.is_some(),
                public_paths: aliases.iter().cloned().collect(),
                kind: kind.to_owned(),
                signature,
                relationships: relationships.into_iter().collect(),
                docs: value["docs"].as_str().map(str::to_owned),
                local_id: id,
            })
        },
        |_, _| Ok(()),
    )?;
    if second.format != first.format
        || second.root != first.root
        || second.version != first.version
        || second.target != first.target
        || second.index_count != first.index_count
    {
        return Err(Error::integrity("Rustdoc JSON changed while processing."));
    }
    Ok(JsonSummary {
        format_version: format,
        target: first.target.clone(),
        version_asserted: first.version.is_some(),
        target_asserted: first.target.is_some() && expected_target.is_some(),
        total_items: first.index_count,
        public_items,
        unresolved_references,
    })
}

#[derive(Default)]
struct HtmlState {
    stack: Vec<String>,
    text: String,
    headings: Vec<String>,
    links: Vec<String>,
    targets: BTreeMap<String, bool>,
    heading: Option<String>,
    anchor: Option<(String, String)>,
    error: Option<Error>,
    completed: usize,
    tokens: usize,
}
struct HtmlSink<'a> {
    state: RefCell<HtmlState>,
    budget: &'a ProcessingBudget,
    platforms: bool,
}
fn hidden(s: &str) -> bool {
    matches!(
        s,
        "script"
            | "style"
            | "head"
            | "template"
            | "noscript"
            | "iframe"
            | "xmp"
            | "noembed"
            | "noframes"
    )
}
fn void(s: &str) -> bool {
    matches!(
        s,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}
impl TokenSink for HtmlSink<'_> {
    type Handle = ();
    fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
        let mut s = self.state.borrow_mut();
        if s.error.is_some() {
            return TokenSinkResult::Continue;
        }
        if let Err(e) = self.budget.check() {
            s.error = Some(e);
            return TokenSinkResult::Continue;
        }
        s.tokens += 1;
        if s.tokens > 500_000 {
            s.error = Some(limit());
            return TokenSinkResult::Continue;
        }
        if !matches!(token, Token::ParseError(_) | Token::EOFToken) {
            s.completed += 1;
        }
        match token {
            Token::TagToken(tag) => {
                let name: &str = tag.name.as_ref();
                if tag.attrs.len() > 128
                    || name.len() > 256
                    || tag
                        .attrs
                        .iter()
                        .map(|a| a.value.len() + a.name.local.len())
                        .sum::<usize>()
                        > 16384
                {
                    s.error = Some(limit());
                    return TokenSinkResult::Continue;
                }
                if tag.kind == TagKind::StartTag {
                    if name == "body"
                        && let Some(at) = s.stack.iter().rposition(|n| n == "head")
                    {
                        s.stack.truncate(at);
                    }
                    let inert = s.stack.iter().any(|n| hidden(n)) || hidden(name);
                    if !inert {
                        if matches!(name, "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
                            s.heading = Some(String::new());
                        }
                        if name == "a" {
                            let href = tag
                                .attrs
                                .iter()
                                .find(|a| &*a.name.local == "href")
                                .map(|a| a.value.to_string());
                            if let Some(href) = href
                                && href.len() <= 4096
                                && !href.chars().any(char::is_control)
                                && !href
                                    .trim_start()
                                    .to_ascii_lowercase()
                                    .starts_with("javascript:")
                                && !href.trim_start().to_ascii_lowercase().starts_with("data:")
                            {
                                if s.links.len() >= 20_000 {
                                    s.error = Some(limit());
                                    return TokenSinkResult::Continue;
                                }
                                s.links.push(href.clone());
                                s.anchor = Some((href, String::new()));
                            }
                        }
                        if matches!(
                            name,
                            "p" | "div" | "pre" | "li" | "br" | "h1" | "h2" | "h3" | "h4" | "tr"
                        ) {
                            s.text.push('\n');
                        }
                    }
                    if !void(name) {
                        if s.stack.len() >= 64 {
                            s.error = Some(limit());
                            return TokenSinkResult::Continue;
                        }
                        s.stack.push(name.into());
                    }
                    return match name {
                        "script" => TokenSinkResult::RawData(RawKind::ScriptData),
                        "style" | "iframe" | "xmp" | "noembed" | "noframes" | "noscript" => {
                            TokenSinkResult::RawData(RawKind::Rawtext)
                        }
                        "title" | "textarea" => TokenSinkResult::RawData(RawKind::Rcdata),
                        _ => TokenSinkResult::Continue,
                    };
                }
                if name == "a"
                    && let Some((href, label)) = s.anchor.take()
                    && self.platforms
                {
                    let triple = label.trim();
                    if valid_target(triple) {
                        if !href.starts_with('/')
                            || href.starts_with("//")
                            || href.contains(['?', '#', '\\'])
                        {
                            s.error = Some(malformed());
                            return TokenSinkResult::Continue;
                        }
                        let default = !href.contains(&format!("/{triple}/"));
                        if s.targets.insert(triple.to_owned(), default).is_some() {
                            s.error = Some(malformed());
                        }
                        if s.targets.len() > MAX_TARGETS {
                            s.error = Some(limit());
                        }
                    }
                }
                if matches!(name, "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
                    && let Some(heading) = s.heading.take()
                {
                    if s.headings.len() >= 20_000 {
                        s.error = Some(limit());
                    } else {
                        s.headings.push(heading.trim().to_owned());
                    }
                }
                if let Some(at) = s.stack.iter().rposition(|n| n == name) {
                    s.stack.truncate(at);
                }
                if matches!(
                    name,
                    "p" | "div" | "pre" | "li" | "h1" | "h2" | "h3" | "h4" | "tr"
                ) && !s.stack.iter().any(|n| hidden(n))
                {
                    s.text.push('\n');
                }
            }
            Token::CharacterTokens(text) if !s.stack.iter().any(|n| hidden(n)) => {
                if s.text.len() + text.len() > MAX_DOCUMENT {
                    s.error = Some(limit());
                    return TokenSinkResult::Continue;
                }
                s.text.push_str(&text);
                if let Some(h) = &mut s.heading {
                    h.push_str(&text);
                }
                if let Some((_, a)) = &mut s.anchor {
                    a.push_str(&text);
                }
            }
            Token::NullCharacterToken => s.error = Some(malformed()),
            Token::CommentToken(text) if text.len() > 16384 => s.error = Some(limit()),
            _ => {}
        }
        TokenSinkResult::Continue
    }
}
fn html(bytes: &[u8], budget: &ProcessingBudget, platforms: bool) -> Result<HtmlState> {
    let text = std::str::from_utf8(bytes).map_err(|_| malformed())?;
    if text.contains('\0') {
        return Err(malformed());
    }
    let sink = HtmlSink {
        state: RefCell::new(HtmlState::default()),
        budget,
        platforms,
    };
    let tokenizer = Tokenizer::new(sink, TokenizerOpts::default());
    let input = BufferQueue::default();
    let mut offset = 0;
    let mut pending = 0;
    while offset < text.len() {
        budget.check()?;
        let mut end = (offset + 4096).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let completed = tokenizer.sink.state.borrow().completed;
        input.push_back(StrTendril::from_slice(&text[offset..end]));
        let _ = tokenizer.feed(&input);
        let mut s = tokenizer.sink.state.borrow_mut();
        if let Some(e) = s.error.take() {
            return Err(e);
        }
        if s.completed == completed {
            pending += end - offset;
        } else {
            pending = 0;
        }
        if pending > 16384 {
            return Err(limit());
        }
        offset = end;
    }
    tokenizer.end();
    let mut state = tokenizer.sink.state.into_inner();
    if let Some(e) = state.error.take() {
        return Err(e);
    }
    Ok(state)
}
pub fn parse_platforms<R: Read>(
    mut reader: R,
    budget: &ProcessingBudget,
) -> Result<Vec<DocTarget>> {
    let bytes = read_bounded(&mut reader, MAX_ITEM, budget)?;
    let state = html(&bytes, budget, true)?;
    Ok(state
        .targets
        .into_iter()
        .map(|(triple, is_default)| DocTarget { triple, is_default })
        .collect())
}
fn read_bounded(reader: &mut impl Read, max: usize, budget: &ProcessingBudget) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        budget.check()?;
        let n = reader.read(&mut chunk).map_err(|_| malformed())?;
        if n == 0 {
            break;
        }
        if n > max.saturating_sub(out.len()) {
            return Err(limit());
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

/// Inspect all members and CRCs, including ignored assets. The caller makes
/// emitted rows visible only after the complete archive has passed validation.
fn zip_preflight(reader: &mut (impl Read + Seek), budget: &ProcessingBudget) -> Result<usize> {
    let length = reader.seek(SeekFrom::End(0)).map_err(|_| malformed())?;
    if length > 32 * 1024 * 1024 {
        return Err(limit());
    }
    let tail_length = length.min(65_557) as usize;
    reader
        .seek(SeekFrom::End(-(tail_length as i64)))
        .map_err(|_| malformed())?;
    let mut tail = vec![0; tail_length];
    reader.read_exact(&mut tail).map_err(|_| malformed())?;
    let end = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&i| {
            tail[i..].starts_with(b"PK\x05\x06")
                && i + 22 + u16::from_le_bytes([tail[i + 20], tail[i + 21]]) as usize == tail.len()
        })
        .ok_or_else(malformed)?;
    let u16at = |i| u16::from_le_bytes([tail[end + i], tail[end + i + 1]]);
    let u32at = |i| {
        u32::from_le_bytes([
            tail[end + i],
            tail[end + i + 1],
            tail[end + i + 2],
            tail[end + i + 3],
        ])
    };
    if u16at(4) != 0 || u16at(6) != 0 || u16at(8) != u16at(10) {
        return Err(malformed());
    }
    let count = u16at(10) as usize;
    if count > MAX_MEMBERS {
        return Err(limit());
    }
    let offset = u32at(16) as u64;
    let directory_size = u32at(12) as u64;
    let end_position = length - tail_length as u64 + end as u64;
    if offset.checked_add(directory_size) != Some(end_position) {
        return Err(malformed());
    }
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|_| malformed())?;
    let mut seen = HashSet::new();
    for _ in 0..count {
        budget.check()?;
        let mut header = [0u8; 46];
        reader.read_exact(&mut header).map_err(|_| malformed())?;
        if &header[..4] != b"PK\x01\x02" {
            return Err(malformed());
        }
        let h16 = |i| u16::from_le_bytes([header[i], header[i + 1]]);
        let mode = u32::from_le_bytes([header[38], header[39], header[40], header[41]]) >> 16;
        if h16(8) & 0x41 != 0
            || !matches!(h16(10), 0 | 8 | 12)
            || !matches!(mode & 0o170000, 0 | 0o040000 | 0o100000)
        {
            return Err(Error::integrity("Unsafe documentation ZIP member."));
        }
        let n = h16(28) as usize;
        if n == 0 || n > 4097 {
            return Err(limit());
        }
        let mut name = vec![0u8; n];
        reader.read_exact(&mut name).map_err(|_| malformed())?;
        let name = std::str::from_utf8(&name).map_err(|_| malformed())?;
        let name = name.strip_suffix('/').unwrap_or(name);
        if !crate::archive::valid_relative_path(name) || !seen.insert(name.to_owned()) {
            return Err(Error::integrity(
                "Unsafe or duplicate documentation ZIP path.",
            ));
        }
        reader
            .seek(SeekFrom::Current(i64::from(h16(30)) + i64::from(h16(32))))
            .map_err(|_| malformed())?;
        if reader.stream_position().map_err(|_| malformed())? > end_position {
            return Err(malformed());
        }
    }
    if reader.stream_position().map_err(|_| malformed())? != end_position {
        return Err(malformed());
    }
    Ok(count)
}
pub fn inspect_html_zip<R: Read + Seek>(
    reader: R,
    budget: &ProcessingBudget,
    mut emit: impl FnMut(HtmlDocument) -> Result<()>,
) -> Result<ZipSummary> {
    budget.check()?;
    let mut reader = reader;
    let expected_members = zip_preflight(&mut reader, budget)?;
    reader.seek(SeekFrom::Start(0)).map_err(|_| malformed())?;
    let mut archive = zip::ZipArchive::new(reader).map_err(|_| malformed())?;
    if archive.len() != expected_members {
        return Err(malformed());
    }
    if archive.len() > MAX_MEMBERS {
        return Err(limit());
    }
    let mut seen = HashSet::new();
    let mut expanded = 0u64;
    let mut documents = 0;
    for i in 0..archive.len() {
        budget.check()?;
        let mut entry = archive.by_index(i).map_err(|_| malformed())?;
        let path = std::str::from_utf8(entry.name_raw())
            .map_err(|_| malformed())?
            .strip_suffix('/')
            .unwrap_or(std::str::from_utf8(entry.name_raw()).map_err(|_| malformed())?)
            .to_owned();
        if !crate::archive::valid_relative_path(&path)
            || !seen.insert(path.clone())
            || entry.encrypted()
            || entry.is_symlink()
        {
            return Err(Error::integrity("Unsafe documentation ZIP member."));
        }
        if let Some(mode) = entry.unix_mode()
            && !matches!(mode & 0o170000, 0 | 0o040000 | 0o100000)
        {
            return Err(Error::integrity("Special documentation ZIP member."));
        }
        if !matches!(
            entry.compression(),
            zip::CompressionMethod::Stored
                | zip::CompressionMethod::Deflated
                | zip::CompressionMethod::Bzip2
        ) {
            return Err(Error::new(
                "unsupported_format",
                "Unsupported documentation ZIP compression.",
            ));
        }
        if entry.size() > MAX_EXPANDED.saturating_sub(expanded) {
            return Err(limit());
        }
        if entry.is_dir() {
            if entry.size() != 0 {
                return Err(malformed());
            }
            continue;
        }
        if path.ends_with(".html") {
            let bytes = read_bounded(&mut entry, MAX_DOCUMENT, budget)?;
            expanded += bytes.len() as u64;
            let state = html(&bytes, budget, false)?;
            let target = path
                .split_once('/')
                .and_then(|(first, _)| valid_target(first).then(|| first.to_owned()));
            emit(HtmlDocument {
                target,
                path,
                text: state.text,
                headings: state.headings,
                links: state.links,
            })?;
            documents += 1;
        } else {
            let mut chunk = [0u8; 8192];
            loop {
                budget.check()?;
                let n = entry.read(&mut chunk).map_err(|_| malformed())?;
                if n == 0 {
                    break;
                }
                expanded = expanded.saturating_add(n as u64);
                if expanded > MAX_EXPANDED {
                    return Err(limit());
                }
            }
        }
        if expanded > MAX_EXPANDED {
            return Err(limit());
        }
    }
    Ok(ZipSummary {
        members: archive.len(),
        documents,
        expanded_bytes: expanded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    fn budget() -> ProcessingBudget {
        ProcessingBudget::new(CancellationToken::new())
    }
    fn fixture(format: u32) -> Vec<u8> {
        match format {
            43 => include_bytes!("../../tests/fixtures/docsrs/schema-43.json").to_vec(),
            55 => include_bytes!("../../tests/fixtures/docsrs/schema-55.json").to_vec(),
            56 => include_bytes!("../../tests/fixtures/docsrs/schema-56.json").to_vec(),
            _ => include_bytes!("../../tests/fixtures/docsrs/schema-61.json").to_vec(),
        }
    }
    fn project(bytes: Vec<u8>, target: Option<&str>) -> Result<(JsonSummary, Vec<ApiItem>)> {
        let mut out = Vec::new();
        let summary = parse_rustdoc_json(Cursor::new(bytes), "1.2.3", target, &budget(), |v| {
            out.push(v);
            Ok(())
        })?;
        Ok((summary, out))
    }
    #[test]
    fn historical_schemas_reexports_and_renamed_library() {
        for format in [43, 55, 56, 61] {
            let (summary, items) =
                project(fixture(format), Some("x86_64-unknown-linux-gnu")).unwrap();
            assert_eq!(summary.format_version, format);
            assert_eq!(summary.public_items, 3);
            assert_eq!(summary.target_asserted, format != 43);
            assert!(summary.version_asserted);
            assert_eq!(summary.unresolved_references, 0);
            assert!(
                items
                    .iter()
                    .all(|item| item.version_asserted && item.target_asserted == (format != 43))
            );
            let function = items.iter().find(|i| i.kind == "function").unwrap();
            assert_eq!(function.public_paths, ["renamed_library::alias"]);
            assert!(function.docs.as_deref().unwrap().contains("Compute"));
            assert_eq!(
                function.signature["inner"]["sig"]["inputs"][0][1]["primitive"],
                "u32"
            );
            assert!(
                !items
                    .iter()
                    .any(|i| i.public_paths.iter().any(|p| p.contains("hidden")))
            );
        }
    }
    #[test]
    fn rejects_identity_mismatch_unknown_schema_and_trailing_data() {
        assert_eq!(
            project(fixture(61), Some("aarch64-apple-darwin"))
                .unwrap_err()
                .code,
            "integrity"
        );
        let mut value: Value = serde_json::from_slice(&fixture(61)).unwrap();
        value["crate_version"] = json!("9.0.0");
        assert_eq!(
            project(serde_json::to_vec(&value).unwrap(), None)
                .unwrap_err()
                .code,
            "integrity"
        );
        value["crate_version"] = json!("1.2.3");
        value["format_version"] = json!(999);
        assert_eq!(
            project(serde_json::to_vec(&value).unwrap(), None)
                .unwrap_err()
                .code,
            "unsupported_format"
        );
        let mut bytes = fixture(43);
        bytes.extend_from_slice(b" {}");
        assert_eq!(project(bytes, None).unwrap_err().code, "integrity");
    }
    #[test]
    fn bounded_items_depth_duplicates_and_cancellation() {
        let mut value: Value = serde_json::from_slice(&fixture(61)).unwrap();
        value["index"]["3"]["docs"] = json!("x".repeat(MAX_ITEM));
        assert_eq!(
            project(serde_json::to_vec(&value).unwrap(), None)
                .unwrap_err()
                .code,
            "capacity"
        );
        let nested = format!("{{\"root\":{}0{}}}", "[".repeat(65), "]".repeat(65));
        assert_eq!(
            project(nested.into_bytes(), None).unwrap_err().code,
            "capacity"
        );
        let duplicated = String::from_utf8(fixture(43)).unwrap().replacen(
            "\"root\": 0,",
            "\"root\": 0, \"root\": 0,",
            1,
        );
        assert_eq!(
            project(duplicated.into_bytes(), None).unwrap_err().code,
            "integrity"
        );
        let b = budget();
        b.cancel.cancel();
        assert_eq!(
            parse_rustdoc_json(Cursor::new(fixture(43)), "1.2.3", None, &b, |_| Ok(()))
                .unwrap_err()
                .code,
            "cancelled"
        );
        let b = ProcessingBudget {
            deadline: Instant::now(),
            cancel: CancellationToken::new(),
        };
        assert_eq!(
            parse_rustdoc_json(Cursor::new(fixture(43)), "1.2.3", None, &b, |_| Ok(()))
                .unwrap_err()
                .code,
            "capacity"
        );
    }
    #[test]
    fn streams_callbacks_and_propagates_failure() {
        let mut calls = 0;
        let error = parse_rustdoc_json(Cursor::new(fixture(55)), "1.2.3", None, &budget(), |_| {
            calls += 1;
            Err(Error::capacity("sink full"))
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(error.message, "sink full");
    }
    #[test]
    fn platforms_and_html_remain_inert() {
        let bytes=b"<li><a href='/pkg/1.2.3/library/'>x86_64-unknown-linux-gnu</a></li><li><a href='/pkg/1.2.3/aarch64-apple-darwin/library/'>aarch64-apple-darwin</a></li><script>evil</script>";
        let targets = parse_platforms(&bytes[..], &budget()).unwrap();
        assert_eq!(targets.len(), 2);
        assert!(
            targets
                .iter()
                .find(|t| t.triple.starts_with("x86"))
                .unwrap()
                .is_default
        );
        assert!(
            !targets
                .iter()
                .find(|t| t.triple.starts_with("aarch64"))
                .unwrap()
                .is_default
        );
        let state=html(b"<!doctype html><head><title>hidden</title></head><body><h1>API &amp; types</h1><script>fetch('secret')</script><style>evil</style><p>Hello <a href='https://example.invalid/doc'>world</a><a href='javascript:evil()'>bad</a></p></body>",&budget(),false).unwrap();
        assert!(state.text.contains("API & types"));
        assert!(state.text.contains("Hello"));
        assert!(!state.text.contains("secret"));
        assert!(!state.text.contains("hidden"));
        assert_eq!(state.headings, ["API & types"]);
        assert_eq!(state.links, ["https://example.invalid/doc"]);
        assert!(html(&[0], &budget(), false).is_err());
        let unfinished = format!("<a value='{}", "x".repeat(30_000));
        assert_eq!(
            html(unfinished.as_bytes(), &budget(), false)
                .err()
                .unwrap()
                .code,
            "capacity"
        );
    }
    fn zip(method: zip::CompressionMethod, entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in entries {
            writer
                .start_file(
                    *name,
                    zip::write::SimpleFileOptions::default().compression_method(method),
                )
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }
    #[test]
    fn zip_deflate_bzip2_and_targets_without_extraction() {
        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
            zip::CompressionMethod::Bzip2,
        ] {
            let bytes = zip(
                method,
                &[
                    ("library/index.html", b"<h1>Default</h1>"),
                    ("aarch64-apple-darwin/library/index.html", b"<h1>Other</h1>"),
                    ("script.js", b"never execute"),
                ],
            );
            let mut docs = Vec::new();
            let summary = inspect_html_zip(Cursor::new(bytes), &budget(), |v| {
                docs.push(v);
                Ok(())
            })
            .unwrap();
            assert_eq!(summary.members, 3);
            assert_eq!(summary.documents, 2);
            assert!(docs[0].target.is_none());
            assert_eq!(docs[1].target.as_deref(), Some("aarch64-apple-darwin"));
        }
    }
    #[test]
    fn zip_rejects_paths_crc_and_member_boundaries() {
        let bytes = zip(zip::CompressionMethod::Stored, &[("../bad.html", b"bad")]);
        assert!(inspect_html_zip(Cursor::new(bytes), &budget(), |_| Ok(())).is_err());
        let mut bytes = zip(
            zip::CompressionMethod::Stored,
            &[("library/index.html", b"<p>unique content</p>")],
        );
        let position = bytes
            .windows(14)
            .position(|v| v == b"unique content")
            .unwrap();
        bytes[position] = b'X';
        assert!(inspect_html_zip(Cursor::new(bytes), &budget(), |_| Ok(())).is_err());
        let mut bytes = zip(
            zip::CompressionMethod::Stored,
            &[("library/index.html", b"text")],
        );
        let end = bytes.len() - 22;
        bytes[end + 10..end + 12].copy_from_slice(&20_001u16.to_le_bytes());
        bytes[end + 8..end + 10].copy_from_slice(&20_001u16.to_le_bytes());
        assert_eq!(
            inspect_html_zip(Cursor::new(bytes), &budget(), |_| Ok(()))
                .unwrap_err()
                .code,
            "capacity"
        );
        let bytes = zip(
            zip::CompressionMethod::Deflated,
            &[("library/index.html", &vec![b'x'; MAX_DOCUMENT + 1])],
        );
        assert_eq!(
            inspect_html_zip(Cursor::new(bytes), &budget(), |_| Ok(()))
                .unwrap_err()
                .code,
            "capacity"
        );
    }
    #[test]
    fn many_short_child_ids_charge_slots_and_heap_before_materialization() {
        let mut value: Value = serde_json::from_slice(&fixture(61)).unwrap();
        value["index"]["0"]["inner"]["module"]["items"] = json!(vec![1; 10_000]);
        let row = &value["index"]["0"];
        let near_limit = Cell::new(MAX_GRAPH - 256 * 1024);
        let before = near_limit.get();
        assert_eq!(node("0", row, &near_limit).err().unwrap().code, "capacity");
        assert_eq!(near_limit.get(), before);
        let roomy = Cell::new(0);
        let n = node("0", row, &roomy).unwrap();
        assert_eq!(n.children.len(), 10_000);
        let actual_slots = n.children.capacity() * std::mem::size_of::<String>();
        let actual_strings = n.children.iter().map(String::capacity).sum::<usize>();
        assert!(roomy.get() >= actual_slots + actual_strings);
        assert!(roomy.get() > 500_000);
    }

    #[test]
    fn unresolved_signature_ids_are_explicit_in_summary_coverage() {
        let mut value: Value = serde_json::from_slice(&fixture(61)).unwrap();
        value["index"]["3"]["inner"]["function"]["sig"]["output"] =
            json!({"resolved_path":{"path":"HiddenType","id":999,"args":null}});
        let (summary, items) = project(serde_json::to_vec(&value).unwrap(), None).unwrap();
        assert!(summary.unresolved_references > 0);
        let function = items.iter().find(|i| i.kind == "function").unwrap();
        assert_eq!(
            function.signature["inner"]["sig"]["output"]["resolved_path"]["id"]["unresolved_reference"],
            true
        );
    }

    #[test]
    fn dotted_official_target_survives_platform_json_and_zip_projection() {
        let target = "thumbv8m.main-none-eabi";
        let fragment = b"<li><a href='/pkg/1.2.3/library/'>thumbv8m.main-none-eabi</a></li>";
        let targets = parse_platforms(fragment.as_slice(), &budget()).unwrap();
        assert_eq!(
            targets,
            [DocTarget {
                triple: target.into(),
                is_default: true
            }]
        );
        let mut value: Value = serde_json::from_slice(&fixture(61)).unwrap();
        value["target"]["triple"] = json!(target);
        assert!(
            project(serde_json::to_vec(&value).unwrap(), Some(target))
                .unwrap()
                .0
                .target_asserted
        );
        let path = format!("{target}/library/index.html");
        let bytes = zip(
            zip::CompressionMethod::Deflated,
            &[(&path, b"<h1>Embedded</h1>")],
        );
        let mut docs = Vec::new();
        inspect_html_zip(Cursor::new(bytes), &budget(), |v| {
            docs.push(v);
            Ok(())
        })
        .unwrap();
        assert_eq!(docs[0].target.as_deref(), Some(target));
        for bad in [
            "../target",
            "target%2Fescape",
            "target/escape",
            "bad..target",
        ] {
            assert!(!valid_target(bad));
        }
    }

    #[test]
    #[ignore = "operator-supplied public docs.rs gzip; DEVRES_DOCSRS_REPLAY_GZIP, no network"]
    fn captured_format56_replays_without_network() {
        let path =
            std::env::var_os("DEVRES_DOCSRS_REPLAY_GZIP").expect("set public capture gzip path");
        let metadata = std::fs::metadata(&path).unwrap();
        assert!(metadata.len() <= 32 * 1024 * 1024);
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(
            crate::archive::sha256(&raw),
            "f41a8139c7bcf95ddec39950b7bf43c249492793130b35d69b3d19312064a199"
        );
        let mut decoder =
            flate2::read::MultiGzDecoder::new(Cursor::new(raw)).take(MAX_EXPANDED + 1);
        let mut stage = tempfile::tempfile().unwrap();
        let expanded = std::io::copy(&mut decoder, &mut stage).unwrap();
        assert!(expanded <= MAX_EXPANDED);
        stage.seek(SeekFrom::Start(0)).unwrap();
        let mut items = 0;
        let summary = parse_rustdoc_json(
            stage,
            "1.0.15",
            Some("x86_64-unknown-linux-gnu"),
            &budget(),
            |_| {
                items += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(summary.format_version, 56);
        assert!(summary.version_asserted && summary.target_asserted);
        assert!(items > 0);
        assert_eq!(summary.public_items, items);
        println!(
            "offline itoa format56 replay: items={}, expanded={}, unresolved={}",
            items, expanded, summary.unresolved_references
        );
    }

    #[test]
    fn signature_references_are_stable_and_expansion_is_bounded() {
        let paths = BTreeMap::from([("4".into(), "renamed_library::PublicType".into())]);
        let mut relations = BTreeSet::new();
        let mut remaining = MAX_ITEM;
        let signature = normalize(
            &json!({"resolved_path":{"id":4}}),
            &paths,
            &mut relations,
            false,
            &mut remaining,
        )
        .unwrap();
        assert_eq!(
            signature["resolved_path"]["id"]["path"],
            "renamed_library::PublicType"
        );
        assert_eq!(relations.into_iter().collect::<Vec<_>>(), ["4"]);
        let paths = BTreeMap::from([("4".into(), "x".repeat(4096))]);
        let mut relations = BTreeSet::new();
        let mut remaining = MAX_ITEM;
        let input = json!({"items":vec![4;1000]});
        assert_eq!(
            normalize(&input, &paths, &mut relations, false, &mut remaining)
                .unwrap_err()
                .code,
            "capacity"
        );
    }

    #[test]
    fn zip_rejects_duplicate_central_paths_and_symlink_modes() {
        let mut bytes = zip(
            zip::CompressionMethod::Stored,
            &[("a.html", b"a"), ("b.html", b"b")],
        );
        let starts = bytes
            .windows(4)
            .enumerate()
            .filter_map(|(i, b)| (b == b"PK\x01\x02").then_some(i))
            .collect::<Vec<_>>();
        let second = starts[1];
        bytes[second + 46] = b'a';
        assert!(inspect_html_zip(Cursor::new(bytes), &budget(), |_| Ok(())).is_err());
        let mut bytes = zip(zip::CompressionMethod::Stored, &[("a.html", b"a")]);
        let central = bytes.windows(4).position(|b| b == b"PK\x01\x02").unwrap();
        bytes[central + 38..central + 42].copy_from_slice(&(0o120777u32 << 16).to_le_bytes());
        assert!(inspect_html_zip(Cursor::new(bytes), &budget(), |_| Ok(())).is_err());
    }
}
