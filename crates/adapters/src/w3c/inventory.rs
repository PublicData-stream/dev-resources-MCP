//! Persistent path inventories with bounded hash-radix directory partitions.
use devres_application::w3c::{
    InventoryNode, Member, W3C_WRITE_BATCH_BYTES, W3C_WRITE_BATCH_ROWS, W3cStore, Write,
};
use devres_domain::{Error, Result};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
pub fn digest(bytes: &[u8]) -> String {
    crate::integrity::hash(bytes)
}
/// Radix digits are always the hexadecimal digest, without the algorithm tag.
fn routing_hash(bytes: &[u8], legacy: bool) -> String {
    if legacy {
        crate::integrity::legacy_hash(bytes)
    } else {
        digest(bytes).trim_start_matches("blake3:").to_owned()
    }
}
pub fn value<T: serde::Serialize>(item: &T) -> Result<serde_json::Value> {
    serde_json::to_value(item).map_err(|_| Error::integrity("Invalid W3C evidence encoding."))
}
pub fn decode<T: serde::de::DeserializeOwned>(item: serde_json::Value) -> Result<T> {
    serde_json::from_value(item).map_err(|_| Error::integrity("Invalid retained W3C evidence."))
}
pub fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != ".." && !s.contains('\\'))
        && path.split('/').count() <= 64
}
/// Worker-local immutable evidence only. Never cache ownership or publication state.
/// FIFO admission bounds both serialized evidence and retained node identities.
pub(crate) struct NodeCache {
    enabled: bool,
    admit_writes: bool,
    nodes: BTreeMap<String, (InventoryNode, usize)>,
    order: VecDeque<String>,
    bytes: usize,
}
impl NodeCache {
    pub(crate) fn new() -> Self {
        Self {
            enabled: true,
            admit_writes: true,
            nodes: BTreeMap::new(),
            order: VecDeque::new(),
            bytes: 0,
        }
    }
    fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::new()
        }
    }
    fn get(&self, id: &str) -> Option<InventoryNode> {
        self.nodes.get(id).map(|(node, _)| node.clone())
    }
    fn insert(&mut self, id: String, node: InventoryNode, serialized_bytes: usize) {
        const MAX_NODES: usize = 4096;
        const MAX_BYTES: usize = 8 * 1024 * 1024;
        let bytes = serialized_bytes.saturating_add(id.len());
        if !self.enabled || bytes > MAX_BYTES || self.nodes.contains_key(&id) {
            return;
        }
        while self.nodes.len() >= MAX_NODES || self.bytes.saturating_add(bytes) > MAX_BYTES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some((_, old_bytes)) = self.nodes.remove(&oldest) {
                self.bytes -= old_bytes;
            }
        }
        self.bytes += bytes;
        self.order.push_back(id.clone());
        self.nodes.insert(id, (node, bytes));
    }
}
pub async fn node(store: &dyn W3cStore, id: &str) -> Result<InventoryNode> {
    node_cached(store, id, &mut NodeCache::disabled()).await
}
pub(crate) async fn node_cached(
    store: &dyn W3cStore,
    id: &str,
    cache: &mut NodeCache,
) -> Result<InventoryNode> {
    if let Some(node) = cache.get(id) {
        return Ok(node);
    }
    let row = store
        .w3c_get("nodes", id)
        .await?
        .ok_or_else(|| Error::integrity("W3C inventory node missing."))?;
    let durable = row.sequence > 0;
    let node: InventoryNode = decode(row.data)?;
    let bytes =
        serde_json::to_vec(&node).map_err(|_| Error::integrity("Invalid W3C inventory."))?;
    if crate::integrity::verify(id, &bytes).is_err() {
        return Err(Error::integrity("W3C inventory hash mismatch."));
    }
    if cache.enabled && durable {
        cache.insert(id.to_owned(), node.clone(), bytes.len());
    }
    Ok(node)
}
fn encoded_node(node: &InventoryNode) -> Result<(String, ValueAndBytes)> {
    if node.children.len() > 64
        || node.buckets.len() > 16
        || (!node.children.is_empty() && !node.buckets.is_empty())
    {
        return Err(Error::capacity("W3C directory partition bound exceeded."));
    }
    let bytes = serde_json::to_vec(node).map_err(|_| Error::integrity("Invalid W3C inventory."))?;
    let id = digest(&bytes);
    Ok((
        id,
        ValueAndBytes {
            data: value(node)?,
            bytes: bytes.len(),
        },
    ))
}
struct ValueAndBytes {
    data: serde_json::Value,
    bytes: usize,
}
pub async fn put_node(store: &dyn W3cStore, node: &InventoryNode) -> Result<String> {
    let (id, encoded) = encoded_node(node)?;
    store.w3c_put("nodes", &id, &encoded.data).await?;
    Ok(id)
}
/// Nodes remain local until the complete new root can be committed as one group.
/// Partitioning may read a newly staged child before it exists in PostgreSQL.
struct Staged<'a> {
    store: &'a dyn W3cStore,
    cache: &'a mut NodeCache,
    nodes: BTreeMap<String, (InventoryNode, usize)>,
    rows: Vec<Write>,
    bytes: usize,
}
impl<'a> Staged<'a> {
    fn new(store: &'a dyn W3cStore, cache: &'a mut NodeCache) -> Self {
        Self {
            store,
            cache,
            nodes: BTreeMap::new(),
            rows: Vec::new(),
            bytes: 0,
        }
    }
    async fn node(&mut self, id: &str) -> Result<InventoryNode> {
        match self.nodes.get(id) {
            Some((node, _)) => Ok(node.clone()),
            None => node_cached(self.store, id, self.cache).await,
        }
    }
    fn put(&mut self, node: &InventoryNode) -> Result<String> {
        let (id, encoded) = encoded_node(node)?;
        if let Some((retained, _)) = self.nodes.get(&id) {
            if retained != node {
                return Err(Error::integrity("W3C staged node identity collision."));
            }
            return Ok(id);
        }
        // The envelope is at most 128 bytes for kind=nodes and a tagged BLAKE3 key.
        self.bytes = self
            .bytes
            .checked_add(encoded.bytes + 128)
            .filter(|bytes| *bytes <= W3C_WRITE_BATCH_BYTES)
            .ok_or_else(|| Error::capacity("W3C inventory update write budget exceeded."))?;
        if self.rows.len() >= W3C_WRITE_BATCH_ROWS {
            return Err(Error::capacity(
                "W3C inventory update node budget exceeded.",
            ));
        }
        self.rows.push(Write {
            kind: "nodes".into(),
            key: id.clone(),
            data: encoded.data,
        });
        self.nodes.insert(id.clone(), (node.clone(), encoded.bytes));
        Ok(id)
    }
    async fn commit(self) -> Result<()> {
        let Self {
            store,
            cache,
            rows,
            nodes,
            ..
        } = self;
        if !cache.enabled || !cache.admit_writes {
            drop(nodes);
            return store.w3c_put_many(&rows).await;
        }
        store.w3c_put_many(&rows).await?;
        // A failed write must never expose staged evidence through the cache.
        for (id, (node, bytes)) in nodes {
            cache.insert(id, node, bytes);
        }
        Ok(())
    }
}

pub async fn empty(store: &dyn W3cStore) -> Result<String> {
    put_node(store, &InventoryNode::default()).await
}
async fn child(
    store: &dyn W3cStore,
    mut n: InventoryNode,
    part: &str,
    cache: &mut NodeCache,
    legacy: bool,
) -> Result<Option<InventoryNode>> {
    let hash = routing_hash(part.as_bytes(), legacy);
    let mut depth = 0;
    while !n.buckets.is_empty() {
        let nibble = hash
            .get(depth..depth + 1)
            .ok_or_else(|| Error::integrity("Invalid W3C directory radix."))?;
        depth += 1;
        let Some(id) = n.buckets.get(nibble) else {
            return Ok(None);
        };
        n = node_cached(store, id, cache).await?;
    }
    match n.children.get(part) {
        Some(id) => Ok(Some(node_cached(store, id, cache).await?)),
        None => Ok(None),
    }
}
pub async fn get(store: &dyn W3cStore, root: &str, path: &str) -> Result<Option<Member>> {
    get_cached(store, root, path, &mut NodeCache::disabled()).await
}
pub(crate) async fn get_cached(
    store: &dyn W3cStore,
    root: &str,
    path: &str,
    cache: &mut NodeCache,
) -> Result<Option<Member>> {
    if !valid_path(path) {
        return Err(Error::invalid("Invalid W3C member path."));
    }
    let mut n = node_cached(store, root, cache).await?;
    for part in path.split('/') {
        let Some(next) = child(store, n, part, cache, !root.starts_with("blake3:")).await? else {
            return Ok(None);
        };
        n = next;
    }
    Ok(n.member)
}
/// Resolve a directory through the same hash-radix routing as member lookups.
pub async fn subtree(store: &dyn W3cStore, root: &str, path: &str) -> Result<Option<String>> {
    if !valid_path(path) {
        return Err(Error::invalid("Invalid W3C directory path."));
    }
    let mut id = root.to_owned();
    for part in path.split('/') {
        let mut n = node(store, &id).await?;
        let hash = routing_hash(part.as_bytes(), !root.starts_with("blake3:"));
        let mut depth = 0;
        while !n.buckets.is_empty() {
            let key = hash
                .get(depth..depth + 1)
                .ok_or_else(|| Error::integrity("Invalid W3C directory radix."))?;
            depth += 1;
            let Some(next) = n.buckets.get(key) else {
                return Ok(None);
            };
            n = node(store, next).await?;
        }
        let Some(next) = n.children.get(part) else {
            return Ok(None);
        };
        id = next.clone();
    }
    Ok(Some(id))
}
#[derive(Clone)]
enum Edge {
    Child(String),
    Bucket(String),
}
fn counts(m: Option<&Member>) -> (u64, u64, u64, BTreeMap<String, u64>) {
    (
        u64::from(m.is_some()),
        u64::from(m.is_some_and(|m| {
            m.projection.is_some()
                && m.raw
                    .as_ref()
                    .and_then(|raw| raw["searchable"].as_bool())
                    .unwrap_or(true)
                && !m.gaps.iter().any(|g| g == "search_index_gap")
        })),
        u64::from(m.is_some_and(|m| !m.gaps.is_empty())),
        m.map(|m| BTreeMap::from([(m.kind.clone(), 1)]))
            .unwrap_or_default(),
    )
}
fn adjust(
    n: &mut InventoryNode,
    old: (u64, u64, u64, BTreeMap<String, u64>),
    new: (u64, u64, u64, BTreeMap<String, u64>),
) {
    n.members = n.members - old.0 + new.0;
    n.searchable = n.searchable - old.1 + new.1;
    n.gaps = n.gaps - old.2 + new.2;
    for (kind, count) in old.3 {
        let total = n.kinds.entry(kind).or_default();
        *total -= count;
    }
    for (kind, count) in new.3 {
        *n.kinds.entry(kind).or_default() += count;
    }
    n.kinds.retain(|_, count| *count > 0);
}
// Called only when a leaf directory first crosses 64 names. The partitioning tree
// remains small and each later update rewrites only one radix branch.
async fn partition(staged: &mut Staged<'_>, n: &mut InventoryNode, depth: usize) -> Result<()> {
    if n.children.len() <= 64 {
        return Ok(());
    }
    if depth >= 64 {
        return Err(Error::capacity(
            "W3C directory hash collision bound exceeded.",
        ));
    }
    let mut groups: BTreeMap<String, InventoryNode> = BTreeMap::new();
    for (name, id) in std::mem::take(&mut n.children) {
        let hash = routing_hash(name.as_bytes(), false);
        let key = hash[depth..depth + 1].to_owned();
        let c = staged.node(&id).await?;
        let group = groups.entry(key).or_default();
        group.members += c.members;
        group.searchable += c.searchable;
        group.gaps += c.gaps;
        for (kind, count) in c.kinds {
            *group.kinds.entry(kind).or_default() += count;
        }
        group.children.insert(name, id);
    }
    for (key, mut group) in groups {
        Box::pin(partition(staged, &mut group, depth + 1)).await?;
        n.buckets.insert(key, staged.put(&group)?);
    }
    Ok(())
}
pub async fn update(
    store: &dyn W3cStore,
    root: &str,
    path: &str,
    member: Option<Member>,
) -> Result<String> {
    update_cached(store, root, path, member, &mut NodeCache::disabled()).await
}
pub(crate) async fn update_cached(
    store: &dyn W3cStore,
    root: &str,
    path: &str,
    member: Option<Member>,
    cache: &mut NodeCache,
) -> Result<String> {
    if !root.starts_with("blake3:") {
        return Err(Error::integrity(
            "Legacy inventory must be migrated before updating.",
        ));
    }
    if !valid_path(path) {
        return Err(Error::invalid("Invalid W3C member path."));
    }
    let mut stack = Vec::new();
    let mut current = node_cached(store, root, cache).await?;
    for part in path.split('/') {
        let hash = routing_hash(part.as_bytes(), false);
        let mut depth = 0;
        while !current.buckets.is_empty() {
            let key = hash
                .get(depth..depth + 1)
                .ok_or_else(|| Error::integrity("Invalid W3C directory radix."))?
                .to_owned();
            depth += 1;
            let next = match current.buckets.get(&key) {
                Some(id) => node_cached(store, id, cache).await?,
                None => InventoryNode::default(),
            };
            stack.push((current, Edge::Bucket(key), depth - 1));
            current = next;
        }
        let next = match current.children.get(part) {
            Some(id) => node_cached(store, id, cache).await?,
            None => InventoryNode::default(),
        };
        stack.push((current, Edge::Child(part.into()), depth));
        current = next;
    }
    if current.member == member {
        return Ok(root.to_owned());
    }
    let mut staged = Staged::new(store, cache);
    let mut previous = current.clone();
    let before = counts(current.member.as_ref());
    let after = counts(member.as_ref());
    current.member = member;
    adjust(&mut current, before, after);
    let mut id = staged.put(&current)?;
    for (mut parent, edge, depth) in stack.into_iter().rev() {
        let old = parent.clone();
        let empty = current.members == 0;
        match edge {
            Edge::Child(key) => {
                if empty {
                    parent.children.remove(&key);
                } else {
                    parent.children.insert(key, id);
                }
            }
            Edge::Bucket(key) => {
                if empty {
                    parent.buckets.remove(&key);
                } else {
                    parent.buckets.insert(key, id);
                }
            }
        }
        adjust(
            &mut parent,
            (
                previous.members,
                previous.searchable,
                previous.gaps,
                previous.kinds.clone(),
            ),
            (
                current.members,
                current.searchable,
                current.gaps,
                current.kinds.clone(),
            ),
        );
        partition(&mut staged, &mut parent, depth).await?;
        id = staged.put(&parent)?;
        current = parent;
        previous = old;
    }
    staged.commit().await?;
    Ok(id)
}
pub async fn members(store: &dyn W3cStore, root: &str, max: usize) -> Result<Vec<Member>> {
    let mut stack = vec![root.to_string()];
    let mut out = Vec::new();
    let mut budget = 0usize;
    let mut visited = 0usize;
    while !stack.is_empty() {
        let start = stack.len().saturating_sub(1000);
        let ids = stack.split_off(start);
        let rows = store.w3c_get_many("nodes", &ids).await?;
        if rows.len() != ids.len() {
            return Err(Error::integrity("W3C inventory node missing."));
        }
        for row in rows {
            visited += 1;
            if visited > 4_000_000 {
                return Err(Error::capacity("W3C inventory traversal bound exceeded."));
            }
            let n: InventoryNode = decode(row.data)?;
            if crate::integrity::verify(
                &row.key,
                &serde_json::to_vec(&n).map_err(|_| Error::integrity("Invalid W3C node."))?,
            )
            .is_err()
            {
                return Err(Error::integrity("W3C inventory hash mismatch."));
            }
            if let Some(m) = n.member {
                budget = budget.saturating_add(
                    serde_json::to_vec(&m)
                        .map_err(|_| Error::integrity("Invalid W3C member."))?
                        .len(),
                );
                out.push(m);
                if out.len() > max || budget > 64 * 1024 * 1024 {
                    return Err(Error::capacity("W3C snapshot membership bound exceeded."));
                }
            }
            stack.extend(n.children.into_values());
            stack.extend(n.buckets.into_values());
        }
    }
    Ok(out)
}

/// Bounded content-addressed projection batches skip already retained objects by key.
pub(crate) struct ProjectionBatch<'a> {
    store: &'a dyn W3cStore,
    rows: BTreeMap<(String, String), serde_json::Value>,
    bytes: usize,
    // Durable identity only, scoped to this projection. Never cache ownership.
    known: BTreeSet<(String, String)>,
    known_bytes: usize,
}
impl<'a> ProjectionBatch<'a> {
    const MAX_KNOWN_KEYS: usize = 131_072;
    // Kind/id string payload; allocator and tree overhead are additional.
    const MAX_KNOWN_BYTES: usize = 8 * 1024 * 1024;
    pub(crate) fn new(store: &'a dyn W3cStore) -> Self {
        Self {
            store,
            rows: BTreeMap::new(),
            bytes: 0,
            known: BTreeSet::new(),
            known_bytes: 0,
        }
    }
    pub(crate) async fn put(&mut self, kind: &str, data: serde_json::Value) -> Result<String> {
        let id = digest(
            &serde_json::to_vec(&data)
                .map_err(|_| Error::integrity("Invalid W3C shared projection."))?,
        );
        self.put_id(kind, &id, data).await?;
        Ok(id)
    }
    pub(crate) async fn put_id(
        &mut self,
        kind: &str,
        id: &str,
        data: serde_json::Value,
    ) -> Result<()> {
        let size = serde_json::to_vec(&data)
            .map_err(|_| Error::integrity("Invalid W3C shared projection."))?
            .len()
            + 256;
        if size > 8 * 1024 * 1024 {
            return Err(Error::capacity(
                "W3C shared projection object exceeds its bound.",
            ));
        }
        let key = (kind.to_owned(), id.to_owned());
        if self.known.contains(&key) {
            return Ok(());
        }
        if self.bytes + size > 8 * 1024 * 1024 || self.rows.len() >= 1000 {
            self.flush().await?;
        }
        if self.rows.insert(key, data).is_none() {
            self.bytes += size;
        }
        Ok(())
    }
    pub(crate) async fn flush(&mut self) -> Result<()> {
        let rows = std::mem::take(&mut self.rows);
        self.bytes = 0;
        let mut groups: BTreeMap<String, Vec<(String, serde_json::Value)>> = BTreeMap::new();
        for ((kind, key), data) in rows {
            groups.entry(kind).or_default().push((key, data));
        }
        for (kind, group) in groups {
            let keys: Vec<String> = group.iter().map(|(key, _)| key.clone()).collect();
            let retained = self.store.w3c_existing(&kind, &keys).await?;
            let rows: Vec<Write> = group
                .into_iter()
                .filter(|(key, _)| !retained.contains(key))
                .map(|(key, data)| Write {
                    kind: kind.clone(),
                    key,
                    data,
                })
                .collect();
            self.store.w3c_put_many(&rows).await?;
            for key in keys {
                let size = kind.len().saturating_add(key.len());
                if self.known.len() < Self::MAX_KNOWN_KEYS
                    && self.known_bytes.saturating_add(size) <= Self::MAX_KNOWN_BYTES
                    && self.known.insert((kind.clone(), key))
                {
                    self.known_bytes += size;
                }
            }
        }
        Ok(())
    }
    /// Content-defined groups retain structural sharing after insertions/deletions.
    pub(crate) async fn sequence(&mut self, values: &[String]) -> Result<String> {
        if values.len() > 1_000_000 {
            return Err(Error::capacity(
                "W3C projection sequence exceeds its bound.",
            ));
        }
        if values.is_empty() {
            return self
                .put("projection-sequences", serde_json::json!({"values":[]}))
                .await;
        }
        let mut current = values.to_vec();
        let mut leaf = true;
        loop {
            let mut next = Vec::new();
            let mut start = 0;
            for i in 0..current.len() {
                let count = i + 1 - start;
                let boundary = current[i]
                    .get(..2)
                    .and_then(|v| u8::from_str_radix(v, 16).ok())
                    .is_some_and(|v| v < 8);
                if count >= 128 || (count >= 16 && boundary) || i + 1 == current.len() {
                    let data = if leaf {
                        serde_json::json!({"values":&current[start..=i]})
                    } else {
                        serde_json::json!({"children":&current[start..=i]})
                    };
                    next.push(self.put("projection-sequences", data).await?);
                    start = i + 1;
                }
            }
            if next.len() == 1 {
                return next
                    .pop()
                    .ok_or_else(|| Error::integrity("W3C sequence root missing."));
            }
            current = next;
            leaf = false;
        }
    }
    pub(crate) async fn text(&mut self, text: &str) -> Result<String> {
        let mut ids = Vec::new();
        for line in text.split_inclusive('\n') {
            let mut start = 0;
            while start < line.len() {
                let mut end = (start + 32768).min(line.len());
                while !line.is_char_boundary(end) {
                    end -= 1;
                }
                ids.push(
                    self.put("projection-chunks", serde_json::json!(&line[start..end]))
                        .await?,
                );
                start = end;
                if ids.len() > 1_000_000 {
                    return Err(Error::capacity("W3C text chunk count exceeds its bound."));
                }
            }
        }
        self.sequence(&ids).await
    }
}

/// Load a shared sequence DAG in bounded batches, preserving every root's order.
pub(crate) async fn sequences(
    store: &dyn W3cStore,
    roots: &[String],
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut pending: std::collections::BTreeSet<String> = roots.iter().cloned().collect();
    let mut nodes = BTreeMap::<String, serde_json::Value>::new();
    let mut bytes = 0;
    while !pending.is_empty() {
        let batch: Vec<String> = pending.iter().take(1000).cloned().collect();
        for id in &batch {
            pending.remove(id);
        }
        let rows = store.w3c_get_many("projection-sequences", &batch).await?;
        if rows.len() != batch.len() {
            return Err(Error::integrity("W3C projection sequence is missing."));
        }
        for row in rows {
            let encoded = serde_json::to_vec(&row.data)
                .map_err(|_| Error::integrity("Invalid W3C projection sequence."))?;
            bytes += encoded.len();
            if bytes > 128 * 1024 * 1024 || nodes.len() > 1_000_000 {
                return Err(Error::capacity(
                    "W3C projection sequence traversal exceeds its bound.",
                ));
            }
            if crate::integrity::verify(&row.key, &encoded).is_err() {
                return Err(Error::integrity("W3C projection sequence hash mismatch."));
            }
            if let Some(children) = row
                .data
                .get("children")
                .and_then(serde_json::Value::as_array)
            {
                if children.len() > 128 {
                    return Err(Error::integrity("Invalid W3C projection sequence width."));
                }
                for child in children {
                    let id = child.as_str().ok_or_else(|| {
                        Error::integrity("Invalid W3C projection sequence child.")
                    })?;
                    if !nodes.contains_key(id) {
                        pending.insert(id.into());
                    }
                }
            }
            nodes.insert(row.key, row.data);
        }
    }
    let mut result = BTreeMap::new();
    for root in roots {
        let mut values = Vec::new();
        let mut stack = vec![(root.clone(), 0_usize)];
        while let Some((id, depth)) = stack.pop() {
            if depth > 32 {
                return Err(Error::capacity(
                    "W3C projection sequence depth exceeds its bound.",
                ));
            }
            let node = nodes
                .get(&id)
                .ok_or_else(|| Error::integrity("W3C projection sequence missing."))?;
            if let Some(children) = node.get("children").and_then(serde_json::Value::as_array) {
                for child in children.iter().rev() {
                    stack.push((
                        child
                            .as_str()
                            .ok_or_else(|| Error::integrity("Invalid W3C sequence child."))?
                            .into(),
                        depth + 1,
                    ));
                }
            } else if let Some(items) = node.get("values").and_then(serde_json::Value::as_array) {
                for item in items {
                    values.push(
                        item.as_str()
                            .ok_or_else(|| Error::integrity("Invalid W3C sequence value."))?
                            .into(),
                    );
                }
            } else {
                return Err(Error::integrity("Invalid W3C projection sequence node."));
            }
            if values.len() > 1_000_000 {
                return Err(Error::capacity(
                    "W3C projection sequence membership exceeds its bound.",
                ));
            }
        }
        result.insert(root.clone(), values);
    }
    Ok(result)
}

/// Rebuild a frozen logical inventory with canonical BLAKE3 routing.
/// The caller rewrites typed references in each member; source data stays unchanged.
pub async fn rebuild_inventory(
    store: &dyn W3cStore,
    root: &str,
    mut rewrite: impl FnMut(Member) -> Result<Member>,
) -> Result<String> {
    let mut retained = members(store, root, 1_000_000).await?;
    retained.sort_by(|left, right| left.path.cmp(&right.path));
    let mut canonical = empty(store).await?;
    let mut cache = NodeCache::new();
    for member in retained {
        let member = rewrite(member)?;
        let path = member.path.clone();
        canonical = update_cached(store, &canonical, &path, Some(member), &mut cache).await?;
    }
    Ok(canonical)
}
