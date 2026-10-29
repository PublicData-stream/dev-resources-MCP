//! Persistent path inventories with bounded hash-radix directory partitions.
use devres_application::mdn::{
    InventoryNode, MDN_WRITE_BATCH_BYTES, MDN_WRITE_BATCH_ROWS, MdnStore, MdnWrite, Member,
};
use devres_domain::{Error, Result};
use std::collections::{BTreeMap, VecDeque};
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
    serde_json::to_value(item).map_err(|_| Error::integrity("Invalid MDN evidence encoding."))
}
pub fn decode<T: serde::de::DeserializeOwned>(item: serde_json::Value) -> Result<T> {
    serde_json::from_value(item).map_err(|_| Error::integrity("Invalid retained MDN evidence."))
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
    pub(crate) fn defer_writes(&mut self) {
        self.admit_writes = false;
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
pub async fn node(store: &dyn MdnStore, id: &str) -> Result<InventoryNode> {
    node_cached(store, id, &mut NodeCache::disabled()).await
}
pub(crate) async fn node_cached(
    store: &dyn MdnStore,
    id: &str,
    cache: &mut NodeCache,
) -> Result<InventoryNode> {
    if let Some(node) = cache.get(id) {
        return Ok(node);
    }
    let row = store
        .mdn_get("nodes", id)
        .await?
        .ok_or_else(|| Error::integrity("MDN inventory node missing."))?;
    let durable = row.sequence > 0;
    let node: InventoryNode = decode(row.data)?;
    let bytes =
        serde_json::to_vec(&node).map_err(|_| Error::integrity("Invalid MDN inventory."))?;
    if crate::integrity::verify(id, &bytes).is_err() {
        return Err(Error::integrity("MDN inventory hash mismatch."));
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
        return Err(Error::capacity("MDN directory partition bound exceeded."));
    }
    let bytes = serde_json::to_vec(node).map_err(|_| Error::integrity("Invalid MDN inventory."))?;
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
pub async fn put_node(store: &dyn MdnStore, node: &InventoryNode) -> Result<String> {
    let (id, encoded) = encoded_node(node)?;
    store.mdn_put("nodes", &id, &encoded.data).await?;
    Ok(id)
}
/// Nodes remain local until the complete new root can be committed as one group.
/// Partitioning may read a newly staged child before it exists in PostgreSQL.
struct Staged<'a> {
    store: &'a dyn MdnStore,
    cache: &'a mut NodeCache,
    nodes: BTreeMap<String, (InventoryNode, usize)>,
    rows: Vec<MdnWrite>,
    bytes: usize,
}
impl<'a> Staged<'a> {
    fn new(store: &'a dyn MdnStore, cache: &'a mut NodeCache) -> Self {
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
                return Err(Error::integrity("MDN staged node identity collision."));
            }
            return Ok(id);
        }
        // The envelope is at most 128 bytes for kind=nodes and a tagged BLAKE3 key.
        self.bytes = self
            .bytes
            .checked_add(encoded.bytes + 128)
            .filter(|bytes| *bytes <= MDN_WRITE_BATCH_BYTES)
            .ok_or_else(|| Error::capacity("MDN inventory update write budget exceeded."))?;
        if self.rows.len() >= MDN_WRITE_BATCH_ROWS {
            return Err(Error::capacity(
                "MDN inventory update node budget exceeded.",
            ));
        }
        self.rows.push(MdnWrite {
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
            return store.mdn_put_many(&rows).await;
        }
        store.mdn_put_many(&rows).await?;
        // A failed write must never expose staged evidence through the cache.
        for (id, (node, bytes)) in nodes {
            cache.insert(id, node, bytes);
        }
        Ok(())
    }
}

pub async fn empty(store: &dyn MdnStore) -> Result<String> {
    put_node(store, &InventoryNode::default()).await
}
async fn child(
    store: &dyn MdnStore,
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
            .ok_or_else(|| Error::integrity("Invalid MDN directory radix."))?;
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
pub async fn get(store: &dyn MdnStore, root: &str, path: &str) -> Result<Option<Member>> {
    get_cached(store, root, path, &mut NodeCache::disabled()).await
}
pub(crate) async fn get_cached(
    store: &dyn MdnStore,
    root: &str,
    path: &str,
    cache: &mut NodeCache,
) -> Result<Option<Member>> {
    if !valid_path(path) {
        return Err(Error::invalid("Invalid MDN member path."));
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
pub async fn subtree(store: &dyn MdnStore, root: &str, path: &str) -> Result<Option<String>> {
    if !valid_path(path) {
        return Err(Error::invalid("Invalid MDN directory path."));
    }
    let mut id = root.to_owned();
    for part in path.split('/') {
        let mut n = node(store, &id).await?;
        let hash = routing_hash(part.as_bytes(), !root.starts_with("blake3:"));
        let mut depth = 0;
        while !n.buckets.is_empty() {
            let key = hash
                .get(depth..depth + 1)
                .ok_or_else(|| Error::integrity("Invalid MDN directory radix."))?;
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
            matches!(m.kind.as_str(), "article" | "feature")
                && m.projection.is_some()
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
            "MDN directory hash collision bound exceeded.",
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
    store: &dyn MdnStore,
    root: &str,
    path: &str,
    member: Option<Member>,
) -> Result<String> {
    update_cached(store, root, path, member, &mut NodeCache::disabled()).await
}
pub(crate) async fn update_cached(
    store: &dyn MdnStore,
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
        return Err(Error::invalid("Invalid MDN member path."));
    }
    let mut stack = Vec::new();
    let mut current = node_cached(store, root, cache).await?;
    for part in path.split('/') {
        let hash = routing_hash(part.as_bytes(), false);
        let mut depth = 0;
        while !current.buckets.is_empty() {
            let key = hash
                .get(depth..depth + 1)
                .ok_or_else(|| Error::integrity("Invalid MDN directory radix."))?
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
pub async fn members(store: &dyn MdnStore, root: &str, max: usize) -> Result<Vec<Member>> {
    let mut stack = vec![root.to_string()];
    let mut out = Vec::new();
    let mut budget = 0usize;
    let mut visited = 0usize;
    while !stack.is_empty() {
        let start = stack.len().saturating_sub(1000);
        let ids = stack.split_off(start);
        let rows = store.mdn_get_many("nodes", &ids).await?;
        if rows.len() != ids.len() {
            return Err(Error::integrity("MDN inventory node missing."));
        }
        for row in rows {
            visited += 1;
            if visited > 4_000_000 {
                return Err(Error::capacity("MDN inventory traversal bound exceeded."));
            }
            let n: InventoryNode = decode(row.data)?;
            if crate::integrity::verify(
                &row.key,
                &serde_json::to_vec(&n).map_err(|_| Error::integrity("Invalid MDN node."))?,
            )
            .is_err()
            {
                return Err(Error::integrity("MDN inventory hash mismatch."));
            }
            if let Some(m) = n.member {
                budget = budget.saturating_add(
                    serde_json::to_vec(&m)
                        .map_err(|_| Error::integrity("Invalid MDN member."))?
                        .len(),
                );
                out.push(m);
                if out.len() > max || budget > 64 * 1024 * 1024 {
                    return Err(Error::capacity("MDN snapshot membership bound exceeded."));
                }
            }
            stack.extend(n.children.into_values());
            stack.extend(n.buckets.into_values());
        }
    }
    Ok(out)
}

/// Rebuild a frozen logical inventory with canonical BLAKE3 routing.
/// The caller rewrites typed references in each member; source data stays unchanged.
pub async fn rebuild_inventory(
    store: &dyn MdnStore,
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use devres_application::mdn::{MdnRow, View, validate_mdn_writes};
    use serde_json::{Value, json};
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    #[derive(Default)]
    struct Memory {
        rows: Mutex<BTreeMap<String, MdnRow>>,
        singles: AtomicUsize,
        reads: AtomicUsize,
        batches: AtomicUsize,
        fail_batch: AtomicBool,
    }
    #[async_trait]
    impl MdnStore for Memory {
        async fn mdn_cutoff(&self) -> Result<i64> {
            Ok(self.rows.lock().expect("rows").len() as i64)
        }
        async fn mdn_get(&self, kind: &str, key: &str) -> Result<Option<MdnRow>> {
            assert_eq!(kind, "nodes");
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(self.rows.lock().expect("rows").get(key).cloned())
        }
        async fn mdn_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
            assert_eq!(kind, "nodes");
            self.singles.fetch_add(1, Ordering::Relaxed);
            let mut rows = self.rows.lock().expect("rows");
            if let Some(row) = rows.get(key) {
                assert_eq!(&row.data, data);
                return Ok(row.sequence);
            }
            let sequence = rows.len() as i64 + 1;
            rows.insert(
                key.into(),
                MdnRow {
                    sequence,
                    key: key.into(),
                    data: data.clone(),
                },
            );
            Ok(sequence)
        }
        async fn mdn_put_many(&self, writes: &[MdnWrite]) -> Result<()> {
            validate_mdn_writes(writes)?;
            self.batches.fetch_add(1, Ordering::Relaxed);
            if self.fail_batch.swap(false, Ordering::Relaxed) {
                return Err(Error::unavailable("Synthetic batch failure."));
            }
            let mut rows = self.rows.lock().expect("rows");
            for write in writes {
                assert_eq!(write.kind, "nodes");
                if let Some(row) = rows.get(&write.key)
                    && row.data != write.data
                {
                    return Err(Error::integrity("Synthetic collision."));
                }
            }
            for write in writes {
                let sequence = rows.len() as i64 + 1;
                rows.entry(write.key.clone()).or_insert(MdnRow {
                    sequence,
                    key: write.key.clone(),
                    data: write.data.clone(),
                });
            }
            Ok(())
        }
        async fn mdn_rows(&self, _: &str, _: i64, _: usize, _: Option<i64>) -> Result<Vec<MdnRow>> {
            unreachable!("unused fixture port")
        }
        async fn mdn_state(&self, _: &str) -> Result<Option<Value>> {
            unreachable!("unused fixture port")
        }
        async fn mdn_set_state(&self, _: &str, _: &Value) -> Result<()> {
            unreachable!("unused fixture port")
        }
        async fn mdn_publish_view(&self, _: &View) -> Result<()> {
            unreachable!("unused fixture port")
        }
    }
    fn member(path: &str) -> Member {
        Member {
            path: path.into(),
            oid: "a".repeat(40),
            mode: "100644".into(),
            kind: "article".into(),
            projection: Some("b".repeat(64)),
            raw: None,
            gaps: Vec::new(),
        }
    }
    #[tokio::test]
    async fn cached_updates_preserve_golden_hash_partitioning_and_public_reads() {
        let store = Memory::default();
        let initial = empty(&store).await.expect("empty");
        let mut cache = NodeCache::new();
        let mut root = update_cached(&store, &initial, "a/b/c", Some(member("a/b/c")), &mut cache)
            .await
            .expect("cached update");
        assert_eq!(
            root,
            "blake3:5d39ea6f61f890c38ed97937d95d5ae980531cc0df3c186a31b863a75cbbcd5d"
        );
        let reads = store.reads.load(Ordering::Relaxed);
        assert_eq!(
            get_cached(&store, &root, "a/b/c", &mut cache)
                .await
                .expect("cache hit"),
            Some(member("a/b/c"))
        );
        assert_eq!(
            store.reads.load(Ordering::Relaxed),
            reads,
            "successful staged nodes are cached"
        );
        assert_eq!(
            get(&store, &root, "a/b/c").await.expect("public lookup"),
            Some(member("a/b/c"))
        );
        assert!(
            store.reads.load(Ordering::Relaxed) > reads,
            "public lookups retain store fences"
        );
        let mut reference = root.clone();
        for n in 0..70 {
            let path = format!("directory/member-{n:03}");
            root = update_cached(&store, &root, &path, Some(member(&path)), &mut cache)
                .await
                .expect("cached partition");
            reference = update(&store, &reference, &path, Some(member(&path)))
                .await
                .expect("reference partition");
            assert_eq!(root, reference, "cache cannot change inventory identity");
        }
        assert_eq!(
            members(&store, &root, 100)
                .await
                .expect("retained membership")
                .len(),
            71
        );
        assert!(
            get_cached(&store, &initial, "a/b/c", &mut cache)
                .await
                .expect("old root")
                .is_none()
        );
    }
    #[tokio::test]
    async fn legacy_radix_rebuild_preserves_members_and_reads() {
        let store = Memory::default();
        async fn legacy_put(store: &Memory, node: &InventoryNode) -> String {
            let bytes = serde_json::to_vec(node).expect("legacy encoding");
            let id = crate::integrity::legacy_hash(&bytes);
            store
                .mdn_put("nodes", &id, &value(node).expect("legacy value"))
                .await
                .expect("legacy row");
            id
        }
        let mut buckets = BTreeMap::<String, InventoryNode>::new();
        for n in 0..80 {
            let path = format!("member-{n:03}");
            let leaf = InventoryNode {
                member: Some(member(&path)),
                members: 1,
                searchable: 1,
                kinds: BTreeMap::from([("article".into(), 1)]),
                ..InventoryNode::default()
            };
            let id = legacy_put(&store, &leaf).await;
            let nibble = crate::integrity::legacy_hash(path.as_bytes())[..1].to_owned();
            let bucket = buckets.entry(nibble).or_default();
            bucket.children.insert(path, id);
            bucket.members += 1;
            bucket.searchable += 1;
            *bucket.kinds.entry("article".into()).or_default() += 1;
        }
        let mut root = InventoryNode {
            members: 80,
            searchable: 80,
            kinds: BTreeMap::from([("article".into(), 80)]),
            ..InventoryNode::default()
        };
        for (nibble, node) in buckets {
            root.buckets.insert(nibble, legacy_put(&store, &node).await);
        }
        let legacy = legacy_put(&store, &root).await;
        let canonical = rebuild_inventory(&store, &legacy, Ok)
            .await
            .expect("rebuild");
        assert!(canonical.starts_with("blake3:"));
        assert_ne!(canonical, legacy);
        for n in 0..80 {
            let path = format!("member-{n:03}");
            assert_eq!(
                get(&store, &legacy, &path).await.expect("legacy lookup"),
                Some(member(&path))
            );
            assert_eq!(
                get(&store, &canonical, &path)
                    .await
                    .expect("canonical lookup"),
                Some(member(&path))
            );
        }
        assert_eq!(
            members(&store, &legacy, 100)
                .await
                .expect("legacy members")
                .len(),
            80
        );
        assert_eq!(
            members(&store, &canonical, 100)
                .await
                .expect("canonical members")
                .len(),
            80
        );
        assert_eq!(
            update(&store, &legacy, "new", Some(member("new")))
                .await
                .expect_err("cannot mix radix generations")
                .code,
            "integrity"
        );
    }

    #[test]
    fn node_cache_fifo_enforces_both_capacity_limits() {
        let mut cache = NodeCache::new();
        let mut first = String::new();
        for n in 0..4097 {
            let node = InventoryNode {
                member: Some(member(&format!("entry-{n}"))),
                ..InventoryNode::default()
            };
            let (id, encoded) = encoded_node(&node).expect("encoded node");
            if n == 0 {
                first = id.clone();
            }
            cache.insert(id, node, encoded.bytes);
        }
        assert_eq!(cache.nodes.len(), 4096);
        assert!(
            !cache.nodes.contains_key(&first),
            "FIFO evicts the oldest admission"
        );
        let mut cache = NodeCache::new();
        for n in 0..10 {
            let mut m = member(&format!("large-{n}"));
            m.raw = Some(json!({"body":"x".repeat(1024 * 1024)}));
            let node = InventoryNode {
                member: Some(m),
                ..InventoryNode::default()
            };
            let (id, encoded) = encoded_node(&node).expect("encoded node");
            cache.insert(id, node, encoded.bytes);
            assert!(cache.bytes <= 8 * 1024 * 1024);
            assert!(cache.nodes.len() <= 4096);
        }
        assert_eq!(cache.nodes.len(), 7, "serialized-byte budget also evicts");
        let mut m = member("oversized");
        m.raw = Some(json!({"body":"x".repeat(8 * 1024 * 1024)}));
        let node = InventoryNode {
            member: Some(m),
            ..InventoryNode::default()
        };
        let (id, encoded) = encoded_node(&node).expect("encoded node");
        let before = (cache.nodes.len(), cache.bytes);
        cache.insert(id.clone(), node, encoded.bytes);
        assert!(!cache.nodes.contains_key(&id));
        assert_eq!((cache.nodes.len(), cache.bytes), before);
    }
    #[tokio::test]
    async fn corrupt_reads_and_failed_writes_never_admit_nodes_to_cache() {
        let store = Memory::default();
        let initial = empty(&store).await.expect("empty");
        let mut cache = NodeCache::new();
        node_cached(&store, &initial, &mut cache)
            .await
            .expect("verified empty");
        let before = cache.nodes.keys().cloned().collect::<Vec<_>>();
        let mut staged = Staged::new(&store, &mut cache);
        let pending = staged
            .put(&InventoryNode {
                member: Some(member("not-committed")),
                ..InventoryNode::default()
            })
            .expect("stage");
        store.fail_batch.store(true, Ordering::Relaxed);
        assert_eq!(
            staged.commit().await.expect_err("failed write").code,
            "unavailable"
        );
        assert_eq!(cache.nodes.keys().cloned().collect::<Vec<_>>(), before);
        assert!(!cache.nodes.contains_key(&pending));
        assert!(
            store
                .mdn_get("nodes", &pending)
                .await
                .expect("failed row absent")
                .is_none()
        );
        let corrupt = "f".repeat(64);
        store
            .mdn_put(
                "nodes",
                &corrupt,
                &value(&InventoryNode::default()).expect("encode"),
            )
            .await
            .expect("corrupt fixture");
        assert_eq!(
            node_cached(&store, &corrupt, &mut cache)
                .await
                .expect_err("hash mismatch")
                .code,
            "integrity"
        );
        assert!(!cache.nodes.contains_key(&corrupt));
    }
    #[tokio::test]
    async fn path_writes_one_group_preserves_hash_and_skips_no_op_updates() {
        let store = Memory::default();
        let empty = empty(&store).await.expect("empty");
        let m = member("a/b/c");
        let root = update(&store, &empty, &m.path, Some(m.clone()))
            .await
            .expect("batched path");
        assert_eq!(
            root, "blake3:5d39ea6f61f890c38ed97937d95d5ae980531cc0df3c186a31b863a75cbbcd5d",
            "canonical BLAKE3 inventory encoding identity"
        );
        assert_eq!(
            store.singles.load(Ordering::Relaxed),
            1,
            "only initial empty node uses single-row publication"
        );
        assert_eq!(store.batches.load(Ordering::Relaxed), 1);
        assert_eq!(
            get(&store, &root, "a/b/c").await.expect("published child"),
            Some(m.clone())
        );
        let count_before_no_op = store.rows.lock().expect("rows").len();
        assert_eq!(
            update(&store, &root, "a/b/c", Some(m))
                .await
                .expect("same member"),
            root
        );
        assert_eq!(
            update(&store, &root, "a/absent/child", None)
                .await
                .expect("absent delete"),
            root
        );
        assert_eq!(
            store.batches.load(Ordering::Relaxed),
            1,
            "no-op updates must not publish or fsync nodes"
        );
        assert_eq!(store.rows.lock().expect("rows").len(), count_before_no_op);
        assert!(
            get(&store, &empty, "a/b/c")
                .await
                .expect("old root")
                .is_none()
        );
    }
    #[tokio::test]
    async fn partition_reads_new_staged_children_and_failed_batch_preserves_old_root() {
        let store = Memory::default();
        let mut root = empty(&store).await.expect("empty");
        for n in 0..64 {
            let path = format!("directory/member-{n:03}");
            root = update(&store, &root, &path, Some(member(&path)))
                .await
                .expect("populate");
        }
        let old = root.clone();
        let old_count = store.rows.lock().expect("rows").len();
        let path = "directory/member-064";
        store.fail_batch.store(true, Ordering::Relaxed);
        assert_eq!(
            update(&store, &root, path, Some(member(path)))
                .await
                .expect_err("failed group")
                .code,
            "unavailable"
        );
        assert_eq!(store.rows.lock().expect("rows").len(), old_count);
        assert!(
            get(&store, &old, path)
                .await
                .expect("unchanged root")
                .is_none()
        );
        root = update(&store, &root, path, Some(member(path)))
            .await
            .expect("partition with staged new child");
        assert_eq!(
            members(&store, &root, 100)
                .await
                .expect("new directory")
                .len(),
            65
        );
        assert_eq!(
            members(&store, &old, 100)
                .await
                .expect("old directory")
                .len(),
            64
        );
        assert_eq!(
            get(&store, &root, path).await.expect("new member"),
            Some(member(path))
        );
        for n in 0..65 {
            let path = format!("directory/member-{n:03}");
            assert_eq!(
                get(&store, &root, &path).await.expect("partition member"),
                Some(member(&path))
            );
        }
        assert_eq!(
            node(&store, &root).await.expect("counts").kinds,
            json!({"article":65})
                .as_object()
                .expect("object")
                .iter()
                .map(|(k, v)| (k.clone(), v.as_u64().expect("count")))
                .collect()
        );
    }
}
