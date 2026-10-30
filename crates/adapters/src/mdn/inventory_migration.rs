//! Offline-only canonical replay. All memo records are disposable and private;
//! immutable inventory nodes must be durable before their memo records are admitted.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tokio_util::sync::CancellationToken;

/// One fixed, deterministic member rewrite context. Do not reuse this memo with a
/// different reference mapping or mutate the backing store during replay.
pub(crate) struct MigrationInventory {
    records: crate::MigrationMap,
    nodes: NodeCache,
}
impl MigrationInventory {
    pub(crate) fn new() -> Self {
        Self {
            records: crate::MigrationMap::new(),
            nodes: NodeCache::new(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Tree {
    id: String,
    /// Immediate named children, including those held in radix buckets.
    names: u64,
    bytes: usize,
    totals: (u64, u64, u64, BTreeMap<String, u64>),
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fragment {
    prefix: Vec<String>,
    tree: Tree,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
struct Summary {
    nodes: u64,
    members: u64,
    bytes: u64,
}
impl Summary {
    fn add(&mut self, other: Self) -> Result<()> {
        self.nodes = self.nodes.saturating_add(other.nodes);
        self.members = self.members.saturating_add(other.members);
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.check()
    }
    fn check(&self) -> Result<()> {
        if self.nodes > 4_000_000 {
            return Err(Error::capacity("MDN inventory traversal bound exceeded."));
        }
        if self.members > 1_000_000 || self.bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity("MDN snapshot membership bound exceeded."));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Converted {
    fragment: Option<Fragment>,
    summary: Summary,
    /// Some shapes need the reference order or its existing memory strategy.
    fallback: Option<UnsupportedReason>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum UnsupportedReason {
    ConflictingMember,
    ResidentUnionShape,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
enum Union {
    Tree(Fragment),
    Unsupported(UnsupportedReason),
}
#[derive(Serialize, Deserialize)]
struct Proof<T> {
    operand: String,
    result: T,
}
struct Directory {
    member: Option<Member>,
    children: BTreeMap<String, Fragment>,
    buckets: BTreeMap<String, Tree>,
    names: u64,
}
impl Directory {
    fn private_bytes(&self) -> usize {
        fn tree_bytes(tree: &Tree) -> usize {
            tree.id.capacity()
                + 256
                + tree
                    .totals
                    .3
                    .keys()
                    .map(|kind| kind.capacity() + 64)
                    .sum::<usize>()
        }
        self.children
            .iter()
            .map(|(name, fragment)| {
                name.capacity()
                    + tree_bytes(&fragment.tree)
                    + fragment.prefix.capacity() * std::mem::size_of::<String>()
                    + fragment.prefix.iter().map(String::capacity).sum::<usize>()
            })
            .sum::<usize>()
            + self
                .buckets
                .iter()
                .map(|(name, tree)| name.capacity() + tree_bytes(tree))
                .sum::<usize>()
    }
}
struct SourceFrame {
    id: String,
    next: VecDeque<String>,
    result: Converted,
    // Binary carry groups keep folds balanced without retaining every member.
    parts: Vec<Option<Fragment>>,
}
impl SourceFrame {
    fn resident_bytes(&self) -> usize {
        let strings = self.next.iter().map(String::capacity).sum::<usize>();
        let fragments = self
            .parts
            .iter()
            .flatten()
            .map(|fragment| {
                fragment.tree.id.capacity()
                    + fragment
                        .tree
                        .totals
                        .3
                        .keys()
                        .map(|kind| kind.capacity() + 64)
                        .sum::<usize>()
                    + fragment.prefix.capacity() * std::mem::size_of::<String>()
                    + fragment.prefix.iter().map(String::capacity).sum::<usize>()
            })
            .sum::<usize>();
        512 + self.id.capacity()
            + self.next.capacity() * std::mem::size_of::<String>()
            + strings
            + self.parts.capacity() * std::mem::size_of::<Option<Fragment>>()
            + fragments
    }
}
enum ReplayError {
    Evidence(Error),
    Unsupported,
}
impl From<Error> for ReplayError {
    fn from(error: Error) -> Self {
        Self::Evidence(error)
    }
}
type ReplayResult<T> = std::result::Result<T, ReplayError>;
struct Replay<'a> {
    memo: &'a mut crate::MigrationMap,
    staged: Staged<'a>,
    cancel: &'a CancellationToken,
    pending: BTreeMap<String, String>,
    pending_bytes: usize,
    active: BTreeSet<String>,
    union_bytes: usize,
}
impl Replay<'_> {
    fn check(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            return Err(Error::new("cancelled", "MDN inventory migration canceled."));
        }
        self.memo.ensure_healthy()
    }
    fn get<T: serde::de::DeserializeOwned>(
        &self,
        kind: &str,
        operand: &str,
    ) -> ReplayResult<Option<T>> {
        self.check()?;
        let key = format!("inventory-v1:{kind}:{}", digest(operand.as_bytes()));
        let encoded = self
            .pending
            .get(&key)
            .cloned()
            .or_else(|| self.memo.get(&key));
        self.memo.ensure_healthy()?;
        encoded
            .map(|encoded| {
                let proof: Proof<T> = serde_json::from_str(&encoded)
                    .map_err(|_| Error::integrity("Invalid inventory migration memo."))?;
                if proof.operand != operand {
                    return Err(Error::integrity(
                        "Inventory migration memo identity collision.",
                    ));
                }
                Ok(proof.result)
            })
            .transpose()
            .map_err(ReplayError::from)
    }
    async fn remember<T: Serialize>(
        &mut self,
        kind: &str,
        operand: String,
        result: &T,
    ) -> ReplayResult<()> {
        self.check()?;
        let key = format!("inventory-v1:{kind}:{}", digest(operand.as_bytes()));
        let encoded = serde_json::to_string(&Proof { operand, result })
            .map_err(|_| Error::integrity("Invalid inventory migration memo."))?;
        let bytes = key.len().saturating_add(encoded.len());
        if bytes > 1024 * 1024 {
            return Err(ReplayError::Unsupported);
        }
        if self.pending_bytes.saturating_add(bytes) > 1024 * 1024 {
            self.flush().await?;
        }
        if let Some(old) = self.pending.insert(key, encoded) {
            self.pending_bytes = self.pending_bytes.saturating_sub(old.len());
        }
        self.pending_bytes = self.pending_bytes.saturating_add(bytes);
        Ok(())
    }
    async fn flush(&mut self) -> ReplayResult<()> {
        self.check()?;
        self.staged.flush().await?;
        // These values refer only to nodes already committed by the successful
        // flush. A failed write never publishes either node-cache or memo state.
        for (key, encoded) in std::mem::take(&mut self.pending) {
            self.check()?;
            crate::migration_map::insert(self.memo, key, encoded)?;
        }
        self.pending_bytes = 0;
        Ok(())
    }
    async fn put(&mut self, node: InventoryNode, names: u64) -> ReplayResult<Tree> {
        self.check()?;
        let metadata = serde_json::to_vec(&node.kinds)
            .map_err(|_| Error::integrity("Invalid MDN inventory kinds."))?;
        if metadata.len() > 4096 {
            return Err(ReplayError::Unsupported);
        }
        let (id, encoded) = encoded_node(&node)?;
        if !self.staged.nodes.contains_key(&id)
            && (self.staged.rows.len() >= MDN_WRITE_BATCH_ROWS
                || self.staged.bytes.saturating_add(encoded.bytes + 128) > 8 * 1024 * 1024)
        {
            self.flush().await?;
        }
        let tree = Tree {
            id: self.staged.put(&node)?,
            names,
            bytes: encoded.bytes,
            totals: (node.members, node.searchable, node.gaps, node.kinds.clone()),
        };
        self.remember("tree", tree.id.clone(), &tree).await?;
        Ok(tree)
    }
    async fn tree(&mut self, id: String) -> ReplayResult<Tree> {
        if let Some(tree) = self.get::<Tree>("tree", &id)? {
            return Ok(tree);
        }
        let node = self.staged.node(&id).await?;
        let mut names = node.children.len() as u64;
        for bucket in node.buckets.values() {
            names = names
                .checked_add(Box::pin(self.tree(bucket.clone())).await?.names)
                .ok_or_else(|| Error::capacity("MDN inventory directory bound exceeded."))?;
        }
        let bytes = serde_json::to_vec(&node)
            .map_err(|_| Error::integrity("Invalid MDN inventory."))?
            .len();
        let tree = Tree {
            id,
            names,
            bytes,
            totals: (node.members, node.searchable, node.gaps, node.kinds),
        };
        self.remember("tree", tree.id.clone(), &tree).await?;
        Ok(tree)
    }
    async fn materialize(&mut self, fragment: Fragment) -> ReplayResult<Tree> {
        let mut tree = fragment.tree;
        for name in fragment.prefix.into_iter().rev() {
            tree = self.build(BTreeMap::from([(name, tree)]), None, 0).await?;
        }
        Ok(tree)
    }
    async fn directory(&mut self, fragment: Fragment) -> ReplayResult<Directory> {
        if let Some((name, rest)) = fragment.prefix.split_first() {
            return Ok(Directory {
                member: None,
                children: BTreeMap::from([(
                    name.clone(),
                    Fragment {
                        prefix: rest.to_vec(),
                        tree: fragment.tree,
                    },
                )]),
                buckets: BTreeMap::new(),
                names: 1,
            });
        }
        let node = self.staged.node(&fragment.tree.id).await?;
        let mut children = BTreeMap::new();
        for (name, id) in node.children {
            children.insert(
                name,
                Fragment {
                    prefix: Vec::new(),
                    tree: self.tree(id).await?,
                },
            );
        }
        let mut buckets = BTreeMap::new();
        for (nibble, id) in node.buckets {
            buckets.insert(nibble, self.tree(id).await?);
        }
        Ok(Directory {
            member: node.member,
            children,
            buckets,
            names: fragment.tree.names,
        })
    }
    async fn named(&mut self, directory: Directory) -> ReplayResult<BTreeMap<String, Fragment>> {
        let mut children = directory.children;
        for tree in directory.buckets.into_values() {
            let next = self
                .directory(Fragment {
                    prefix: Vec::new(),
                    tree,
                })
                .await?;
            for (name, child) in Box::pin(self.named(next)).await? {
                if children.insert(name, child).is_some() {
                    return Err(ReplayError::Evidence(Error::integrity(
                        "Invalid canonical MDN directory.",
                    )));
                }
            }
        }
        Ok(children)
    }
    async fn bucketed(
        &mut self,
        directory: Directory,
        depth: usize,
    ) -> ReplayResult<BTreeMap<String, Tree>> {
        if !directory.buckets.is_empty() {
            return Ok(directory.buckets);
        }
        if depth >= 64 && !directory.children.is_empty() {
            return Err(ReplayError::Evidence(Error::capacity(
                "MDN directory hash collision bound exceeded.",
            )));
        }
        let mut groups = BTreeMap::<String, BTreeMap<String, Tree>>::new();
        for (name, fragment) in directory.children {
            let nibble = routing_hash(name.as_bytes(), false)[depth..depth + 1].to_owned();
            let tree = self.materialize(fragment).await?;
            groups.entry(nibble).or_default().insert(name, tree);
        }
        let mut buckets = BTreeMap::new();
        for (nibble, children) in groups {
            buckets.insert(nibble, self.build(children, None, depth + 1).await?);
        }
        Ok(buckets)
    }
    async fn build(
        &mut self,
        children: BTreeMap<String, Tree>,
        member: Option<Member>,
        depth: usize,
    ) -> ReplayResult<Tree> {
        let names = children.len() as u64;
        let mut node = InventoryNode {
            member,
            ..InventoryNode::default()
        };
        let own = counts(node.member.as_ref());
        adjust(&mut node, (0, 0, 0, BTreeMap::new()), own);
        for tree in children.values() {
            adjust(&mut node, (0, 0, 0, BTreeMap::new()), tree.totals.clone());
        }
        if names <= 64 {
            node.children = children
                .into_iter()
                .map(|(name, tree)| (name, tree.id))
                .collect();
        } else {
            if depth >= 64 {
                return Err(ReplayError::Evidence(Error::capacity(
                    "MDN directory hash collision bound exceeded.",
                )));
            }
            let mut groups = BTreeMap::<String, BTreeMap<String, Tree>>::new();
            for (name, tree) in children {
                let nibble = routing_hash(name.as_bytes(), false)[depth..depth + 1].to_owned();
                groups.entry(nibble).or_default().insert(name, tree);
            }
            for (nibble, children) in groups {
                let tree = Box::pin(self.build(children, None, depth + 1)).await?;
                node.buckets.insert(nibble, tree.id);
            }
        }
        self.put(node, names).await
    }
    async fn union(&mut self, left: Fragment, right: Fragment) -> ReplayResult<Union> {
        self.check()?;
        if left == right {
            return Ok(Union::Tree(left));
        }
        let common = left
            .prefix
            .iter()
            .zip(&right.prefix)
            .take_while(|(a, b)| a == b)
            .count();
        let prefix = left.prefix[..common].to_vec();
        let left = Fragment {
            prefix: left.prefix[common..].to_vec(),
            tree: left.tree,
        };
        let right = Fragment {
            prefix: right.prefix[common..].to_vec(),
            tree: right.tree,
        };
        match Box::pin(self.merge(left, right, 0)).await? {
            Union::Unsupported(reason) => Ok(Union::Unsupported(reason)),
            Union::Tree(mut result) => {
                let mut combined = prefix;
                combined.append(&mut result.prefix);
                result.prefix = combined;
                Ok(Union::Tree(result))
            }
        }
    }
    async fn merge(
        &mut self,
        left: Fragment,
        right: Fragment,
        depth: usize,
    ) -> ReplayResult<Union> {
        self.check()?;
        let operand = serde_json::to_string(&(depth, &left, &right))
            .map_err(|_| Error::integrity("Invalid inventory union encoding."))?;
        if let Some(result) = self.get("union", &operand)? {
            return Ok(result);
        }
        fn cost(fragment: &Fragment) -> usize {
            if fragment.prefix.is_empty() {
                fragment.tree.bytes.saturating_add(256)
            } else {
                512 + fragment.prefix.iter().map(String::len).sum::<usize>()
                    + fragment
                        .tree
                        .totals
                        .3
                        .keys()
                        .map(|kind| kind.len() + 64)
                        .sum::<usize>()
            }
        }
        // Charge retained directory encodings and the selected own-member clone
        // before reading either operand. This is a serialized working-set bound,
        // not a claim about allocator overhead or process RSS.
        let a = cost(&left);
        let b = cost(&right);
        let charge = a.saturating_add(b).saturating_add(a.max(b));
        if self.union_bytes.saturating_add(charge) > 12 * 1024 * 1024 {
            return Ok(Union::Unsupported(UnsupportedReason::ResidentUnionShape));
        }
        self.union_bytes += charge;
        let result = self.merge_inner(left, right, depth).await;
        self.union_bytes -= charge;
        let result = result?;
        self.remember("union", operand, &result).await?;
        Ok(result)
    }
    async fn merge_inner(
        &mut self,
        left: Fragment,
        right: Fragment,
        depth: usize,
    ) -> ReplayResult<Union> {
        if left == right {
            return Ok(Union::Tree(Fragment {
                prefix: Vec::new(),
                tree: self.materialize(left).await?,
            }));
        }
        let left = self.directory(left).await?;
        let right = self.directory(right).await?;
        let private = left.private_bytes().saturating_add(right.private_bytes());
        if self.union_bytes.saturating_add(private) > 12 * 1024 * 1024 {
            return Ok(Union::Unsupported(UnsupportedReason::ResidentUnionShape));
        }
        self.union_bytes += private;
        let result = self.merge_loaded(left, right, depth).await;
        self.union_bytes -= private;
        result
    }
    async fn merge_loaded(
        &mut self,
        left: Directory,
        right: Directory,
        depth: usize,
    ) -> ReplayResult<Union> {
        let member = match (&left.member, &right.member) {
            (Some(a), Some(b)) if a != b => {
                return Ok(Union::Unsupported(UnsupportedReason::ConflictingMember));
            }
            (Some(a), _) => Some(a.clone()),
            (_, member) => member.clone(),
        };
        let tree = if left.names <= 64 && right.names <= 64 {
            let mut children = self.named(left).await?;
            for (name, incoming) in self.named(right).await? {
                let fragment = if let Some(old) = children.remove(&name) {
                    match Box::pin(self.union(old, incoming)).await? {
                        Union::Tree(fragment) => fragment,
                        Union::Unsupported(reason) => return Ok(Union::Unsupported(reason)),
                    }
                } else {
                    incoming
                };
                children.insert(name, fragment);
            }
            let mut materialized = BTreeMap::new();
            for (name, fragment) in children {
                materialized.insert(name, self.materialize(fragment).await?);
            }
            self.build(materialized, member, depth).await?
        } else {
            let mut buckets = self.bucketed(left, depth).await?;
            for (nibble, incoming) in self.bucketed(right, depth).await? {
                let tree = if let Some(old) = buckets.remove(&nibble) {
                    match Box::pin(self.merge(
                        Fragment {
                            prefix: Vec::new(),
                            tree: old,
                        },
                        Fragment {
                            prefix: Vec::new(),
                            tree: incoming,
                        },
                        depth + 1,
                    ))
                    .await?
                    {
                        Union::Tree(fragment) => self.materialize(fragment).await?,
                        Union::Unsupported(reason) => return Ok(Union::Unsupported(reason)),
                    }
                } else {
                    incoming
                };
                buckets.insert(nibble, tree);
            }
            let names = buckets.values().map(|tree| tree.names).sum();
            let mut node = InventoryNode {
                member,
                ..InventoryNode::default()
            };
            let own = counts(node.member.as_ref());
            adjust(&mut node, (0, 0, 0, BTreeMap::new()), own);
            for (nibble, tree) in buckets {
                adjust(&mut node, (0, 0, 0, BTreeMap::new()), tree.totals.clone());
                node.buckets.insert(nibble, tree.id);
            }
            self.put(node, names).await?
        };
        // Only named directory edges may be compressed. Radix bucket levels carry
        // hashing depth and are never removed by this normalization.
        let fragment = if depth == 0 {
            self.compress(tree).await?
        } else {
            Fragment {
                prefix: Vec::new(),
                tree,
            }
        };
        Ok(Union::Tree(fragment))
    }
    async fn compress(&mut self, mut tree: Tree) -> ReplayResult<Fragment> {
        let mut prefix = Vec::new();
        loop {
            let node = self.staged.node(&tree.id).await?;
            if node.member.is_some() || !node.buckets.is_empty() || node.children.len() != 1 {
                break;
            }
            let Some((name, id)) = node.children.into_iter().next() else {
                break;
            };
            prefix.push(name);
            tree = self.tree(id).await?;
        }
        Ok(Fragment { prefix, tree })
    }
    async fn append(&mut self, frame: &mut SourceFrame, next: Converted) -> ReplayResult<()> {
        frame.result.summary.add(next.summary)?;
        frame.result.fallback = frame.result.fallback.or(next.fallback);
        if frame.result.fallback.is_some() {
            frame.parts.clear();
            return Ok(());
        }
        let Some(mut incoming) = next.fragment else {
            return Ok(());
        };
        let mut level = 0;
        loop {
            if level == frame.parts.len() {
                frame.parts.push(None);
            }
            let Some(old) = frame.parts[level].take() else {
                frame.parts[level] = Some(incoming);
                break;
            };
            incoming = match self.union(old, incoming).await? {
                Union::Tree(fragment) => fragment,
                Union::Unsupported(reason) => {
                    frame.result.fallback = Some(reason);
                    frame.parts.clear();
                    break;
                }
            };
            level += 1;
        }
        Ok(())
    }
    async fn start(
        &mut self,
        id: String,
        rewrite: &mut impl FnMut(Member) -> Result<Member>,
        visited: &mut Summary,
    ) -> ReplayResult<SourceFrame> {
        self.check()?;
        if !self.active.insert(id.clone()) {
            return Err(ReplayError::Evidence(Error::integrity(
                "Cyclic MDN inventory.",
            )));
        }
        // Admit the physical occurrence before its read or descendant work. Memo
        // hits are charged separately with their full expanded source summaries.
        visited.add(Summary {
            nodes: 1,
            ..Summary::default()
        })?;
        let node = self.staged.node(&id).await?;
        let mut summary = Summary {
            nodes: 1,
            ..Summary::default()
        };
        let mut parts = Vec::new();
        if let Some(member) = node.member {
            summary.members = 1;
            summary.bytes = serde_json::to_vec(&member)
                .map_err(|_| Error::integrity("Invalid MDN member."))?
                .len() as u64;
            visited.add(Summary {
                nodes: 0,
                ..summary
            })?;
            let member = rewrite(member)?;
            if !valid_path(&member.path) {
                return Err(ReplayError::Evidence(Error::invalid(
                    "Invalid MDN member path.",
                )));
            }
            let prefix = member.path.split('/').map(str::to_owned).collect();
            let mut leaf = InventoryNode {
                member: Some(member),
                ..InventoryNode::default()
            };
            let own = counts(leaf.member.as_ref());
            adjust(&mut leaf, (0, 0, 0, BTreeMap::new()), own);
            parts.push(Some(Fragment {
                prefix,
                tree: self.put(leaf, 0).await?,
            }));
        }
        Ok(SourceFrame {
            id,
            // Routing is ignored for placement. Both edge kinds remain part of
            // hash validation and expanded-occurrence accounting.
            next: node
                .children
                .into_values()
                .chain(node.buckets.into_values())
                .collect(),
            result: Converted {
                fragment: None,
                summary,
                fallback: None,
            },
            parts,
        })
    }
    async fn convert(
        &mut self,
        id: &str,
        rewrite: &mut impl FnMut(Member) -> Result<Member>,
    ) -> ReplayResult<Converted> {
        self.check()?;
        let mut visited = Summary::default();
        if let Some(result) = self.get::<Converted>("source", id)? {
            visited.add(result.summary)?;
            return Ok(result);
        }
        // Producer paths have <=64 named components and <=64 radix levels per
        // directory. Reject deeper malformed graphs without recursive polling.
        const MAX_DEPTH: usize = 64 * 65 + 1;
        // Together with the two 8MiB spill caches, 8MiB node cache, 8MiB staged
        // writes and 1MiB pending proofs this leaves room below 64MiB for unions.
        // The staging API also accepts one isolated node up to its 16MiB bound.
        const MAX_FRAMES: usize = 8 * 1024 * 1024;
        let frame = self.start(id.to_owned(), rewrite, &mut visited).await?;
        let mut resident = frame.resident_bytes();
        let mut stack = vec![frame];
        loop {
            self.check()?;
            if resident > MAX_FRAMES || stack.len() > MAX_DEPTH {
                return Err(ReplayError::Evidence(Error::capacity(
                    "MDN inventory migration frame bound exceeded.",
                )));
            }
            let next = stack.last_mut().and_then(|frame| frame.next.pop_front());
            if let Some(id) = next {
                resident = resident.saturating_sub(id.capacity());
                if let Some(result) = self.get::<Converted>("source", &id)? {
                    visited.add(result.summary)?;
                    let Some(parent) = stack.last_mut() else {
                        return Err(ReplayError::Evidence(Error::integrity(
                            "Invalid inventory traversal state.",
                        )));
                    };
                    let before = parent.resident_bytes();
                    self.append(parent, result).await?;
                    resident = resident
                        .saturating_sub(before)
                        .saturating_add(parent.resident_bytes());
                } else {
                    let frame = self.start(id, rewrite, &mut visited).await?;
                    resident = resident.saturating_add(frame.resident_bytes());
                    stack.push(frame);
                }
                continue;
            }
            let Some(mut frame) = stack.pop() else {
                return Err(ReplayError::Evidence(Error::integrity(
                    "Invalid inventory traversal state.",
                )));
            };
            resident = resident.saturating_sub(frame.resident_bytes());
            if frame.result.fallback.is_none() {
                for fragment in frame.parts.into_iter().rev().flatten() {
                    frame.result.fragment = Some(match frame.result.fragment.take() {
                        None => fragment,
                        Some(old) => match self.union(old, fragment).await? {
                            Union::Tree(fragment) => fragment,
                            Union::Unsupported(reason) => {
                                frame.result.fallback = Some(reason);
                                break;
                            }
                        },
                    });
                }
            }
            self.active.remove(&frame.id);
            self.remember("source", frame.id, &frame.result).await?;
            let Some(parent) = stack.last_mut() else {
                return Ok(frame.result);
            };
            let before = parent.resident_bytes();
            self.append(parent, frame.result).await?;
            resident = resident
                .saturating_sub(before)
                .saturating_add(parent.resident_bytes());
        }
    }
}

/// Exact fresh-rebuild identity, with shared old subtrees and canonical unions
/// memoized privately. `rewrite` must be deterministic for the lifetime of `memo`.
pub(crate) async fn rebuild_inventory_memoized(
    store: &dyn MdnStore,
    root: &str,
    mut rewrite: impl FnMut(Member) -> Result<Member>,
    memo: &mut MigrationInventory,
    cancel: &CancellationToken,
) -> Result<String> {
    let mut replay = Replay {
        memo: &mut memo.records,
        staged: Staged::new(store, &mut memo.nodes),
        cancel,
        pending: BTreeMap::new(),
        pending_bytes: 0,
        active: BTreeSet::new(),
        union_bytes: 0,
    };
    let converted = match replay.convert(root, &mut rewrite).await {
        Ok(converted) => Some(converted),
        Err(ReplayError::Evidence(error)) => return Err(error),
        Err(ReplayError::Unsupported) => None,
    };
    if let Some(converted) = &converted {
        converted.summary.check()?;
    }
    if converted
        .as_ref()
        .is_none_or(|converted| converted.fallback.is_some())
    {
        // Flush only bounded, already completed evidence; discard an unfinished
        // oversized proof rather than catching unrelated operational failures.
        match replay.flush().await {
            Ok(()) => {}
            Err(ReplayError::Evidence(error)) => return Err(error),
            Err(ReplayError::Unsupported) => {
                return Err(Error::integrity("Invalid inventory flush control."));
            }
        }
        drop(replay);
        // Preserve the reference's stable original-path sort and last-write wins,
        // including rare shapes exceeding the optimized union working set.
        return tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(Error::new("cancelled", "MDN inventory migration canceled.")),
            result = rebuild_inventory(store, root, rewrite) => result,
        };
    }
    let Some(converted) = converted else {
        return Err(Error::integrity("Invalid inventory conversion control."));
    };
    let finish = async {
        let tree = match converted.fragment {
            Some(fragment) => replay.materialize(fragment).await?,
            None => replay.put(InventoryNode::default(), 0).await?,
        };
        replay.flush().await?;
        Ok::<_, ReplayError>(tree.id)
    }
    .await;
    match finish {
        Ok(root) => Ok(root),
        Err(ReplayError::Evidence(error)) => Err(error),
        Err(ReplayError::Unsupported) => {
            drop(replay);
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(Error::new("cancelled", "MDN inventory migration canceled.")),
                result = rebuild_inventory(store, root, rewrite) => result,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Memory, member};
    use super::*;
    use std::sync::atomic::Ordering;

    async fn legacy_put(store: &Memory, node: &InventoryNode) -> String {
        let id = crate::integrity::legacy_hash(&serde_json::to_vec(node).expect("node bytes"));
        store
            .mdn_put("nodes", &id, &value(node).expect("node value"))
            .await
            .expect("retained source");
        id
    }
    async fn legacy_partition(store: &Memory, mut node: InventoryNode, depth: usize) -> String {
        if node.children.len() > 64 {
            let mut groups = BTreeMap::<String, InventoryNode>::new();
            for (name, id) in std::mem::take(&mut node.children) {
                let nibble = routing_hash(name.as_bytes(), true)[depth..depth + 1].to_owned();
                groups.entry(nibble).or_default().children.insert(name, id);
            }
            for (nibble, group) in groups {
                node.buckets.insert(
                    nibble,
                    Box::pin(legacy_partition(store, group, depth + 1)).await,
                );
            }
        }
        // Deliberately false stored aggregates prove replay counts retained data.
        node.members = 999;
        node.searchable = 555;
        legacy_put(store, &node).await
    }
    async fn legacy_directory(store: &Memory, items: Vec<(Vec<String>, Member)>) -> String {
        let mut node = InventoryNode::default();
        let mut groups = BTreeMap::<String, Vec<(Vec<String>, Member)>>::new();
        for (path, member) in items {
            if let Some((name, rest)) = path.split_first() {
                groups
                    .entry(name.clone())
                    .or_default()
                    .push((rest.to_vec(), member));
            } else {
                node.member = Some(member);
            }
        }
        for (name, group) in groups {
            node.children
                .insert(name, Box::pin(legacy_directory(store, group)).await);
        }
        legacy_partition(store, node, 0).await
    }
    async fn legacy_inventory(store: &Memory, members: Vec<Member>) -> String {
        legacy_directory(
            store,
            members
                .into_iter()
                .map(|member| (member.path.split('/').map(str::to_owned).collect(), member))
                .collect(),
        )
        .await
    }
    async fn compare(store: &Memory, source: &str, memo: &mut MigrationInventory) -> String {
        let expected = rebuild_inventory(store, source, Ok)
            .await
            .expect("reference rebuild");
        let result = rebuild_inventory_memoized(store, source, Ok, memo, &CancellationToken::new())
            .await
            .expect("memoized rebuild");
        assert_eq!(result, expected, "exact canonical root identity");
        result
    }
    #[tokio::test]
    async fn legacy_thresholds_and_randomized_history_match_reference_hashes() {
        let store = Memory::default();
        let mut memo = MigrationInventory::new();
        for count in [0, 1, 63, 64, 65, 100, 140] {
            let source = legacy_inventory(
                &store,
                (0..count)
                    .map(|n| {
                        let mut m = member(&format!("en-us/docs/Web/API/member-{n:03}"));
                        if n % 7 == 0 {
                            m.gaps.push("search_index_gap".into());
                        }
                        if n % 11 == 0 {
                            m.kind = "feature".into();
                        }
                        m
                    })
                    .collect(),
            )
            .await;
            compare(&store, &source, &mut memo).await;
        }
        let mut seed = 0x3742_b91a_u64;
        let mut retained = BTreeMap::new();
        for step in 0..96 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let path = format!("a/{}/entry-{:02}", (seed >> 32) % 5, (seed >> 16) % 72);
            if step % 5 == 0 {
                retained.remove(&path);
            } else {
                let mut m = member(&path);
                m.oid = format!("{step:040x}");
                retained.insert(path, m);
            }
            let source = legacy_inventory(&store, retained.values().cloned().collect()).await;
            compare(&store, &source, &mut memo).await;
        }
    }
    #[tokio::test]
    async fn deeply_colliding_names_and_overpartitioned_deletions_normalize() {
        let store = Memory::default();
        let mut colliding = Vec::new();
        for candidate in 0..100_000 {
            let name = format!("name-{candidate:06}");
            if routing_hash(name.as_bytes(), false).starts_with("00") {
                colliding.push(member(&format!("same/deep/{name}")));
                if colliding.len() == 70 {
                    break;
                }
            }
        }
        assert_eq!(colliding.len(), 70);
        let source = legacy_inventory(&store, colliding.clone()).await;
        let mut memo = MigrationInventory::new();
        let mut canonical = compare(&store, &source, &mut memo).await;
        for m in colliding.iter().take(10) {
            canonical = update(&store, &canonical, &m.path, None)
                .await
                .expect("delete");
        }
        let rebuilt = compare(&store, &canonical, &mut memo).await;
        assert_ne!(
            canonical, rebuilt,
            "deletion left old radix partitions in place"
        );
        assert_eq!(
            members(&store, &rebuilt, 100).await.expect("members").len(),
            60
        );
    }
    #[tokio::test]
    async fn absolute_ambiguity_rename_and_noninjective_fallback_preserve_order() {
        let store = Memory::default();
        let source = legacy_inventory(
            &store,
            vec![member("en-us/docs/a"), member("other/b"), member("z")],
        )
        .await;
        let rewrite = |mut m: Member| {
            m.path = format!("@ambiguities/{}/{}", m.oid, m.path);
            m.projection = Some(format!("blake3:{}", m.projection.expect("projection")));
            Ok(m)
        };
        let expected = rebuild_inventory(&store, &source, rewrite)
            .await
            .expect("reference rename");
        let result = rebuild_inventory_memoized(
            &store,
            &source,
            rewrite,
            &mut MigrationInventory::new(),
            &CancellationToken::new(),
        )
        .await
        .expect("memo rename");
        assert_eq!(result, expected);
        let collide = |mut m: Member| {
            m.oid = m.path.clone();
            m.path = "same/destination".into();
            Ok(m)
        };
        let expected = rebuild_inventory(&store, &source, collide)
            .await
            .expect("reference collision");
        let mut memo = MigrationInventory::new();
        let result = rebuild_inventory_memoized(
            &store,
            &source,
            collide,
            &mut memo,
            &CancellationToken::new(),
        )
        .await
        .expect("collision fallback");
        assert_eq!(result, expected);
        assert_eq!(
            get(&store, &result, "same/destination")
                .await
                .expect("last winner")
                .expect("member")
                .oid,
            "z"
        );
        assert_eq!(
            rebuild_inventory_memoized(
                &store,
                &source,
                collide,
                &mut memo,
                &CancellationToken::new()
            )
            .await
            .expect("memoized fallback"),
            expected
        );
    }
    #[tokio::test]
    async fn shared_root_reuse_reads_no_old_nodes_and_does_not_publish_aliases() {
        let store = Memory::default();
        let source = legacy_inventory(
            &store,
            (0..100)
                .map(|n| member(&format!("shared/deep/{n:03}")))
                .collect(),
        )
        .await;
        let mut memo = MigrationInventory::new();
        let first = compare(&store, &source, &mut memo).await;
        let reads = store.reads.load(Ordering::Relaxed);
        let rows = store.rows.lock().expect("rows").len();
        let second =
            rebuild_inventory_memoized(&store, &source, Ok, &mut memo, &CancellationToken::new())
                .await
                .expect("repeat");
        assert_eq!(first, second);
        assert_eq!(store.reads.load(Ordering::Relaxed), reads);
        assert_eq!(store.rows.lock().expect("rows").len(), rows);
        assert!(
            memo.records.len() > 100,
            "private reusable fragments and unions"
        );
        assert!(memo.records.accounted_bytes() < 16 * 1024 * 1024);
    }
    #[tokio::test]
    async fn expanded_bounds_include_repeated_memoized_source_occurrences() {
        let store = Memory::default();
        let mut m = member("leaf");
        m.raw = Some(serde_json::json!({"retained": "x".repeat(2048)}));
        let mut source = legacy_inventory(&store, vec![m]).await;
        let mut memo = MigrationInventory::new();
        for level in 0..3 {
            let mut node = InventoryNode::default();
            for n in 0..64 {
                node.children.insert(format!("edge-{n:02}"), source.clone());
            }
            source = legacy_put(&store, &node).await;
            let result = rebuild_inventory_memoized(
                &store,
                &source,
                Ok,
                &mut memo,
                &CancellationToken::new(),
            )
            .await;
            if level < 2 {
                result.expect("bounded expanded inventory");
            } else {
                assert_eq!(result.expect_err("expanded byte bound").code, "capacity");
            }
        }
        assert!(
            Summary {
                nodes: 4_000_001,
                ..Summary::default()
            }
            .check()
            .is_err()
        );
        assert!(
            Summary {
                members: 1_000_001,
                ..Summary::default()
            }
            .check()
            .is_err()
        );
    }
    #[tokio::test]
    async fn failed_node_commit_never_publishes_memo_and_retry_is_exact() {
        let store = Memory::default();
        let source = legacy_inventory(&store, vec![member("a/b/c")]).await;
        let mut memo = MigrationInventory::new();
        store.fail_batch.store(true, Ordering::Relaxed);
        let error =
            rebuild_inventory_memoized(&store, &source, Ok, &mut memo, &CancellationToken::new())
                .await
                .expect_err("failed commit");
        assert_eq!(error.code, "unavailable");
        assert!(memo.records.is_empty());
        compare(&store, &source, &mut memo).await;
    }
    #[tokio::test]
    async fn oversized_union_and_metadata_shapes_use_exact_reference_fallback() {
        let store = Memory::default();
        let mut large = member("branch");
        large.raw = Some(serde_json::json!({"retained": "x".repeat(7 * 1024 * 1024)}));
        let source = legacy_inventory(&store, vec![large, member("branch/child")]).await;
        let mut memo = MigrationInventory::new();
        compare(&store, &source, &mut memo).await;
        let key = format!("inventory-v1:source:{}", digest(source.as_bytes()));
        let retained: Proof<Converted> =
            serde_json::from_str(&memo.records.get(&key).expect("source memo"))
                .expect("source proof");
        assert!(matches!(
            retained.result.fallback,
            Some(UnsupportedReason::ResidentUnionShape)
        ));
        let mut unusual = member("unusual-kind");
        unusual.kind = "k".repeat(8192);
        let source = legacy_inventory(&store, vec![unusual]).await;
        compare(&store, &source, &mut MigrationInventory::new()).await;
    }
    #[tokio::test]
    async fn iterative_source_walk_handles_deep_chains_and_rejects_malformed_depth() {
        let store = Memory::default();
        let mut source = legacy_inventory(&store, vec![member("leaf")]).await;
        for _ in 0..2048 {
            source = legacy_put(
                &store,
                &InventoryNode {
                    children: BTreeMap::from([("redundant".into(), source)]),
                    ..InventoryNode::default()
                },
            )
            .await;
        }
        compare(&store, &source, &mut MigrationInventory::new()).await;
        for _ in 0..2200 {
            source = legacy_put(
                &store,
                &InventoryNode {
                    children: BTreeMap::from([("redundant".into(), source)]),
                    ..InventoryNode::default()
                },
            )
            .await;
        }
        assert_eq!(
            rebuild_inventory_memoized(
                &store,
                &source,
                Ok,
                &mut MigrationInventory::new(),
                &CancellationToken::new()
            )
            .await
            .expect_err("malformed physical depth")
            .code,
            "capacity"
        );
    }
    #[tokio::test]
    async fn forward_summary_admission_precedes_uncached_sibling_rewrite() {
        let store = Memory::default();
        let first = legacy_inventory(&store, vec![member("first")]).await;
        let next = legacy_inventory(&store, vec![member("must-not-rewrite")]).await;
        let source = legacy_put(
            &store,
            &InventoryNode {
                children: BTreeMap::from([("a".into(), first.clone()), ("z".into(), next)]),
                ..InventoryNode::default()
            },
        )
        .await;
        let mut memo = MigrationInventory::new();
        let cached = Converted {
            fragment: None,
            fallback: None,
            summary: Summary {
                nodes: 4_000_000,
                members: 0,
                bytes: 0,
            },
        };
        let operand = first;
        let key = format!("inventory-v1:source:{}", digest(operand.as_bytes()));
        let proof = serde_json::to_string(&Proof {
            operand,
            result: cached,
        })
        .expect("proof");
        crate::migration_map::insert(&mut memo.records, key, proof).expect("private fixture memo");
        let mut rewrites = 0;
        let error = rebuild_inventory_memoized(
            &store,
            &source,
            |m| {
                rewrites += 1;
                Ok(m)
            },
            &mut memo,
            &CancellationToken::new(),
        )
        .await
        .expect_err("forward node bound");
        assert_eq!(error.code, "capacity");
        assert_eq!(rewrites, 0, "reject before uncached sibling processing");
    }
    #[tokio::test]
    async fn corrupt_missing_and_canceled_sources_fail_closed() {
        let store = Memory::default();
        let source = legacy_inventory(&store, vec![member("a")]).await;
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            rebuild_inventory_memoized(
                &store,
                &source,
                Ok,
                &mut MigrationInventory::new(),
                &cancel
            )
            .await
            .expect_err("canceled")
            .code,
            "cancelled"
        );
        let missing = legacy_put(
            &store,
            &InventoryNode {
                children: BTreeMap::from([("missing".into(), "0".repeat(64))]),
                ..InventoryNode::default()
            },
        )
        .await;
        assert_eq!(
            rebuild_inventory_memoized(
                &store,
                &missing,
                Ok,
                &mut MigrationInventory::new(),
                &CancellationToken::new()
            )
            .await
            .expect_err("missing")
            .code,
            "integrity"
        );
        let corrupt = "f".repeat(64);
        store
            .mdn_put(
                "nodes",
                &corrupt,
                &value(&InventoryNode::default()).expect("value"),
            )
            .await
            .expect("corrupt row");
        assert_eq!(
            rebuild_inventory_memoized(
                &store,
                &corrupt,
                Ok,
                &mut MigrationInventory::new(),
                &CancellationToken::new()
            )
            .await
            .expect_err("corrupt")
            .code,
            "integrity"
        );
    }
}
