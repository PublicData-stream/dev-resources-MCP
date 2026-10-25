//! A private, per-source-member overlay. Success here can mean queued evidence;
//! the owning entry must flush before publishing its root or checkpoint.
use async_trait::async_trait;
use devres_application::mdn::{
    MDN_WRITE_BATCH_BYTES, MDN_WRITE_BATCH_ROWS, MdnRow, MdnStore, MdnWrite, View,
    validate_mdn_writes,
};
use devres_domain::{Error, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use tokio::sync::Mutex;

const QUEUE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
struct Pending {
    rows: Vec<MdnWrite>,
    positions: BTreeMap<(String, String), usize>,
    bytes: usize,
    failed: bool,
}

pub(super) struct BufferedMdnStore<'a> {
    base: &'a dyn MdnStore,
    pending: Mutex<Pending>,
}

fn unsupported() -> Error {
    Error::unavailable("MDN entry buffer cannot access publication or private state.")
}
fn checked(kind: &str, key: &str) -> Result<()> {
    if !matches!(
        kind,
        "nodes" | "projections" | "projection-headers" | "index-documents"
    ) || key.is_empty()
        || key.len() > 4096
        || key.chars().any(char::is_control)
    {
        return Err(Error::invalid("Invalid MDN entry evidence key."));
    }
    Ok(())
}
fn measured<T: serde::Serialize>(value: &T, limit: usize) -> Result<usize> {
    use std::io::{self, Write};
    struct Counter {
        bytes: usize,
        limit: usize,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|n| *n <= self.limit)
                .ok_or_else(|| io::Error::other("MDN evidence byte budget"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { bytes: 0, limit };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| Error::capacity("MDN immutable write batch exceeds its byte bound."))?;
    Ok(counter.bytes)
}
impl<'a> BufferedMdnStore<'a> {
    pub(super) fn new(base: &'a dyn MdnStore) -> Self {
        Self {
            base,
            pending: Mutex::new(Pending::default()),
        }
    }
    async fn flush_locked(&self, pending: &mut Pending) -> Result<()> {
        if pending.failed {
            return Err(unsupported());
        }
        if !pending.rows.is_empty() {
            if let Err(error) = self.base.mdn_put_many(&pending.rows).await {
                pending.failed = true;
                return Err(error);
            }
            pending.rows.clear();
            pending.positions.clear();
            pending.bytes = 0;
        }
        Ok(())
    }
    pub(super) async fn flush(&self) -> Result<()> {
        self.flush_locked(&mut *self.pending.lock().await).await
    }
    async fn append(&self, rows: &[MdnWrite]) -> Result<()> {
        // Validate the complete incoming group before queuing any of its rows.
        validate_mdn_writes(rows)?;
        for row in rows {
            checked(&row.kind, &row.key)?;
        }
        let mut pending = self.pending.lock().await;
        if pending.failed {
            return Err(unsupported());
        }
        for row in rows {
            let key = (row.kind.clone(), row.key.clone());
            if let Some(index) = pending.positions.get(&key) {
                if pending.rows[*index].data != row.data {
                    return Err(Error::integrity(
                        "MDN immutable evidence identity collision.",
                    ));
                }
                continue;
            }
            let bytes = measured(row, MDN_WRITE_BATCH_BYTES)?;
            if bytes > QUEUE_BYTES {
                // Large, otherwise valid evidence retains its existing admission
                // limit, without ever entering the smaller private queue.
                self.flush_locked(&mut pending).await?;
                if let Err(error) = self.base.mdn_put_many(std::slice::from_ref(row)).await {
                    pending.failed = true;
                    return Err(error);
                }
                continue;
            }
            if pending.rows.len() >= MDN_WRITE_BATCH_ROWS || pending.bytes + bytes > QUEUE_BYTES {
                self.flush_locked(&mut pending).await?;
            }
            let index = pending.rows.len();
            pending.bytes += bytes;
            pending.positions.insert(key, index);
            pending.rows.push(row.clone());
        }
        Ok(())
    }
}
#[async_trait]
impl MdnStore for BufferedMdnStore<'_> {
    async fn mdn_cutoff(&self) -> Result<i64> {
        Err(unsupported())
    }
    async fn mdn_get(&self, kind: &str, key: &str) -> Result<Option<MdnRow>> {
        checked(kind, key)?;
        let pending = self.pending.lock().await;
        if pending.failed {
            return Err(unsupported());
        }
        if let Some(index) = pending.positions.get(&(kind.to_owned(), key.to_owned())) {
            return Ok(Some(MdnRow {
                sequence: 0,
                key: key.to_owned(),
                data: pending.rows[*index].data.clone(),
            }));
        }
        drop(pending);
        self.base.mdn_get(kind, key).await
    }
    async fn mdn_get_many(&self, kind: &str, keys: &[String]) -> Result<Vec<MdnRow>> {
        checked(kind, "batch")?;
        if keys.len() > 1000 {
            return Err(Error::capacity("MDN batch read exceeds its bound."));
        }
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        for key in keys {
            if let Some(row) = self.mdn_get(kind, key).await? {
                bytes = bytes.saturating_add(measured(&row.data, 64 * 1024 * 1024)?);
                if bytes > 64 * 1024 * 1024 {
                    return Err(Error::capacity("MDN batch read memory bound exceeded."));
                }
                rows.push(row);
            }
        }
        Ok(rows)
    }
    async fn mdn_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
        self.append(&[MdnWrite {
            kind: kind.to_owned(),
            key: key.to_owned(),
            data: data.clone(),
        }])
        .await?;
        Ok(0)
    }
    async fn mdn_put_many(&self, rows: &[MdnWrite]) -> Result<()> {
        self.append(rows).await
    }
    async fn mdn_rows(&self, _: &str, _: i64, _: usize, _: Option<i64>) -> Result<Vec<MdnRow>> {
        Err(unsupported())
    }
    async fn mdn_state(&self, _: &str) -> Result<Option<Value>> {
        Err(unsupported())
    }
    async fn mdn_set_state(&self, _: &str, _: &Value) -> Result<()> {
        Err(unsupported())
    }
    async fn mdn_publish_view(&self, _: &View) -> Result<()> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bulk::{BulkBroker, BulkConfig},
        mdn_inventory as inventory,
    };
    use devres_application::mdn::{MdnConfig, Member};
    use serde_json::json;
    use std::sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio_util::sync::CancellationToken;

    #[derive(Default)]
    struct Memory {
        rows: StdMutex<BTreeMap<(String, String), MdnRow>>,
        batches: StdMutex<Vec<Vec<MdnWrite>>>,
        calls: AtomicUsize,
        fail_at: AtomicUsize,
    }
    #[async_trait]
    impl MdnStore for Memory {
        async fn mdn_cutoff(&self) -> Result<i64> {
            Ok(self.rows.lock().unwrap().len() as i64)
        }
        async fn mdn_get(&self, kind: &str, key: &str) -> Result<Option<MdnRow>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .get(&(kind.to_owned(), key.to_owned()))
                .cloned())
        }
        async fn mdn_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
            self.mdn_put_many(&[MdnWrite {
                kind: kind.into(),
                key: key.into(),
                data: data.clone(),
            }])
            .await?;
            Ok(self.mdn_get(kind, key).await?.unwrap().sequence)
        }
        async fn mdn_put_many(&self, writes: &[MdnWrite]) -> Result<()> {
            validate_mdn_writes(writes)?;
            let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            if self.fail_at.load(Ordering::Relaxed) == call {
                return Err(Error::unavailable("Synthetic durable flush failure."));
            }
            let mut rows = self.rows.lock().unwrap();
            for write in writes {
                if let Some(old) = rows.get(&(write.kind.clone(), write.key.clone()))
                    && old.data != write.data
                {
                    return Err(Error::integrity("Synthetic immutable collision."));
                }
            }
            for write in writes {
                let sequence = rows.len() as i64 + 1;
                rows.entry((write.kind.clone(), write.key.clone()))
                    .or_insert(MdnRow {
                        sequence,
                        key: write.key.clone(),
                        data: write.data.clone(),
                    });
            }
            self.batches.lock().unwrap().push(writes.to_vec());
            Ok(())
        }
        async fn mdn_rows(&self, _: &str, _: i64, _: usize, _: Option<i64>) -> Result<Vec<MdnRow>> {
            Err(unsupported())
        }
        async fn mdn_state(&self, _: &str) -> Result<Option<Value>> {
            Err(unsupported())
        }
        async fn mdn_set_state(&self, _: &str, _: &Value) -> Result<()> {
            Err(unsupported())
        }
        async fn mdn_publish_view(&self, _: &View) -> Result<()> {
            Err(unsupported())
        }
    }
    fn row(n: usize) -> MdnWrite {
        MdnWrite {
            kind: "projections".into(),
            key: format!("row-{n:04}"),
            data: json!({"n":n}),
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
    async fn queue_count_overlay_collision_and_restricted_ports() {
        let base = Memory::default();
        let buffer = BufferedMdnStore::new(&base);
        for n in 0..1001 {
            buffer.mdn_put_many(&[row(n)]).await.unwrap();
        }
        assert_eq!(base.calls.load(Ordering::Relaxed), 1);
        assert_eq!(base.rows.lock().unwrap().len(), 1000);
        assert_eq!(
            buffer
                .mdn_get("projections", "row-1000")
                .await
                .unwrap()
                .unwrap()
                .sequence,
            0
        );
        assert!(
            buffer
                .mdn_get("projections", "row-0000")
                .await
                .unwrap()
                .unwrap()
                .sequence
                > 0
        );
        assert_eq!(buffer.pending.lock().await.rows.len(), 1);
        buffer.mdn_put_many(&[row(1000)]).await.unwrap();
        let mut collision = row(1000);
        collision.data = json!({"changed":true});
        assert_eq!(
            buffer.mdn_put_many(&[collision]).await.unwrap_err().code,
            "integrity"
        );
        assert_eq!(
            buffer
                .mdn_get("projections", "row-1000")
                .await
                .unwrap()
                .unwrap()
                .data,
            row(1000).data
        );
        assert!(buffer.mdn_get("snapshots", "forbidden").await.is_err());
        assert!(
            buffer
                .mdn_put("snapshots", "forbidden", &Value::Null)
                .await
                .is_err()
        );
        let mixed = buffer
            .mdn_get_many("projections", &["row-0000".into(), "row-1000".into()])
            .await
            .unwrap();
        assert!(mixed[0].sequence > 0);
        assert_eq!(mixed[1].sequence, 0);
        assert!(buffer.mdn_get_many("snapshots", &[]).await.is_err());
        let view = View {
            id: "a".repeat(64),
            content: "b".repeat(64),
            compatibility: "c".repeat(64),
            content_observation: "d".into(),
            compatibility_observation: "e".into(),
            validated_at: 1,
        };
        assert!(buffer.mdn_publish_view(&view).await.is_err());
        assert!(buffer.mdn_cutoff().await.is_err());
        assert!(buffer.mdn_rows("nodes", 0, 1, None).await.is_err());
        assert!(buffer.mdn_state("default").await.is_err());
        assert!(buffer.mdn_set_state("default", &Value::Null).await.is_err());
        buffer.flush().await.unwrap();
        assert_eq!(base.rows.lock().unwrap().len(), 1001);
        assert!(buffer.pending.lock().await.rows.is_empty());
        let order: Vec<_> = base
            .batches
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .map(|r| r.key.clone())
            .collect();
        assert_eq!(order, (0..1001).map(|n| row(n).key).collect::<Vec<_>>());
    }
    #[tokio::test]
    async fn byte_threshold_and_large_row_passthrough_preserve_order_and_admission() {
        let base = Memory::default();
        let buffer = BufferedMdnStore::new(&base);
        for (key, bytes) in [
            ("first", 5 * 1024 * 1024),
            ("second", 4 * 1024 * 1024),
            ("large", 9 * 1024 * 1024),
        ] {
            buffer
                .mdn_put("projections", key, &json!({"body":"x".repeat(bytes)}))
                .await
                .unwrap();
            assert!(buffer.pending.lock().await.bytes <= QUEUE_BYTES);
        }
        assert!(buffer.pending.lock().await.rows.is_empty());
        let order: Vec<_> = base
            .batches
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .map(|r| r.key.clone())
            .collect();
        assert_eq!(order, ["first", "second", "large"]);
        assert_eq!(base.calls.load(Ordering::Relaxed), 3);
        assert!(
            buffer
                .mdn_put(
                    "projections",
                    "too-large",
                    &json!("x".repeat(MDN_WRITE_BATCH_BYTES))
                )
                .await
                .is_err()
        );
        assert_eq!(
            base.calls.load(Ordering::Relaxed),
            3,
            "invalid row never reaches storage"
        );
    }
    #[tokio::test]
    async fn failed_final_flush_retains_overlay_and_new_buffer_replays() {
        let base = Memory::default();
        let buffer = BufferedMdnStore::new(&base);
        for n in 0..1001 {
            buffer.mdn_put_many(&[row(n)]).await.unwrap();
        }
        base.fail_at.store(2, Ordering::Relaxed);
        assert!(buffer.flush().await.is_err());
        let pending = buffer.pending.lock().await;
        assert_eq!(pending.rows.len(), 1);
        assert_eq!(pending.positions.len(), 1);
        assert!(pending.failed);
        drop(pending);
        assert!(
            buffer.flush().await.is_err(),
            "a failed entry cannot silently become successful"
        );
        drop(buffer);
        let replay = BufferedMdnStore::new(&base);
        for n in 0..1001 {
            replay.mdn_put_many(&[row(n)]).await.unwrap();
        }
        replay.flush().await.unwrap();
        assert_eq!(base.rows.lock().unwrap().len(), 1001);
    }
    #[tokio::test]
    async fn deferred_inventory_preserves_golden_root_without_premature_cache_admission() {
        let base = Memory::default();
        let initial = inventory::empty(&base).await.unwrap();
        let mut cache = inventory::NodeCache::new();
        cache.defer_writes();
        let buffer = BufferedMdnStore::new(&base);
        let root = inventory::update_cached(
            &buffer,
            &initial,
            "a/b/c",
            Some(member("a/b/c")),
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(
            root,
            "59cc157dfa306cdebe2c26b81c8f786ce50dc412dbf66dff817e6f799c2fff27"
        );
        assert_eq!(
            inventory::get_cached(&buffer, &root, "a/b/c", &mut cache)
                .await
                .unwrap(),
            Some(member("a/b/c"))
        );
        assert!(base.mdn_get("nodes", &root).await.unwrap().is_none());
        drop(buffer);
        assert_eq!(
            inventory::get_cached(&base, &root, "a/b/c", &mut cache)
                .await
                .unwrap_err()
                .code,
            "integrity",
            "neither queued writes nor sequence-zero overlay reads enter durable node cache"
        );
        let buffer = BufferedMdnStore::new(&base);
        let replay = inventory::update_cached(
            &buffer,
            &initial,
            "a/b/c",
            Some(member("a/b/c")),
            &mut cache,
        )
        .await
        .unwrap();
        buffer.flush().await.unwrap();
        assert_eq!(root, replay);
        assert_eq!(
            inventory::get_cached(&base, &root, "a/b/c", &mut cache)
                .await
                .unwrap(),
            Some(member("a/b/c"))
        );
    }
    fn corpus(base: Arc<Memory>, root: &std::path::Path) -> super::super::MdnCorpus {
        super::super::MdnCorpus::new(
            base,
            Arc::new(BulkBroker::new(BulkConfig::default()).unwrap()),
            root,
            MdnConfig {
                enabled: false,
                min_free_bytes: 64 * 1024 * 1024,
                ..MdnConfig::default()
            },
        )
        .unwrap()
    }
    #[tokio::test]
    async fn entry_final_flush_failure_preserves_caller_root_for_addition_and_deletion() {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        let root = tempfile::tempdir().unwrap();
        let base = Arc::new(Memory::default());
        let corpus = corpus(base.clone(), root.path());
        let initial = inventory::empty(base.as_ref()).await.unwrap();
        let mut published = initial.clone();
        let mut cache = inventory::NodeCache::new();
        let entry = super::super::TreeEntry {
            path: "a/b/c".into(),
            oid: "a".repeat(40),
            mode: "160000".into(),
            kind: "commit".into(),
            removed: false,
            raw_path_hex: None,
        };
        base.fail_at
            .store(base.calls.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        assert!(
            corpus
                .apply_entry(
                    &mut cache,
                    super::super::Repo::Content,
                    &"b".repeat(40),
                    &mut published,
                    entry.clone(),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
        assert_eq!(published, initial);
        corpus
            .apply_entry(
                &mut cache,
                super::super::Repo::Content,
                &"b".repeat(40),
                &mut published,
                entry.clone(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_ne!(published, initial);
        let added = published.clone();
        let deletion = super::super::TreeEntry {
            removed: true,
            ..entry
        };
        base.fail_at
            .store(base.calls.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        assert!(
            corpus
                .apply_entry(
                    &mut cache,
                    super::super::Repo::Content,
                    &"b".repeat(40),
                    &mut published,
                    deletion.clone(),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
        assert_eq!(
            published, added,
            "deletion early return waits for durable flush"
        );
        corpus
            .apply_entry(
                &mut cache,
                super::super::Repo::Content,
                &"b".repeat(40),
                &mut published,
                deletion,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(published, initial);
    }
    #[tokio::test]
    async fn large_bcd_entry_mid_flush_failure_replays_without_publishing_partial_root() {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        let root = tempfile::tempdir().unwrap();
        let base = Arc::new(Memory::default());
        let corpus = corpus(base.clone(), root.path());
        crate::mdn_git::tests::fixture_init(&corpus.compat).await;
        let mut features = serde_json::Map::new();
        for n in 0..500 {
            features.insert(
                format!("feature_{n:03}"),
                json!({"__compat":{"support":{"chrome":{"version_added":"1"}}}}),
            );
        }
        let body = serde_json::to_vec(&json!({"api":{"Demo":features}})).unwrap();
        let revision =
            crate::mdn_git::tests::commit_files(&corpus.compat, &[("api/demo.json", &body)], &[])
                .await;
        let entry = corpus
            .compat
            .entry(&revision, "api/demo.json", CancellationToken::new())
            .await
            .unwrap()
            .unwrap();
        let initial = inventory::empty(base.as_ref()).await.unwrap();
        let mut published = initial.clone();
        let mut cache = inventory::NodeCache::new();
        base.fail_at
            .store(base.calls.load(Ordering::Relaxed) + 2, Ordering::Relaxed);
        assert!(
            corpus
                .apply_entry(
                    &mut cache,
                    super::super::Repo::Compat,
                    &revision,
                    &mut published,
                    entry.clone(),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
        assert_eq!(published, initial);
        assert!(
            base.rows.lock().unwrap().len() > 1,
            "earlier flushed evidence may remain unreferenced"
        );
        let before = base.calls.load(Ordering::Relaxed);
        corpus
            .apply_entry(
                &mut cache,
                super::super::Repo::Compat,
                &revision,
                &mut published,
                entry.clone(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(
            base.calls.load(Ordering::Relaxed) - before <= 20,
            "hundreds of features share bounded durable batches"
        );
        assert_eq!(
            inventory::node(base.as_ref(), &published)
                .await
                .unwrap()
                .members,
            501
        );
        let once = published.clone();
        let mut replay = initial;
        corpus
            .apply_entry(
                &mut cache,
                super::super::Repo::Compat,
                &revision,
                &mut replay,
                entry,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            replay, once,
            "replay preserves all content-addressed identities"
        );
    }
}
