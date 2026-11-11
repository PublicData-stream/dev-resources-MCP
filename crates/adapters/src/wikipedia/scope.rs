//! Read-only reachability of the currently observed category membership graph.
//! Historical captures never depend on this automatic-acquisition scope check.
use devres_application::wikipedia::{WikipediaConfig, WikipediaStore};
use devres_domain::{Error, Result};
use std::{
    collections::{BTreeSet, VecDeque},
    future::Future,
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const MAX_CATEGORIES: usize = 1000;
const PAGE: usize = 100;

fn capacity() -> Error {
    Error::capacity("Wikipedia category reachability exceeds its processing bound.")
}
fn malformed() -> Error {
    Error::integrity("Invalid retained Wikipedia category membership.")
}
fn check(cancel: &CancellationToken, deadline: Instant) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "Wikipedia scope lookup canceled."));
    }
    if Instant::now() >= deadline {
        return Err(capacity());
    }
    Ok(())
}
async fn bounded<T>(
    cancel: &CancellationToken,
    deadline: Instant,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    check(cancel, deadline)?;
    tokio::select! {
        biased;
        _=cancel.cancelled()=>Err(Error::new("cancelled","Wikipedia scope lookup canceled.")),
        result=tokio::time::timeout_at(deadline,future)=>result.map_err(|_|capacity())?,
    }
}
struct Traversal<'a> {
    store: &'a dyn WikipediaStore,
    config: &'a WikipediaConfig,
    cancel: &'a CancellationToken,
    deadline: Instant,
    seen: BTreeSet<String>,
    queue: VecDeque<String>,
}
impl<'a> Traversal<'a> {
    fn new(
        store: &'a dyn WikipediaStore,
        config: &'a WikipediaConfig,
        cancel: &'a CancellationToken,
    ) -> Self {
        Self {
            store,
            config,
            cancel,
            deadline: Instant::now() + Duration::from_secs(15),
            seen: BTreeSet::new(),
            queue: VecDeque::new(),
        }
    }
    /// Return true only for a permitted configured root; enqueue new ancestors.
    fn enqueue(&mut self, title: &str) -> Result<bool> {
        check(self.cancel, self.deadline)?;
        if !title.starts_with("Category:")
            || title.len() <= 9
            || super::source::validate_title(title).is_err()
        {
            return Err(malformed());
        }
        if self
            .config
            .excluded_categories
            .iter()
            .any(|excluded| excluded == title)
        {
            return Ok(false);
        }
        if self.seen.insert(title.to_owned()) {
            if self.seen.len() > MAX_CATEGORIES {
                return Err(capacity());
            }
            if self.config.category_roots.iter().any(|root| root == title) {
                return Ok(true);
            }
            self.queue.push_back(title.to_owned());
        }
        Ok(false)
    }
    /// Stream a complete reverse-edge page sequence without trusting inherited roots.
    async fn parents(&mut self, prefix: &str) -> Result<bool> {
        let mut after = String::new();
        loop {
            let rows = bounded(
                self.cancel,
                self.deadline,
                self.store.wiki_states(prefix, &after, PAGE),
            )
            .await?;
            if rows.len() > PAGE {
                return Err(malformed());
            }
            let more = rows.len() == PAGE;
            for row in rows {
                check(self.cancel, self.deadline)?;
                if !row.key.starts_with(prefix) || row.key <= after {
                    return Err(malformed());
                }
                after = row.key;
                if row.data["active"] == true {
                    let parent = row.data["category"].as_str().ok_or_else(malformed)?;
                    if self.enqueue(parent)? {
                        return Ok(true);
                    }
                }
            }
            if !more {
                return Ok(false);
            }
        }
    }
    async fn walk(&mut self) -> Result<bool> {
        while let Some(title) = self.queue.pop_front() {
            check(self.cancel, self.deadline)?;
            let prefix = format!(
                "membership-category:{}:",
                crate::integrity::hash(title.as_bytes())
            );
            if self.parents(&prefix).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub(crate) async fn category_reachable(
    store: &dyn WikipediaStore,
    config: &WikipediaConfig,
    title: &str,
    cancel: &CancellationToken,
) -> Result<bool> {
    let mut traversal = Traversal::new(store, config, cancel);
    if traversal.enqueue(title)? {
        return Ok(true);
    }
    traversal.walk().await
}

pub(crate) async fn article_reachable(
    store: &dyn WikipediaStore,
    config: &WikipediaConfig,
    page_id: u64,
    cancel: &CancellationToken,
) -> Result<bool> {
    if page_id == 0 {
        return Err(Error::invalid("Invalid Wikipedia article identity."));
    }
    let mut traversal = Traversal::new(store, config, cancel);
    let demand = bounded(
        cancel,
        traversal.deadline,
        store.wiki_state(&format!("tracked-demand:{page_id}")),
    )
    .await?;
    if demand == Some(serde_json::Value::Bool(true)) {
        return Ok(true);
    }
    if traversal
        .parents(&format!("membership-page:{page_id}:"))
        .await?
    {
        return Ok(true);
    }
    traversal.walk().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use devres_application::wikipedia::{Row, State, Write};
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct Store {
        states: Mutex<BTreeMap<String, State>>,
        reads: AtomicUsize,
        fail: bool,
        stall: bool,
    }
    impl Store {
        async fn category(&self, child: &str, parent: &str, active: bool) {
            self.put(
                format!(
                    "membership-category:{}:{}",
                    crate::integrity::hash(child.as_bytes()),
                    crate::integrity::hash(parent.as_bytes())
                ),
                json!({"category":parent,"active":active}),
            )
            .await;
        }
        async fn article(&self, page: u64, parent: &str, active: bool) {
            self.put(
                format!(
                    "membership-page:{page}:{}",
                    crate::integrity::hash(parent.as_bytes())
                ),
                json!({"category":parent,"active":active}),
            )
            .await;
        }
        async fn put(&self, key: String, data: Value) {
            self.states.lock().await.insert(
                key.clone(),
                State {
                    key,
                    data,
                    due_at: None,
                },
            );
        }
    }
    #[async_trait]
    impl WikipediaStore for Store {
        async fn wiki_state(&self, key: &str) -> Result<Option<Value>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.stall {
                std::future::pending::<()>().await;
            }
            if self.fail {
                return Err(Error::unavailable("Fixture store unavailable."));
            }
            Ok(self
                .states
                .lock()
                .await
                .get(key)
                .map(|row| row.data.clone()))
        }
        async fn wiki_states(&self, prefix: &str, after: &str, limit: usize) -> Result<Vec<State>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.stall {
                std::future::pending::<()>().await;
            }
            if self.fail {
                return Err(Error::unavailable("Fixture store unavailable."));
            }
            Ok(self
                .states
                .lock()
                .await
                .values()
                .filter(|row| row.key.starts_with(prefix) && row.key.as_str() > after)
                .take(limit)
                .cloned()
                .collect())
        }
        async fn wiki_get(&self, _: &str, _: &str) -> Result<Option<Row>> {
            Err(Error::integrity("Unexpected fixture read."))
        }
        async fn wiki_rows(&self, _: &str, _: i64, _: usize, _: Option<i64>) -> Result<Vec<Row>> {
            Err(Error::integrity("Unexpected fixture read."))
        }
        async fn wiki_cutoff(&self) -> Result<i64> {
            Err(Error::integrity("Unexpected fixture read."))
        }
        async fn wiki_catalog(&self, _: u64, _: usize, _: i64) -> Result<Vec<Row>> {
            Err(Error::integrity("Unexpected fixture read."))
        }
        async fn wiki_page_captures(&self, _: u64, _: i64, _: usize, _: i64) -> Result<Vec<Row>> {
            Err(Error::integrity("Unexpected fixture read."))
        }
        async fn wiki_due(&self, _: &str, _: i64, _: usize) -> Result<Vec<State>> {
            Err(Error::integrity("Unexpected fixture read."))
        }
        async fn wiki_commit(&self, _: &[Write], _: &[State]) -> Result<()> {
            Err(Error::integrity("Scope lookup must not write."))
        }
    }
    fn config() -> WikipediaConfig {
        WikipediaConfig {
            category_roots: vec!["Category:Science".into()],
            ..Default::default()
        }
    }
    #[tokio::test]
    async fn cycles_and_multiple_parents_resolve_only_actual_active_paths() {
        let store = Store::default();
        let config = config();
        let cancel = CancellationToken::new();
        store
            .category("Category:Leaf", "Category:Cycle", true)
            .await;
        store
            .category("Category:Cycle", "Category:Leaf", true)
            .await;
        assert!(
            !category_reachable(&store, &config, "Category:Leaf", &cancel)
                .await
                .unwrap()
        );
        store
            .category("Category:Leaf", "Category:Science", true)
            .await;
        assert!(
            category_reachable(&store, &config, "Category:Leaf", &cancel)
                .await
                .unwrap()
        );
        store
            .category("Category:Leaf", "Category:Science", false)
            .await;
        assert!(
            !category_reachable(&store, &config, "Category:Leaf", &cancel)
                .await
                .unwrap()
        );
    }
    #[tokio::test]
    async fn exclusions_block_roots_and_intermediate_paths_but_demand_is_explicit() {
        let store = Store::default();
        let mut config = config();
        let cancel = CancellationToken::new();
        store
            .category("Category:Leaf", "Category:Middle", true)
            .await;
        store
            .category("Category:Middle", "Category:Science", true)
            .await;
        store.article(7, "Category:Leaf", true).await;
        assert!(
            article_reachable(&store, &config, 7, &cancel)
                .await
                .unwrap()
        );
        config.excluded_categories = vec!["Category:Middle".into()];
        assert!(
            !article_reachable(&store, &config, 7, &cancel)
                .await
                .unwrap()
        );
        config.excluded_categories = vec!["Category:Science".into()];
        assert!(
            !category_reachable(&store, &config, "Category:Science", &cancel)
                .await
                .unwrap()
        );
        assert!(
            !article_reachable(&store, &config, 7, &cancel)
                .await
                .unwrap()
        );
        store.put("tracked-demand:7".into(), json!(true)).await;
        assert!(
            article_reachable(&store, &config, 7, &cancel)
                .await
                .unwrap()
        );
    }
    #[tokio::test]
    async fn article_memberships_are_paged_and_removed_edges_do_not_prove_scope() {
        let store = Store::default();
        let config = config();
        let cancel = CancellationToken::new();
        for index in 0..105 {
            store
                .article(9, &format!("Category:Detached {index}"), false)
                .await;
        }
        store.article(9, "Category:Science", true).await;
        assert!(
            article_reachable(&store, &config, 9, &cancel)
                .await
                .unwrap()
        );
        store.article(9, "Category:Science", false).await;
        assert!(
            !article_reachable(&store, &config, 9, &cancel)
                .await
                .unwrap()
        );
        assert!(store.reads.load(Ordering::SeqCst) >= 5);
    }
    #[tokio::test]
    async fn category_budget_is_shared_across_article_parents() {
        let store = Store::default();
        let config = config();
        for index in 0..=MAX_CATEGORIES {
            store
                .article(5, &format!("Category:Detached {index}"), true)
                .await;
        }
        assert_eq!(
            article_reachable(&store, &config, 5, &CancellationToken::new())
                .await
                .unwrap_err()
                .code,
            "capacity"
        );
    }
    #[tokio::test(start_paused = true)]
    async fn failed_or_timed_out_reads_are_unknown_and_cancellation_stops_even_root_reads() {
        let failed = Store {
            fail: true,
            ..Default::default()
        };
        assert_eq!(
            category_reachable(
                &failed,
                &config(),
                "Category:Other",
                &CancellationToken::new()
            )
            .await
            .unwrap_err()
            .code,
            "unavailable"
        );
        let stalled = Store {
            stall: true,
            ..Default::default()
        };
        assert_eq!(
            article_reachable(&stalled, &config(), 7, &CancellationToken::new())
                .await
                .unwrap_err()
                .code,
            "capacity"
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            category_reachable(&Store::default(), &config(), "Category:Science", &cancel)
                .await
                .unwrap_err()
                .code,
            "cancelled"
        );
    }
}
