use super::*;
use async_trait::async_trait;
use devres_application::chromium::{ChromiumConfig, ChromiumStore, Row, Write};
use std::sync::Mutex;

#[derive(Default)]
pub(super) struct Memory {
    rows: Mutex<BTreeMap<(String, String), Row>>,
    state: Mutex<BTreeMap<String, Value>>,
    pub(super) fail_index_markers: std::sync::atomic::AtomicBool,
}
#[async_trait]
impl ChromiumStore for Memory {
    async fn chromium_cutoff(&self) -> Result<i64> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .values()
            .map(|r| r.sequence)
            .max()
            .unwrap_or(0))
    }
    async fn chromium_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .get(&(kind.into(), key.into()))
            .cloned())
    }
    async fn chromium_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
        let mut rows = self.rows.lock().unwrap();
        if let Some(old) = rows.get(&(kind.into(), key.into())) {
            if &old.data != data {
                return Err(Error::integrity("immutable collision"));
            }
            return Ok(old.sequence);
        }
        let sequence = rows.len() as i64 + 1;
        rows.insert(
            (kind.into(), key.into()),
            Row {
                sequence,
                key: key.into(),
                data: data.clone(),
            },
        );
        Ok(sequence)
    }
    async fn chromium_put_many(&self, rows: &[Write]) -> Result<()> {
        if rows.iter().any(|row| row.kind == "indexed")
            && self
                .fail_index_markers
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Error::unavailable(
                "Synthetic interrupted index publication.",
            ));
        }
        for row in rows {
            self.chromium_put(&row.kind, &row.key, &row.data).await?;
        }
        Ok(())
    }
    async fn chromium_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
    ) -> Result<Vec<Row>> {
        let mut rows: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|((k, _), r)| {
                k == kind && r.sequence > after && cutoff.is_none_or(|c| r.sequence <= c)
            })
            .map(|(_, r)| r.clone())
            .collect();
        rows.sort_by_key(|r| r.sequence);
        rows.truncate(limit);
        Ok(rows)
    }
    async fn chromium_state(&self, key: &str) -> Result<Option<Value>> {
        Ok(self.state.lock().unwrap().get(key).cloned())
    }
    async fn chromium_set_state(&self, key: &str, data: &Value) -> Result<()> {
        self.state.lock().unwrap().insert(key.into(), data.clone());
        Ok(())
    }
    async fn chromium_publish_view(&self, view: &View) -> Result<()> {
        let data = json!(view);
        self.chromium_put("views", &view.id, &data).await?;
        self.chromium_set_state("default", &data).await
    }
}

pub(super) async fn corpus_fixture(
    broker: Arc<BulkBroker>,
) -> (tempfile::TempDir, Arc<Memory>, ChromiumCorpus) {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(Memory::default());
    let corpus = ChromiumCorpus::new(
        store.clone(),
        broker,
        root.path(),
        ChromiumConfig {
            enabled: false,
            min_free_bytes: 64 * 1024 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    (root, store, corpus)
}

#[test]
fn applicable_footer_terms_do_not_come_from_examples_or_scripts() {
    for source in [
        "<article><code>creativecommons.org/licenses/by/4.0</code></article>",
        "<script>const x=\"</div><footer>content of this page is licensed under https://creativecommons.org/licenses/by/4.0</footer>\";</script>",
        "<footer><code>content of this page is licensed under https://creativecommons.org/licenses/by/4.0</code></footer>",
    ] {
        assert_eq!(
            licensing::qualify(
                "chrome",
                source,
                "https://developer.chrome.com/docs/example"
            )["decision"],
            "unresolved"
        );
    }
    let valid = "<article>Example</article><p class=devsite-license>Except as otherwise noted, the content of this page is licensed under the <a href=https://creativecommons.org/licenses/by/4.0/>Creative Commons Attribution 4.0 License</a>, and code samples are licensed under the Apache 2.0 License.</p>";
    let license = licensing::qualify("chrome", valid, "https://developer.chrome.com/docs/example");
    assert_eq!(license["decision"], "approved");
    assert_eq!(license["licenses"], json!(["CC-BY-4.0", "Apache-2.0"]));
    assert!(!license["notice"].as_str().unwrap().contains("Example"));
    let actual_shape = "<devsite-content-footer class=\"nocontent\" data-nosnippet>Except as otherwise noted, the content of this page is licensed under the <a href=\"https://creativecommons.org/licenses/by/4.0/\">Creative Commons Attribution 4.0 License</a>, and code samples are licensed under the Apache 2.0 License.</devsite-content-footer>";
    assert_eq!(
        licensing::qualify(
            "chrome",
            actual_shape,
            "https://developer.chrome.com/docs/example"
        )["decision"],
        "approved"
    );
    for hidden in [
        format!("<pre>{actual_shape}</pre>"),
        format!("<script>const example={actual_shape:?};</script>"),
    ] {
        assert_eq!(
            licensing::qualify(
                "chrome",
                &hidden,
                "https://developer.chrome.com/docs/example"
            )["decision"],
            "unresolved"
        );
    }
    let inherited = json!({"decision":"approved","licenses":["BSD-3-Clause"]});
    assert_eq!(
        licensing::body_license(
            &inherited,
            b"<!-- Copyright Example. All rights reserved. No redistribution. -->",
            "https://example.invalid"
        )["decision"],
        "unresolved"
    );
}

#[tokio::test]
async fn immutable_inventory_grafts_share_children_and_keep_old_members() {
    let store = Memory::default();
    let empty = inventory::empty(&store).await.unwrap();
    let member = |path: &str| Member {
        path: path.into(),
        oid: "a".repeat(40),
        mode: "100644".into(),
        kind: "document".into(),
        projection: None,
        raw: None,
        gaps: vec!["license_scope_unresolved".into()],
    };
    let child = inventory::update(&store, &empty, "README.md", Some(member("docs/README.md")))
        .await
        .unwrap();
    let mut cache = inventory::NodeCache::new();
    let old = inventory::graft_cached(&store, &empty, "docs", &child, &mut cache)
        .await
        .unwrap();
    let changed = inventory::update(&store, &child, "more.md", Some(member("docs/more.md")))
        .await
        .unwrap();
    let new = inventory::graft_cached(&store, &old, "docs", &changed, &mut cache)
        .await
        .unwrap();
    assert!(
        inventory::get(&store, &old, "docs/more.md")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        inventory::get(&store, &new, "docs/more.md")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(inventory::node(&store, &old).await.unwrap().members, 1);
    assert_eq!(inventory::node(&store, &new).await.unwrap().members, 2);
    assert_eq!(
        inventory::subtree(&store, &old, "docs").await.unwrap(),
        Some(child)
    );
}
