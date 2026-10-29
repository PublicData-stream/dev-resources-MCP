//! Bounded fixed metadata observations; failed corroboration never discards the API catalog.
use super::*;
use crate::w3c::discovery::{self as w3c_discovery, DiscoveryOperation};
use futures::StreamExt;

impl W3cCorpus {
    async fn discovery_observation(
        &self,
        operation: DiscoveryOperation,
        cancel: CancellationToken,
    ) -> Result<(Vec<u8>, Value)> {
        let deadline = Instant::now() + Duration::from_secs(120);
        let observed_at = devres_domain::unix_now();
        // The broker owns the sole optional retry; this layer never retries it.
        let mut response = self
            .broker
            .open(
                BulkRequest {
                    source: BulkSource::W3cDiscovery(operation),
                    validators: Validators::default(),
                    max_bytes: operation.max_bytes() as u64,
                    deadline,
                    body: Vec::new(),
                },
                cancel.clone(),
            )
            .await?;
        if response.status != 200 {
            return Err(Error::unavailable("W3C discovery endpoint is unavailable."));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = bulk::bounded(&cancel, deadline, async {
            Ok(response.stream.next().await)
        })
        .await?
        {
            let chunk = chunk?;
            if bytes.len().saturating_add(chunk.len()) > operation.max_bytes() {
                return Err(Error::capacity(
                    "W3C discovery response exceeds its byte bound.",
                ));
            }
            bytes.extend(chunk);
        }
        cancelled(&cancel)?;
        let artifact = self.raw.capture_bytes(bytes.clone(), cancel).await?;
        let evidence = json!({"policy_version":w3c_discovery::POLICY_VERSION,"source_url":operation.url()?,"operation":operation,"body_hash":artifact.body_hash,"bytes":artifact.bytes,"artifact":artifact,"observed_at":observed_at,"assurance":"https","role":"official_public_catalog_metadata"});
        let id = inventory::digest(&serde_json::to_vec(&evidence).map_err(|_| failure())?);
        self.store
            .w3c_put("discovery-captures", &id, &evidence)
            .await?;
        Ok((bytes, evidence))
    }
    pub(super) async fn reconcile_catalog(
        &self,
        mut catalog: Catalog,
        cancel: CancellationToken,
    ) -> Result<Catalog> {
        for operation in [
            DiscoveryOperation::TrIndex,
            DiscoveryOperation::BrowserSpecs,
        ] {
            cancelled(&cancel)?;
            let mut captured_evidence = None;
            let result = match self.discovery_observation(operation, cancel.clone()).await {
                Ok((bytes, evidence)) => {
                    captured_evidence = Some(evidence.clone());
                    // Parsing mutates only a candidate: a malformed observation cannot
                    // leak partially applied enrichment into the published catalog.
                    let mut candidate = catalog.clone();
                    let result = match operation {
                        DiscoveryOperation::TrIndex => {
                            w3c_discovery::reconcile_tr(&mut candidate, &bytes, &evidence, &cancel)
                        }
                        DiscoveryOperation::BrowserSpecs => w3c_discovery::enrich_browser_specs(
                            &mut candidate,
                            &bytes,
                            &evidence,
                            &cancel,
                        ),
                    };
                    result.map(|()| candidate)
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(candidate) => catalog = candidate,
                Err(error) if error.code == "cancelled" => return Err(error),
                Err(error) => catalog.gaps.push(json!({"kind":"discovery_observation_unavailable","operation":operation,"source_url":operation.url()?,"code":error.code,"observed_at":devres_domain::unix_now(),"api_catalog_preserved":true,"evidence":captured_evidence})),
            }
        }
        Ok(catalog)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::{Router, http::StatusCode, routing::get};
    use devres_application::w3c::Row;
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    };
    #[derive(Default)]
    struct Memory {
        rows: StdMutex<BTreeMap<(String, String), Row>>,
        state: StdMutex<BTreeMap<String, Value>>,
    }
    #[async_trait]
    impl W3cStore for Memory {
        async fn w3c_cutoff(&self) -> Result<i64> {
            Ok(self.rows.lock().unwrap().len() as i64)
        }
        async fn w3c_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .get(&(kind.into(), key.into()))
                .cloned())
        }
        async fn w3c_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(old) = rows.get(&(kind.into(), key.into())) {
                if old.data != *data {
                    return Err(Error::integrity("fixture immutable collision"));
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
        async fn w3c_rows(
            &self,
            kind: &str,
            after: i64,
            limit: usize,
            cutoff: Option<i64>,
        ) -> Result<Vec<Row>> {
            let mut rows = self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|((k, _), r)| {
                    k == kind && r.sequence > after && cutoff.is_none_or(|c| r.sequence <= c)
                })
                .map(|(_, r)| r.clone())
                .collect::<Vec<_>>();
            rows.sort_by_key(|r| r.sequence);
            rows.truncate(limit);
            Ok(rows)
        }
        async fn w3c_state(&self, key: &str) -> Result<Option<Value>> {
            Ok(self.state.lock().unwrap().get(key).cloned())
        }
        async fn w3c_set_state(&self, key: &str, data: &Value) -> Result<()> {
            self.state.lock().unwrap().insert(key.into(), data.clone());
            Ok(())
        }
        async fn w3c_publish_view(&self, _: &View) -> Result<()> {
            Err(Error::integrity(
                "discovery fixture must not publish a view",
            ))
        }
    }
    fn api_catalog() -> Catalog {
        Catalog {
            id: "original-api-identity".into(),
            observed_at: 123,
            standards: vec![Standard {
                id: "css-color-4".into(),
                title: "Synthetic CSS Color 4".into(),
                url: "https://www.w3.org/TR/css-color-4/".into(),
                repository: String::new(),
                metadata: json!({}),
            }],
            gaps: vec![],
        }
    }
    async fn fixture(
        status: StatusCode,
        tr: &'static str,
        browser: &'static str,
    ) -> (
        tempfile::TempDir,
        Arc<Memory>,
        W3cCorpus,
        Arc<BulkBroker>,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let requests = Arc::new(AtomicUsize::new(0));
        let tr_requests = requests.clone();
        let browser_requests = requests.clone();
        let app = Router::new()
            .route(
                "/TR/",
                get(move || {
                    let count = tr_requests.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        (status, [("content-type", "text/html")], tr)
                    }
                }),
            )
            .route(
                "/browser-specs/index.json",
                get(move || {
                    let count = browser_requests.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        (status, [("content-type", "application/json")], browser)
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let broker = Arc::new(
            BulkBroker::fixture(url::Url::parse(&format!("http://{address}/")).unwrap())
                .unwrap()
                .with_attempt_budget(4)
                .unwrap(),
        );
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(Memory::default());
        let corpus = W3cCorpus::new(
            store.clone(),
            broker.clone(),
            root.path(),
            W3cConfig {
                enabled: false,
                min_free_bytes: 64 * 1024 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        (root, store, corpus, broker, requests, server)
    }
    #[tokio::test]
    async fn discovery_captures_preserve_exact_provenance_without_changing_api_membership_or_time()
    {
        let(_root,store,corpus,broker,requests,server)=fixture(StatusCode::OK,"<h3><a href='/TR/css-color-4/'>Synthetic CSS Color 4</a></h3><p>Candidate Standard</p>",r#"[{"shortname":"css-color-4","organization":"W3C","url":"https://www.w3.org/TR/css-color-4/","nightly":{"url":"https://drafts.csswg.org/css-color-4/","repository":"https://github.com/w3c/csswg-drafts","sourcePath":"css-color-4/Overview.bs"}}]"#).await;
        let original = api_catalog();
        let catalog = corpus
            .reconcile_catalog(original.clone(), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(catalog.id, original.id);
        assert_eq!(catalog.observed_at, original.observed_at);
        assert_eq!(catalog.standards.len(), 1);
        assert!(catalog.standards[0].repository.is_empty());
        assert!(catalog.gaps.is_empty());
        let rows = store
            .w3c_rows("discovery-captures", 0, 10, None)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(broker.attempt_count(), 2);
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        for row in rows {
            assert_eq!(row.data["assurance"], "https");
            let hash = row.data["body_hash"].as_str().unwrap();
            assert!(hash.starts_with("blake3:"));
            assert_eq!(hash.len(), 71);
            let mut file = corpus
                .raw
                .open(hash, 16 * 1024 * 1024, CancellationToken::new())
                .await
                .unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(inventory::digest(&bytes), hash);
            assert_eq!(row.data["bytes"].as_u64(), Some(bytes.len() as u64));
        }
        assert_eq!(
            catalog.standards[0].metadata["tr_index"]["evidence"]["source_url"],
            "https://www.w3.org/TR/"
        );
        assert_eq!(
            catalog.standards[0].metadata["browser_specs"]["evidence"]["source_url"],
            "https://w3c.github.io/browser-specs/index.json"
        );
        server.abort();
    }
    #[tokio::test]
    async fn transient_discovery_failures_keep_api_catalog_and_have_one_retry_owner() {
        let (_root, store, corpus, broker, requests, server) = fixture(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "unavailable",
        )
        .await;
        let original = api_catalog();
        let catalog = corpus
            .reconcile_catalog(original.clone(), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(catalog.id, original.id);
        assert_eq!(catalog.standards.len(), original.standards.len());
        assert_eq!(catalog.gaps.len(), 2);
        assert!(
            catalog
                .gaps
                .iter()
                .all(|g| g["api_catalog_preserved"] == true)
        );
        assert_eq!(broker.attempt_count(), 4);
        assert_eq!(requests.load(Ordering::SeqCst), 4);
        assert!(
            store
                .w3c_rows("discovery-captures", 0, 10, None)
                .await
                .unwrap()
                .is_empty()
        );
        server.abort();
    }
    #[tokio::test]
    async fn malformed_listing_is_a_gap_and_precancellation_performs_no_request() {
        let (_root, _store, corpus, broker, requests, server) =
            fixture(StatusCode::OK, "<h1>No report links</h1>", "[]").await;
        let catalog = corpus
            .reconcile_catalog(api_catalog(), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(catalog.standards.len(), 1);
        assert_eq!(catalog.gaps.len(), 1);
        assert_eq!(catalog.gaps[0]["code"], "integrity");
        assert_eq!(
            catalog.gaps[0]["evidence"]["body_hash"]
                .as_str()
                .unwrap()
                .len(),
            71
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        let before = broker.attempt_count();
        assert_eq!(
            corpus
                .reconcile_catalog(api_catalog(), cancel)
                .await
                .unwrap_err()
                .code,
            "cancelled"
        );
        assert_eq!(broker.attempt_count(), before);
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        server.abort();
    }
}
