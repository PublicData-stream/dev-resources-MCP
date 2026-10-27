//! Frozen research views select only immutable capture IDs named by their inventory.
use super::*;

const MAX_FROZEN_LINK_BYTES: usize = 32 * 1024 * 1024;
fn missing_canonical(
    count: &mut usize,
    samples: &mut Vec<Value>,
    standard: &Standard,
    reason: &str,
) {
    *count += 1;
    if samples.len() < 100 {
        samples.push(json!({"specification":standard.id,"reason":reason}));
    }
}

impl W3cCorpus {
    /// Lookup a projection through immutable rows, without mutable revision/index aliases.
    pub(super) async fn frozen_publication_snapshot(
        &self,
        standard: &Standard,
        publication: &Publication,
    ) -> Result<Option<Snapshot>> {
        let Some(artifact) = &publication.artifact else {
            return Ok(None);
        };
        if publication.standard != standard.id
            || publication.status != 200
            || publication.license["decision"] != "approved"
        {
            return Ok(None);
        }
        let representation = publication.url.kind().representation();
        let key = alias(
            &standard.id,
            publication.url.as_str(),
            &publication.id,
            representation,
        )?;
        let Some(row) = self.store.w3c_get("snapshot-keys", &key).await? else {
            return Ok(None);
        };
        let id = row
            .data
            .as_str()
            .ok_or_else(|| Error::integrity("Frozen W3C snapshot alias is invalid."))?;
        let snapshot: Snapshot = decode(
            self.store
                .w3c_get("snapshots", id)
                .await?
                .ok_or_else(|| Error::integrity("Frozen W3C publication projection is missing."))?
                .data,
        )?;
        if snapshot.id != id
            || snapshot.standard != standard.id
            || snapshot.repository != publication.url.as_str()
            || snapshot.source_url != publication.url.as_str()
            || snapshot.revision != publication.id
            || snapshot.tree != artifact.body_hash
            || snapshot.representation != representation
            || snapshot.processor_version != PROCESSOR_VERSION
            || snapshot.coverage["publication"] != publication.id
            || snapshot.coverage["license"]["decision"] != "approved"
        {
            return Err(Error::integrity(
                "Frozen W3C publication projection identity mismatch.",
            ));
        }
        Ok(Some(snapshot))
    }

    /// A fresh immutable index is built only from the supplied inventories. No
    /// current view, mutable index context, or previously indexed members are read.
    pub(super) async fn frozen_index(
        &self,
        roots: &[String],
        identity: &str,
        cancel: CancellationToken,
    ) -> Result<Value> {
        if roots.len() > MAX_MEMBERS || identity.is_empty() || identity.len() > 4096 {
            return Err(Error::capacity(
                "Frozen W3C index selection exceeds bounds.",
            ));
        }
        let roots: BTreeSet<_> = roots.iter().cloned().collect();
        let generation = format!(
            "w3c-frozen-{}",
            inventory::digest(
                &serde_json::to_vec(&(identity, &roots, PROCESSOR_VERSION))
                    .map_err(|_| failure())?
            )
        );
        let mut required = BTreeSet::new();
        for root in roots {
            cancelled(&cancel)?;
            required.extend(self.root_members(&root).await?);
            if required.len() > MAX_MEMBERS {
                return Err(Error::capacity(
                    "Frozen W3C index membership exceeds bounds.",
                ));
            }
        }
        let ids: Vec<_> = required.into_iter().collect();
        let mut pending = IndexDocuments::new(self.store.as_ref(), &ids);
        let mut reference = None;
        let mut shards = 0;
        while pending.position < ids.len() || reference.is_none() {
            cancelled(&cancel)?;
            if shards >= 4090 {
                return Err(Error::capacity(
                    "Frozen W3C index requires too many shards.",
                ));
            }
            let (documents, _) = pending.next_shard(&cancel).await?;
            reference = Some(
                self.index
                    .publish_generation(reference.as_ref(), documents, cancel.clone(), &generation)
                    .await?,
            );
            shards += 1;
        }
        reference.ok_or_else(failure)
    }

    pub(super) async fn publish_frozen_default(
        &self,
        frozen: &Frozen,
        cancel: CancellationToken,
    ) -> Result<Value> {
        if frozen.publications.len() > MAX_PUBLICATIONS
            || frozen.catalog.standards.len() > catalog::MAX_CATALOG
        {
            return Err(Error::capacity(
                "Frozen W3C publication selection exceeds bounds.",
            ));
        }
        let mut candidates: BTreeMap<String, (i64, String)> = BTreeMap::new();
        let mut link_bytes = 0usize;
        for id in &frozen.publications {
            cancelled(&cancel)?;
            let publication: Publication = decode(
                self.store
                    .w3c_get("publications", id)
                    .await?
                    .ok_or_else(|| Error::integrity("Frozen W3C publication is missing."))?
                    .data,
            )?;
            if publication.id != *id {
                return Err(Error::integrity(
                    "Frozen W3C publication identity mismatch.",
                ));
            }
            publication.url.validate()?;
            let url = publication.url.as_str();
            let proposed = (publication.observed_at, id.clone());
            if !candidates.contains_key(url) {
                link_bytes = link_bytes
                    .checked_add(url.len())
                    .and_then(|bytes| bytes.checked_add(id.len() + 64))
                    .filter(|bytes| *bytes <= MAX_FROZEN_LINK_BYTES)
                    .ok_or_else(|| {
                        Error::capacity("Frozen W3C publication URL metadata exceeds bounds.")
                    })?;
            }
            match candidates.entry(url.into()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(proposed);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if proposed > *entry.get() {
                        entry.insert(proposed);
                    }
                }
            }
        }
        let publications: BTreeMap<_, _> = candidates
            .into_iter()
            .map(|(url, (_, id))| (url, id))
            .collect();
        let mut snapshots = BTreeMap::new();
        let mut validations = BTreeMap::new();
        let mut roots = Vec::new();
        let mut missing_canonical_count = 0usize;
        let mut missing_canonical_samples = Vec::new();
        let mut missing_edition_documents = 0u64;
        let mut missing_edition_samples = Vec::new();
        for standard in &frozen.catalog.standards {
            cancelled(&cancel)?;
            let canonical_url = catalog::current_publication(standard)?;
            let Some(id) = publications.get(canonical_url.as_str()) else {
                missing_canonical(
                    &mut missing_canonical_count,
                    &mut missing_canonical_samples,
                    standard,
                    "not_in_frozen_publications",
                );
                continue;
            };
            let publication: Publication = decode(
                self.store
                    .w3c_get("publications", id)
                    .await?
                    .ok_or_else(failure)?
                    .data,
            )?;
            let Some(canonical) = self
                .frozen_publication_snapshot(standard, &publication)
                .await?
            else {
                missing_canonical(
                    &mut missing_canonical_count,
                    &mut missing_canonical_samples,
                    standard,
                    "unavailable_unlicensed_or_unprocessed_frozen_capture",
                );
                continue;
            };
            if !self.usable(&canonical).await? {
                missing_canonical(
                    &mut missing_canonical_count,
                    &mut missing_canonical_samples,
                    standard,
                    "frozen_canonical_projection_unusable",
                );
                continue;
            }
            let edition = self
                .aggregate_edition_with(standard, &canonical, Some(&publications), cancel.clone())
                .await?;
            missing_edition_documents = missing_edition_documents
                .checked_add(
                    edition.coverage["edition_missing_documents"]
                        .as_u64()
                        .unwrap_or(0),
                )
                .ok_or_else(|| {
                    Error::capacity("Frozen W3C missing-document count exceeds bounds.")
                })?;
            if let Some(samples) = edition.coverage["edition_missing_samples"].as_array() {
                for url in samples
                    .iter()
                    .take(100usize.saturating_sub(missing_edition_samples.len()))
                {
                    missing_edition_samples.push(json!({"specification":standard.id,"url":url}));
                }
            }
            if !self.usable(&edition).await? {
                missing_canonical(
                    &mut missing_canonical_count,
                    &mut missing_canonical_samples,
                    standard,
                    "frozen_edition_projection_unusable",
                );
                continue;
            }
            roots.push(edition.inventory.clone());
            validations.insert(
                standard.id.clone(),
                edition.validated_at.min(publication.observed_at),
            );
            if snapshots.insert(standard.id.clone(), edition.id).is_some() {
                return Err(Error::integrity(
                    "Frozen W3C catalog contains duplicate specification identities.",
                ));
            }
        }
        let mut summary = json!({"frozen":frozen.id,"view":null,"complete":!snapshots.is_empty() && snapshots.len()==frozen.catalog.standards.len() && missing_canonical_count==0 && missing_edition_documents==0,
            "expected_specifications":frozen.catalog.standards.len(),"published_specifications":snapshots.len(),
            "missing_canonical":missing_canonical_count,"missing_canonical_samples":missing_canonical_samples,
            "missing_edition_documents":missing_edition_documents,"missing_edition_samples":missing_edition_samples,
            "scope":"exact_frozen_publication_membership"});
        if snapshots.is_empty() {
            return Ok(summary);
        }
        let validated_at = validations
            .values()
            .copied()
            .min()
            .unwrap_or(frozen.catalog.observed_at)
            .min(frozen.catalog.observed_at);
        let index = self.frozen_index(&roots, &frozen.id, cancel).await?;
        let id = inventory::digest(
            &serde_json::to_vec(&(
                &frozen.catalog.id,
                &snapshots,
                &index,
                &validations,
                validated_at,
            ))
            .map_err(|_| failure())?,
        );
        self.store
            .w3c_publish_view(&View {
                id: id.clone(),
                catalog: frozen.catalog.id.clone(),
                snapshots,
                index,
                validations,
                validated_at,
            })
            .await?;
        summary["view"] = json!(id);
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Standard {
        Standard {
            id: "example".into(),
            title: "Synthetic frozen edition".into(),
            url: "https://www.w3.org/TR/example/".into(),
            repository: String::new(),
            metadata: json!({"publication_url":"https://www.w3.org/TR/example/","latest_tr_url":"https://www.w3.org/TR/example/","publication_status":"Working Draft"}),
        }
    }
    async fn page(
        corpus: &W3cCorpus,
        standard: &Standard,
        url: &str,
        text: &str,
        observed_at: i64,
    ) -> (Publication, Snapshot) {
        let body=format!("<h1>Synthetic Example</h1><p class=w3c-state>Working Draft</p><p class=copyright>Copyright 2026 W3C synthetic fixture. <a href='https://www.w3.org/copyright/document-license-2023/'>Document License</a></p>{text}").into_bytes();
        let url = PublicationUrl::qualified(url, &standard.url).unwrap();
        let license = catalog::publication_license(&url, &body);
        assert_eq!(license["decision"], "approved");
        let metadata = catalog::publication_metadata(&body, &CancellationToken::new()).unwrap();
        let artifact = corpus
            .raw
            .capture_bytes(body, CancellationToken::new())
            .await
            .unwrap();
        let chunk_hashes = corpus
            .publication_chunks(&artifact, CancellationToken::new())
            .await
            .unwrap();
        let publication = Publication {
            id: inventory::digest(
                &serde_json::to_vec(&(url.as_str(), observed_at, &artifact.body_hash)).unwrap(),
            ),
            standard: standard.id.clone(),
            url,
            observed_at,
            artifact: Some(artifact),
            status: 200,
            links: metadata.links,
            gaps: vec![],
            repositories: vec![],
            chunk_hashes,
            metadata_version: catalog::METADATA_VERSION,
            metadata_parent: None,
            license,
            advertisements: metadata.advertisements,
            exclusions: metadata.exclusions,
        };
        corpus
            .store
            .w3c_put(
                "publications",
                &publication.id,
                &encode(&publication).unwrap(),
            )
            .await
            .unwrap();
        for kind in ["publication", "publication-success", "publication-usable"] {
            corpus
                .store
                .w3c_set_state(
                    &state_key(kind, publication.url.as_str()),
                    &json!(publication.id),
                )
                .await
                .unwrap();
        }
        let snapshot = corpus
            .process_publication(standard, &publication, CancellationToken::new())
            .await
            .unwrap()
            .unwrap();
        (publication, snapshot)
    }
    async fn frozen(
        corpus: &W3cCorpus,
        standard: Standard,
        publications: Vec<String>,
        observed_at: i64,
    ) -> Frozen {
        let catalog = Catalog {
            id: inventory::digest(b"synthetic frozen edition catalog"),
            observed_at,
            standards: vec![standard],
            gaps: vec![],
        };
        corpus
            .store
            .w3c_put("catalogs", &catalog.id, &encode(&catalog).unwrap())
            .await
            .unwrap();
        Frozen {
            id: inventory::digest(&serde_json::to_vec(&(&catalog.id, &publications)).unwrap()),
            catalog,
            observations: BTreeMap::new(),
            publications,
            mode: "full".into(),
            lineage: None,
        }
    }
    #[tokio::test]
    async fn frozen_original_edition_ignores_newer_heads_aliases_and_unrelated_index_members() {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        let broker = Arc::new(BulkBroker::new(Default::default()).unwrap());
        let (_root, store, corpus) = super::super::tests::corpus_fixture(broker.clone()).await;
        let corpus = Arc::new(corpus);
        let standard = report();
        let now = devres_domain::unix_now();
        let (canonical, canonical_snapshot) = page(
            &corpus,
            &standard,
            &standard.url,
            "<nav id=toc><a href='chapter.html'>Chapter</a></nav>",
            now - 100,
        )
        .await;
        let (chapter_v1, chapter_snapshot_v1) = page(
            &corpus,
            &standard,
            "https://www.w3.org/TR/example/chapter.html",
            "<h2 id=original>Originalquasar chapter</h2><p>Originalquasar retained body.</p>",
            now - 200,
        )
        .await;
        let frozen = frozen(
            &corpus,
            standard.clone(),
            vec![canonical.id.clone(), chapter_v1.id.clone()],
            now - 50,
        )
        .await;
        corpus
            .publish_frozen_default(&frozen, CancellationToken::new())
            .await
            .unwrap();
        let baseline = corpus.view(None).await.unwrap();
        let baseline_snapshot = corpus
            .snapshot(&baseline.snapshots["example"])
            .await
            .unwrap();
        assert_eq!(baseline.validations["example"], now - 200);
        let research = crate::w3c_research::W3cResearch::new(corpus.clone());
        let chapter_path = corpus.members(&chapter_snapshot_v1, 0, 10).await.unwrap()[0]
            .path
            .clone();
        let original=research.call("w3c_get",json!({"specification":"example","snapshot":baseline_snapshot.id,"path":chapter_path})).await.unwrap();
        let original_uri = original["resource_uri"].as_str().unwrap().to_owned();
        let (_chapter_v2,chapter_snapshot_v2)=page(&corpus,&standard,"https://www.w3.org/TR/example/chapter.html","<h2 id=future>Futurequasar replacement</h2><p>Futurequasar body outside the original freeze.</p>",now-10).await;
        store
            .w3c_set_state(
                &state_key("current", &standard.id),
                &json!({"snapshot":canonical_snapshot.id,"validated_at":canonical.observed_at}),
            )
            .await
            .unwrap();
        corpus
            .publish_default(&frozen.catalog, CancellationToken::new())
            .await
            .unwrap();
        let runtime = corpus.view(None).await.unwrap();
        assert_ne!(runtime.snapshots["example"], baseline_snapshot.id);
        // Poison mutable aliases and per-snapshot index repair too: frozen reads must use immutable rows.
        let old_alias = alias(
            &standard.id,
            chapter_v1.url.as_str(),
            &chapter_v1.id,
            chapter_v1.url.kind().representation(),
        )
        .unwrap();
        store
            .w3c_set_state(
                &state_key("revision-alias", &old_alias),
                &json!(chapter_snapshot_v2.id),
            )
            .await
            .unwrap();
        store
            .w3c_set_state(
                &state_key("snapshot-index", &canonical_snapshot.id),
                &json!({"reference":runtime.index}),
            )
            .await
            .unwrap();
        corpus
            .publish_frozen_default(&frozen, CancellationToken::new())
            .await
            .unwrap();
        let resumed = corpus.view(None).await.unwrap();
        assert_eq!(resumed.id, baseline.id);
        assert_eq!(resumed.snapshots, baseline.snapshots);
        assert_eq!(resumed.validations, baseline.validations);
        let old_resource = research.read_resource(&original_uri).await.unwrap();
        assert!(
            old_resource["contents"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Originalquasar")
        );
        assert_eq!(
            research
                .call(
                    "w3c_search",
                    json!({"specification":"example","view":resumed.id,"query":"futurequasar"})
                )
                .await
                .unwrap()["total"],
            0
        );
        // Even deliberately broad internal membership cannot find the newer body in the frozen-only index.
        let mut members = corpus
            .root_members(&baseline_snapshot.inventory)
            .await
            .unwrap();
        members.extend(
            corpus
                .root_members(&chapter_snapshot_v2.inventory)
                .await
                .unwrap(),
        );
        let result = corpus
            .index
            .search(
                &resumed.index,
                members,
                crate::w3c_index::SearchSpec {
                    query: Some("futurequasar".into()),
                    ..Default::default()
                },
                CancellationToken::new(),
            )
            .await
            .expect_err("newer member IDs are absent from the frozen-only index");
        assert_eq!(result.code, "integrity");
        assert_eq!(broker.attempt_count(), 0);
    }
    #[tokio::test]
    async fn frozen_selection_never_uses_global_current_or_editor_draft_for_blocked_canonical() {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        let broker = Arc::new(BulkBroker::new(Default::default()).unwrap());
        let (_root, store, corpus) = super::super::tests::corpus_fixture(broker.clone()).await;
        let mut standard = report();
        standard.metadata["editor_draft"] = json!("https://drafts.example.org/example/");
        let now = devres_domain::unix_now();
        let (canonical, canonical_snapshot) = page(
            &corpus,
            &standard,
            &standard.url,
            "<h2 id=old>Original canonical</h2>",
            now - 100,
        )
        .await;
        let initial = frozen(
            &corpus,
            standard.clone(),
            vec![canonical.id.clone()],
            now - 50,
        )
        .await;
        corpus
            .publish_frozen_default(&initial, CancellationToken::new())
            .await
            .unwrap();
        let baseline = corpus.view(None).await.unwrap();
        let (editor, _) = page(
            &corpus,
            &standard,
            "https://drafts.example.org/example/",
            "<h2>Editor draft outside default role</h2>",
            now - 10,
        )
        .await;
        let mut blocked = canonical;
        blocked.id = inventory::digest(b"synthetic blocked canonical");
        blocked.observed_at = now;
        blocked.status = 503;
        blocked.artifact = None;
        blocked.license = json!({"decision":"unresolved"});
        store
            .w3c_put("publications", &blocked.id, &encode(&blocked).unwrap())
            .await
            .unwrap();
        let mut selected = initial.clone();
        selected.id = inventory::digest(b"blocked freeze");
        selected.publications = vec![blocked.id, editor.id];
        store
            .w3c_set_state(
                &state_key("current", &standard.id),
                &json!({"snapshot":canonical_snapshot.id,"validated_at":now}),
            )
            .await
            .unwrap();
        let summary = corpus
            .publish_frozen_default(&selected, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(summary["complete"], false);
        assert_eq!(summary["missing_canonical"], 1);
        assert!(summary["view"].is_null());
        assert_eq!(corpus.view(None).await.unwrap().id, baseline.id);
        assert_eq!(broker.attempt_count(), 0);
    }
    #[tokio::test]
    async fn frozen_duplicate_urls_choose_latest_observation_then_id_independently_of_input_order()
    {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        let broker = Arc::new(BulkBroker::new(Default::default()).unwrap());
        let (_root, _store, corpus) = super::super::tests::corpus_fixture(broker).await;
        let standard = report();
        let now = devres_domain::unix_now();
        let (canonical, _) = page(
            &corpus,
            &standard,
            &standard.url,
            "<nav><a href='chapter.html'>Chapter</a></nav>",
            now - 100,
        )
        .await;
        let (first, first_snapshot) = page(
            &corpus,
            &standard,
            "https://www.w3.org/TR/example/chapter.html",
            "<h2>First tied chapter</h2>",
            now - 50,
        )
        .await;
        let (second, second_snapshot) = page(
            &corpus,
            &standard,
            "https://www.w3.org/TR/example/chapter.html",
            "<h2>Second tied chapter</h2>",
            now - 50,
        )
        .await;
        let selected = frozen(
            &corpus,
            standard,
            vec![canonical.id, first.id.clone(), second.id.clone()],
            now,
        )
        .await;
        corpus
            .publish_frozen_default(&selected, CancellationToken::new())
            .await
            .unwrap();
        let before = corpus.view(None).await.unwrap();
        let snapshot = corpus.snapshot(&before.snapshots["example"]).await.unwrap();
        let chapter = corpus
            .members(&snapshot, 0, 10)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.path.ends_with("chapter.html"))
            .unwrap();
        let expected = if first.id > second.id {
            first_snapshot
        } else {
            second_snapshot
        };
        assert_eq!(chapter.oid, expected.tree);
        let mut reversed = selected;
        reversed.publications.reverse();
        corpus
            .publish_frozen_default(&reversed, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(corpus.view(None).await.unwrap().id, before.id);
    }
    #[tokio::test]
    async fn omitted_frozen_chapter_and_canonical_are_incomplete_even_when_global_heads_exist() {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        let broker = Arc::new(BulkBroker::new(Default::default()).unwrap());
        let (_root, _store, corpus) = super::super::tests::corpus_fixture(broker.clone()).await;
        let standard = report();
        let now = devres_domain::unix_now();
        let (canonical, _) = page(
            &corpus,
            &standard,
            &standard.url,
            "<nav><a href='chapter.html'>Chapter</a></nav>",
            now - 20,
        )
        .await;
        let (_, chapter) = page(
            &corpus,
            &standard,
            "https://www.w3.org/TR/example/chapter.html",
            "<h2>Global chapter outside this freeze</h2>",
            now - 10,
        )
        .await;
        let partial = frozen(&corpus, standard, vec![canonical.id], now).await;
        let summary = corpus
            .publish_frozen_default(&partial, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(summary["complete"], false);
        assert_eq!(summary["missing_canonical"], 0);
        assert_eq!(summary["missing_edition_documents"], 1);
        assert_eq!(summary["published_specifications"], 1);
        assert_eq!(
            summary["missing_edition_samples"][0]["url"],
            chapter.source_url
        );
        let view = corpus.view(None).await.unwrap();
        let edition = corpus.snapshot(&view.snapshots["example"]).await.unwrap();
        assert_eq!(corpus.members(&edition, 0, 10).await.unwrap().len(), 1);
        let mut absent = partial;
        absent.publications.clear();
        let missing = corpus
            .publish_frozen_default(&absent, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(missing["complete"], false);
        assert_eq!(missing["missing_canonical"], 1);
        assert!(missing["view"].is_null());
        assert_eq!(corpus.view(None).await.unwrap().id, view.id);
        assert_eq!(broker.attempt_count(), 0);
    }
}
