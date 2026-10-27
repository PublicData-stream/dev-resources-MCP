//! Immutable rendered-edition membership, including explicitly advertised chapters.
use super::*;

const MAX_EDITION_DOCUMENTS: usize = 10_000;
const MAX_EDITION_LINK_BYTES: usize = 8 * 1024 * 1024;

fn document_navigation(standard: &Standard, publication: &Publication) -> Vec<PublicationUrl> {
    let advertised = url::Url::parse(publication.url.as_str())
        .ok()
        .map(|base| {
            publication
                .advertisements
                .iter()
                .filter(|ad| ad.role == catalog::AdvertisementRole::DocumentNavigation)
                .filter_map(|ad| {
                    let mut url = base.join(&ad.href).ok()?;
                    url.set_fragment(None);
                    Some(url.to_string())
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    catalog::qualified_advertised(
        standard,
        &publication.url,
        &publication
            .advertisements
            .iter()
            .filter(|ad| ad.role == catalog::AdvertisementRole::DocumentNavigation)
            .cloned()
            .collect::<Vec<_>>(),
    )
    .into_iter()
    .filter(|url| url.as_str() != publication.url.as_str() && advertised.contains(url.as_str()))
    .collect()
}

impl W3cCorpus {
    /// Called only by the fenced collector. This performs no upstream I/O.
    pub(super) async fn aggregate_edition(
        &self,
        standard: &Standard,
        canonical: &Snapshot,
        cancel: CancellationToken,
    ) -> Result<Snapshot> {
        self.aggregate_edition_with(standard, canonical, None, cancel)
            .await
    }

    pub(super) async fn aggregate_edition_with(
        &self,
        standard: &Standard,
        canonical: &Snapshot,
        publications: Option<&BTreeMap<String, String>>,
        cancel: CancellationToken,
    ) -> Result<Snapshot> {
        let Some(publication_id) = canonical.coverage["publication"].as_str() else {
            return Ok(canonical.clone());
        };
        if canonical.representation == "source" {
            return Ok(canonical.clone());
        }
        let publication: Publication = decode(
            self.store
                .w3c_get("publications", publication_id)
                .await?
                .ok_or_else(failure)?
                .data,
        )?;
        let mut queue = VecDeque::from([publication]);
        let mut seen = BTreeSet::new();
        let mut link_bytes = 0usize;
        let mut dependencies = BTreeMap::new();
        let mut missing = BTreeSet::new();
        let mut root = inventory::empty(self.store.as_ref()).await?;
        let mut cache = inventory::NodeCache::new();
        let mut validated_at = canonical.validated_at;
        while let Some(publication) = queue.pop_front() {
            cancelled(&cancel)?;
            let source = publication.url.as_str().to_owned();
            if dependencies.contains_key(&source) {
                continue;
            }
            if dependencies.len() >= MAX_EDITION_DOCUMENTS {
                return Err(Error::capacity(
                    "W3C edition document count exceeds bounds.",
                ));
            }
            if publication.standard != standard.id || publication.license["decision"] != "approved"
            {
                missing.insert(source);
                continue;
            }
            let selected = if publication.id == publication_id {
                Some(canonical.clone())
            } else if publications.is_some() {
                self.frozen_publication_snapshot(standard, &publication)
                    .await?
            } else {
                self.snapshot_for_revision(
                    &standard.id,
                    publication.url.as_str(),
                    &publication.id,
                    publication.url.kind().representation(),
                )
                .await?
            };
            let selected = if let Some(selected) =
                selected.filter(|snapshot| snapshot.coverage["usable"] == true)
            {
                Some(selected)
            } else if publications.is_none() {
                missing.insert(source.clone());
                let previous = self
                    .store
                    .w3c_state(&state_key("publication-usable", &source))
                    .await?
                    .and_then(|value| value.as_str().map(str::to_owned));
                if let Some(previous) = previous.filter(|id| id != &publication.id) {
                    let previous: Publication = decode(
                        self.store
                            .w3c_get("publications", &previous)
                            .await?
                            .ok_or_else(failure)?
                            .data,
                    )?;
                    if previous.standard == standard.id
                        && previous.url.as_str() == source
                        && previous.status == 200
                        && previous.license["decision"] == "approved"
                    {
                        queue.push_back(previous);
                    }
                }
                None
            } else {
                None
            };
            let Some(selected) = selected else {
                missing.insert(source);
                continue;
            };
            validated_at = validated_at.min(publication.observed_at);
            dependencies.insert(source.clone(), publication.id.clone());
            for mut member in self.members(&selected, 0, MAX_MEMBERS).await? {
                if let Some(raw) = member.raw.as_mut().and_then(Value::as_object_mut) {
                    raw.insert("source_url".into(), json!(source));
                    raw.insert("license".into(), publication.license.clone());
                }
                if let Some(existing) =
                    inventory::get(self.store.as_ref(), &root, &member.path).await?
                {
                    if existing != member {
                        return Err(Error::integrity(
                            "W3C edition documents collide at one source path.",
                        ));
                    }
                } else {
                    let path = member.path.clone();
                    root = inventory::update_cached(
                        self.store.as_ref(),
                        &root,
                        &path,
                        Some(member),
                        &mut cache,
                    )
                    .await?;
                }
            }
            for target in document_navigation(standard, &publication) {
                if !seen.insert(target.as_str().to_owned()) {
                    continue;
                }
                link_bytes = link_bytes
                    .checked_add(target.as_str().len())
                    .filter(|bytes| *bytes <= MAX_EDITION_LINK_BYTES)
                    .ok_or_else(|| Error::capacity("W3C edition navigation exceeds bounds."))?;
                if seen.len() > MAX_EDITION_DOCUMENTS {
                    return Err(Error::capacity(
                        "W3C edition navigation count exceeds bounds.",
                    ));
                }
                let id = if let Some(frozen) = publications {
                    frozen.get(target.as_str()).cloned()
                } else {
                    self.store
                        .w3c_state(&state_key("publication", target.as_str()))
                        .await?
                        .and_then(|value| value.as_str().map(str::to_owned))
                };
                let Some(id) = id else {
                    missing.insert(target.as_str().to_owned());
                    continue;
                };
                let mut next: Publication = decode(
                    self.store
                        .w3c_get("publications", &id)
                        .await?
                        .ok_or_else(failure)?
                        .data,
                )?;
                if next.url.as_str() != target.as_str() {
                    return Err(Error::integrity(
                        "W3C edition publication identity mismatch.",
                    ));
                }
                if next.status != 200
                    || next.artifact.is_none()
                    || next.license["decision"] != "approved"
                {
                    missing.insert(target.as_str().to_owned());
                    if publications.is_none()
                        && let Some(previous) = self
                            .store
                            .w3c_state(&state_key("publication-usable", target.as_str()))
                            .await?
                            .and_then(|value| value.as_str().map(str::to_owned))
                    {
                        next = decode(
                            self.store
                                .w3c_get("publications", &previous)
                                .await?
                                .ok_or_else(failure)?
                                .data,
                        )?;
                    }
                }
                if next.url.as_str() == target.as_str()
                    && next.status == 200
                    && next.artifact.is_some()
                    && next.license["decision"] == "approved"
                {
                    queue.push_back(next);
                }
            }
        }
        if dependencies.len() == 1 && missing.is_empty() {
            return Ok(canonical.clone());
        }
        let node = inventory::node(self.store.as_ref(), &root).await?;
        let id = inventory::digest(
            &serde_json::to_vec(&(
                canonical.id.as_str(),
                &root,
                &dependencies,
                &missing,
                PROCESSOR_VERSION,
            ))
            .map_err(|_| failure())?,
        );
        if let Some(row) = self.store.w3c_get("snapshots", &id).await? {
            let retained: Snapshot = decode(row.data)?;
            if retained.inventory != root
                || retained.standard != standard.id
                || retained.revision != canonical.revision
            {
                return Err(Error::integrity("W3C edition snapshot identity mismatch."));
            }
            return Ok(retained);
        }
        let index = self
            .frozen_index(std::slice::from_ref(&root), &id, cancel)
            .await?;
        let manifest = json!({"version":1,"root_snapshot":canonical.id,"inventory":root,"publications":dependencies,"missing":missing,"validated_at":validated_at});
        let manifest_id = inventory::digest(&serde_json::to_vec(&manifest).map_err(|_| failure())?);
        self.store
            .w3c_put("editions", &manifest_id, &manifest)
            .await?;
        let mut snapshot = canonical.clone();
        snapshot.id = id.clone();
        snapshot.inventory = root;
        snapshot.index = index;
        snapshot.validated_at = validated_at;
        snapshot.coverage["edition_root_snapshot"] = json!(canonical.id);
        snapshot.coverage["edition_manifest"] = json!(manifest_id);
        snapshot.coverage["edition_documents"] = json!(dependencies.len());
        snapshot.coverage["edition_missing_documents"] = json!(missing.len());
        snapshot.coverage["edition_missing_samples"] =
            json!(missing.iter().take(100).collect::<Vec<_>>());
        snapshot.coverage["edition_inventory_complete"] = json!(missing.is_empty());
        snapshot.coverage["members"] = json!(node.members);
        snapshot.coverage["raw_members"] = json!(node.members);
        snapshot.coverage["searchable"] = json!(node.searchable);
        snapshot.coverage["usable"] = json!(node.searchable > 0);
        snapshot.coverage["projection_gaps"] =
            json!(node.gaps.saturating_add(missing.len() as u64));
        snapshot.coverage["index_gaps"] = json!(
            inventory::members(self.store.as_ref(), &snapshot.inventory, MAX_MEMBERS)
                .await?
                .iter()
                .filter(|member| member.gaps.iter().any(|gap| gap.starts_with("index_")))
                .count()
        );
        if !missing.is_empty() {
            let mut gaps = snapshot.coverage["gaps"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            gaps.push(json!("edition_document_unavailable"));
            snapshot.coverage["gaps"] = json!(gaps);
        }
        self.publish_snapshot(
            snapshot,
            &alias(
                &standard.id,
                &canonical.repository,
                &format!("edition:{id}"),
                &canonical.representation,
            )?,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Standard {
        Standard {
            id: "example".into(),
            title: "Synthetic Example".into(),
            url: "https://www.w3.org/TR/example/".into(),
            repository: String::new(),
            metadata: json!({"publication_url":"https://www.w3.org/TR/example/","latest_tr_url":"https://www.w3.org/TR/example/","publication_status":"Working Draft"}),
        }
    }
    async fn retain_page(
        corpus: &W3cCorpus,
        standard: &Standard,
        url: &str,
        text: &str,
        observed: i64,
    ) -> (Publication, Snapshot) {
        let body=format!("<html><h1>Synthetic Example</h1><p id=w3c-state>Working Draft</p><p class=copyright>Copyright 2026 W3C synthetic fixture. <a href='/copyright/document-license-2023/'>Document License</a></p>{text}</html>").into_bytes();
        let url = PublicationUrl::new(url).unwrap();
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
            id: inventory::digest(format!("{}:{observed}", url.as_str()).as_bytes()),
            standard: standard.id.clone(),
            url,
            observed_at: observed,
            artifact: Some(artifact),
            status: 200,
            links: metadata.links,
            gaps: Vec::new(),
            repositories: Vec::new(),
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
        for kind in ["publication", "publication-success"] {
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

    #[tokio::test]
    async fn default_edition_searches_chapters_and_preserves_earlier_partial_snapshot() {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        let (_root, store, corpus) = super::super::tests::corpus_fixture(Arc::new(
            BulkBroker::new(Default::default()).unwrap(),
        ))
        .await;
        let standard = report();
        let now = devres_domain::unix_now();
        let (publication, canonical) = retain_page(
            &corpus,
            &standard,
            &standard.url,
            "<nav id=toc><a href='chapter.html'>Chapter</a></nav>",
            now,
        )
        .await;
        assert!(
            !document_navigation(&standard, &publication).is_empty(),
            "fixture must advertise a chapter"
        );
        let partial = corpus
            .aggregate_edition(&standard, &canonical, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(partial.coverage["edition_missing_documents"], 1);
        assert_eq!(partial.coverage["edition_inventory_complete"], false);
        let (_,chapter)=retain_page(&corpus,&standard,"https://www.w3.org/TR/example/chapter.html","<h2 id=quasar>Quasar callback</h2><p>The quasar callback is synthetic chapter content.</p>",now-120).await;
        let catalog = Catalog {
            id: inventory::digest(b"synthetic edition catalog"),
            observed_at: now,
            standards: vec![standard.clone()],
            gaps: Vec::new(),
        };
        store
            .w3c_put("catalogs", &catalog.id, &json!(catalog))
            .await
            .unwrap();
        store
            .w3c_set_state("catalog", &json!(catalog.id))
            .await
            .unwrap();
        store
            .w3c_set_state(
                &state_key("current", &standard.id),
                &json!({"snapshot":canonical.id,"validated_at":now}),
            )
            .await
            .unwrap();
        corpus
            .publish_default(&catalog, CancellationToken::new())
            .await
            .unwrap();
        let view = corpus.view(None).await.unwrap();
        let edition = corpus.snapshot(&view.snapshots["example"]).await.unwrap();
        assert_ne!(edition.id, partial.id);
        assert_eq!(edition.coverage["edition_documents"], 2);
        assert_eq!(edition.coverage["edition_missing_documents"], 0);
        assert_eq!(edition.validated_at, now - 120);
        assert_eq!(
            corpus
                .members(&corpus.snapshot(&partial.id).await.unwrap(), 0, 100)
                .await
                .unwrap()
                .len(),
            1
        );
        let child_member = corpus
            .members(&edition, 0, 100)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.path.ends_with("chapter.html"))
            .unwrap();
        assert_eq!(
            child_member.raw.as_ref().unwrap()["source_url"],
            chapter.source_url
        );
        let research = crate::w3c_research::W3cResearch::new(Arc::new(corpus));
        let found = research
            .call(
                "w3c_search",
                json!({"specification":"example","query":"quasar"}),
            )
            .await
            .unwrap();
        assert!(!found["results"].as_array().unwrap().is_empty());
        let text = research
            .call(
                "w3c_get",
                json!({"specification":"example","snapshot":edition.id,"path":child_member.path}),
            )
            .await
            .unwrap();
        assert!(text["page"]["text"].as_str().unwrap().contains("quasar"));
        let uri = text["resource_uri"].as_str().unwrap();
        let resource = research.read_resource(uri).await.unwrap();
        assert!(resource["contents"].is_array());
    }

    #[tokio::test]
    async fn failed_chapter_refresh_keeps_qualified_body_with_incomplete_edition_coverage() {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        let (_root, store, corpus) = super::super::tests::corpus_fixture(Arc::new(
            BulkBroker::new(Default::default()).unwrap(),
        ))
        .await;
        let standard = report();
        let now = devres_domain::unix_now();
        let (_, canonical) = retain_page(
            &corpus,
            &standard,
            &standard.url,
            "<nav id=toc><a href='chapter.html'>Chapter</a></nav>",
            now,
        )
        .await;
        let (mut failed, _) = retain_page(
            &corpus,
            &standard,
            "https://www.w3.org/TR/example/chapter.html",
            "<h2 id=retained>Retained chapter</h2><p>Preserved synthetic text.</p>",
            now - 10,
        )
        .await;
        failed.id = inventory::digest(b"synthetic chapter503");
        failed.status = 503;
        failed.artifact = None;
        store
            .w3c_put("publications", &failed.id, &json!(failed))
            .await
            .unwrap();
        store
            .w3c_set_state(
                &state_key("publication", failed.url.as_str()),
                &json!(failed.id),
            )
            .await
            .unwrap();
        let edition = corpus
            .aggregate_edition(&standard, &canonical, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(edition.coverage["edition_documents"], 2);
        assert_eq!(edition.coverage["edition_missing_documents"], 1);
        assert_eq!(edition.coverage["edition_inventory_complete"], false);
        assert_eq!(corpus.members(&edition, 0, 100).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn failed_chapter_projection_preserves_prior_usable_member() {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        let (_root, store, corpus) = super::super::tests::corpus_fixture(Arc::new(
            BulkBroker::new(Default::default()).unwrap(),
        ))
        .await;
        let standard = report();
        let now = devres_domain::unix_now();
        let (_, canonical) = retain_page(
            &corpus,
            &standard,
            &standard.url,
            "<nav id=toc><a href='chapter.html'>Chapter</a></nav>",
            now,
        )
        .await;
        let (mut broken, previous) = retain_page(
            &corpus,
            &standard,
            "https://www.w3.org/TR/example/chapter.html",
            "<h2 id=retained>Retained chapter</h2><p>Previous usable synthetic text.</p>",
            now - 120,
        )
        .await;
        let artifact = corpus
            .raw
            .capture_bytes(vec![0xff, 0xfe, 0], CancellationToken::new())
            .await
            .unwrap();
        broken.id = inventory::digest(b"synthetic chapter failed projection");
        broken.artifact = Some(artifact.clone());
        broken.observed_at = now;
        broken.chunk_hashes = corpus
            .publication_chunks(&artifact, CancellationToken::new())
            .await
            .unwrap();
        store
            .w3c_put("publications", &broken.id, &json!(broken))
            .await
            .unwrap();
        store
            .w3c_set_state(
                &state_key("publication", broken.url.as_str()),
                &json!(broken.id),
            )
            .await
            .unwrap();
        store
            .w3c_set_state(
                &state_key("publication-success", broken.url.as_str()),
                &json!(broken.id),
            )
            .await
            .unwrap();
        let failed = corpus
            .process_publication(&standard, &broken, CancellationToken::new())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(failed.coverage["usable"], false);
        let edition = corpus
            .aggregate_edition(&standard, &canonical, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(edition.coverage["edition_documents"], 2);
        assert_eq!(edition.coverage["edition_inventory_complete"], false);
        assert_eq!(edition.validated_at, now - 120);
        let old = corpus
            .members(&previous, 0, 100)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let retained = corpus
            .members(&edition, 0, 100)
            .await
            .unwrap()
            .into_iter()
            .find(|member| member.path.ends_with("chapter.html"))
            .unwrap();
        assert_eq!(retained.oid, old.oid);
        assert_eq!(retained.projection, old.projection);
    }

    #[tokio::test]
    async fn edition_navigation_has_segment_boundaries_and_keeps_nested_siblings() {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        let (_root, _store, corpus) = super::super::tests::corpus_fixture(Arc::new(
            BulkBroker::new(Default::default()).unwrap(),
        ))
        .await;
        let standard = report();
        let (publication,_)=retain_page(&corpus,&standard,"https://www.w3.org/TR/example/part1/page.html","<nav id=toc><a href='../part2/page.html'>Next chapter</a><a href='/TR/example-other/chapter.html'>Another report</a></nav>",devres_domain::unix_now()).await;
        let links = document_navigation(&standard, &publication);
        assert!(
            links
                .iter()
                .any(|link| link.as_str() == "https://www.w3.org/TR/example/part2/page.html")
        );
        assert!(
            !links
                .iter()
                .any(|link| link.as_str().contains("example-other"))
        );
    }
}
