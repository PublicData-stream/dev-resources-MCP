//! W3C-specific API acquisition and license-gated archival. All preflight state is disposable.
use super::*;
use futures::StreamExt;
use std::sync::atomic::{AtomicU64, Ordering};
static PREFLIGHT: AtomicU64 = AtomicU64::new(0);
struct TemporaryRoot(PathBuf);
impl TemporaryRoot {
    fn new() -> Result<Self> {
        for _ in 0..10 {
            let path = PathBuf::from(format!(
                "/tmp/devres-w3c-preflight-{}-{}",
                std::process::id(),
                PREFLIGHT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                        .map_err(|_| failure())?;
                    std::fs::write(
                        path.join("owner-v1"),
                        b"devres-w3c-disposable-preflight-v1\n",
                    )
                    .map_err(|_| failure())?;
                    return Ok(Self(path));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(failure()),
            }
        }
        Err(failure())
    }
}
impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl W3cCorpus {
    async fn api(
        &self,
        operation: catalog::ApiOperation,
        cancel: CancellationToken,
    ) -> Result<(Vec<u8>, BulkArtifact)> {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut response = self
            .broker
            .open(
                BulkRequest {
                    source: BulkSource::W3cApi(operation),
                    validators: Validators::default(),
                    max_bytes: 8 * 1024 * 1024,
                    deadline,
                    body: Vec::new(),
                },
                cancel.clone(),
            )
            .await?;
        if response.status != 200 {
            return Err(Error::unavailable("W3C metadata API request failed."));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = bulk::bounded(&cancel, deadline, async {
            Ok(response.stream.next().await)
        })
        .await?
        {
            let chunk = chunk?;
            if bytes.len().saturating_add(chunk.len()) > 8 * 1024 * 1024 {
                return Err(Error::capacity("W3C metadata API body exceeds bounds."));
            }
            bytes.extend(chunk);
        }
        let artifact = self.raw.capture_bytes(bytes.clone(), cancel).await?;
        Ok((bytes, artifact))
    }
    pub(super) async fn acquire_catalog(&self, cancel: CancellationToken) -> Result<Catalog> {
        let observed_at = devres_domain::unix_now();
        let mut standards = BTreeMap::new();
        let mut captures = Vec::new();
        let previous = self
            .catalog()
            .await
            .ok()
            .map(|c| {
                c.standards
                    .into_iter()
                    .map(|s| (s.id.clone(), s))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let mut page = 1;
        loop {
            let (bytes, artifact) = self
                .api(catalog::ApiOperation::Catalog { page }, cancel.clone())
                .await?;
            let catalog = catalog::parse(&bytes, observed_at)?;
            for mut standard in catalog.standards {
                // Retain discovered source associations across catalog refreshes, never invent them.
                standard.metadata["api_catalog_capture"] = json!(artifact.body_hash);
                if let Some(old) = previous.get(&standard.id) {
                    standard.repository = old.repository.clone();
                    for key in [
                        "repository_admission",
                        "repository_license",
                        "source_mapping",
                        "editor_draft",
                        "latest_tr_url",
                        "publication_url",
                        "versions",
                        "versions_complete",
                        "versions_root",
                        "versions_count",
                        "version_inventory_observed_at",
                        "latest_version_api",
                        "versions_next_page",
                        "versions_pending_count",
                        "versions_has_next",
                        "detail_observed_at",
                    ] {
                        if let Some(v) = old.metadata.get(key) {
                            standard.metadata[key] = v.clone();
                        }
                    }
                }
                if standards.insert(standard.id.clone(), standard).is_some() {
                    return Err(Error::integrity(
                        "Duplicate W3C specification across API pages.",
                    ));
                }
            }
            if standards.len() > catalog::MAX_CATALOG {
                return Err(Error::capacity("W3C catalog count exceeds bounds."));
            }
            captures.push(artifact);
            if !catalog::page_has_next(&bytes)? {
                break;
            }
            page += 1;
            if page > 1000 {
                return Err(Error::capacity(
                    "W3C API catalog pagination exceeds bounds.",
                ));
            }
        }
        if standards.is_empty() {
            return Err(Error::integrity("W3C catalog is empty."));
        }
        let catalog = Catalog {
            id: String::new(),
            observed_at,
            standards: standards.into_values().collect(),
            gaps: Vec::new(),
        };
        let mut catalog = self.reconcile_catalog(catalog, cancel.clone()).await?;
        let id = inventory::digest(
            &serde_json::to_vec(&(&catalog.standards, &catalog.gaps, &captures, observed_at))
                .map_err(|_| failure())?,
        );
        catalog.id = id.clone();
        self.store
            .w3c_put("catalogs", &id, &encode(&catalog)?)
            .await?;
        self.store
            .w3c_put(
                "catalog-captures",
                &id,
                &json!({"api_pages":captures,"observed_at":observed_at}),
            )
            .await?;
        self.store.w3c_set_state("catalog", &json!(id)).await?;
        Ok(catalog)
    }
    pub(super) async fn hydrate_standard(
        &self,
        original: &Standard,
        cancel: CancellationToken,
    ) -> Result<Standard> {
        if original.metadata["detail_observed_at"]
            .as_i64()
            .is_some_and(|t| {
                devres_domain::unix_now().saturating_sub(t)
                    < self.config.catalog_refresh_secs as i64
            })
        {
            return Ok(original.clone());
        }
        let (bytes, capture) = self
            .api(
                catalog::ApiOperation::Specification {
                    shortname: original.id.clone(),
                },
                cancel.clone(),
            )
            .await?;
        let data: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::integrity("Malformed W3C specification metadata."))?;
        let mut standard = original.clone();
        let latest_api = data["_links"]["latest-version"]["href"].as_str();
        let changed =
            latest_api.is_some() && latest_api != original.metadata["latest_version_api"].as_str();
        let refresh = original.metadata["versions_complete"] == true
            && original.metadata["version_inventory_observed_at"]
                .as_i64()
                .is_none_or(|t| {
                    devres_domain::unix_now().saturating_sub(t)
                        >= self.config.catalog_refresh_secs as i64
                });
        if changed || refresh {
            standard.metadata["versions_complete"] = json!(false);
            standard.metadata["versions_next_page"] = json!(1);
            standard.metadata["versions_pending_count"] = json!(0);
            self.store
                .w3c_set_state(&state_key("versions-pending", &standard.id), &json!([]))
                .await?;
        }
        if let Some(latest) = latest_api {
            standard.metadata["latest_version_api"] = json!(latest);
        }
        self.store
            .w3c_put(
                "specification-records",
                &capture.body_hash,
                &json!({"specification":standard.id,"capture":capture,"metadata":data}),
            )
            .await?;
        standard.metadata["specification_metadata"] =
            json!({"shortname":data["shortname"],"title":data["title"]});
        standard.metadata["specification_capture"] = encode(&capture)?;
        if let Some(href) = data["_links"]["latest-version"]["href"].as_str() {
            let prefix = format!(
                "https://api.w3.org/specifications/{}/versions/",
                original.id
            );
            if let Some(version) = href.strip_prefix(&prefix).filter(|v| !v.contains('/')) {
                let (body, capture) = self
                    .api(
                        catalog::ApiOperation::Version {
                            shortname: original.id.clone(),
                            version: version.into(),
                        },
                        cancel,
                    )
                    .await?;
                let value: Value = serde_json::from_slice(&body)
                    .map_err(|_| Error::integrity("Malformed W3C latest version metadata."))?;
                if let Some(uri) = value["uri"].as_str() {
                    let normalized = catalog::PublicationUrl::new(uri)?;
                    standard.metadata["latest_tr_url"] = json!(normalized.as_str());
                    standard.metadata["publication_url"] = json!(normalized.as_str());
                }
                if let Some(editor) = value["editor-draft"]
                    .as_str()
                    .or_else(|| value["editor_draft"].as_str())
                    .or_else(|| value["_links"]["editor-draft"]["href"].as_str())
                    && catalog::PublicationUrl::qualified(editor, &original.url).is_ok()
                {
                    standard.metadata["editor_draft"] = json!(editor);
                }
                standard.metadata["publication_status"] = value["status"].clone();
                self.store
                    .w3c_put(
                        "version-records",
                        &capture.body_hash,
                        &json!({"specification":standard.id,"capture":capture,"metadata":value}),
                    )
                    .await?;
                standard.metadata["latest_version_metadata"] =
                    json!({"uri":value["uri"],"status":value["status"],"date":value["date"]});
                standard.metadata["latest_version_capture"] = encode(&capture)?;
            }
        }
        standard.metadata["detail_observed_at"] = json!(devres_domain::unix_now());
        Ok(standard)
    }
    pub(super) async fn versions_step(
        &self,
        standard: &mut Standard,
        cancel: CancellationToken,
    ) -> Result<()> {
        if standard.metadata["versions_complete"] == true {
            return Ok(());
        }
        let page = standard.metadata["versions_next_page"]
            .as_u64()
            .unwrap_or(1) as u32;
        let mut pending = self
            .store
            .w3c_state(&state_key("versions-pending", &standard.id))
            .await?
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        if pending.is_empty() {
            let (bytes, capture) = self
                .api(
                    catalog::ApiOperation::Versions {
                        shortname: standard.id.clone(),
                        page,
                    },
                    cancel.clone(),
                )
                .await?;
            let data: Value = serde_json::from_slice(&bytes)
                .map_err(|_| Error::integrity("Malformed W3C version inventory."))?;
            pending = data["_embedded"]["version-history"]
                .as_array()
                .or_else(|| data["_links"]["version-history"].as_array())
                .ok_or_else(|| Error::integrity("W3C version inventory entries absent."))?
                .clone();
            if pending.len() > 1000 {
                return Err(Error::capacity("W3C version page count exceeds bounds."));
            }
            pending=pending.into_iter().map(|row|json!({"uri":row["uri"],"status":row["status"],"date":row["date"],"href":row["href"].as_str().or_else(||row["_links"]["self"]["href"].as_str())})).collect();
            standard.metadata["versions_has_next"] = json!(catalog::page_has_next(&bytes)?);
            standard.metadata["versions_capture"] = encode(&capture)?;
        }
        let mut versions = standard.metadata["versions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if !pending.is_empty() {
            let mut row = pending.remove(0);
            let mut row_capture = standard.metadata["versions_capture"].clone();
            if row["uri"].is_null()
                && let Some(href) = row["href"]
                    .as_str()
                    .or_else(|| row["_links"]["self"]["href"].as_str())
            {
                let prefix = format!(
                    "https://api.w3.org/specifications/{}/versions/",
                    standard.id
                );
                if let Some(version) = href.strip_prefix(&prefix).filter(|v| !v.contains('/')) {
                    let (bytes, capture) = self
                        .api(
                            catalog::ApiOperation::Version {
                                shortname: standard.id.clone(),
                                version: version.into(),
                            },
                            cancel,
                        )
                        .await?;
                    row = serde_json::from_slice(&bytes)
                        .map_err(|_| Error::integrity("Malformed W3C version metadata."))?;
                    row_capture = encode(&capture)?;
                }
            }
            if let Some(uri) = row["uri"].as_str() {
                let normalized = catalog::PublicationUrl::new(uri)?;
                row["publication_url"] = json!(normalized.as_str());
            } else {
                row["gap"] = json!("version_publication_uri_unavailable");
            }
            let record_id = inventory::digest(
                &serde_json::to_vec(&(&standard.id, &row, &row_capture)).map_err(|_| failure())?,
            );
            self.store
                .w3c_put(
                    "version-records",
                    &record_id,
                    &json!({"specification":standard.id,"capture":row_capture,"metadata":row}),
                )
                .await?;
            let descriptor = json!({"publication_url":row["publication_url"],"date":row["date"],"status":row["status"],"record":record_id});
            let membership = inventory::digest(
                &serde_json::to_vec(&(&standard.id, &descriptor)).map_err(|_| failure())?,
            );
            let existing = self
                .store
                .w3c_get("version-memberships", &membership)
                .await?;
            if let Some(existing) = existing {
                let id = existing.data.as_str().ok_or_else(failure)?;
                let node = self
                    .store
                    .w3c_get("edition-nodes", id)
                    .await?
                    .ok_or_else(failure)?;
                let root = self
                    .store
                    .w3c_state(&state_key("versions-root", &standard.id))
                    .await?;
                if root
                    .as_ref()
                    .is_none_or(|value| value == &node.data["previous"])
                {
                    self.store
                        .w3c_set_state(&state_key("versions-root", &standard.id), &json!(id))
                        .await?;
                }
            } else {
                let previous = self
                    .store
                    .w3c_state(&state_key("versions-root", &standard.id))
                    .await?
                    .and_then(|v| v.as_str().map(str::to_owned));
                let count = standard.metadata["versions_count"].as_u64().unwrap_or(0) + 1;
                if count > 100000 {
                    return Err(Error::capacity(
                        "W3C edition inventory count exceeds bounds.",
                    ));
                }
                let node = json!({"previous":previous,"entry":descriptor,"count":count,"specification":standard.id});
                let id = inventory::digest(&serde_json::to_vec(&node).map_err(|_| failure())?);
                self.store.w3c_put("edition-nodes", &id, &node).await?;
                self.store
                    .w3c_put("version-memberships", &membership, &json!(id))
                    .await?;
                self.store
                    .w3c_set_state(&state_key("versions-root", &standard.id), &json!(id))
                    .await?;
                standard.metadata["versions_root"] = json!(id);
                standard.metadata["versions_count"] = json!(count);
            }
            if let Some(uri) = descriptor["publication_url"].as_str() {
                let mut frontier = self.publication_frontier(&standard.id).await?;
                if !frontier.iter().any(|u| u == uri) {
                    frontier.push(uri.into());
                    self.retain_publication_frontier(&standard.id, &frontier)
                        .await?;
                }
            }
            if !versions.iter().any(|old| old == &descriptor) {
                versions.push(descriptor);
                if versions.len() > 8 {
                    versions.remove(0);
                }
            }
        }

        if pending.is_empty() {
            if standard.metadata["versions_has_next"] == true {
                standard.metadata["versions_next_page"] = json!(page + 1);
            } else {
                standard.metadata["versions_complete"] = json!(true);
                standard.metadata["version_inventory_observed_at"] =
                    json!(devres_domain::unix_now());
            }
        }
        if let Some(root) = self
            .store
            .w3c_state(&state_key("versions-root", &standard.id))
            .await?
            .and_then(|v| v.as_str().map(str::to_owned))
        {
            let node = self
                .store
                .w3c_get("edition-nodes", &root)
                .await?
                .ok_or_else(failure)?;
            standard.metadata["versions_root"] = json!(root);
            standard.metadata["versions_count"] = node.data["count"].clone();
        }
        standard.metadata["versions"] = json!(versions);
        standard.metadata["versions_pending_count"] = json!(pending.len());
        self.store
            .w3c_set_state(
                &state_key("versions-pending", &standard.id),
                &json!(pending),
            )
            .await?;
        Ok(())
    }
    pub(super) async fn observe_repository(
        &self,
        identity: &str,
        cancel: CancellationToken,
    ) -> Result<Observation> {
        let key = state_key("observation", identity);
        let old: Option<Observation> = self.store.w3c_state(&key).await?.map(decode).transpose()?;
        cleanup_stale_preflights()?;
        let temporary = TemporaryRoot::new()?;
        let repo = Repo::new(identity)?;
        let preflight = W3cGit::new(
            &temporary.0,
            repo,
            self.config.max_git_bytes,
            self.config.min_free_bytes,
            None,
        )?;
        if let Some(old) = &old {
            let durable = self.git(identity)?;
            preflight
                .import_observation(&durable, old, cancel.clone())
                .await?;
        }
        let mut observation = preflight
            .synchronize(
                self.broker.clone(),
                old.as_ref().map(|o| &o.manifest),
                cancel.clone(),
            )
            .await?;
        let mut license = preflight
            .license_preflight(&observation, cancel.clone())
            .await?;
        self.store
            .w3c_set_state(&state_key("repository-license", identity), &license)
            .await?;
        if license["decision"] != "approved" {
            self.store
                .w3c_put(
                    "repository-gaps",
                    &inventory::digest(
                        &serde_json::to_vec(&(identity, &license)).map_err(|_| failure())?,
                    ),
                    &json!({"repository":identity,"license":license,"raw_retained":false}),
                )
                .await?;
            return Err(Error::unavailable(
                "W3C repository archival awaits historical license qualification.",
            ));
        }
        let source_manifest = observation.manifest.body_hash.clone();
        observation = preflight
            .reachable_observation(&observation, cancel.clone())
            .await?;
        license["evidence"]["source_manifest"] = json!(source_manifest);
        license["evidence"]["manifest"] = json!(observation.manifest.body_hash);
        license["evidence"]["archive_scope"] = json!("retained_ref_reachable_objects_only");
        self.store
            .w3c_set_state(&state_key("repository-license", identity), &license)
            .await?;
        let durable = self.git(identity)?;
        durable
            .import_observation(&preflight, &observation, cancel)
            .await?;
        self.store
            .w3c_put(
                "observations",
                &observation.manifest.body_hash,
                &encode(&observation)?,
            )
            .await?;
        self.store
            .w3c_set_state(&key, &encode(&observation)?)
            .await?;
        Ok(observation)
    }
    pub(super) async fn capture_publication_inner(
        &self,
        standard: &Standard,
        url: PublicationUrl,
        cancel: CancellationToken,
        publish_head: bool,
    ) -> Result<Publication> {
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;
        url.validate()?;
        let deadline = Instant::now() + Duration::from_secs(3600);
        let mut response = self
            .broker
            .open(
                BulkRequest {
                    source: BulkSource::W3cPublication(url.clone()),
                    validators: Validators::default(),
                    max_bytes: bulk::MAX_ARTIFACT_BYTES,
                    deadline,
                    body: Vec::new(),
                },
                cancel.clone(),
            )
            .await?;
        let status = response.status;
        let observed_at = devres_domain::unix_now();
        let temporary = TemporaryRoot::new()?;
        let spool = temporary.0.join("document");
        let mut file = tokio::fs::File::create(&spool)
            .await
            .map_err(|_| failure())?;
        let mut bytes = Vec::new();
        let mut total = 0u64;
        let mut hasher = Sha256::new();
        let mut gaps = Vec::new();
        let mut metadata = catalog::PublicationMetadata::default();
        if status == 200 {
            while let Some(chunk) = bulk::bounded(&cancel, deadline, async {
                Ok(response.stream.next().await)
            })
            .await?
            {
                let chunk = chunk?;
                total = total.checked_add(chunk.len() as u64).ok_or_else(failure)?;
                if total > bulk::MAX_ARTIFACT_BYTES
                    || self.raw.quota_bytes().is_some_and(|limit| {
                        self.raw
                            .accounted_bytes()
                            .is_none_or(|bytes| bytes.saturating_add(total) > limit)
                    })
                    || fs2::available_space(&temporary.0).map_err(|_| failure())?
                        < self
                            .config
                            .min_free_bytes
                            .saturating_add(chunk.len() as u64)
                {
                    return Err(Error::capacity(
                        "W3C document preflight storage bounds exceeded.",
                    ));
                }
                hasher.update(&chunk);
                let remaining = MAX_SOURCE.saturating_sub(bytes.len());
                bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                bulk::bounded(&cancel, deadline, async {
                    file.write_all(&chunk).await.map_err(|_| failure())
                })
                .await?;
            }
            file.sync_all().await.map_err(|_| failure())?;
        } else {
            gaps.push(format!("publication_http_{status}"));
        }
        drop(file);
        let body_hash = hex::encode(hasher.finalize());
        let mut license = if status == 200 {
            let source = url.clone();
            let stop = cancel.clone();
            let (license, retained) = tokio::task::spawn_blocking(move || {
                let license = catalog::publication_license_with_cancel(&source, &bytes, stop);
                (license, bytes)
            })
            .await
            .map_err(|_| failure())?;
            bytes = retained;
            cancelled(&cancel)?;
            license
        } else {
            json!({"decision":"unresolved","reason":"publication_unavailable"})
        };
        let inherited = standard.metadata["licensed_alternates"]
            .as_array()
            .is_some_and(|items| items.iter().any(|v| v.as_str() == Some(url.as_str())))
            || standard.metadata["licensed_chapters"]
                .as_array()
                .is_some_and(|items| items.iter().any(|v| v.as_str() == Some(url.as_str())));
        if license["decision"] != "approved"
            && status == 200
            && standard.metadata["license"]["decision"] == "approved"
            && inherited
        {
            license = if let Some(id) = standard.metadata["license"]["publication"].as_str() {
                self.store.w3c_get("publications",id).await?.map(|row|row.data["license"].clone()).unwrap_or_else(||json!({"decision":"unresolved","reason":"governing_publication_missing"}))
            } else {
                standard.metadata["license"].clone()
            };
            license["evidence"]["alternate_source_url"] = json!(url.as_str());
            license["evidence"]["qualification"] =
                json!("explicit_same_document_navigation_or_alternate");
        }
        if status == 200
            && matches!(
                url.kind(),
                catalog::PublicationKind::Html | catalog::PublicationKind::Xml
            )
        {
            if total > MAX_SOURCE as u64 {
                gaps.push("publication_metadata_input_limit".into());
            } else {
                match catalog::publication_metadata(&bytes, &cancel) {
                    Ok(m) => metadata = m,
                    Err(e) if e.code == "cancelled" => return Err(e),
                    Err(e) => gaps.push(format!("publication_metadata_{}", e.code)),
                }
            }
        }
        if license["decision"] == "approved" {
            license["evidence"]["body_hash"] = json!(body_hash);
            license["evidence"]["notice_inspection_bytes"] = json!(bytes.len());
        }
        let artifact = if status == 200 && license["decision"] == "approved" {
            let a = self
                .raw
                .ingest_file(&spool, bulk::MAX_ARTIFACT_BYTES, cancel.clone())
                .await?;
            if a.body_hash != body_hash || a.bytes != total {
                return Err(Error::integrity(
                    "W3C preflight/full capture hash mismatch.",
                ));
            }
            Some(a)
        } else {
            if status == 200 {
                gaps.push("license_unresolved_raw_not_retained".into());
            }
            None
        };
        let id = inventory::digest(
            &serde_json::to_vec(&(
                &standard.id,
                url.as_str(),
                observed_at,
                &artifact,
                status,
                &license,
                catalog::METADATA_VERSION,
            ))
            .map_err(|_| failure())?,
        );
        let chunk_hashes = if let Some(a) = &artifact {
            self.publication_chunks(a, cancel).await?
        } else {
            Vec::new()
        };
        let publication = Publication {
            id: id.clone(),
            standard: standard.id.clone(),
            url,
            observed_at,
            artifact,
            status,
            links: metadata.links,
            repositories: metadata.repositories,
            advertisements: metadata.advertisements,
            exclusions: metadata.exclusions,
            gaps,
            chunk_hashes,
            metadata_version: catalog::METADATA_VERSION,
            metadata_parent: None,
            license,
        };
        self.store
            .w3c_put("publications", &id, &encode(&publication)?)
            .await?;
        if publish_head
            && publication.status == 200
            && publication.artifact.is_some()
            && publication.license["decision"] == "approved"
        {
            self.store
                .w3c_set_state(
                    &state_key("publication-success", publication.url.as_str()),
                    &json!(id),
                )
                .await?;
        }
        if publish_head {
            self.store
                .w3c_set_state(
                    &state_key("publication", publication.url.as_str()),
                    &json!(id),
                )
                .await?;
        }
        Ok(publication)
    }
    pub(super) async fn current_step(&self, cancel: CancellationToken) -> Result<()> {
        let _guard = self.processing.lock().await;
        let mut catalog = match self.catalog().await {
            Ok(c)
                if devres_domain::unix_now().saturating_sub(c.observed_at)
                    < self.config.catalog_refresh_secs as i64 =>
            {
                c
            }
            _ => self.acquire_catalog(cancel.clone()).await?,
        };
        let offset = self
            .store
            .w3c_state("current-offset")
            .await?
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize
            % catalog.standards.len();
        let original = catalog.standards[offset].clone();
        self.store
            .w3c_set_state(
                &state_key("current-attempt", &original.id),
                &json!({"attempted_at":devres_domain::unix_now()}),
            )
            .await?;
        let hydrated = self.hydrate_standard(&original, cancel.clone()).await?;
        let url = catalog::current_publication(&hydrated)?;
        let previous = self
            .store
            .w3c_state(&state_key("publication", url.as_str()))
            .await?
            .and_then(|v| v.as_str().map(str::to_owned));
        let previous: Option<Publication> = match previous {
            Some(id) => self
                .store
                .w3c_get("publications", &id)
                .await?
                .map(|r| decode(r.data))
                .transpose()?,
            None => None,
        };
        let publication = if let Some(p) = previous.filter(|p| {
            devres_domain::unix_now().saturating_sub(p.observed_at)
                < if p.status == 200 && p.artifact.is_some() {
                    self.config.publication_refresh_secs as i64
                } else {
                    60
                }
        }) {
            p
        } else {
            self.capture_publication(&hydrated, url, cancel.clone())
                .await?
        };
        let mut standard = self.resolved_standard(&hydrated, &publication);
        standard.metadata["license"] = compact_license(&publication);
        standard.metadata["licensed_alternates"] = json!(licensed_alternates(&publication));
        standard.metadata["licensed_chapters"] = json!(licensed_chapters(&standard, &publication));
        if let Some(snapshot) = self
            .process_publication(&standard, &publication, cancel.clone())
            .await?
            && self.usable(&snapshot).await?
        {
            self.store.w3c_set_state(&state_key("current",&standard.id),&json!({"snapshot":snapshot.id,"validated_at":publication.observed_at,"latest_publication":standard.metadata["latest_tr_url"],"effective_publication":snapshot.source_url,"fallback":false})).await?;
        } else if let Some(mut selected) = self
            .store
            .w3c_state(&state_key("current", &standard.id))
            .await?
        {
            selected["latest_publication"] = standard.metadata["latest_tr_url"].clone();
            selected["fallback"] = json!(true);
            selected["fallback_reason"] = json!(if publication.status != 200 {
                "latest_publication_unavailable"
            } else {
                "latest_publication_unusable_or_license_unresolved"
            });
            if let Some(id) = selected["snapshot"].as_str() {
                let mut snapshot = self.snapshot(id).await?;
                snapshot.coverage["latest_publication"] =
                    standard.metadata["latest_tr_url"].clone();
                snapshot.coverage["effective_publication"] = json!(snapshot.source_url);
                snapshot.coverage["fallback_reason"] = selected["fallback_reason"].clone();
                snapshot.coverage["fallback"] = json!(true);
                let origin = snapshot.coverage["fallback_origin_snapshot"]
                    .as_str()
                    .unwrap_or(&snapshot.id)
                    .to_owned();
                snapshot.coverage["fallback_origin_snapshot"] = json!(origin);
                snapshot.id = inventory::digest(
                    &serde_json::to_vec(&(&origin, &snapshot.coverage)).map_err(|_| failure())?,
                );
                self.store
                    .w3c_put("snapshots", &snapshot.id, &encode(&snapshot)?)
                    .await?;
                selected["snapshot"] = json!(snapshot.id);
            }
            self.store
                .w3c_set_state(&state_key("current", &standard.id), &selected)
                .await?;
        }
        // Current publication becomes available before potentially expensive source-history work.
        let mut frontier = self.publication_frontier(&standard.id).await?;
        for url in
            catalog::qualified_advertised(&standard, &publication.url, &publication.advertisements)
                .into_iter()
                .chain(catalog::editor_publication(&standard))
        {
            if !frontier.iter().any(|s| s == url.as_str())
                && url.as_str() != publication.url.as_str()
            {
                frontier.push(url.as_str().into());
            }
        }
        self.retain_publication_frontier(&standard.id, &frontier)
            .await?;
        catalog.standards[offset] = standard;
        catalog = self.retain_resolved_catalog(catalog).await?;
        self.store
            .w3c_set_state(
                "current-offset",
                &json!((offset + 1) % catalog.standards.len()),
            )
            .await?;
        self.publish_default(&catalog, cancel).await?;
        self.update_status().await
    }
}
impl W3cCorpus {
    pub(super) async fn freeze_mode(&self, mode: &str, cancel: CancellationToken) -> Result<Value> {
        let _guard = self.processing.lock().await;
        let mut work: FreezeWork = if let Some(value) = self
            .store
            .w3c_state("freezing")
            .await?
            .filter(|v| !v.is_null() && v["mode"] == mode)
        {
            decode(value)?
        } else {
            FreezeWork {
                catalog: self.acquire_catalog(cancel.clone()).await?,
                observations: BTreeMap::new(),
                publications: Vec::new(),
                mode: mode.into(),
                metadata_policy: catalog::METADATA_VERSION,
                standard_offset: 0,
                queue: VecDeque::new(),
                seen: BTreeSet::new(),
            }
        };
        while work.standard_offset < work.catalog.standards.len() {
            cancelled(&cancel)?;
            let original = work.catalog.standards[work.standard_offset].clone();
            let mut standard = self.hydrate_standard(&original, cancel.clone()).await?;
            if mode == "full" {
                while standard.metadata["versions_complete"] != true {
                    self.versions_step(&mut standard, cancel.clone()).await?;
                    work.catalog.standards[work.standard_offset] = standard.clone();
                    self.store
                        .w3c_set_state("freezing", &encode(&work)?)
                        .await?;
                }
            }
            let publication = self
                .capture_publication(
                    &standard,
                    catalog::current_publication(&standard)?,
                    cancel.clone(),
                )
                .await?;
            standard = self.resolved_standard(&standard, &publication);
            standard.metadata["license"] = compact_license(&publication);
            standard.metadata["licensed_alternates"] = json!(licensed_alternates(&publication));
            standard.metadata["licensed_chapters"] =
                json!(licensed_chapters(&standard, &publication));
            work.seen.insert(publication.url.as_str().into());
            work.publications.push(publication.id.clone());
            if mode == "full" && !standard.repository.is_empty() {
                match self
                    .observe_repository(&standard.repository, cancel.clone())
                    .await
                {
                    Ok(observation) => {
                        work.observations.insert(standard.id.clone(), observation);
                    }
                    Err(error) if error.code == "cancelled" => return Err(error),
                    Err(error) => {
                        standard.metadata["repository_gap"] = json!({"code":error.code,"reason":"source_preflight_or_acquisition_unavailable"});
                    }
                }
                if let Some(license) = self
                    .store
                    .w3c_state(&state_key("repository-license", &standard.repository))
                    .await?
                {
                    standard.metadata["repository_license"] = license;
                }
            }
            let urls = if mode == "full" {
                self.edition_urls(&standard).await?
            } else {
                Vec::new()
            };
            for url in urls.into_iter().chain(catalog::qualified_advertised(
                &standard,
                &publication.url,
                &publication.advertisements,
            )) {
                if work.seen.insert(url.as_str().into()) {
                    work.queue.push_back((standard.id.clone(), url));
                }
            }
            work.catalog.standards[work.standard_offset] = standard;
            work.standard_offset += 1;
            self.store
                .w3c_set_state("freezing", &encode(&work)?)
                .await?;
        }
        while let Some((id, url)) = work.queue.front().cloned() {
            cancelled(&cancel)?;
            if work.seen.len() > MAX_PUBLICATIONS {
                return Err(Error::capacity("W3C publication inventory exceeds bounds."));
            }
            let standard = work
                .catalog
                .standards
                .iter()
                .find(|s| s.id == id)
                .ok_or_else(failure)?;
            let publication = self
                .capture_publication(standard, url, cancel.clone())
                .await?;
            if mode == "full" {
                for url in catalog::qualified_advertised(
                    standard,
                    &publication.url,
                    &publication.advertisements,
                ) {
                    if work.seen.insert(url.as_str().into()) {
                        work.queue.push_back((id.clone(), url));
                    }
                }
            }
            work.publications.push(publication.id);
            work.queue.pop_front();
            self.store
                .w3c_set_state("freezing", &encode(&work)?)
                .await?;
        }
        work.catalog = self.retain_resolved_catalog(work.catalog).await?;
        let id = inventory::digest(
            &serde_json::to_vec(&(
                &work.catalog.id,
                &work.observations,
                &work.publications,
                mode,
            ))
            .map_err(|_| failure())?,
        );
        let frozen = Frozen {
            id: id.clone(),
            catalog: work.catalog,
            observations: work.observations,
            publications: work.publications,
            mode: mode.into(),
            lineage: None,
        };
        let value = encode(&frozen)?;
        self.store.w3c_put("frozen", &id, &value).await?;
        self.store.w3c_set_state("freezing", &Value::Null).await?;
        Ok(value)
    }
}
fn licensed_alternates(publication: &Publication) -> Vec<String> {
    let Ok(origin) = url::Url::parse(publication.url.as_str()) else {
        return Vec::new();
    };
    publication
        .advertisements
        .iter()
        .filter(|ad| ad.role == catalog::AdvertisementRole::ExplicitRepresentation)
        .filter_map(|ad| origin.join(&ad.href).ok())
        .filter(|url| url.host_str() == origin.host_str())
        .map(|url| url.to_string())
        .collect()
}
pub(super) fn cleanup_stale_preflights() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let own_uid = std::fs::metadata("/proc/self")
        .map_err(|_| failure())?
        .uid();
    let mut count = 0;
    for entry in std::fs::read_dir("/tmp").map_err(|_| failure())? {
        count += 1;
        if count > 100000 {
            return Err(Error::capacity(
                "W3C preflight temporary namespace exceeds bounds.",
            ));
        }
        let entry = entry.map_err(|_| failure())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(suffix) = name.strip_prefix("devres-w3c-preflight-") else {
            continue;
        };
        let Some((pid, _)) = suffix.split_once('-') else {
            continue;
        };
        if pid.is_empty()
            || !pid.bytes().all(|b| b.is_ascii_digit())
            || std::path::Path::new("/proc").join(pid).exists()
        {
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| failure())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != own_uid {
            continue;
        }
        let marker = entry.path().join("owner-v1");
        let Ok(metadata) = std::fs::symlink_metadata(&marker) else {
            continue;
        };
        if metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == own_uid
            && metadata.len() == 35
            && std::fs::read(&marker).ok().as_deref()
                == Some(b"devres-w3c-disposable-preflight-v1\n")
        {
            std::fs::remove_dir_all(entry.path()).map_err(|_| failure())?;
        }
    }
    Ok(())
}
impl W3cCorpus {
    pub(super) async fn revision_mapping(
        &self,
        standard: &Standard,
        observation: &Observation,
        revision: &str,
        cancel: CancellationToken,
    ) -> Result<Standard> {
        let mut resolved = standard.clone();
        let mapping = &standard.metadata["source_mapping"];
        let prefix = mapping["prefix"].as_str().unwrap_or("").trim_matches('/');
        if mapping["kind"] == "unresolved" {
            return Ok(resolved);
        }
        let advertised_ref = mapping["ref"].as_str().map(|r| format!("refs/heads/{r}"));
        if advertised_ref.as_ref().is_some_and(|name| {
            observation
                .refs
                .iter()
                .any(|r| &r.name == name && r.peeled_commit.as_deref() == Some(revision))
        }) {
            resolved.metadata["source_mapping"]["kind"] = json!("revision_qualified_prefix");
            resolved.metadata["source_mapping"]["revision"] = json!(revision);
            resolved.metadata["source_mapping"]["qualification"] =
                json!("official_source_route_at_advertised_ref");
            return Ok(resolved);
        }
        let git = self.git(&standard.repository)?;
        let mut entrypoints = [
            "Overview.bs",
            "index.bs",
            "Overview.html",
            "index.html",
            "index.xhtml",
            "README.md",
            "Overview.src.html",
        ]
        .iter()
        .map(|name| {
            if prefix.is_empty() {
                (*name).to_owned()
            } else {
                format!("{prefix}/{name}")
            }
        })
        .collect::<Vec<_>>();
        if let Some(path) = mapping["entrypoint"].as_str().filter(|path| {
            path.len() <= 4096
                && !path.starts_with('/')
                && !path.split('/').any(|part| part == "..")
                && !path.chars().any(char::is_control)
        }) && !entrypoints.iter().any(|p| p == path)
        {
            entrypoints.push(path.into());
        }
        for path in entrypoints {
            let Some(entry) = git.entry(revision, &path, cancel.clone()).await? else {
                continue;
            };
            if entry.kind != "blob" || entry.mode == "120000" {
                continue;
            }
            let length = git.blob_size(&entry.oid, cancel.clone()).await?;
            if length > 4 * 1024 * 1024 {
                continue;
            }
            let bytes = git
                .read_blob_known_length(&entry.oid, length, 4 * 1024 * 1024, cancel.clone())
                .await?;
            let Ok(source) = std::str::from_utf8(&bytes) else {
                continue;
            };
            let source_id = source
                .lines()
                .find_map(|line| line.trim().strip_prefix("Shortname:").map(str::trim));
            let level = source
                .lines()
                .find_map(|line| line.trim().strip_prefix("Level:").map(str::trim));
            let bikeshed = source_id.is_some_and(|name| {
                name == standard.id
                    || level.is_some_and(|level| format!("{name}-{level}") == standard.id)
            });
            let identity = catalog::publication_metadata(&bytes, &cancel)
                .ok()
                .is_some_and(|metadata| {
                    metadata.identity_urls.iter().any(|u| {
                        u == &standard.url
                            || standard.metadata["latest_tr_url"].as_str() == Some(u.as_str())
                    })
                });
            if bikeshed || identity {
                resolved.metadata["source_mapping"] = json!({"kind":"revision_qualified_prefix","prefix":prefix,"revision":revision,"evidence_url":mapping["evidence_url"],"entrypoint":path,"oid":entry.oid,"qualification":"captured_revision_declares_specification_identity"});
                return Ok(resolved);
            }
        }
        resolved.metadata["source_mapping"] = json!({"kind":"unresolved","revision":revision,"candidate_prefix":prefix,"reason":"historical_path_association_unproven"});
        Ok(resolved)
    }
}
fn licensed_chapters(standard: &Standard, publication: &Publication) -> Vec<String> {
    let Ok(origin) = url::Url::parse(publication.url.as_str()) else {
        return Vec::new();
    };
    publication
        .advertisements
        .iter()
        .filter(|ad| ad.role == catalog::AdvertisementRole::DocumentNavigation)
        .filter_map(|ad| origin.join(&ad.href).ok())
        .filter(|url| {
            url.host_str() == origin.host_str()
                && url
                    .path()
                    .starts_with(&catalog::edition_root_path(standard, &publication.url))
        })
        .map(|url| url.to_string())
        .collect()
}
impl W3cCorpus {
    pub(super) async fn revision_license(
        &self,
        standard: &Standard,
        revision: &str,
        cancel: CancellationToken,
    ) -> Result<Value> {
        let git = self.git(&standard.repository)?;
        let mut entries = git.records(revision, None, cancel.clone())?;
        let mut notices = Vec::new();
        let mut copyright = Vec::new();
        let mut root_notice = String::new();
        let mut bytes = 0usize;
        while let Some(entry) = entries.recv().await {
            let entry = entry?;
            let basename = entry
                .path
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if entry.kind != "blob"
                || entry.mode == "120000"
                || !source_path_selected(standard, &entry.path)
                || !["license", "licence", "copying", "copyright", "notice"]
                    .iter()
                    .any(|p| basename.starts_with(p))
            {
                continue;
            }
            if notices.len() >= 128 {
                return Err(Error::capacity(
                    "W3C selected revision notice count exceeds bounds.",
                ));
            }
            let raw = git
                .read_blob(&entry.oid, 1024 * 1024, cancel.clone())
                .await?;
            bytes = bytes.saturating_add(raw.len());
            if bytes > 1024 * 1024 {
                return Err(Error::capacity(
                    "W3C selected revision notice bytes exceed bounds.",
                ));
            }
            let text = std::str::from_utf8(&raw)
                .map_err(|_| Error::integrity("W3C qualified notice encoding changed."))?;
            if !entry.path.contains('/') && root_notice.is_empty() {
                root_notice = text.to_owned();
            }
            for line in text
                .lines()
                .filter(|line| line.contains("Copyright") || line.contains('©'))
            {
                if copyright
                    .iter()
                    .map(String::len)
                    .sum::<usize>()
                    .saturating_add(line.len())
                    > 32768
                {
                    return Err(Error::capacity(
                        "W3C original copyright notices exceed bounds.",
                    ));
                }
                if !copyright.iter().any(|s| s == line) {
                    copyright.push(line.to_owned());
                }
            }
            notices.push(json!({"path":entry.path,"oid":entry.oid,"body_hash":inventory::digest(&raw),"source_evidence":{"repository":standard.repository,"revision":revision,"path":entry.path,"oid":entry.oid}}));
        }
        let mut license = standard.metadata["repository_license"].clone();
        let w3c = license["licenses"]
            .as_array()
            .is_some_and(|v| v.iter().any(|v| v == "W3C-Software-and-Document-2023"));
        license["notice"] = json!(if w3c {
            format!("{root_notice}\n\n{}", catalog::W3C_SOFTWARE_NOTICE)
        } else {
            root_notice
        });
        license["copyright"] = json!(copyright.join("\n"));
        license["notices"] = json!(notices);
        license["derived_notice"] = json!(format!(
            "This software or document includes material copied from or derived from {} ({} at revision {}). Original versioned copyright and license notices accompany this extracted projection.",
            standard.title, standard.repository, revision
        ));
        if w3c {
            license["license_url"] = json!("https://www.w3.org/copyright/software-license-2023/");
        }
        Ok(license)
    }
}
fn compact_license(publication: &Publication) -> Value {
    json!({"decision":publication.license["decision"],"license_url":publication.license["license_url"],"publication":publication.id,"reason":publication.license["reason"]})
}
impl W3cCorpus {
    pub(super) async fn edition_urls(&self, standard: &Standard) -> Result<Vec<PublicationUrl>> {
        let mut urls = BTreeMap::new();
        for url in catalog::source_publications(standard, &[])? {
            urls.insert(url.as_str().to_owned(), url);
        }
        let mut root = standard.metadata["versions_root"]
            .as_str()
            .map(str::to_owned);
        let mut seen = BTreeSet::new();
        while let Some(id) = root {
            if seen.len() >= 100000 || !seen.insert(id.clone()) {
                return Err(Error::capacity(
                    "W3C immutable version inventory exceeds bounds.",
                ));
            }
            let node = self
                .store
                .w3c_get("edition-nodes", &id)
                .await?
                .ok_or_else(|| Error::integrity("W3C version inventory node missing."))?;
            if inventory::digest(&serde_json::to_vec(&node.data).map_err(|_| failure())?) != id
                || node.data["specification"].as_str() != Some(&standard.id)
            {
                return Err(Error::integrity("W3C version inventory identity mismatch."));
            }
            if let Some(uri) = node.data["entry"]["publication_url"].as_str() {
                let url = PublicationUrl::new(uri)?;
                urls.insert(url.as_str().to_owned(), url);
            }
            root = node.data["previous"].as_str().map(str::to_owned);
        }
        Ok(urls.into_values().collect())
    }
}
