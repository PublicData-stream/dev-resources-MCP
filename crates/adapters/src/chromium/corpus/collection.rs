use super::*;
use devres_application::collection::{
    CollectorStatus, LimitKind, Phase, ProgressKind, at_phase, http_failure, limited,
};
use quick_xml::{Reader, events::Event};

fn collection_failure(stage: &'static str, error: &Error) {
    let code = match error.code.as_str() {
        "invalid_input" | "unavailable" | "not_found" | "capacity" | "integrity" | "cancelled" => {
            error.code.as_str()
        }
        _ => "other",
    };
    tracing::warn!(target: "devres_server::collection", provider = "chromium", stage, code, "Public collection stage failed");
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Frame {
    path: String,
    tree: String,
    offset: usize,
    inventory: String,
    license: Value,
    #[serde(default)]
    traversal_gaps: u64,
    #[serde(default)]
    traversal_gap_root: Option<String>,
    #[serde(default)]
    excluded_subtrees: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DerivedInventory {
    inventory: String,
    traversal_gaps: u64,
    #[serde(default)]
    traversal_gap_root: Option<String>,
    excluded_subtrees: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Work {
    component: String,
    commit: Commit,
    stack: Vec<Frame>,
    inventory: String,
    observed_at: i64,
    #[serde(default)]
    traversal_gaps: u64,
    #[serde(default)]
    traversal_gap_root: Option<String>,
    #[serde(default)]
    excluded_subtrees: u64,
    #[serde(default)]
    processed_members: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TreeHeader {
    id: String,
    pages: Vec<String>,
    entries: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebWork {
    id: String,
    observed_at: i64,
    validation_min: i64,
    map_after: i64,
    page_after: i64,
    inventory: String,
    discovery_complete: bool,
    #[serde(default)]
    processed_pages: u64,
    #[serde(default)]
    processed_maps: u64,
}

fn work_key(component: &str, revision: &str) -> String {
    state_key(
        "work",
        &format!("{component}:{revision}:{PROCESSOR_VERSION}:{COLLECTION_VERSION}"),
    )
}
fn job_key(component: &str, revision: &str) -> String {
    crate::integrity::legacy_hash(
        format!("{component}:{revision}:{PROCESSOR_VERSION}:{COLLECTION_VERSION}").as_bytes(),
    )
}
fn legacy_job_key(component: &str, revision: &str) -> String {
    crate::integrity::legacy_hash(format!("{component}:{revision}:1").as_bytes())
}
fn scheduling_key(name: &str) -> String {
    format!("{name}-collection-{COLLECTION_VERSION}")
}
fn derived_key(component: &str, tree: &str, path: &str, license: &Value) -> Result<String> {
    Ok(inventory::digest(
        &serde_json::to_vec(&(
            component,
            tree,
            path,
            license,
            PROCESSOR_VERSION,
            COLLECTION_VERSION,
        ))
        .map_err(|_| failure())?,
    ))
}
fn join_path(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.into()
    } else {
        format!("{path}/{name}")
    }
}
fn document_candidate(component: &str, path: &str) -> bool {
    if component == "site"
        && (!path.starts_with("site/") || path.split('/').any(|p| p.starts_with('_')))
    {
        return false;
    }
    if component == "chrome-archive" {
        let parts = path.split('/').collect::<Vec<_>>();
        // The archived site stores language-qualified content under site/<locale>.
        if parts.first() == Some(&"site") && parts.len() > 2 && parts[1] != "en" {
            return false;
        }
    }
    chromium_processing::candidate(path)
}
fn subtree_candidate(component: &str, path: &str) -> bool {
    if !chromium_processing::may_contain_documents(path) {
        return false;
    }
    let parts = path.split('/').collect::<Vec<_>>();
    if component == "site"
        && (parts.first() != Some(&"site") || parts.iter().any(|part| part.starts_with('_')))
    {
        return false;
    }
    !(component == "chrome-archive"
        && parts.first() == Some(&"site")
        && parts.get(1).is_some_and(|part| *part != "en"))
}
fn valid_component(value: &str) -> bool {
    COMPONENTS.contains(&value)
}

impl ChromiumCorpus {
    pub(super) async fn collector_status(
        &self,
        component: &str,
        lane: &str,
    ) -> Result<CollectorStatus> {
        self.store
            .chromium_state(&state_key("collector", &format!("{component}:{lane}")))
            .await?
            .map(decode)
            .transpose()
            .map(|value| value.unwrap_or_default())
    }
    pub(super) async fn save_collector(
        &self,
        component: &str,
        lane: &str,
        status: &CollectorStatus,
    ) -> Result<()> {
        self.store
            .chromium_set_state(
                &state_key("collector", &format!("{component}:{lane}")),
                &encode(status)?,
            )
            .await
    }
    async fn put_gap_manifest(&self, data: &Value) -> Result<String> {
        let id = inventory::digest(&serde_json::to_vec(data).map_err(|_| failure())?);
        self.store
            .chromium_put("traversal-gap-manifests", &id, data)
            .await?;
        Ok(id)
    }
    async fn merge_gap_roots(
        &self,
        left: Option<String>,
        right: Option<String>,
    ) -> Result<Option<String>> {
        let (Some(left), Some(right)) = (left.clone(), right.clone()) else {
            return Ok(left.or(right));
        };
        let a = self
            .store
            .chromium_get("traversal-gap-manifests", &left)
            .await?
            .ok_or_else(failure)?;
        let b = self
            .store
            .chromium_get("traversal-gap-manifests", &right)
            .await?
            .ok_or_else(failure)?;
        let count = a.data["count"]
            .as_u64()
            .and_then(|count| count.checked_add(b.data["count"].as_u64()?))
            .ok_or_else(|| Error::capacity("Chromium traversal gap count exceeds its bound."))?;
        self.put_gap_manifest(&json!({"left":left,"right":right,"count":count}))
            .await
            .map(Some)
    }
    async fn traversal_progress(&self, work: &Work, lane: &str) -> Result<()> {
        let mut status = self.collector_status(&work.component, lane).await?;
        status.progress(ProgressKind::Members, work.processed_members);
        status.progress(
            ProgressKind::TraversalGaps,
            work.traversal_gaps.saturating_add(
                work.stack
                    .iter()
                    .map(|frame| frame.traversal_gaps)
                    .sum::<u64>(),
            ),
        );
        status.progress(
            ProgressKind::ExcludedSubtrees,
            work.excluded_subtrees.saturating_add(
                work.stack
                    .iter()
                    .map(|frame| frame.excluded_subtrees)
                    .sum::<u64>(),
            ),
        );
        self.save_collector(&work.component, lane, &status).await
    }
    async fn request(
        &self,
        operation: &Operation,
        cancel: CancellationToken,
    ) -> Result<source::SourceResponse> {
        cancelled(&cancel)?;
        if self
            .store
            .chromium_state(&state_key("deferred", operation.host()))
            .await?
            .and_then(|value| value["retry_at"].as_i64())
            .is_some_and(|retry| retry > devres_domain::unix_now())
        {
            return Err(Error::unavailable(
                "Chromium provider is deferred until its admitted retry time.",
            ));
        }
        let response = self
            .source
            .fetch(operation, cancel)
            .await
            .map_err(|error| at_phase(error, Phase::PublicationAcquisition))
            .inspect_err(|error| collection_failure("source_acquisition", error))?;
        if let Some(retry_at) = response.retry_at {
            self.store
                .chromium_set_state(
                    &state_key("deferred", operation.host()),
                    &json!({"retry_at":retry_at,"status":response.status}),
                )
                .await?;
        }
        if !matches!(response.status, 200 | 404) {
            tracing::warn!(target: "devres_server::collection", provider = "chromium", stage = "source_http_status", status = response.status, "Public collection stage failed");
            return Err(http_failure(
                Error::unavailable(
                    "Chromium provider response is unavailable; absence is unconfirmed.",
                ),
                Phase::PublicationAcquisition,
                response.status,
            ));
        }
        Ok(response)
    }
    async fn ensure_catalog(&self) -> Result<Catalog> {
        if self
            .store
            .chromium_state("catalog")
            .await
            .map_err(|error| at_phase(error, Phase::CatalogLookup))?
            .is_some()
        {
            return self
                .catalog()
                .await
                .map_err(|error| at_phase(error, Phase::CatalogLookup));
        }
        self.publish_catalog()
            .await
            .map_err(|error| at_phase(error, Phase::CatalogPublication))
    }
    async fn publish_catalog(&self) -> Result<Catalog> {
        let observed_at = devres_domain::unix_now();
        let components = COMPONENTS
            .iter()
            .map(|id| component(id))
            .collect::<Result<Vec<_>>>()?;
        let gaps = vec![
            json!({"component":"chrome","code":"unexposed_migrated_history","detail":"Public archived Git history and observed current HTML are separate; unavailable intervening revisions cannot be reconstructed."}),
        ];
        let id = inventory::digest(
            &serde_json::to_vec(&(observed_at, &components, &gaps)).map_err(|_| failure())?,
        );
        let catalog = Catalog {
            id,
            observed_at,
            components,
            gaps,
        };
        self.store
            .chromium_put("catalogs", &catalog.id, &encode(&catalog)?)
            .await?;
        self.store
            .chromium_set_state("catalog", &json!(catalog.id))
            .await?;
        Ok(catalog)
    }
    async fn enqueue(&self, component: &str, revision: &str) -> Result<()> {
        if !source::valid_oid(revision) || !valid_component(component) {
            return Err(Error::integrity("Invalid Chromium ancestry obligation."));
        }
        let key = job_key(component, revision);
        self.store.chromium_put("jobs",&key,&json!({"component":component,"revision":revision,"processor_version":PROCESSOR_VERSION,"collection_version":COLLECTION_VERSION})).await?;
        Ok(())
    }
    async fn observe_refs(
        &self,
        component: &str,
        namespace: Option<&str>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let scope = namespace.unwrap_or("current");
        let mut page = 1_u32;
        let mut refs = BTreeMap::new();
        let mut observed_at = devres_domain::unix_now();
        let mut exposed = true;
        loop {
            let operation = if namespace.is_none() {
                Operation::CurrentRef {
                    component: component.into(),
                }
            } else if component != "chrome-archive" {
                Operation::RefsNamespace {
                    component: component.into(),
                    namespace: scope.into(),
                }
            } else if page == 1 {
                Operation::Refs {
                    component: component.into(),
                }
            } else {
                Operation::RefsPage {
                    component: component.into(),
                    page,
                }
            };
            let response = self.request(&operation, cancel.clone()).await?;
            let absent_optional = response.status == 404
                && component != "chrome-archive"
                && matches!(namespace, Some("tags" | "branch-heads"));
            if response.status != 200 && !absent_optional {
                return Err(http_failure(
                    Error::unavailable("Chromium ref inventory is unavailable."),
                    Phase::PublicationAcquisition,
                    response.status,
                ));
            }
            exposed &= !absent_optional;
            observed_at = observed_at.min(response.observed_at);
            let mut parsed = if absent_optional {
                BTreeMap::new()
            } else {
                source::parse_refs(component, &response.bytes)
                    .map_err(|error| at_phase(error, Phase::SourceValidation))
                    .inspect_err(|error| collection_failure("source_validation", error))?
            };
            let tags = if absent_optional {
                BTreeMap::new()
            } else {
                source::annotated_tags(component, &response.bytes)
                    .map_err(|error| at_phase(error, Phase::SourceValidation))
                    .inspect_err(|error| collection_failure("source_validation", error))?
            };
            for (name, original) in tags {
                let mut revision = original.clone();
                let mut finished = false;
                for _ in 0..16 {
                    let response = self
                        .request(
                            &Operation::Tag {
                                component: component.into(),
                                revision: revision.clone(),
                            },
                            cancel.clone(),
                        )
                        .await?;
                    if response.status != 200 {
                        return Err(Error::unavailable("Chromium annotated tag is unavailable."));
                    }
                    let tag = source::parse_tag(component, &response.bytes)
                        .map_err(|error| at_phase(error, Phase::SourceValidation))
                        .inspect_err(|error| collection_failure("source_validation", error))?;
                    if tag.revision != revision {
                        return Err(Error::integrity(
                            "Chromium annotated tag identity mismatch.",
                        ));
                    }
                    self.store.chromium_put("tags",&revision,&json!({"component":component,"tag":tag,"source_url":response.source_url})).await?;
                    revision = tag.target;
                    if tag.kind == "commit" {
                        finished = true;
                        break;
                    }
                }
                if !finished {
                    return Err(Error::capacity(
                        "Chromium annotated tag nesting exceeds its bound.",
                    ));
                }
                parsed.insert(name, revision);
            }
            refs.extend(parsed);
            match response.next {
                Some(next) if namespace.is_some() => {
                    let next = next.parse::<u32>().map_err(|_| failure())?;
                    if next != page.checked_add(1).ok_or_else(failure)? {
                        return Err(Error::integrity("Invalid Chromium ref continuation."));
                    }
                    page = next;
                }
                _ => break,
            }
        }
        let current = if namespace.is_none() {
            Some(
                refs.get("refs/heads/main")
                    .or_else(|| refs.get("HEAD"))
                    .cloned()
                    .ok_or_else(|| Error::integrity("Chromium main ref is missing."))?,
            )
        } else {
            None
        };
        let mut changes = refs
            .iter()
            .filter(|(name, _)| name.as_str() != "HEAD")
            .map(|(name, revision)| json!({"name":name,"revision":revision,"removed":false}))
            .collect::<Vec<_>>();
        let observation_key = state_key("observation", &format!("{component}:{scope}"));
        if let Some(previous) = self.store.chromium_state(&observation_key).await? {
            let pages: Vec<String> = decode(previous["ref_pages"].clone())?;
            for id in pages {
                let retained = self
                    .store
                    .chromium_get("ref-pages", &id)
                    .await?
                    .ok_or_else(failure)?;
                let old: Vec<Value> = decode(retained.data)?;
                for item in old {
                    if item["removed"] != true
                        && let Some(name) = item["name"].as_str()
                        && !refs.contains_key(name)
                    {
                        changes
                            .push(json!({"name":name,"revision":item["revision"],"removed":true}));
                    }
                }
            }
        }
        let mut pages = Vec::new();
        for chunk in changes.chunks(500) {
            let data = json!(chunk);
            let id = inventory::digest(&serde_json::to_vec(&data).map_err(|_| failure())?);
            self.store.chromium_put("ref-pages", &id, &data).await?;
            pages.push(id);
        }
        for revision in refs.values().collect::<BTreeSet<_>>() {
            self.enqueue(component, revision).await?;
        }
        let evidence = json!({"component":component,"repository":component_base(component)?,"observed_at":observed_at,"current_revision":current,"namespace":scope,"namespace_exposed":exposed,"refs":[],"ref_pages":pages,"provenance":"https_observed_commit_metadata; blobs_and_exact_trees_oid_verified"});
        let id = inventory::digest(&serde_json::to_vec(&evidence).map_err(|_| failure())?);
        self.store
            .chromium_put("observations", &id, &evidence)
            .await?;
        self.store
            .chromium_set_state(&observation_key, &evidence)
            .await?;
        if let Some(current) = current {
            self.store
                .chromium_set_state(
                    &state_key("current-root", component),
                    &json!({"revision":current,"observed_at":observed_at,"observation":id}),
                )
                .await?;
            self.store
                .chromium_set_state(&state_key("ref-validated", component), &json!(observed_at))
                .await?;
        } else {
            self.store
                .chromium_set_state(
                    &state_key("namespace-validated", &format!("{component}:{scope}")),
                    &json!(observed_at),
                )
                .await?;
        }
        Ok(())
    }
    async fn directory(
        &self,
        component: &str,
        revision: &str,
        path: &str,
        tree: &str,
        cancel: CancellationToken,
    ) -> Result<TreeHeader> {
        if let Some(retained) = self.store.chromium_get("trees", tree).await? {
            return decode(retained.data);
        }
        let operation = Operation::Tree {
            component: component.into(),
            revision: if component == "chrome-archive" {
                tree.into()
            } else {
                revision.into()
            },
            path: if component == "chrome-archive" {
                String::new()
            } else {
                path.into()
            },
        };
        let response = self.request(&operation, cancel).await?;
        if response.status != 200 {
            return Err(Error::unavailable(
                "Chromium historical directory is unavailable.",
            ));
        }
        let directory: Directory = source::parse_tree(component, &response.bytes)
            .map_err(|error| at_phase(error, Phase::SourceValidation))
            .inspect_err(|error| collection_failure("source_validation", error))?;
        if directory.id != tree {
            return Err(Error::integrity(
                "Chromium selected directory differs from its tree identity.",
            ));
        }
        let mut pages = Vec::new();
        for chunk in directory.entries.chunks(500) {
            let data = encode(&chunk)?;
            let id = inventory::digest(&serde_json::to_vec(&data).map_err(|_| failure())?);
            self.store.chromium_put("tree-pages", &id, &data).await?;
            pages.push(id);
        }
        let header = TreeHeader {
            id: directory.id,
            pages,
            entries: directory.entries.len(),
        };
        self.store
            .chromium_put("trees", tree, &encode(&header)?)
            .await?;
        Ok(header)
    }
    async fn tree_entry(&self, header: &TreeHeader, offset: usize) -> Result<Option<Entry>> {
        if offset >= header.entries {
            return Ok(None);
        }
        let id = header
            .pages
            .get(offset / 500)
            .ok_or_else(|| Error::integrity("Chromium tree page missing."))?;
        let row = self
            .store
            .chromium_get("tree-pages", id)
            .await?
            .ok_or_else(failure)?;
        if crate::integrity::verify(id, &serde_json::to_vec(&row.data).map_err(|_| failure())?)
            .is_err()
        {
            return Err(Error::integrity("Chromium tree page hash mismatch."));
        }
        let entries: Vec<Entry> = decode(row.data)?;
        entries
            .get(offset % 500)
            .cloned()
            .map(Some)
            .ok_or_else(|| Error::integrity("Chromium tree entry missing."))
    }
    async fn blob(
        &self,
        component: &str,
        revision: &str,
        path: &str,
        oid: &str,
        cancel: CancellationToken,
    ) -> Result<(Vec<u8>, String)> {
        let response = self
            .request(
                &Operation::Blob {
                    component: component.into(),
                    revision: revision.into(),
                    path: path.into(),
                },
                cancel,
            )
            .await?;
        if response.status != 200 {
            return Err(Error::not_found("Chromium document body is unavailable."));
        }
        let bytes = source::decode_blob(component, &response.bytes, oid)
            .map_err(|error| at_phase(error, Phase::SourceValidation))
            .inspect_err(|error| collection_failure("source_validation", error))?;
        Ok((bytes, response.source_url))
    }
    async fn local_license(
        &self,
        component: &str,
        revision: &str,
        path: &str,
        header: &TreeHeader,
        parent: &Value,
        cancel: CancellationToken,
    ) -> Result<Value> {
        // An uninspectable governing notice cannot be overridden by inheriting
        // some other convenient terms while traversing the same affected scope.
        if parent["gap"] == "unsupported_notice_path" {
            return Ok(parent.clone());
        }
        let cache_key = inventory::digest(
            &serde_json::to_vec(&(component, path, &header.id, parent)).map_err(|_| failure())?,
        );
        if let Some(row) = self
            .store
            .chromium_get("license-scopes", &cache_key)
            .await?
        {
            return Ok(row.data);
        }
        let mut license = parent.clone();
        for offset in 0..header.entries {
            let entry = self.tree_entry(header, offset).await?.ok_or_else(failure)?;
            if entry.kind != "blob" || !licensing::license_name(&entry.name) {
                continue;
            }
            let full = join_path(path, &entry.name);
            if !source::valid_path(&full) || !inventory::valid_path(&full) {
                license = licensing::unresolved(component, "unrequestable_notice");
                license["gap"] = json!("unsupported_notice_path");
                break;
            }
            let notice_key = inventory::digest(
                &serde_json::to_vec(&(component, &full, &entry.oid)).map_err(|_| failure())?,
            );
            if let Some(row) = self
                .store
                .chromium_get("notice-objects", &notice_key)
                .await?
            {
                license = row.data;
                continue;
            }
            let (bytes, url) = self
                .blob(component, revision, &full, &entry.oid, cancel.clone())
                .await?;
            license = match std::str::from_utf8(&bytes) {
                Ok(text) => licensing::qualify(component, text, &url),
                Err(_) => licensing::unresolved(component, &full),
            };
            if license["decision"] == "approved" {
                let artifact = self
                    .raw
                    .capture_bytes_bounded(bytes, MAX_SOURCE as u64, cancel.clone())
                    .await
                    .map_err(|error| at_phase(error, Phase::RawRetention))?;
                license["artifact"] = encode(&artifact)?;
                self.store
                    .chromium_put(
                        "license-notices",
                        &inventory::digest(&serde_json::to_vec(&license).map_err(|_| failure())?),
                        &license,
                    )
                    .await?;
            }
            license["notice_oid"] = json!(entry.oid);
            self.store
                .chromium_put("notice-objects", &notice_key, &license)
                .await?;
            // More-specific unknown or conflicting notices block the whole scope.
            if license["decision"] != "approved" {
                break;
            }
        }
        self.store
            .chromium_put("license-scopes", &cache_key, &license)
            .await?;
        Ok(license)
    }
    async fn site_license(
        &self,
        revision: &str,
        root: &TreeHeader,
        cancel: CancellationToken,
    ) -> Result<Value> {
        let mut header = root.clone();
        let mut path = String::new();
        for name in ["site", "_includes"] {
            let mut found = None;
            for offset in 0..header.entries {
                let entry = self
                    .tree_entry(&header, offset)
                    .await?
                    .ok_or_else(failure)?;
                if entry.name == name && entry.kind == "tree" {
                    found = Some(entry);
                    break;
                }
            }
            let Some(entry) = found else {
                return Ok(licensing::unresolved("site", "website_footer"));
            };
            path = join_path(&path, name);
            header = self
                .directory("site", revision, &path, &entry.oid, cancel.clone())
                .await?;
        }
        // Check all possible governing footer names before accepting an earlier
        // readable footer; an unrequestable sibling remains unresolved evidence.
        for offset in 0..header.entries {
            let entry = self
                .tree_entry(&header, offset)
                .await?
                .ok_or_else(failure)?;
            let full = join_path(&path, &entry.name);
            if entry.kind == "blob"
                && (entry.name.to_ascii_lowercase().contains("footer")
                    || entry.name.to_ascii_lowercase().contains("sidebar"))
                && (!source::valid_path(&full) || !inventory::valid_path(&full))
            {
                let mut license = licensing::unresolved("site", "unrequestable_footer");
                license["gap"] = json!("unsupported_notice_path");
                return Ok(license);
            }
        }
        for offset in 0..header.entries {
            let entry = self
                .tree_entry(&header, offset)
                .await?
                .ok_or_else(failure)?;
            if entry.kind == "blob"
                && (entry.name.to_ascii_lowercase().contains("footer")
                    || entry.name.to_ascii_lowercase().contains("sidebar"))
            {
                let full = join_path(&path, &entry.name);
                if !source::valid_path(&full) || !inventory::valid_path(&full) {
                    let mut license = licensing::unresolved("site", "unrequestable_footer");
                    license["gap"] = json!("unsupported_notice_path");
                    return Ok(license);
                }
                let notice_key = inventory::digest(
                    &serde_json::to_vec(&("site", &full, &entry.oid)).map_err(|_| failure())?,
                );
                if let Some(row) = self
                    .store
                    .chromium_get("notice-objects", &notice_key)
                    .await?
                {
                    return Ok(row.data);
                }
                let (bytes, url) = self
                    .blob("site", revision, &full, &entry.oid, cancel.clone())
                    .await?;
                let Ok(text) = std::str::from_utf8(&bytes) else {
                    continue;
                };
                let mut license = licensing::qualify("site", text, &url);
                if license["decision"] == "approved" {
                    let artifact = self
                        .raw
                        .capture_bytes_bounded(bytes, MAX_SOURCE as u64, cancel.clone())
                        .await
                        .map_err(|error| at_phase(error, Phase::RawRetention))?;
                    license["artifact"] = encode(&artifact)?;
                    license["notice_oid"] = json!(entry.oid);
                    self.store
                        .chromium_put("notice-objects", &notice_key, &license)
                        .await?;
                    return Ok(license);
                }
            }
        }
        Ok(licensing::unresolved("site", "website_footer"))
    }
    async fn begin_work(
        &self,
        component: &str,
        revision: &str,
        observed_at: i64,
        cancel: CancellationToken,
    ) -> Result<Option<Work>> {
        let key = job_key(component, revision);
        let retained = match self.store.chromium_get("commits", &key).await? {
            Some(row) => Some(row),
            None => {
                self.store
                    .chromium_get("commits", &legacy_job_key(component, revision))
                    .await?
            }
        };
        let commit: Commit = if let Some(row) = retained {
            if row.data["component"] != component {
                return Err(Error::integrity(
                    "Chromium retained commit component mismatch.",
                ));
            }
            decode(row.data["commit"].clone())?
        } else {
            let response = self
                .request(
                    &Operation::Commit {
                        component: component.into(),
                        revision: revision.into(),
                    },
                    cancel.clone(),
                )
                .await?;
            if response.status == 404 {
                self.store.chromium_put("history-gaps",&key,&json!({"component":component,"revision":revision,"code":"historical_commit_unavailable"})).await?;
                self.store
                    .chromium_set_state(&state_key("completed", &key), &json!(true))
                    .await?;
                return Ok(None);
            }
            let commit = source::parse_commit(component, &response.bytes)
                .map_err(|error| at_phase(error, Phase::SourceValidation))
                .inspect_err(|error| collection_failure("source_validation", error))?;
            if commit.revision != revision {
                return Err(Error::integrity("Chromium commit identity mismatch."));
            }
            self.store.chromium_put("commits",&key,&json!({"component":component,"repository":component_base(component)?,"commit":commit,"source_url":response.source_url,"verification":"https_metadata"})).await?;
            commit
        };
        if commit.revision != revision {
            return Err(Error::integrity(
                "Chromium retained commit revision mismatch.",
            ));
        }
        for parent in &commit.parents {
            self.enqueue(component, parent).await?;
        }
        let root = self
            .directory(component, revision, "", &commit.tree, cancel.clone())
            .await?;
        let inherited = if component == "site" {
            self.site_license(revision, &root, cancel.clone()).await?
        } else {
            licensing::unresolved(component, "")
        };
        let license = self
            .local_license(component, revision, "", &root, &inherited, cancel)
            .await?;
        let inventory = inventory::empty(self.store.as_ref()).await?;
        Ok(Some(Work {
            component: component.into(),
            commit: commit.clone(),
            stack: vec![Frame {
                path: String::new(),
                tree: commit.tree,
                offset: 0,
                inventory: inventory.clone(),
                license,
                traversal_gaps: 0,
                traversal_gap_root: None,
                excluded_subtrees: 0,
            }],
            inventory,
            observed_at,
            traversal_gaps: 0,
            traversal_gap_root: None,
            excluded_subtrees: 0,
            processed_members: 0,
        }))
    }
    async fn retain_member(
        &self,
        component: &str,
        revision: &str,
        path: &str,
        entry: &Entry,
        license: &Value,
        cancel: CancellationToken,
    ) -> Result<Member> {
        let mut member = Member {
            path: path.into(),
            oid: entry.oid.clone(),
            mode: format!("{:o}", entry.mode),
            kind: "document".into(),
            projection: None,
            raw: None,
            gaps: Vec::new(),
        };
        if license["decision"] != "approved" {
            member.gaps.push("license_scope_unresolved".into());
            if license["gap"] == "unsupported_notice_path" {
                member.gaps.push("license_notice_unrequestable".into());
            }
            return Ok(member);
        }
        let cache_key = inventory::digest(
            &serde_json::to_vec(&(component, path, &entry.oid, license, PROCESSOR_VERSION))
                .map_err(|_| failure())?,
        );
        if let Some(row) = self
            .store
            .chromium_get("document-members", &cache_key)
            .await?
        {
            return decode(row.data);
        }
        let (bytes, url) = match self
            .blob(component, revision, path, &entry.oid, cancel.clone())
            .await
        {
            Ok(value) => value,
            Err(error) if error.code == "not_found" => {
                member.gaps.push("document_body_unavailable".into());
                return Ok(member);
            }
            Err(error) if matches!(error.code.as_str(), "capacity" | "integrity") => {
                member.gaps.push(format!("acquisition_{}", error.code));
                return Ok(member);
            }
            Err(error) => return Err(error),
        };
        let license = licensing::body_license(license, &bytes, &url);
        if license["decision"] != "approved" {
            member.gaps.push("license_scope_unresolved".into());
            return Ok(member);
        }
        let artifact = self
            .raw
            .capture_bytes_bounded(bytes.clone(), MAX_SOURCE as u64, cancel.clone())
            .await
            .map_err(|error| at_phase(error, Phase::RawRetention))?;
        let chunks = self.publication_chunks(&artifact, cancel.clone()).await?;
        member.raw = Some(
            json!({"artifact":artifact,"source_url":url,"license":license,"chunk_hashes":chunks,"revision":revision}),
        );
        match self
            .project(&super::component(component)?, path, "git", bytes, cancel)
            .await
            .map_err(|error| at_phase(error, Phase::Projection))
        {
            Ok((projection, gaps)) => {
                member.projection = Some(projection);
                member.gaps = gaps;
            }
            Err(error) if error.code == "cancelled" => return Err(error),
            Err(error)
                if matches!(
                    error.code.as_str(),
                    "invalid_input" | "integrity" | "capacity"
                ) =>
            {
                member.gaps.push(format!("processing_{}", error.code))
            }
            Err(error) => return Err(error),
        }
        self.store
            .chromium_put("document-members", &cache_key, &encode(&member)?)
            .await?;
        Ok(member)
    }
    async fn commit_step(
        &self,
        component: &str,
        revision: &str,
        observed_at: i64,
        lane: &str,
        cancel: CancellationToken,
    ) -> Result<bool> {
        let key = job_key(component, revision);
        if self
            .store
            .chromium_state(&state_key("completed", &key))
            .await?
            == Some(json!(true))
        {
            return Ok(true);
        }
        let checkpoint = work_key(component, revision);
        let mut work: Work = match self.store.chromium_state(&checkpoint).await? {
            Some(value) => decode(value)?,
            None => match self
                .begin_work(component, revision, observed_at, cancel.clone())
                .await?
            {
                Some(work) => work,
                None => return Ok(true),
            },
        };
        let mut cache = inventory::NodeCache::new();
        // Each slice checkpoints after bounded work; directory frames never hold full trees.
        for _ in 0..64 {
            cancelled(&cancel)?;
            let Some(frame) = work.stack.last().cloned() else {
                break;
            };
            let derived = derived_key(component, &frame.tree, &frame.path, &frame.license)?;
            if frame.offset == 0
                && let Some(row) = self
                    .store
                    .chromium_get("derived-inventories", &derived)
                    .await?
            {
                let cached: DerivedInventory = decode(row.data)?;
                let root = cached.inventory;
                work.stack.pop();
                if let Some(parent) = work.stack.last_mut() {
                    parent.traversal_gaps += cached.traversal_gaps;
                    parent.traversal_gap_root = self
                        .merge_gap_roots(
                            parent.traversal_gap_root.clone(),
                            cached.traversal_gap_root.clone(),
                        )
                        .await?;
                    parent.excluded_subtrees += cached.excluded_subtrees;
                    let name = frame.path.rsplit('/').next().ok_or_else(failure)?;
                    parent.inventory = inventory::graft_cached(
                        self.store.as_ref(),
                        &parent.inventory,
                        name,
                        &root,
                        &mut cache,
                    )
                    .await?;
                } else {
                    work.inventory = root;
                    work.traversal_gaps = cached.traversal_gaps;
                    work.traversal_gap_root = cached.traversal_gap_root;
                    work.excluded_subtrees = cached.excluded_subtrees;
                }
                continue;
            }
            let header = self
                .directory(
                    component,
                    revision,
                    &frame.path,
                    &frame.tree,
                    cancel.clone(),
                )
                .await?;
            let Some(entry) = self.tree_entry(&header, frame.offset).await? else {
                self.store
                    .chromium_put(
                        "derived-inventories",
                        &derived,
                        &encode(&DerivedInventory {
                            inventory: frame.inventory.clone(),
                            traversal_gaps: frame.traversal_gaps,
                            traversal_gap_root: frame.traversal_gap_root.clone(),
                            excluded_subtrees: frame.excluded_subtrees,
                        })?,
                    )
                    .await?;
                work.stack.pop();
                if let Some(parent) = work.stack.last_mut() {
                    parent.traversal_gaps += frame.traversal_gaps;
                    parent.traversal_gap_root = self
                        .merge_gap_roots(
                            parent.traversal_gap_root.clone(),
                            frame.traversal_gap_root.clone(),
                        )
                        .await?;
                    parent.excluded_subtrees += frame.excluded_subtrees;
                    let name = frame.path.rsplit('/').next().ok_or_else(failure)?;
                    parent.inventory = inventory::graft_cached(
                        self.store.as_ref(),
                        &parent.inventory,
                        name,
                        &frame.inventory,
                        &mut cache,
                    )
                    .await?;
                } else {
                    work.inventory = frame.inventory;
                    work.traversal_gaps = frame.traversal_gaps;
                    work.traversal_gap_root = frame.traversal_gap_root;
                    work.excluded_subtrees = frame.excluded_subtrees;
                }
                continue;
            };
            let path = join_path(&frame.path, &entry.name);
            if entry.kind == "tree" && !subtree_candidate(component, &path) {
                if let Some(last) = work.stack.last_mut() {
                    last.offset += 1;
                    last.excluded_subtrees += 1;
                }
                self.store
                    .chromium_set_state(&checkpoint, &encode(&work)?)
                    .await?;
                continue;
            }
            if !inventory::valid_path(&path)
                || !source::valid_path(&path)
                || (entry.kind == "tree" && work.stack.len() >= 64)
            {
                let gap = json!({"component":component,"revision":revision,"parent_tree":frame.tree,"member_oid":entry.oid,"path_hash":inventory::digest(path.as_bytes()),"code":if entry.kind == "tree" && work.stack.len() >= 64 {"tree_depth_exceeded"} else {"unsupported_path"},"collection_version":COLLECTION_VERSION});
                let gap_id = inventory::digest(&serde_json::to_vec(&gap).map_err(|_| failure())?);
                self.store
                    .chromium_put("traversal-gaps", &gap_id, &gap)
                    .await?;
                let leaf = self
                    .put_gap_manifest(&json!({"gap":gap_id,"count":1}))
                    .await?;
                if let Some(last) = work.stack.last_mut() {
                    last.offset += 1;
                    last.traversal_gaps += 1;
                    last.traversal_gap_root = self
                        .merge_gap_roots(last.traversal_gap_root.clone(), Some(leaf))
                        .await?;
                }
                self.store
                    .chromium_set_state(&checkpoint, &encode(&work)?)
                    .await?;
                continue;
            }
            if let Some(last) = work.stack.last_mut() {
                last.offset += 1;
            }
            if entry.kind == "tree" {
                let header = self
                    .directory(component, revision, &path, &entry.oid, cancel.clone())
                    .await?;
                let license = self
                    .local_license(
                        component,
                        revision,
                        &path,
                        &header,
                        &frame.license,
                        cancel.clone(),
                    )
                    .await?;
                work.stack.push(Frame {
                    path,
                    tree: entry.oid,
                    offset: 0,
                    inventory: inventory::empty(self.store.as_ref()).await?,
                    license,
                    traversal_gaps: 0,
                    traversal_gap_root: None,
                    excluded_subtrees: 0,
                });
            } else if entry.kind == "blob"
                && entry.mode & 0o170000 == 0o100000
                && document_candidate(component, &path)
            {
                work.processed_members += 1;
                let member = self
                    .retain_member(
                        component,
                        revision,
                        &path,
                        &entry,
                        &frame.license,
                        cancel.clone(),
                    )
                    .await?;
                if let Some(last) = work.stack.last_mut() {
                    last.inventory = inventory::update_cached(
                        self.store.as_ref(),
                        &last.inventory,
                        &entry.name,
                        Some(member),
                        &mut cache,
                    )
                    .await?;
                }
            }
            self.store
                .chromium_set_state(&checkpoint, &encode(&work)?)
                .await?;
        }
        self.store
            .chromium_set_state(&checkpoint, &encode(&work)?)
            .await?;
        self.traversal_progress(&work, lane).await?;
        if !work.stack.is_empty() {
            return Ok(false);
        }
        if let Some(root) = &work.traversal_gap_root {
            self.verify_gap_manifest(root, work.traversal_gaps, &cancel)
                .await
                .map_err(|error| at_phase(error, Phase::ArtifactVerification))?;
        } else if work.traversal_gaps != 0 {
            return Err(at_phase(
                Error::integrity("Chromium traversal gap coverage root is missing."),
                Phase::ArtifactVerification,
            ));
        }
        let metadata = inventory::node(self.store.as_ref(), &work.inventory).await?;
        let index = self
            .flush_index(std::slice::from_ref(&work.inventory), cancel.clone())
            .await
            .map_err(|error| at_phase(error, Phase::IndexPublication))?;
        let coverage = json!({"accounted":true,"usable":metadata.searchable>0,"documents":metadata.members,"projection_gaps":metadata.gaps,"index_gaps":0,"license":{"decision":"approved","scope":"qualified_retained_members_only"},"ancestry":"parent_closure_queued","raw_commit_verification":"https_metadata","classifier_version":chromium_processing::CLASSIFIER_VERSION,"collection_version":COLLECTION_VERSION,"traversal_gaps":work.traversal_gaps,"traversal_gap_root":work.traversal_gap_root,"excluded_subtrees":work.excluded_subtrees,"complete":work.traversal_gaps==0 && metadata.gaps==0});
        let id = inventory::digest(
            &serde_json::to_vec(&(
                component,
                revision,
                &work.inventory,
                PROCESSOR_VERSION,
                COLLECTION_VERSION,
                &work.traversal_gap_root,
                &index,
            ))
            .map_err(|_| failure())?,
        );
        let snapshot = Snapshot {
            id: id.clone(),
            component: component.into(),
            repository: component_base(component)?.into(),
            revision: revision.into(),
            tree: work.commit.tree,
            parents: work.commit.parents,
            committed_at: work.commit.committed_at,
            inventory: work.inventory,
            processor_version: PROCESSOR_VERSION,
            index,
            coverage,
            source_url: format!("{}#revision={revision}", component_base(component)?),
            representation: "git".into(),
            validated_at: work.observed_at,
        };
        self.store
            .chromium_put("snapshots", &id, &encode(&snapshot)?)
            .await?;
        let alias = alias(component, &snapshot.repository, revision, "git")?;
        self.store
            .chromium_put("snapshot-keys", &alias, &json!(id))
            .await?;
        self.store
            .chromium_set_state(&state_key("completed", &key), &json!(true))
            .await?;
        Ok(true)
    }
    async fn finish_pending_index(&self, cancel: CancellationToken) -> Result<()> {
        let Some(pending) = self
            .store
            .chromium_state("index-pending")
            .await?
            .filter(|v| !v.is_null())
        else {
            return Ok(());
        };
        let generation = pending["generation"].as_u64().ok_or_else(failure)?;
        let ids: Vec<String> = decode(pending["ids"].clone())?;
        self.index
            .prewarm(&pending["reference"], cancel.clone())
            .await?;
        for chunk in ids.chunks(500) {
            cancelled(&cancel)?;
            let rows = chunk
                .iter()
                .map(|id| devres_application::chromium::Write {
                    kind: "indexed".into(),
                    key: format!("{generation}:{id}"),
                    data: json!(true),
                })
                .collect::<Vec<_>>();
            self.store.chromium_put_many(&rows).await?;
        }
        self.store
            .chromium_set_state(
                &format!("index-generation:{generation}"),
                &pending["reference"],
            )
            .await?;
        self.store
            .chromium_set_state("index", &pending["reference"])
            .await?;
        self.store
            .chromium_set_state("index-pending", &Value::Null)
            .await
    }
    async fn flush_index(&self, roots: &[String], cancel: CancellationToken) -> Result<Value> {
        self.finish_pending_index(cancel.clone()).await?;
        let generation = self
            .store
            .chromium_state("index-generation")
            .await?
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let index_state = format!("index-generation:{generation}");
        let mut reference = self.store.chromium_state(&index_state).await?;
        let mut selected = BTreeSet::new();
        for root in roots {
            for member in inventory::members(self.store.as_ref(), root, MAX_MEMBERS).await? {
                if let Some(id) = member.projection {
                    let row = self
                        .store
                        .chromium_get("projections", &id)
                        .await?
                        .ok_or_else(failure)?;
                    selected.extend(self.projection_members(&row.data).await?);
                    if selected.len() > MAX_MEMBERS {
                        return Err(Error::capacity(
                            "Chromium selected index membership exceeds its bound.",
                        ));
                    }
                }
            }
        }
        let generation = self
            .store
            .chromium_state("index-generation")
            .await?
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let context = format!("chromium-v{PROCESSOR_VERSION}-generation-{generation}");
        let selected = selected.into_iter().collect::<Vec<_>>();
        for chunk in selected.chunks(500) {
            cancelled(&cancel)?;
            let indexed = self
                .store
                .chromium_existing(
                    "indexed",
                    &chunk
                        .iter()
                        .map(|id| format!("{generation}:{id}"))
                        .collect::<Vec<_>>(),
                )
                .await?;
            let missing = chunk
                .iter()
                .filter(|id| !indexed.contains(&format!("{generation}:{id}")))
                .cloned()
                .collect::<Vec<_>>();
            if missing.is_empty() {
                continue;
            }
            let mut documents = Vec::new();
            for row in self
                .store
                .chromium_get_many("index-documents", &missing)
                .await?
            {
                documents.push(decode::<IndexDocument>(row.data)?);
            }
            if documents.len() != missing.len() {
                return Err(Error::integrity("Chromium index input is missing."));
            }
            let next = self
                .index
                .publish_generation(reference.as_ref(), documents, cancel.clone(), &context)
                .await?;
            // Journal the durable new chain before publishing completion markers.
            // Every replay completes this exact batch before constructing another shard.
            self.store
                .chromium_set_state(
                    "index-pending",
                    &json!({"generation":generation,"reference":next,"ids":missing}),
                )
                .await?;
            self.finish_pending_index(cancel.clone()).await?;
            reference = Some(next);
        }
        match reference {
            Some(reference) => Ok(reference),
            None => {
                let reference = self
                    .index
                    .publish_generation(None, Vec::new(), cancel, &context)
                    .await?;
                self.store
                    .chromium_set_state(&index_state, &reference)
                    .await?;
                self.store.chromium_set_state("index", &reference).await?;
                Ok(reference)
            }
        }
    }
    async fn begin_web(&self) -> Result<()> {
        let observed_at = devres_domain::unix_now();
        let id = inventory::digest(
            &serde_json::to_vec(&("chrome", observed_at, PROCESSOR_VERSION, COLLECTION_VERSION))
                .map_err(|_| failure())?,
        );
        let work = WebWork {
            id: id.clone(),
            observed_at,
            validation_min: observed_at,
            map_after: 0,
            page_after: 0,
            inventory: inventory::empty(self.store.as_ref()).await?,
            discovery_complete: false,
            processed_pages: 0,
            processed_maps: 0,
        };
        self.store
            .chromium_put(
                "web-map-jobs",
                &format!("{id}:root"),
                &json!({"work":id,"path":"sitemap.xml","depth":0}),
            )
            .await?;
        self.store
            .chromium_set_state(&scheduling_key("web-work"), &encode(&work)?)
            .await?;
        Ok(())
    }
    async fn web_step(&self, cancel: CancellationToken) -> Result<bool> {
        let Some(value) = self
            .store
            .chromium_state(&scheduling_key("web-work"))
            .await?
        else {
            return Ok(true);
        };
        let mut work: WebWork = decode(value)?;
        let mut status = self.collector_status("chrome", "current").await?;
        status.phase = Some(if work.discovery_complete {
            Phase::PublicationAcquisition
        } else {
            Phase::SitemapDiscovery
        });
        status.progress(ProgressKind::Pages, work.processed_pages);
        status.progress(ProgressKind::Batches, work.processed_maps);
        self.save_collector("chrome", "current", &status).await?;
        if !work.discovery_complete {
            let rows = self
                .store
                .chromium_rows("web-map-jobs", work.map_after, 1, None)
                .await?;
            if let Some(row) = rows.first() {
                work.map_after = row.sequence;
                if row.data["work"] == work.id {
                    let path = row.data["path"].as_str().ok_or_else(failure)?;
                    let depth = row.data["depth"].as_u64().ok_or_else(failure)?;
                    if depth > 16 {
                        return Err(limited(
                            Error::capacity("Chromium sitemap recursion exceeds its bound."),
                            Phase::SitemapDiscovery,
                            LimitKind::TreeDepth,
                            Some(depth),
                            Some(16),
                        ));
                    }
                    let response = self
                        .request(&Operation::Sitemap { path: path.into() }, cancel.clone())
                        .await?;
                    if response.status != 200 {
                        return Err(Error::unavailable(
                            "Chromium sitemap inventory is unavailable.",
                        ));
                    }
                    let (maps, pages) = sitemap_locations(&response.bytes)
                        .map_err(|error| at_phase(error, Phase::SourceValidation))
                        .inspect_err(|error| collection_failure("source_validation", error))?;
                    for path in maps {
                        let id = inventory::digest(format!("{}:{path}", work.id).as_bytes());
                        self.store
                            .chromium_put(
                                "web-map-jobs",
                                &id,
                                &json!({"work":work.id,"path":path,"depth":depth+1}),
                            )
                            .await?;
                    }
                    for path in pages {
                        let id = inventory::digest(format!("{}:{path}", work.id).as_bytes());
                        self.store
                            .chromium_put(
                                "web-page-jobs",
                                &id,
                                &json!({"work":work.id,"path":path}),
                            )
                            .await?;
                    }
                    work.processed_maps += 1;
                    let id = inventory::digest(&response.bytes);
                    self.store.chromium_put("sitemaps",&id,&json!({"source_url":response.source_url,"observed_at":response.observed_at,"body_hash":id,"work":work.id})).await?;
                }
                self.store
                    .chromium_set_state(&scheduling_key("web-work"), &encode(&work)?)
                    .await?;
                return Ok(false);
            }
            work.discovery_complete = true;
            self.store
                .chromium_set_state(&scheduling_key("web-work"), &encode(&work)?)
                .await?;
        }
        let rows = self
            .store
            .chromium_rows("web-page-jobs", work.page_after, 1, None)
            .await?;
        if let Some(row) = rows.first() {
            if row.data["work"] == work.id {
                let path = row.data["path"].as_str().ok_or_else(failure)?;
                let response = self
                    .request(&Operation::Page { path: path.into() }, cancel.clone())
                    .await?;
                let mut member = Member {
                    path: path.into(),
                    oid: inventory::digest(&response.bytes),
                    mode: "100644".into(),
                    kind: "document".into(),
                    projection: None,
                    raw: None,
                    gaps: Vec::new(),
                };
                if response.status == 404 {
                    member.gaps.push("document_body_unavailable".into());
                } else {
                    let license = std::str::from_utf8(&response.bytes)
                        .map(|body| licensing::qualify("chrome", body, &response.source_url))
                        .unwrap_or_else(|_| licensing::unresolved("chrome", path));
                    if license["decision"] != "approved" {
                        tracing::warn!(target: "devres_server::collection", provider = "chromium", stage = "publication_license", code = "unresolved", "Public collection stage withheld");
                        member.gaps.push("license_scope_unresolved".into());
                    } else {
                        let artifact = self
                            .raw
                            .capture_bytes_bounded(
                                response.bytes.clone(),
                                MAX_SOURCE as u64,
                                cancel.clone(),
                            )
                            .await
                            .map_err(|error| at_phase(error, Phase::RawRetention))?;
                        let chunks = self.publication_chunks(&artifact, cancel.clone()).await?;
                        member.raw = Some(
                            json!({"artifact":artifact,"source_url":response.source_url,"license":license,"chunk_hashes":chunks,"observed_at":response.observed_at}),
                        );
                        match self
                            .project(
                                &component("chrome")?,
                                path,
                                "html",
                                response.bytes,
                                cancel.clone(),
                            )
                            .await
                        {
                            Ok((id, gaps)) => {
                                member.projection = Some(id);
                                member.gaps = gaps;
                            }
                            Err(error) if error.code == "cancelled" => return Err(error),
                            Err(error)
                                if matches!(
                                    error.code.as_str(),
                                    "invalid_input" | "integrity" | "capacity"
                                ) =>
                            {
                                collection_failure("publication_projection", &error);
                                member.gaps.push(format!("processing_{}", error.code))
                            }
                            Err(error) => return Err(error),
                        }
                    }
                }
                if response.status == 200
                    && member.raw.is_some()
                    && member.projection.is_none()
                    && let Some(selected) = self
                        .store
                        .chromium_state(&state_key("current", "chrome"))
                        .await?
                {
                    let old = self
                        .snapshot(selected["snapshot"].as_str().ok_or_else(failure)?)
                        .await?;
                    if let Some(mut retained) = self.member(&old, path).await?
                        && retained.projection.is_some()
                    {
                        let failed = encode(&member)?;
                        self.store
                            .chromium_put(
                                "failed-pages",
                                &inventory::digest(
                                    &serde_json::to_vec(&failed).map_err(|_| failure())?,
                                ),
                                &failed,
                            )
                            .await?;
                        let validated = retained
                            .raw
                            .as_ref()
                            .and_then(|raw| raw["observed_at"].as_i64())
                            .unwrap_or(old.validated_at);
                        work.validation_min = work.validation_min.min(validated);
                        retained
                            .gaps
                            .push("newer_projection_failed_previous_retained".into());
                        member = retained;
                    }
                }
                work.inventory =
                    inventory::update(self.store.as_ref(), &work.inventory, path, Some(member))
                        .await?;
                work.processed_pages += 1;
            }
            work.page_after = row.sequence;
            self.store
                .chromium_set_state(&scheduling_key("web-work"), &encode(&work)?)
                .await?;
            return Ok(false);
        }
        let inventory_node = inventory::node(self.store.as_ref(), &work.inventory).await?;
        if inventory_node.members == 0 {
            return Err(Error::integrity(
                "Chromium website discovery contains no English editorial documents.",
            ));
        }
        let index = self
            .flush_index(std::slice::from_ref(&work.inventory), cancel.clone())
            .await
            .map_err(|error| at_phase(error, Phase::IndexPublication))?;
        let revision = inventory::digest(
            &serde_json::to_vec(&(&work.id, &work.inventory)).map_err(|_| failure())?,
        );
        let observation = json!({"component":"chrome","repository":component_base("chrome")?,"current_revision":revision,"observed_at":work.validation_min,"acquisition_started_at":work.observed_at,"inventory":work.inventory,"work":work.id,"refs":[],"ref_pages":[],"history_gap":"unexposed_migrated_history"});
        let observation_id =
            inventory::digest(&serde_json::to_vec(&observation).map_err(|_| failure())?);
        self.store
            .chromium_put("observations", &observation_id, &observation)
            .await?;
        let id = inventory::digest(
            &serde_json::to_vec(&(
                "chrome",
                &revision,
                &work.inventory,
                PROCESSOR_VERSION,
                COLLECTION_VERSION,
                &index,
            ))
            .map_err(|_| failure())?,
        );
        let snapshot = Snapshot {
            id: id.clone(),
            component: "chrome".into(),
            repository: component_base("chrome")?.into(),
            revision: revision.clone(),
            tree: inventory::digest(work.inventory.as_bytes()),
            parents: Vec::new(),
            committed_at: work.observed_at,
            inventory: work.inventory,
            index,
            processor_version: PROCESSOR_VERSION,
            coverage: json!({"accounted":true,"usable":inventory_node.searchable>0,"collection_version":COLLECTION_VERSION,"documents":inventory_node.members,"projection_gaps":inventory_node.gaps,"index_gaps":0,"license":{"decision":"approved","scope":"qualified_retained_members_only"},"observation":observation_id,"history_gap":"unexposed_migrated_history"}),
            source_url: component_base("chrome")?.into(),
            representation: "html".into(),
            validated_at: work.validation_min,
        };
        self.store
            .chromium_put("snapshots", &id, &encode(&snapshot)?)
            .await?;
        if snapshot.coverage["usable"] == true {
            self.store
                .chromium_set_state(
                    &state_key("current", "chrome"),
                    &json!({"snapshot":id,"validated_at":work.validation_min}),
                )
                .await?;
        }
        self.store
            .chromium_set_state(&scheduling_key("web-completed"), &json!(work.id))
            .await?;
        self.store
            .chromium_set_state(&scheduling_key("web-work"), &Value::Null)
            .await?;
        self.store
            .chromium_set_state(
                &state_key("publication-validated-v2", "chrome"),
                &json!(work.observed_at),
            )
            .await?;
        Ok(true)
    }
    async fn publish_default(&self, cancel: CancellationToken) -> Result<()> {
        let catalog = self.ensure_catalog().await?;
        let mut snapshots = BTreeMap::new();
        let mut validations = BTreeMap::new();
        let mut roots = Vec::new();
        for component in ["src", "site", "chrome"] {
            if let Some(value) = self
                .store
                .chromium_state(&state_key("current", component))
                .await?
            {
                let id = value["snapshot"].as_str().ok_or_else(failure)?;
                let validated = value["validated_at"].as_i64().ok_or_else(failure)?;
                let snapshot = self.snapshot(id).await?;
                let gaps = snapshot.coverage["traversal_gaps"].as_u64().unwrap_or(0);
                if let Some(root) = snapshot.coverage["traversal_gap_root"].as_str() {
                    self.verify_gap_manifest(root, gaps, &cancel)
                        .await
                        .map_err(|error| at_phase(error, Phase::ArtifactVerification))?;
                } else if gaps != 0 {
                    return Err(at_phase(
                        Error::integrity("Chromium traversal gap coverage root is missing."),
                        Phase::ArtifactVerification,
                    ));
                }
                if snapshot.coverage["accounted"] != true
                    || snapshot.coverage["usable"] != true
                    || devres_domain::unix_now().saturating_sub(validated) > 7 * 86400
                {
                    continue;
                }
                roots.push(snapshot.inventory);
                snapshots.insert(component.into(), id.into());
                validations.insert(component.into(), validated);
            }
        }
        if snapshots.is_empty() {
            return Ok(());
        }
        let index = self
            .flush_index(&roots, cancel)
            .await
            .map_err(|error| at_phase(error, Phase::IndexPublication))?;
        let validated_at = validations
            .values()
            .copied()
            .min()
            .unwrap_or(catalog.observed_at)
            .min(catalog.observed_at);
        let id = inventory::digest(
            &serde_json::to_vec(&(&catalog.id, &snapshots, &index, &validations, validated_at))
                .map_err(|_| failure())?,
        );
        self.store
            .chromium_publish_view(&View {
                id,
                catalog: catalog.id,
                snapshots,
                index,
                validations,
                validated_at,
            })
            .await
            .map_err(|error| at_phase(error, Phase::ViewPublication))
    }
    pub async fn collect_current_once(&self, cancel: CancellationToken) -> Result<bool> {
        let _guard = self.processing.lock().await;
        self.current_step(true, cancel).await
    }
    async fn current_step(&self, refresh: bool, cancel: CancellationToken) -> Result<bool> {
        let catalog = self.ensure_catalog().await?;
        let now = devres_domain::unix_now();
        if refresh
            && now.saturating_sub(catalog.observed_at) >= self.config.catalog_refresh_secs as i64
        {
            self.publish_catalog().await?;
        }
        let offset = self
            .store
            .chromium_state(&scheduling_key("current-offset"))
            .await?
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let selected = COMPONENTS[offset % COMPONENTS.len()];
        self.store
            .chromium_set_state(
                &scheduling_key("current-offset"),
                &json!((offset + 1) % COMPONENTS.len()),
            )
            .await?;
        let host = match selected {
            "chrome" => "developer.chrome.com",
            "chrome-archive" => "api.github.com",
            _ => "chromium.googlesource.com",
        };
        if self
            .store
            .chromium_state(&state_key("deferred", host))
            .await?
            .and_then(|value| value["retry_at"].as_i64())
            .is_some_and(|retry| retry > now)
        {
            let mut status = self.collector_status(selected, "current").await?;
            status.active = false;
            status.retry_at = self
                .store
                .chromium_state(&state_key("deferred", host))
                .await?
                .and_then(|value| value["retry_at"].as_i64());
            self.save_collector(selected, "current", &status).await?;
            self.update_status().await?;
            return self.current_complete().await;
        }
        let mut status = self.collector_status(selected, "current").await?;
        status.begin(if selected == "chrome" {
            Phase::SitemapDiscovery
        } else {
            Phase::Traversal
        });
        self.save_collector(selected, "current", &status).await?;
        let result = self
            .current_component_step(selected, refresh, now, cancel)
            .await;
        let mut status = self.collector_status(selected, "current").await?;
        if selected == "chrome"
            && let Some(value) = self
                .store
                .chromium_state(&scheduling_key("web-work"))
                .await?
                .filter(|value| !value.is_null())
        {
            let work: WebWork = decode(value)?;
            status.progress(ProgressKind::Pages, work.processed_pages);
            status.progress(ProgressKind::Batches, work.processed_maps);
        }
        let retry_at = self
            .store
            .chromium_state(&state_key("deferred", host))
            .await?
            .and_then(|value| value["retry_at"].as_i64())
            .unwrap_or(0)
            .max(devres_domain::unix_now() + 60);
        match &result {
            Ok(_) => status.succeed(devres_domain::unix_now()),
            Err(error) => status.fail(
                error,
                Phase::Traversal,
                devres_domain::unix_now(),
                Some(retry_at),
            ),
        }
        self.save_collector(selected, "current", &status).await?;
        self.update_status()
            .await
            .map_err(|error| at_phase(error, Phase::StatusRead))?;
        result
    }
    async fn current_component_step(
        &self,
        selected: &str,
        refresh: bool,
        now: i64,
        cancel: CancellationToken,
    ) -> Result<bool> {
        if selected == "chrome" {
            let state = self
                .store
                .chromium_state(&scheduling_key("web-work"))
                .await?
                .filter(|v| !v.is_null());
            let validated = self
                .store
                .chromium_state(&state_key("publication-validated-v2", "chrome"))
                .await?
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if state.is_none()
                && refresh
                && now.saturating_sub(validated) >= self.config.publication_refresh_secs as i64
            {
                self.begin_web().await?;
            }
            if self
                .store
                .chromium_state(&scheduling_key("web-work"))
                .await?
                .is_some_and(|v| !v.is_null())
            {
                self.web_step(cancel.clone()).await?;
            }
        } else {
            let validated = self
                .store
                .chromium_state(&state_key("ref-validated", selected))
                .await?
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let active = self
                .store
                .chromium_state(&state_key("current-root", selected))
                .await?;
            let in_progress = if let Some(root) = active {
                let revision = root["revision"].as_str().ok_or_else(failure)?;
                self.store
                    .chromium_state(&state_key("completed", &job_key(selected, revision)))
                    .await?
                    != Some(json!(true))
            } else {
                false
            };
            if refresh
                && !in_progress
                && now.saturating_sub(validated) >= self.config.ref_refresh_secs as i64
            {
                self.observe_refs(selected, None, cancel.clone()).await?;
            }
            if let Some(root) = self
                .store
                .chromium_state(&state_key("current-root", selected))
                .await?
            {
                let revision = root["revision"].as_str().ok_or_else(failure)?;
                let observed = root["observed_at"].as_i64().ok_or_else(failure)?;
                if self
                    .commit_step(selected, revision, observed, "current", cancel.clone())
                    .await?
                    && selected != "chrome-archive"
                    && let Some(snapshot) = self
                        .snapshot_for_revision(selected, component_base(selected)?, revision, "git")
                        .await?
                    && snapshot.coverage["usable"] == true
                {
                    self.store
                        .chromium_set_state(
                            &state_key("current", selected),
                            &json!({"snapshot":snapshot.id,"validated_at":observed}),
                        )
                        .await?;
                }
            }
        }
        self.publish_default(cancel).await?;
        self.update_status().await?;
        self.current_complete().await
    }
    async fn current_complete(&self) -> Result<bool> {
        for component in ["src", "site", "chrome-archive"] {
            let Some(root) = self
                .store
                .chromium_state(&state_key("current-root", component))
                .await?
            else {
                return Ok(false);
            };
            let revision = root["revision"].as_str().ok_or_else(failure)?;
            if self
                .store
                .chromium_state(&state_key("completed", &job_key(component, revision)))
                .await?
                != Some(json!(true))
            {
                return Ok(false);
            }
        }
        Ok(self
            .store
            .chromium_state(&scheduling_key("web-work"))
            .await?
            .is_none_or(|v| v.is_null())
            && self
                .store
                .chromium_state(&scheduling_key("web-completed"))
                .await?
                .is_some())
    }
    pub async fn collect_history_once(&self, cancel: CancellationToken) -> Result<bool> {
        let _guard = self.processing.lock().await;
        self.history_step(true, cancel).await
    }
    async fn process_history_job(&self, data: &Value, cancel: CancellationToken) -> Result<()> {
        let component = data["component"].as_str().ok_or_else(failure)?;
        let revision = data["revision"].as_str().ok_or_else(failure)?;
        let key = job_key(component, revision);
        let mut status = self.collector_status(component, "history").await?;
        status.begin(Phase::Traversal);
        self.save_collector(component, "history", &status).await?;
        let result = self
            .commit_step(component, revision, 0, "history", cancel)
            .await;
        let mut status = self.collector_status(component, "history").await?;
        let delay = if result
            .as_ref()
            .err()
            .is_some_and(|error| matches!(error.code.as_str(), "capacity" | "integrity"))
        {
            self.config.ref_refresh_secs as i64
        } else {
            60
        };
        let host = if component == "chrome-archive" {
            "api.github.com"
        } else {
            "chromium.googlesource.com"
        };
        let retry_at = self
            .store
            .chromium_state(&state_key("deferred", host))
            .await?
            .and_then(|value| value["retry_at"].as_i64())
            .unwrap_or(0)
            .max(devres_domain::unix_now() + delay);
        match &result {
            Ok(_) => status.succeed(devres_domain::unix_now()),
            Err(error) => status.fail(
                error,
                Phase::Traversal,
                devres_domain::unix_now(),
                Some(retry_at),
            ),
        }
        self.save_collector(component, "history", &status).await?;
        match result {
            Ok(true) => {
                self.store
                    .chromium_set_state(&state_key("blocked", &key), &json!({"done":true}))
                    .await?;
            }
            result => {
                let (code, retry_at) = match result {
                    Ok(_) => ("in_progress".to_owned(), 0),
                    Err(error) if error.code == "cancelled" => return Err(error),
                    Err(error) => {
                        let retry = devres_domain::unix_now()
                            + if matches!(error.code.as_str(), "capacity" | "integrity") {
                                self.config.ref_refresh_secs as i64
                            } else {
                                60
                            };
                        let gap = json!({"component":component,"revision":revision,"job":key,"code":error.code});
                        self.store
                            .chromium_put(
                                "history-gaps",
                                &inventory::digest(
                                    &serde_json::to_vec(&gap).map_err(|_| failure())?,
                                ),
                                &gap,
                            )
                            .await?;
                        (error.code, retry)
                    }
                };
                self.store.chromium_put("blocked-jobs", &key, &json!({"component":component,"revision":revision,"processor_version":PROCESSOR_VERSION,"collection_version":COLLECTION_VERSION})).await?;
                self.store
                    .chromium_set_state(
                        &state_key("blocked", &key),
                        &json!({"done":false,"code":code,"retry_at":retry_at}),
                    )
                    .await?;
            }
        }
        Ok(())
    }
    async fn history_step(&self, discover: bool, cancel: CancellationToken) -> Result<bool> {
        if discover {
            let offset = self
                .store
                .chromium_state(&scheduling_key("namespace-offset"))
                .await?
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            let namespaces = [
                ("src", "heads"),
                ("site", "heads"),
                ("src", "tags"),
                ("site", "tags"),
                ("src", "branch-heads"),
                ("site", "branch-heads"),
                ("chrome-archive", "all"),
            ];
            let (component, namespace) = namespaces[offset % namespaces.len()];
            self.store
                .chromium_set_state(
                    &scheduling_key("namespace-offset"),
                    &json!((offset + 1) % namespaces.len()),
                )
                .await?;
            let key = state_key("namespace-validated", &format!("{component}:{namespace}"));
            let validated = self
                .store
                .chromium_state(&key)
                .await?
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if devres_domain::unix_now().saturating_sub(validated)
                >= self.config.ref_refresh_secs as i64
                && let Err(error) = self
                    .observe_refs(component, Some(namespace), cancel.clone())
                    .await
            {
                if error.code == "cancelled" {
                    return Err(error);
                }
                let data = json!({"component":component,"namespace":namespace,"code":error.code,"observed_at":devres_domain::unix_now()});
                self.store
                    .chromium_put(
                        "history-gaps",
                        &inventory::digest(&serde_json::to_vec(&data).map_err(|_| failure())?),
                        &data,
                    )
                    .await?;
                // Bounded failed inventory cannot prevent main ancestry progress.
                self.store
                    .chromium_set_state(&key, &json!(devres_domain::unix_now()))
                    .await?;
            }
        }
        let after = self
            .store
            .chromium_state(&scheduling_key("history-after"))
            .await?
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let rows = self.store.chromium_rows("jobs", after, 1, None).await?;
        if let Some(row) = rows.first() {
            self.process_history_job(&row.data, cancel).await?;
            self.store
                .chromium_set_state(&scheduling_key("history-after"), &json!(row.sequence))
                .await?;
            self.store
                .chromium_set_state(&scheduling_key("history-exhausted"), &json!(false))
                .await?;
            self.update_status().await?;
            return Ok(false);
        }
        let after = self
            .store
            .chromium_state(&scheduling_key("blocked-after"))
            .await?
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let rows = self
            .store
            .chromium_rows("blocked-jobs", after, 100, None)
            .await?;
        if rows.is_empty() {
            let pending = self
                .store
                .chromium_state(&scheduling_key("blocked-cycle-pending"))
                .await?
                == Some(json!(true));
            self.store
                .chromium_set_state(&scheduling_key("blocked-after"), &json!(0))
                .await?;
            self.store
                .chromium_set_state(&scheduling_key("blocked-cycle-pending"), &json!(false))
                .await?;
            self.store
                .chromium_set_state(&scheduling_key("history-exhausted"), &json!(!pending))
                .await?;
            self.update_status().await?;
            return Ok(!pending);
        }
        for row in rows {
            self.store
                .chromium_set_state(&scheduling_key("blocked-after"), &json!(row.sequence))
                .await?;
            let component = row.data["component"].as_str().ok_or_else(failure)?;
            let revision = row.data["revision"].as_str().ok_or_else(failure)?;
            let status = match self
                .store
                .chromium_state(&state_key("blocked", &job_key(component, revision)))
                .await?
            {
                Some(status) => status,
                None => self
                    .store
                    .chromium_state(&state_key("blocked", &row.key))
                    .await?
                    .ok_or_else(failure)?,
            };
            if status["done"] == true {
                continue;
            }
            self.store
                .chromium_set_state(&scheduling_key("blocked-cycle-pending"), &json!(true))
                .await?;
            let host = if component == "chrome-archive" {
                "api.github.com"
            } else {
                "chromium.googlesource.com"
            };
            let deferred = self
                .store
                .chromium_state(&state_key("deferred", host))
                .await?
                .and_then(|value| value["retry_at"].as_i64())
                .unwrap_or(0);
            if deferred.max(status["retry_at"].as_i64().unwrap_or(0)) <= devres_domain::unix_now() {
                self.process_history_job(&row.data, cancel).await?;
                break;
            }
        }
        self.store
            .chromium_set_state(&scheduling_key("history-exhausted"), &json!(false))
            .await?;
        self.update_status().await?;
        Ok(false)
    }
    async fn record_failure(&self, lane: &str, error: &Error) -> Result<()> {
        self.store
            .chromium_set_state("failure", &{
                let mut status = CollectorStatus::default();
                status.fail(
                    error,
                    Phase::Traversal,
                    devres_domain::unix_now(),
                    Some(devres_domain::unix_now() + 60),
                );
                let mut failure = encode(&status.failure)?;
                failure["lane"] = json!(lane);
                failure
            })
            .await?;
        self.update_status().await
    }
    pub(super) async fn update_status(&self) -> Result<()> {
        let catalog = if self
            .store
            .chromium_state("catalog")
            .await
            .map_err(|error| at_phase(error, Phase::CatalogLookup))?
            .is_some()
        {
            Some(
                self.catalog()
                    .await
                    .map_err(|error| at_phase(error, Phase::CatalogLookup))?,
            )
        } else {
            None
        };
        let view = if self.store.chromium_state("default").await?.is_some() {
            Some(
                self.view(None)
                    .await
                    .map_err(|error| at_phase(error, Phase::StatusRead))?,
            )
        } else {
            None
        };
        let statistics = self.store.chromium_statistics().await?;
        let mut components = BTreeMap::new();
        for component in COMPONENTS {
            let selected = match &view {
                Some(view) => view.snapshots.get(component).cloned(),
                None => None,
            };
            let validated = view
                .as_ref()
                .and_then(|v| v.validations.get(component))
                .copied();
            components.insert(component,json!({"selected_snapshot":selected,"validated_at":validated,"missing":selected.is_none(),"historical_only":component=="chrome-archive","collector":{"current":self.collector_status(component,"current").await?,"history":self.collector_status(component,"history").await?},"stale":validated.is_none_or(|v|devres_domain::unix_now().saturating_sub(v)>86400)}));
        }
        self.store.chromium_set_state("status",&json!({"processor_version":PROCESSOR_VERSION,"classifier_version":chromium_processing::CLASSIFIER_VERSION,"collection_version":COLLECTION_VERSION,"collection_enabled":self.config.enabled,"catalog":catalog.as_ref().map(|c|&c.id),"catalog_components":catalog.as_ref().map_or(0,|c|c.components.len()),"components":components,"statistics":statistics,"snapshots":statistics["snapshots"],"projection_gaps":statistics["projection_gaps"],"index_gaps":statistics["index_gaps"],"gap_scope":"all_retained_snapshot_generations","view":view.as_ref().map(|v|&v.id),"published_components":view.as_ref().map_or(0,|v|v.snapshots.len()),"history_queue_exhausted":self.store.chromium_state(&scheduling_key("history-exhausted")).await?.unwrap_or(json!(false)),"history_gap":"unexposed_migrated_history","failure":self.store.chromium_state("failure").await?,"archive_bytes":self.raw.accounted_bytes(),"archive_quota_bytes":self.raw.quota_bytes()})).await
    }
    pub async fn run_current(&self, cancel: CancellationToken) -> Result<()> {
        if let Err(error) = self.recover(cancel.clone()).await {
            if cancel.is_cancelled() {
                return Ok(());
            }
            self.record_failure("recovery", &error).await?;
        }
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let mut delay = self.config.collection_interval_secs;
            if self.config.enabled
                && let Err(error) = self.collect_current_once(cancel.clone()).await
            {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                self.record_failure("current", &error).await?;
                delay = 60;
            }
            tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(delay))=>{}}
        }
    }
    pub async fn run_history(&self, cancel: CancellationToken) -> Result<()> {
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let mut delay = self.config.collection_interval_secs;
            if self.config.enabled {
                let result = if let Ok(_guard) = self.processing.try_lock() {
                    self.history_step(true, cancel.clone()).await
                } else {
                    Ok(false)
                };
                if let Err(error) = result {
                    if cancel.is_cancelled() {
                        return Ok(());
                    }
                    self.record_failure("history", &error).await?;
                    delay = 60;
                }
            }
            tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(delay))=>{}}
        }
    }
    pub async fn recover(&self, cancel: CancellationToken) -> Result<()> {
        let _guard = self.processing.lock().await;
        self.raw.recover_stages().await?;
        self.index.recover_stages()?;
        self.finish_pending_index(cancel.clone()).await?;
        if let Some(index) = self.store.chromium_state("index").await? {
            self.index.prewarm(&index, cancel).await?;
        }
        Ok(())
    }
    pub async fn rebuild_index(&self, cancel: CancellationToken) -> Result<Value> {
        let _guard = self.processing.lock().await;
        let generation = self
            .store
            .chromium_state("index-generation")
            .await?
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            + 1;
        // Rebuild owns the processing fence and starts a fresh derived chain.
        // A corrupt pending chain cannot be replayed, so retain its journal as
        // immutable recovery evidence and retire only the mutable pending pointer.
        if let Some(pending) = self
            .store
            .chromium_state("index-pending")
            .await?
            .filter(|value| !value.is_null())
        {
            let retired = json!({"pending":pending,"successor_generation":generation,"reason":"fresh_index_rebuild"});
            let id = inventory::digest(&serde_json::to_vec(&retired).map_err(|_| failure())?);
            self.store
                .chromium_put("index-recoveries", &id, &retired)
                .await?;
            self.store
                .chromium_set_state("index-pending", &Value::Null)
                .await?;
        }
        self.store
            .chromium_set_state("index-generation", &json!(generation))
            .await?;
        // Old snapshot references are immutable. Rebuild produces successor snapshots.
        let cutoff = self.store.chromium_cutoff().await?;
        let mut after = 0;
        let mut rebuilt = 0;
        loop {
            let rows = self
                .store
                .chromium_rows("snapshots", after, 100, Some(cutoff))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                cancelled(&cancel)?;
                let old: Snapshot = decode(row.data)?;
                let index = self
                    .flush_index(std::slice::from_ref(&old.inventory), cancel.clone())
                    .await?;
                let mut successor = old.clone();
                successor.index = index;
                successor.id = inventory::digest(
                    &serde_json::to_vec(&(&old.id, generation, &successor.index))
                        .map_err(|_| failure())?,
                );
                successor.coverage["rebuild_parent"] = json!(old.id);
                self.store
                    .chromium_put("snapshots", &successor.id, &encode(&successor)?)
                    .await?;
                let revision_alias = alias_for_collection(
                    &successor.component,
                    &successor.repository,
                    &successor.revision,
                    &successor.representation,
                    successor.coverage["collection_version"]
                        .as_u64()
                        .unwrap_or(1) as u32,
                )?;
                self.store
                    .chromium_set_state(
                        &state_key("revision-alias", &revision_alias),
                        &json!(successor.id),
                    )
                    .await?;
                for component in ["src", "site", "chrome"] {
                    if let Some(mut value) = self
                        .store
                        .chromium_state(&state_key("current", component))
                        .await?
                        && value["snapshot"] == old.id
                    {
                        value["snapshot"] = json!(successor.id);
                        self.store
                            .chromium_set_state(&state_key("current", component), &value)
                            .await?;
                    }
                }
                rebuilt += 1;
            }
        }
        self.publish_default(cancel).await?;
        self.update_status().await?;
        Ok(
            json!({"rebuilt_snapshots":rebuilt,"generation":generation,"validation_times_preserved":true}),
        )
    }
    pub async fn freeze_current_observation(&self, cancel: CancellationToken) -> Result<Value> {
        self.freeze(false, cancel).await
    }
    pub async fn freeze_observation(&self, cancel: CancellationToken) -> Result<Value> {
        self.freeze(true, cancel).await
    }
    async fn freeze(&self, full: bool, cancel: CancellationToken) -> Result<Value> {
        // A freeze first captures current web bodies. Afterwards resume never
        // refreshes refs, sitemaps or moving publications.
        loop {
            if self.collect_current_once(cancel.clone()).await? {
                break;
            }
            cancelled(&cancel)?;
        }
        let mut namespaces = BTreeMap::new();
        if full {
            for (component, namespace) in [
                ("src", "heads"),
                ("site", "heads"),
                ("src", "tags"),
                ("site", "tags"),
                ("src", "branch-heads"),
                ("site", "branch-heads"),
                ("chrome-archive", "all"),
            ] {
                self.observe_refs(component, Some(namespace), cancel.clone())
                    .await?;
                let evidence = self
                    .store
                    .chromium_state(&state_key(
                        "observation",
                        &format!("{component}:{namespace}"),
                    ))
                    .await?
                    .ok_or_else(failure)?;
                namespaces.insert(
                    format!("{component}:{namespace}"),
                    inventory::digest(&serde_json::to_vec(&evidence).map_err(|_| failure())?),
                );
            }
        }
        let mut roots = BTreeMap::new();
        for component in ["src", "site", "chrome-archive"] {
            roots.insert(
                component,
                self.store
                    .chromium_state(&state_key("current-root", component))
                    .await?
                    .ok_or_else(failure)?,
            );
        }
        let evidence = json!({"version":1,"processor_version":PROCESSOR_VERSION,"collection_version":COLLECTION_VERSION,"mode":if full{"full"}else{"current"},"catalog":self.catalog().await?.id,"roots":roots,"namespaces":namespaces,"web":self.store.chromium_state(&scheduling_key("web-completed")).await?,"cutoff":self.store.chromium_cutoff().await?});
        let id = inventory::digest(&serde_json::to_vec(&evidence).map_err(|_| failure())?);
        self.store.chromium_put("freezes", &id, &evidence).await?;
        Ok(json!({"id":id,"evidence":evidence}))
    }
    async fn validate_frozen(&self, frozen: &Value) -> Result<()> {
        let id = frozen["id"]
            .as_str()
            .ok_or_else(|| Error::invalid("Chromium frozen observation missing."))?;
        let row = self
            .store
            .chromium_get("freezes", id)
            .await?
            .ok_or_else(failure)?;
        if row.data["collection_version"].as_u64().unwrap_or(1) != u64::from(COLLECTION_VERSION) {
            return Err(Error::invalid(
                "Chromium frozen collection generation is unsupported; retain the original observation.",
            ));
        }
        if row.data != frozen["evidence"]
            || crate::integrity::verify(id, &serde_json::to_vec(&row.data).map_err(|_| failure())?)
                .is_err()
            || row.data["processor_version"] != PROCESSOR_VERSION
        {
            return Err(Error::integrity("Chromium frozen observation mismatch."));
        }
        Ok(())
    }
    pub async fn resume_frozen(&self, frozen: &Value, cancel: CancellationToken) -> Result<bool> {
        self.validate_frozen(frozen).await?;
        if frozen["evidence"]["mode"] != "full" {
            return Err(Error::invalid(
                "Chromium historical resume requires a full frozen observation.",
            ));
        }
        let _guard = self.processing.lock().await;
        self.history_step(false, cancel).await
    }
    async fn current_qualified(&self, cancel: CancellationToken) -> Result<bool> {
        if !self.current_complete().await? {
            return Ok(false);
        }
        for component in COMPONENTS {
            let snapshot = if component == "chrome" {
                let Some(current) = self
                    .store
                    .chromium_state(&state_key("current", component))
                    .await?
                else {
                    return Ok(false);
                };
                self.snapshot(current["snapshot"].as_str().ok_or_else(failure)?)
                    .await?
            } else {
                let Some(root) = self
                    .store
                    .chromium_state(&state_key("current-root", component))
                    .await?
                else {
                    return Ok(false);
                };
                let revision = root["revision"].as_str().ok_or_else(failure)?;
                let Some(snapshot) = self
                    .snapshot_for_revision(component, component_base(component)?, revision, "git")
                    .await?
                else {
                    return Ok(false);
                };
                snapshot
            };
            if snapshot.coverage["usable"] != true
                || snapshot.coverage["traversal_gaps"].as_u64().unwrap_or(0) != 0
                || snapshot.coverage["projection_gaps"].as_u64().unwrap_or(0) != 0
                || snapshot.coverage["index_gaps"].as_u64().unwrap_or(0) != 0
            {
                return Ok(false);
            }
            if self
                .index
                .prewarm(&snapshot.index, cancel.clone())
                .await
                .is_err()
            {
                return Ok(false);
            }
            for member in
                inventory::members(self.store.as_ref(), &snapshot.inventory, MAX_MEMBERS).await?
            {
                if !member.gaps.is_empty()
                    || member.projection.is_none()
                    || member
                        .raw
                        .as_ref()
                        .is_none_or(|raw| raw["license"]["decision"] != "approved")
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
    async fn unresolved_history_gaps(&self, frozen: &Value) -> Result<bool> {
        let mut after = 0;
        loop {
            let rows = self
                .store
                .chromium_rows("history-gaps", after, 500, None)
                .await?;
            if rows.is_empty() {
                return Ok(false);
            }
            for row in rows {
                after = row.sequence;
                if let Some(namespace) = row.data["namespace"].as_str() {
                    let component = row.data["component"].as_str().ok_or_else(failure)?;
                    if frozen["evidence"]["namespaces"]
                        .get(format!("{component}:{namespace}"))
                        .is_some()
                    {
                        continue;
                    }
                }
                if let Some(job) = row.data["job"].as_str()
                    && self
                        .store
                        .chromium_state(&state_key("blocked", job))
                        .await?
                        .is_some_and(|value| value["done"] == true)
                {
                    continue;
                }
                return Ok(true);
            }
        }
    }
    pub async fn frozen_status(&self, frozen: &Value) -> Result<Value> {
        self.validate_frozen(frozen).await?;
        let mut value = self.status().await?;
        let current = self.current_qualified(CancellationToken::new()).await?;
        let exhausted = self
            .store
            .chromium_state(&scheduling_key("history-exhausted"))
            .await?
            == Some(json!(true));
        let stats = self.store.chromium_statistics().await?;
        let has_history_gaps = self.unresolved_history_gaps(frozen).await?;
        let gaps = stats["projection_gaps"].as_u64().unwrap_or(0)
            + stats["index_gaps"].as_u64().unwrap_or(0);
        let complete = if frozen["evidence"]["mode"] == "current" {
            current
        } else {
            current && exhausted && gaps == 0 && !has_history_gaps
        };
        value["frozen_observation"] = frozen["id"].clone();
        value["current_observation_accounted"] = json!(current);
        value["frozen_observation_complete"] = json!(complete);
        value["full_corpus_complete"] = json!(complete && frozen["evidence"]["mode"] == "full");
        value["full_history_complete"] = json!(false);
        value["completeness_note"] = json!(
            "Frozen reachable-source accounting excludes unexposed migrated-site revisions; acquisition, license, projection and index gaps prevent completion."
        );
        Ok(value)
    }
}

fn component_base(component: &str) -> Result<&'static str> {
    match component {
        "src" => Ok("https://chromium.googlesource.com/chromium/src"),
        "site" => Ok("https://chromium.googlesource.com/website"),
        "chrome" => Ok("https://developer.chrome.com/"),
        "chrome-archive" => Ok("https://github.com/GoogleChrome/developer.chrome.com"),
        _ => Err(Error::invalid("Unknown Chromium component.")),
    }
}

fn sitemap_locations(bytes: &[u8]) -> Result<(Vec<String>, Vec<String>)> {
    if bytes.len() > MAX_SOURCE {
        return Err(Error::capacity("Chromium sitemap exceeds its bound."));
    }
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut loc = false;
    let mut value = String::new();
    let mut maps = BTreeSet::new();
    let mut pages = BTreeSet::new();
    let mut tokens = 0_usize;
    let mut depth = 0_usize;
    loop {
        tokens += 1;
        if tokens > 1_000_000 {
            return Err(Error::capacity(
                "Chromium sitemap token count exceeds its bound.",
            ));
        }
        match reader
            .read_event()
            .map_err(|_| Error::integrity("Malformed Chromium sitemap."))?
        {
            Event::Start(tag) => {
                depth += 1;
                if depth > 64 {
                    return Err(Error::capacity(
                        "Chromium sitemap nesting exceeds its bound.",
                    ));
                }
                if tag.local_name().as_ref() == "loc" {
                    loc = true;
                    value.clear();
                }
            }
            Event::Empty(_) => {}
            Event::End(tag) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| Error::integrity("Malformed Chromium sitemap nesting."))?;
                if tag.local_name().as_ref() == "loc" {
                    loc = false;
                    if value.len() > 4096 {
                        return Err(Error::capacity("Chromium sitemap URL exceeds its bound."));
                    }
                    let url = url::Url::parse(&value)
                        .map_err(|_| Error::integrity("Invalid Chromium sitemap URL."))?;
                    if url.scheme() != "https"
                        || url.host_str() != Some("developer.chrome.com")
                        || url.port().is_some()
                        || !url.username().is_empty()
                        || url.password().is_some()
                        || url.fragment().is_some()
                    {
                        continue;
                    }
                    if url.query().is_some_and(|q| q != "hl=en") {
                        continue;
                    }
                    let path = url.path().trim_start_matches('/');
                    if (Operation::Sitemap { path: path.into() }).url().is_ok() {
                        maps.insert(path.into());
                    } else if (Operation::Page { path: path.into() }).url().is_ok() {
                        pages.insert(path.into());
                    }
                }
            }
            Event::Text(text) if loc => {
                value.push_str(&text.xml10_content());
                if value.len() > 4096 {
                    return Err(Error::capacity("Chromium sitemap URL exceeds its bound."));
                }
            }
            Event::GeneralRef(_) | Event::DocType(_) => {
                return Err(Error::integrity(
                    "Chromium sitemap entities are unsupported.",
                ));
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if depth != 0 {
        return Err(Error::integrity("Incomplete Chromium sitemap."));
    }
    Ok((maps.into_iter().collect(), pages.into_iter().collect()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::{OriginalUri, State},
        http::StatusCode,
        response::IntoResponse,
        routing::get,
    };
    pub(super) const BSD: &str = "Copyright 2026 Synthetic Authors. Redistribution and use in source and binary forms, with or without modification, are permitted. Neither the name of the authors nor contributors may be used to endorse products. THIS SOFTWARE IS PROVIDED AS IS.";
    type Routes = Arc<BTreeMap<String, Vec<u8>>>;
    fn build_tree(
        files: &BTreeMap<String, Vec<u8>>,
        prefix: &str,
        trees: &mut BTreeMap<String, Directory>,
    ) -> String {
        let mut files_here = BTreeMap::new();
        let mut directories = BTreeSet::new();
        for (path, bytes) in files {
            let Some(tail) = path.strip_prefix(prefix) else {
                continue;
            };
            if let Some((name, _)) = tail.split_once('/') {
                directories.insert(name.to_owned());
            } else {
                files_here.insert(tail.to_owned(), bytes.clone());
            }
        }
        let mut entries = Vec::new();
        for (name, bytes) in files_here {
            entries.push(Entry {
                name,
                oid: source::object_oid("blob", &bytes),
                kind: "blob".into(),
                mode: 0o100644,
            });
        }
        for name in directories {
            let oid = build_tree(files, &format!("{prefix}{name}/"), trees);
            entries.push(Entry {
                name,
                oid,
                kind: "tree".into(),
                mode: 0o040000,
            });
        }
        entries.sort_by_cached_key(|e| {
            if e.kind == "tree" {
                format!("{}/", e.name)
            } else {
                e.name.clone()
            }
        });
        let mut bytes = Vec::new();
        for entry in &entries {
            bytes.extend_from_slice(format!("{:o} {}\0", entry.mode, entry.name).as_bytes());
            bytes.extend_from_slice(&hex::decode(&entry.oid).unwrap());
        }
        let id = source::object_oid("tree", &bytes);
        trees.insert(
            prefix.trim_end_matches('/').into(),
            Directory {
                id: id.clone(),
                entries,
            },
        );
        id
    }
    pub(super) fn repository(
        routes: &mut BTreeMap<String, Vec<u8>>,
        component: &str,
        revision: &str,
        parents: &[String],
        files: &[(&str, &str)],
    ) {
        let files = files
            .iter()
            .map(|(path, text)| (path.to_string(), text.as_bytes().to_vec()))
            .collect::<BTreeMap<_, _>>();
        let mut trees = BTreeMap::new();
        let tree = build_tree(&files, "", &mut trees);
        let base = if component == "src" {
            "/chromium/src"
        } else if component == "site" {
            "/website"
        } else {
            "/repos/GoogleChrome/developer.chrome.com"
        };
        if component == "chrome-archive" {
            routes.insert(format!("{base}/commits/{revision}"),serde_json::to_vec(&json!({"sha":revision,"commit":{"tree":{"sha":tree},"committer":{"date":"2026-10-27T00:00:00Z"}},"parents":parents.iter().map(|sha|json!({"sha":sha})).collect::<Vec<_>>()})).unwrap());
            for directory in trees.values() {
                routes.insert(format!("{base}/git/trees/{}",directory.id),serde_json::to_vec(&json!({"sha":directory.id,"tree":directory.entries.iter().map(|e|json!({"path":e.name,"sha":e.oid,"type":e.kind,"mode":format!("{:06o}",e.mode)})).collect::<Vec<_>>(),"truncated":false})).unwrap());
            }
            for (path, bytes) in files {
                routes.insert(format!("{base}/contents/{path}"),serde_json::to_vec(&json!({"sha":source::object_oid("blob",&bytes),"encoding":"base64","content":STANDARD.encode(bytes)})).unwrap());
            }
        } else {
            routes.insert(format!("{base}/+/{revision}"),serde_json::to_vec(&json!({"commit":revision,"tree":tree,"parents":parents,"committer":{"time":"Tue Oct 27 00:00:00 2026 +0000"}})).unwrap());
            for (path, directory) in trees {
                routes.insert(if path.is_empty(){format!("{base}/+/{revision}/")}else{format!("{base}/+/{revision}/{path}/")},serde_json::to_vec(&json!({"id":directory.id,"entries":directory.entries.iter().map(|e|json!({"name":e.name,"id":e.oid,"type":e.kind,"mode":e.mode})).collect::<Vec<_>>()})).unwrap());
            }
            for (path, bytes) in files {
                routes.insert(
                    format!("{base}/+/{revision}/{path}"),
                    STANDARD.encode(bytes).into_bytes(),
                );
            }
        }
    }
    async fn reply(
        State(routes): State<Routes>,
        OriginalUri(uri): OriginalUri,
    ) -> impl IntoResponse {
        match routes.get(uri.path()) {
            Some(bytes) => (StatusCode::OK, bytes.clone()),
            None => (StatusCode::NOT_FOUND, Vec::new()),
        }
    }
    #[tokio::test]
    async fn current_components_and_deleted_document_history_are_local_immutable_evidence() {
        let _gate = crate::mdn::index::TEST_GATE.lock().await;
        let main = "a".repeat(40);
        let parent = "b".repeat(40);
        let site = "c".repeat(40);
        let archive = "d".repeat(40);
        let mut routes = BTreeMap::new();
        repository(
            &mut routes,
            "src",
            &main,
            std::slice::from_ref(&parent),
            &[
                ("LICENSE", BSD),
                (
                    "docs/guide.md",
                    "# Guide\nCurrent synthetic Chromium documentation.",
                ),
            ],
        );
        repository(
            &mut routes,
            "src",
            &parent,
            &[],
            &[
                ("LICENSE", BSD),
                (
                    "docs/deleted.md",
                    "# Deleted\nHistorical synthetic Chromium documentation.",
                ),
            ],
        );
        repository(
            &mut routes,
            "site",
            &site,
            &[],
            &[
                (
                    "site/_includes/footer.html",
                    "Except as otherwise noted, the content of this page is licensed under a Creative Commons Attribution 2.5 license, and examples are licensed under the BSD License.",
                ),
                (
                    "site/Home/index.md",
                    "# Chromium project\nSynthetic project website documentation.",
                ),
            ],
        );
        repository(
            &mut routes,
            "chrome-archive",
            &archive,
            &[],
            &[
                (
                    "LICENSE",
                    "Except as otherwise noted, the content of this site is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License, and code samples are licensed under the Apache 2.0 License.",
                ),
                (
                    "site/en/docs/guide.md",
                    "# Archived Chrome\nSynthetic archived documentation.",
                ),
            ],
        );
        for (component, revision, base) in
            [("src", &main, "/chromium/src"), ("site", &site, "/website")]
        {
            routes.insert(
                format!("{base}/+refs/heads/main"),
                serde_json::to_vec(&json!({"refs/heads/main":{"value":revision}})).unwrap(),
            );
            routes.insert(
                format!("{base}/+refs/heads"),
                serde_json::to_vec(&json!({"refs/heads/main":{"value":revision}})).unwrap(),
            );
            routes.insert(format!("{base}/+refs/tags"), b"{}".to_vec());
            routes.insert(format!("{base}/+refs/branch-heads"), b"{}".to_vec());
            assert!(matches!(component, "src" | "site"));
        }
        routes.insert(
            "/repos/GoogleChrome/developer.chrome.com/git/ref/heads/main".into(),
            serde_json::to_vec(
                &json!({"ref":"refs/heads/main","object":{"sha":archive,"type":"commit"}}),
            )
            .unwrap(),
        );
        routes.insert(
            "/repos/GoogleChrome/developer.chrome.com/git/refs".into(),
            serde_json::to_vec(
                &json!([{"ref":"refs/heads/main","object":{"sha":archive,"type":"commit"}}]),
            )
            .unwrap(),
        );
        routes.insert("/sitemap.xml".into(),b"<urlset><url><loc>https://developer.chrome.com/docs/fixture</loc></url><url><loc>https://developer.chrome.com/docs/fixture?hl=ko</loc></url><url><loc>https://example.invalid/docs/no</loc></url></urlset>".to_vec());
        routes.insert("/docs/fixture".into(),b"<main><h1 id=guide>Chrome guide</h1><p>Current synthetic Chrome documentation.</p></main><p class=devsite-license>Except as otherwise noted, the content of this page is licensed under the <a href=https://creativecommons.org/licenses/by/4.0/>Creative Commons Attribution 4.0 License</a>, and code samples are licensed under the Apache 2.0 License.</p>".to_vec());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .fallback(get(reply))
                    .with_state(Arc::new(routes)),
            )
            .await
            .unwrap();
        });
        let broker =
            Arc::new(BulkBroker::fixture(format!("http://{address}").parse().unwrap()).unwrap());
        let (root, store, corpus) = super::super::tests::corpus_fixture(broker.clone()).await;
        let cancel = CancellationToken::new();
        let mut finished = false;
        for _ in 0..100 {
            if corpus.collect_current_once(cancel.clone()).await.unwrap() {
                finished = true;
                break;
            }
        }
        assert!(
            finished,
            "bounded synthetic current inventories must finish"
        );
        let view = corpus.view(None).await.unwrap();
        assert_eq!(view.snapshots.len(), 3);
        assert!(!view.snapshots.contains_key("chrome-archive"));
        let current = corpus.select("src", None, None).await.unwrap();
        assert!(
            corpus
                .member(&current, "docs/guide.md")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            corpus
                .member(&current, "docs/deleted.md")
                .await
                .unwrap()
                .is_none()
        );
        let chrome = corpus.select("chrome", None, None).await.unwrap();
        let members = corpus.search_members(&chrome).await.unwrap();
        let hits = corpus
            .index()
            .search(
                &chrome.index,
                members,
                crate::chromium::index::SearchSpec {
                    query: Some("synthetic".into()),
                    ..Default::default()
                },
                cancel.clone(),
            )
            .await
            .unwrap();
        assert!(
            hits["results"]
                .as_array()
                .unwrap()
                .iter()
                .all(|hit| hit["path"] == "docs/fixture")
        );
        for _ in 0..100 {
            if corpus.collect_history_once(cancel.clone()).await.unwrap() {
                break;
            }
        }
        let historical = corpus
            .snapshot_for_revision("src", component_base("src").unwrap(), &parent, "git")
            .await
            .unwrap()
            .unwrap();
        assert!(
            corpus
                .member(&historical, "docs/deleted.md")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            corpus
                .member(&historical, "docs/guide.md")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            corpus.snapshot(&current.id).await.unwrap().inventory,
            current.inventory
        );
        let before = broker.attempt_count();
        corpus.rebuild_index(cancel.clone()).await.unwrap();
        assert_eq!(
            broker.attempt_count(),
            before,
            "offline rebuild must make no provider requests"
        );
        let rebuilt = corpus.select("src", None, None).await.unwrap();
        assert_ne!(rebuilt.id, current.id);
        assert_eq!(rebuilt.validated_at, current.validated_at);
        assert_eq!(
            corpus.snapshot(&current.id).await.unwrap().index,
            current.index,
            "historical search references must remain fixed"
        );
        assert!(
            store
                .chromium_rows("commits", 0, 100, None)
                .await
                .unwrap()
                .len()
                >= 4
        );
        // A fresh generation must rebuild from retained projections even when an
        // original immutable manifest is corrupt; that historical selector stays broken.
        let old_manifest = root.path().join("chromium-search").join(
            current.index["path"].as_str().unwrap().replacen(
                "chromium-indexes/",
                "mdn-indexes/",
                1,
            ),
        );
        let pending = json!({"generation":1,"reference":rebuilt.index,"ids":corpus.search_members(&rebuilt).await.unwrap()});
        store
            .chromium_set_state("index-pending", &pending)
            .await
            .unwrap();
        let pending_manifest = root.path().join("chromium-search").join(
            rebuilt.index["path"].as_str().unwrap().replacen(
                "chromium-indexes/",
                "mdn-indexes/",
                1,
            ),
        );
        std::fs::write(&pending_manifest, b"synthetic corrupt pending chain").unwrap();
        std::fs::write(&old_manifest, b"synthetic corrupt manifest").unwrap();
        assert!(
            corpus
                .index()
                .prewarm(&current.index, cancel.clone())
                .await
                .is_err()
        );
        let network_before = broker.attempt_count();
        corpus.rebuild_index(cancel.clone()).await.unwrap();
        assert_eq!(broker.attempt_count(), network_before);
        assert_eq!(
            store.chromium_state("index-pending").await.unwrap(),
            Some(Value::Null)
        );
        assert_eq!(
            store
                .chromium_rows("index-recoveries", 0, 100, None)
                .await
                .unwrap()
                .len(),
            1
        );
        let repaired = corpus.select("src", None, None).await.unwrap();
        corpus
            .index()
            .prewarm(&repaired.index, cancel.clone())
            .await
            .unwrap();
        assert!(
            corpus
                .index()
                .prewarm(
                    &corpus.snapshot(&current.id).await.unwrap().index,
                    cancel.clone()
                )
                .await
                .is_err()
        );
        let repaired_id = repaired.id.clone();
        store
            .chromium_set_state(&scheduling_key("current-offset"), &json!(0))
            .await
            .unwrap();
        corpus.collect_current_once(cancel.clone()).await.unwrap();
        assert_eq!(
            corpus.select("src", None, None).await.unwrap().id,
            repaired_id,
            "revalidation of unchanged root must preserve rebuilt default"
        );
        server.abort();
    }
    #[tokio::test]
    async fn interrupted_index_markers_replay_the_exact_pending_batch_without_duplicate_shards() {
        let _gate = crate::mdn::index::TEST_GATE.lock().await;
        let broker = Arc::new(BulkBroker::new(crate::bulk::BulkConfig::default()).unwrap());
        let (_root, store, corpus) = super::super::tests::corpus_fixture(broker).await;
        let cancel = CancellationToken::new();
        let bytes = b"# Replay\nSynthetic replay evidence.".to_vec();
        let (projection, _) = corpus
            .project(
                &component("src").unwrap(),
                "docs/replay.md",
                "git",
                bytes.clone(),
                cancel.clone(),
            )
            .await
            .unwrap();
        let artifact = corpus
            .raw
            .capture_bytes(bytes, cancel.clone())
            .await
            .unwrap();
        let empty = inventory::empty(store.as_ref()).await.unwrap();
        let root = inventory::update(
            store.as_ref(),
            &empty,
            "docs/replay.md",
            Some(Member {
                path: "docs/replay.md".into(),
                oid: "a".repeat(40),
                mode: "100644".into(),
                kind: "document".into(),
                projection: Some(projection),
                raw: Some(json!({"artifact":artifact,"license":{"decision":"approved"}})),
                gaps: vec![],
            }),
        )
        .await
        .unwrap();
        store
            .fail_index_markers
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            corpus
                .flush_index(std::slice::from_ref(&root), cancel.clone())
                .await
                .is_err()
        );
        assert!(
            store
                .chromium_state("index-pending")
                .await
                .unwrap()
                .is_some_and(|value| !value.is_null())
        );
        let reference = corpus
            .flush_index(std::slice::from_ref(&root), cancel.clone())
            .await
            .unwrap();
        assert_eq!(
            store.chromium_state("index-pending").await.unwrap(),
            Some(Value::Null)
        );
        corpus
            .index()
            .prewarm(&reference, cancel.clone())
            .await
            .unwrap();
        let membership = inventory::members(store.as_ref(), &root, 100)
            .await
            .unwrap();
        let descriptor = store
            .chromium_get("projections", membership[0].projection.as_ref().unwrap())
            .await
            .unwrap()
            .unwrap();
        let ids = corpus
            .projection_members(&descriptor.data)
            .await
            .unwrap()
            .into_iter()
            .collect();
        let hits = corpus
            .index()
            .search(
                &reference,
                ids,
                crate::chromium::index::SearchSpec {
                    query: Some("replay".into()),
                    ..Default::default()
                },
                cancel,
            )
            .await
            .unwrap();
        assert_eq!(hits["total"], 1);
    }
}

#[cfg(test)]
mod collector_regressions {
    use super::*;

    #[test]
    fn pruning_only_excludes_existing_classifier_subtrees() {
        for (component, prefix) in [
            ("src", "third_party/other"),
            ("src", "third_party/blink/web_tests"),
            ("src", "components/example/testdata"),
            ("site", "site/_assets"),
            ("site", "build"),
            ("chrome-archive", "site/ko"),
        ] {
            assert!(!subtree_candidate(component, prefix));
            for leaf in ["README.md", "docs/index.html", "guide.markdown"] {
                assert!(!document_candidate(component, &format!("{prefix}/{leaf}")));
            }
        }
        for (component, prefix) in [
            ("src", "third_party"),
            ("src", "third_party/blink"),
            ("src", "components/example"),
            ("site", "site"),
            ("chrome-archive", "site"),
            ("chrome-archive", "site/en"),
        ] {
            assert!(subtree_candidate(component, prefix));
        }
    }

    #[test]
    fn git_identity_accepts_unrequestable_names_without_expanding_operations() {
        let mut entries = Vec::new();
        let oid = source::object_oid("blob", b"synthetic");
        for name in ["literal%20.md", "query?.md", "anchor#.md", "back\\slash.md"] {
            entries.push(json!({"name":name,"id":oid,"type":"blob","mode":0o100644}));
            assert!(!source::valid_path(name));
            assert!(
                Operation::Blob {
                    component: "src".into(),
                    revision: "a".repeat(40),
                    path: name.into()
                }
                .url()
                .is_err()
            );
        }
        entries.sort_by_key(|entry| entry["name"].as_str().unwrap().to_owned());
        let mut bytes = Vec::new();
        for entry in &entries {
            bytes.extend_from_slice(
                format!("100644 {}\0", entry["name"].as_str().unwrap()).as_bytes(),
            );
            bytes.extend_from_slice(&hex::decode(&oid).unwrap());
        }
        let id = source::object_oid("tree", &bytes);
        let encoded = serde_json::to_vec(&json!({"id":id,"entries":entries})).unwrap();
        let tree = source::parse_tree("src", &encoded).unwrap();
        assert_eq!(tree.id, id);
        assert_eq!(tree.entries.len(), 4);
        let mut corrupt: Value = serde_json::from_slice(&encoded).unwrap();
        corrupt["entries"][0]["name"] = json!("changed.md");
        assert_eq!(
            source::parse_tree("src", &serde_json::to_vec(&corrupt).unwrap())
                .unwrap_err()
                .code,
            "integrity"
        );
    }
    async fn fixture_reply(
        axum::extract::State(routes): axum::extract::State<Arc<BTreeMap<String, Vec<u8>>>>,
        axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    ) -> impl axum::response::IntoResponse {
        match routes.get(uri.path()) {
            Some(bytes) => (axum::http::StatusCode::OK, bytes.clone()),
            None if uri.path().starts_with("/website/") => {
                (axum::http::StatusCode::SERVICE_UNAVAILABLE, Vec::new())
            }
            None => (axum::http::StatusCode::NOT_FOUND, Vec::new()),
        }
    }
    async fn fixture_source(
        files: &[(&str, &str)],
        revision: &str,
    ) -> (Arc<BulkBroker>, tokio::task::JoinHandle<()>, Value) {
        let mut routes = BTreeMap::new();
        super::tests::repository(&mut routes, "src", revision, &[], files);
        let commit_route = format!("/chromium/src/+/{revision}");
        let commit: Value =
            serde_json::from_slice(routes.remove(&commit_route).unwrap().as_slice()).unwrap();
        routes.insert(
            "/chromium/src/+refs/heads/main".into(),
            serde_json::to_vec(&json!({"refs/heads/main":{"value":revision}})).unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new()
                    .fallback(axum::routing::get(fixture_reply))
                    .with_state(Arc::new(routes)),
            )
            .await
            .unwrap();
        });
        let broker =
            Arc::new(BulkBroker::fixture(format!("http://{address}").parse().unwrap()).unwrap());
        (broker, server, commit)
    }
    async fn seed_legacy_root(corpus: &ChromiumCorpus, revision: &str, commit: &Value) {
        let store = corpus.store();
        let commit = source::parse_commit("src", &serde_json::to_vec(commit).unwrap()).unwrap();
        store.chromium_put("commits", &legacy_job_key("src",revision), &json!({"component":"src","repository":component_base("src").unwrap(),"commit":commit,"source_url":"https://fixtures.invalid/chromium-collector"})).await.unwrap();
        corpus
            .observe_refs("src", None, CancellationToken::new())
            .await
            .unwrap();
        store
            .chromium_set_state(&scheduling_key("current-offset"), &json!(0))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn generation_two_restarts_with_old_source_preserving_old_work_and_gaps() {
        let _gate = crate::mdn::index::TEST_GATE.lock().await;
        let revision = "9a".repeat(20);
        let mut owned = (0..80)
            .map(|n| {
                (
                    format!("docs/file-{n:03}.data"),
                    format!("# Guide {n}\nCollectorRegressionToken inert documentation."),
                )
            })
            .collect::<Vec<_>>();
        owned.extend([
            ("LICENSE".into(), super::tests::BSD.into()),
            (
                "docs/guide.md".into(),
                "# Guide\nCollectorRegressionToken inert documentation.".into(),
            ),
            (
                "docs/url#sample.md".into(),
                "Unsupported operation path.".into(),
            ),
            (
                "docs/url?sample.md".into(),
                "Another unsupported operation path.".into(),
            ),
            (
                "third_party/other/README.md".into(),
                "Excluded third-party tree.".into(),
            ),
            (
                "third_party/blink/web_tests/example%20/README.md".into(),
                "Excluded browser test tree.".into(),
            ),
        ]);
        let files = owned
            .iter()
            .map(|(path, body)| (path.as_str(), body.as_str()))
            .collect::<Vec<_>>();
        let (broker, server, commit) = fixture_source(&files, &revision).await;
        let (root, store, corpus) = super::super::tests::corpus_fixture(broker.clone()).await;
        seed_legacy_root(&corpus, &revision, &commit).await;
        let old_work_key = state_key("work", &format!("src:{revision}:1"));
        let original = json!({"synthetic_legacy_checkpoint":true});
        store
            .chromium_set_state(&old_work_key, &original)
            .await
            .unwrap();
        assert!(
            !corpus
                .collect_current_once(CancellationToken::new())
                .await
                .unwrap()
        );
        assert!(
            store
                .chromium_state(&work_key("src", &revision))
                .await
                .unwrap()
                .is_some()
        );
        drop(corpus);
        let corpus = ChromiumCorpus::new(
            store.clone(),
            broker.clone(),
            root.path(),
            ChromiumConfig {
                enabled: false,
                min_free_bytes: 64 * 1024 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        for _ in 0..10 {
            store
                .chromium_set_state(&scheduling_key("current-offset"), &json!(0))
                .await
                .unwrap();
            corpus
                .collect_current_once(CancellationToken::new())
                .await
                .unwrap();
            if corpus
                .snapshot_for_revision("src", component_base("src").unwrap(), &revision, "git")
                .await
                .unwrap()
                .is_some()
            {
                break;
            }
        }
        let current = corpus.select("src", None, None).await.unwrap();
        assert_eq!(current.coverage["collection_version"], 2);
        assert_eq!(current.processor_version, 1);
        assert_eq!(current.coverage["traversal_gaps"], 2);
        assert_eq!(current.coverage["excluded_subtrees"], 2);
        assert_eq!(current.coverage["complete"], false);
        assert_eq!(current.coverage["documents"], 1);
        assert_eq!(current.coverage["accounted"], true);
        let gap_root = current.coverage["traversal_gap_root"].as_str().unwrap();
        corpus
            .verify_gap_manifest(gap_root, 2, &CancellationToken::new())
            .await
            .unwrap();
        let manifest = store
            .chromium_get("traversal-gap-manifests", gap_root)
            .await
            .unwrap()
            .unwrap();
        let leaf = store
            .chromium_get(
                "traversal-gap-manifests",
                manifest.data["left"].as_str().unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let gap_id = leaf.data["gap"].as_str().unwrap();
        let removed = store.remove_test_row("traversal-gaps", gap_id).unwrap();
        assert_eq!(
            corpus
                .verify_gap_manifest(gap_root, 2, &CancellationToken::new())
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        store
            .chromium_put("traversal-gaps", &removed.key, &removed.data)
            .await
            .unwrap();

        assert_eq!(
            store.chromium_state(&old_work_key).await.unwrap(),
            Some(original)
        );
        assert_eq!(
            broker.attempt_count(),
            7,
            "one source license, root, docs, third_party and Blink tree plus document reads; no legacy commit refetch or excluded subtree request"
        );
        let mut legacy = current.clone();
        legacy.id = inventory::digest(b"synthetic preserved generation-one snapshot");
        legacy
            .coverage
            .as_object_mut()
            .unwrap()
            .remove("collection_version");
        store
            .chromium_put("snapshots", &legacy.id, &encode(&legacy).unwrap())
            .await
            .unwrap();
        let legacy_alias =
            alias_for_collection("src", &legacy.repository, &revision, "git", 1).unwrap();
        store
            .chromium_put("snapshot-keys", &legacy_alias, &json!(legacy.id))
            .await
            .unwrap();
        let before = broker.attempt_count();
        corpus
            .rebuild_index(CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(broker.attempt_count(), before);
        assert_eq!(corpus.snapshot(&legacy.id).await.unwrap().id, legacy.id);
        let legacy_successor = store
            .chromium_state(&state_key("revision-alias", &legacy_alias))
            .await
            .unwrap()
            .unwrap();
        let successor = corpus
            .snapshot(legacy_successor.as_str().unwrap())
            .await
            .unwrap();
        assert!(successor.coverage.get("collection_version").is_none());
        assert_eq!(
            corpus
                .snapshot_for_revision("src", &legacy.repository, &revision, "git")
                .await
                .unwrap()
                .unwrap()
                .coverage["collection_version"],
            2
        );
        // The next component fails, but cannot remove the healthy published source.
        store
            .chromium_set_state(&scheduling_key("current-offset"), &json!(1))
            .await
            .unwrap();
        assert!(
            corpus
                .collect_current_once(CancellationToken::new())
                .await
                .is_err()
        );
        let failed = corpus.collector_status("site", "current").await.unwrap();
        assert_eq!(failed.failure.unwrap().phase, Phase::PublicationAcquisition);
        assert!(corpus.select("src", None, None).await.is_ok());
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires stopped disposable cluster writer, PostgreSQL and optional fixture S3"]
    async fn chromium_collector_cluster_seed() {
        use devres_application::attribution::AttributionStore;
        use devres_domain::attribution::*;
        let _gate = crate::mdn::index::TEST_GATE.lock().await;
        let database = std::env::var("DATABASE_URL").expect("disposable cluster PostgreSQL");
        let root = std::path::PathBuf::from(
            std::env::var("BLOB_DIR").expect("disposable cluster blob root"),
        );
        let s3 = std::env::var_os("DEVRES_TEST_S3_CONFIG").map(|path| {
            toml::from_str::<crate::object_storage::S3Config>(
                &std::fs::read_to_string(path).unwrap(),
            )
            .unwrap()
        });
        let store = Arc::new(
            crate::PgBlobStore::connect_archive_for_maintenance(&database, &root, s3)
                .await
                .unwrap(),
        );
        let revision = "9c".repeat(20);
        let expected = "ChromiumCollectorClusterToken";
        let (broker,server,commit)=fixture_source(&[
            ("LICENSE",super::tests::BSD),
            ("docs/collector-cluster.md","# Collector cluster fixture\nChromiumCollectorClusterToken is first-party synthetic evidence."),
            ("third_party/other/README.md","Excluded synthetic subtree."),
            ("docs/unsupported#path.md","Unrequestable synthetic metadata gap."),
        ],&revision).await;
        let corpus = Arc::new(
            ChromiumCorpus::new(
                store.clone(),
                broker,
                &root,
                ChromiumConfig {
                    enabled: false,
                    min_free_bytes: 64 * 1024 * 1024,
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        seed_legacy_root(&corpus, &revision, &commit).await;
        for _ in 0..4 {
            store
                .chromium_set_state(&scheduling_key("current-offset"), &json!(0))
                .await
                .unwrap();
            corpus
                .collect_current_once(CancellationToken::new())
                .await
                .unwrap();
            if corpus
                .snapshot_for_revision("src", component_base("src").unwrap(), &revision, "git")
                .await
                .unwrap()
                .is_some()
            {
                break;
            }
        }
        let snapshot = corpus.select("src", None, None).await.unwrap();
        assert_eq!(snapshot.revision, revision);
        assert_eq!(snapshot.coverage["accounted"], true);
        assert_eq!(snapshot.coverage["complete"], false);
        assert_eq!(snapshot.coverage["traversal_gaps"], 1);
        // Force a sibling source observation against the local-only HTTP failure fixture.
        store
            .chromium_set_state(
                &state_key("current-root", "site"),
                &json!({"revision":"8c".repeat(20),"observed_at":devres_domain::unix_now()}),
            )
            .await
            .unwrap();
        store
            .chromium_set_state(&scheduling_key("current-offset"), &json!(1))
            .await
            .unwrap();
        assert!(
            corpus
                .collect_current_once(CancellationToken::new())
                .await
                .is_err()
        );
        assert!(corpus.select("src", None, None).await.is_ok());
        let research = crate::chromium::research::ChromiumResearch::new(corpus.clone());
        let arguments =
            json!({"component":"src","path":"docs/collector-cluster.md","snapshot":snapshot.id});
        let output = research
            .call("chromium.get", arguments.clone())
            .await
            .unwrap();
        let resource = output["resource_uri"]
            .as_str()
            .expect("immutable synthetic resource")
            .to_owned();
        assert!(serde_json::to_string(&output).unwrap().contains(expected));
        let resource_output = research.read_resource(&resource).await.unwrap();
        let mut targets = BTreeMap::new();
        for output in [&output, &resource_output] {
            for target in crate::attribution_providers::targets("chromium", output).unwrap() {
                targets.insert(serde_json::to_string(&target.subject).unwrap(), target);
            }
        }
        assert!(!targets.is_empty());
        for target in targets.values() {
            store.attribution_enqueue(target, 255).await.unwrap();
        }
        const NOTICE: &str = "First-party synthetic Chromium collector cluster acceptance by dev-resources-MCP contributors; AGPL-3.0-only. This fixture is not upstream acquisition evidence.";
        for admission in 0..1024 {
            if targets.is_empty() {
                break;
            }
            let job = store
                .attribution_claim(&["chromium".into()], devres_domain::unix_now(), admission)
                .await
                .unwrap()
                .expect("synthetic qualification claim");
            let identity = serde_json::to_string(&job.target.subject).unwrap();
            if targets.remove(&identity).is_none() {
                store
                    .attribution_fail(
                        &job,
                        Some(devres_domain::unix_now() + 300),
                        "fixture_deferred",
                    )
                    .await
                    .unwrap();
                continue;
            }
            let generation = AttributionGeneration {
                subject: job.target.subject.clone(),
                policy_epoch: ATTRIBUTION_POLICY_EPOCH,
                policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
                notices: vec![AttributionNotice {
                    source_url: "https://fixtures.invalid/devres/chromium-collector".into(),
                    license: Some("AGPL-3.0-only".into()),
                    copyright: Some("dev-resources-MCP synthetic fixture authors".into()),
                    text: NOTICE.into(),
                    evidence: json!({"synthetic":true,"fixture":"chromium-collector-cluster-v2","body_hash":crate::integrity::hash(NOTICE.as_bytes())}),
                }],
                receipts: vec![
                    json!({"kind":"synthetic_fixture_validation","synthetic":true,"status":200,"source_url":"https://fixtures.invalid/devres/chromium-collector","body_hash":crate::integrity::hash(NOTICE.as_bytes()),"validated_at":devres_domain::unix_now(),"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT,"source_fingerprint":job.target.subject.fingerprint}),
                ],
            };
            store.attribution_complete(&job, &generation).await.unwrap();
        }
        assert!(
            targets.is_empty(),
            "bounded synthetic qualification completed"
        );
        std::fs::write("/tmp/chromium-collector-receipt.json",serde_json::to_vec_pretty(&json!({"provider":"chromium","tool":"chromium.get","arguments":arguments,"resource":resource,"expected":expected})).unwrap()).unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn catalog_storage_failures_are_not_replaced_by_empty_catalogs() {
        let broker = Arc::new(BulkBroker::new(Default::default()).unwrap());
        let (_root, store, corpus) = super::super::tests::corpus_fixture(broker.clone()).await;
        store
            .fail_catalog_read
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let error = corpus.ensure_catalog().await.unwrap_err();
        assert_eq!(error.code, "integrity");
        assert_eq!(
            devres_application::collection::context(&error)
                .unwrap()
                .phase,
            Phase::CatalogLookup
        );
        assert_eq!(broker.attempt_count(), 0);
        store
            .fail_catalog_read
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(
            store
                .chromium_rows("catalogs", 0, 1, None)
                .await
                .unwrap()
                .is_empty()
        );
    }
    #[tokio::test]
    async fn unpublished_checkpoint_and_cache_gap_closure_is_verified() {
        let broker = Arc::new(BulkBroker::new(Default::default()).unwrap());
        let (_root, store, corpus) = super::super::tests::corpus_fixture(broker).await;
        let empty = inventory::empty(store.as_ref()).await.unwrap();
        let missing = inventory::digest(b"missing sole unpublished gap root");
        let key = state_key("work", "synthetic-unpublished-root");
        store.chromium_set_state(&key,&json!({"inventory":empty,"traversal_gaps":1,"traversal_gap_root":missing,"stack":[]})).await.unwrap();
        assert!(
            corpus
                .verify_gap_checkpoints(&CancellationToken::new())
                .await
                .is_err()
        );
        store
            .chromium_set_state(&key, &json!({"inventory":empty,"stack":[]}))
            .await
            .unwrap();
        corpus
            .verify_gap_checkpoints(&CancellationToken::new())
            .await
            .unwrap();
        store
            .chromium_put(
                "derived-inventories",
                "synthetic-unpublished-cache",
                &json!({"inventory":empty,"traversal_gaps":1,"traversal_gap_root":missing}),
            )
            .await
            .unwrap();
        assert!(
            corpus
                .verify_gap_checkpoints(&CancellationToken::new())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn unrequestable_notice_is_a_rights_gap_without_an_unsafe_request() {
        let _gate = crate::mdn::index::TEST_GATE.lock().await;
        let revision = "9d".repeat(20);
        let (broker, server, commit) = fixture_source(
            &[
                ("LICENSE", super::tests::BSD),
                ("LICENSE.%20", "Unrequestable governing notice."),
                ("docs/guide.md", "Must remain metadata-only."),
            ],
            &revision,
        )
        .await;
        let (_root, _store, corpus) = super::super::tests::corpus_fixture(broker.clone()).await;
        seed_legacy_root(&corpus, &revision, &commit).await;
        corpus
            .collect_current_once(CancellationToken::new())
            .await
            .unwrap();
        let snapshot = corpus
            .snapshot_for_revision("src", component_base("src").unwrap(), &revision, "git")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.coverage["usable"], false);
        assert_eq!(snapshot.coverage["traversal_gaps"], 1);
        assert_eq!(snapshot.coverage["accounted"], true);
        let member = corpus
            .member(&snapshot, "docs/guide.md")
            .await
            .unwrap()
            .unwrap();
        assert!(member.raw.is_none());
        assert!(member.projection.is_none());
        assert!(
            member
                .gaps
                .iter()
                .any(|gap| gap == "license_notice_unrequestable")
        );
        assert_eq!(
            broker.attempt_count(),
            4,
            "only root/tree and approved source notice; no unsafe notice or document body fetch"
        );
        server.abort();
    }
    #[tokio::test]
    async fn writer_restart_clears_activity_without_erasing_retained_diagnostics() {
        let broker = Arc::new(BulkBroker::new(Default::default()).unwrap());
        let (root, store, corpus) = super::super::tests::corpus_fixture(broker.clone()).await;
        let mut status = CollectorStatus::default();
        status.fail(
            &at_phase(
                Error::unavailable("Synthetic source failure."),
                Phase::PublicationAcquisition,
            ),
            Phase::Traversal,
            100,
            Some(200),
        );
        status.progress(ProgressKind::Members, 7);
        status.begin(Phase::Traversal);
        corpus
            .save_collector("src", "current", &status)
            .await
            .unwrap();
        corpus.initialize_status().await.unwrap();
        let restarted = corpus.collector_status("src", "current").await.unwrap();
        assert!(!restarted.active);
        assert_eq!(restarted.progress[&ProgressKind::Members], 7);
        assert_eq!(
            restarted.failure.unwrap().phase,
            Phase::PublicationAcquisition
        );
        corpus
            .save_collector("src", "current", &status)
            .await
            .unwrap();
        let public_before = store.chromium_state("status").await.unwrap();
        let component_before = store
            .chromium_state(&state_key("collector", "src:current"))
            .await
            .unwrap();
        let reader = ChromiumCorpus::new_reader(
            store.clone(),
            broker.clone(),
            root.path(),
            corpus.config().clone(),
        )
        .unwrap();
        assert_eq!(
            reader.initialize_status().await.unwrap_err().code,
            "integrity"
        );
        assert_eq!(store.chromium_state("status").await.unwrap(), public_before);
        assert_eq!(
            store
                .chromium_state(&state_key("collector", "src:current"))
                .await
                .unwrap(),
            component_before
        );
        assert!(
            corpus
                .collector_status("src", "current")
                .await
                .unwrap()
                .active
        );
        assert_eq!(broker.attempt_count(), 0);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn chromium_collector_postgres_publication_with_accounted_gaps() {
        let _gate = crate::mdn::index::TEST_GATE.lock().await;
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL");
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let database = format!("devres_chromium_collector_{}_{nonce}", std::process::id());
        assert!(
            database
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        );
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "CREATE DATABASE {database}"
        )))
        .execute(&admin)
        .await
        .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{database}"));
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = Arc::new(
            crate::PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        let revision = "9e".repeat(20);
        let (broker, server, commit) = fixture_source(
            &[
                ("LICENSE", super::tests::BSD),
                (
                    "docs/qualified.md",
                    "# Qualified\nChromiumPostgresCollectorToken retained content.",
                ),
                (
                    "docs/unsupported#path.md",
                    "Unrequestable metadata-only path.",
                ),
            ],
            &revision,
        )
        .await;
        let corpus = ChromiumCorpus::new(
            store.clone(),
            broker.clone(),
            root.path(),
            ChromiumConfig {
                enabled: false,
                min_free_bytes: 64 * 1024 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        seed_legacy_root(&corpus, &revision, &commit).await;
        corpus
            .collect_current_once(CancellationToken::new())
            .await
            .unwrap();
        let snapshot = corpus.select("src", None, None).await.unwrap();
        assert_eq!(snapshot.coverage["accounted"], true);
        assert_eq!(snapshot.coverage["complete"], false);
        assert_eq!(snapshot.coverage["usable"], true);
        assert_eq!(snapshot.coverage["traversal_gaps"], 1);
        let view = corpus.view(None).await.unwrap();
        let observations = store
            .chromium_rows("observations", 0, 100, None)
            .await
            .unwrap();
        assert!(observations.iter().any(|row| row.data["component"] == "src"
            && row.data["current_revision"] == revision
            && row.data["observed_at"] == view.validations["src"]));
        let member = corpus
            .member(&snapshot, "docs/qualified.md")
            .await
            .unwrap()
            .unwrap();
        assert!(member.raw.is_some());
        assert!(member.projection.is_some());
        let before = store.chromium_state("default").await.unwrap();
        let current = store
            .chromium_state(&state_key("current", "src"))
            .await
            .unwrap()
            .unwrap();
        // Test-only missing evidence injection into this owned disposable store:
        // an actual online observation and qualified member cannot excuse a broken DAG.
        let mut broken = snapshot.clone();
        broken.id = inventory::digest(b"synthetic missing Chromium gap root snapshot");
        broken.coverage["traversal_gap_root"] =
            json!(inventory::digest(b"missing Chromium gap manifest"));
        store
            .chromium_put("snapshots", &broken.id, &encode(&broken).unwrap())
            .await
            .unwrap();
        store
            .chromium_set_state(
                &state_key("current", "src"),
                &json!({"snapshot":broken.id,"validated_at":view.validations["src"]}),
            )
            .await
            .unwrap();
        let error = corpus
            .publish_default(CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.code, "integrity");
        assert_eq!(
            devres_application::collection::context(&error)
                .unwrap()
                .phase,
            Phase::ArtifactVerification
        );
        assert_eq!(store.chromium_state("default").await.unwrap(), before);
        store
            .chromium_set_state(&state_key("current", "src"), &current)
            .await
            .unwrap();
        assert!(corpus.select("src", None, None).await.is_ok());
        server.abort();
        drop(corpus);
        drop(store);
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP DATABASE {database} WITH (FORCE)"
        )))
        .execute(&admin)
        .await
        .unwrap();
        admin.close().await;
    }
}
