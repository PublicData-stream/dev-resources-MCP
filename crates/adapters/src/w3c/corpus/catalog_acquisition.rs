//! Durable candidate discovery. Only a complete catalog can replace the published head.
use super::*;

const VERSION: u32 = 1;
const MAX_PAGES: usize = 1000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogWork {
    version: u32,
    generation: String,
    started_at: i64,
    predecessor: Option<String>,
    pages: Vec<String>,
    standards: usize,
    complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogPage {
    version: u32,
    generation: String,
    page: u32,
    observed_at: i64,
    previous: Option<String>,
    artifact: BulkArtifact,
    standards: Vec<Standard>,
    has_next: bool,
}

impl W3cCorpus {
    pub(super) async fn verify_catalog_discovery(&self, cancel: CancellationToken) -> Result<()> {
        for kind in ["catalog-pages", "catalog-failures"] {
            let mut after = 0;
            loop {
                cancelled(&cancel)?;
                let rows = self.store.w3c_migration_rows(kind, after, 100).await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    after = row.sequence;
                    crate::integrity::verify(
                        &row.key,
                        &serde_json::to_vec(&row.data).map_err(|_| failure())?,
                    )?;
                    if kind == "catalog-pages" {
                        let page: CatalogPage = decode(row.data)?;
                        if page.version != VERSION
                            || page.page == 0
                            || page.page as usize > MAX_PAGES
                        {
                            return Err(Error::integrity("Invalid retained W3C catalog page."));
                        }
                        if let Some(id) = page.previous {
                            let previous: CatalogPage = decode(
                                self.store
                                    .w3c_get("catalog-pages", &id)
                                    .await?
                                    .ok_or_else(|| {
                                        Error::integrity("Retained W3C catalog ancestor missing.")
                                    })?
                                    .data,
                            )?;
                            if previous.generation != page.generation
                                || previous.page + 1 != page.page
                                || !previous.has_next
                            {
                                return Err(Error::integrity(
                                    "Invalid retained W3C catalog ancestry.",
                                ));
                            }
                        } else if page.page != 1 {
                            return Err(Error::integrity("W3C catalog page root missing."));
                        }
                        let artifact = self
                            .raw
                            .verify(&page.artifact.body_hash, 8 * 1024 * 1024, cancel.clone())
                            .await?;
                        if artifact != page.artifact {
                            return Err(Error::integrity("Retained W3C catalog artifact differs."));
                        }
                    } else {
                        let work: CatalogWork = decode(row.data["work"].clone())?;
                        self.catalog_pages(&work, &cancel).await?;
                    }
                }
            }
        }
        if let Some(value) = self
            .store
            .w3c_state("catalog-work")
            .await?
            .filter(|v| !v.is_null())
        {
            let work: CatalogWork = decode(value)?;
            if work.version != VERSION || work.pages.len() > MAX_PAGES {
                return Err(Error::integrity("Invalid W3C catalog checkpoint."));
            }
            self.catalog_pages(&work, &cancel).await?;
        }
        Ok(())
    }
    async fn catalog_work(&self) -> Result<CatalogWork> {
        if let Some(value) = self
            .store
            .w3c_state("catalog-work")
            .await?
            .filter(|v| !v.is_null())
        {
            let work: CatalogWork = decode(value)?;
            if work.version != VERSION || work.pages.len() > MAX_PAGES {
                return Err(Error::integrity("Unsupported W3C catalog checkpoint."));
            }
            return Ok(work);
        }
        let started_at = devres_domain::unix_now();
        let predecessor = self.catalog_optional().await?.map(|c| c.id);
        let generation = inventory::digest(
            &serde_json::to_vec(&(
                "w3c-catalog-generation-v1",
                started_at,
                self.store.w3c_cutoff().await?,
                &predecessor,
            ))
            .map_err(|_| failure())?,
        );
        let work = CatalogWork {
            version: VERSION,
            generation,
            started_at,
            predecessor,
            pages: Vec::new(),
            standards: 0,
            complete: false,
        };
        self.store
            .w3c_set_state("catalog-work", &encode(&work)?)
            .await?;
        Ok(work)
    }

    async fn catalog_pages(
        &self,
        work: &CatalogWork,
        cancel: &CancellationToken,
    ) -> Result<(BTreeMap<String, Standard>, Vec<BulkArtifact>, i64)> {
        let mut standards = BTreeMap::new();
        let mut captures = Vec::new();
        let mut observed_at = i64::MAX;
        let mut previous = None;
        for (position, id) in work.pages.iter().enumerate() {
            cancelled(cancel)?;
            let value = self
                .store
                .w3c_get("catalog-pages", id)
                .await?
                .ok_or_else(|| Error::integrity("W3C catalog checkpoint page missing."))?
                .data;
            crate::integrity::verify(id, &serde_json::to_vec(&value).map_err(|_| failure())?)?;
            let page: CatalogPage = decode(value)?;
            if page.version != VERSION
                || page.generation != work.generation
                || page.page as usize != position + 1
                || page.previous != previous
                || (position + 1 < work.pages.len() && !page.has_next)
                || (position + 1 == work.pages.len() && page.has_next == work.complete)
            {
                return Err(Error::integrity("Invalid W3C catalog checkpoint chain."));
            }
            observed_at = observed_at.min(page.observed_at);
            for standard in page.standards {
                if standards.insert(standard.id.clone(), standard).is_some() {
                    return Err(Error::integrity(
                        "Duplicate W3C specification across API pages.",
                    ));
                }
            }
            if standards.len() > catalog::MAX_CATALOG {
                return Err(collection::limited(
                    Error::capacity("W3C catalog count exceeds bounds."),
                    Phase::CatalogValidation,
                    LimitKind::CatalogStandards,
                    Some(standards.len() as u64),
                    Some(catalog::MAX_CATALOG as u64),
                ));
            }
            captures.push(page.artifact);
            previous = Some(id.clone());
        }
        if standards.len() != work.standards {
            return Err(Error::integrity("W3C catalog checkpoint count differs."));
        }
        Ok((standards, captures, observed_at))
    }

    async fn catalog_step_inner(
        &self,
        work: &mut CatalogWork,
        cancel: CancellationToken,
    ) -> Result<Option<Catalog>> {
        // Verify committed checkpoint rows and their chain before another provider request.
        let (mut standards, mut captures, mut observed_at) =
            self.catalog_pages(work, &cancel).await?;
        if !work.complete {
            if work.pages.len() >= MAX_PAGES {
                return Err(collection::limited(
                    Error::capacity("W3C API catalog pagination exceeds bounds."),
                    Phase::CatalogValidation,
                    LimitKind::CatalogPages,
                    Some(work.pages.len() as u64 + 1),
                    Some(MAX_PAGES as u64),
                ));
            }
            let page = work.pages.len() as u32 + 1;
            let acquired_at = devres_domain::unix_now();
            self.collector_begin("catalog", Phase::CatalogAcquisition)
                .await?;
            let (bytes, artifact) = self
                .api(catalog::ApiOperation::Catalog { page }, cancel.clone())
                .await?;
            self.collector_begin("catalog", Phase::CatalogValidation)
                .await?;
            let mut parsed = catalog::parse(&bytes, acquired_at)
                .map_err(|e| collection::at_phase(e, Phase::CatalogValidation))?;
            for standard in &mut parsed.standards {
                standard.metadata["api_catalog_capture"] = json!(artifact.body_hash);
            }
            let has_next = catalog::page_has_next(&bytes)
                .map_err(|e| collection::at_phase(e, Phase::CatalogValidation))?;
            for standard in &parsed.standards {
                if standards
                    .insert(standard.id.clone(), standard.clone())
                    .is_some()
                {
                    return Err(Error::integrity(
                        "Duplicate W3C specification across API pages.",
                    ));
                }
            }
            if standards.len() > catalog::MAX_CATALOG {
                return Err(collection::limited(
                    Error::capacity("W3C catalog count exceeds bounds."),
                    Phase::CatalogValidation,
                    LimitKind::CatalogStandards,
                    Some(standards.len() as u64),
                    Some(catalog::MAX_CATALOG as u64),
                ));
            }
            let retained = CatalogPage {
                version: VERSION,
                generation: work.generation.clone(),
                page,
                observed_at: acquired_at,
                previous: work.pages.last().cloned(),
                artifact: artifact.clone(),
                standards: parsed.standards,
                has_next,
            };
            let value = encode(&retained)?;
            let id = inventory::digest(&serde_json::to_vec(&value).map_err(|_| failure())?);
            self.store.w3c_put("catalog-pages", &id, &value).await?;
            work.pages.push(id);
            work.standards = standards.len();
            work.complete = !has_next;
            self.store
                .w3c_set_state("catalog-work", &encode(work)?)
                .await?;
            captures.push(artifact);
            observed_at = observed_at.min(acquired_at);
            if has_next {
                return Ok(None);
            }
        }
        if standards.is_empty() {
            return Err(Error::integrity("W3C catalog is empty."));
        }
        for artifact in &captures {
            let actual = self
                .raw
                .verify(&artifact.body_hash, 8 * 1024 * 1024, cancel.clone())
                .await
                .map_err(|e| collection::at_phase(e, Phase::CatalogRetention))?;
            if actual != *artifact {
                return Err(collection::at_phase(
                    Error::integrity("W3C catalog artifact differs."),
                    Phase::CatalogRetention,
                ));
            }
        }
        let previous = self
            .catalog_optional()
            .await?
            .map(|c| {
                c.standards
                    .into_iter()
                    .map(|s| (s.id.clone(), s))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        for standard in standards.values_mut() {
            // Enrichment belongs to previously published evidence; candidate pages stay immutable.
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
                    if let Some(value) = old.metadata.get(key) {
                        standard.metadata[key] = value.clone();
                    }
                }
            }
        }
        // A resumed candidate retains the oldest source observation as its freshness clock.
        let mut catalog = self
            .reconcile_catalog(
                Catalog {
                    id: String::new(),
                    observed_at,
                    standards: standards.into_values().collect(),
                    gaps: Vec::new(),
                },
                cancel,
            )
            .await?;
        catalog.id = inventory::digest(
            &serde_json::to_vec(&(&catalog.standards, &catalog.gaps, &captures, observed_at))
                .map_err(|_| failure())?,
        );
        self.collector_begin("catalog", Phase::CatalogPublication)
            .await?;
        self.store
            .w3c_put("catalogs", &catalog.id, &encode(&catalog)?)
            .await?;
        self.store.w3c_put("catalog-captures", &catalog.id, &json!({"api_pages":captures,"observed_at":observed_at,"generation":work.generation,"pages":work.pages})).await?;
        self.store
            .w3c_set_state("catalog", &json!(catalog.id))
            .await?;
        self.store
            .w3c_set_state("catalog-work", &Value::Null)
            .await?;
        Ok(Some(catalog))
    }

    pub(super) async fn catalog_step(&self, cancel: CancellationToken) -> Result<Option<Catalog>> {
        self.collector_begin("catalog", Phase::CatalogLookup)
            .await?;
        let mut work = self
            .catalog_work()
            .await
            .map_err(|e| collection::at_phase(e, Phase::CatalogLookup))?;
        let result = self.catalog_step_inner(&mut work, cancel).await;
        let mut status = self.collector_status("catalog").await?;
        let phase = status.phase.unwrap_or(Phase::CatalogLookup);
        let result = result.map_err(|e| collection::at_phase(e, phase));
        status.progress(ProgressKind::Pages, work.pages.len() as u64);
        status.progress(ProgressKind::Standards, work.standards as u64);
        match &result {
            Ok(Some(catalog)) => {
                status.progress(ProgressKind::Standards, catalog.standards.len() as u64);
                status.succeed(devres_domain::unix_now());
            }
            Ok(None) => {
                status.active = false;
                status.phase = Some(Phase::CatalogAcquisition);
            }
            Err(error) => {
                let now = devres_domain::unix_now();
                status.fail(
                    error,
                    Phase::CatalogValidation,
                    now,
                    Some(now.saturating_add(60)),
                );
            }
        }
        self.store
            .w3c_set_state("collector-catalog", &encode(&status)?)
            .await?;
        match result {
            Err(error) if matches!(error.code.as_str(), "integrity" | "invalid_input") => {
                let value = json!({"version":VERSION,"work":work,"code":collection::safe_code(&error.code),"context":collection::context(&error),"observed_at":devres_domain::unix_now()});
                let id = inventory::digest(&serde_json::to_vec(&value).map_err(|_| failure())?);
                self.store.w3c_put("catalog-failures", &id, &value).await?;
                self.store
                    .w3c_set_state("catalog-work", &Value::Null)
                    .await?;
                Err(error)
            }
            result => result,
        }
    }

    pub(super) async fn acquire_catalog(&self, cancel: CancellationToken) -> Result<Catalog> {
        loop {
            cancelled(&cancel)?;
            if let Some(catalog) = self.catalog_step(cancel.clone()).await? {
                return Ok(catalog);
            }
        }
    }
}
