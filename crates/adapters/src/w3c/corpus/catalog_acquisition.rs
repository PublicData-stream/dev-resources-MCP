//! Durable candidate discovery. Only a complete catalog can replace the published head.
use super::catalog_failure::{Attempt, CatalogFailure, Operation, Reason};
use super::*;

const VERSION: u32 = 1;
const MAX_PAGES: usize = 1000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogWork {
    pub(super) version: u32,
    pub(super) generation: String,
    pub(super) started_at: i64,
    pub(super) predecessor: Option<String>,
    pub(super) pages: Vec<String>,
    pub(super) standards: usize,
    pub(super) complete: bool,
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

/// Replay one typed immutable page; ordered ancestry remains the caller's responsibility.
pub(super) fn verify_diagnostic_page(value: Value, body: &[u8]) -> Result<()> {
    let page: CatalogPage = decode(value)?;
    if page.version != VERSION
        || page.page == 0
        || page.page as usize > MAX_PAGES
        || !crate::integrity::valid_hash(&page.generation)
        || page
            .previous
            .as_ref()
            .is_some_and(|id| !crate::integrity::valid_hash(id))
        || page.artifact.bytes > 8 * 1024 * 1024
        || page.artifact.bytes != body.len() as u64
        || page.artifact.relative_path
            != crate::integrity::relative_path(&page.artifact.body_hash)?.to_string_lossy()
    {
        return Err(Error::integrity("Invalid retained W3C diagnostic page."));
    }
    crate::integrity::verify(&page.artifact.body_hash, body)?;
    let mut parsed = catalog::parse_page(body, page.observed_at)?;
    if parsed.standards.len() != page.standards.len()
        || catalog::page_has_next(body)? != page.has_next
    {
        return Err(Error::integrity(
            "Retained W3C catalog page differs from its body.",
        ));
    }
    let legacy = crate::integrity::legacy_hash(body);
    for (expected, retained) in parsed.standards.iter_mut().zip(&page.standards) {
        // Canonical migration preserves this original capture metadata while rewriting
        // the raw descriptor. Both algorithms must identify these exact bytes.
        let capture = retained.metadata["api_catalog_capture"]
            .as_str()
            .filter(|capture| *capture == page.artifact.body_hash || *capture == legacy)
            .ok_or_else(|| Error::integrity("W3C catalog capture metadata differs."))?;
        expected.metadata["api_catalog_capture"] = json!(capture);
    }
    if encode(&parsed.standards)? != encode(&page.standards)? {
        return Err(Error::integrity(
            "Retained W3C catalog membership differs from its body.",
        ));
    }
    Ok(())
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
                        let failure = CatalogFailure::decode(row.data)?;
                        self.catalog_pages(&failure.work, &cancel).await?;
                        if let Some(artifact) = failure.attempt.and_then(|attempt| attempt.artifact)
                        {
                            let actual = self
                                .raw
                                .verify(&artifact.body_hash, 8 * 1024 * 1024, cancel.clone())
                                .await?;
                            if actual != artifact {
                                return Err(Error::integrity(
                                    "Retained W3C failed-attempt artifact differs.",
                                ));
                            }
                        }
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
        self.catalog_pages_diagnostic(work, cancel, &mut Attempt::new())
            .await
    }

    async fn catalog_pages_diagnostic(
        &self,
        work: &CatalogWork,
        cancel: &CancellationToken,
        attempt: &mut Attempt,
    ) -> Result<(BTreeMap<String, Standard>, Vec<BulkArtifact>, i64)> {
        attempt.enter(Operation::Checkpoint, Reason::CheckpointLookup);
        let mut standards = BTreeMap::new();
        let mut captures = Vec::new();
        let mut observed_at = i64::MAX;
        let mut previous = None;
        for (position, id) in work.pages.iter().enumerate() {
            cancelled(cancel)?;
            attempt.enter(Operation::Checkpoint, Reason::CheckpointLookup);
            attempt.page = Some(position as u32 + 1);
            let value = self
                .store
                .w3c_get("catalog-pages", id)
                .await?
                .ok_or_else(|| Error::integrity("W3C catalog checkpoint page missing."))?
                .data;
            attempt.reason = Reason::CheckpointDigest;
            crate::integrity::verify(id, &serde_json::to_vec(&value).map_err(|_| failure())?)?;
            attempt.reason = Reason::CheckpointDecode;
            let page: CatalogPage = decode(value)?;
            attempt.artifact = Some(page.artifact.clone());
            attempt.observed_at = Some(page.observed_at);
            attempt.reason = Reason::CheckpointAncestry;
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
                    attempt.reason = Reason::DuplicateIdentity;
                    return Err(Error::integrity(
                        "Duplicate W3C specification across API pages.",
                    ));
                }
            }
            if standards.len() > catalog::MAX_CATALOG {
                attempt.reason = Reason::CountLimit;
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
            attempt.enter(Operation::Checkpoint, Reason::CheckpointCount);
            return Err(Error::integrity("W3C catalog checkpoint count differs."));
        }
        Ok((standards, captures, observed_at))
    }

    async fn catalog_step_inner(
        &self,
        work: &mut CatalogWork,
        cancel: CancellationToken,
        attempt: &mut Attempt,
    ) -> Result<Option<Catalog>> {
        // Verify committed checkpoint rows and their chain before another provider request.
        let (mut standards, mut captures, mut observed_at) = self
            .catalog_pages_diagnostic(work, &cancel, attempt)
            .await?;
        if !work.complete {
            attempt.enter(Operation::Acquisition, Reason::PageLimit);
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
            attempt.enter(Operation::Acquisition, Reason::CollectorStateWrite);
            attempt.page = Some(page);
            attempt.observed_at = Some(acquired_at);
            self.collector_begin("catalog", Phase::CatalogAcquisition)
                .await?;
            attempt.reason = Reason::Acquisition;
            let (bytes, artifact) = self
                .api(catalog::ApiOperation::Catalog { page }, cancel.clone())
                .await?;
            attempt.enter(Operation::PageValidation, Reason::CollectorStateWrite);
            attempt.page = Some(page);
            attempt.observed_at = Some(acquired_at);
            attempt.artifact = Some(artifact.clone());
            self.collector_begin("catalog", Phase::CatalogValidation)
                .await?;
            let mut parsed =
                catalog::parse_page_diagnostic(&bytes, acquired_at).map_err(|failure| {
                    attempt.reason = Reason::ParsePage {
                        reason: failure.reason,
                    };
                    attempt.row = failure.row;
                    collection::at_phase(failure.error, Phase::CatalogValidation)
                })?;
            for standard in &mut parsed.standards {
                standard.metadata["api_catalog_capture"] = json!(artifact.body_hash);
            }
            attempt.reason = Reason::Pagination;
            let has_next = catalog::page_has_next(&bytes)
                .map_err(|e| collection::at_phase(e, Phase::CatalogValidation))?;
            for standard in &parsed.standards {
                if standards
                    .insert(standard.id.clone(), standard.clone())
                    .is_some()
                {
                    attempt.reason = Reason::DuplicateIdentity;
                    return Err(Error::integrity(
                        "Duplicate W3C specification across API pages.",
                    ));
                }
            }
            if standards.len() > catalog::MAX_CATALOG {
                attempt.reason = Reason::CountLimit;
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
            attempt.operation = Operation::PageRetention;
            attempt.reason = Reason::EvidenceWrite;
            let value = encode(&retained)?;
            let id = inventory::digest(&serde_json::to_vec(&value).map_err(|_| failure())?);
            self.store.w3c_put("catalog-pages", &id, &value).await?;
            work.pages.push(id);
            work.standards = standards.len();
            work.complete = !has_next;
            attempt.reason = Reason::StateWrite;
            self.store
                .w3c_set_state("catalog-work", &encode(work)?)
                .await?;
            captures.push(artifact);
            observed_at = observed_at.min(acquired_at);
            if has_next {
                return Ok(None);
            }
        }
        attempt.enter(Operation::ArtifactVerification, Reason::EmptyCatalog);
        if standards.is_empty() {
            return Err(Error::integrity("W3C catalog is empty."));
        }
        for artifact in &captures {
            attempt.reason = Reason::ArtifactRead;
            attempt.artifact = Some(artifact.clone());
            attempt.observed_at = Some(observed_at);
            let actual = self
                .raw
                .verify(&artifact.body_hash, 8 * 1024 * 1024, cancel.clone())
                .await
                .map_err(|e| collection::at_phase(e, Phase::CatalogRetention))?;
            if actual != *artifact {
                attempt.reason = Reason::ArtifactDescriptor;
                return Err(collection::at_phase(
                    Error::integrity("W3C catalog artifact differs."),
                    Phase::CatalogRetention,
                ));
            }
        }
        attempt.enter(Operation::Reconciliation, Reason::Reconciliation);
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
        attempt.enter(Operation::Publication, Reason::CollectorStateWrite);
        self.collector_begin("catalog", Phase::CatalogPublication)
            .await?;
        attempt.enter(Operation::Publication, Reason::EvidenceWrite);
        self.store
            .w3c_put("catalogs", &catalog.id, &encode(&catalog)?)
            .await?;
        self.store.w3c_put("catalog-captures", &catalog.id, &json!({"api_pages":captures,"observed_at":observed_at,"generation":work.generation,"pages":work.pages})).await?;
        attempt.reason = Reason::StateWrite;
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
        let mut attempt = Attempt::new();
        let result = self
            .catalog_step_inner(&mut work, cancel, &mut attempt)
            .await;
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
                let retained = CatalogFailure {
                    version: 2,
                    work,
                    code: collection::safe_code(&error.code).into(),
                    context: collection::context(&error),
                    observed_at: devres_domain::unix_now(),
                    attempt: Some(attempt),
                };
                retained.validate()?;
                let value = encode(&retained)?;
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

#[cfg(test)]
mod diagnostic_page_tests {
    use super::*;

    #[test]
    fn exact_retained_page_replay_rejects_tampered_membership_pagination_and_descriptors() {
        let body = serde_json::to_vec(&json!({"_links":{"specifications":[
            {"shortname":"fixture","title":"Retained fixture"}
        ],"next":{"href":"https://api.w3.org/specifications?page=2&items=100"}}}))
        .unwrap();
        let digest = inventory::digest(&body);
        let mut parsed = catalog::parse_page(&body, 7).unwrap();
        parsed.standards[0].metadata["api_catalog_capture"] = json!(digest);
        let page = encode(&CatalogPage {
            version: 1,
            generation: inventory::digest(b"generation"),
            page: 1,
            observed_at: 7,
            previous: None,
            artifact: BulkArtifact {
                body_hash: digest.clone(),
                bytes: body.len() as u64,
                relative_path: crate::integrity::relative_path(&digest)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            },
            standards: parsed.standards,
            has_next: true,
        })
        .unwrap();
        verify_diagnostic_page(page.clone(), &body).unwrap();
        for (path, replacement) in [
            ("/version", json!(2)),
            ("/page", json!(0)),
            ("/page", json!(1001)),
            ("/generation", json!("invalid")),
            ("/previous", json!("invalid")),
            ("/has_next", json!(false)),
            ("/artifact/bytes", json!(body.len() + 1)),
            ("/artifact/relative_path", json!("../outside")),
            (
                "/artifact/body_hash",
                json!(inventory::digest(b"other bytes")),
            ),
            ("/standards/0/title", json!("Substituted title")),
            ("/standards/0/repository", json!("Substituted repository")),
            (
                "/standards/0/metadata/api_catalog_capture",
                json!(inventory::digest(b"other capture")),
            ),
        ] {
            let mut tampered = page.clone();
            *tampered.pointer_mut(path).unwrap() = replacement;
            assert!(verify_diagnostic_page(tampered, &body).is_err(), "{path}");
        }
        let mut changed_body = body.clone();
        changed_body[0] = b'[';
        assert!(verify_diagnostic_page(page.clone(), &changed_body).is_err());

        // A migrated BLAKE3 raw descriptor can retain its original SHA256 capture metadata.
        let mut migrated = page;
        migrated["standards"][0]["metadata"]["api_catalog_capture"] =
            json!(crate::integrity::legacy_hash(&body));
        verify_diagnostic_page(migrated, &body).unwrap();
    }
}
