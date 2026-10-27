//! Explicit, append-only publication-policy successors of retained frozen evidence.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Lineage {
    parent: String,
    parent_hash: String,
    parent_acceptance: String,
    parent_acceptance_hash: String,
    metadata_policy: u32,
    processor_version: u32,
    dispositions: String,
    witnesses: String,
    capture_attempts: String,
    original_candidates: usize,
    required_publications: usize,
    excluded_candidates: usize,
    publication_capture_calls: usize,
    interrupted_capture_calls: usize,
    broker_attempts_observed: usize,
    broker_counter_scope: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    standard: String,
    original: Option<String>,
    publication: Option<String>,
    metadata_done: bool,
    last_attempt: Option<i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Seed {
    standard: String,
    witness: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Attempt {
    url: String,
    started_at: i64,
    finished_at: Option<i64>,
    broker_before: usize,
    broker_after: Option<usize>,
    publication: Option<String>,
    status: Option<u16>,
    error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Recovering {
    parent: String,
    parent_hash: String,
    policy: u32,
    seeded: usize,
    seeds: BTreeMap<String, Seed>,
    entries: BTreeMap<String, Entry>,
    attempts: Vec<Attempt>,
}
#[derive(Clone)]
struct Witness {
    data: Value,
}
#[derive(Default)]
struct Qualification {
    standard: String,
    positive: Option<String>,
    negative: Option<String>,
    witnesses: BTreeSet<String>,
}
#[derive(Default)]
struct Qualifications {
    urls: BTreeMap<String, Qualification>,
    witnesses: BTreeMap<String, Witness>,
    bytes: usize,
}
impl Qualifications {
    fn insert(&mut self, standard: &str, url: &str, positive: bool, data: Value) -> Result<()> {
        let encoded = serde_json::to_vec(&data).map_err(|_| failure())?;
        let id = inventory::digest(&encoded);
        let qualification = self.urls.entry(url.into()).or_default();
        if !qualification.standard.is_empty() && qualification.standard != standard {
            return Err(Error::integrity(
                "W3C recovery qualification crosses standards.",
            ));
        }
        qualification.standard = standard.into();
        let previous = if positive {
            &mut qualification.positive
        } else {
            &mut qualification.negative
        };
        if previous.as_ref().is_none_or(|old| &id < old) {
            *previous = Some(id.clone());
        }
        qualification.witnesses.insert(id.clone());
        if !self.witnesses.contains_key(&id) {
            self.bytes = self.bytes.saturating_add(encoded.len());
            self.witnesses.insert(id, Witness { data });
        }
        if self.urls.len() > MAX_PUBLICATIONS
            || self.witnesses.len() > MAX_MEMBERS
            || self.bytes as u64 > MAX_PROJECTION
        {
            return Err(Error::capacity(
                "W3C recovery qualification exceeds its bound.",
            ));
        }
        Ok(())
    }
}
fn target(base: &PublicationUrl, href: &str) -> Option<PublicationUrl> {
    if href.split('#').next().is_none_or(str::is_empty) {
        return None;
    }
    let origin = url::Url::parse(base.as_str()).ok()?;
    let url = origin.join(href).ok()?;
    if url.host_str() != Some(base.host()) {
        return None;
    }
    PublicationUrl::new(url.as_str()).ok()
}
fn standard<'a>(frozen: &'a Frozen, id: &str) -> Result<&'a Standard> {
    frozen
        .catalog
        .standards
        .iter()
        .find(|s| s.id == id)
        .ok_or_else(|| Error::integrity("W3C recovery standard is not frozen."))
}
fn metadata_gap(publication: &Publication) -> bool {
    publication.url.kind() == catalog::PublicationKind::Html
        && publication
            .gaps
            .iter()
            .any(|gap| gap.starts_with("publication_metadata_"))
}

impl W3cCorpus {
    pub(super) async fn publication_frontier(&self, standard: &str) -> Result<Vec<String>> {
        let value = self
            .store
            .w3c_state(&state_key("frontier", standard))
            .await?;
        let Some(value) = value else {
            return Ok(Vec::new());
        };
        if let Some(legacy) = value.as_array() {
            if legacy.is_empty() {
                return Ok(Vec::new());
            }
            return Err(Error::unavailable(
                "Legacy W3C publication frontier requires explicit policy recovery; no queued request was admitted.",
            ));
        }
        if value["metadata_policy"].as_u64() != Some(u64::from(catalog::METADATA_VERSION)) {
            return Err(Error::unavailable(
                "W3C publication frontier has an incompatible metadata policy.",
            ));
        }
        let urls: Vec<String> = decode(value["urls"].clone())?;
        if urls.len() > MAX_PUBLICATIONS {
            return Err(Error::capacity(
                "W3C publication frontier exceeds its bound.",
            ));
        }
        Ok(urls)
    }
    pub(super) async fn retain_publication_frontier(
        &self,
        standard: &str,
        urls: &[String],
    ) -> Result<()> {
        if urls.len() > MAX_PUBLICATIONS {
            return Err(Error::capacity(
                "W3C publication frontier exceeds its bound.",
            ));
        }
        self.store
            .w3c_set_state(
                &state_key("frontier", standard),
                &json!({"metadata_policy":catalog::METADATA_VERSION,"urls":urls}),
            )
            .await
    }
    async fn recovery_publication(&self, id: &str) -> Result<Publication> {
        let row = self
            .store
            .w3c_get("publications", id)
            .await?
            .ok_or_else(failure)?;
        let publication: Publication = decode(row.data)?;
        if row.key != id || publication.id != id {
            return Err(Error::integrity(
                "W3C recovery publication lookup identity changed.",
            ));
        }
        publication.url.validate()?;
        Ok(publication)
    }
    async fn retain_recovery_work(&self, key: &str, work: &Recovering) -> Result<()> {
        if work.entries.len() > MAX_PUBLICATIONS
            || work.attempts.len() > MAX_PUBLICATIONS
            || work.seeds.len() > MAX_PUBLICATIONS
        {
            return Err(Error::capacity("W3C recovery inventory exceeds its bound."));
        }
        self.store.w3c_set_state(key, &encode(work)?).await
    }
    async fn seed_recovery(
        &self,
        parent: &Frozen,
        key: &str,
        work: &mut Recovering,
        cancel: CancellationToken,
    ) -> Result<()> {
        while work.seeded < parent.catalog.standards.len() {
            cancelled(&cancel)?;
            let item = &parent.catalog.standards[work.seeded];
            let observation = parent.observations.get(&item.id).ok_or_else(|| {
                Error::integrity("W3C recovery has no frozen source observation.")
            })?;
            if observation.repo.as_str() != item.repository {
                return Err(Error::integrity(
                    "W3C recovery source identity differs from the frozen catalog.",
                ));
            }
            let mut seeds = vec![
                (
                    PublicationUrl::new(&item.url)?,
                    json!({"kind":"catalog_listed","catalog":parent.catalog.id,"standard":item.id,"url":item.url}),
                ),
                (
                    catalog::current_publication(item)?,
                    json!({"kind":"catalog_current","catalog":parent.catalog.id,"standard":item.id,"url":catalog::current_publication(item)?.as_str()}),
                ),
            ];
            let git = self.git(&item.repository)?;
            if !git.repository().is_dir() {
                git.restore(&observation.manifest, cancel.clone()).await?;
            }
            let paths = git.publication_paths(observation, cancel.clone()).await?;
            for path in paths {
                for url in catalog::source_publications(item, std::slice::from_ref(&path))? {
                    seeds.push((url.clone(), json!({"kind":"frozen_source_inventory","standard":item.id,"observation":observation.manifest.body_hash,"path":path,"url":url.as_str()})));
                }
            }
            for (url, witness) in seeds {
                if let Some(existing) = work.seeds.get(url.as_str())
                    && existing.standard != item.id
                {
                    return Err(Error::integrity(
                        "W3C recovery catalog seeds overlap standards.",
                    ));
                }
                work.seeds.entry(url.as_str().into()).or_insert(Seed {
                    standard: item.id.clone(),
                    witness,
                });
            }
            work.seeded += 1;
            self.retain_recovery_work(key, work).await?;
        }
        Ok(())
    }
    async fn repair_recovery_metadata(
        &self,
        parent: &Frozen,
        key: &str,
        work: &mut Recovering,
        cancel: CancellationToken,
    ) -> Result<()> {
        let urls: Vec<_> = work.entries.keys().cloned().collect();
        for url in urls {
            cancelled(&cancel)?;
            let entry = work.entries.get(&url).cloned().ok_or_else(failure)?;
            if entry.metadata_done {
                continue;
            }
            let Some(id) = entry.publication else {
                continue;
            };
            let old: Publication = self.recovery_publication(&id).await?;
            let next = if old.status == 200
                && old.artifact.is_some()
                && old.url.kind() == catalog::PublicationKind::Html
                && old.metadata_version < catalog::METADATA_VERSION
            {
                self.repair_publication_metadata_inner(&old, cancel.clone(), false)
                    .await?
            } else {
                old
            };
            let selected = standard(parent, &next.standard)?;
            if next.url.as_str() == catalog::current_publication(selected)?.as_str()
                && !next.repositories.is_empty()
                && !next.repositories.contains(&selected.repository)
            {
                return Err(Error::integrity(
                    "W3C repaired metadata conflicts with frozen source authority.",
                ));
            }
            let entry = work.entries.get_mut(&url).ok_or_else(failure)?;
            entry.publication = Some(next.id);
            entry.metadata_done = true;
            self.retain_recovery_work(key, work).await?;
        }
        Ok(())
    }
    async fn capture_recovery_publication(
        &self,
        parent: &Frozen,
        key: &str,
        work: &mut Recovering,
        standard_id: &str,
        url: &PublicationUrl,
        cancel: CancellationToken,
    ) -> Result<Publication> {
        let now = devres_domain::unix_now();
        if let Some(entry) = work.entries.get(url.as_str()) {
            if entry
                .last_attempt
                .is_some_and(|at| now.saturating_sub(at) < 60)
            {
                return Err(Error::unavailable(
                    "W3C recovery publication retry is not due.",
                ));
            }
            if let Some(id) = &entry.publication {
                let previous: Publication = self.recovery_publication(id).await?;
                let backoff = if previous.status == 404 { 300 } else { 60 };
                if previous.status != 200 && now.saturating_sub(previous.observed_at) < backoff {
                    return Err(Error::unavailable(
                        "W3C recovery publication retry is not due.",
                    ));
                }
            } else if entry
                .last_attempt
                .is_some_and(|at| now.saturating_sub(at) < 60)
            {
                return Err(Error::unavailable(
                    "W3C recovery publication retry is not due.",
                ));
            }
        }
        if work.attempts.len() >= MAX_PUBLICATIONS {
            return Err(Error::capacity("W3C recovery attempt limit exceeded."));
        }
        let entry = work.entries.entry(url.as_str().into()).or_insert(Entry {
            standard: standard_id.into(),
            original: None,
            publication: None,
            metadata_done: false,
            last_attempt: None,
        });
        if entry.standard != standard_id {
            return Err(Error::integrity("W3C recovery capture crosses standards."));
        }
        entry.last_attempt = Some(now);
        let before = self.broker.attempt_count();
        work.attempts.push(Attempt {
            url: url.as_str().into(),
            started_at: now,
            finished_at: None,
            broker_before: before,
            broker_after: None,
            publication: None,
            status: None,
            error: None,
        });
        self.retain_recovery_work(key, work).await?;
        let result = self
            .capture_publication_inner(standard(parent, standard_id)?, url.clone(), cancel, false)
            .await;
        let after = self.broker.attempt_count();
        let attempt = work.attempts.last_mut().ok_or_else(failure)?;
        attempt.finished_at = Some(devres_domain::unix_now());
        attempt.broker_after = Some(after);
        match &result {
            Ok(publication) => {
                attempt.publication = Some(publication.id.clone());
                attempt.status = Some(publication.status);
            }
            Err(error) => {
                attempt.error = Some(error.code.clone());
            }
        }
        if let Ok(publication) = &result {
            let entry = work.entries.get_mut(url.as_str()).ok_or_else(failure)?;
            entry.publication = Some(publication.id.clone());
            entry.metadata_done = true;
        }
        self.retain_recovery_work(key, work).await?;
        let publication = result?;
        if publication.status != 200 || publication.artifact.is_none() {
            return Err(Error::unavailable(
                "A qualified W3C recovery publication remains unavailable.",
            ));
        }
        Ok(publication)
    }
    async fn qualify_recovery(
        &self,
        parent: &Frozen,
        key: &str,
        work: &mut Recovering,
        cancel: CancellationToken,
    ) -> Result<Qualifications> {
        let mut qualifications = Qualifications::default();
        let mut pending = BTreeMap::<String, String>::new();
        for (url, seed) in &work.seeds {
            qualifications.insert(&seed.standard, url, true, seed.witness.clone())?;
            pending.insert(url.clone(), seed.standard.clone());
        }
        let mut visited = BTreeSet::new();
        while let Some((url, standard_id)) = pending.pop_first() {
            cancelled(&cancel)?;
            if !visited.insert(url.clone()) {
                continue;
            }
            if visited.len() > MAX_PUBLICATIONS {
                return Err(Error::capacity("W3C recovery closure exceeds its bound."));
            }
            let parsed = PublicationUrl::new(&url)?;
            let existing = match work
                .entries
                .get(&url)
                .and_then(|entry| entry.publication.as_ref())
            {
                Some(id) => Some(self.recovery_publication(id).await?),
                None => None,
            };
            let publication = match existing {
                Some(publication)
                    if publication.status == 200 && publication.artifact.is_some() =>
                {
                    publication
                }
                _ => {
                    self.capture_recovery_publication(
                        parent,
                        key,
                        work,
                        &standard_id,
                        &parsed,
                        cancel.clone(),
                    )
                    .await?
                }
            };
            if publication.standard != standard_id || publication.url.as_str() != url {
                return Err(Error::integrity(
                    "W3C recovery publication identity changed.",
                ));
            }
            if metadata_gap(&publication)
                || publication.url.kind() == catalog::PublicationKind::Html
                    && publication.metadata_version < catalog::METADATA_VERSION
            {
                return Err(Error::unavailable(
                    "W3C recovery publication discovery remains incomplete.",
                ));
            }
            if publication.url.kind() != catalog::PublicationKind::Html {
                continue;
            }
            let selected = standard(parent, &standard_id)?;
            if publication.url.as_str() == catalog::current_publication(selected)?.as_str()
                && !publication.repositories.is_empty()
                && !publication.repositories.contains(&selected.repository)
            {
                return Err(Error::integrity(
                    "W3C recovery publication conflicts with frozen source authority.",
                ));
            }
            let admitted: BTreeSet<_> = catalog::qualified_advertised(
                selected,
                &publication.url,
                &publication.advertisements,
            )
            .into_iter()
            .map(|url| url.as_str().to_owned())
            .collect();
            for advertisement in &publication.advertisements {
                let Some(destination) = target(&publication.url, &advertisement.href)
                    .filter(|url| admitted.contains(url.as_str()))
                else {
                    continue;
                };
                let destination = destination.as_str().to_owned();
                let witness = json!({"kind":"advertisement","source_publication":publication.id,"source_parent":publication.metadata_parent,"artifact":publication.artifact.as_ref().map(|a|&a.body_hash),"observed_at":publication.observed_at,"href":advertisement.href,"role":advertisement.role,"target":destination});
                qualifications.insert(&standard_id, &destination, true, witness)?;
                pending.insert(destination, standard_id.clone());
            }
            for exclusion in &publication.exclusions {
                let Some(destination) = target(&publication.url, &exclusion.href) else {
                    continue;
                };
                let witness = json!({"kind":"exclusion","source_publication":publication.id,"source_parent":publication.metadata_parent,"artifact":publication.artifact.as_ref().map(|a|&a.body_hash),"observed_at":publication.observed_at,"href":exclusion.href,"role":exclusion.role,"source_anchor":exclusion.source_anchor,"target_anchor":exclusion.target_anchor,"target":destination.as_str()});
                qualifications.insert(&standard_id, destination.as_str(), false, witness)?;
            }
        }
        Ok(qualifications)
    }
    /// Build a separately identified policy successor; original observations and
    /// receipts are never overwritten. Only missing positively qualified bodies
    /// can initiate mediated publication acquisition, never catalog/Git refresh.
    pub async fn recover_frozen(
        &self,
        parent_value: &Value,
        cancel: CancellationToken,
    ) -> Result<Value> {
        let _guard = self.processing.lock().await;
        cancelled(&cancel)?;
        let parent: Frozen = decode(parent_value.clone())?;
        if parent.mode != "full" || catalog::METADATA_VERSION < 3 {
            return Err(Error::invalid(
                "W3C recovery requires a full frozen observation and policy three or later.",
            ));
        }
        if parent.catalog.standards.is_empty() || parent.publications.len() > MAX_PUBLICATIONS {
            return Err(Error::integrity(
                "W3C recovery parent inventory is invalid.",
            ));
        }
        let retained = self
            .store
            .w3c_get("frozen", &parent.id)
            .await?
            .ok_or_else(|| Error::integrity("W3C recovery parent is not retained."))?;
        if retained.data != *parent_value {
            return Err(Error::integrity(
                "W3C recovery parent differs from retained evidence.",
            ));
        }
        let parent_hash =
            inventory::digest(&serde_json::to_vec(parent_value).map_err(|_| failure())?);
        let receipt_key = format!("{}:full:{PROCESSOR_VERSION}", parent.id);
        let receipt = self
            .store
            .w3c_get("acceptance", &receipt_key)
            .await?
            .ok_or_else(|| {
                Error::integrity("W3C recovery requires a retained parent acceptance receipt.")
            })?;
        let receipt_hash =
            inventory::digest(&serde_json::to_vec(&receipt.data).map_err(|_| failure())?);
        if receipt.data["processor_version"] != PROCESSOR_VERSION
            || receipt.data["frozen"] != parent.id
            || receipt.data["mode"] != "full"
        {
            return Err(Error::integrity(
                "W3C recovery parent receipt identity changed.",
            ));
        }
        let suffix = format!("{}:{}", parent.id, catalog::METADATA_VERSION);
        let work_key = state_key("recovering", &suffix);
        let result_key = state_key("recovery-result", &suffix);
        if let Some(result) = self
            .store
            .w3c_state(&result_key)
            .await?
            .and_then(|v| v.as_str().map(str::to_owned))
        {
            let value = self
                .store
                .w3c_get("frozen", &result)
                .await?
                .map(|row| row.data)
                .ok_or_else(failure)?;
            let child: Frozen = decode(value.clone())?;
            let lineage = child.lineage.as_ref().ok_or_else(failure)?;
            let identity = inventory::digest(
                &serde_json::to_vec(&(
                    &child.catalog,
                    &child.observations,
                    &child.publications,
                    lineage,
                    "full",
                ))
                .map_err(|_| failure())?,
            );
            if child.mode != "full"
                || child.id != result
                || identity != result
                || lineage.parent != parent.id
                || lineage.parent_hash != parent_hash
                || lineage.parent_acceptance_hash != receipt_hash
                || lineage.metadata_policy != catalog::METADATA_VERSION
                || lineage.processor_version != PROCESSOR_VERSION
                || encode(&child.catalog)? != encode(&parent.catalog)?
                || encode(&child.observations)? != encode(&parent.observations)?
            {
                return Err(Error::integrity(
                    "W3C retained recovery successor identity changed.",
                ));
            }
            return Ok(value);
        }
        let mut work: Recovering = if let Some(value) = self
            .store
            .w3c_state(&work_key)
            .await?
            .filter(|v| !v.is_null())
        {
            decode(value)?
        } else {
            let mut entries = BTreeMap::new();
            for id in &parent.publications {
                cancelled(&cancel)?;
                let publication: Publication = self.recovery_publication(id).await?;
                publication.url.validate()?;
                standard(&parent, &publication.standard)?;
                if entries
                    .insert(
                        publication.url.as_str().into(),
                        Entry {
                            standard: publication.standard,
                            original: Some(id.clone()),
                            publication: Some(id.clone()),
                            metadata_done: false,
                            last_attempt: None,
                        },
                    )
                    .is_some()
                {
                    return Err(Error::integrity(
                        "W3C recovery parent contains duplicate publication URLs.",
                    ));
                }
            }
            Recovering {
                parent: parent.id.clone(),
                parent_hash: parent_hash.clone(),
                policy: catalog::METADATA_VERSION,
                seeded: 0,
                seeds: BTreeMap::new(),
                entries,
                attempts: Vec::new(),
            }
        };
        if work.parent != parent.id
            || work.parent_hash != parent_hash
            || work.policy != catalog::METADATA_VERSION
        {
            return Err(Error::integrity(
                "W3C recovery checkpoint identity changed.",
            ));
        }
        self.retain_recovery_work(&work_key, &work).await?;
        self.seed_recovery(&parent, &work_key, &mut work, cancel.clone())
            .await?;
        self.repair_recovery_metadata(&parent, &work_key, &mut work, cancel.clone())
            .await?;
        let qualifications = self
            .qualify_recovery(&parent, &work_key, &mut work, cancel.clone())
            .await?;
        let mut records = Vec::new();
        let mut selected = BTreeMap::new();
        let mut excluded = 0;
        for (url, entry) in &work.entries {
            cancelled(&cancel)?;
            let qualification = qualifications.urls.get(url).ok_or_else(|| {
                Error::unavailable("A prior W3C candidate has no source-role qualification.")
            })?;
            if qualification.standard != entry.standard {
                return Err(Error::unavailable(
                    "W3C recovery candidate qualification is conflicting.",
                ));
            }
            let (disposition, witness) = if let Some(witness) = &qualification.positive {
                let id = entry.publication.as_ref().ok_or_else(failure)?;
                let publication: Publication = self.recovery_publication(id).await?;
                if publication.status != 200
                    || publication.artifact.is_none()
                    || metadata_gap(&publication)
                {
                    return Err(Error::unavailable(
                        "A required W3C recovery publication remains incomplete.",
                    ));
                }
                selected.insert(url.clone(), id.clone());
                ("required_publication", witness)
            } else if let Some(witness) = &qualification.negative {
                excluded += usize::from(entry.original.is_some());
                ("non_publication", witness)
            } else {
                return Err(Error::unavailable(
                    "W3C recovery candidate qualification is absent.",
                ));
            };
            records.push((qualification.witnesses.iter().cloned().collect::<Vec<_>>(),json!({"url":url,"standard":entry.standard,"original_publication":entry.original,"publication":entry.publication,"disposition":disposition,"witness":witness,"policy":catalog::METADATA_VERSION})));
        }
        let mut shared = inventory::ProjectionBatch::new(self.store.as_ref());
        let mut witness_ids = BTreeSet::new();
        let mut dispositions = Vec::new();
        for (id, witness) in &qualifications.witnesses {
            shared
                .put_id("recovery-witnesses", id, witness.data.clone())
                .await?;
            witness_ids.insert(id.clone());
        }
        for (witnesses, mut record) in records {
            record["witnesses"] = json!(shared.sequence(&witnesses).await?);
            dispositions.push(shared.put("recovery-dispositions", record).await?);
        }
        let mut attempts = Vec::new();
        for attempt in &work.attempts {
            attempts.push(shared.put("recovery-attempts", encode(attempt)?).await?);
        }
        let disposition_root = shared.sequence(&dispositions).await?;
        let witness_root = shared
            .sequence(&witness_ids.into_iter().collect::<Vec<_>>())
            .await?;
        let attempts_root = shared.sequence(&attempts).await?;
        shared.flush().await?;
        let mut publications = Vec::new();
        for id in &parent.publications {
            let original: Publication = self.recovery_publication(id).await?;
            if let Some(id) = selected.remove(original.url.as_str()) {
                publications.push(id);
            }
        }
        publications.extend(selected.into_values());
        let lineage = Lineage {
            parent: parent.id.clone(),
            parent_hash,
            parent_acceptance: receipt_key,
            parent_acceptance_hash: receipt_hash,
            metadata_policy: catalog::METADATA_VERSION,
            processor_version: PROCESSOR_VERSION,
            dispositions: disposition_root,
            witnesses: witness_root,
            capture_attempts: attempts_root,
            original_candidates: parent.publications.len(),
            required_publications: publications.len(),
            excluded_candidates: excluded,
            publication_capture_calls: work.attempts.len(),
            interrupted_capture_calls: work
                .attempts
                .iter()
                .filter(|attempt| attempt.finished_at.is_none())
                .count(),
            broker_attempts_observed: work
                .attempts
                .iter()
                .map(|a| {
                    a.broker_after
                        .unwrap_or(a.broker_before)
                        .saturating_sub(a.broker_before)
                })
                .fold(0usize, usize::saturating_add),
            broker_counter_scope: "shared_broker_observed_during_private_capture_calls".into(),
        };
        let id = inventory::digest(
            &serde_json::to_vec(&(
                &parent.catalog,
                &parent.observations,
                &publications,
                &lineage,
                "full",
            ))
            .map_err(|_| failure())?,
        );
        let successor = Frozen {
            id: id.clone(),
            catalog: parent.catalog,
            observations: parent.observations,
            publications,
            mode: "full".into(),
            lineage: Some(lineage),
        };
        let value = encode(&successor)?;
        cancelled(&cancel)?;
        self.store.w3c_put_many(&[devres_application::w3c::Write {kind:"frozen".into(),key:id.clone(),data:value.clone()},devres_application::w3c::Write {kind:"frozen-recoveries".into(),key:id.clone(),data:json!({"parent":parent.id,"successor":id,"policy":catalog::METADATA_VERSION,"lineage":successor.lineage})}]).await?;
        self.store.w3c_set_state(&result_key, &json!(id)).await?;
        self.store.w3c_set_state(&work_key, &Value::Null).await?;
        Ok(value)
    }
}
