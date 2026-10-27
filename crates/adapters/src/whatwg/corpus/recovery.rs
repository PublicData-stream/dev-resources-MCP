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
                "WHATWG recovery qualification crosses standards.",
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
                "WHATWG recovery qualification exceeds its bound.",
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
        .ok_or_else(|| Error::integrity("WHATWG recovery standard is not frozen."))
}
fn metadata_gap(publication: &Publication) -> bool {
    publication.url.kind() == catalog::PublicationKind::Html
        && publication
            .gaps
            .iter()
            .any(|gap| gap.starts_with("publication_metadata_"))
}

impl WhatwgCorpus {
    pub(super) async fn publication_frontier(&self, standard: &str) -> Result<Vec<String>> {
        let value = self
            .store
            .whatwg_state(&state_key("frontier", standard))
            .await?;
        let Some(value) = value else {
            return Ok(Vec::new());
        };
        if let Some(legacy) = value.as_array() {
            if legacy.is_empty() {
                return Ok(Vec::new());
            }
            return Err(Error::unavailable(
                "Legacy WHATWG publication frontier requires explicit policy recovery; no queued request was admitted.",
            ));
        }
        if value["metadata_policy"].as_u64() != Some(u64::from(catalog::METADATA_VERSION)) {
            return Err(Error::unavailable(
                "WHATWG publication frontier has an incompatible metadata policy.",
            ));
        }
        let urls: Vec<String> = decode(value["urls"].clone())?;
        if urls.len() > MAX_PUBLICATIONS {
            return Err(Error::capacity(
                "WHATWG publication frontier exceeds its bound.",
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
                "WHATWG publication frontier exceeds its bound.",
            ));
        }
        self.store
            .whatwg_set_state(
                &state_key("frontier", standard),
                &json!({"metadata_policy":catalog::METADATA_VERSION,"urls":urls}),
            )
            .await
    }
    async fn recovery_publication(&self, id: &str) -> Result<Publication> {
        let row = self
            .store
            .whatwg_get("publications", id)
            .await?
            .ok_or_else(failure)?;
        let publication: Publication = decode(row.data)?;
        if row.key != id || publication.id != id {
            return Err(Error::integrity(
                "WHATWG recovery publication lookup identity changed.",
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
            return Err(Error::capacity(
                "WHATWG recovery inventory exceeds its bound.",
            ));
        }
        self.store.whatwg_set_state(key, &encode(work)?).await
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
                Error::integrity("WHATWG recovery has no frozen source observation.")
            })?;
            if observation.repo.as_str() != item.repository {
                return Err(Error::integrity(
                    "WHATWG recovery source identity differs from the frozen catalog.",
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
                        "WHATWG recovery catalog seeds overlap standards.",
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
                    "WHATWG repaired metadata conflicts with frozen source authority.",
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
                    "WHATWG recovery publication retry is not due.",
                ));
            }
            if let Some(id) = &entry.publication {
                let previous: Publication = self.recovery_publication(id).await?;
                let backoff = if previous.status == 404 { 300 } else { 60 };
                if previous.status != 200 && now.saturating_sub(previous.observed_at) < backoff {
                    return Err(Error::unavailable(
                        "WHATWG recovery publication retry is not due.",
                    ));
                }
            } else if entry
                .last_attempt
                .is_some_and(|at| now.saturating_sub(at) < 60)
            {
                return Err(Error::unavailable(
                    "WHATWG recovery publication retry is not due.",
                ));
            }
        }
        if work.attempts.len() >= MAX_PUBLICATIONS {
            return Err(Error::capacity("WHATWG recovery attempt limit exceeded."));
        }
        let entry = work.entries.entry(url.as_str().into()).or_insert(Entry {
            standard: standard_id.into(),
            original: None,
            publication: None,
            metadata_done: false,
            last_attempt: None,
        });
        if entry.standard != standard_id {
            return Err(Error::integrity(
                "WHATWG recovery capture crosses standards.",
            ));
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
                "A qualified WHATWG recovery publication remains unavailable.",
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
                return Err(Error::capacity(
                    "WHATWG recovery closure exceeds its bound.",
                ));
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
                    "WHATWG recovery publication identity changed.",
                ));
            }
            if metadata_gap(&publication)
                || publication.url.kind() == catalog::PublicationKind::Html
                    && publication.metadata_version < catalog::METADATA_VERSION
            {
                return Err(Error::unavailable(
                    "WHATWG recovery publication discovery remains incomplete.",
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
                    "WHATWG recovery publication conflicts with frozen source authority.",
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
                "WHATWG recovery requires a full frozen observation and policy three or later.",
            ));
        }
        if parent.catalog.standards.is_empty() || parent.publications.len() > MAX_PUBLICATIONS {
            return Err(Error::integrity(
                "WHATWG recovery parent inventory is invalid.",
            ));
        }
        let retained = self
            .store
            .whatwg_get("frozen", &parent.id)
            .await?
            .ok_or_else(|| Error::integrity("WHATWG recovery parent is not retained."))?;
        if retained.data != *parent_value {
            return Err(Error::integrity(
                "WHATWG recovery parent differs from retained evidence.",
            ));
        }
        let parent_hash =
            inventory::digest(&serde_json::to_vec(parent_value).map_err(|_| failure())?);
        let receipt_key = format!("{}:full:{PROCESSOR_VERSION}", parent.id);
        let receipt = self
            .store
            .whatwg_get("acceptance", &receipt_key)
            .await?
            .ok_or_else(|| {
                Error::integrity("WHATWG recovery requires a retained parent acceptance receipt.")
            })?;
        let receipt_hash =
            inventory::digest(&serde_json::to_vec(&receipt.data).map_err(|_| failure())?);
        if receipt.data["processor_version"] != PROCESSOR_VERSION
            || receipt.data["frozen"] != parent.id
            || receipt.data["mode"] != "full"
        {
            return Err(Error::integrity(
                "WHATWG recovery parent receipt identity changed.",
            ));
        }
        let suffix = format!("{}:{}", parent.id, catalog::METADATA_VERSION);
        let work_key = state_key("recovering", &suffix);
        let result_key = state_key("recovery-result", &suffix);
        if let Some(result) = self
            .store
            .whatwg_state(&result_key)
            .await?
            .and_then(|v| v.as_str().map(str::to_owned))
        {
            let value = self
                .store
                .whatwg_get("frozen", &result)
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
                    "WHATWG retained recovery successor identity changed.",
                ));
            }
            return Ok(value);
        }
        let mut work: Recovering = if let Some(value) = self
            .store
            .whatwg_state(&work_key)
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
                        "WHATWG recovery parent contains duplicate publication URLs.",
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
                "WHATWG recovery checkpoint identity changed.",
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
                Error::unavailable("A prior WHATWG candidate has no source-role qualification.")
            })?;
            if qualification.standard != entry.standard {
                return Err(Error::unavailable(
                    "WHATWG recovery candidate qualification is conflicting.",
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
                        "A required WHATWG recovery publication remains incomplete.",
                    ));
                }
                selected.insert(url.clone(), id.clone());
                ("required_publication", witness)
            } else if let Some(witness) = &qualification.negative {
                excluded += usize::from(entry.original.is_some());
                ("non_publication", witness)
            } else {
                return Err(Error::unavailable(
                    "WHATWG recovery candidate qualification is absent.",
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
        self.store.whatwg_put_many(&[devres_application::whatwg::Write {kind:"frozen".into(),key:id.clone(),data:value.clone()},devres_application::whatwg::Write {kind:"frozen-recoveries".into(),key:id.clone(),data:json!({"parent":parent.id,"successor":id,"policy":catalog::METADATA_VERSION,"lineage":successor.lineage})}]).await?;
        self.store.whatwg_set_state(&result_key, &json!(id)).await?;
        self.store.whatwg_set_state(&work_key, &Value::Null).await?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::Memory;
    use super::*;
    use std::sync::atomic::Ordering;

    struct Fixture {
        _roots: Vec<tempfile::TempDir>,
        corpus: WhatwgCorpus,
        store: Arc<Memory>,
        parent: Value,
        originals: Vec<Publication>,
        server: tokio::task::JoinHandle<()>,
    }
    async fn old_publication(
        corpus: &WhatwgCorpus,
        url: &str,
        body: Option<&[u8]>,
        version: u32,
        gaps: Vec<String>,
    ) -> Publication {
        let artifact = match body {
            Some(bytes) => Some(
                corpus
                    .raw
                    .capture_bytes(bytes.to_vec(), CancellationToken::new())
                    .await
                    .expect("raw fixture"),
            ),
            None => None,
        };
        let status = if artifact.is_some() { 200 } else { 404 };
        let id = inventory::digest(
            &serde_json::to_vec(&(url, &artifact, status, "legacy fixture")).expect("identity"),
        );
        let publication = Publication {
            id: id.clone(),
            standard: "html".into(),
            url: PublicationUrl::new(url).expect("URL"),
            observed_at: devres_domain::unix_now() - 3600,
            artifact,
            status,
            links: Vec::new(),
            gaps,
            repositories: Vec::new(),
            chunk_hashes: Vec::new(),
            metadata_version: version,
            metadata_parent: None,
            advertisements: Vec::new(),
            exclusions: Vec::new(),
        };
        corpus
            .store
            .whatwg_put(
                "publications",
                &id,
                &encode(&publication).expect("publication"),
            )
            .await
            .expect("legacy observation");
        publication
    }
    async fn fixture(extra_navigation: &str) -> Fixture {
        use crate::whatwg::git::tests as git_fixture;
        let source_root = tempfile::tempdir().expect("source");
        let source = Arc::new(
            WhatwgGit::new(
                source_root.path(),
                Repo::new("whatwg/fixture").expect("repo"),
                64 * 1024 * 1024,
                64 * 1024 * 1024,
                None,
            )
            .expect("Git"),
        );
        git_fixture::fixture_init(&source).await;
        let head = git_fixture::commit_files(
            &source,
            &[(
                "source",
                b"<h2 id=source>Source</h2><p>Frozen source clause.</p>",
            )],
            &[],
        )
        .await;
        git_fixture::update(&source, "refs/heads/main", &head).await;
        let router = git_fixture::fixture_router(source)
            .route(
                "/review-drafts/2025-07/",
                axum::routing::get(|| async { "<h2 id=new>New qualified edition</h2>" }),
            )
            .route(
                "/review-drafts/2025-01/diagram.svg",
                axum::routing::get(|| async { "<svg>Original image asset</svg>" }),
            )
            .route(
                "/review-drafts/2025-01/note-bfcache",
                axum::routing::get(|| async {
                    "<p>A200 response is not publication-role evidence.</p>"
                }),
            );
        let (broker, server) = git_fixture::serve_fixture(router).await;
        let root = tempfile::tempdir().expect("corpus root");
        let store = Arc::new(Memory::default());
        let corpus = WhatwgCorpus::new(
            store.clone(),
            broker,
            root.path(),
            WhatwgConfig {
                enabled: false,
                min_free_bytes: 64 * 1024 * 1024,
                ..Default::default()
            },
        )
        .expect("corpus");
        let standard = Standard {
            id: "html".into(),
            title: "HTML fixture".into(),
            url: "https://html.spec.whatwg.org/".into(),
            repository: "whatwg/fixture".into(),
            metadata: json!({}),
        };
        let observation = corpus
            .observe_repository(&standard.repository, CancellationToken::new())
            .await
            .expect("retained Git observation");
        let catalog = Catalog {
            id: inventory::digest(b"recovery fixture catalog"),
            observed_at: observation.observed_at,
            standards: vec![standard],
            gaps: Vec::new(),
        };
        store
            .whatwg_put("catalogs", &catalog.id, &encode(&catalog).expect("catalog"))
            .await
            .expect("retain catalog");
        let current = format!(
            "<h2 id=current>Current</h2><nav><a href=/review-drafts/2025-01/>Review draft</a><a href=/multipage/forms.html>Forms</a>{extra_navigation}</nav>"
        );
        let forms = format!(
            "<h3 id=forms>Forms</h3><dl class=domintro><dt>control.labels{}<dd>Labels</dl>",
            "x".repeat(1600)
        );
        let mut originals = Vec::new();
        originals.push(
            old_publication(
                &corpus,
                "https://html.spec.whatwg.org/",
                Some(current.as_bytes()),
                0,
                Vec::new(),
            )
            .await,
        );
        originals.push(old_publication(&corpus,"https://html.spec.whatwg.org/review-drafts/2025-01/",Some(format!("<h2 id=draft>Draft</h2><div class=example><a href=diagram.svg>a flowchart</a>{extra_navigation}</div><div id=note-bfcache class=note>Note</div><p><a href=note-bfcache>back/forward cache</a></p>").as_bytes()),0,Vec::new()).await);
        originals.push(
            old_publication(
                &corpus,
                "https://html.spec.whatwg.org/multipage/forms.html",
                Some(forms.as_bytes()),
                2,
                vec!["publication_metadata_capacity".into()],
            )
            .await,
        );
        originals.push(
            old_publication(
                &corpus,
                "https://html.spec.whatwg.org/review-drafts/2025-01/diagram.svg",
                Some(b"<svg><text>Original image asset</text></svg>"),
                0,
                Vec::new(),
            )
            .await,
        );
        originals.push(
            old_publication(
                &corpus,
                "https://html.spec.whatwg.org/review-drafts/2025-01/note-bfcache",
                None,
                0,
                vec!["publication_http_404".into()],
            )
            .await,
        );
        let id = inventory::digest(
            &serde_json::to_vec(&originals.iter().map(|p| &p.id).collect::<Vec<_>>())
                .expect("frozen ID"),
        );
        let frozen = Frozen {
            id,
            catalog,
            observations: BTreeMap::from([("html".into(), observation)]),
            publications: originals.iter().map(|p| p.id.clone()).collect(),
            mode: "full".into(),
            lineage: None,
        };
        let parent = encode(&frozen).expect("parent");
        store
            .whatwg_put("frozen", &frozen.id, &parent)
            .await
            .expect("retain parent");
        let outcome = corpus
            .accept_frozen(&parent, CancellationToken::new())
            .await
            .expect("retained failed original receipt");
        assert_eq!(outcome["complete"], false);
        assert_eq!(outcome["unavailable_publications"], 1);
        assert_eq!(outcome["discovery_gaps"], 1);
        Fixture {
            _roots: vec![source_root, root],
            corpus,
            store,
            parent,
            originals,
            server,
        }
    }
    #[tokio::test]
    async fn recovery_preserves_parent_raw_times_source_work_and_status_blind_dispositions() {
        let _gate = crate::mdn::index::TEST_GATE.lock().await;
        let fixture = fixture("").await;
        let parent: Frozen = decode(fixture.parent.clone()).expect("parent");
        let parent_key = format!("{}:full:{PROCESSOR_VERSION}", parent.id);
        let receipt = fixture
            .store
            .whatwg_get("acceptance", &parent_key)
            .await
            .expect("receipt")
            .expect("receipt")
            .data;
        let source = fixture
            .corpus
            .snapshot_for_revision(
                "html",
                "whatwg/fixture",
                parent.observations["html"]
                    .main_revision
                    .as_deref()
                    .expect("head"),
                "source",
            )
            .await
            .expect("snapshot")
            .expect("source");
        let snapshots_before = fixture
            .store
            .whatwg_rows("snapshots", 0, 1000, None)
            .await
            .expect("snapshots")
            .len();
        let attempts = fixture.corpus.broker.attempt_count();
        let child_value = fixture
            .corpus
            .recover_frozen(&fixture.parent, CancellationToken::new())
            .await
            .expect("closed successor");
        let child: Frozen = decode(child_value.clone()).expect("child");
        assert_ne!(child.id, parent.id);
        assert_eq!(
            encode(&child.catalog).expect("catalog"),
            encode(&parent.catalog).expect("catalog")
        );
        assert_eq!(
            encode(&child.observations).expect("observations"),
            encode(&parent.observations).expect("observations")
        );
        assert_eq!(child.publications.len(), 3);
        let lineage = child.lineage.as_ref().expect("lineage");
        assert_eq!(lineage.parent, parent.id);
        assert_eq!(
            lineage.excluded_candidates, 2,
            "both the200asset and404inline reference have non-publication roles"
        );
        assert_eq!(lineage.publication_capture_calls, 0);
        assert_eq!(fixture.corpus.broker.attempt_count(), attempts);
        assert_eq!(
            fixture
                .store
                .whatwg_rows("snapshots", 0, 1000, None)
                .await
                .expect("snapshots")
                .len(),
            snapshots_before,
            "recovery does not reprocess source or publication snapshots"
        );
        for old in &fixture.originals {
            assert_eq!(
                fixture
                    .store
                    .whatwg_get("publications", &old.id)
                    .await
                    .expect("old")
                    .expect("old")
                    .data,
                encode(old).expect("old encoding")
            );
            if old.status == 200 && old.url.kind() == catalog::PublicationKind::Html {
                let next = child.publications.iter().map(|id| async {
                    fixture
                        .corpus
                        .recovery_publication(id)
                        .await
                        .expect("child publication")
                });
                let mut found = None;
                for future in next {
                    let publication = future.await;
                    if publication.metadata_parent.as_deref() == Some(old.id.as_str()) {
                        found = Some(publication);
                    }
                }
                let repaired = found.expect("even successful gap-free legacy HTML is re-extracted");
                assert_eq!(repaired.observed_at, old.observed_at);
                assert_eq!(
                    encode(&repaired.artifact).expect("artifact"),
                    encode(&old.artifact).expect("artifact")
                );
                assert_eq!(repaired.status, old.status);
                assert_eq!(repaired.metadata_version, catalog::METADATA_VERSION);
            }
        }
        let disposition_ids = inventory::sequences(
            fixture.store.as_ref(),
            std::slice::from_ref(&lineage.dispositions),
        )
        .await
        .expect("disposition sequence")
        .remove(&lineage.dispositions)
        .expect("root");
        assert_eq!(disposition_ids.len(), 5);
        for id in disposition_ids {
            let row = fixture
                .store
                .whatwg_get("recovery-dispositions", &id)
                .await
                .expect("disposition")
                .expect("row");
            let witness = row.data["witness"].as_str().expect("witness");
            assert!(
                fixture
                    .store
                    .whatwg_get("recovery-witnesses", witness)
                    .await
                    .expect("witness")
                    .is_some()
            );
        }
        assert_eq!(
            fixture
                .corpus
                .recover_frozen(&fixture.parent, CancellationToken::new())
                .await
                .expect("idempotent resumed result"),
            child_value
        );
        let outcome = fixture
            .corpus
            .accept_frozen(&child_value, CancellationToken::new())
            .await
            .expect("offline successor acceptance");
        assert_eq!(outcome["complete"], true);
        assert_eq!(outcome["git_commits_processed"], 1);
        assert_eq!(outcome["publications_processed"], 3);
        assert_eq!(outcome["discovery_gaps"], 0);
        assert_eq!(
            fixture.corpus.broker.attempt_count(),
            attempts,
            "acceptance and metadata-only recovery are offline"
        );
        assert_eq!(
            fixture
                .corpus
                .snapshot_for_revision("html", "whatwg/fixture", &source.revision, "source")
                .await
                .expect("source")
                .expect("source")
                .id,
            source.id
        );
        assert_eq!(
            fixture
                .store
                .whatwg_get("frozen", &parent.id)
                .await
                .expect("original")
                .expect("original")
                .data,
            fixture.parent
        );
        assert_eq!(
            fixture
                .store
                .whatwg_get("acceptance", &parent_key)
                .await
                .expect("receipt")
                .expect("receipt")
                .data,
            receipt
        );
        fixture.server.abort();
        let _ = fixture.server.await;
    }
    #[tokio::test]
    async fn recovery_resumes_after_metadata_child_precedes_failed_checkpoint() {
        let _gate = crate::mdn::index::TEST_GATE.lock().await;
        let fixture = fixture("").await;
        fixture
            .store
            .fail_recovery_state_after
            .store(3, Ordering::Release);
        let attempts = fixture.corpus.broker.attempt_count();
        assert_eq!(
            fixture
                .corpus
                .recover_frozen(&fixture.parent, CancellationToken::new())
                .await
                .expect_err("checkpoint failure")
                .code,
            "unavailable"
        );
        let retained = fixture
            .store
            .whatwg_rows("publications", 0, 1000, None)
            .await
            .expect("children");
        let first_child = retained
            .iter()
            .find(|r| r.data["metadata_parent"].is_string())
            .expect("child durable before failed work pointer")
            .key
            .clone();
        let child = fixture
            .corpus
            .recover_frozen(&fixture.parent, CancellationToken::new())
            .await
            .expect("resume without immutable collision");
        assert!(
            fixture
                .store
                .whatwg_get("publications", &first_child)
                .await
                .expect("child")
                .is_some()
        );
        assert_eq!(child["lineage"]["publication_capture_calls"], 0);
        assert_eq!(fixture.corpus.broker.attempt_count(), attempts);
        fixture.server.abort();
        let _ = fixture.server.await;
    }
    #[tokio::test]
    async fn recovery_captures_only_missing_qualified_publications_and_keeps_true404_blocking() {
        let _gate = crate::mdn::index::TEST_GATE.lock().await;
        for (path, available) in [("2025-07", true), ("2026-01", false)] {
            let fixture = fixture(&format!(
                "<a href=/review-drafts/{path}/>Additional review draft</a>"
            ))
            .await;
            let before = fixture.corpus.broker.attempt_count();
            let result = fixture
                .corpus
                .recover_frozen(&fixture.parent, CancellationToken::new())
                .await;
            assert_eq!(
                fixture.corpus.broker.attempt_count() - before,
                1,
                "only the missing qualified URL is requested, neverGit/catalog or excluded old404"
            );
            if available {
                let child = result.expect("new qualified body closes successor");
                assert_eq!(child["lineage"]["publication_capture_calls"], 1);
                assert_eq!(
                    child["publications"]
                        .as_array()
                        .expect("publications")
                        .len(),
                    4
                );
                let child: Frozen = decode(child).expect("child");
                let root = &child.lineage.as_ref().expect("lineage").dispositions;
                let ids = inventory::sequences(fixture.store.as_ref(), std::slice::from_ref(root))
                    .await
                    .expect("dispositions")
                    .remove(root)
                    .expect("root");
                let mut mixed = false;
                for id in ids {
                    let record = fixture
                        .store
                        .whatwg_get("recovery-dispositions", &id)
                        .await
                        .expect("record")
                        .expect("record")
                        .data;
                    if record["url"]
                        != format!("https://html.spec.whatwg.org/review-drafts/{path}/")
                    {
                        continue;
                    }
                    assert_eq!(record["disposition"], "required_publication");
                    let root = record["witnesses"]
                        .as_str()
                        .expect("witness root")
                        .to_owned();
                    let ids =
                        inventory::sequences(fixture.store.as_ref(), std::slice::from_ref(&root))
                            .await
                            .expect("witnesses")
                            .remove(&root)
                            .expect("root");
                    let mut kinds = BTreeSet::new();
                    for id in ids {
                        kinds.insert(
                            fixture
                                .store
                                .whatwg_get("recovery-witnesses", &id)
                                .await
                                .expect("witness")
                                .expect("witness")
                                .data["kind"]
                                .as_str()
                                .expect("kind")
                                .to_owned(),
                        );
                    }
                    assert_eq!(
                        kinds,
                        BTreeSet::from(["advertisement".into(), "exclusion".into()])
                    );
                    mixed = true;
                }
                assert!(
                    mixed,
                    "independent positive wins while both occurrence roles remain witnessed"
                );
            } else {
                assert_eq!(
                    result.expect_err("true publication404 blocks").code,
                    "unavailable"
                );
                assert_eq!(
                    fixture
                        .store
                        .whatwg_rows("frozen", 0, 1000, None)
                        .await
                        .expect("frozen")
                        .len(),
                    1
                );
                let attempts = fixture.corpus.broker.attempt_count();
                assert_eq!(
                    fixture
                        .corpus
                        .recover_frozen(&fixture.parent, CancellationToken::new())
                        .await
                        .expect_err("backoff remains blocked")
                        .code,
                    "unavailable"
                );
                assert_eq!(fixture.corpus.broker.attempt_count(), attempts);
                assert!(
                    fixture
                        .store
                        .whatwg_rows("publications", 0, 1000, None)
                        .await
                        .expect("observations")
                        .iter()
                        .any(|r| r.data["url"]["url"]
                            == format!("https://html.spec.whatwg.org/review-drafts/{path}/")
                            && r.data["status"] == 404)
                );
            }
            fixture.server.abort();
            let _ = fixture.server.await;
        }
    }
    #[tokio::test]
    async fn recovery_does_not_drop_unknown_candidates_or_accept_changed_parents() {
        let _gate = crate::mdn::index::TEST_GATE.lock().await;
        let fixture = fixture("").await;
        let unknown = old_publication(
            &fixture.corpus,
            "https://html.spec.whatwg.org/review-drafts/2025-01/unqualified.bin",
            Some(b"Unknown retained object"),
            0,
            Vec::new(),
        )
        .await;
        let mut parent: Frozen = decode(fixture.parent.clone()).expect("parent");
        parent.id = inventory::digest(b"parent with unknown candidate");
        parent.publications.push(unknown.id);
        let value = encode(&parent).expect("parent");
        fixture
            .store
            .whatwg_put("frozen", &parent.id, &value)
            .await
            .expect("retain parent");
        fixture.store.whatwg_put("acceptance",&format!("{}:full:{PROCESSOR_VERSION}",parent.id),&json!({"frozen":parent.id,"mode":"full","processor_version":PROCESSOR_VERSION,"complete":false})).await.expect("receipt");
        let attempts = fixture.corpus.broker.attempt_count();
        assert_eq!(
            fixture
                .corpus
                .recover_frozen(&value, CancellationToken::new())
                .await
                .expect_err("unknown role blocks")
                .code,
            "unavailable"
        );
        assert_eq!(fixture.corpus.broker.attempt_count(), attempts);
        let mut changed = value.clone();
        changed["catalog"]["observed_at"] = json!(0);
        assert_eq!(
            fixture
                .corpus
                .recover_frozen(&changed, CancellationToken::new())
                .await
                .expect_err("exact parent evidence required")
                .code,
            "integrity"
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            fixture
                .corpus
                .recover_frozen(&value, cancel)
                .await
                .expect_err("cancel")
                .code,
            "cancelled"
        );
        fixture.server.abort();
        let _ = fixture.server.await;
    }
    #[tokio::test]
    async fn legacy_queues_cannot_authorize_requests_even_when_the_target_returns200() {
        let _gate = crate::mdn::index::TEST_GATE.lock().await;
        let fixture = fixture("").await;
        let parent: Frozen = decode(fixture.parent.clone()).expect("parent");
        fixture
            .store
            .whatwg_set_state("catalog", &json!(parent.catalog.id))
            .await
            .expect("catalog pointer");
        fixture
            .store
            .whatwg_set_state(
                &state_key("current-attempt", "html"),
                &json!({"observed_at":0}),
            )
            .await
            .expect("attempt marker");
        for suffix in ["diagram.svg", "note-bfcache"] {
            let url = format!("https://html.spec.whatwg.org/review-drafts/2025-01/{suffix}");
            let queue = json!([url]);
            let frontier = state_key("frontier", "html");
            fixture
                .store
                .whatwg_set_state(&frontier, &queue)
                .await
                .expect("unversioned frontier");
            let before = fixture.corpus.broker.attempt_count();
            assert_eq!(
                fixture
                    .corpus
                    .history_step(CancellationToken::new())
                    .await
                    .expect_err("legacy history queue")
                    .code,
                "unavailable"
            );
            assert_eq!(
                fixture
                    .corpus
                    .current_step(CancellationToken::new())
                    .await
                    .expect_err("current cannot append typed authority to old queue")
                    .code,
                "unavailable"
            );
            assert_eq!(
                fixture
                    .store
                    .whatwg_state(&frontier)
                    .await
                    .expect("frontier"),
                Some(queue)
            );
            let work = FreezeWork {
                catalog: parent.catalog.clone(),
                observations: parent.observations.clone(),
                publications: parent.publications.clone(),
                mode: "full".into(),
                metadata_policy: 0,
                standard_offset: 1,
                queue: VecDeque::from([("html".into(), PublicationUrl::new(&url).expect("URL"))]),
                seen: BTreeSet::from([url]),
            };
            let mut legacy = encode(&work).expect("work");
            legacy
                .as_object_mut()
                .expect("object")
                .remove("metadata_policy");
            fixture
                .store
                .whatwg_set_state("freezing", &legacy)
                .await
                .expect("legacy freeze work");
            assert_eq!(
                fixture
                    .corpus
                    .freeze(CancellationToken::new())
                    .await
                    .expect_err("unversioned freeze queue")
                    .code,
                "unavailable"
            );
            assert_eq!(
                fixture.store.whatwg_state("freezing").await.expect("work"),
                Some(legacy)
            );
            assert_eq!(
                fixture.corpus.broker.attempt_count(),
                before,
                "noHTTP/Git/catalog attempt is authorized by persisted old URLs"
            );
        }
        fixture
            .corpus
            .retain_publication_frontier(
                "html",
                &["https://html.spec.whatwg.org/review-drafts/2025-01/".into()],
            )
            .await
            .expect("one atomic typed checkpoint");
        assert_eq!(
            fixture
                .corpus
                .publication_frontier("html")
                .await
                .expect("typed queue")
                .len(),
            1
        );
        let mut roles = Qualifications::default();
        roles
            .insert(
                "html",
                "https://html.spec.whatwg.org/",
                true,
                json!({"kind":"catalog"}),
            )
            .expect("authority");
        assert_eq!(
            roles
                .insert(
                    "other",
                    "https://html.spec.whatwg.org/",
                    false,
                    json!({"kind":"exclusion"})
                )
                .expect_err("cross-standard authority cannot merge")
                .code,
            "integrity"
        );
        fixture.server.abort();
        let _ = fixture.server.await;
    }
}
