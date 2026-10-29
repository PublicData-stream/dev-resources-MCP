//! Capture-fixed local crate research. No request invokes package code or providers.
use crate::{
    crates_io::index::{self as crate_index, SearchSpec},
    research::{capture_json, text_page},
};
use devres_application::{
    Retrieval,
    crate_corpus::{ContentFilter, ContentRecord, CrateCorpusStore, Snapshot, VersionRecord},
};
use devres_domain::{Error, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
    sync::Arc,
};

pub struct CrateResearch {
    store: Arc<dyn CrateCorpusStore>,
    retrieval: Arc<Retrieval>,
    root: PathBuf,
}
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct Input {
    name: Option<String>,
    version: Option<String>,
    snapshot: Option<String>,
    query: Option<String>,
    target: Option<String>,
    path: Option<String>,
    kind: Option<String>,
    mode: Option<String>,
    license: Option<String>,
    keyword: Option<String>,
    category: Option<String>,
    msrv: Option<String>,
    yanked: Option<bool>,
    cursor: Option<String>,
    direction: Option<String>,
    from_version: Option<String>,
    to_version: Option<String>,
    offset: usize,
    limit: Option<usize>,
}
impl Input {
    fn name(&self) -> Result<&str> {
        self.name
            .as_deref()
            .ok_or_else(|| Error::invalid("Crate name is required."))
    }
    fn version(&self) -> Result<&str> {
        self.version
            .as_deref()
            .ok_or_else(|| Error::invalid("Exact crate version is required."))
    }
    fn path(&self) -> Result<&str> {
        self.path
            .as_deref()
            .ok_or_else(|| Error::invalid("Exact document or public API path is required."))
    }
    fn page(&self, text: bool) -> Result<(usize, usize)> {
        let limit = self.limit.unwrap_or(if text { 32768 } else { 20 });
        if limit == 0 || limit > if text { 32768 } else { 100 } || (!text && self.offset > 10000) {
            return Err(Error::invalid("Research page exceeds supported bounds."));
        }
        Ok((self.offset, limit))
    }
    fn validate(&self) -> Result<()> {
        if self
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > 16384 || cursor.contains('\0'))
        {
            return Err(Error::invalid("Invalid comparison cursor."));
        }
        if let Some(name) = &self.name {
            crate::crates_io::packages::validate_name(name)?;
        }
        for version in [&self.version, &self.from_version, &self.to_version]
            .into_iter()
            .flatten()
        {
            crate::crates_io::packages::validate_version(version)?;
        }
        if self
            .snapshot
            .as_ref()
            .is_some_and(|s| !crate::integrity::valid_hash(s))
        {
            return Err(Error::invalid("Invalid crate research snapshot."));
        }
        for value in [
            &self.query,
            &self.license,
            &self.keyword,
            &self.category,
            &self.msrv,
        ]
        .into_iter()
        .flatten()
        {
            if value.chars().count() > 256 || value.chars().any(char::is_control) {
                return Err(Error::invalid("Research filter exceeds supported bounds."));
            }
        }
        if self
            .target
            .as_ref()
            .is_some_and(|target| !crate::bulk::valid_target(target))
        {
            return Err(Error::invalid("Invalid documentation target."));
        }
        if self
            .path
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 4096 || s.chars().any(char::is_control))
        {
            return Err(Error::invalid("Invalid document or API path."));
        }
        Ok(())
    }
    fn spec(&self, class: &str) -> Result<SearchSpec> {
        let (offset, limit) = self.page(false)?;
        Ok(SearchSpec {
            query: self.query.clone(),
            cursor: self.cursor.clone(),
            mode: self.mode.clone().unwrap_or_else(|| "technical".into()),
            class: Some(class.into()),
            name: self.name.clone(),
            version: self.version.clone(),
            target: self.target.clone(),
            path: self.path.clone(),
            kind: self.kind.clone(),
            license: self.license.clone(),
            keyword: self.keyword.clone(),
            category: self.category.clone(),
            msrv: self.msrv.clone(),
            yanked: self.yanked,
            offset,
            limit,
            ..Default::default()
        })
    }
}
impl CrateResearch {
    pub fn new(store: Arc<dyn CrateCorpusStore>, retrieval: Arc<Retrieval>, root: PathBuf) -> Self {
        Self {
            store,
            retrieval,
            root,
        }
    }
    async fn snapshot(&self, id: Option<&str>) -> Result<Snapshot> {
        let snapshot = self.store.snapshot(id).await?.ok_or_else(|| {
            if id.is_some() {
                Error::not_found("Crate research snapshot is absent.")
            } else {
                Error::unavailable("No crate research snapshot is published.")
            }
        })?;
        if id.is_none()
            && devres_domain::unix_now().saturating_sub(snapshot.inventory.validated_at) > 7 * 86400
        {
            return Err(Error::unavailable(
                "Default crate inventory is older than seven days; select a historical snapshot.",
            ));
        }
        Ok(snapshot)
    }
    async fn mutable_source(&self, id: &str, historical: bool) -> Result<Value> {
        let artifact = self.store.artifact(id).await?.ok_or_else(|| {
            Error::unavailable("Documentation source capture metadata is unavailable.")
        })?;
        if artifact.capture.id != id || artifact.capture.validated_at < 0 {
            return Err(Error::integrity(
                "Documentation source capture identity is invalid.",
            ));
        }
        if !historical
            && devres_domain::unix_now().saturating_sub(artifact.capture.validated_at) > 7 * 86400
        {
            return Err(Error::unavailable(
                "Selected documentation source is older than seven days; select an explicit historical snapshot.",
            ));
        }
        let mut metadata = capture_json(&artifact.capture, 86400);
        // Raw JSON gzip and HTML ZIP artifacts require typed projections.
        metadata["resource_uri"] = Value::Null;
        Ok(metadata)
    }
    async fn selected_source(
        &self,
        row: &ContentRecord,
        historical: bool,
    ) -> Result<Option<Value>> {
        if matches!(row.kind.as_str(), "rustdoc" | "api") {
            Ok(Some(
                self.mutable_source(&row.archive_capture, historical)
                    .await?,
            ))
        } else {
            Ok(None)
        }
    }
    async fn search(
        &self,
        snapshot: &Snapshot,
        spec: SearchSpec,
        historical: bool,
    ) -> Result<Value> {
        let mut result =
            crate_index::search(self.root.clone(), snapshot.index_manifest.clone(), spec).await?;
        let mut sources = HashMap::<String, Value>::new();
        let items = result["items"]
            .as_array_mut()
            .ok_or_else(|| Error::integrity("Malformed crate search page."))?;
        for item in items {
            if item["document"]["class"] == "content"
                && matches!(
                    item["document"]["record"]["kind"].as_str(),
                    Some("rustdoc" | "api")
                )
            {
                let id = item["document"]["record"]["archive_capture"]
                    .as_str()
                    .ok_or_else(|| Error::integrity("Documentation source capture is absent."))?
                    .to_owned();
                let source = match sources.get(&id) {
                    Some(value) => value.clone(),
                    None => {
                        let value = self.mutable_source(&id, historical).await?;
                        sources.insert(id, value.clone());
                        value
                    }
                };
                item["source_capture"] = source;
            }
        }
        result["snapshot"] = snapshot_json(snapshot);
        Ok(result)
    }
    async fn version(
        &self,
        snapshot: &Snapshot,
        name: &str,
        version: &str,
    ) -> Result<VersionRecord> {
        self.store
            .version(&snapshot.inventory.id, name, version)
            .await?
            .ok_or_else(|| Error::not_found("Version is absent from the selected inventory."))
    }

    async fn document(
        &self,
        snapshot: &Snapshot,
        input: &Input,
        kind: &str,
        version: &str,
    ) -> Result<ContentRecord> {
        let filter = ContentFilter {
            name: Some(input.name()?.into()),
            version: Some(version.into()),
            target: if kind == "text" {
                Some(input.target.clone().unwrap_or_default())
            } else {
                input.target.clone()
            },
            path: input.path.clone(),
            kind: if kind == "text" {
                None
            } else {
                Some(kind.into())
            },
        };
        let rows = self
            .store
            .contents(snapshot.content_sequence, &filter, None, 2)
            .await?;
        match rows.len() {
            0 => Err(Error::not_found("Document is absent from this snapshot.")),
            1 => {
                let row = rows
                    .into_iter()
                    .next()
                    .ok_or_else(|| Error::not_found("Document is absent."))?;
                self.selected_source(&row, input.snapshot.is_some()).await?;
                Ok(row)
            }
            _ => Err(Error::invalid(
                "Multiple documents match; select an exact path and target.",
            )),
        }
    }
    async fn text(
        &self,
        row: &ContentRecord,
        offset: usize,
        limit: usize,
        historical: bool,
    ) -> Result<Value> {
        let source = self.selected_source(row, historical).await?;
        let captured = self.retrieval.read_capture(&row.capture).await?;
        if captured.body.len() > 4 * 1024 * 1024 {
            return Err(Error::capacity("Research document exceeds 4 MiB."));
        }
        let text = std::str::from_utf8(&captured.body)
            .map_err(|_| Error::integrity("Research document is not UTF-8."))?;
        let page = text_page(text, offset, limit)?;
        let mut result = json!({"document":row,"page":page,"capture":capture_json(&captured.capture,365*86400),"resource_uri":format!("devres://capture/{}?offset={offset}&limit={limit}",row.capture),"metadata_capture":row.metadata_capture,"archive_capture":row.archive_capture,"license_notice":"Captured content retains its original copyright and licensing."});
        if let Some(source) = source {
            result["source_capture"] = source;
        }
        Ok(result)
    }
    pub async fn call(&self, tool: &str, input: Value) -> Result<Value> {
        let schema = schemas()
            .into_iter()
            .find(|s| s["name"] == tool)
            .ok_or_else(|| Error::invalid("Unknown crate research tool."))?;
        let object = input
            .as_object()
            .ok_or_else(|| Error::invalid("Tool input must be an object."))?;
        let properties = schema["inputSchema"]["properties"]
            .as_object()
            .ok_or_else(|| Error::integrity("Research schema is unavailable."))?;
        if object.keys().any(|key| !properties.contains_key(key)) {
            return Err(Error::invalid("Unknown crate research argument."));
        }
        let mut input: Input = serde_json::from_value(input)
            .map_err(|_| Error::invalid("Arguments do not match research schema."))?;
        input.validate()?;
        input.name = input.name.map(|name| name.to_ascii_lowercase());
        if tool == "crate.corpus_status" {
            return self.store.status().await;
        }
        let snapshot = self.snapshot(input.snapshot.as_deref()).await?;
        match tool {
            "crate.versions" => {
                input.name()?;
                self.search(&snapshot, input.spec("version")?, input.snapshot.is_some())
                    .await
            }
            "crate.catalog_search" => {
                self.search(&snapshot, input.spec("version")?, input.snapshot.is_some())
                    .await
            }
            "crate.content_search" | "crate.api_search" => {
                if input.query.as_ref().is_none_or(|s| s.trim().is_empty()) {
                    return Err(Error::invalid("A nonempty search query is required."));
                }
                let mut spec = input.spec("content")?;
                if tool == "crate.api_search" {
                    spec.kind = Some("api".into());
                }
                self.search(&snapshot, spec, input.snapshot.is_some()).await
            }
            "crate.document_get" => {
                let (offset, limit) = input.page(true)?;
                let kind = input
                    .kind
                    .as_deref()
                    .ok_or_else(|| Error::invalid("Document kind is required."))?;
                if !matches!(
                    kind,
                    "source" | "manifest" | "readme" | "license" | "rustdoc"
                ) {
                    return Err(Error::invalid("Unsupported document kind."));
                }
                let row = self
                    .document(&snapshot, &input, kind, input.version()?)
                    .await?;
                let mut result = self
                    .text(&row, offset, limit, input.snapshot.is_some())
                    .await?;
                result["snapshot"] = snapshot_json(&snapshot);
                Ok(result)
            }
            "crate.api_get" => {
                input.path()?;
                let row = self
                    .document(&snapshot, &input, "api", input.version()?)
                    .await?;
                let projection_coverage = self
                    .store
                    .projection_status(
                        snapshot.content_sequence,
                        &row.name,
                        &row.version,
                        "json",
                        Some(&row.target),
                    )
                    .await?;
                let source_capture = self
                    .mutable_source(&row.archive_capture, input.snapshot.is_some())
                    .await?;
                Ok(
                    json!({"item":row,"observed_signature":row.attributes["signature"],"relationships":row.attributes["relationships"],"projection_coverage":projection_coverage,"source_capture":source_capture,"snapshot":snapshot_json(&snapshot),"resource_uri":format!("devres://capture/{}",row.capture),"assessment_scope":"observed captured rustdoc API; no build or compatibility certification"}),
                )
            }
            "crate.dependencies" => self.dependencies(&snapshot, &input).await,
            "crate.compare" => self.compare(&snapshot, &input).await,
            _ => Err(Error::invalid("Unsupported crate research tool.")),
        }
    }
    async fn dependencies(&self, snapshot: &Snapshot, input: &Input) -> Result<Value> {
        let name = input.name()?;
        let (offset, limit) = input.page(false)?;
        match input.direction.as_deref().unwrap_or("forward") {
            "forward" => {
                if input.cursor.is_some() {
                    return Err(Error::invalid(
                        "Forward dependency pages use offset and limit; cursor is for reverse declarations.",
                    ));
                }
                let version = self.version(snapshot, name, input.version()?).await?;
                let dependencies = version.record["deps"]
                    .as_array()
                    .ok_or_else(|| Error::integrity("Dependencies are absent."))?;
                let items: Vec<_> = dependencies
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .cloned()
                    .collect();
                Ok(
                    json!({"name":name,"version":version.version,"items":items,"total":dependencies.len(),"offset":offset,"next_offset":if offset.saturating_add(limit)<dependencies.len(){Some(offset+limit)}else{None},"metadata_capture":version.metadata_capture,"metadata_status":version.metadata_status,"complete":version.metadata_status.is_none(),"snapshot":snapshot_json(snapshot),"dependency_scope":"published declarations; no solved dependency graph or package execution"}),
                )
            }
            "reverse" => {
                if input.version.is_some() {
                    return Err(Error::invalid(
                        "Reverse declaration lookup accepts a package name; version is only used for forward declarations.",
                    ));
                }
                let spec = SearchSpec {
                    class: Some("version".into()),
                    dependency: Some(name.into()),
                    offset,
                    limit,
                    cursor: input.cursor.clone(),
                    ..Default::default()
                };
                let mut result = self
                    .search(snapshot, spec, input.snapshot.is_some())
                    .await?;
                result["dependency_scope"] =
                    json!("declared package-name references; version constraints are not resolved");
                Ok(result)
            }
            _ => Err(Error::invalid(
                "Dependency direction must be forward or reverse.",
            )),
        }
    }
    async fn comparison_coverage(
        &self,
        snapshot: &Snapshot,
        input: &Input,
        before: &str,
        after: &str,
        kind: &str,
    ) -> Result<Value> {
        self.version(snapshot, input.name()?, before).await?;
        self.version(snapshot, input.name()?, after).await?;
        let source_kind = if kind == "api" { "json" } else { "archive" };
        let old = self
            .store
            .projection_status(
                snapshot.content_sequence,
                input.name()?,
                before,
                source_kind,
                input.target.as_deref(),
            )
            .await?;
        let new = self
            .store
            .projection_status(
                snapshot.content_sequence,
                input.name()?,
                after,
                source_kind,
                input.target.as_deref(),
            )
            .await?;
        if old.len() > 1000
            || new.len() > 1000
            || serde_json::to_vec(&(&old, &new))
                .map_err(|_| Error::integrity("Malformed comparison coverage."))?
                .len()
                > 128 * 1024
        {
            return Err(Error::capacity(
                "Comparison projection metadata exceeds its budget; select a target.",
            ));
        }
        let mut source_captures = BTreeMap::new();
        if kind == "api" {
            for summary in old.iter().chain(&new) {
                let id = summary["source_capture"].as_str().ok_or_else(|| {
                    Error::unavailable("API projection source capture metadata is unavailable.")
                })?;
                if !source_captures.contains_key(id) {
                    source_captures.insert(
                        id.to_owned(),
                        self.mutable_source(id, input.snapshot.is_some()).await?,
                    );
                }
            }
        }
        let qualified = |rows: &[Value]| -> Result<BTreeSet<String>> {
            if rows.is_empty() {
                return Err(Error::unavailable(
                    "Both versions require complete captured projections before absence can be compared.",
                ));
            }
            let mut targets = BTreeSet::new();
            for row in rows {
                let complete = if kind == "api" {
                    row["version_asserted"] == true
                        && row["target_asserted"] == true
                        && row["unresolved_references"].as_u64() == Some(0)
                } else {
                    row["complete_for_eligible_text"] == true
                        && row["skipped_oversized"].as_u64() == Some(0)
                        && row["skipped_binary"].as_u64() == Some(0)
                };
                if !complete {
                    return Err(Error::unavailable(
                        "Comparison coverage is partial or has unqualified version/target evidence.",
                    ));
                }
                targets.insert(
                    row["target"]
                        .as_str()
                        .ok_or_else(|| Error::integrity("Projection target is absent."))?
                        .to_owned(),
                );
            }
            Ok(targets)
        };
        if qualified(&old)? != qualified(&new)? {
            return Err(Error::unavailable(
                "Compared versions have different captured target coverage.",
            ));
        }
        Ok(
            json!({"before":old,"after":new,"qualified":true,"source_captures":source_captures.into_values().collect::<Vec<_>>()}),
        )
    }
    async fn selected_path_coverage(
        &self,
        snapshot: &Snapshot,
        before: &ContentRecord,
        after: &ContentRecord,
        kind: &str,
        historical: bool,
    ) -> Result<Value> {
        if before.target != after.target {
            return Err(Error::unavailable(
                "Selected paths have different captured targets.",
            ));
        }
        if kind == "text" {
            return Ok(json!({"scope":"selected_captured_paths","qualified":true}));
        }
        let normalized = |item: &ContentRecord| {
            let mut pending = vec![&item.attributes["signature"]];
            if pending[0].is_null() {
                return false;
            }
            while let Some(value) = pending.pop() {
                match value {
                    Value::Object(fields) => {
                        if fields.get("unresolved_reference") == Some(&Value::Bool(true)) {
                            return false;
                        }
                        pending.extend(fields.values());
                    }
                    Value::Array(values) => pending.extend(values),
                    _ => {}
                }
            }
            true
        };
        if !normalized(before) || !normalized(after) {
            return Err(Error::unavailable(
                "Selected API signatures contain unresolved references.",
            ));
        }
        let mut projections = Vec::new();
        let mut source_captures = BTreeMap::new();
        for item in [before, after] {
            if !source_captures.contains_key(&item.archive_capture) {
                source_captures.insert(
                    item.archive_capture.clone(),
                    self.mutable_source(&item.archive_capture, historical)
                        .await?,
                );
            }
            let rows = self
                .store
                .projection_status(
                    snapshot.content_sequence,
                    &item.name,
                    &item.version,
                    "json",
                    Some(&item.target),
                )
                .await?;
            if rows.len() > 1000
                || serde_json::to_vec(&rows)
                    .map_err(|_| Error::integrity("Malformed API projection coverage."))?
                    .len()
                    > 128 * 1024
            {
                return Err(Error::capacity(
                    "API projection metadata exceeds its budget; select a target.",
                ));
            }
            if rows.is_empty()
                || rows.iter().any(|row| {
                    row["version_asserted"] != true
                        || row["target_asserted"] != true
                        || row["target"].as_str() != Some(item.target.as_str())
                })
            {
                return Err(Error::unavailable(
                    "Selected API items require qualified version and target evidence.",
                ));
            }
            projections.push(rows);
        }
        Ok(
            json!({"scope":"selected_captured_paths","qualified":true,"normalization":"complete_for_selected_items","before":projections[0],"after":projections[1],"source_captures":source_captures.into_values().collect::<Vec<_>>()}),
        )
    }
    async fn compare(&self, snapshot: &Snapshot, input: &Input) -> Result<Value> {
        let name = input.name()?;
        let before = input
            .from_version
            .as_deref()
            .ok_or_else(|| Error::invalid("from_version is required."))?;
        let after = input
            .to_version
            .as_deref()
            .ok_or_else(|| Error::invalid("to_version is required."))?;
        let kind = input.kind.as_deref().unwrap_or("metadata");
        if matches!(kind, "text" | "api") {
            self.version(snapshot, name, before).await?;
            self.version(snapshot, name, after).await?;
        }
        let mut coverage = None;
        let result = match kind {
            "metadata" | "dependencies" => {
                let left = self.version(snapshot, name, before).await?;
                let right = self.version(snapshot, name, after).await?;
                let (left_value, right_value) = if kind == "dependencies" {
                    (left.record["deps"].clone(), right.record["deps"].clone())
                } else {
                    (left.record, right.record)
                };
                json!({"changed":left_value!=right_value,"before":left_value,"after":right_value,"before_metadata_capture":left.metadata_capture,"after_metadata_capture":right.metadata_capture,"before_metadata_status":left.metadata_status,"after_metadata_status":right.metadata_status,"complete":left.metadata_status.is_none() && right.metadata_status.is_none()})
            }
            "text" | "api" if input.path.is_none() => {
                coverage = Some(
                    self.comparison_coverage(snapshot, input, before, after, kind)
                        .await?,
                );
                let limit = input.limit.unwrap_or(20);
                if limit == 0 || limit > 100 || input.offset != 0 {
                    return Err(Error::invalid(
                        "Release comparison uses a cursor and limit 1..100.",
                    ));
                }
                let mut rows = self
                    .store
                    .content_deltas(&devres_application::crate_corpus::ContentDeltaQuery {
                        cutoff: snapshot.content_sequence,
                        name: name.into(),
                        from_version: before.into(),
                        to_version: after.into(),
                        target: input.target.clone(),
                        kind: kind.into(),
                        after: input.cursor.clone(),
                        limit: limit + 1,
                    })
                    .await?;
                let more = rows.len() > limit;
                rows.truncate(limit);
                let cursor = if more {
                    rows.last()
                        .and_then(|row| row["cursor"].as_str())
                        .map(str::to_owned)
                } else {
                    None
                };
                if more && cursor.is_none() {
                    return Err(Error::integrity("Comparison page lacks its stable cursor."));
                }
                json!({"items":rows,"next_cursor":cursor,"comparison_scope":"all captured public paths at the frozen snapshot; observed differences only","assessment_scope":"no package execution or semantic-version compatibility guarantee"})
            }
            "text" | "api" => {
                input.path()?;
                let document_kind = if kind == "api" { "api" } else { "text" };
                let left = self.document(snapshot, input, document_kind, before).await;
                let right = self.document(snapshot, input, document_kind, after).await;
                let left = match left {
                    Ok(v) => Some(v),
                    Err(e) if e.code == "not_found" => None,
                    Err(e) => return Err(e),
                };
                let right = match right {
                    Ok(v) => Some(v),
                    Err(e) if e.code == "not_found" => None,
                    Err(e) => return Err(e),
                };
                coverage = Some(match (&left, &right) {
                    (Some(left), Some(right)) => {
                        self.selected_path_coverage(
                            snapshot,
                            left,
                            right,
                            kind,
                            input.snapshot.is_some(),
                        )
                        .await?
                    }
                    _ => {
                        self.comparison_coverage(snapshot, input, before, after, kind)
                            .await?
                    }
                });
                if left.is_none() && right.is_none() {
                    return Err(Error::not_found(
                        "Compared path is absent in both versions.",
                    ));
                }
                if kind == "api" {
                    let old = left.as_ref().map(|r| r.attributes["signature"].clone());
                    let new = right.as_ref().map(|r| r.attributes["signature"].clone());
                    let comparable = match (&left, &right) {
                        (Some(a), Some(b)) => {
                            a.attributes["format_version"].is_number()
                                && a.attributes["format_version"] == b.attributes["format_version"]
                        }
                        _ => true,
                    };
                    json!({"changed":if comparable{Some(old!=new)}else{None},"change":if !comparable{"uncomparable"}else if left.is_none(){"added"}else if right.is_none(){"removed"}else if old!=new{"changed"}else{"unchanged"},"before":left,"after":right,"assessment_scope":"observed signatures at this public path and target; no semantic-version compatibility guarantee"})
                } else {
                    let (offset, limit) = input.page(true)?;
                    let old = match &left {
                        Some(row) => Some(
                            self.text(row, offset, limit, input.snapshot.is_some())
                                .await?,
                        ),
                        None => None,
                    };
                    let new = match &right {
                        Some(row) => Some(
                            self.text(row, offset, limit, input.snapshot.is_some())
                                .await?,
                        ),
                        None => None,
                    };
                    json!({"changed":old.as_ref().map(|r|&r["capture"]["body_hash"])!=new.as_ref().map(|r|&r["capture"]["body_hash"]),"before":old,"after":new,"comparison_scope":"exact path; equality checks the complete captured text, output is paged"})
                }
            }
            _ => {
                return Err(Error::invalid(
                    "Comparison kind must be metadata, dependencies, text or api.",
                ));
            }
        };
        let mut result = result;
        result["snapshot"] = snapshot_json(snapshot);
        result["name"] = json!(name);
        result["from_version"] = json!(before);
        result["to_version"] = json!(after);
        result["kind"] = json!(kind);
        if let Some(coverage) = coverage {
            result["comparison_coverage"] = coverage;
        }
        if serde_json::to_vec(&result)
            .map_err(|_| Error::integrity("Comparison projection failed."))?
            .len()
            > 256 * 1024
        {
            return Err(Error::capacity("Comparison exceeds result budget."));
        }
        Ok(result)
    }
}
fn snapshot_json(snapshot: &Snapshot) -> Value {
    json!({"id":snapshot.id,"inventory":snapshot.inventory.id,"revision":snapshot.inventory.revision,"enrichment_capture":snapshot.enrichment,"created_at":snapshot.created_at,"inventory_created_at":snapshot.inventory.created_at,"validated_at":snapshot.inventory.validated_at,"stale":devres_domain::unix_now().saturating_sub(snapshot.inventory.validated_at)>3600,"coverage":snapshot.coverage,"search_coverage":{"available":(snapshot.index_manifest["digest"].is_string() || snapshot.index_manifest["sha256"].is_string()),"complete":snapshot.index_manifest["complete_search_coverage"],"skipped_documents":snapshot.index_manifest["skipped_documents"],"gap_samples":snapshot.index_manifest["gap_samples"]}})
}

pub fn schemas() -> Vec<Value> {
    let text = json!({"type":"string","minLength":1,"maxLength":256});
    let name = json!({"type":"string","minLength":1,"maxLength":64});
    let version = json!({"type":"string","minLength":1,"maxLength":128});
    let snapshot = json!({"type":"string","pattern":"^[a-f0-9]{64}$"});
    let path = json!({"type":"string","minLength":1,"maxLength":4096});
    let list = json!({"type":"integer","minimum":1,"maximum":100,"default":20});
    let offset = json!({"type":"integer","minimum":0,"maximum":10000,"default":0});
    let mut out = Vec::new();
    let definitions = [
        (
            "crate.versions",
            "List all captured versions in semantic-version order.",
            vec!["name"],
            vec!["name", "snapshot", "offset", "limit"],
        ),
        (
            "crate.catalog_search",
            "Search local package metadata; defaults to all versions.",
            vec![],
            vec![
                "query", "name", "version", "license", "keyword", "category", "msrv", "yanked",
                "mode", "snapshot", "offset", "limit",
            ],
        ),
        (
            "crate.document_get",
            "Read captured package text, retaining original notices and capture citations.",
            vec!["name", "version", "kind"],
            vec![
                "name", "version", "kind", "path", "target", "snapshot", "offset", "limit",
            ],
        ),
        (
            "crate.dependencies",
            "Inspect forward or reverse published dependency declarations; never resolve a graph.",
            vec!["name"],
            vec![
                "name",
                "version",
                "direction",
                "snapshot",
                "offset",
                "limit",
            ],
        ),
        (
            "crate.compare",
            "Compare exact versions, complete captured release changes, or an exact source/API path.",
            vec!["name", "from_version", "to_version"],
            vec![
                "name",
                "from_version",
                "to_version",
                "cursor",
                "kind",
                "path",
                "target",
                "snapshot",
                "offset",
                "limit",
            ],
        ),
        (
            "crate.content_search",
            "Search captured package source and documentation with global BM25.",
            vec!["query"],
            vec![
                "query", "name", "version", "path", "target", "kind", "mode", "snapshot", "offset",
                "limit",
            ],
        ),
        (
            "crate.api_search",
            "Search observed rustdoc API items across captured versions and targets.",
            vec!["query"],
            vec![
                "query", "name", "version", "path", "target", "mode", "snapshot", "offset", "limit",
            ],
        ),
        (
            "crate.api_get",
            "Read one observed public API path, signature and relationships.",
            vec!["name", "version", "path"],
            vec!["name", "version", "path", "target", "snapshot"],
        ),
        (
            "crate.corpus_status",
            "Inspect aggregate corpus progress and coverage without administrative controls.",
            vec![],
            vec![],
        ),
    ];
    for (tool, description, required, keys) in definitions {
        let mut properties = serde_json::Map::new();
        let mut keys = keys;
        if matches!(
            tool,
            "crate.versions"
                | "crate.catalog_search"
                | "crate.content_search"
                | "crate.api_search"
                | "crate.dependencies"
        ) {
            keys.push("cursor");
        }
        for key in keys {
            let value = match key {
                "cursor" => json!({"type":"string","minLength":1,"maxLength":16384}),
                "name" => name.clone(),
                "version" | "from_version" | "to_version" => version.clone(),
                "snapshot" => snapshot.clone(),
                "path" => path.clone(),
                "offset" => {
                    if matches!(tool, "crate.document_get" | "crate.compare") {
                        json!({"type":"integer","minimum":0,"default":0})
                    } else {
                        offset.clone()
                    }
                }
                "limit" => {
                    if tool == "crate.document_get" {
                        json!({"type":"integer","minimum":1,"maximum":32768,"default":32768})
                    } else if tool == "crate.compare" {
                        json!({"type":"integer","minimum":1,"maximum":32768,"description":"Release change pages default to 20 (maximum100); exact text pages default to 32768 bytes."})
                    } else {
                        list.clone()
                    }
                }
                "direction" => json!({"enum":["forward","reverse"],"default":"forward"}),
                "mode" => json!({"enum":["technical","english"],"default":"technical"}),
                "yanked" => json!({"type":"boolean"}),
                "kind" => {
                    if tool == "crate.compare" {
                        json!({"enum":["metadata","dependencies","text","api"],"default":"metadata"})
                    } else {
                        json!({"enum":["source","manifest","readme","license","rustdoc","api"]})
                    }
                }
                _ => text.clone(),
            };
            properties.insert(key.into(), value);
        }
        let mut input_schema = json!({"type":"object","properties":properties,"required":required,"additionalProperties":false});
        if tool == "crate.compare" {
            input_schema["allOf"] = json!([{"if":{"required":["path"]},"else":{"properties":{"limit":{"maximum":100},"offset":{"maximum":0}}}}]);
        }
        out.push(json!({"name":tool,"description":description,"inputSchema":input_schema,"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crates_io::index::tests::{NoNetwork, fixture};

    #[tokio::test]
    async fn research_uses_frozen_snapshots_and_preserves_declared_dependency_scope() {
        let root = tempfile::tempdir().unwrap();
        let store = fixture();
        let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
        let research = CrateResearch::new(store.clone(), retrieval, root.path().to_path_buf());
        let dependencies = research
            .call(
                "crate.dependencies",
                json!({"name":"example","version":"1.10.0"}),
            )
            .await
            .unwrap();
        assert_eq!(dependencies["items"][0]["package"], "dependency");
        assert_eq!(dependencies["metadata_capture"], "e".repeat(64));
        let api = research
            .call(
                "crate.api_get",
                json!({"name":"example","version":"1.10.0","path":"example::send"}),
            )
            .await
            .unwrap();
        assert_eq!(api["observed_signature"]["input"], "u8");
        assert_eq!(api["item"]["archive_capture"], "3".repeat(64));
        assert_eq!(research.call("crate.api_get",json!({"name":"example","version":"1.10.0","path":"example::send","surprise":true})).await.unwrap_err().code,"invalid_input");
        store.snapshot.lock().unwrap().inventory.validated_at -= 8 * 86400;
        assert_eq!(
            research
                .call(
                    "crate.dependencies",
                    json!({"name":"example","version":"1.10.0"})
                )
                .await
                .unwrap_err()
                .code,
            "unavailable"
        );
        assert!(
            research
                .call(
                    "crate.dependencies",
                    json!({"name":"example","version":"1.10.0","snapshot":"c".repeat(64)})
                )
                .await
                .is_ok()
        );
    }
    #[tokio::test]
    async fn complete_release_deltas_use_stable_cursor_paging() {
        let root = tempfile::tempdir().unwrap();
        let store = fixture();
        let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
        let research = CrateResearch::new(store, retrieval, root.path().to_path_buf());
        let first=research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"api","limit":1})).await.unwrap();
        assert_eq!(first["items"][0]["path"], "api0");
        assert_eq!(first["next_cursor"], "item0");
        let second=research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"api","limit":1,"cursor":first["next_cursor"]})).await.unwrap();
        assert_eq!(second["items"][0]["path"], "api1");
        assert_eq!(research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"api","offset":1})).await.unwrap_err().code,"invalid_input");
    }
    #[tokio::test]
    async fn every_research_tool_uses_indexed_or_paged_fixture_evidence() {
        let _serial = crate_index::TEST_BUILD.lock().await;
        let root = tempfile::tempdir().unwrap();
        let store = fixture();
        let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
        let snapshot = store.snapshot.lock().unwrap().clone();
        let manifest = crate_index::build(
            store.clone(),
            retrieval.clone(),
            root.path().to_path_buf(),
            snapshot,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        store.snapshot.lock().unwrap().index_manifest = manifest;
        let research = CrateResearch::new(store, retrieval, root.path().to_path_buf());
        let versions = research
            .call("crate.versions", json!({"name":"example"}))
            .await
            .unwrap();
        assert_eq!(versions["total"], 2);
        assert_eq!(
            versions["items"][0]["document"]["record"]["version"],
            "1.10.0"
        );
        let catalog=research.call("crate.catalog_search",json!({"query":"transport","license":"MIT","msrv":"1.70","keyword":"network","category":"development-tools","yanked":false})).await.unwrap();
        assert_eq!(catalog["total"], 2);
        let readme = research
            .call(
                "crate.document_get",
                json!({"name":"example","version":"1.10.0","kind":"readme","offset":0,"limit":9}),
            )
            .await
            .unwrap();
        assert_eq!(readme["page"]["text"], "transport");
        assert_eq!(readme["archive_capture"], "b".repeat(64));
        let reverse = research
            .call(
                "crate.dependencies",
                json!({"name":"dependency","direction":"reverse"}),
            )
            .await
            .unwrap();
        assert_eq!(reverse["total"], 2);
        let content = research
            .call(
                "crate.content_search",
                json!({"query":"source","kind":"source","version":"1.10.0"}),
            )
            .await
            .unwrap();
        assert_eq!(content["total"], 1);
        let apis = research
            .call(
                "crate.api_search",
                json!({"query":"transport","name":"example"}),
            )
            .await
            .unwrap();
        assert_eq!(apis["total"], 2);
        let metadata=research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"metadata"})).await.unwrap();
        assert_eq!(metadata["changed"], true);
        let deps=research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"dependencies"})).await.unwrap();
        assert_eq!(deps["changed"], false);
        let text=research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"text","path":"src/lib.rs"})).await.unwrap();
        assert_eq!(text["changed"], false);
        let api=research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"api","path":"example::send"})).await.unwrap();
        assert_eq!(api["changed"], true);
        assert_eq!(
            research
                .call("crate.corpus_status", json!({}))
                .await
                .unwrap()["fixture"],
            true
        );
        assert_eq!(
            research
                .call("crate.content_search", json!({"query":"field:source"}))
                .await
                .unwrap_err()
                .code,
            "invalid_input"
        );
    }
    #[tokio::test]
    async fn missing_or_unqualified_projection_never_becomes_an_added_removed_claim() {
        let root = tempfile::tempdir().unwrap();
        let store = fixture();
        let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
        *store.qualified.lock().unwrap() = false;
        let research = CrateResearch::new(store, retrieval, root.path().to_path_buf());
        assert_eq!(research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"api"})).await.unwrap_err().code,"unavailable");
        assert_eq!(research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"text"})).await.unwrap_err().code,"unavailable");
        assert_eq!(research.call("crate.compare",json!({"name":"example","from_version":"0.1.0","to_version":"1.10.0","kind":"api"})).await.unwrap_err().code,"not_found");
    }
    #[tokio::test]
    async fn dotted_rust_targets_are_accepted_by_actual_api_dispatch() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Arc::try_unwrap(fixture()).ok().unwrap();
        for row in &mut store.contents {
            if row.kind == "api" {
                row.target = "thumbv8m.main-none-eabi".into();
            }
        }
        let store = Arc::new(store);
        let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
        let research = CrateResearch::new(store, retrieval, root.path().to_path_buf());
        let result=research.call("crate.api_get",json!({"name":"example","version":"1.10.0","path":"example::send","target":"thumbv8m.main-none-eabi"})).await.unwrap();
        assert_eq!(result["item"]["target"], "thumbv8m.main-none-eabi");
        assert_eq!(research.call("crate.api_get",json!({"name":"example","version":"1.10.0","path":"example::send","target":"../escape"})).await.unwrap_err().code,"invalid_input");
    }
    #[tokio::test]
    async fn exact_captured_text_paths_ignore_unrelated_archive_binary_gaps() {
        let root = tempfile::tempdir().unwrap();
        let store = fixture();
        *store.skipped_binary.lock().unwrap() = 1;
        let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
        let research = CrateResearch::new(store, retrieval, root.path().to_path_buf());
        let result=research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"text","path":"src/lib.rs"})).await.unwrap();
        assert_eq!(result["changed"], false);
        assert_eq!(
            result["comparison_coverage"]["scope"],
            "selected_captured_paths"
        );
        assert_eq!(research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"text"})).await.unwrap_err().code,"unavailable");
    }
    #[tokio::test]
    async fn missing_text_path_with_archive_binary_gaps_is_not_an_addition_claim() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Arc::try_unwrap(fixture()).ok().unwrap();
        store
            .contents
            .retain(|row| !(row.version == "1.9.0" && row.kind == "source"));
        *store.skipped_binary.lock().unwrap() = 1;
        let store = Arc::new(store);
        let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
        let research = CrateResearch::new(store, retrieval, root.path().to_path_buf());
        assert_eq!(research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"text","path":"src/lib.rs"})).await.unwrap_err().code,"unavailable");
    }
    #[tokio::test]
    async fn exact_api_comparisons_ignore_only_unrelated_unresolved_references() {
        let root = tempfile::tempdir().unwrap();
        let store = fixture();
        *store.unresolved_references.lock().unwrap() = 3;
        let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
        let research = CrateResearch::new(store, retrieval, root.path().to_path_buf());
        let result=research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"api","path":"example::send"})).await.unwrap();
        assert_eq!(result["changed"], true);
        assert_eq!(
            result["comparison_coverage"]["normalization"],
            "complete_for_selected_items"
        );
        assert_eq!(research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"api"})).await.unwrap_err().code,"unavailable");
        let mut incomplete = Arc::try_unwrap(fixture()).ok().unwrap();
        incomplete
            .contents
            .iter_mut()
            .find(|row| row.version == "1.9.0" && row.kind == "api")
            .unwrap()
            .attributes["signature"] = json!({"input":{"unresolved_reference":true}});
        let incomplete = Arc::new(incomplete);
        let retrieval = Arc::new(Retrieval::new(incomplete.clone(), Arc::new(NoNetwork)));
        let research = CrateResearch::new(incomplete, retrieval, root.path().to_path_buf());
        assert_eq!(research.call("crate.compare",json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"api","path":"example::send"})).await.unwrap_err().code,"unavailable");
    }
    fn age_raw_source(
        store: &crate::crates_io::index::tests::FixtureStore,
        id: &str,
        seconds: i64,
    ) {
        store
            .artifacts
            .lock()
            .unwrap()
            .get_mut(id)
            .unwrap()
            .capture
            .validated_at = devres_domain::unix_now() - seconds;
    }
    #[tokio::test]
    async fn mutable_get_and_compare_use_raw_source_age_and_preserve_explicit_history() {
        let root = tempfile::tempdir().unwrap();
        let store = fixture();
        let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
        let research = CrateResearch::new(store.clone(), retrieval, root.path().to_path_buf());
        let api = json!({"name":"example","version":"1.10.0","path":"example::send"});
        let docs = json!({"name":"example","version":"1.10.0","kind":"rustdoc","path":"example/index.html"});
        age_raw_source(&store, &"3".repeat(64), 2 * 86400);
        age_raw_source(&store, &"9".repeat(64), 2 * 86400);
        let result = research.call("crate.api_get", api.clone()).await.unwrap();
        assert_eq!(result["source_capture"]["id"], "3".repeat(64));
        assert_eq!(result["source_capture"]["stale"], true);
        let text = research
            .call("crate.document_get", docs.clone())
            .await
            .unwrap();
        assert_eq!(text["source_capture"]["id"], "9".repeat(64));
        assert_eq!(text["source_capture"]["stale"], true);
        assert_eq!(text["capture"]["stale"], false);
        for path in [Some("example::send"), None] {
            let mut input =
                json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"api"});
            if let Some(path) = path {
                input["path"] = json!(path);
            }
            let compared = research.call("crate.compare", input).await.unwrap();
            let source = compared["comparison_coverage"]["source_captures"]
                .as_array()
                .unwrap()
                .iter()
                .find(|capture| capture["id"] == "3".repeat(64))
                .unwrap();
            assert_eq!(source["stale"], true);
            assert_eq!(
                source["validated_at"],
                result["source_capture"]["validated_at"]
            );
        }
        age_raw_source(&store, &"3".repeat(64), 8 * 86400);
        age_raw_source(&store, &"9".repeat(64), 8 * 86400);
        age_raw_source(&store, &"b".repeat(64), 8 * 86400);
        for (tool, input) in [
            ("crate.api_get", api.clone()),
            ("crate.document_get", docs.clone()),
        ] {
            let error = research.call(tool, input.clone()).await.unwrap_err();
            assert_eq!(error.code, "unavailable");
            assert!(error.message.contains("explicit historical snapshot"));
            let mut pinned = input;
            pinned["snapshot"] = json!("c".repeat(64));
            assert_eq!(
                research.call(tool, pinned).await.unwrap()["source_capture"]["stale"],
                true
            );
        }
        for path in [Some("example::send"), None] {
            let mut compare =
                json!({"name":"example","from_version":"1.9.0","to_version":"1.10.0","kind":"api"});
            if let Some(path) = path {
                compare["path"] = json!(path);
            }
            assert_eq!(
                research
                    .call("crate.compare", compare.clone())
                    .await
                    .unwrap_err()
                    .code,
                "unavailable"
            );
            compare["snapshot"] = json!("c".repeat(64));
            assert!(research.call("crate.compare", compare).await.is_ok());
        }
        let before = store
            .artifact_reads
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            research
                .call(
                    "crate.document_get",
                    json!({"name":"example","version":"1.10.0","kind":"source","path":"src/lib.rs"})
                )
                .await
                .is_ok()
        );
        assert!(
            research
                .call(
                    "crate.dependencies",
                    json!({"name":"example","version":"1.10.0"})
                )
                .await
                .is_ok()
        );
        assert_eq!(
            store
                .artifact_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            before
        );
        store.artifacts.lock().unwrap().remove(&"3".repeat(64));
        let mut pinned = api;
        pinned["snapshot"] = json!("c".repeat(64));
        assert_eq!(
            research
                .call("crate.api_get", pinned)
                .await
                .unwrap_err()
                .code,
            "unavailable"
        );
    }
    #[tokio::test]
    async fn search_freshness_checks_only_selected_mutable_hits_and_deduplicates_raw_ids() {
        let _serial = crate_index::TEST_BUILD.lock().await;
        let root = tempfile::tempdir().unwrap();
        let mut fixture_store = Arc::try_unwrap(fixture()).ok().unwrap();
        let mut alias = fixture_store
            .contents
            .iter()
            .find(|row| row.kind == "api" && row.version == "1.10.0")
            .unwrap()
            .clone();
        alias.id = "c".repeat(64);
        alias.path = "example::send_alias".into();
        fixture_store.contents.push(alias);
        let store = Arc::new(fixture_store);
        let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
        let snapshot = store.snapshot.lock().unwrap().clone();
        let manifest = crate_index::build(
            store.clone(),
            retrieval.clone(),
            root.path().to_path_buf(),
            snapshot,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        store.snapshot.lock().unwrap().index_manifest = manifest;
        let research = CrateResearch::new(store.clone(), retrieval, root.path().to_path_buf());
        age_raw_source(&store, &"3".repeat(64), 8 * 86400);
        age_raw_source(&store, &"9".repeat(64), 8 * 86400);
        assert_eq!(
            research
                .call(
                    "crate.api_search",
                    json!({"query":"transport","name":"example"})
                )
                .await
                .unwrap_err()
                .code,
            "unavailable"
        );
        let fresh = research
            .call(
                "crate.api_search",
                json!({"query":"transport","version":"1.9.0"}),
            )
            .await
            .unwrap();
        assert_eq!(fresh["total"], 1);
        assert_eq!(fresh["items"][0]["source_capture"]["stale"], false);
        assert!(
            research
                .call(
                    "crate.content_search",
                    json!({"query":"source","kind":"source"})
                )
                .await
                .is_ok()
        );
        assert_eq!(
            research
                .call(
                    "crate.content_search",
                    json!({"query":"source","kind":"rustdoc"})
                )
                .await
                .unwrap_err()
                .code,
            "unavailable"
        );
        let historical = research
            .call(
                "crate.content_search",
                json!({"query":"source","kind":"rustdoc","snapshot":"c".repeat(64)}),
            )
            .await
            .unwrap();
        assert_eq!(historical["items"][0]["source_capture"]["stale"], true);
        store
            .artifact_reads
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let historical = research
            .call(
                "crate.api_search",
                json!({"query":"transport","version":"1.10.0","snapshot":"c".repeat(64)}),
            )
            .await
            .unwrap();
        assert_eq!(historical["total"], 2);
        assert_eq!(historical["items"].as_array().unwrap().len(), 2);
        assert_eq!(
            store
                .artifact_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        age_raw_source(&store, &"3".repeat(64), 2 * 86400);
        let stale = research
            .call(
                "crate.api_search",
                json!({"query":"transport","version":"1.10.0"}),
            )
            .await
            .unwrap();
        assert_eq!(stale["items"][0]["source_capture"]["stale"], true);
        let before = store
            .artifact_reads
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            research
                .call("crate.catalog_search", json!({"name":"example"}))
                .await
                .unwrap()["total"],
            2
        );
        assert_eq!(
            store
                .artifact_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            before
        );
        store.artifacts.lock().unwrap().remove(&"3".repeat(64));
        assert_eq!(
            research
                .call(
                    "crate.api_search",
                    json!({"query":"transport","version":"1.10.0","snapshot":"c".repeat(64)})
                )
                .await
                .unwrap_err()
                .code,
            "unavailable"
        );
    }
}
