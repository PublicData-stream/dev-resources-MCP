//! Local, capture-fixed npm research. No call in this module initiates provider traffic.
use crate::{
    npm::corpus::{NpmCorpus, identity, snapshot_summary},
    npm::index::SearchSpec,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub struct NpmResearch {
    corpus: Arc<NpmCorpus>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    name: Option<String>,
    version: Option<String>,
    from_version: Option<String>,
    to_version: Option<String>,
    path: Option<String>,
    query: Option<String>,
    mode: Option<String>,
    snapshot: Option<String>,
    cursor: Option<String>,
    filters: BTreeMap<String, Value>,
    offset: usize,
    limit: Option<usize>,
    direction: Option<String>,
    representation: Option<String>,
    id: Option<String>,
    history_snapshot: Option<i64>,
    lane: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    #[serde(default)]
    version: u8,
    snapshot: String,
    query: String,
    position: usize,
    cutoff: Option<i64>,
}
fn invalid() -> Error {
    Error::invalid("Arguments do not match the npm research schema.")
}
fn failure() -> Error {
    Error::integrity("npm research evidence is incomplete or invalid.")
}
fn required(value: &Option<String>) -> Result<&str> {
    value.as_deref().ok_or_else(invalid)
}
fn deadline(start: Instant) -> Result<()> {
    if start.elapsed() > Duration::from_secs(15) {
        Err(Error::capacity("npm research deadline exceeded."))
    } else {
        Ok(())
    }
}
fn cursor(value: &str) -> Result<Cursor> {
    if value.len() > 16 * 1024 {
        return Err(invalid());
    }
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(value).map_err(|_| invalid())?)
        .map_err(|_| invalid())
}
fn summary(row: &Value) -> Value {
    let m = &row["manifest"];
    json!({"name":row["name"],"version":row["version"],"description":m["description"],"license":m["license"],
        "keywords":m["keywords"],"deprecated":m["deprecated"],"engines":m["engines"],"dist":m["dist"],"metadata_capture":row["metadata"]})
}
impl NpmResearch {
    pub fn new(corpus: Arc<NpmCorpus>) -> Self {
        Self { corpus }
    }
    pub async fn call(&self, tool: &str, value: Value) -> Result<Value> {
        let schema = schemas()
            .into_iter()
            .find(|v| v["name"] == tool)
            .ok_or_else(|| Error::not_found("Unknown npm research tool."))?;
        let object = value.as_object().ok_or_else(invalid)?;
        let properties = schema["inputSchema"]["properties"]
            .as_object()
            .ok_or_else(invalid)?;
        if object.keys().any(|k| !properties.contains_key(k)) {
            return Err(invalid());
        }
        if schema["inputSchema"]["required"]
            .as_array()
            .is_some_and(|fields| {
                fields
                    .iter()
                    .any(|field| field.as_str().is_none_or(|name| !object.contains_key(name)))
            })
        {
            return Err(invalid());
        }
        let mut input: Input = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        if (!matches!(
            tool,
            "npm.document_get" | "npm.contract_get" | "npm.advisory_get" | "npm.compare"
        ) && input.offset > 10_000)
            || input
                .query
                .as_ref()
                .is_some_and(|v| v.chars().count() > 256 || v.chars().any(char::is_control))
        {
            return Err(invalid());
        }
        if let Some(name) = &input.name {
            crate::npm::processing::validate_name(name)?;
        }
        if tool == "npm.corpus_status" {
            return self.corpus.status().await;
        }
        let mut arguments = value;
        if let Some(arguments) = arguments.as_object_mut() {
            for key in ["offset", "limit", "cursor", "snapshot", "history_snapshot"] {
                arguments.remove(key);
            }
        }
        let query_value = json!([tool, arguments]);
        let version = input
            .cursor
            .as_deref()
            .map(cursor)
            .transpose()?
            .map_or(2, |c| c.version);
        let query = match version {
            0 => crate::integrity::legacy_hash(
                &serde_json::to_vec(&query_value).map_err(|_| failure())?,
            ),
            2 => identity(&query_value)?,
            _ => return Err(Error::invalid("Unsupported npm cursor version.")),
        };
        if tool == "npm.content_search" {
            if input.cursor.is_some() && input.snapshot.is_none() {
                return Err(Error::invalid(
                    "npm content cursor requires its returned snapshot.",
                ));
            }
            let snapshot = self
                .corpus
                .selection("research", input.snapshot.as_deref())
                .await?;
            return self.content_search(input, snapshot).await;
        }
        let selected_cursor = input.cursor.as_deref().map(cursor).transpose()?;
        if let Some(cursor) = &selected_cursor {
            if cursor.query != query
                || input
                    .snapshot
                    .as_ref()
                    .is_some_and(|v| v != &cursor.snapshot)
            {
                return Err(Error::invalid(
                    "npm cursor belongs to another query or snapshot.",
                ));
            }
            input.snapshot = Some(cursor.snapshot.clone());
        }
        if tool == "npm.history" || tool == "npm.snapshots" {
            return self.discovery(tool, input, &query, selected_cursor).await;
        }
        if tool.starts_with("npm.advisory_") {
            return self.advisories(tool, input, &query, selected_cursor).await;
        }
        let snapshot = self
            .corpus
            .selection("research", input.snapshot.as_deref())
            .await?;
        match tool {
            "npm.content_search" => self.content_search(input, snapshot).await,
            "npm.document_get" => self.document_get(input, &snapshot).await,
            "npm.contract_get" => self.contract_get(input, &snapshot).await,
            "npm.compare" => self.compare(input, &snapshot).await,
            "npm.dependencies" => {
                self.dependencies(input, &snapshot, &query, selected_cursor)
                    .await
            }
            "npm.versions" | "npm.catalog_search" => {
                self.catalog(tool, input, &snapshot, &query, selected_cursor)
                    .await
            }
            _ => Err(Error::not_found("Unknown npm research tool.")),
        }
    }
    async fn members(
        &self,
        snapshot: &Value,
        kind: &str,
        name: Option<&str>,
    ) -> Result<Vec<Value>> {
        let start = Instant::now();
        let mut output = Vec::new();
        let mut bytes = 0;
        let packages = snapshot["packages"].as_object().ok_or_else(failure)?;
        if name.is_some_and(|name| !packages.contains_key(name)) {
            return Err(Error::not_found(
                "Package is outside the selected npm snapshot.",
            ));
        }
        for (package, id) in packages {
            if name.is_some_and(|name| name != package) {
                continue;
            }
            let filter = json!({"snapshot":id,"kind":kind});
            let mut after = 0;
            loop {
                deadline(start)?;
                let rows = self
                    .corpus
                    .store
                    .npm_rows("members", after, 1000, None, Some(&filter))
                    .await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    after = row.sequence;
                    bytes += serde_json::to_vec(&row.data).map_err(|_| failure())?.len();
                    if output.len() >= 1_000_000 || bytes > 64 * 1024 * 1024 {
                        return Err(Error::capacity("npm selected membership exceeds bound."));
                    }
                    output.push(row.data);
                }
            }
        }
        output.sort_by(|a, b| {
            a["name"]
                .as_str()
                .cmp(&b["name"].as_str())
                .then_with(|| {
                    let a = a["version"].as_str().unwrap_or_default();
                    let b = b["version"].as_str().unwrap_or_default();
                    match (
                        crate::npm::processing::parse_version(a),
                        crate::npm::processing::parse_version(b),
                    ) {
                        (Ok(a), Ok(b)) => b.cmp(&a),
                        _ => b.cmp(a),
                    }
                })
                .then_with(|| a["record"].as_str().cmp(&b["record"].as_str()))
        });
        Ok(output)
    }
    async fn release(&self, snapshot: &Value, name: &str, version: &str) -> Result<Value> {
        crate::npm::processing::validate_name(name)?;
        let members = self.members(snapshot, "version", Some(name)).await?;
        let member = members
            .iter()
            .find(|v| v["version"] == version)
            .ok_or_else(|| {
                Error::not_found("Exact npm version is not captured in this snapshot.")
            })?;
        self.corpus
            .store
            .npm_get("versions", member["record"].as_str().ok_or_else(failure)?)
            .await?
            .map(|r| r.data)
            .ok_or_else(failure)
    }
    async fn projection(&self, snapshot: &Value, name: &str, version: &str) -> Result<Value> {
        let members = self.members(snapshot, "projection", Some(name)).await?;
        let member = members
            .iter()
            .find(|v| v["version"] == version)
            .ok_or_else(|| {
                Error::unavailable("npm release has no supported package projection.")
            })?;
        self.corpus
            .store
            .npm_get(
                "projections",
                member["record"].as_str().ok_or_else(failure)?,
            )
            .await?
            .map(|r| r.data)
            .ok_or_else(failure)
    }
    fn page(
        &self,
        input: &Input,
        snapshot: &Value,
        query: &str,
        selected_cursor: Option<Cursor>,
        items: Vec<Value>,
    ) -> Result<Value> {
        let limit = input.limit.unwrap_or(20);
        if !(1..=100).contains(&limit) {
            return Err(invalid());
        }
        let position = selected_cursor
            .as_ref()
            .map_or(input.offset, |c| c.position);
        let total = items.len();
        let end = position.saturating_add(limit).min(total);
        let next = if end < total {
            Some(
                URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(&Cursor {
                        version: if query.starts_with("blake3:") { 2 } else { 0 },
                        snapshot: snapshot["id"].as_str().ok_or_else(failure)?.into(),
                        query: query.into(),
                        position: end,
                        cutoff: None,
                    })
                    .map_err(|_| failure())?,
                ),
            )
        } else {
            None
        };
        Ok(
            json!({"items":items.into_iter().skip(position).take(limit).collect::<Vec<_>>(),"total":total,"offset":position,
            "next_offset":if end<total&&end<=10_000{Some(end)}else{None},"next_cursor":next,"snapshot":snapshot_summary(snapshot)}),
        )
    }
    async fn catalog(
        &self,
        tool: &str,
        input: Input,
        snapshot: &Value,
        query: &str,
        selected_cursor: Option<Cursor>,
    ) -> Result<Value> {
        if tool == "npm.versions" && input.name.is_none() {
            return Err(invalid());
        }
        let members = self
            .members(snapshot, "version", input.name.as_deref())
            .await?;
        let mut output = Vec::new();
        let mut output_bytes = 0;
        let start = Instant::now();
        for member in members {
            deadline(start)?;
            if let Some(version) = &input.version
                && member["version"] != *version
            {
                continue;
            }
            let row = self
                .corpus
                .store
                .npm_get("versions", member["record"].as_str().ok_or_else(failure)?)
                .await?
                .ok_or_else(failure)?
                .data;
            if !matches_catalog(&row, &input)? {
                continue;
            }
            bounded_push(&mut output, &mut output_bytes, summary(&row))?;
            if output.len() > 50_000 {
                return Err(Error::capacity(
                    "npm catalog result exceeds bounded query window.",
                ));
            }
        }
        self.page(&input, snapshot, query, selected_cursor, output)
    }
    async fn document_get(&self, input: Input, snapshot: &Value) -> Result<Value> {
        let name = required(&input.name)?;
        let version = required(&input.version)?;
        if input.representation.as_deref() == Some("metadata") {
            let release = self.release(snapshot, name, version).await?;
            let text = serde_json::to_string_pretty(&release["manifest"]).map_err(|_| failure())?;
            return Ok(
                json!({"name":name,"version":version,"representation":"metadata","snapshot":snapshot_summary(snapshot),
                "page":crate::research::text_page(&text,input.offset,input.limit.unwrap_or(32768))?,"provenance":release["metadata"]}),
            );
        }
        if input
            .representation
            .as_deref()
            .is_some_and(|v| !matches!(v, "text" | "source"))
        {
            return Err(invalid());
        }
        let projection = self.projection(snapshot, name, version).await?;
        let path = input.path.as_deref().unwrap_or("package.json");
        for id in projection["documents"].as_array().into_iter().flatten() {
            let id = id.as_str().ok_or_else(failure)?;
            let row = self
                .corpus
                .store
                .npm_get("documents", id)
                .await?
                .ok_or_else(failure)?
                .data;
            if row["path"] != path {
                continue;
            }
            let text = row["text"].as_str().ok_or_else(failure)?;
            let uri = resource(
                snapshot,
                "document",
                &json!({"name":name,"version":version,"path":path}),
            )?;
            return Ok(
                json!({"name":name,"version":version,"path":path,"kind":row["kind"],"snapshot":snapshot_summary(snapshot),
                "page":crate::research::text_page(text,input.offset,input.limit.unwrap_or(32768))?,"resource_uri":uri,
                "provenance":{"metadata":row["release"],"archive":row["artifact"]},"gaps":projection["gaps"],"notices":"Original package license and notices apply; source is inert."}),
            );
        }
        Err(Error::not_found(
            "npm document path is absent or unprojected.",
        ))
    }
    async fn contract_get(&self, input: Input, snapshot: &Value) -> Result<Value> {
        let name = required(&input.name)?;
        let version = required(&input.version)?;
        let projection = self.projection(snapshot, name, version).await?;
        let serialized =
            serde_json::to_string_pretty(&projection["contracts"]).map_err(|_| failure())?;
        Ok(
            json!({"name":name,"version":version,"snapshot":snapshot_summary(snapshot),"contracts":if serialized.len()<=65536{projection["contracts"].clone()}else{Value::Null},
            "page":crate::research::text_page(&serialized,input.offset,input.limit.unwrap_or(32768))?,"gaps":projection["gaps"],
            "resource_uri":resource(snapshot,"contract",&json!({"name":name,"version":version}))?,
            "provenance":{"archive":projection["artifact"],"metadata":projection["release"]},
            "scope":"Published manifest and declaration contracts; no module resolution or JS/TS symbol analysis."}),
        )
    }
    async fn dependencies(
        &self,
        input: Input,
        snapshot: &Value,
        query: &str,
        selected_cursor: Option<Cursor>,
    ) -> Result<Value> {
        let name = required(&input.name)?;
        let mut output = Vec::new();
        let mut output_bytes = 0;
        let direction = input.direction.as_deref().unwrap_or("forward");
        if !matches!(direction, "forward" | "reverse") {
            return Err(invalid());
        }
        if direction == "forward" {
            let release = self
                .release(snapshot, name, required(&input.version)?)
                .await?;
            output = dependencies(&release);
        } else {
            let start = Instant::now();
            for member in self.members(snapshot, "version", None).await? {
                deadline(start)?;
                let row = self
                    .corpus
                    .store
                    .npm_get("versions", member["record"].as_str().ok_or_else(failure)?)
                    .await?
                    .ok_or_else(failure)?
                    .data;
                for mut dependency in dependencies(&row) {
                    let declared = dependency["name"].as_str().unwrap_or_default();
                    let spec = dependency["specifier"].as_str().unwrap_or_default();
                    let target = alias_target(spec).unwrap_or(declared);
                    if target == name {
                        dependency["dependent"] = summary(&row);
                        bounded_push(&mut output, &mut output_bytes, dependency)?;
                    }
                }
                if output.len() > 50_000 {
                    return Err(Error::capacity(
                        "npm reverse-reference results exceed bound.",
                    ));
                }
            }
        }
        let mut output = self.page(&input, snapshot, query, selected_cursor, output)?;
        output["scope"] = json!("Declared references only; no dependency or peer resolution.");
        Ok(output)
    }
    async fn compare(&self, input: Input, snapshot: &Value) -> Result<Value> {
        let name = required(&input.name)?;
        let from = required(&input.from_version)?;
        let to = required(&input.to_version)?;
        let before = self.release(snapshot, name, from).await?;
        let after = self.release(snapshot, name, to).await?;
        let mut changes = Vec::new();
        let before_object = before["manifest"].as_object().ok_or_else(failure)?;
        let after_object = after["manifest"].as_object().ok_or_else(failure)?;
        let keys: BTreeSet<_> = before_object.keys().chain(after_object.keys()).collect();
        for key in keys {
            if before_object.get(key) != after_object.get(key) {
                changes.push(json!({"field":key,"before":before_object.get(key),"after":after_object.get(key)}));
            }
        }
        let before_contract = self.projection(snapshot, name, from).await;
        let after_contract = self.projection(snapshot, name, to).await;
        let contracts = match (before_contract, after_contract) {
            (Ok(a), Ok(b)) => {
                json!({"qualified":projection_qualified(&a)&&projection_qualified(&b),"changed":a["contracts"]!=b["contracts"],"before":a["contracts"],"after":b["contracts"],"before_gaps":a["gaps"],"after_gaps":b["gaps"]})
            }
            _ => json!({"qualified":false,"reason":"projection_unavailable"}),
        };
        let mut result = json!({"name":name,"from_version":from,"to_version":to,"snapshot":snapshot_summary(snapshot),"metadata_changes":changes,
            "declarations":{"before":dependencies(&before),"after":dependencies(&after)},"contracts":contracts,
            "scope":"Captured observations; not semantic-version, compatibility or security certification."});
        if let Some(path) = &input.path {
            let a = self.document_text(snapshot, name, from, path).await?;
            let b = self.document_text(snapshot, name, to, path).await?;
            let (text, count) = positional_diff(&a.0, &b.0)?;
            result["text_diff"] = json!({"path":path,"algorithm":"positional_line_changes","changes":count,
                "identical":a.0==b.0,"qualified":a.1&&b.1,"page":crate::research::text_page(&text,input.offset,input.limit.unwrap_or(32768))?});
        }
        Ok(result)
    }
    async fn document_text(
        &self,
        snapshot: &Value,
        name: &str,
        version: &str,
        path: &str,
    ) -> Result<(String, bool)> {
        let projection = self.projection(snapshot, name, version).await?;
        for id in projection["documents"].as_array().into_iter().flatten() {
            let row = self
                .corpus
                .store
                .npm_get("documents", id.as_str().ok_or_else(failure)?)
                .await?
                .ok_or_else(failure)?;
            if row.data["path"] == path {
                return Ok((
                    row.data["text"].as_str().ok_or_else(failure)?.into(),
                    projection_qualified(&projection),
                ));
            }
        }
        Err(Error::not_found(
            "npm comparison document is absent or unprojected.",
        ))
    }
    async fn content_search(&self, input: Input, snapshot: Value) -> Result<Value> {
        let mut members = BTreeSet::new();
        for member in self
            .members(&snapshot, "indexed-document", input.name.as_deref())
            .await?
        {
            members.insert(member["record"].as_str().ok_or_else(failure)?.into());
        }
        let index = snapshot["index"].clone();
        if index.is_null() {
            return Err(Error::unavailable(
                "npm snapshot has no usable content index.",
            ));
        }
        let mut filters = BTreeMap::new();
        for (k, v) in input.filters {
            filters.insert(k, v.as_str().ok_or_else(invalid)?.into());
        }
        if let Some(name) = input.name {
            filters.insert("name".into(), name);
        }
        if let Some(version) = input.version {
            filters.insert("version".into(), version);
        }
        let cancel = CancellationToken::new();
        let _guard = cancel.clone().drop_guard();
        let mut result = self
            .corpus
            .index
            .search(
                &index,
                members,
                SearchSpec {
                    query: input.query,
                    snapshot: snapshot["id"].as_str().map(str::to_owned),
                    mode: input.mode.unwrap_or_else(|| "technical".into()),
                    filters,
                    offset: input.offset,
                    limit: input.limit.unwrap_or(20),
                    cursor: input.cursor,
                },
                cancel,
            )
            .await?;
        result["snapshot"] = snapshot_summary(&snapshot);
        Ok(result)
    }
    async fn discovery(
        &self,
        tool: &str,
        input: Input,
        query: &str,
        selected_cursor: Option<Cursor>,
    ) -> Result<Value> {
        let cutoff = selected_cursor
            .as_ref()
            .and_then(|v| v.cutoff)
            .or(input.history_snapshot)
            .unwrap_or(self.corpus.store.npm_cutoff().await?);
        if cutoff < 0 {
            return Err(invalid());
        }
        if tool == "npm.history" && input.name.is_none() {
            return Err(invalid());
        }
        let mut output = Vec::new();
        let mut output_bytes = 0;
        let mut after = 0;
        let start = Instant::now();
        let kind = if tool == "npm.history" {
            "package-snapshots"
        } else {
            "snapshots"
        };
        let filter = if tool == "npm.history" {
            input.name.as_ref().map(|name| json!({"name":name}))
        } else {
            if input
                .lane
                .as_ref()
                .is_some_and(|v| !matches!(v.as_str(), "research" | "advisories"))
            {
                return Err(invalid());
            }
            input.lane.as_ref().map(|lane| json!({"lane":lane}))
        };
        loop {
            deadline(start)?;
            let rows = self
                .corpus
                .store
                .npm_rows(kind, after, 1000, Some(cutoff), filter.as_ref())
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                let mut data = snapshot_summary(&row.data);
                data["publication_sequence"] = json!(row.sequence);
                if tool == "npm.history" {
                    for key in [
                        "name",
                        "previous",
                        "versions",
                        "documents",
                        "dist_tags",
                        "metadata",
                        "time",
                    ] {
                        if let Some(value) = row.data.get(key) {
                            data[key] = value.clone();
                        }
                    }
                    data["observation"] = json!("captured_package_metadata");
                }
                bounded_push(&mut output, &mut output_bytes, data)?;
            }
            if output.len() > 50_000 {
                return Err(Error::capacity("npm history selection exceeds bound."));
            }
        }
        let view = json!({"id":format!("history-{cutoff}"),"history_snapshot":cutoff});
        let mut result = self.page(&input, &view, query, selected_cursor, output)?;
        result["history_snapshot"] = json!(cutoff);
        if let Some(encoded) = result["next_cursor"].as_str() {
            let mut token = cursor(encoded)?;
            token.cutoff = Some(cutoff);
            result["next_cursor"] =
                json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&token).map_err(|_| failure())?));
        }
        Ok(result)
    }
    async fn advisories(
        &self,
        tool: &str,
        input: Input,
        query: &str,
        selected_cursor: Option<Cursor>,
    ) -> Result<Value> {
        let snapshot = self
            .corpus
            .advisory_selection(input.snapshot.as_deref())
            .await?;
        if tool == "npm.advisory_lookup" {
            let name = required(&input.name)?;
            let version = required(&input.version)?;
            crate::npm::processing::parse_version(version)?;
            let evidence = self
                .corpus
                .advisory_snapshot_for_names(snapshot["id"].as_str(), &[name.to_string()])
                .await?;
            let mut output = Vec::new();
            let mut output_bytes = 0;
            let mut complete = snapshot["complete"] == true
                && snapshot["historical"] != true
                && snapshot["validated_at"].as_i64().is_some_and(|t| {
                    t > 0
                        && t <= devres_domain::unix_now()
                        && devres_domain::unix_now() - t <= 7 * 86400
                });
            for record in evidence["records"].as_array().into_iter().flatten() {
                let matched = crate::npm::audit::match_record(record, name, version)?;
                complete &= matched["complete"] == true;
                if matched["matched"] == true {
                    bounded_push(&mut output, &mut output_bytes, advisory_summary(record))?;
                }
            }
            let mut result = self.page(&input, &snapshot, query, selected_cursor, output)?;
            result["complete"] = json!(complete);
            return Ok(result);
        }
        let mut filter = json!({"snapshot":snapshot["membership"]});
        if let Some(id) = &input.id {
            filter["id"] = json!(id);
        }
        let mut output = Vec::new();
        let mut output_bytes = 0;
        let mut after = 0;
        let start = Instant::now();
        loop {
            deadline(start)?;
            let rows = self
                .corpus
                .store
                .npm_rows("advisory-members", after, 100, None, Some(&filter))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                let record = self
                    .corpus
                    .store
                    .npm_get(
                        "advisories",
                        row.data["record"].as_str().ok_or_else(failure)?,
                    )
                    .await?
                    .ok_or_else(failure)?
                    .data;
                if tool == "npm.advisory_get" {
                    if record["rights_gap"] == true {
                        return Ok(
                            json!({"advisory":advisory_summary(&record),"snapshot":snapshot_summary(&snapshot),"metadata_only":true,"gap":"unresolved_redistribution_rights","page":null,"resource_uri":null}),
                        );
                    }
                    if input.representation.as_deref() == Some("metadata") {
                        return Ok(
                            json!({"advisory":advisory_summary(&record),"snapshot":snapshot_summary(&snapshot)}),
                        );
                    }
                    let raw_id = row.data["raw"].as_str().ok_or_else(|| {
                        Error::unavailable("Original npm advisory bytes are unavailable.")
                    })?;
                    let raw = self
                        .corpus
                        .store
                        .npm_get("advisory-raw", raw_id)
                        .await?
                        .ok_or_else(failure)?
                        .data;
                    let artifact: crate::bulk::BulkArtifact =
                        serde_json::from_value(raw["artifact"].clone()).map_err(|_| failure())?;
                    let bytes = self
                        .corpus
                        .bytes(&artifact, 1024 * 1024, CancellationToken::new())
                        .await?;
                    let original = std::str::from_utf8(&bytes).map_err(|_| failure())?;
                    return Ok(
                        json!({"advisory":advisory_summary(&record),"snapshot":snapshot_summary(&snapshot),"representation":input.representation.as_deref().unwrap_or("source"),
                        "page":crate::research::text_page(original,input.offset,input.limit.unwrap_or(32768))?,"provenance":raw,"resource_uri":resource(&snapshot,"advisory",&json!({"id":record["id"]}))?}),
                    );
                }
                let projected = advisory_summary(&record);
                if input.name.as_ref().is_some_and(|name| {
                    !record["packages"]
                        .as_array()
                        .is_some_and(|a| a.is_empty() || a.iter().any(|v| v == name || v == "*"))
                }) {
                    continue;
                }
                let text = serde_json::to_string(&projected)
                    .map_err(|_| failure())?
                    .to_lowercase();
                if input.query.as_ref().is_some_and(|q| {
                    !q.to_lowercase()
                        .split_whitespace()
                        .all(|term| text.contains(term))
                }) {
                    continue;
                }
                for key in input.filters.keys() {
                    if !matches!(key.as_str(), "classification" | "id" | "alias") {
                        return Err(invalid());
                    }
                }
                if input
                    .filters
                    .get("classification")
                    .is_some_and(|v| v != &record["classification"])
                {
                    continue;
                }
                if input.filters.get("id").is_some_and(|v| v != &record["id"]) {
                    continue;
                }
                if input.filters.get("alias").is_some_and(|v| {
                    !record["original"]["aliases"]
                        .as_array()
                        .is_some_and(|a| a.contains(v))
                }) {
                    continue;
                }
                bounded_push(&mut output, &mut output_bytes, projected)?;
                if output.len() > 50_000 {
                    return Err(Error::capacity(
                        "npm advisory results exceed bounded query window.",
                    ));
                }
            }
        }
        if tool == "npm.advisory_get" {
            return Err(Error::not_found("npm advisory not found."));
        }
        self.page(&input, &snapshot, query, selected_cursor, output)
    }
    pub async fn read_resource(&self, uri: &str) -> Result<Value> {
        if uri.len() > 16 * 1024 {
            return Err(invalid());
        }
        let url = url::Url::parse(uri).map_err(|_| invalid())?;
        if url.scheme() != "devres"
            || url.host_str() != Some("npm")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        let parts: Vec<_> = url.path().trim_start_matches('/').split('/').collect();
        if parts.len() != 3 {
            return Err(invalid());
        }
        let identity: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        let mut input = identity.as_object().cloned().ok_or_else(invalid)?;
        input.insert("snapshot".into(), json!(parts[0]));
        let mut seen = BTreeSet::new();
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string()) || !matches!(key.as_ref(), "offset" | "limit") {
                return Err(invalid());
            }
            input.insert(
                key.into_owned(),
                json!(value.parse::<usize>().map_err(|_| invalid())?),
            );
        }
        let tool = match parts[1] {
            "document" => "npm.document_get",
            "contract" => "npm.contract_get",
            "advisory" => "npm.advisory_get",
            _ => return Err(invalid()),
        };
        let value = self.call(tool, Value::Object(input)).await?;
        if value["metadata_only"] == true {
            return Err(Error::unavailable(
                "npm advisory source redistribution rights are unresolved.",
            ));
        }
        let text = if let Some(text) = value.pointer("/page/text").and_then(Value::as_str) {
            text.to_string()
        } else {
            let text = serde_json::to_string_pretty(&value["contracts"]).map_err(|_| failure())?;
            if text.len() > 32768 {
                return Err(Error::capacity(
                    "npm contract resource exceeds bounded text page.",
                ));
            }
            text
        };
        Ok(json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":text}]}))
    }
}
fn resource(snapshot: &Value, kind: &str, key: &Value) -> Result<String> {
    Ok(format!(
        "devres://npm/{}/{kind}/{}",
        snapshot["id"].as_str().ok_or_else(failure)?,
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(key).map_err(|_| failure())?)
    ))
}
fn dependencies(release: &Value) -> Vec<Value> {
    let mut output = Vec::new();
    for kind in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        for (name, specifier) in release["manifest"][kind].as_object().into_iter().flatten() {
            output.push(json!({"name":name,"specifier":specifier,"kind":kind,"peer_meta":release["manifest"]["peerDependenciesMeta"][name]}));
        }
    }
    for item in release["manifest"]["bundleDependencies"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(
            release["manifest"]["bundledDependencies"]
                .as_array()
                .into_iter()
                .flatten(),
        )
    {
        output.push(json!({"name":item,"kind":"bundled_declaration","specifier":null}));
    }
    output
}
fn alias_target(spec: &str) -> Option<&str> {
    let value = spec.strip_prefix("npm:")?;
    let index = value.rfind('@')?;
    if index == 0 {
        None
    } else {
        Some(&value[..index])
    }
}
fn matches_catalog(row: &Value, input: &Input) -> Result<bool> {
    for key in input.filters.keys() {
        if !matches!(
            key.as_str(),
            "license" | "keyword" | "deprecated" | "has_types" | "name"
        ) {
            return Err(invalid());
        }
    }
    let m = &row["manifest"];
    if input.filters.get("name").is_some_and(|v| v != &row["name"]) {
        return Ok(false);
    }
    if input
        .filters
        .get("license")
        .is_some_and(|v| v != &m["license"])
    {
        return Ok(false);
    }
    if input
        .filters
        .get("keyword")
        .is_some_and(|v| !m["keywords"].as_array().is_some_and(|a| a.contains(v)))
    {
        return Ok(false);
    }
    if input.filters.get("deprecated").is_some_and(|v| {
        v.as_bool() != Some(m["deprecated"].as_str().is_some_and(|s| !s.is_empty()))
    }) {
        return Ok(false);
    }
    if input.filters.get("has_types").is_some_and(|v| {
        v.as_bool() != Some(m.get("types").is_some() || m.get("typings").is_some())
    }) {
        return Ok(false);
    }
    if let Some(query) = &input.query {
        let text = format!(
            "{} {} {}",
            row["name"].as_str().unwrap_or_default(),
            m["description"].as_str().unwrap_or_default(),
            m["keywords"]
        )
        .to_lowercase();
        if !query
            .to_lowercase()
            .split_whitespace()
            .all(|term| text.contains(term))
        {
            return Ok(false);
        }
    }
    Ok(true)
}
fn advisory_summary(record: &Value) -> Value {
    json!({"id":record["id"],"packages":record["packages"],"classification":record["classification"],
    "matching_complete":record["matching_complete"],"license":record["license"],"attribution_url":record["attribution_url"],"rights_gap":record["rights_gap"],
    "aliases":record["original"]["aliases"],"summary":if record["rights_gap"]==true{Value::Null}else{record["original"]["summary"].clone()},"published":record["original"]["published"],"modified":record["original"]["modified"],"withdrawn":record["original"]["withdrawn"]})
}

fn bounded_push(output: &mut Vec<Value>, bytes: &mut usize, value: Value) -> Result<()> {
    let added = serde_json::to_vec(&value).map_err(|_| failure())?.len();
    *bytes = bytes
        .checked_add(added)
        .filter(|v| *v <= 64 * 1024 * 1024)
        .ok_or_else(|| Error::capacity("npm research selection exceeds 64 MiB."))?;
    output.push(value);
    Ok(())
}

fn projection_qualified(value: &Value) -> bool {
    value["gaps"].as_array().is_some_and(Vec::is_empty)
}
fn positional_diff(before: &str, after: &str) -> Result<(String, usize)> {
    let start = Instant::now();
    let mut a = before.split_inclusive('\n');
    let mut b = after.split_inclusive('\n');
    let mut output = String::new();
    let mut count = 0;
    for line in 0..=200_000 {
        deadline(start)?;
        let old = a.next();
        let new = b.next();
        if old.is_none() && new.is_none() {
            return Ok((output, count));
        }
        if old != new {
            count += 1;
            output.push_str(&format!("@@ line {} @@\n", line + 1));
            if let Some(old) = old {
                output.push('-');
                output.push_str(old);
                if !old.ends_with('\n') {
                    output.push('\n');
                }
            }
            if let Some(new) = new {
                output.push('+');
                output.push_str(new);
                if !new.ends_with('\n') {
                    output.push('\n');
                }
            }
            if output.len() > 16 * 1024 * 1024 {
                return Err(Error::capacity("npm text comparison exceeds 16 MiB."));
            }
        }
    }
    Err(Error::capacity("npm text comparison exceeds 200000 lines."))
}

pub fn schemas() -> Vec<Value> {
    let text = json!({"type":"string","minLength":1,"maxLength":256});
    let hash = json!({"type":"string","minLength":1,"maxLength":128});
    let mut tools = Vec::new();
    for (name, description, properties, required, text_page) in [
        (
            "npm.versions",
            "List exact captured npm versions in semantic-version order.",
            json!({"name":text}),
            vec!["name"],
            false,
        ),
        (
            "npm.catalog_search",
            "Search captured public npm version metadata with conjunctive filters.",
            json!({"name":text,"version":text,"query":text,"filters":{"type":"object","properties":{"name":text,"license":text,"keyword":text,"deprecated":{"type":"boolean"},"has_types":{"type":"boolean"}},"additionalProperties":false}}),
            vec![],
            false,
        ),
        (
            "npm.document_get",
            "Read captured inert source, manifest, README, license or declaration text.",
            json!({"name":text,"version":text,"path":{"type":"string","maxLength":4096},"representation":{"enum":["text","source","metadata"]}}),
            vec!["name", "version"],
            true,
        ),
        (
            "npm.dependencies",
            "Read declarations or reverse package-name references; no dependency resolution.",
            json!({"name":text,"version":text,"direction":{"enum":["forward","reverse"],"default":"forward"}}),
            vec!["name"],
            false,
        ),
        (
            "npm.compare",
            "Compare captured release metadata, dependency declarations and ordered exports/types contracts.",
            json!({"name":text,"from_version":text,"to_version":text,"path":{"type":"string","maxLength":4096}}),
            vec!["name", "from_version", "to_version"],
            true,
        ),
        (
            "npm.content_search",
            "Search selected captured npm documents using technical or English BM25.",
            json!({"name":text,"version":text,"query":text,"mode":{"enum":["technical","english"]},"filters":{"type":"object","properties":{"name":text,"version":text,"kind":text,"path":text},"additionalProperties":false}}),
            vec!["query"],
            false,
        ),
        (
            "npm.contract_get",
            "Read ordered published exports/imports/types declarations; no JS/TS symbol analysis.",
            json!({"name":text,"version":text}),
            vec!["name", "version"],
            true,
        ),
        (
            "npm.history",
            "Discover permanent package observations with a frozen history cutoff.",
            json!({"name":text,"history_snapshot":{"type":"integer","minimum":0}}),
            vec!["name"],
            false,
        ),
        (
            "npm.snapshots",
            "Discover immutable local npm research and advisory snapshots.",
            json!({"history_snapshot":{"type":"integer","minimum":0},"lane":{"enum":["research","advisories"]}}),
            vec![],
            false,
        ),
        (
            "npm.corpus_status",
            "Inspect aggregate npm collection, storage and projection coverage.",
            json!({}),
            vec![],
            false,
        ),
        (
            "npm.advisory_lookup",
            "Match an exact public npm release against local captured OSV evidence.",
            json!({"name":text,"version":text}),
            vec!["name", "version"],
            false,
        ),
        (
            "npm.advisory_get",
            "Read original captured npm OSV advisory source and attribution.",
            json!({"id":text,"representation":{"enum":["source","metadata"]}}),
            vec!["id"],
            true,
        ),
        (
            "npm.advisory_catalog_search",
            "Search captured npm advisories; withdrawals and coverage remain explicit.",
            json!({"name":text,"query":text,"filters":{"type":"object","properties":{"classification":text,"id":text,"alias":text},"additionalProperties":false}}),
            vec![],
            false,
        ),
    ] {
        let mut properties = properties.as_object().cloned().unwrap_or_default();
        if name != "npm.corpus_status" {
            properties.insert("snapshot".into(), hash.clone());
            properties.insert(
                "offset".into(),
                json!({"type":"integer","minimum":0,"maximum":if text_page{u64::MAX}else{10000}}),
            );
            properties.insert("limit".into(),json!({"type":"integer","minimum":1,"maximum":if text_page{32768}else{100},"default":if text_page{32768}else{20}}));
            if !text_page {
                properties.insert("cursor".into(), json!({"type":"string","maxLength":16384}));
            }
        }
        tools.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}));
    }
    tools
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_keep_the_real_scoped_identity() {
        assert_eq!(alias_target("npm:@scope/real@^1.2.0"), Some("@scope/real"));
        assert_eq!(alias_target("file:thing"), None);
    }
    #[test]
    fn filters_are_conjunctive_and_do_not_claim_engine_compatibility() {
        let row = json!({"name":"demo","version":"1.0.0","manifest":{"license":"MIT","keywords":["parser"],"types":"index.d.ts"}});
        let input: Input = serde_json::from_value(
            json!({"filters":{"license":"MIT","keyword":"parser","has_types":true}}),
        )
        .unwrap();
        assert!(matches_catalog(&row, &input).unwrap());
        let input: Input = serde_json::from_value(json!({"filters":{"engine":"node20"}})).unwrap();
        assert!(matches_catalog(&row, &input).is_err());
    }
}
