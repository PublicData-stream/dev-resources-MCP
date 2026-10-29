//! Local read-only MDN research over immutable public-source snapshots.
use crate::{
    mdn::git::{MdnGit, Repo},
    mdn::index::{MdnIndex, SearchSpec},
    mdn::processing::{ProcessingBudget, resolve_support},
    research::{decode, text_page},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use devres_application::mdn::{MdnStore, Member, Snapshot, View};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{io::AsyncReadExt, sync::Semaphore};
use tokio_util::sync::CancellationToken;

const MAX_MEMBERS: usize = 1_000_000;
const MAX_SCAN: usize = 10_000;
const MAX_TEXT: usize = 4 * 1024 * 1024;
static NORMALIZERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
fn failure() -> Error {
    Error::unavailable("MDN evidence unavailable.")
}
fn integrity() -> Error {
    Error::integrity("Invalid retained MDN evidence.")
}
fn valid_hash(s: &str) -> bool {
    crate::integrity::valid_hash(s)
}
fn from_value<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| integrity())
}
fn default_repository() -> String {
    "content".into()
}
fn default_representation() -> String {
    "text".into()
}
fn default_mode() -> String {
    "technical".into()
}
fn twenty() -> usize {
    20
}
fn text_limit() -> usize {
    32768
}
fn repo(value: &str) -> Result<Repo> {
    match value {
        "content" => Ok(Repo::Content),
        "compat" => Ok(Repo::Compat),
        _ => Err(Error::invalid("MDN repository must be content or compat.")),
    }
}
fn valid_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(Error::invalid("Invalid MDN repository path."));
    }
    Ok(())
}
fn bounded_string(s: &str) -> Result<()> {
    if s.is_empty() || s.chars().count() > 256 || s.chars().any(char::is_control) {
        return Err(Error::invalid("MDN identifier exceeds bounds."));
    }
    Ok(())
}

pub struct MdnResearch {
    store: Arc<dyn MdnStore>,
    root: PathBuf,
    index: MdnIndex,
    content_git: MdnGit,
    compat_git: MdnGit,
    admission: Arc<Semaphore>,
}
struct Selection {
    snapshot: Snapshot,
    compatibility: Option<Snapshot>,
    view: Option<View>,
    historical: bool,
}
impl Selection {
    fn selector(&self) -> &str {
        self.view
            .as_ref()
            .map(|v| v.id.as_str())
            .unwrap_or(&self.snapshot.id)
    }
    fn public(&self) -> Value {
        json!({"snapshot":self.snapshot.id,"revision":self.snapshot.revision,"repository":self.snapshot.repository,"processor_version":self.snapshot.processor_version,"coverage":self.snapshot.coverage,"historical":self.historical,"view":self.view.as_ref().map(|v|&v.id),"compatibility_snapshot":self.compatibility.as_ref().map(|s|&s.id),"validated_at":self.view.as_ref().map(|v|v.validated_at),"stale":self.view.as_ref().map(|v|devres_domain::unix_now().saturating_sub(v.validated_at)>86400)})
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchInput {
    query: Option<String>,
    snapshot: Option<String>,
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "twenty")]
    limit: usize,
    cursor: Option<String>,
    slug: Option<String>,
    path: Option<String>,
    page_type: Option<String>,
    status: Option<String>,
    compatibility_key: Option<String>,
    feature: Option<String>,
    browser: Option<String>,
    experimental: Option<bool>,
    deprecated: Option<bool>,
    standard_track: Option<bool>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetInput {
    slug: Option<String>,
    path: Option<String>,
    snapshot: Option<String>,
    compatibility_snapshot: Option<String>,
    #[serde(default = "default_repository")]
    repository: String,
    #[serde(default = "default_representation")]
    representation: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "text_limit")]
    limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatInput {
    feature: String,
    snapshot: Option<String>,
    browser: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "twenty")]
    limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserInput {
    browser: String,
    snapshot: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "twenty")]
    limit: usize,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct DiscoveryInput {
    #[serde(default = "default_repository")]
    repository: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "twenty")]
    limit: usize,
    cursor: Option<String>,
    history_snapshot: Option<i64>,
    path: Option<String>,
    slug: Option<String>,
    feature: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
    representation: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    #[serde(default)]
    version: u8,
    fingerprint: String,
    cutoff: i64,
    after: i64,
    position: usize,
    #[serde(default)]
    remaining_offset: usize,
}

impl MdnResearch {
    pub(crate) fn for_verification(store: Arc<dyn MdnStore>, root: &Path) -> Result<Self> {
        Ok(Self {
            store,
            root: root.into(),
            index: MdnIndex::for_verification(root)?,
            content_git: MdnGit::for_verification(
                root,
                Repo::Content,
                8 * 1024 * 1024 * 1024,
                64 * 1024 * 1024,
            )?,
            compat_git: MdnGit::for_verification(
                root,
                Repo::Compat,
                8 * 1024 * 1024 * 1024,
                64 * 1024 * 1024,
            )?,
            admission: Arc::new(Semaphore::new(2)),
        })
    }
    pub fn new(store: Arc<dyn MdnStore>, root: &Path) -> Result<Self> {
        Ok(Self {
            store,
            root: std::fs::canonicalize(root).map_err(|_| failure())?,
            index: MdnIndex::new(root)?,
            content_git: MdnGit::new(
                root,
                Repo::Content,
                8 * 1024 * 1024 * 1024,
                64 * 1024 * 1024,
                None,
            )?,
            compat_git: MdnGit::new(
                root,
                Repo::Compat,
                8 * 1024 * 1024 * 1024,
                64 * 1024 * 1024,
                None,
            )?,
            admission: Arc::new(Semaphore::new(2)),
        })
    }
    pub async fn call(&self, tool: &str, input: Value) -> Result<Value> {
        let _permit = self
            .admission
            .try_acquire()
            .map_err(|_| Error::capacity("MDN research reader capacity exhausted."))?;
        match tool {
            "mdn.search" => self.search(decode(input)?, false).await,
            "mdn.compat_search" => self.search(decode(input)?, true).await,
            "mdn.get" => self.get(decode(input)?).await,
            "mdn.compat_get" => self.compat_get(decode(input)?).await,
            "mdn.browser_get" => self.browser_get(decode(input)?).await,
            "mdn.history" => self.discovery(decode(input)?, true).await,
            "mdn.snapshots" => self.discovery(decode(input)?, false).await,
            "mdn.corpus_status" => {
                let _: Empty = decode(input)?;
                let status = self
                    .store
                    .mdn_state("status")
                    .await?
                    .unwrap_or_else(|| json!({"available":false,"bootstrap":true}));
                Ok(status)
            }
            _ => Err(Error::not_found("Unknown MDN tool.")),
        }
    }
    async fn snapshot(&self, id: &str, repository: &str) -> Result<Snapshot> {
        if !valid_hash(id) {
            return Err(Error::invalid("Invalid MDN snapshot identifier."));
        }
        let row = self
            .store
            .mdn_get("snapshots", id)
            .await?
            .ok_or_else(|| Error::not_found("MDN snapshot not found."))?;
        let snapshot: Snapshot = from_value(row.data)?;
        if snapshot.id != id || snapshot.repository != repository {
            return Err(Error::invalid(
                "MDN snapshot belongs to another repository.",
            ));
        }
        Ok(snapshot)
    }
    async fn select(
        &self,
        selector: Option<&str>,
        repository: &str,
        compat_selector: Option<&str>,
    ) -> Result<Selection> {
        repo(repository)?;
        if repository == "compat" && compat_selector.is_some() {
            return Err(Error::invalid(
                "Compatibility enrichment applies only to MDN content.",
            ));
        }
        let historical = selector.is_some();
        let selected = match selector {
            Some(id) => id.to_owned(),
            None => self
                .store
                .mdn_state("default-view")
                .await?
                .and_then(|v| v.as_str().map(str::to_owned))
                .ok_or_else(|| Error::unavailable("MDN current view has not been published."))?,
        };
        if !valid_hash(&selected) {
            return Err(Error::invalid("Invalid MDN snapshot identifier."));
        }
        if let Some(row) = self.store.mdn_get("views", &selected).await? {
            let view: View = from_value(row.data)?;
            if view.id != selected {
                return Err(integrity());
            }
            if !historical {
                let age = devres_domain::unix_now()
                    .checked_sub(view.validated_at)
                    .filter(|n| *n >= 0)
                    .ok_or_else(failure)?;
                if age > 7 * 86400 {
                    return Err(Error::unavailable(
                        "MDN default view has not been validated within seven days.",
                    ));
                }
            }
            let snapshot = self
                .snapshot(
                    if repository == "content" {
                        &view.content
                    } else {
                        &view.compatibility
                    },
                    repository,
                )
                .await?;
            let compatibility = if repository == "content" {
                Some(
                    self.snapshot(compat_selector.unwrap_or(&view.compatibility), "compat")
                        .await?,
                )
            } else {
                None
            };
            return Ok(Selection {
                snapshot,
                compatibility,
                view: Some(view),
                historical,
            });
        }
        let snapshot = self.snapshot(&selected, repository).await?;
        let compatibility = if repository == "content" {
            match compat_selector {
                Some(id) => Some(self.snapshot(id, "compat").await?),
                None => None,
            }
        } else {
            None
        };
        Ok(Selection {
            snapshot,
            compatibility,
            view: None,
            historical: true,
        })
    }
    async fn all_members(&self, snapshot: &Snapshot) -> Result<Vec<Member>> {
        crate::mdn::inventory::members(self.store.as_ref(), &snapshot.inventory, MAX_MEMBERS).await
    }
    async fn projection(&self, member: &Member) -> Result<Option<Value>> {
        match &member.projection {
            Some(id) => Ok(Some(
                self.store
                    .mdn_get("projections", id)
                    .await?
                    .ok_or_else(integrity)?
                    .data,
            )),
            None => Ok(None),
        }
    }
    async fn search(&self, input: SearchInput, compat: bool) -> Result<Value> {
        if input.limit == 0 || input.limit > 100 || input.offset > 10_000 {
            return Err(Error::invalid(
                "MDN search limit must be 1..100 and offset at most 10000.",
            ));
        }
        let selection = self
            .select(
                input.snapshot.as_deref(),
                if compat { "compat" } else { "content" },
                None,
            )
            .await?;
        let members = self.all_members(&selection.snapshot).await?;
        let ids = members
            .into_iter()
            .filter(|m| m.kind == if compat { "feature" } else { "article" })
            .filter(|m| !m.gaps.iter().any(|g| g == "search_index_gap"))
            .filter_map(|m| m.projection)
            .collect();
        let mut filters = BTreeMap::new();
        filters.insert(
            "kind".into(),
            if compat { "feature" } else { "article" }.into(),
        );
        for (key, value) in [
            ("slug", input.slug),
            ("path", input.path),
            ("page_type", input.page_type),
            ("status", input.status),
            ("compatibility_key", input.compatibility_key),
            ("feature", input.feature),
            ("browser", input.browser),
        ] {
            if let Some(value) = value {
                filters.insert(key.into(), value);
            }
        }
        for (key, value) in [
            ("experimental", input.experimental),
            ("deprecated", input.deprecated),
            ("standard_track", input.standard_track),
        ] {
            if let Some(value) = value {
                filters.insert(key.into(), value.to_string());
            }
        }
        let spec = SearchSpec {
            query: input.query,
            snapshot: Some(selection.selector().to_owned()),
            mode: input.mode,
            filters,
            offset: input.offset,
            limit: input.limit,
            cursor: input.cursor,
        };
        let mut result = self
            .index
            .search(
                &selection.snapshot.index,
                ids,
                spec,
                CancellationToken::new(),
            )
            .await?;
        result["provenance"] = selection.public();
        result["snapshot"] = json!(selection.selector());
        if let Some(rows) = result["results"].as_array_mut() {
            for row in rows {
                if let Some(path) = row["path"].as_str() {
                    row["resource_uri"] = json!(resource_uri(
                        &selection.snapshot.repository,
                        &selection.snapshot.id,
                        "source",
                        path,
                        None
                    ));
                }
            }
        }
        Ok(result)
    }
    async fn find_member(
        &self,
        snapshot: &Snapshot,
        path: Option<&str>,
        slug: Option<&str>,
    ) -> Result<(Member, Vec<Value>)> {
        if let Some(path) = path {
            valid_path(path)?;
            let member = crate::mdn::inventory::get(self.store.as_ref(), &snapshot.inventory, path)
                .await?
                .ok_or_else(|| Error::not_found("MDN source path not found in this snapshot."))?;
            return Ok((member, Vec::new()));
        }
        let mut wanted = slug
            .ok_or_else(|| Error::invalid("Select exactly one MDN slug or path."))?
            .to_owned();
        if wanted.is_empty() || wanted.len() > 4096 || wanted.chars().any(char::is_control) {
            return Err(Error::invalid("Invalid MDN slug."));
        }
        let members = self.all_members(snapshot).await?;
        let mut redirects = BTreeMap::new();
        let mut articles = BTreeMap::<String, Vec<Member>>::new();
        for chunk in members.chunks(500) {
            let keys: Vec<_> = chunk
                .iter()
                .filter(|m| matches!(m.kind.as_str(), "article" | "redirects"))
                .filter_map(|m| m.projection.clone())
                .collect();
            let rows = self.store.mdn_get_many("projection-headers", &keys).await?;
            let by_key: BTreeMap<_, _> = rows.into_iter().map(|r| (r.key, r.data)).collect();
            for member in chunk {
                if let Some(id) = &member.projection
                    && let Some(projection) = by_key.get(id)
                {
                    if member.kind == "article" {
                        if let Some(slug) = projection["slug"].as_str() {
                            articles
                                .entry(slug.to_owned())
                                .or_default()
                                .push(member.clone());
                        }
                    } else if member.kind == "redirects"
                        && let Some(rows) = projection["redirects"].as_array()
                    {
                        for row in rows {
                            if let (Some(from), Some(to)) =
                                (row["from"].as_str(), row["to"].as_str())
                            {
                                redirects.insert(normalize_slug(from), normalize_slug(to));
                            }
                        }
                    }
                }
            }
        }
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        for _ in 0..=8 {
            if !seen.insert(wanted.clone()) {
                return Err(Error::integrity("MDN redirect cycle."));
            }
            if let Some(found) = articles.get(&wanted) {
                if found.len() != 1 {
                    return Err(Error::integrity("Ambiguous MDN slug in snapshot."));
                }
                return Ok((found[0].clone(), chain));
            }
            let Some(next) = redirects.get(&wanted) else {
                return Err(Error::not_found("MDN slug not found in this snapshot."));
            };
            if chain.len() >= 8 {
                return Err(Error::capacity("MDN redirect chain exceeds limit."));
            }
            chain.push(json!({"from":wanted,"to":next}));
            wanted = next.clone();
        }
        Err(integrity())
    }
    async fn get(&self, input: GetInput) -> Result<Value> {
        if input.repository == "compat" && input.slug.is_some() {
            return Err(Error::invalid(
                "MDN slugs select content; use a repository path for compatibility source.",
            ));
        }
        if input.slug.is_some() == input.path.is_some() {
            return Err(Error::invalid("Select exactly one MDN slug or path."));
        }
        if input.limit == 0 || input.limit > 32768 {
            return Err(Error::invalid("MDN text limit must be 1..32768."));
        }
        if !["text", "source", "bytes"].contains(&input.representation.as_str()) {
            return Err(Error::invalid(
                "MDN representation must be text, source, or bytes.",
            ));
        }
        let selection = self
            .select(
                input.snapshot.as_deref(),
                &input.repository,
                input.compatibility_snapshot.as_deref(),
            )
            .await?;
        let (member, redirects) = self
            .find_member(
                &selection.snapshot,
                input.path.as_deref(),
                input.slug.as_deref(),
            )
            .await?;
        let projection = self.projection(&member).await?;
        let mut result = json!({"snapshot":selection.selector(),"provenance":selection.public(),"path":member.path,"oid":member.oid,"kind":member.kind,"gaps":member.gaps,"redirects":redirects,"representation":input.representation,"source_url":source_url(&selection.snapshot,member.raw.as_ref().and_then(|r|r["source_path"].as_str()).unwrap_or(&member.path)),"license":license(&selection.snapshot),"resource_uri":resource_uri(&selection.snapshot.repository,&selection.snapshot.id,&input.representation,&member.path,selection.compatibility.as_ref().map(|s|s.id.as_str()))});
        if member
            .raw
            .as_ref()
            .is_some_and(|r| r["raw_path_hex"].is_string())
        {
            result["source_url"] = Value::Null;
            result["source_path_hex"] = member
                .raw
                .as_ref()
                .map(|r| r["raw_path_hex"].clone())
                .unwrap_or(Value::Null);
        }
        if input.representation == "text" {
            let projection = projection.ok_or_else(|| {
                Error::unavailable(
                    "MDN text projection is unavailable; original source remains retained.",
                )
            })?;
            let text = projection["text"].as_str().ok_or_else(|| {
                Error::unavailable(
                    "This MDN member has no text projection; request original source.",
                )
            })?;
            let mut rendered_text = text.to_owned();
            let mut metadata = projection.clone();
            if let Some(object) = metadata.as_object_mut() {
                object.remove("text");
                // Generation 3 shares normalized articles across source-only edits.
                // Their public source identity belongs to the selected member.
                if selection.snapshot.processor_version >= 3 && member.kind == "article" {
                    object.insert("source_oid".into(), json!(member.oid));
                }
            }
            result["document"] = metadata;
            if let Some(compat) = &selection.compatibility
                && let Some(keys) = projection["compatibility_keys"].as_array()
            {
                let mut compatibility = Vec::new();
                let mut attachment_bytes = 0usize;
                for key in keys.iter().take(100) {
                    if let Some(feature) = key.as_str() {
                        let value = match self.compat_record(compat, feature, None).await {
                            Ok(value) => value,
                            Err(error) if error.code == "not_found" => {
                                json!({"feature":feature,"gap":"feature_not_in_selected_compatibility_snapshot"})
                            }
                            Err(error) => return Err(error),
                        };
                        append_compatibility(&mut rendered_text, &value)?;
                        let bytes = serde_json::to_vec(&value).map_err(|_| integrity())?.len();
                        if attachment_bytes.saturating_add(bytes) <= 64 * 1024 {
                            attachment_bytes += bytes;
                            compatibility.push(value);
                        } else {
                            compatibility.push(json!({"feature":feature,"snapshot":compat.id,"resource_uri":resource_uri("compat",&compat.id,"feature",feature,None),"gap":"read_full_structured_evidence_with_mdn_compat_get"}));
                        }
                    }
                }
                result["compatibility"] = json!(compatibility);
                if keys.len() > 100 {
                    result["compatibility_page"] = json!({"returned":100,"total":keys.len(),"gap":"use_mdn_compat_get_for_remaining_features"});
                }
            }
            result["page"] = text_page(&rendered_text, input.offset, input.limit)?;
        } else {
            result["page"] = self
                .raw_page(
                    &member,
                    input.offset,
                    input.limit,
                    input.representation == "bytes",
                )
                .await?;
        }
        Ok(result)
    }
    async fn raw_page(
        &self,
        member: &Member,
        offset: usize,
        limit: usize,
        bytes_only: bool,
    ) -> Result<Value> {
        let raw = member
            .raw
            .as_ref()
            .ok_or_else(|| Error::unavailable("MDN original member is not a blob."))?;
        if raw["git"] == true {
            let repository = raw["repository"].as_str().ok_or_else(integrity)?;
            let git = match repo(repository)? {
                Repo::Content => &self.content_git,
                Repo::Compat => &self.compat_git,
            };
            let oid = raw["oid"].as_str().unwrap_or(&member.oid);
            let page = git
                .blob_page(oid, offset as u64, limit, CancellationToken::new())
                .await?;
            return Ok(
                json!({"data":STANDARD.encode(&page.bytes),"encoding":"base64","offset":offset,"next_offset":if (offset as u64)+(page.bytes.len()as u64)<page.total_bytes{Some(offset+page.bytes.len())}else{None},"total_bytes":page.total_bytes,"body_hash":page.body_hash}),
            );
        }
        let expected = raw["body_hash"]
            .as_str()
            .filter(|s| valid_hash(s))
            .ok_or_else(integrity)?;
        let relative = raw["relative_path"].as_str().ok_or_else(integrity)?;
        if relative
            != format!(
                "mdn/raw-artifacts/{}",
                crate::integrity::relative_path(expected)?.display()
            )
        {
            return Err(integrity());
        }
        let path = self.root.join(relative);
        if !expected.starts_with("blake3:") {
            let legacy_path = path.clone();
            tokio::task::spawn_blocking(move || {
                crate::integrity::verify_legacy_file(
                    &legacy_path,
                    std::time::Instant::now() + Duration::from_secs(15),
                )
            })
            .await
            .map_err(|_| failure())??;
        }
        let meta = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|_| failure())?;
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.len() != raw["bytes"].as_u64().ok_or_else(integrity)?
            || meta.len() > 32 * 1024 * 1024 * 1024
        {
            return Err(integrity());
        }
        if offset as u64 > meta.len() {
            return Err(Error::invalid("MDN source offset exceeds its length."));
        }
        let expected = expected.to_owned();
        let textual = !bytes_only && meta.len() <= MAX_TEXT as u64;
        let total = meta.len();
        let operation = async {
            let mut file = tokio::fs::File::open(path).await.map_err(|_| failure())?;
            let mut hash = Sha256::new();
            let mut blake3_hash = blake3::Hasher::new();
            let mut buffer = vec![0u8; 65536];
            let mut position = 0u64;
            let mut selected = Vec::new();
            let mut text = Vec::new();
            loop {
                let n = file.read(&mut buffer).await.map_err(|_| failure())?;
                if n == 0 {
                    break;
                }
                hash.update(&buffer[..n]);
                blake3_hash.update(&buffer[..n]);
                if textual {
                    text.extend_from_slice(&buffer[..n]);
                } else {
                    let start = (offset as u64).saturating_sub(position).min(n as u64) as usize;
                    let end = (offset as u64)
                        .saturating_add(limit as u64)
                        .saturating_sub(position)
                        .min(n as u64) as usize;
                    if end > start {
                        selected.extend_from_slice(&buffer[start..end]);
                    }
                }
                position = position.saturating_add(n as u64);
                if position > total {
                    return Err(integrity());
                }
            }
            let observed = if expected.starts_with("blake3:") {
                format!("blake3:{}", blake3_hash.finalize().to_hex())
            } else {
                hex::encode(hash.finalize())
            };
            if position != total || observed != expected {
                return Err(integrity());
            }
            if textual && let Ok(text) = std::str::from_utf8(&text) {
                let mut page = text_page(text, offset, limit)?;
                page["body_hash"] = json!(expected);
                page["encoding"] = json!("utf-8");
                Ok(page)
            } else {
                if textual {
                    selected = text
                        .get(offset..offset.saturating_add(limit).min(text.len()))
                        .ok_or_else(integrity)?
                        .to_vec();
                }
                Ok(
                    json!({"data":STANDARD.encode(&selected),"encoding":"base64","offset":offset,"next_offset":if (offset as u64)+(selected.len()as u64)<total{Some(offset+selected.len())}else{None},"total_bytes":total,"body_hash":expected}),
                )
            }
        };
        tokio::time::timeout(Duration::from_secs(15), operation)
            .await
            .map_err(|_| Error::capacity("MDN raw-source verification deadline exceeded."))?
    }
    async fn compat_record(
        &self,
        snapshot: &Snapshot,
        feature: &str,
        browser: Option<&str>,
    ) -> Result<Value> {
        if feature.is_empty() || feature.len() > 4096 || feature.chars().any(char::is_control) {
            return Err(Error::invalid("Invalid MDN feature identifier."));
        }
        if let Some(browser) = browser {
            bounded_string(browser)?;
        }
        let path = format!("@features/{feature}");
        let member = crate::mdn::inventory::get(self.store.as_ref(), &snapshot.inventory, &path)
            .await?
            .ok_or_else(|| Error::not_found("MDN compatibility feature not found."))?;
        let record = self.projection(&member).await?.ok_or_else(integrity)?;
        if record["key"] != feature {
            return Err(integrity());
        }
        let mut browsers = BTreeMap::new();
        let browser_members = match crate::mdn::inventory::subtree(
            self.store.as_ref(),
            &snapshot.inventory,
            "@browsers",
        )
        .await?
        {
            Some(id) => crate::mdn::inventory::members(self.store.as_ref(), &id, 1000).await?,
            None => Vec::new(),
        };
        for member in browser_members.into_iter().filter(|m| m.kind == "browser") {
            let value = self.projection(&member).await?.ok_or_else(integrity)?;
            let key = value["key"].as_str().ok_or_else(integrity)?.to_owned();
            browsers.insert(key, value["data"].clone());
        }
        let feature_data = record["data"].clone();
        let permit = NORMALIZERS
            .get_or_init(|| Arc::new(Semaphore::new(2)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::capacity("MDN compatibility worker capacity exhausted."))?;
        let cancel = CancellationToken::new();
        let _guard = CancelOnDrop(cancel.clone());
        let resolved = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            resolve_support(&feature_data, &browsers, &ProcessingBudget::new(cancel))
        })
        .await
        .map_err(|_| failure())??;
        let mut result = json!({"feature":feature,"snapshot":snapshot.id,"revision":snapshot.revision,"metadata":record["data"].as_object().map(|v|v.iter().filter(|(key,_)|key.as_str()!="support").map(|(k,v)|(k.clone(),v.clone())).collect::<serde_json::Map<String,Value>>()),"original":resolved.original,"resolved":resolved.resolved,"gaps":resolved.gaps,"source_path":member.raw.as_ref().and_then(|r|r["source_path"].as_str()),"source_url":source_url(snapshot,member.raw.as_ref().and_then(|r|r["source_path"].as_str()).unwrap_or(&member.path)),"license":license(snapshot),"resource_uri":resource_uri("compat",&snapshot.id,"feature",feature,None)});
        if let Some(browser) = browser {
            let original = result["original"].get(browser).cloned();
            if original.is_none()
                && let Some(gaps) = result["gaps"].as_array_mut()
            {
                gaps.push(json!({"code":"browser_support_unknown","detail":browser}));
            }
            let resolved = result["resolved"].get(browser).cloned();
            result["original"] = json!({(browser):original});
            result["resolved"] = json!({(browser):resolved});
            result["browser"] = json!(browser);
        }
        Ok(result)
    }
    async fn compat_get(&self, input: CompatInput) -> Result<Value> {
        if input.limit == 0 || input.limit > 100 || input.offset > 10000 {
            return Err(Error::invalid("Invalid MDN compatibility page."));
        }
        let selection = self
            .select(input.snapshot.as_deref(), "compat", None)
            .await?;
        let mut result = self
            .compat_record(
                &selection.snapshot,
                &input.feature,
                input.browser.as_deref(),
            )
            .await?;
        result["provenance"] = selection.public();
        result["snapshot"] = json!(selection.selector());
        let Some(original) = result["original"].as_object() else {
            result["paging_supported"] = json!(false);
            result["total"] = Value::Null;
            result["next_offset"] = Value::Null;
            return Ok(result);
        };
        let keys: Vec<_> = original.keys().cloned().collect();
        let selected: BTreeSet<_> = keys
            .iter()
            .skip(input.offset)
            .take(input.limit)
            .cloned()
            .collect();
        for field in ["original", "resolved"] {
            if let Some(object) = result[field].as_object_mut() {
                object.retain(|key, _| selected.contains(key));
            }
        }
        result["total"] = json!(keys.len());
        result["offset"] = json!(input.offset);
        result["next_offset"] = json!(if input.offset.saturating_add(input.limit) < keys.len() {
            Some(input.offset + input.limit)
        } else {
            None
        });
        Ok(result)
    }
    async fn browser_get(&self, input: BrowserInput) -> Result<Value> {
        bounded_string(&input.browser)?;
        if input.limit == 0 || input.limit > 100 || input.offset > 10000 {
            return Err(Error::invalid("Invalid MDN browser page."));
        }
        let selection = self
            .select(input.snapshot.as_deref(), "compat", None)
            .await?;
        let member = crate::mdn::inventory::get(
            self.store.as_ref(),
            &selection.snapshot.inventory,
            &format!("@browsers/{}", input.browser),
        )
        .await?
        .ok_or_else(|| Error::not_found("MDN browser not found."))?;
        let value = self.projection(&member).await?.ok_or_else(integrity)?;
        let mut metadata = value["data"].clone();
        let releases = metadata
            .as_object_mut()
            .ok_or_else(integrity)?
            .remove("releases")
            .unwrap_or_else(|| json!({}));
        let releases = releases.as_object().ok_or_else(integrity)?;
        let rows: Vec<_> = releases
            .iter()
            .skip(input.offset)
            .take(input.limit)
            .map(|(version, data)| json!({"version":version,"data":data}))
            .collect();
        Ok(
            json!({"snapshot":selection.selector(),"browser":input.browser,"metadata":metadata,"releases":rows,"total":releases.len(),"offset":input.offset,"next_offset":if input.offset+input.limit<releases.len(){Some(input.offset+input.limit)}else{None},"provenance":selection.public(),"license":license(&selection.snapshot),"resource_uri":resource_uri("compat",&selection.snapshot.id,"browser",&input.browser,None)}),
        )
    }
    async fn discovery(&self, input: DiscoveryInput, history: bool) -> Result<Value> {
        repo(&input.repository)?;
        if input.limit == 0 || input.limit > 100 || input.offset > 10000 {
            return Err(Error::invalid("Invalid MDN discovery page."));
        }
        let selected = [
            input.path.is_some(),
            input.slug.is_some(),
            input.feature.is_some(),
        ]
        .iter()
        .filter(|v| **v)
        .count();
        if history && input.feature.is_some() && input.repository != "compat" {
            return Err(Error::invalid(
                "Feature history requires repository=compat.",
            ));
        }
        if history && input.slug.is_some() && input.repository != "content" {
            return Err(Error::invalid("Slug history requires repository=content."));
        }
        if history && selected != 1 {
            return Err(Error::invalid(
                "MDN history requires exactly one path, slug, or feature.",
            ));
        }
        if !history && selected != 0 {
            return Err(Error::invalid(
                "MDN snapshot discovery does not accept member filters.",
            ));
        }
        if let Some(path) = &input.path {
            valid_path(path)?;
        }
        for value in [input.feature.as_deref(), input.reference.as_deref()]
            .into_iter()
            .flatten()
        {
            bounded_string(value)?;
        }
        if let Some(slug) = &input.slug
            && (slug.is_empty() || slug.len() > 4096 || slug.chars().any(char::is_control))
        {
            return Err(Error::invalid("Invalid MDN history slug."));
        }
        let representation = input.representation.as_deref().unwrap_or("commits");
        if !["commits", "refs"].contains(&representation) || history && input.reference.is_some() {
            return Err(Error::invalid("Invalid MDN history/discovery selector."));
        }
        if !history && representation == "commits" && input.reference.is_some() {
            return Err(Error::invalid(
                "An exact ref filter selects representation=refs.",
            ));
        }
        let mut normalized = input.clone();
        normalized.cursor = None;
        normalized.offset = 0;
        normalized.limit = 0;
        normalized.history_snapshot = None;
        let identity = serde_json::to_vec(&(history, &normalized)).map_err(|_| integrity())?;
        let version = match input.cursor.as_deref() {
            Some(encoded) if encoded.len() <= 16_384 => {
                serde_json::from_str::<Cursor>(encoded)
                    .map_err(|_| Error::invalid("Malformed MDN discovery cursor."))?
                    .version
            }
            Some(_) => return Err(Error::invalid("MDN cursor exceeds its bound.")),
            None => 2,
        };
        let fingerprint = match version {
            0 => crate::integrity::legacy_hash(&identity),
            2 => crate::integrity::hash(&identity),
            _ => return Err(Error::invalid("Unsupported MDN cursor version.")),
        };
        let (cutoff, mut after, mut position, offset_to_skip) = if let Some(cursor) = &input.cursor
        {
            if cursor.len() > 16384 || input.offset != 0 {
                return Err(Error::invalid("Invalid MDN discovery cursor."));
            }
            let c: Cursor = serde_json::from_str(cursor)
                .map_err(|_| Error::invalid("Malformed MDN discovery cursor."))?;
            if c.fingerprint != fingerprint
                || c.cutoff < 0
                || c.after < 0
                || input.history_snapshot.is_some_and(|v| v != c.cutoff)
            {
                return Err(Error::invalid(
                    "MDN discovery cursor belongs to another query.",
                ));
            }
            (c.cutoff, c.after, c.position, c.remaining_offset)
        } else {
            let cutoff = match input.history_snapshot {
                Some(n) if n >= 0 => n,
                Some(_) => return Err(Error::invalid("Invalid MDN history cutoff.")),
                None => self.store.mdn_cutoff().await?,
            };
            (cutoff, 0, 0, input.offset)
        };
        let kind = if history {
            "changes"
        } else if representation == "refs" {
            "observations"
        } else {
            "snapshots"
        };
        let mut results = Vec::new();
        let mut skipped = 0usize;
        let mut scanned = 0usize;
        let mut more = false;
        'scan: loop {
            let rows = self.store.mdn_rows(kind, after, 100, Some(cutoff)).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                scanned += 1;
                if row.data["repository"]
                    .as_str()
                    .or_else(|| row.data["repo"].as_str())
                    != Some(&input.repository)
                {
                    after = row.sequence;
                    position = 0;
                    continue;
                }
                let values = if !history && representation == "refs" {
                    row.data["refs"].as_array().ok_or_else(integrity)?.iter().map(|reference|json!({"observation":row.key,"observed_at":row.data["observed_at"],"ref":reference})).collect::<Vec<_>>()
                } else {
                    vec![row.data.clone()]
                };
                for (i, mut value) in values.into_iter().enumerate().skip(position) {
                    if history && value.get("processor_version").is_none() {
                        value["processor_version"] = json!(change_generation(&value, &row.key)?);
                    }
                    let matched = if history {
                        history_matches(&input, &value)
                    } else {
                        input
                            .reference
                            .as_ref()
                            .is_none_or(|wanted| value["ref"]["name"].as_str() == Some(wanted))
                    };
                    if matched {
                        if skipped < offset_to_skip {
                            skipped += 1;
                        } else if results.len() < input.limit {
                            let mut value = value;
                            if let Some(object) = value.as_object_mut() {
                                object.insert("sequence".into(), json!(row.sequence));
                            }
                            results.push(value);
                        } else {
                            more = true;
                            position = i;
                            break 'scan;
                        }
                    }
                }
                after = row.sequence;
                position = 0;
                if scanned >= MAX_SCAN {
                    more = true;
                    break 'scan;
                }
            }
        }
        let next_cursor = if more {
            Some(
                serde_json::to_string(&Cursor {
                    version,
                    fingerprint,
                    cutoff,
                    after,
                    position,
                    remaining_offset: offset_to_skip.saturating_sub(skipped),
                })
                .map_err(|_| integrity())?,
            )
        } else {
            None
        };
        Ok(
            json!({"results":results,"history_snapshot":cutoff,"next_cursor":next_cursor,"scan_complete":!more,"scanned":scanned,"repository":input.repository,"history_scope":"published_evidence_at_frozen_cutoff","corpus_status":self.store.mdn_state("status").await?}),
        )
    }
    pub async fn read_resource(&self, uri: &str) -> Result<Value> {
        let _permit = self
            .admission
            .try_acquire()
            .map_err(|_| Error::capacity("MDN research reader capacity exhausted."))?;
        if uri.len() > 16384 {
            return Err(Error::invalid("MDN resource URI exceeds limit."));
        }
        let url = url::Url::parse(uri).map_err(|_| Error::invalid("Invalid MDN resource URI."))?;
        if url.scheme() != "devres"
            || url.host_str() != Some("mdn")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::invalid("Invalid MDN resource URI."));
        }
        let parts: Vec<_> = url.path().trim_start_matches('/').split('/').collect();
        if parts.len() != 4 {
            return Err(Error::invalid("Invalid MDN resource identity."));
        }
        repo(parts[0])?;
        if !valid_hash(parts[1]) {
            return Err(Error::invalid("Invalid MDN resource snapshot."));
        }
        let identity = String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(parts[3])
                .map_err(|_| Error::invalid("Invalid MDN resource identity."))?,
        )
        .map_err(|_| Error::invalid("Invalid MDN resource identity."))?;
        let mut offset = 0usize;
        let mut limit = None;
        let mut compatibility_snapshot = None;
        let mut seen = BTreeSet::new();
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string()) {
                return Err(Error::invalid("Duplicate MDN resource parameter."));
            }
            match key.as_ref() {
                "offset" => {
                    offset = value
                        .parse()
                        .map_err(|_| Error::invalid("Invalid MDN resource offset."))?
                }
                "limit" => {
                    limit = Some(
                        value
                            .parse()
                            .map_err(|_| Error::invalid("Invalid MDN resource limit."))?,
                    )
                }
                "compatibility_snapshot" => compatibility_snapshot = Some(value.into_owned()),
                _ => return Err(Error::invalid("Unknown MDN resource parameter.")),
            }
        }
        let output = match parts[2] {
            "feature" if parts[0] == "compat" => {
                self.compat_get(CompatInput {
                    feature: identity,
                    snapshot: Some(parts[1].into()),
                    browser: None,
                    offset,
                    limit: limit.unwrap_or(20),
                })
                .await?
            }
            "browser" if parts[0] == "compat" => {
                self.browser_get(BrowserInput {
                    browser: identity,
                    snapshot: Some(parts[1].into()),
                    offset,
                    limit: limit.unwrap_or(20),
                })
                .await?
            }
            "source" | "text" | "bytes" => {
                self.get(GetInput {
                    slug: None,
                    path: Some(identity),
                    snapshot: Some(parts[1].into()),
                    compatibility_snapshot,
                    repository: parts[0].into(),
                    representation: parts[2].into(),
                    offset,
                    limit: limit.unwrap_or(32768),
                })
                .await?
            }
            _ => return Err(Error::invalid("Invalid MDN resource representation.")),
        };
        if let Some(text) = output["page"]["text"].as_str() {
            Ok(
                json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":text,"_meta":{"provenance":output["provenance"],"source_url":output["source_url"],"license":output["license"],"gaps":output["gaps"]}}]}),
            )
        } else if let Some(bytes) = output["page"]["data"].as_str() {
            Ok(
                json!({"contents":[{"uri":uri,"mimeType":"application/octet-stream","blob":bytes,"_meta":{"provenance":output["provenance"],"source_url":output["source_url"],"license":output["license"],"gaps":output["gaps"]}}]}),
            )
        } else {
            Ok(
                json!({"contents":[{"uri":uri,"mimeType":"application/json","text":serde_json::to_string(&output).map_err(|_|integrity())?}]}),
            )
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
fn append_compatibility(text: &mut String, value: &Value) -> Result<()> {
    let feature = value["feature"].as_str().unwrap_or("unknown");
    text.push_str("\n\nCaptured browser compatibility: ");
    text.push_str(feature);
    text.push('\n');
    if let Some(snapshot) = value["snapshot"].as_str() {
        text.push_str("Compatibility snapshot: ");
        text.push_str(snapshot);
        text.push('\n');
    }
    if let Some(statements) = value["resolved"].as_object() {
        for (browser, statement) in statements {
            text.push_str(browser);
            text.push_str(": ");
            text.push_str(&serde_json::to_string(statement).map_err(|_| integrity())?);
            text.push('\n');
            if text.len() > MAX_TEXT {
                return Err(Error::capacity(
                    "Joined MDN text exceeds the 4 MiB projection bound.",
                ));
            }
        }
    } else if let Some(gap) = value["gap"].as_str() {
        text.push_str("Coverage gap: ");
        text.push_str(gap);
        text.push('\n');
    }
    if value["gaps"].as_array().is_some_and(|v| !v.is_empty()) {
        text.push_str("Mirror coverage gaps: ");
        text.push_str(&serde_json::to_string(&value["gaps"]).map_err(|_| integrity())?);
        text.push('\n');
    }
    if text.len() > MAX_TEXT {
        return Err(Error::capacity(
            "Joined MDN text exceeds the 4 MiB projection bound.",
        ));
    }
    Ok(())
}
fn normalize_slug(value: &str) -> String {
    value
        .strip_prefix("/en-US/docs/")
        .or_else(|| value.strip_prefix("/en-us/docs/"))
        .or_else(|| value.strip_prefix("/docs/"))
        .unwrap_or(value)
        .to_owned()
}
fn history_matches(input: &DiscoveryInput, value: &Value) -> bool {
    input
        .path
        .as_ref()
        .is_none_or(|path| value["path"].as_str() == Some(path))
        && input.slug.as_ref().is_none_or(|slug| {
            value["slug"].as_str() == Some(slug)
                || value["before_slug"].as_str() == Some(slug)
                || value["after_slug"].as_str() == Some(slug)
                || value["slugs"]
                    .as_array()
                    .is_some_and(|slugs| slugs.iter().any(|s| s.as_str() == Some(slug)))
        })
        && input.feature.as_ref().is_none_or(|feature| {
            value["feature"].as_str() == Some(feature)
                || value["path"].as_str() == Some(format!("@features/{feature}").as_str())
        })
}
fn change_generation(data: &Value, key: &str) -> Result<Option<u32>> {
    for generation in 1..=devres_application::mdn::PROCESSOR_VERSION {
        let identity = json!([
            data["repository"],
            data["revision"],
            data["parent"],
            data["parent_index"],
            data["path"],
            generation
        ]);
        if crate::mdn::index::hash(&serde_json::to_vec(&identity).map_err(|_| integrity())?) == key
        {
            return Ok(Some(generation));
        }
    }
    Ok(None)
}
fn source_url(snapshot: &Snapshot, path: &str) -> String {
    let repository = if snapshot.repository == "content" {
        "content"
    } else {
        "browser-compat-data"
    };
    let Ok(mut url) = url::Url::parse(if snapshot.coverage["synthetic"] == true {
        "https://fixtures.invalid/"
    } else {
        "https://github.com/"
    }) else {
        return String::new();
    };
    if let Ok(mut segments) = url.path_segments_mut() {
        segments.pop_if_empty();
        for part in ["mdn", repository, "blob", snapshot.revision.as_str()] {
            segments.push(part);
        }
        for part in path.split('/') {
            segments.push(part);
        }
    }
    url.into()
}
fn license(snapshot: &Snapshot) -> Value {
    if snapshot.coverage["synthetic"] == true {
        return json!({"name":"AGPL-3.0-only","attribution":"dev-resources-MCP synthetic acceptance fixtures","synthetic":true});
    }
    if snapshot.repository == "compat" {
        json!({"name":"CC0-1.0","url":source_url(snapshot,"LICENSE")})
    } else {
        json!({"attribution":"MDN contributors","prose":"CC-BY-SA-2.5","code":"CC0 or MIT according to original notices and contribution date; no blanket code-license inference","url":source_url(snapshot,"LICENSE.md"),"projection":"Inert extracted/expanded research text; original source retained"})
    }
}
fn resource_uri(
    repository: &str,
    snapshot: &str,
    representation: &str,
    identity: &str,
    compatibility: Option<&str>,
) -> String {
    let mut uri = format!(
        "devres://mdn/{repository}/{snapshot}/{representation}/{}",
        URL_SAFE_NO_PAD.encode(identity)
    );
    if representation == "text"
        && let Some(id) = compatibility
    {
        uri.push_str("?compatibility_snapshot=");
        uri.push_str(id);
    }
    uri
}

pub fn schemas() -> Vec<Value> {
    let string = json!({"type":"string","minLength":1,"maxLength":256});
    let snapshot = json!({"type":"string","pattern":"^[a-f0-9]{64}$"});
    let path = json!({"type":"string","minLength":1,"maxLength":4096});
    let list_limit = json!({"type":"integer","minimum":1,"maximum":100,"default":20});
    let list_offset = json!({"type":"integer","minimum":0,"maximum":10000});
    let cursor = json!({"type":"string","minLength":1,"maxLength":16384});
    let repository = json!({"enum":["content","compat"],"default":"content"});
    let mut tools = Vec::new();
    let mut add = |name: &str, description: &str, properties: Value, required: Vec<&str>| {
        tools.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}))
    };
    add(
        "mdn.search",
        "Search immutable English MDN document snapshots locally using technical tokens or English phrases, OR and exclusions.",
        json!({"query":string,"snapshot":snapshot,"mode":{"enum":["technical","english"],"default":"technical"},"slug":path,"path":path,"page_type":string,"status":string,"compatibility_key":string,"offset":list_offset,"limit":list_limit,"cursor":cursor}),
        vec![],
    );
    add(
        "mdn.compat_search",
        "Search locally captured BCD features. Support evidence retains uncertainty; no browser-version compatibility verdict is inferred.",
        json!({"query":string,"snapshot":snapshot,"mode":{"enum":["technical","english"],"default":"technical"},"feature":path,"browser":string,"experimental":{"type":"boolean"},"deprecated":{"type":"boolean"},"standard_track":{"type":"boolean"},"offset":list_offset,"limit":list_limit,"cursor":cursor}),
        vec![],
    );
    add(
        "mdn.get",
        "Read one MDN document by slug or repository path. Original source/bytes survive projection gaps. Historical BCD enrichment requires an explicit compatibility_snapshot.",
        json!({"slug":path,"path":path,"repository":repository,"snapshot":snapshot,"compatibility_snapshot":snapshot,"representation":{"enum":["text","source","bytes"],"default":"text"},"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":32768,"default":32768}}),
        vec![],
    );
    add(
        "mdn.compat_get",
        "Read exact original BCD feature support and derived mirror mappings with source provenance. offset/limit page browser statements.",
        json!({"feature":path,"snapshot":snapshot,"browser":string,"offset":list_offset,"limit":list_limit}),
        vec!["feature"],
    );
    add(
        "mdn.browser_get",
        "Read a captured browser identity and engine/release mappings. Release pages preserve the selected immutable BCD snapshot.",
        json!({"browser":string,"snapshot":snapshot,"offset":list_offset,"limit":list_limit}),
        vec!["browser"],
    );
    add(
        "mdn.history",
        "Discover parent-relative source changes for exactly one path, slug or feature, with a frozen publication cutoff and resumable cursor.",
        json!({"repository":repository,"path":path,"slug":path,"feature":path,"history_snapshot":{"type":"integer","minimum":0},"offset":list_offset,"limit":list_limit,"cursor":cursor}),
        vec![],
    );
    add(
        "mdn.snapshots",
        "Discover immutable commit snapshots or advertised ref observations. Ref filters require representation=refs. Follow next_cursor even on an empty bounded scan page.",
        json!({"repository":repository,"representation":{"enum":["commits","refs"],"default":"commits"},"ref":path,"history_snapshot":{"type":"integer","minimum":0},"offset":list_offset,"limit":list_limit,"cursor":cursor}),
        vec![],
    );
    add(
        "mdn.corpus_status",
        "Inspect MDN acquisition, ancestry, processing gaps, publication and freshness without administrative controls.",
        json!({}),
        vec![],
    );
    for tool in &mut tools {
        if tool["name"] == "mdn.get" {
            tool["inputSchema"]["oneOf"] = json!([{"required":["slug"],"not":{"required":["path"]}},{"required":["path"],"not":{"required":["slug"]}}]);
        } else if tool["name"] == "mdn.history" {
            tool["inputSchema"]["oneOf"] = json!([{"required":["slug"],"not":{"anyOf":[{"required":["path"]},{"required":["feature"]}]}},{"required":["path"],"not":{"anyOf":[{"required":["slug"]},{"required":["feature"]}]}},{"required":["feature"],"not":{"anyOf":[{"required":["slug"]},{"required":["path"]}]}}]);
        }
    }
    tools
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use devres_application::mdn::MdnRow;
    use std::sync::{
        Mutex,
        atomic::{AtomicI64, Ordering},
    };
    #[derive(Default)]
    struct Memory {
        rows: Mutex<BTreeMap<(String, String), MdnRow>>,
        state: Mutex<BTreeMap<String, Value>>,
        sequence: AtomicI64,
    }
    #[async_trait]
    impl MdnStore for Memory {
        async fn mdn_cutoff(&self) -> Result<i64> {
            Ok(self.sequence.load(Ordering::Relaxed))
        }
        async fn mdn_get(&self, kind: &str, key: &str) -> Result<Option<MdnRow>> {
            Ok(self
                .rows
                .lock()
                .expect("rows")
                .get(&(kind.into(), key.into()))
                .cloned())
        }
        async fn mdn_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
            let mut rows = self.rows.lock().expect("rows");
            let k = (kind.into(), key.into());
            if let Some(row) = rows.get(&k) {
                if &row.data != data {
                    return Err(integrity());
                }
                return Ok(row.sequence);
            }
            let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
            rows.insert(
                k,
                MdnRow {
                    sequence,
                    key: key.into(),
                    data: data.clone(),
                },
            );
            Ok(sequence)
        }
        async fn mdn_rows(
            &self,
            kind: &str,
            after: i64,
            limit: usize,
            cutoff: Option<i64>,
        ) -> Result<Vec<MdnRow>> {
            let mut rows: Vec<_> = self
                .rows
                .lock()
                .expect("rows")
                .iter()
                .filter(|((k, _), v)| {
                    k == kind && v.sequence > after && cutoff.is_none_or(|c| v.sequence <= c)
                })
                .map(|(_, v)| v.clone())
                .collect();
            rows.sort_by_key(|r| r.sequence);
            rows.truncate(limit);
            Ok(rows)
        }
        async fn mdn_state(&self, key: &str) -> Result<Option<Value>> {
            Ok(self.state.lock().expect("state").get(key).cloned())
        }
        async fn mdn_set_state(&self, key: &str, data: &Value) -> Result<()> {
            self.state
                .lock()
                .expect("state")
                .insert(key.into(), data.clone());
            Ok(())
        }
        async fn mdn_publish_view(&self, view: &View) -> Result<()> {
            self.mdn_put(
                "views",
                &view.id,
                &serde_json::to_value(view).expect("view"),
            )
            .await?;
            self.mdn_set_state("default-view", &json!(view.id)).await
        }
    }
    async fn put_projection(store: &Memory, value: Value) -> String {
        let id = crate::mdn::index::hash(&serde_json::to_vec(&value).expect("projection"));
        store
            .mdn_put("projections", &id, &value)
            .await
            .expect("put");
        let mut header = value.clone();
        if let Some(object) = header.as_object_mut() {
            object.remove("text");
        }
        store
            .mdn_put("projection-headers", &id, &header)
            .await
            .expect("header");
        id
    }
    async fn article(store: &Memory, root: &Path, text: &str, revision: &str) -> Snapshot {
        let source = format!("---\ntitle: Fetch\nslug: Web/API/Fetch\n---\n{text}");
        let body_hash = crate::mdn::index::hash(source.as_bytes());
        std::fs::create_dir_all(root.join("mdn/raw-artifacts/blake3")).expect("raw directory");
        std::fs::write(
            root.join("mdn/raw-artifacts")
                .join(crate::integrity::relative_path(&body_hash).expect("digest path")),
            source.as_bytes(),
        )
        .expect("raw");
        let projection=put_projection(store,json!({"title":"Fetch","slug":"Web/API/Fetch","text":text,"compatibility_keys":["api.fetch"],"gaps":[],"status":[],"page_type":"web-api-method"})).await;
        let empty = crate::mdn::inventory::empty(store).await.expect("empty");
        let inventory=crate::mdn::inventory::update(store,&empty,"files/en-us/web/api/fetch/index.md",Some(Member{path:"files/en-us/web/api/fetch/index.md".into(),oid:"a".repeat(40),mode:"100644".into(),kind:"article".into(),projection:Some(projection),raw:Some(json!({"body_hash":body_hash,"relative_path":format!("mdn/raw-artifacts/{}",crate::integrity::relative_path(&body_hash).expect("digest path").display()),"bytes":source.len(),"source_path":"files/en-us/web/api/fetch/index.md"})),gaps:Vec::new()})).await.expect("inventory");
        let id = crate::mdn::index::hash(format!("content:{revision}:{inventory}").as_bytes());
        let snapshot = Snapshot {
            id,
            repository: "content".into(),
            revision: revision.repeat(40),
            tree: "b".repeat(40),
            parents: Vec::new(),
            committed_at: 1,
            inventory,
            processor_version: 1,
            index: json!({}),
            coverage: json!({"accounted":true}),
        };
        store
            .mdn_put(
                "snapshots",
                &snapshot.id,
                &serde_json::to_value(&snapshot).expect("snapshot"),
            )
            .await
            .expect("put snapshot");
        snapshot
    }
    async fn compatibility(store: &Memory, version: &str) -> Snapshot {
        let mut inventory = crate::mdn::inventory::empty(store).await.expect("empty");
        let value = json!({"key":"api.fetch","data":{"support":{"chrome":{"version_added":version}},"status":{"experimental":false,"standard_track":true,"deprecated":false},"description":"Fetch API"}});
        let projection = put_projection(store, value).await;
        inventory = crate::mdn::inventory::update(
            store,
            &inventory,
            "@features/api.fetch",
            Some(Member {
                path: "@features/api.fetch".into(),
                oid: "c".repeat(40),
                mode: "100644".into(),
                kind: "feature".into(),
                projection: Some(projection),
                raw: None,
                gaps: Vec::new(),
            }),
        )
        .await
        .expect("inventory");
        let id = crate::mdn::index::hash(format!("compat:{version}:{inventory}").as_bytes());
        let snapshot = Snapshot {
            id,
            repository: "compat".into(),
            revision: "c".repeat(40),
            tree: "d".repeat(40),
            parents: Vec::new(),
            committed_at: 1,
            inventory,
            processor_version: 1,
            index: json!({}),
            coverage: json!({"accounted":true}),
        };
        store
            .mdn_put(
                "snapshots",
                &snapshot.id,
                &serde_json::to_value(&snapshot).expect("snapshot"),
            )
            .await
            .expect("put snapshot");
        snapshot
    }
    async fn view(
        store: &Memory,
        content: &Snapshot,
        compatibility: &Snapshot,
        validated_at: i64,
    ) -> View {
        let id = crate::mdn::index::hash(
            format!("{}:{}:{validated_at}", content.id, compatibility.id).as_bytes(),
        );
        let view = View {
            id,
            content: content.id.clone(),
            compatibility: compatibility.id.clone(),
            content_observation: "e".repeat(64),
            compatibility_observation: "f".repeat(64),
            validated_at,
        };
        store.mdn_publish_view(&view).await.expect("view");
        view
    }
    #[tokio::test]
    async fn historical_document_does_not_rebind_to_current_compatibility() {
        let dir = tempfile::tempdir().expect("temp");
        let store = Arc::new(Memory::default());
        let content = article(&store, dir.path(), "Original fetch text", "a").await;
        let compat = compatibility(&store, "42").await;
        let v = view(&store, &content, &compat, devres_domain::unix_now()).await;
        let research = MdnResearch::new(store.clone(), dir.path()).expect("research");
        let current = research
            .call("mdn.get", json!({"slug":"Web/API/Fetch"}))
            .await
            .expect("current");
        assert_eq!(
            current["compatibility"][0]["original"]["chrome"]["version_added"],
            "42"
        );
        assert_eq!(current["provenance"]["view"], v.id);
        let historical = research
            .call(
                "mdn.get",
                json!({"slug":"Web/API/Fetch","snapshot":content.id}),
            )
            .await
            .expect("historical");
        assert!(historical.get("compatibility").is_none());
        assert!(historical["provenance"]["compatibility_snapshot"].is_null());
        let paired=research.call("mdn.get",json!({"slug":"Web/API/Fetch","snapshot":content.id,"compatibility_snapshot":compat.id})).await.expect("pair");
        assert_eq!(
            paired["compatibility"][0]["metadata"]["status"]["experimental"],
            false
        );
    }
    #[tokio::test]
    async fn expired_default_fails_but_pinned_resources_keep_original_utf8() {
        let dir = tempfile::tempdir().expect("temp");
        let store = Arc::new(Memory::default());
        let content = article(&store, dir.path(), "한글 fetch text", "a").await;
        let compat = compatibility(&store, "42").await;
        view(
            &store,
            &content,
            &compat,
            devres_domain::unix_now() - 8 * 86400,
        )
        .await;
        let research = MdnResearch::new(store, dir.path()).expect("research");
        assert_eq!(
            research
                .call("mdn.get", json!({"slug":"Web/API/Fetch"}))
                .await
                .expect_err("expired")
                .code,
            "unavailable"
        );
        let uri = resource_uri(
            "content",
            &content.id,
            "text",
            "files/en-us/web/api/fetch/index.md",
            None,
        );
        let resource = research.read_resource(&uri).await.expect("resource");
        assert_eq!(resource["contents"][0]["text"], "한글 fetch text");
        assert!(
            research
                .read_resource(&format!("{uri}?offset=1"))
                .await
                .is_err()
        );
        assert!(
            research
                .read_resource(&format!("{uri}?offset=0&offset=0"))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn projection_failure_preserves_original_binary_resource() {
        let dir = tempfile::tempdir().expect("temp");
        let store = Arc::new(Memory::default());
        let content = article(&store, dir.path(), "text", "a").await;
        let mut member = crate::mdn::inventory::get(
            store.as_ref(),
            &content.inventory,
            "files/en-us/web/api/fetch/index.md",
        )
        .await
        .expect("get")
        .expect("member");
        member.projection = None;
        member.gaps = vec!["unsupported_format".into()];
        let bytes = [0, 255, 1, 2];
        let hash = crate::mdn::index::hash(&bytes);
        std::fs::write(
            dir.path()
                .join("mdn/raw-artifacts")
                .join(crate::integrity::relative_path(&hash).expect("digest path")),
            bytes,
        )
        .expect("raw");
        member.raw = Some(
            json!({"body_hash":hash,"relative_path":format!("mdn/raw-artifacts/{}",crate::integrity::relative_path(&hash).expect("digest path").display()),"bytes":bytes.len(),"source_path":member.path}),
        );
        let mut historical = content.clone();
        historical.inventory = crate::mdn::inventory::update(
            store.as_ref(),
            &content.inventory,
            &member.path.clone(),
            Some(member),
        )
        .await
        .expect("update");
        historical.id = crate::mdn::index::hash(b"failed projection snapshot");
        store
            .mdn_put(
                "snapshots",
                &historical.id,
                &serde_json::to_value(&historical).expect("snapshot"),
            )
            .await
            .expect("snapshot");
        let research = MdnResearch::new(store, dir.path()).expect("research");
        let output=research.call("mdn.get",json!({"path":"files/en-us/web/api/fetch/index.md","snapshot":historical.id,"representation":"source","offset":1,"limit":2})).await.expect("source");
        assert_eq!(output["page"]["data"], STANDARD.encode([255, 1]));
        assert_eq!(output["page"]["next_offset"], 3);
        assert!(
            research
                .call(
                    "mdn.get",
                    json!({"path":"files/en-us/web/api/fetch/index.md","snapshot":historical.id})
                )
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn discovery_cursor_freezes_cutoff_and_mid_observation_position() {
        let dir = tempfile::tempdir().expect("temp");
        let store = Arc::new(Memory::default());
        store.mdn_put("observations","first",&json!({"repo":"content","observed_at":1,"refs":[{"name":"refs/heads/main","oid":"a"},{"name":"refs/tags/v1","oid":"b"}]})).await.expect("first");
        let research = MdnResearch::new(store.clone(), dir.path()).expect("research");
        let first = research
            .call("mdn.snapshots", json!({"representation":"refs","limit":1}))
            .await
            .expect("first");
        assert_eq!(first["results"][0]["ref"]["name"], "refs/heads/main");
        store.mdn_put("observations","later",&json!({"repo":"content","observed_at":2,"refs":[{"name":"refs/tags/v2","oid":"c"}]})).await.expect("later");
        let second = research
            .call(
                "mdn.snapshots",
                json!({"representation":"refs","cursor":first["next_cursor"],"limit":20}),
            )
            .await
            .expect("second");
        assert_eq!(second["results"].as_array().expect("results").len(), 1);
        assert_eq!(second["results"][0]["ref"]["name"], "refs/tags/v1");
        assert!(second["next_cursor"].is_null());
        assert!(research.call("mdn.snapshots",json!({"representation":"refs","repository":"compat","cursor":first["next_cursor"]})).await.is_err());
    }
    #[tokio::test]
    async fn document_selection_and_untrusted_destinations_fail_before_lookup() {
        let dir = tempfile::tempdir().expect("temp");
        let store = Arc::new(Memory::default());
        let research = MdnResearch::new(store, dir.path()).expect("research");
        assert_eq!(
            research
                .call("mdn.get", json!({}))
                .await
                .expect_err("missing selector")
                .code,
            "invalid_input"
        );
        assert_eq!(
            research
                .call("mdn.get", json!({"slug":"A","path":"B"}))
                .await
                .expect_err("duplicate selector")
                .code,
            "invalid_input"
        );
        assert_eq!(
            research
                .call("mdn.get", json!({"slug":"A","url":"https://example.com"}))
                .await
                .expect_err("unknown URL")
                .code,
            "invalid_input"
        );
        assert!(
            research
                .read_resource("devres://mdn/content/../../source/Zm9v")
                .await
                .is_err()
        );
        assert!(
            research
                .read_resource("https://example.com/anything")
                .await
                .is_err()
        );
    }
}
