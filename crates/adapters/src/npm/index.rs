//! Provider-specific facade over the established immutable, selected-membership BM25 engine.
//! The reusable engine's field names and paths are private implementation details.
use crate::mdn::index::{self as mdn_index, MdnIndex};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexDocument {
    pub id: String,
    pub name: String,
    pub version: String,
    pub path: String,
    pub title: String,
    pub text: String,
    pub kind: String,
    pub metadata: Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchSpec {
    pub query: Option<String>,
    pub snapshot: Option<String>,
    #[serde(default = "technical")]
    pub mode: String,
    #[serde(default)]
    pub filters: BTreeMap<String, String>,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "twenty")]
    pub limit: usize,
    pub cursor: Option<String>,
}
fn technical() -> String {
    "technical".into()
}
fn twenty() -> usize {
    20
}
impl Default for SearchSpec {
    fn default() -> Self {
        Self {
            query: None,
            snapshot: None,
            mode: technical(),
            filters: BTreeMap::new(),
            offset: 0,
            limit: 20,
            cursor: None,
        }
    }
}
fn provider_error(mut error: Error) -> Error {
    error.message = error.message.replace("MDN", "Npm");
    error
}
fn reference(value: &Value, external: bool) -> Result<Value> {
    let mut output = value.clone();
    let path = output
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::integrity("Invalid Npm search reference."))?;
    let (from, to) = if external {
        ("mdn-indexes/", "npm-indexes/")
    } else {
        ("npm-indexes/", "mdn-indexes/")
    };
    let suffix = path
        .strip_prefix(from)
        .ok_or_else(|| Error::integrity("Invalid Npm search reference namespace."))?;
    output["path"] = Value::String(format!("{to}{suffix}"));
    Ok(output)
}
fn document(input: IndexDocument) -> Result<mdn_index::IndexDocument> {
    if input.name.len() > 214
        || input.version.len() > 128
        || input.kind.len() > 128
        || [&input.name, &input.version, &input.kind]
            .iter()
            .any(|s| s.chars().any(char::is_control))
    {
        return Err(Error::invalid("Invalid Npm index identity."));
    }
    let mut metadata = input
        .metadata
        .as_object()
        .cloned()
        .ok_or_else(|| Error::invalid("Npm index metadata must be an object."))?;
    metadata.insert("page_type".into(), Value::String(input.version));
    metadata.insert("feature".into(), Value::String(input.id.clone()));
    if let Some(symbol_kind) = metadata.get("symbol_kind").cloned() {
        metadata.insert("status".into(), symbol_kind);
    }
    Ok(mdn_index::IndexDocument {
        id: input.id,
        kind: input.kind,
        slug: input.name,
        title: input.title,
        path: input.path,
        text: input.text,
        metadata: Value::Object(metadata),
    })
}
#[derive(Clone)]
pub struct NpmIndex {
    inner: MdnIndex,
}
impl NpmIndex {
    pub fn new(root: &Path) -> Result<Self> {
        let owned = root.join("npm-search");
        if owned.exists() {
            let metadata = std::fs::symlink_metadata(&owned)
                .map_err(|_| Error::unavailable("Npm search storage unavailable."))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(Error::integrity("Invalid Npm search storage."));
            }
        } else {
            std::fs::create_dir(&owned)
                .map_err(|_| Error::unavailable("Npm search storage unavailable."))?;
        }
        Ok(Self {
            inner: MdnIndex::new(&owned).map_err(provider_error)?,
        })
    }
    pub fn validate_document(input: &IndexDocument, cancel: &CancellationToken) -> Result<()> {
        MdnIndex::validate_document(&document(input.clone())?, cancel).map_err(provider_error)
    }
    pub fn recover_stages(&self) -> Result<()> {
        self.inner.recover_stages().map_err(provider_error)
    }
    pub async fn publish(
        &self,
        previous: Option<&Value>,
        documents: Vec<IndexDocument>,
        cancel: CancellationToken,
    ) -> Result<Value> {
        self.publish_generation(previous, documents, cancel, "")
            .await
    }
    pub async fn publish_generation(
        &self,
        previous: Option<&Value>,
        documents: Vec<IndexDocument>,
        cancel: CancellationToken,
        generation: &str,
    ) -> Result<Value> {
        let previous = previous.map(|value| reference(value, false)).transpose()?;
        let documents = documents
            .into_iter()
            .map(document)
            .collect::<Result<Vec<_>>>()?;
        let result = self
            .inner
            .publish_generation(previous.as_ref(), documents, cancel, generation)
            .await
            .map_err(provider_error)?;
        reference(&result, true)
    }
    pub async fn prewarm(&self, index: &Value, cancel: CancellationToken) -> Result<()> {
        self.inner
            .prewarm(&reference(index, false)?, cancel)
            .await
            .map_err(provider_error)
    }
    /// Statistics cover only these immutable section/symbol IDs, across all selected names.
    pub async fn search(
        &self,
        index: &Value,
        members: BTreeSet<String>,
        spec: SearchSpec,
        cancel: CancellationToken,
    ) -> Result<Value> {
        let mut filters = BTreeMap::new();
        for (key, value) in spec.filters {
            let internal = match key.as_str() {
                "id" => "feature",
                "name" => "slug",
                "version" => "page_type",
                "symbol_kind" => "status",
                "kind" => "kind",
                "path" => "path",
                _ => return Err(Error::invalid("Invalid Npm search filter.")),
            };
            filters.insert(internal.into(), value);
        }
        let spec = mdn_index::SearchSpec {
            query: spec.query,
            snapshot: spec.snapshot,
            mode: spec.mode,
            filters,
            offset: spec.offset,
            limit: spec.limit,
            cursor: spec.cursor,
        };
        let mut result = self
            .inner
            .search(&reference(index, false)?, members, spec, cancel)
            .await
            .map_err(provider_error)?;
        if let Some(results) = result.get_mut("results").and_then(Value::as_array_mut) {
            for hit in results {
                if let Some(hit) = hit.as_object_mut() {
                    if let Some(name) = hit.remove("slug") {
                        hit.insert("name".into(), name);
                    }
                    if let Some(metadata) = hit.get_mut("metadata").and_then(Value::as_object_mut) {
                        let version = metadata.remove("page_type");
                        metadata.remove("status");
                        metadata.remove("feature");
                        if let Some(version) = version {
                            hit.insert("version".into(), version);
                        }
                    }
                }
            }
        }
        Ok(result)
    }
}
