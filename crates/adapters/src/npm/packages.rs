//! Request-driven npm package reads. Published package contents remain inert data.
use crate::{
    archive,
    npm::processing as npm_processing,
    npm::source::Operation,
    research::{capture_json, text_page},
};
use async_trait::async_trait;
use devres_application::{ResponseValidator, Retrieval};
use devres_domain::{Error, FetchRequest, FetchResponse, Result, StoredCapture};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::OwnedSemaphorePermit;

const MAX_SEARCH: usize = 2 * 1024 * 1024;
const METADATA_TTL: u64 = 3600;
const ARCHIVE_TTL: u64 = 365 * 86400;
type Lease = Arc<OwnedSemaphorePermit>;

async fn process<T: Send + 'static>(
    lease: Lease,
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(move || {
        let _lease = lease;
        operation()
    })
    .await
    .map_err(|_| Error::unavailable("npm processing worker failed."))?
}

#[derive(Clone, Copy)]
enum MetadataNumbers {
    Canonical,
    ArchiveIdentity,
}
impl MetadataNumbers {
    fn select(self, bytes: &[u8], name: &str, version: &str) -> Result<Value> {
        match self {
            Self::Canonical => npm_processing::select_packument(bytes, name, version),
            Self::ArchiveIdentity => npm_processing::select_source_packument(bytes, name, version),
        }
    }
}

enum Validation {
    Metadata(String, String, MetadataNumbers),
    Search,
    Archive {
        record: Value,
        metadata_capture: String,
    },
}
struct Validator {
    validation: Validation,
    lease: Lease,
}
#[async_trait]
impl ResponseValidator for Validator {
    fn acquisition(
        &self,
        request: &FetchRequest,
    ) -> Result<Option<devres_application::acquisition::Acquisition>> {
        use devres_application::acquisition::Acquisition;
        Ok(Some(match &self.validation {
            Validation::Metadata(name, version, numbers) => Acquisition::NpmMetadata {
                name: name.clone(),
                version: version.clone(),
                source_identity: matches!(numbers, MetadataNumbers::ArchiveIdentity),
            },
            Validation::Search => {
                let value = request
                    .key
                    .strip_prefix("npm:search:")
                    .ok_or_else(|| Error::invalid("Invalid npm search identity."))?;
                let (query, offset) = value
                    .rsplit_once(':')
                    .ok_or_else(|| Error::invalid("Invalid npm search identity."))?;
                Acquisition::NpmSearch {
                    query: query.into(),
                    offset: offset
                        .parse()
                        .map_err(|_| Error::invalid("Invalid npm search page."))?,
                }
            }
            Validation::Archive {
                record,
                metadata_capture,
            } => Acquisition::NpmArchive {
                name: record["name"]
                    .as_str()
                    .ok_or_else(|| Error::integrity("Missing npm package identity."))?
                    .into(),
                version: record["version"]
                    .as_str()
                    .ok_or_else(|| Error::integrity("Missing npm version identity."))?
                    .into(),
                metadata_capture: metadata_capture.clone(),
            },
        }))
    }

    async fn validate(&self, _: &FetchRequest, response: FetchResponse) -> Result<FetchResponse> {
        let validation = match &self.validation {
            Validation::Metadata(name, version, numbers) => {
                Validation::Metadata(name.clone(), version.clone(), *numbers)
            }
            Validation::Search => Validation::Search,
            Validation::Archive {
                record,
                metadata_capture,
            } => Validation::Archive {
                record: record.clone(),
                metadata_capture: metadata_capture.clone(),
            },
        };
        process(self.lease.clone(), move || {
            match validation {
                Validation::Metadata(name, version, numbers) => {
                    numbers.select(&response.body, &name, &version)?;
                }
                Validation::Search => {
                    search_document(&response.body)?;
                }
                // Raw checksum verification is independent of archive processing.
                Validation::Archive { record, .. } => {
                    npm_processing::verify_integrity(&response.body, &record)?;
                }
            }
            Ok(response)
        })
        .await
    }
}

fn twenty() -> usize {
    20
}
fn text_limit() -> usize {
    32768
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchInput {
    query: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "twenty")]
    limit: usize,
    capture: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataInput {
    name: String,
    version: String,
    capture: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceInput {
    name: String,
    version: String,
    metadata_capture: Option<String>,
    archive_capture: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "twenty")]
    limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadInput {
    name: String,
    version: String,
    path: String,
    metadata_capture: Option<String>,
    archive_capture: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "text_limit")]
    limit: usize,
}
fn decode<T: serde::de::DeserializeOwned>(input: Value) -> Result<T> {
    serde_json::from_value(input)
        .map_err(|_| Error::invalid("Arguments do not match the npm tool input schema."))
}
fn page(offset: usize, limit: usize) -> Result<()> {
    if offset > 1_000_000 || limit == 0 || limit > 100 {
        return Err(Error::invalid(
            "npm list limit must be 1..100 and offset at most 1000000.",
        ));
    }
    Ok(())
}
fn search_document(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_SEARCH {
        return Err(Error::capacity(
            "npm search response exceeds processing limit.",
        ));
    }
    let document = npm_processing::parse_json(bytes, MAX_SEARCH)?;
    let objects = document["objects"]
        .as_array()
        .filter(|items| items.len() <= 100)
        .ok_or_else(|| Error::integrity("Invalid npm search result list."))?;
    let total = document["total"]
        .as_u64()
        .ok_or_else(|| Error::integrity("npm search total is absent."))?;
    if total < objects.len() as u64 {
        return Err(Error::integrity("npm search total is inconsistent."));
    }
    let mut seen = HashSet::new();
    for result in objects {
        let package = &result["package"];
        let name = package["name"]
            .as_str()
            .ok_or_else(|| Error::integrity("npm search package identity is absent."))?;
        npm_processing::validate_name(name)
            .map_err(|_| Error::integrity("Invalid npm search package identity."))?;
        let version = package["version"]
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 256)
            .ok_or_else(|| Error::integrity("npm search version is absent."))?;
        if !seen.insert(name) || version.chars().any(char::is_control) {
            return Err(Error::integrity("Invalid or duplicate npm search result."));
        }
    }
    Ok(document)
}

fn ensure(stored: &StoredCapture, key: &str, url: &str, media_type: &str) -> Result<()> {
    if stored.capture.key != key
        || stored.capture.source_url != url
        || stored.capture.media_type != media_type
    {
        return Err(Error::invalid(
            "npm capture belongs to another package, representation or source.",
        ));
    }
    Ok(())
}
pub fn archive_key(name: &str, version: &str, manifest: &Value) -> Result<String> {
    npm_processing::validate_name(name)?;
    npm_processing::parse_version(version)?;
    let bytes = serde_json::to_vec(&manifest["dist"])
        .map_err(|_| Error::integrity("Invalid npm distribution metadata."))?;
    Ok(format!(
        "npm:archive:{name}:{version}:{}",
        crate::integrity::legacy_hash(&bytes)
    ))
}
fn selected(document: &Value, version: &str) -> Result<Value> {
    let normalized = npm_processing::parse_version(version)?.to_string();
    document["versions"]
        .get(version)
        .or_else(|| document["versions"].get(&normalized))
        .cloned()
        .ok_or_else(|| Error::not_found("npm version is absent from the captured metadata."))
}

pub struct NpmPackages {
    retrieval: Arc<Retrieval>,
}
impl NpmPackages {
    pub fn new(retrieval: Arc<Retrieval>) -> Self {
        Self { retrieval }
    }
    pub async fn call(&self, tool: &str, input: Value) -> Result<Value> {
        match tool {
            "packages.npm.search" => self.search(decode(input)?).await,
            "packages.npm.metadata" => self.metadata(decode(input)?).await,
            "packages.npm.source_list" => self.source_list(decode(input)?).await,
            "packages.npm.source_read" => self.source_read(decode(input)?).await,
            _ => Err(Error::not_found("Unknown npm package tool.")),
        }
    }
    async fn packument(
        &self,
        name: &str,
        version: &str,
        pin: Option<&str>,
        numbers: MetadataNumbers,
        lease: Lease,
    ) -> Result<(StoredCapture, Value)> {
        npm_processing::validate_name(name)?;
        let key = format!("npm:metadata:{name}");
        let url = Operation::Metadata { name: name.into() }.url()?;
        let stored = match pin {
            Some(id) => {
                let stored = self.retrieval.read_capture(id).await?;
                ensure(&stored, &key, &url, "application/json")?;
                stored
            }
            None => {
                self.retrieval
                    .get_validated(
                        FetchRequest {
                            key,
                            url,
                            ttl_secs: METADATA_TTL,
                            max_bytes: npm_processing::MAX_METADATA,
                            media_type: "application/json".into(),
                        },
                        &Validator {
                            validation: Validation::Metadata(name.into(), version.into(), numbers),
                            lease: lease.clone(),
                        },
                    )
                    .await?
            }
        };
        let body = stored.body.clone();
        let name = name.to_owned();
        let version = version.to_owned();
        let document = process(lease, move || numbers.select(&body, &name, &version)).await?;
        Ok((stored, document))
    }
    async fn search(&self, input: SearchInput) -> Result<Value> {
        page(input.offset, input.limit)?;
        if input.offset > 10_000 || input.query.trim().is_empty() || input.query.len() > 256 {
            return Err(Error::invalid(
                "npm search requires 1..256 query bytes and offset at most 10000.",
            ));
        }
        let provider_offset = input.offset / 100 * 100;
        let within = input.offset % 100;
        let key = format!("npm:search:{}:{provider_offset}", input.query);
        let url = Operation::Search {
            query: input.query.clone(),
            offset: provider_offset,
            limit: 100,
        }
        .url()?;
        let lease = Arc::new(archive::admit()?);
        let stored = match input.capture {
            Some(id) => {
                let stored = self.retrieval.read_capture(&id).await?;
                ensure(&stored, &key, &url, "application/json")?;
                stored
            }
            None => {
                self.retrieval
                    .get_validated(
                        FetchRequest {
                            key,
                            url,
                            ttl_secs: METADATA_TTL,
                            max_bytes: MAX_SEARCH,
                            media_type: "application/json".into(),
                        },
                        &Validator {
                            validation: Validation::Search,
                            lease: lease.clone(),
                        },
                    )
                    .await?
            }
        };
        let body = stored.body.clone();
        let document = process(lease, move || search_document(&body)).await?;
        let objects = document["objects"]
            .as_array()
            .ok_or_else(|| Error::integrity("npm search objects absent."))?;
        let count = input.limit.min(100 - within);
        let items: Vec<_> = objects.iter().skip(within).take(count).map(|item| {
            let package = &item["package"];
            json!({"id":format!("npm:{}@{}",package["name"].as_str().unwrap_or(""),package["version"].as_str().unwrap_or("")),"name":package["name"],"version":package["version"],"description":package["description"],"keywords":package["keywords"],"url":package["links"]["npm"],"score":item["score"],"search_score":item["searchScore"]})
        }).collect();
        let consumed = input.offset.saturating_add(items.len());
        let total = document["total"].as_u64().unwrap_or(0);
        let next = if !items.is_empty() && (consumed as u64) < total && consumed <= 10_000 {
            Some(consumed)
        } else {
            None
        };
        Ok(
            json!({"items":items,"total":total,"offset":input.offset,"next_offset":next,"capture":capture_json(&stored.capture,METADATA_TTL),"source":"npm","ranking":"upstream npm package search"}),
        )
    }
    async fn metadata(&self, input: MetadataInput) -> Result<Value> {
        npm_processing::parse_version(&input.version)?;
        let lease = Arc::new(archive::admit()?);
        let (stored, document) = self
            .packument(
                &input.name,
                &input.version,
                input.capture.as_deref(),
                MetadataNumbers::Canonical,
                lease,
            )
            .await?;
        let record = selected(&document, &input.version)?;
        let original_version = record["version"].as_str().unwrap_or(&input.version);
        let response = json!({"id":format!("npm:{}@{}",input.name,original_version),"metadata":record,"dist_tags":document["dist-tags"],"time":{"created":document["time"]["created"],"modified":document["time"]["modified"],"published":document["time"][original_version]},"capture":capture_json(&stored.capture,METADATA_TTL),"dependency_scope":"published declarations; no dependency resolution or package execution","license_notice":"npm package contents retain their original licensing and notices."});
        if serde_json::to_vec(&response)
            .map_err(|_| Error::integrity("Invalid npm metadata projection."))?
            .len()
            > 256 * 1024
        {
            return Err(Error::capacity(
                "Selected npm metadata exceeds 256 KiB; original public capture remains retained.",
            ));
        }
        Ok(response)
    }
    async fn sources(
        &self,
        name: &str,
        version: &str,
        metadata_pin: Option<&str>,
        archive_pin: Option<&str>,
        lease: Lease,
    ) -> Result<(StoredCapture, StoredCapture, Value)> {
        if metadata_pin.is_some() != archive_pin.is_some() {
            return Err(Error::invalid(
                "Supply both npm metadata_capture and archive_capture, or neither.",
            ));
        }
        npm_processing::parse_version(version)?;
        let (metadata, document) = self
            .packument(
                name,
                version,
                metadata_pin,
                MetadataNumbers::ArchiveIdentity,
                lease.clone(),
            )
            .await?;
        let record = selected(&document, version)?;
        let original_version = record["version"]
            .as_str()
            .ok_or_else(|| Error::integrity("npm version manifest identity is absent."))?;
        let tarball = record["dist"]["tarball"]
            .as_str()
            .ok_or_else(|| Error::integrity("npm tarball URL is absent."))?;
        let url = Operation::Archive {
            name: name.into(),
            version: original_version.into(),
            url: tarball.into(),
        }
        .url()?;
        let key = archive_key(name, original_version, &record)?;
        let archive = match archive_pin {
            Some(id) => {
                let stored = self.retrieval.read_capture(id).await?;
                ensure(&stored, &key, &url, "application/gzip")?;
                stored
            }
            None => {
                self.retrieval
                    .get_validated(
                        FetchRequest {
                            key,
                            url,
                            ttl_secs: ARCHIVE_TTL,
                            max_bytes: 128 * 1024 * 1024,
                            media_type: "application/gzip".into(),
                        },
                        &Validator {
                            validation: Validation::Archive {
                                record: record.clone(),
                                metadata_capture: metadata.capture.id.clone(),
                            },
                            lease: lease.clone(),
                        },
                    )
                    .await?
            }
        };
        let bytes = archive.body.clone();
        let manifest = record.clone();
        // Capture pins are also verified; a pin is provenance, not permission to
        // skip package identity and integrity checking.
        process(lease, move || {
            npm_processing::verify_integrity(&bytes, &manifest)
        })
        .await?;
        Ok((metadata, archive, record))
    }
    async fn source_list(&self, input: SourceInput) -> Result<Value> {
        page(input.offset, input.limit)?;
        let lease = Arc::new(archive::admit()?);
        let (metadata, archive, record) = self
            .sources(
                &input.name,
                &input.version,
                input.metadata_capture.as_deref(),
                input.archive_capture.as_deref(),
                lease.clone(),
            )
            .await?;
        let bytes = archive.body.clone();
        let inspected = process(lease, move || {
            npm_processing::inspect_package(&bytes, &record)
        })
        .await;
        let inspected = match inspected {
            Ok(value) => value,
            Err(error) => {
                return Ok(
                    json!({"files":[],"total":0,"offset":input.offset,"next_offset":null,"metadata_capture":capture_json(&metadata.capture,METADATA_TTL),"archive_capture":capture_json(&archive.capture,ARCHIVE_TTL),"checksum_verified":true,"processing_complete":false,"gaps":[{"code":error.code,"message":error.message}]}),
                );
            }
        };
        let members = inspected["members"]
            .as_array()
            .ok_or_else(|| Error::integrity("npm member projection absent."))?;
        let mut files = Vec::new();
        for member in members.iter().skip(input.offset).take(input.limit) {
            let path = member["path"]
                .as_str()
                .ok_or_else(|| Error::integrity("npm member identity absent."))?;
            files.push(json!({"path":path,"bytes":member["size"],"resource_uri":source_uri(&input.name,&input.version,path,&metadata.capture.id,&archive.capture.id,0,32768)?}));
        }
        Ok(
            json!({"files":files,"total":members.len(),"offset":input.offset,"next_offset":if input.offset.saturating_add(input.limit)<members.len() {Some(input.offset+input.limit)} else {None},"metadata_capture":capture_json(&metadata.capture,METADATA_TTL),"archive_capture":capture_json(&archive.capture,ARCHIVE_TTL),"checksum_verified":true,"processing_complete":true,"gaps":inspected["gaps"],"license_notice":"Published package contents retain their original copyright, licensing and notices."}),
        )
    }
    async fn source_read(&self, input: ReadInput) -> Result<Value> {
        if !archive::valid_relative_path(&input.path)
            || input.limit == 0
            || input.limit > 32768
            || input.offset > npm_processing::MAX_DOCUMENT
        {
            return Err(Error::invalid("Invalid npm source path or text page."));
        }
        let lease = Arc::new(archive::admit()?);
        let (metadata, archive, record) = self
            .sources(
                &input.name,
                &input.version,
                input.metadata_capture.as_deref(),
                input.archive_capture.as_deref(),
                lease.clone(),
            )
            .await?;
        let bytes = archive.body.clone();
        let path = input.path.clone();
        let document = process(lease, move || {
            npm_processing::read_member(&bytes, &record, &path)
        })
        .await?;
        let text = document["text"]
            .as_str()
            .ok_or_else(|| Error::integrity("npm document projection absent."))?;
        Ok(
            json!({"path":input.path,"kind":document["kind"],"page":text_page(text,input.offset,input.limit)?,"resource_uri":source_uri(&input.name,&input.version,&input.path,&metadata.capture.id,&archive.capture.id,input.offset,input.limit)?,"metadata_capture":capture_json(&metadata.capture,METADATA_TTL),"archive_capture":capture_json(&archive.capture,ARCHIVE_TTL),"checksum_verified":true,"license_notice":"Published source retains its original copyright and licensing."}),
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn source_uri(
    name: &str,
    version: &str,
    path: &str,
    metadata: &str,
    archive: &str,
    offset: usize,
    limit: usize,
) -> Result<String> {
    let mut uri = url::Url::parse("devres://npm-source/")
        .map_err(|_| Error::invalid("Invalid npm source resource configuration."))?;
    uri.query_pairs_mut()
        .append_pair("name", name)
        .append_pair("version", version)
        .append_pair("path", path)
        .append_pair("metadata_capture", metadata)
        .append_pair("archive_capture", archive)
        .append_pair("offset", &offset.to_string())
        .append_pair("limit", &limit.to_string());
    if uri.as_str().len() > 16384 {
        return Err(Error::capacity("npm source resource exceeds 16 KiB."));
    }
    Ok(uri.to_string())
}
pub fn source_input_from_uri(value: &str) -> Result<Value> {
    if value.len() > 16384 {
        return Err(Error::invalid("npm source resource exceeds 16 KiB."));
    }
    let uri =
        url::Url::parse(value).map_err(|_| Error::invalid("Invalid npm source resource URI."))?;
    if uri.scheme() != "devres"
        || uri.host_str() != Some("npm-source")
        || !matches!(uri.path(), "" | "/")
        || uri.fragment().is_some()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.port().is_some()
    {
        return Err(Error::invalid("Invalid npm source resource identity."));
    }
    let mut input = serde_json::Map::new();
    for (key, value) in uri.query_pairs() {
        if input.contains_key(key.as_ref()) {
            return Err(Error::invalid("Duplicate npm source resource parameter."));
        }
        let value = if key == "offset" || key == "limit" {
            json!(
                value
                    .parse::<usize>()
                    .map_err(|_| Error::invalid("Invalid npm source page."))?
            )
        } else {
            json!(value)
        };
        input.insert(key.into_owned(), value);
    }
    let value = Value::Object(input);
    let parsed: ReadInput = decode(value.clone())?;
    if parsed.metadata_capture.is_none() || parsed.archive_capture.is_none() {
        return Err(Error::invalid(
            "npm source resources must be capture-fixed.",
        ));
    }
    Ok(value)
}

pub fn schemas() -> Vec<Value> {
    let name = json!({"type":"string","minLength":1,"maxLength":214});
    let version = json!({"type":"string","minLength":1,"maxLength":256});
    let capture = json!({"type":"string","pattern":"^(blake3:)?[0-9a-f]{64}$"});
    let offset = json!({"type":"integer","minimum":0,"maximum":1000000,"default":0});
    let limit = json!({"type":"integer","minimum":1,"maximum":100,"default":20});
    let mut tools = Vec::new();
    let mut add = |name: &str, description: &str, properties: Value, required: Vec<&str>| {
        tools.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}}))
    };
    add(
        "packages.npm.search",
        "Search public npm package metadata; reuse the returned capture for the same provider page.",
        json!({"query":{"type":"string","minLength":1,"maxLength":256},"offset":{"type":"integer","minimum":0,"maximum":10000,"default":0},"limit":limit,"capture":capture}),
        vec!["query"],
    );
    add(
        "packages.npm.metadata",
        "Read an exact public npm version and published dependency declarations without resolving or executing packages.",
        json!({"name":name,"version":version,"capture":capture}),
        vec!["name", "version"],
    );
    add(
        "packages.npm.source_list",
        "List integrity-verified published npm archive members; processing gaps remain separate from retained raw captures.",
        json!({"name":name,"version":version,"metadata_capture":capture,"archive_capture":capture,"offset":offset,"limit":limit}),
        vec!["name", "version"],
    );
    add(
        "packages.npm.source_read",
        "Read inert published npm source text; byte pagination is pinned to metadata and archive captures.",
        json!({"name":name,"version":version,"path":{"type":"string","minLength":1,"maxLength":4096},"metadata_capture":capture,"archive_capture":capture,"offset":{"type":"integer","minimum":0,"maximum":4194304,"default":0},"limit":{"type":"integer","minimum":1,"maximum":32768,"default":32768}}),
        vec!["name", "version", "path"],
    );
    tools
}

/// Writer-side canonical reconstruction; the request cannot supply a destination.
pub(crate) async fn writer_acquire(
    retrieval: Arc<Retrieval>,
    operation: &devres_application::acquisition::Acquisition,
) -> Result<StoredCapture> {
    use devres_application::acquisition::Acquisition;
    let lease = Arc::new(archive::admit()?);
    match operation {
        Acquisition::NpmMetadata {
            name,
            version,
            source_identity,
        } => {
            npm_processing::parse_version(version)?;
            let numbers = if *source_identity {
                MetadataNumbers::ArchiveIdentity
            } else {
                MetadataNumbers::Canonical
            };
            NpmPackages::new(retrieval)
                .packument(name, version, None, numbers, lease)
                .await
                .map(|(stored, _)| stored)
        }
        Acquisition::NpmSearch { query, offset } => {
            if query.trim().is_empty() || query.len() > 256 || *offset > 10000 || *offset % 100 != 0
            {
                return Err(Error::invalid("Invalid npm acquisition page."));
            }
            let url = Operation::Search {
                query: query.clone(),
                offset: *offset,
                limit: 100,
            }
            .url()?;
            retrieval
                .get_validated(
                    FetchRequest {
                        key: format!("npm:search:{query}:{offset}"),
                        url,
                        ttl_secs: METADATA_TTL,
                        max_bytes: MAX_SEARCH,
                        media_type: "application/json".into(),
                    },
                    &Validator {
                        validation: Validation::Search,
                        lease,
                    },
                )
                .await
        }
        Acquisition::NpmArchive {
            name,
            version,
            metadata_capture,
        } => {
            npm_processing::validate_name(name)?;
            npm_processing::parse_version(version)?;
            let packages = NpmPackages::new(retrieval.clone());
            let (_, document) = packages
                .packument(
                    name,
                    version,
                    Some(metadata_capture),
                    MetadataNumbers::ArchiveIdentity,
                    lease.clone(),
                )
                .await?;
            let record = selected(&document, version)?;
            let original = record["version"]
                .as_str()
                .ok_or_else(|| Error::integrity("Missing npm version."))?;
            let tarball = record["dist"]["tarball"]
                .as_str()
                .ok_or_else(|| Error::integrity("Missing npm archive identity."))?;
            let url = Operation::Archive {
                name: name.clone(),
                version: original.into(),
                url: tarball.into(),
            }
            .url()?;
            retrieval
                .get_validated(
                    FetchRequest {
                        key: archive_key(name, original, &record)?,
                        url,
                        ttl_secs: ARCHIVE_TTL,
                        max_bytes: 128 * 1024 * 1024,
                        media_type: "application/gzip".into(),
                    },
                    &Validator {
                        validation: Validation::Archive {
                            record,
                            metadata_capture: metadata_capture.clone(),
                        },
                        lease,
                    },
                )
                .await
        }
        _ => Err(Error::invalid("Unsupported npm acquisition.")),
    }
}
