//! crates.io search, sparse-index metadata, and checksum-verified source browsing.

use crate::{
    archive,
    research::{Page, capture_json, ensure_capture, list_limit, text_limit, text_page},
};
use devres_application::Retrieval;
use devres_domain::{Error, FetchRequest, Result, StoredCapture};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchInput {
    pub query: String,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "list_limit")]
    pub limit: usize,
    #[serde(default)]
    pub capture: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataInput {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub capture: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceListInput {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub metadata_capture: Option<String>,
    #[serde(default)]
    pub archive_capture: Option<String>,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "list_limit")]
    pub limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReadInput {
    pub name: String,
    pub version: String,
    pub path: String,
    #[serde(default)]
    pub metadata_capture: Option<String>,
    #[serde(default)]
    pub archive_capture: Option<String>,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "text_limit")]
    pub limit: usize,
}

pub(crate) fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || v == b'_' || v == b'-')
    {
        return Err(Error::invalid(
            "Crate names must contain 1..64 ASCII letters, digits, hyphens or underscores.",
        ));
    }
    Ok(())
}
pub(crate) fn validate_version(version: &str) -> Result<semver::Version> {
    if version.len() > 128 {
        return Err(Error::invalid("Crate version is too long."));
    }
    semver::Version::parse(version)
        .map_err(|_| Error::invalid("An exact semantic version is required."))
}

pub fn sparse_path(name: &str) -> Result<String> {
    validate_name(name)?;
    let name = name.to_ascii_lowercase();
    Ok(match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    })
}

pub async fn search(retrieval: &Retrieval, input: SearchInput) -> Result<Value> {
    if input.query.trim().is_empty() || input.query.len() > 256 {
        return Err(Error::invalid(
            "Crate search query must contain 1..256 bytes.",
        ));
    }
    let page = Page {
        offset: input.offset,
        limit: input.limit,
    }
    .checked()?;
    // Always fetch a fixed 100-result provider page, so local page-size changes do
    // not duplicate API calls and each cached provider page has one identity.
    let upstream_page = page.offset / 100 + 1;
    let within_page = page.offset % 100;
    let key = format!("cargo:search:{}:{upstream_page}", input.query);
    let captured = match input.capture {
        Some(id) => {
            let stored = retrieval.read_capture(&id).await?;
            ensure_capture(&stored, &key)?;
            stored
        }
        None => {
            let mut url = url::Url::parse("https://crates.io/api/v1/crates")
                .map_err(|_| Error::invalid("Invalid registry configuration."))?;
            url.query_pairs_mut()
                .append_pair("q", &input.query)
                .append_pair("per_page", "100")
                .append_pair("page", &upstream_page.to_string());
            retrieval
                .get(FetchRequest {
                    key,
                    url: url.to_string(),
                    ttl_secs: 3600,
                    max_bytes: 2 * 1024 * 1024,
                    media_type: "application/json".into(),
                })
                .await?
        }
    };
    let document: Value = serde_json::from_slice(&captured.body)
        .map_err(|_| Error::integrity("Malformed crates.io search response."))?;
    let crates = document["crates"]
        .as_array()
        .filter(|v| v.len() <= 100)
        .ok_or_else(|| Error::integrity("Invalid crates.io search result list."))?;
    let count = page.limit.min(100 - within_page);
    let mut items = Vec::new();
    for package in crates.iter().skip(within_page).take(count) {
        let name = package["name"]
            .as_str()
            .ok_or_else(|| Error::integrity("Crate search result lacks a name."))?;
        validate_name(name)
            .map_err(|_| Error::integrity("Invalid crate name in search result."))?;
        let version = package["max_version"]
            .as_str()
            .ok_or_else(|| Error::integrity("Crate search result lacks a version."))?;
        validate_version(version)
            .map_err(|_| Error::integrity("Invalid version in crate search result."))?;
        items.push(json!({"id":format!("crate:{name}@{version}"),"name":name,"version":version,"description":package["description"],"url":format!("https://crates.io/crates/{name}/{version}")}));
    }
    let total = document["meta"]["total"]
        .as_u64()
        .ok_or_else(|| Error::integrity("Crate search total is absent."))?;
    let next = page.offset.saturating_add(items.len());
    Ok(
        json!({"items":items,"total":total,"offset":page.offset,"next_offset":if next>page.offset && (next as u64)<total {Some(next)}else{None},"capture":capture_json(&captured.capture,3600),"pagination_note":"Capture pins one upstream page of at most 100 results; crossing that boundary starts another captured provider page."}),
    )
}

async fn index(retrieval: &Retrieval, name: &str, captured: Option<&str>) -> Result<StoredCapture> {
    let path = sparse_path(name)?;
    let key = format!("cargo:index:{}", name.to_ascii_lowercase());
    match captured {
        Some(id) => {
            let stored = retrieval.read_capture(id).await?;
            ensure_capture(&stored, &key)?;
            Ok(stored)
        }
        None => {
            retrieval
                .get(FetchRequest {
                    key,
                    url: format!("https://index.crates.io/{path}"),
                    ttl_secs: 3600,
                    max_bytes: 16 * 1024 * 1024,
                    media_type: "application/x-ndjson".into(),
                })
                .await
        }
    }
}

pub fn version_record(bytes: &[u8], name: &str, version: &str) -> Result<Value> {
    validate_name(name)?;
    validate_version(version)?;
    let text =
        std::str::from_utf8(bytes).map_err(|_| Error::integrity("Sparse index is not UTF-8."))?;
    let mut selected = None;
    for (index, line) in text.lines().enumerate() {
        if index > 50_000 || line.len() > 1024 * 1024 {
            return Err(Error::capacity("Sparse-index record limit exceeded."));
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|_| Error::integrity("Malformed sparse-index record."))?;
        let actual_name = value["name"]
            .as_str()
            .ok_or_else(|| Error::integrity("Sparse-index name is absent."))?;
        if !actual_name.eq_ignore_ascii_case(name) {
            return Err(Error::integrity("Sparse-index crate identity mismatch."));
        }
        if value["vers"].as_str() == Some(version) {
            if selected.is_some() {
                return Err(Error::integrity("Duplicate version in sparse index."));
            }
            let checksum = value["cksum"]
                .as_str()
                .ok_or_else(|| Error::integrity("Sparse-index archive checksum is absent."))?;
            if checksum.len() != 64 || !checksum.bytes().all(|v| v.is_ascii_hexdigit()) {
                return Err(Error::integrity("Invalid sparse-index archive checksum."));
            }
            if !value["deps"].is_array()
                || !value["features"].is_object()
                || !value["yanked"].is_boolean()
            {
                return Err(Error::integrity(
                    "Sparse-index dependency, feature, or yanked metadata is absent.",
                ));
            }
            selected = Some(value);
        }
    }
    selected.ok_or_else(|| {
        Error::not_found("Requested crate version is absent from the captured index.")
    })
}

pub async fn metadata(retrieval: &Retrieval, input: MetadataInput) -> Result<Value> {
    validate_version(&input.version)?;
    let captured = index(retrieval, &input.name, input.capture.as_deref()).await?;
    let version = version_record(&captured.body, &input.name, &input.version)?;
    Ok(
        json!({"id":format!("crate:{}@{}",input.name,input.version),"metadata":version,"capture":capture_json(&captured.capture,3600),"url":format!("https://crates.io/crates/{}/{}",input.name,input.version),"dependency_scope":"published declarations; no dependency resolution, build, or execution"}),
    )
}

struct Sources {
    metadata: StoredCapture,
    archive: StoredCapture,
    checksum: String,
    root: String,
}

async fn sources(
    retrieval: &Retrieval,
    name: &str,
    version: &str,
    metadata_id: Option<&str>,
    archive_id: Option<&str>,
) -> Result<Sources> {
    validate_version(version)?;
    if metadata_id.is_some() != archive_id.is_some() {
        return Err(Error::invalid(
            "Supply both metadata_capture and archive_capture, or neither.",
        ));
    }
    let metadata = index(retrieval, name, metadata_id).await?;
    let record = version_record(&metadata.body, name, version)?;
    let checksum = record["cksum"]
        .as_str()
        .ok_or_else(|| Error::integrity("Archive checksum is absent."))?
        .to_ascii_lowercase();
    let canonical_name = record["name"]
        .as_str()
        .ok_or_else(|| Error::integrity("Crate name is absent."))?
        .to_owned();
    let key = format!(
        "cargo:archive:{}:{version}:{checksum}",
        canonical_name.to_ascii_lowercase()
    );
    let archive = match archive_id {
        Some(id) => { let stored = retrieval.read_capture(id).await?; ensure_capture(&stored,&key)?; stored },
        None => retrieval.get(FetchRequest { key,url:format!("https://static.crates.io/crates/{canonical_name}/{canonical_name}-{version}.crate"),ttl_secs:365*86400,max_bytes:archive::MAX_COMPRESSED,media_type:"application/gzip".into() }).await?,
    };
    Ok(Sources {
        metadata,
        archive,
        checksum,
        root: format!("{canonical_name}-{version}"),
    })
}

fn resource_uri(input: &SourceReadInput, metadata: &str, archive: &str) -> Result<String> {
    let mut url = url::Url::parse("devres://source/")
        .map_err(|_| Error::invalid("Invalid resource configuration."))?;
    url.query_pairs_mut()
        .append_pair("name", &input.name)
        .append_pair("version", &input.version)
        .append_pair("path", &input.path)
        .append_pair("metadata_capture", metadata)
        .append_pair("archive_capture", archive)
        .append_pair("offset", &input.offset.to_string())
        .append_pair("limit", &input.limit.to_string());
    let uri = url.to_string();
    if uri.len() > 16384 {
        return Err(Error::capacity("Source resource URI exceeds 16 KiB."));
    }
    Ok(uri)
}

pub fn source_input_from_uri(url: &url::Url) -> Result<SourceReadInput> {
    if url.path() != "" && url.path() != "/" {
        return Err(Error::invalid(
            "Source resources use query parameters only.",
        ));
    }
    let mut properties = serde_json::Map::new();
    for (key, value) in url.query_pairs() {
        if properties.contains_key(key.as_ref()) {
            return Err(Error::invalid("Duplicate source resource parameter."));
        }
        let parsed = if key == "offset" || key == "limit" {
            json!(
                value
                    .parse::<usize>()
                    .map_err(|_| Error::invalid("Invalid source resource page."))?
            )
        } else {
            json!(value)
        };
        properties.insert(key.into_owned(), parsed);
    }
    let input: SourceReadInput = serde_json::from_value(Value::Object(properties))
        .map_err(|_| Error::invalid("Invalid source resource arguments."))?;
    if input.metadata_capture.is_none() || input.archive_capture.is_none() {
        return Err(Error::invalid("Source resources must be capture-fixed."));
    }
    Ok(input)
}

pub async fn source_list(retrieval: &Retrieval, input: SourceListInput) -> Result<Value> {
    let page = Page {
        offset: input.offset,
        limit: input.limit,
    }
    .checked()?;
    let permit = archive::admit()?;
    let mut source = sources(
        retrieval,
        &input.name,
        &input.version,
        input.metadata_capture.as_deref(),
        input.archive_capture.as_deref(),
    )
    .await?;
    let inspected = archive::inspect_async(
        std::mem::take(&mut source.archive.body),
        source.checksum.clone(),
        source.root.clone(),
        None,
        permit,
    )
    .await?;
    let total = inspected.members.len();
    let mut files = Vec::new();
    for member in inspected
        .members
        .into_iter()
        .skip(page.offset)
        .take(page.limit)
    {
        let uri = resource_uri(
            &SourceReadInput {
                name: input.name.clone(),
                version: input.version.clone(),
                path: member.path.clone(),
                metadata_capture: None,
                archive_capture: None,
                offset: 0,
                limit: 32768,
            },
            &source.metadata.capture.id,
            &source.archive.capture.id,
        )?;
        files.push(json!({"path":member.path,"bytes":member.size,"resource_uri":uri}));
    }
    Ok(
        json!({"files":files,"total":total,"offset":page.offset,"next_offset":if page.offset.saturating_add(page.limit)<total{Some(page.offset+page.limit)}else{None},"metadata_capture":capture_json(&source.metadata.capture,3600),"archive_capture":capture_json(&source.archive.capture,365*86400),"checksum_verified":true,"license_notice":"Published crate contents retain their original licensing; inspect LICENSE/NOTICE and package metadata."}),
    )
}

pub async fn source_read(retrieval: &Retrieval, input: SourceReadInput) -> Result<Value> {
    if !archive::valid_relative_path(&input.path) {
        return Err(Error::invalid("Invalid source member path."));
    }
    let permit = archive::admit()?;
    let mut source = sources(
        retrieval,
        &input.name,
        &input.version,
        input.metadata_capture.as_deref(),
        input.archive_capture.as_deref(),
    )
    .await?;
    let inspected = archive::inspect_async(
        std::mem::take(&mut source.archive.body),
        source.checksum.clone(),
        source.root.clone(),
        Some(input.path.clone()),
        permit,
    )
    .await?;
    let body = inspected
        .selected
        .ok_or_else(|| Error::not_found("Source member not found."))?;
    let text = std::str::from_utf8(&body)
        .map_err(|_| Error::invalid("Selected source member is not UTF-8 text."))?;
    if text.contains('\0') {
        return Err(Error::invalid("Selected source member is binary."));
    }
    let page = text_page(text, input.offset, input.limit)?;
    let uri = resource_uri(
        &input,
        &source.metadata.capture.id,
        &source.archive.capture.id,
    )?;
    Ok(
        json!({"path":input.path,"page":page,"resource_uri":uri,"metadata_capture":capture_json(&source.metadata.capture,3600),"archive_capture":capture_json(&source.archive.capture,365*86400),"checksum_verified":true,"license_notice":"Published source retains its original copyright and licensing."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_paths_and_input_identity_are_bounded() {
        assert_eq!(sparse_path("A").unwrap(), "1/a");
        assert_eq!(sparse_path("Ab").unwrap(), "2/ab");
        assert_eq!(sparse_path("Abc").unwrap(), "3/a/abc");
        assert_eq!(sparse_path("Serde").unwrap(), "se/rd/serde");
        assert!(sparse_path("../serde").is_err());
        assert!(validate_version("^1.0").is_err());
    }
    #[test]
    fn exact_version_preserves_yanked_and_dependency_features() {
        let row = json!({"name":"test","vers":"1.0.0-beta.1","deps":[{"name":"dep","req":"^1","optional":true,"target":"cfg(unix)"}],"cksum":"a".repeat(64),"features":{"feature":["dep"]},"yanked":true});
        let parsed = version_record(row.to_string().as_bytes(), "test", "1.0.0-beta.1").unwrap();
        assert_eq!(parsed["deps"][0]["target"], "cfg(unix)");
        assert_eq!(parsed["yanked"], true);
        assert!(version_record(row.to_string().as_bytes(), "other", "1.0.0-beta.1").is_err());
        assert!(version_record(row.to_string().as_bytes(), "test", "1.0.0").is_err());
    }
    #[test]
    fn source_resource_requires_both_captures_and_unique_parameters() {
        assert!(
            source_input_from_uri(
                &url::Url::parse("devres://source?name=x&version=1.0.0&path=a").unwrap()
            )
            .is_err()
        );
        let url=url::Url::parse("devres://source?name=x&name=y&version=1.0.0&path=a&metadata_capture=a&archive_capture=b").unwrap();
        assert!(source_input_from_uri(&url).is_err());
    }

    #[test]
    fn maximum_percent_encoded_member_path_roundtrips_within_resource_budget() {
        let input = SourceReadInput {
            name: "example".into(),
            version: "1.0.0".into(),
            path: "#".repeat(4096),
            metadata_capture: None,
            archive_capture: None,
            offset: 0,
            limit: 32768,
        };
        let uri = resource_uri(&input, &"a".repeat(64), &"b".repeat(64)).unwrap();
        assert!(uri.len() > 8192 && uri.len() <= 16384);
        let decoded = source_input_from_uri(&url::Url::parse(&uri).unwrap()).unwrap();
        assert_eq!(decoded.path, input.path);
        assert_eq!(
            decoded.metadata_capture.as_deref(),
            Some("a".repeat(64).as_str())
        );
    }
}
