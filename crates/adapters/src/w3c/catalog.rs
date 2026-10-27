//! W3C API identities and evidence-qualified destinations. Inputs never execute.
use crate::w3c::git::Repo;
use devres_application::w3c::{Catalog, Standard};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

pub const METADATA_VERSION: u32 = 1;
pub const MAX_CATALOG: usize = 10_000;
pub const DOCUMENT_LICENSE: &str = "https://www.w3.org/copyright/document-license-2023/";

#[derive(Clone, Debug)]
pub enum ApiOperation {
    Catalog { page: u32 },
    Versions { shortname: String, page: u32 },
    Specification { shortname: String },
    Version { shortname: String, version: String },
}
impl ApiOperation {
    pub fn url(&self) -> Result<String> {
        let slug = |s: &str| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || b"-_ .".contains(&b) && b != b' ' && b != b'.'
                })
        };
        let result = match self {
            Self::Catalog { page } if (1..=1000).contains(page) => {
                format!("https://api.w3.org/specifications?page={page}&items=100")
            }
            Self::Versions { shortname, page } if slug(shortname) && (1..=1000).contains(page) => {
                format!(
                    "https://api.w3.org/specifications/{shortname}/versions?page={page}&items=100"
                )
            }
            Self::Specification { shortname } if slug(shortname) => {
                format!("https://api.w3.org/specifications/{shortname}")
            }
            Self::Version { shortname, version } if slug(shortname) && slug(version) => {
                format!("https://api.w3.org/specifications/{shortname}/versions/{version}")
            }
            _ => return Err(Error::invalid("Invalid W3C API selector.")),
        };
        Ok(result)
    }
}

pub fn public_https(value: &str) -> Result<Url> {
    if value.len() > 4096
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.contains(['\\', '%'])
        || value.contains("..")
    {
        return Err(Error::invalid("Invalid W3C destination."));
    }
    let url = Url::parse(value).map_err(|_| Error::invalid("Invalid W3C destination."))?;
    let host = url.host_str().unwrap_or_default();
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || !matches!(url.host(), Some(url::Host::Domain(_)))
        || !host.contains('.')
        || host == "localhost"
        || [
            ".localhost",
            ".local",
            ".internal",
            ".invalid",
            ".test",
            ".example",
        ]
        .iter()
        .any(|s| host.ends_with(s))
        || url.path().contains("//")
    {
        return Err(Error::invalid(
            "W3C destination must be a public HTTPS origin.",
        ));
    }
    Ok(url)
}
pub fn publication_host(host: &str) -> bool {
    host == "www.w3.org" || host == "w3.org" || host == "api.w3.org"
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicationUrl {
    url: String,
    host: String,
    #[serde(default)]
    qualification: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationKind {
    Html,
    Pdf,
    Text,
    Json,
    Xml,
    Raw,
}
impl PublicationKind {
    pub fn representation(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Pdf => "pdf",
            Self::Text => "text",
            Self::Json => "json",
            Self::Xml => "xml",
            Self::Raw => "raw",
        }
    }
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Html => "text/html",
            Self::Pdf => "application/pdf",
            Self::Text => "text/plain",
            Self::Json => "application/json",
            Self::Xml => "application/xml",
            Self::Raw => "application/octet-stream",
        }
    }
    pub fn has_projection(self) -> bool {
        !matches!(self, Self::Raw)
    }
}
impl PublicationUrl {
    /// Fixed W3C TR namespace; external destinations require captured official evidence.
    pub(crate) fn new(value: &str) -> Result<Self> {
        let normalized = value
            .strip_prefix("http://www.w3.org/")
            .map(|s| format!("https://www.w3.org/{s}"))
            .or_else(|| {
                value
                    .strip_prefix("http://w3.org/")
                    .map(|s| format!("https://w3.org/{s}"))
            });
        let value = normalized.as_deref().unwrap_or(value);
        let url = public_https(value)?;
        if !matches!(url.host_str(), Some("www.w3.org" | "w3.org"))
            || !url.path().starts_with("/TR/")
        {
            return Err(Error::invalid(
                "W3C publication needs official qualification.",
            ));
        }
        Self::qualified(value, "https://www.w3.org/TR/")
    }
    pub(crate) fn qualified(value: &str, evidence: &str) -> Result<Self> {
        let mut url = public_https(value)?;
        let evidence_url = public_https(evidence)?;
        if !matches!(
            evidence_url.host_str(),
            Some("www.w3.org" | "w3.org" | "api.w3.org")
        ) || !["/TR/", "/specifications"]
            .iter()
            .any(|p| evidence_url.path().starts_with(p))
        {
            return Err(Error::invalid(
                "W3C publication qualification is not official.",
            ));
        }
        url.set_fragment(None);
        Ok(Self {
            host: url.host_str().unwrap_or_default().into(),
            url: url.to_string(),
            qualification: evidence.into(),
        })
    }
    pub fn kind(&self) -> PublicationKind {
        let path = Url::parse(&self.url)
            .map(|u| u.path().to_ascii_lowercase())
            .unwrap_or_default();
        if path.ends_with(".pdf") {
            PublicationKind::Pdf
        } else if [
            ".txt",
            ".idl",
            ".bs",
            ".md",
            ".markdown",
            ".yaml",
            ".yml",
            ".csv",
            ".tsv",
            ".ttl",
            ".nt",
            ".nq",
            ".trig",
            ".rnc",
            ".rng",
            ".abnf",
            ".bnf",
            ".ebnf",
            ".n3",
            ".dtd",
            ".grammar",
            ".webidl",
        ]
        .iter()
        .any(|e| path.ends_with(e))
        {
            PublicationKind::Text
        } else if path.ends_with(".json") || path.ends_with(".jsonld") || path.ends_with(".json-ld")
        {
            PublicationKind::Json
        } else if [".xml", ".svg", ".xsd", ".rdf", ".xhtml", ".xht"]
            .iter()
            .any(|e| path.ends_with(e))
        {
            PublicationKind::Xml
        } else if path.ends_with('/')
            || path.ends_with(".html")
            || path.ends_with(".htm")
            || !path.rsplit('/').next().unwrap_or_default().contains('.')
        {
            PublicationKind::Html
        } else {
            PublicationKind::Raw
        }
    }
    pub fn as_str(&self) -> &str {
        &self.url
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn media_type(&self) -> &'static str {
        self.kind().media_type()
    }
    pub fn validate(&self) -> Result<()> {
        let check = Self::qualified(&self.url, &self.qualification)?;
        if check.host != self.host || check.url != self.url {
            return Err(Error::integrity("W3C destination identity mismatch."));
        }
        Ok(())
    }
    pub(crate) fn linked(&self, value: &str) -> Result<Self> {
        let url = public_https(value)?;
        let base = Url::parse(&self.url)
            .map_err(|_| Error::integrity("W3C publication origin invalid."))?;
        // A qualified draft may advertise same-origin siblings, never a new origin.
        if url.host_str() != base.host_str() {
            return Err(Error::invalid(
                "W3C linked document crosses its qualified origin.",
            ));
        }
        Self::qualified(value, &self.qualification)
    }
}
fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}
fn link<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get("_links")
        .and_then(|l| l.get(key))
        .and_then(|l| l.get("href"))
        .and_then(Value::as_str)
}
fn rows<'a>(data: &'a Value, kind: &str) -> Result<&'a Vec<Value>> {
    data.get("_embedded")
        .and_then(|v| v.get(kind))
        .and_then(Value::as_array)
        .or_else(|| {
            data.get("_links")
                .and_then(|v| v.get(kind))
                .and_then(Value::as_array)
        })
        .ok_or_else(|| Error::integrity("W3C API page has no expected collection."))
}
pub fn parse_page(bytes: &[u8], observed_at: i64) -> Result<Catalog> {
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(Error::capacity("W3C catalog page exceeds bounds."));
    }
    let data: Value =
        serde_json::from_slice(bytes).map_err(|_| Error::integrity("Malformed W3C catalog."))?;
    let mut standards = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows(&data, "specifications")? {
        if standards.len() >= MAX_CATALOG {
            return Err(Error::capacity("W3C catalog count exceeds bounds."));
        }
        let derived_id = link(row, "self")
            .or_else(|| text(row, "href"))
            .and_then(|u| u.trim_end_matches('/').rsplit('/').next());
        let id = text(row, "shortname")
            .or(derived_id)
            .filter(|v| {
                !v.is_empty()
                    && v.len() <= 128
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            })
            .ok_or_else(|| Error::integrity("W3C specification shortname missing."))?;
        if !seen.insert(id) {
            return Err(Error::integrity("Duplicate W3C specification identity."));
        }
        let title = text(row, "title")
            .filter(|v| !v.is_empty() && v.len() <= 4096)
            .ok_or_else(|| Error::integrity("W3C specification title missing."))?;
        let url = text(row, "shortlink")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("https://www.w3.org/TR/{id}/"));
        PublicationUrl::new(&url)?;
        let mut metadata =
            json!({"shortname":id,"title":title,"shortlink":url,"status":row["status"]});
        metadata["api_url"] = json!(format!("https://api.w3.org/specifications/{id}"));
        metadata["publication_url"] = json!(url);
        metadata["latest_tr_url"] = json!(url);
        metadata["license"] =
            json!({"decision":"unresolved","reason":"publication_notice_preflight_required"});
        if let Some(latest) = link(row, "latest-version") {
            metadata["latest_version_api"] = json!(latest);
        }
        standards.push(Standard {
            id: id.into(),
            title: title.into(),
            url,
            repository: String::new(),
            metadata,
        });
    }
    standards.sort_by(|a, b| a.id.cmp(&b.id));
    let id = crate::w3c::inventory::digest(
        &serde_json::to_vec(&(bytes, observed_at))
            .map_err(|_| Error::integrity("W3C catalog identity failed."))?,
    );
    Ok(Catalog {
        id,
        observed_at,
        standards,
        gaps: Vec::new(),
    })
}
pub fn parse(bytes: &[u8], observed_at: i64) -> Result<Catalog> {
    parse_page(bytes, observed_at)
}
pub fn page_has_next(bytes: &[u8]) -> Result<bool> {
    let data: Value = serde_json::from_slice(bytes)
        .map_err(|_| Error::integrity("Malformed W3C API pagination."))?;
    Ok(data["_links"]["next"]["href"].is_string())
}
pub fn parse_versions(bytes: &[u8], standard: &Standard) -> Result<Vec<Value>> {
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(Error::capacity("W3C version page exceeds bounds."));
    }
    let data: Value =
        serde_json::from_slice(bytes).map_err(|_| Error::integrity("Malformed W3C versions."))?;
    let mut result = Vec::new();
    for row in rows(&data, "version-history")? {
        if result.len() >= 10000 {
            return Err(Error::capacity("W3C version count exceeds bounds."));
        }
        let url = text(row, "uri")
            .or_else(|| text(row, "url"))
            .or_else(|| link(row, "self"));
        let mut version = row.clone();
        if let Some(url) = url.filter(|u| {
            u.starts_with("https://www.w3.org/TR/") || u.starts_with("https://w3.org/TR/")
        }) {
            PublicationUrl::new(url)?;
            version["publication_url"] = json!(url);
        }
        version["specification"] = json!(standard.id);
        result.push(version);
    }
    Ok(result)
}
pub fn current_publication(standard: &Standard) -> Result<PublicationUrl> {
    PublicationUrl::new(
        standard.metadata["publication_url"]
            .as_str()
            .unwrap_or(&standard.url),
    )
}
pub fn editor_publication(standard: &Standard) -> Option<PublicationUrl> {
    standard.metadata["editor_draft"]
        .as_str()
        .and_then(|u| PublicationUrl::qualified(u, &standard.url).ok())
}
pub fn source_publications(standard: &Standard, _paths: &[String]) -> Result<Vec<PublicationUrl>> {
    let mut result = Vec::new();
    if let Some(versions) = standard.metadata["versions"].as_array() {
        for v in versions {
            if let Some(u) = v["publication_url"].as_str() {
                result.push(PublicationUrl::new(u)?);
            }
        }
    }
    if let Some(editor) = editor_publication(standard) {
        result.push(editor);
    }
    Ok(result)
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdvertisementRole {
    EditionNavigation,
    DocumentNavigation,
    PublishedSupportData,
    ExplicitRepresentation,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicationAdvertisement {
    pub href: String,
    pub role: AdvertisementRole,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionRole {
    EmbeddedAsset,
    ExampleReference,
    MalformedLocalReference,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicationExclusion {
    pub href: String,
    pub role: ExclusionRole,
    pub source_anchor: Option<String>,
    pub target_anchor: Option<String>,
}
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PublicationMetadata {
    pub links: Vec<String>,
    #[serde(default)]
    pub identity_urls: Vec<String>,
    pub repositories: Vec<String>,
    pub advertisements: Vec<PublicationAdvertisement>,
    pub exclusions: Vec<PublicationExclusion>,
}
mod metadata;
pub fn publication_metadata(
    bytes: &[u8],
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<PublicationMetadata> {
    metadata::extract(bytes, cancel)
}
fn repository_url(value: &str) -> Option<String> {
    let url = public_https(value).ok()?;
    if url.fragment().is_some() || repository_mapping(value).is_err() {
        return None;
    }
    // Preserve source-route path evidence until the corpus resolves clone identity and scope.
    Some(url.to_string())
}
pub fn repository_mapping(value: &str) -> Result<(Repo, Value)> {
    let url = public_https(value)?;
    let parts = url.path().trim_matches('/').split('/').collect::<Vec<_>>();
    if url.host_str() == Some("github.com") {
        if parts.len() < 2 {
            return Err(Error::invalid(
                "W3C GitHub source repository is incomplete.",
            ));
        }
        let repo = Repo::new(&format!(
            "https://github.com/{}/{}.git",
            parts[0],
            parts[1].trim_end_matches(".git")
        ))?;
        if parts.len() > 2 && !matches!(parts[2], "tree" | "blob") {
            return Err(Error::invalid(
                "W3C repository admission excludes issue and administration routes.",
            ));
        }
        if parts.get(2) == Some(&"blob") && parts.len() < 5 {
            return Err(Error::invalid(
                "W3C GitHub editor source entrypoint is missing.",
            ));
        }
        let mapping = if matches!(parts.get(2), Some(&"tree" | &"blob")) && parts.len() >= 4 {
            let path = parts.get(4..).unwrap_or_default().join("/");
            if parts.get(2) == Some(&"blob") {
                let prefix = path
                    .rsplit_once('/')
                    .map(|(parent, _)| parent)
                    .unwrap_or("");
                json!({"kind":"explicit_source_path","ref":parts[3],"prefix":prefix,"entrypoint":path,"evidence_url":value})
            } else {
                json!({"kind":"explicit_source_path","ref":parts[3],"prefix":path,"evidence_url":value})
            }
        } else {
            json!({"kind":"repository_root","prefix":"","evidence_url":value})
        };
        return Ok((repo, mapping));
    }
    if url.path().contains("/-/issues") || url.path().contains("/-/merge_requests") {
        return Err(Error::invalid(
            "W3C source admission excludes issue-only endpoints.",
        ));
    }
    Ok((
        Repo::new(value)?,
        json!({"kind":"repository_root","prefix":"","evidence_url":value}),
    ))
}

pub fn qualified_advertised(
    standard: &Standard,
    base: &PublicationUrl,
    ads: &[PublicationAdvertisement],
) -> Vec<PublicationUrl> {
    let Ok(origin) = Url::parse(base.as_str()) else {
        return Vec::new();
    };
    let mut result = BTreeMap::new();
    for ad in ads {
        let Ok(url) = origin.join(&ad.href) else {
            continue;
        };
        let permitted = match ad.role {
            AdvertisementRole::EditionNavigation => {
                url.path() == format!("/TR/{}/", standard.id)
                    || url.path().contains(&format!("-{}-", standard.id))
                    || standard.metadata["versions"].as_array().is_some_and(|v| {
                        v.iter()
                            .any(|v| v["publication_url"].as_str() == Some(url.as_str()))
                    })
            }
            AdvertisementRole::DocumentNavigation => {
                url.host_str() == origin.host_str()
                    && url.path().starts_with(&edition_root_path(standard, base))
            }
            AdvertisementRole::PublishedSupportData | AdvertisementRole::ExplicitRepresentation => {
                true
            }
        };
        if permitted {
            let admitted = if url.host_str() == origin.host_str() {
                base.linked(url.as_str())
            } else {
                PublicationUrl::new(url.as_str())
            };
            if let Ok(u) = admitted {
                result.insert(u.as_str().to_owned(), u);
            }
        }
    }
    if let Ok(u) = current_publication(standard) {
        result.insert(u.as_str().to_owned(), u);
    }
    result.into_values().collect()
}
pub fn advertised(
    standard: &Standard,
    base: &PublicationUrl,
    links: &[String],
) -> Vec<PublicationUrl> {
    let ads = links
        .iter()
        .map(|s| PublicationAdvertisement {
            href: s.clone(),
            role: AdvertisementRole::DocumentNavigation,
        })
        .collect::<Vec<_>>();
    qualified_advertised(standard, base, &ads)
}

/// License evidence is established before raw bytes enter the permanent archive.
mod license;
pub fn publication_license(url: &PublicationUrl, bytes: &[u8]) -> Value {
    license::extract(url, bytes)
}
pub(crate) fn publication_license_with_cancel(
    url: &PublicationUrl,
    bytes: &[u8],
    cancel: tokio_util::sync::CancellationToken,
) -> Value {
    license::extract_cancel(url, bytes, cancel)
}

/// Fixed reviewed current notice, never fetched from source-selected URLs at runtime.
pub const W3C_SOFTWARE_NOTICE: &str = r#"By obtaining and/or copying this work, you (the licensee) agree that you have read, understood, and will comply with the following terms and conditions.
Permission to copy, modify, and distribute this work, with or without modification, for any purpose and without fee or royalty is hereby granted, provided that you include the following on ALL copies of the work or portions thereof, including modifications:
1. The full text of this NOTICE in a location viewable to users of the redistributed or derivative work.
2. Any pre-existing intellectual property disclaimers, notices, or terms and conditions. If none exist, the W3C software and document short notice should be included.
3. Notice of any changes or modifications, through a copyright statement on the new code or document such as "This software or document includes material copied from or derived from [title and URI of the W3C document]. Copyright © [$year-of-document] World Wide Web Consortium. https://www.w3.org/copyright/software-license-2023/"
THIS WORK IS PROVIDED "AS IS," AND COPYRIGHT HOLDERS MAKE NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO, WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF THE SOFTWARE OR DOCUMENT WILL NOT INFRINGE ANY THIRD PARTY PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.
COPYRIGHT HOLDERS WILL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF ANY USE OF THE SOFTWARE OR DOCUMENT.
The name and trademarks of copyright holders may NOT be used in advertising or publicity pertaining to the work without specific, written prior permission. Title to copyright in this work will at all times remain with copyright holders."#;

pub fn publication_status(standard: &Standard, url: &PublicationUrl, license: &Value) -> Value {
    if let Some(status) = license["publication_status"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        return json!(status);
    }
    if let Some(versions) = standard.metadata["versions"].as_array() {
        for row in versions {
            if row["publication_url"].as_str() == Some(url.as_str())
                || row["uri"].as_str() == Some(url.as_str())
            {
                return row["status"].clone();
            }
        }
    }
    if standard.metadata["latest_tr_url"].as_str() == Some(url.as_str()) {
        return standard.metadata["publication_status"].clone();
    }
    Value::Null
}

pub(crate) fn edition_root_path(standard: &Standard, base: &PublicationUrl) -> String {
    let Ok(url) = Url::parse(base.as_str()) else {
        return "/".into();
    };
    let parts = url.path().trim_matches('/').split('/').collect::<Vec<_>>();
    if matches!(url.host_str(), Some("www.w3.org" | "w3.org"))
        && parts.first() == Some(&"TR")
        && parts.len() >= 2
    {
        if parts[1].len() == 4 && parts[1].bytes().all(|b| b.is_ascii_digit()) && parts.len() >= 3 {
            return format!("/TR/{}/{}/", parts[1], parts[2]);
        }
        return format!("/TR/{}/", parts[1]);
    }
    if let Some(editor) = editor_publication(standard)
        .and_then(|u| Url::parse(u.as_str()).ok())
        .filter(|u| u.host_str() == url.host_str())
    {
        let root = if editor.path().ends_with('/') {
            editor.path().to_owned()
        } else {
            format!(
                "{}/",
                editor.path().rsplit_once('/').map(|p| p.0).unwrap_or("")
            )
        };
        if url.path().starts_with(&root) {
            return root;
        }
    }
    if url.path().ends_with('/') {
        url.path().to_owned()
    } else {
        format!(
            "{}/",
            url.path().rsplit_once('/').map(|p| p.0).unwrap_or("")
        )
    }
}
#[cfg(test)]
mod edition_root_tests {
    use super::*;
    #[test]
    fn nested_chapters_share_segment_safe_edition_root() {
        let standard = Standard {
            id: "example".into(),
            title: "Example".into(),
            url: "https://www.w3.org/TR/example/".into(),
            repository: String::new(),
            metadata: json!({}),
        };
        let base = PublicationUrl::new("https://www.w3.org/TR/example/part1/page.html").unwrap();
        let ads = vec![
            PublicationAdvertisement {
                href: "../part2/page.html".into(),
                role: AdvertisementRole::DocumentNavigation,
            },
            PublicationAdvertisement {
                href: "/TR/example-other/foreign.html".into(),
                role: AdvertisementRole::DocumentNavigation,
            },
        ];
        let found = qualified_advertised(&standard, &base, &ads);
        assert!(
            found
                .iter()
                .any(|u| u.as_str().ends_with("/TR/example/part2/page.html"))
        );
        assert!(!found.iter().any(|u| u.as_str().contains("example-other")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tr_identity_and_external_qualification() {
        let c=parse(br#"{"_embedded":{"specifications":[{"shortname":"example","title":"Example","shortlink":"https://www.w3.org/TR/example/"}]}}"#,42).unwrap();
        assert_eq!(c.standards[0].id, "example");
        assert!(c.standards[0].repository.is_empty());
        assert!(PublicationUrl::new("https://drafts.csswg.org/css-align/").is_err());
        assert!(
            PublicationUrl::qualified(
                "https://drafts.csswg.org/css-align/",
                "https://www.w3.org/TR/css-align-3/"
            )
            .unwrap()
            .validate()
            .is_ok()
        );
    }
    #[test]
    fn qualification_rejects_private_syntax() {
        for u in [
            "http://127.0.0.1/TR/a/",
            "https://127.0.0.1/TR/a/",
            "https://host.local/TR/a/",
            "https://user@www.w3.org/TR/a/",
            "https://www.w3.org/TR/%2e%2e/",
        ] {
            assert!(PublicationUrl::new(u).is_err());
        }
    }
    #[test]
    fn historical_w3c_http_identifiers_capture_through_https_only() {
        let url = PublicationUrl::new("http://www.w3.org/TR/1998/REC-example/").unwrap();
        assert_eq!(url.as_str(), "https://www.w3.org/TR/1998/REC-example/");
        assert!(url.validate().is_ok());
    }
    #[test]
    fn notice_required_before_archival() {
        let u = PublicationUrl::new("https://www.w3.org/TR/example/").unwrap();
        assert_eq!(
            publication_license(&u, b"unlicensed")["decision"],
            "unresolved"
        );
        assert_eq!(
            publication_license(&u, DOCUMENT_LICENSE.as_bytes())["decision"],
            "unresolved"
        );
    }
    #[test]
    fn ordinary_citations_are_not_acquisition_advertisements() {
        let data=publication_metadata(b"<h1>Report</h1><p>See <a href='/TR/unrelated/'>other</a><a href='ordinary.html'>link</a><a href='ordinary.pdf'>PDF</a></p>",&tokio_util::sync::CancellationToken::new()).unwrap();
        assert!(data.advertisements.is_empty());
        assert_eq!(data.links.len(), 3);
    }
    #[test]
    fn api_selector_never_accepts_url_input() {
        assert!(
            ApiOperation::Versions {
                shortname: "../private".into(),
                page: 1
            }
            .url()
            .is_err()
        );
        assert_eq!(
            ApiOperation::Catalog { page: 1 }.url().unwrap(),
            "https://api.w3.org/specifications?page=1&items=100"
        );
    }
}

#[cfg(test)]
mod publisher_editor_source_tests {
    use super::*;
    #[test]
    fn bikeshed_suggest_edit_header_preserves_canonical_repository_and_file_scope() {
        // Shape observed in the licensed CSS Color4 dated TR; metadata only.
        let body=b"<div class=head><h1>CSS Color Module Level 4</h1><dl><dt>Suggest an Edit for this Spec:\n<dd><a href='https://github.com/w3c/csswg-drafts/blob/main/css-color-4/Overview.bs'>GitHub Editor</a><dt>Test Suite:<dd><a href='https://wpt.fyi/results/css/css-color/'>Tests</a></dl></div><h2>Body</h2>";
        let metadata =
            publication_metadata(body, &tokio_util::sync::CancellationToken::new()).unwrap();
        assert_eq!(
            metadata.repositories,
            vec!["https://github.com/w3c/csswg-drafts/blob/main/css-color-4/Overview.bs"]
        );
        let (repo, mapping) = repository_mapping(&metadata.repositories[0]).unwrap();
        assert_eq!(repo.as_str(), "https://github.com/w3c/csswg-drafts.git");
        assert_eq!(mapping["prefix"], "css-color-4");
        assert_eq!(mapping["entrypoint"], "css-color-4/Overview.bs");
        assert_eq!(mapping["ref"], "main");
    }
    #[test]
    fn feedback_issue_routes_body_examples_and_general_body_do_not_admit_editor_sources() {
        let source = "<a href='https://github.com/w3c/csswg-drafts/blob/main/css-color-4/Overview.bs'>GitHub Editor</a>";
        for body in [
            format!("<div class=head><dl><dt>Feedback:<dd>{source}</dl></div>"),
            "<div class=head><dl><dt>Suggest an Edit for this Spec:<dd><a href='https://github.com/w3c/csswg-drafts/issues'>GitHub Editor</a></dl></div>".to_owned(),
            format!(
                "<h1>Body</h1><h2>Examples</h2><dl><dt>Suggest an Edit for this Spec:<dd>{source}</dl>"
            ),
            format!(
                "<div class=head><div class=example><dl><dt>Suggest an Edit for this Spec:<dd>{source}</dl></div></div>"
            ),
            format!(
                "<h1>Body</h1><p>Example</p><dl><dt>Suggest an Edit for this Spec:<dd>{source}</dl>"
            ),
        ] {
            let metadata =
                publication_metadata(body.as_bytes(), &tokio_util::sync::CancellationToken::new())
                    .unwrap();
            assert!(metadata.repositories.is_empty(), "{body}");
        }
        assert!(repository_mapping("https://github.com/w3c/csswg-drafts/issues").is_err());
    }
    #[test]
    fn root_editor_file_and_tree_directory_keep_distinct_scope_semantics() {
        let (_, file) =
            repository_mapping("https://github.com/w3c/permissions/blob/main/index.html").unwrap();
        assert_eq!(file["prefix"], "");
        assert_eq!(file["entrypoint"], "index.html");
        let (_, tree) =
            repository_mapping("https://github.com/w3c/csswg-drafts/tree/main/css-color-4")
                .unwrap();
        assert_eq!(tree["prefix"], "css-color-4");
        assert!(tree.get("entrypoint").is_none());
    }
}

#[cfg(test)]
mod retained_editor_source_fixture {
    use super::*;
    #[test]
    #[ignore = "requires explicit retained licensed CSS capture under /tmp; performs no requests"]
    fn retained_licensed_css_editor_source_reprocesses_without_network() {
        let path = std::env::var("DEVRES_W3C_RETAINED_HEADER_FIXTURE")
            .expect("explicit retained licensed capture path");
        let path = std::path::Path::new(&path).canonicalize().unwrap();
        assert!(path.starts_with("/tmp"));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 1049399);
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            crate::w3c::inventory::digest(&bytes),
            "a5cef4674c085a5b568773e85affceb20a3c0d121dff371f3dd555fd51ac02f4"
        );
        let url =
            PublicationUrl::new("https://www.w3.org/TR/2026/CRD-css-color-4-20261026/").unwrap();
        assert_eq!(publication_license(&url, &bytes)["decision"], "approved");
        let metadata =
            publication_metadata(&bytes, &tokio_util::sync::CancellationToken::new()).unwrap();
        let mapping = metadata
            .repositories
            .iter()
            .filter_map(|source| repository_mapping(source).ok())
            .find(|(repo, _)| repo.as_str() == "https://github.com/w3c/csswg-drafts.git")
            .expect("publisher-qualified CSS source repository");
        assert_eq!(mapping.1["prefix"], "css-color-4");
        assert_eq!(mapping.1["entrypoint"], "css-color-4/Overview.bs");
        assert_eq!(mapping.1["ref"], "main");
    }
}
