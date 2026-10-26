//! Official-catalog parsing and typed publication destinations. No document executes.
use crate::whatwg_git::Repo;
use devres_application::whatwg::{Catalog, Standard};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use url::Url;

pub const CATALOG_REPOSITORY: &str = "whatwg/sg";
pub const CATALOG_PATH: &str = "db.json";
pub const METADATA_VERSION: u32 = 3;

pub fn publication_host(host: &str) -> bool {
    host.strip_suffix(".spec.whatwg.org")
        .is_some_and(valid_slug)
        || host == "w3c-cg.github.io"
}
fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Constructed only from catalogue-qualified publication discovery, never tool input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicationUrl {
    url: String,
    host: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationKind {
    Html,
    Pdf,
    Text,
    Json,
    Raw,
}
impl PublicationKind {
    pub fn representation(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Pdf => "pdf",
            Self::Text => "text",
            Self::Json => "json",
            Self::Raw => "raw",
        }
    }
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Html => "text/html",
            Self::Pdf => "application/pdf",
            Self::Text => "text/plain",
            Self::Json => "application/json",
            Self::Raw => "application/octet-stream",
        }
    }
    pub fn has_projection(self) -> bool {
        matches!(self, Self::Html | Self::Pdf | Self::Text)
    }
}
impl PublicationUrl {
    pub fn kind(&self) -> PublicationKind {
        let Ok(url) = Url::parse(&self.url) else {
            return PublicationKind::Raw;
        };
        let path = url.path().to_ascii_lowercase();
        if path.ends_with(".pdf") {
            PublicationKind::Pdf
        } else if path.ends_with(".txt") || path.ends_with(".idl") {
            PublicationKind::Text
        } else if path.ends_with(".json") {
            PublicationKind::Json
        } else if path.ends_with('/') || path.ends_with(".html") || path.ends_with(".htm") {
            PublicationKind::Html
        } else {
            PublicationKind::Raw
        }
    }
    pub fn media_type(&self) -> &'static str {
        self.kind().media_type()
    }
    pub(crate) fn new(value: &str) -> Result<Self> {
        if value.len() > 4096
            || value.trim() != value
            || value.contains('\\')
            || value.chars().any(char::is_control)
            || value.contains('%')
            || value.contains("..")
        {
            return Err(Error::invalid("Invalid WHATWG publication URL."));
        }
        let mut url =
            Url::parse(value).map_err(|_| Error::invalid("Invalid WHATWG publication URL."))?;
        let host = url.host_str().unwrap_or_default().to_owned();
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.query().is_some()
            || !publication_host(&host)
            || url.path().contains("..")
            || url.path().contains("//")
            || (host == "w3c-cg.github.io" && !url.path().starts_with("/web-nfc/"))
        {
            return Err(Error::invalid(
                "WHATWG publication destination is not permitted.",
            ));
        }
        url.set_fragment(None);
        Ok(Self {
            url: url.to_string(),
            host,
        })
    }
    pub fn as_str(&self) -> &str {
        &self.url
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn validate(&self) -> Result<()> {
        let checked = Self::new(&self.url)?;
        if checked.host != self.host {
            return Err(Error::integrity("Invalid retained WHATWG destination."));
        }
        Ok(())
    }
}

fn explicit_repository(row: &Value) -> Result<Option<String>> {
    for key in ["repository", "source_repository", "repo"] {
        if let Some(value) = row.get(key) {
            let value = value
                .as_str()
                .ok_or_else(|| Error::integrity("Invalid WHATWG repository metadata."))?;
            let identity = if let Some(identity) = value.strip_prefix("https://github.com/") {
                identity.trim_end_matches('/').trim_end_matches(".git")
            } else {
                value
            };
            let repo = Repo::new(identity)?;
            return Ok(Some(repo.as_str()));
        }
    }
    Ok(None)
}

/// Preserve original catalogue metadata; the host, not workstream, owns identity.
pub fn parse(bytes: &[u8], observed_at: i64) -> Result<Catalog> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(Error::capacity("WHATWG catalog exceeds its bound."));
    }
    let data: Value =
        serde_json::from_slice(bytes).map_err(|_| Error::integrity("Malformed WHATWG catalog."))?;
    let workstreams = data["workstreams"]
        .as_array()
        .ok_or_else(|| Error::integrity("WHATWG workstreams missing."))?;
    if workstreams.len() > 256 {
        return Err(Error::capacity(
            "WHATWG workstream count exceeds its bound.",
        ));
    }
    let mut standards = Vec::new();
    let mut seen = BTreeSet::new();
    let mut gaps = Vec::new();
    for workstream in workstreams {
        let rows = workstream["standards"]
            .as_array()
            .ok_or_else(|| Error::integrity("WHATWG standards missing."))?;
        for row in rows {
            if standards.len() >= 256 {
                return Err(Error::capacity("WHATWG catalog count exceeds its bound."));
            }
            let href = row["href"]
                .as_str()
                .ok_or_else(|| Error::integrity("WHATWG standard URL missing."))?;
            let url = PublicationUrl::new(href)?;
            let id = url
                .host()
                .strip_suffix(".spec.whatwg.org")
                .filter(|id| valid_slug(id))
                .ok_or_else(|| Error::integrity("WHATWG catalog identity is not a standard host."))?
                .to_owned();
            if !seen.insert(id.clone()) {
                return Err(Error::integrity("Duplicate WHATWG standard identity."));
            }
            let title = row["name"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 1024)
                .ok_or_else(|| Error::integrity("WHATWG standard name missing."))?
                .to_owned();
            let repository = explicit_repository(row)?.unwrap_or_else(|| {
                if id == "nfc" {
                    "w3c-cg/web-nfc".into()
                } else {
                    format!("whatwg/{id}")
                }
            });
            Repo::new(&repository)?;
            let mut metadata = row.clone();
            if id == "nfc" {
                metadata["publication_url"] = json!("https://w3c-cg.github.io/web-nfc/");
                metadata["listed_publication_url"] = json!(href);
                metadata["predecessor_publication_url"] =
                    json!("https://w3c-cg.github.io/web-nfc/");
                metadata["repository_policy"] = json!("reviewed_predecessor_mapping");
            } else {
                metadata["repository_policy"] = json!(if explicit_repository(row)?.is_some() {
                    "explicit_catalog_metadata"
                } else {
                    "whatwg_standard_host"
                });
            }
            standards.push(Standard {
                id,
                title,
                url: url.as_str().into(),
                repository,
                metadata,
            });
        }
    }
    if standards.is_empty() {
        return Err(Error::integrity("Empty WHATWG catalog."));
    }
    standards.sort_by(|a, b| a.id.cmp(&b.id));
    if !seen.contains("nfc") {
        gaps.push(json!({"code":"predecessor_absent","standard":"nfc"}));
    }
    let id = crate::whatwg_inventory::digest(
        &serde_json::to_vec(&(bytes, observed_at))
            .map_err(|_| Error::integrity("Invalid WHATWG catalog identity."))?,
    );
    Ok(Catalog {
        id,
        observed_at,
        standards,
        gaps,
    })
}

pub fn current_publication(standard: &Standard) -> Result<PublicationUrl> {
    if let Some(url) = standard.metadata["publication_url"].as_str() {
        return PublicationUrl::new(url);
    }
    let url = PublicationUrl::new(&standard.url)?;
    // HTML's full single-page edition supplies all sections; preserve multipage too.
    if standard.id == "html" {
        return PublicationUrl::new("https://html.spec.whatwg.org/");
    }
    Ok(url)
}

fn known_document_path(standard: &Standard, path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let family = lower.starts_with("/review-drafts/")
        || lower.starts_with("/commit-snapshots/")
        || lower.starts_with("/multipage/")
        || lower.starts_with("/dev/");
    family && (lower.ends_with(".html") || lower.ends_with(".htm"))
        || standard.id == "bluetooth" && matches!(path, "/scanning.html" | "/tests.html")
}

fn edition_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let path = path.trim_start_matches('/');
    if matches!(
        path,
        "dev/" | "multipage/" | "single-page.html" | "single-page/"
    ) {
        return true;
    }
    let Some(directory) = path.strip_suffix('/') else {
        return false;
    };
    if let Some(date) = directory.strip_prefix("review-drafts/") {
        return date.len() == 7
            && date.as_bytes()[4] == b'-'
            && date[..4]
                .bytes()
                .chain(date[5..].bytes())
                .all(|b| b.is_ascii_digit())
            && date[5..]
                .parse::<u8>()
                .is_ok_and(|month| (1..=12).contains(&month));
    }
    directory
        .strip_prefix("commit-snapshots/")
        .is_some_and(|commit| {
            !commit.is_empty()
                && commit.len() <= 128
                && commit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        })
}

/// Follow positive source-role advertisements; HTTP status never qualifies a link.
pub fn qualified_advertised(
    standard: &Standard,
    base: &PublicationUrl,
    advertisements: &[PublicationAdvertisement],
) -> Vec<PublicationUrl> {
    if base.kind() != PublicationKind::Html {
        return Vec::new();
    }
    let Ok(origin) = Url::parse(base.as_str()) else {
        return Vec::new();
    };
    let mut found = std::collections::BTreeMap::new();
    for advertisement in advertisements {
        let Ok(url) = origin.join(&advertisement.href) else {
            continue;
        };
        if url.host_str() != Some(base.host()) {
            continue;
        }
        let path = url.path();
        let lower = path.to_ascii_lowercase();
        let accepted = match advertisement.role {
            AdvertisementRole::EditionNavigation => edition_path(path),
            AdvertisementRole::DocumentNavigation => known_document_path(standard, path),
            AdvertisementRole::PublishedSupportData => {
                lower.ends_with(".txt") || lower.ends_with(".idl") || lower.ends_with(".json")
            }
            AdvertisementRole::ExplicitRepresentation => true,
        };
        if accepted && let Ok(value) = PublicationUrl::new(url.as_str()) {
            found.insert(value.as_str().to_owned(), value);
        }
    }
    // These are reviewed catalog seeds, not source-edge witnesses.
    for seed in [
        PublicationUrl::new(&standard.url),
        current_publication(standard),
    ]
    .into_iter()
    .flatten()
    {
        found.insert(seed.as_str().to_owned(), seed);
    }
    found.into_values().collect()
}

/// Strict legacy route wrapper. Runtime discovery consumes typed source roles.
pub fn advertised(
    standard: &Standard,
    base: &PublicationUrl,
    links: &[String],
) -> Vec<PublicationUrl> {
    if base.kind() != PublicationKind::Html {
        return Vec::new();
    }
    let Ok(origin) = Url::parse(base.as_str()) else {
        return Vec::new();
    };
    let mut found = std::collections::BTreeMap::new();
    for link in links {
        let Ok(url) = origin.join(link) else {
            continue;
        };
        if url.host_str() != Some(base.host()) {
            continue;
        }
        let path = url.path();
        let lower = path.to_ascii_lowercase();
        let publication = lower.ends_with(".pdf")
            || edition_path(path)
            || known_document_path(standard, path)
            || ((lower.ends_with(".txt") || lower.ends_with(".idl") || lower.ends_with(".json"))
                && (lower.contains("/review-drafts/") || lower.contains("/commit-snapshots/")));
        if !publication {
            continue;
        }
        if let Ok(value) = PublicationUrl::new(url.as_str()) {
            found.insert(value.as_str().to_owned(), value);
        }
    }
    if let Ok(original) = PublicationUrl::new(&standard.url) {
        found.insert(original.as_str().to_owned(), original);
    }
    found.into_values().collect()
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
    pub repositories: Vec<String>,
    pub advertisements: Vec<PublicationAdvertisement>,
    pub exclusions: Vec<PublicationExclusion>,
}
mod metadata;

/// Extract bounded source metadata and role-qualified publication edges, without execution.
pub fn publication_metadata(
    bytes: &[u8],
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<PublicationMetadata> {
    metadata::extract(bytes, cancel)
}

fn repository_url(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Repo::new(url.path().trim_matches('/').trim_end_matches(".git"))
        .ok()
        .map(|r| r.as_str())
}

/// Review draft filenames are an official publication inventory, unlike guessed commit URLs.
pub fn source_publications(standard: &Standard, paths: &[String]) -> Result<Vec<PublicationUrl>> {
    let base = current_publication(standard)?;
    let origin = Url::parse(base.as_str())
        .map_err(|_| Error::integrity("Invalid WHATWG standard origin."))?;
    let mut urls = Vec::new();
    for path in paths {
        let Some(name) = path.strip_prefix("review-drafts/") else {
            continue;
        };
        let Some(date) = name
            .strip_suffix(".bs")
            .or_else(|| name.strip_suffix(".wattsi"))
        else {
            continue;
        };
        let bytes = date.as_bytes();
        if bytes.len() != 7
            || bytes[4] != b'-'
            || !bytes[..4].iter().chain(&bytes[5..]).all(u8::is_ascii_digit)
            || !date[5..]
                .parse::<u8>()
                .is_ok_and(|month| (1..=12).contains(&month))
        {
            continue;
        }
        let url = origin
            .join(&format!("/review-drafts/{date}/"))
            .map_err(|_| Error::integrity("Invalid WHATWG review draft publication."))?;
        urls.push(PublicationUrl::new(url.as_str())?);
    }
    Ok(urls)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standard_identity_and_foreign_repository_require_catalog_metadata() {
        let body=br#"{"workstreams":[{"id":"fetch","standards":[{"name":"Cookie Store","href":"https://cookiestore.spec.whatwg.org/"},{"name":"Foreign","href":"https://foreign.spec.whatwg.org/","repository":"https://github.com/example/standard.git"},{"name":"Web NFC","href":"https://nfc.spec.whatwg.org/"}]}]}"#;
        let catalog = parse(body, 42).expect("catalog");
        assert_eq!(catalog.standards[0].id, "cookiestore");
        assert_eq!(catalog.standards[0].repository, "whatwg/cookiestore");
        assert_eq!(catalog.standards[1].repository, "example/standard");
        assert_eq!(catalog.standards[2].repository, "w3c-cg/web-nfc");
        for url in [
            "https://evil.invalid/",
            "http://dom.spec.whatwg.org/",
            "https://user@dom.spec.whatwg.org/",
            "https://w3c-cg.github.io/other/",
            "https://dom.spec.whatwg.org/%2e%2e/private",
        ] {
            assert!(PublicationUrl::new(url).is_err(), "{url}");
        }
    }
    #[test]
    fn publication_routes_preserve_media_and_capture_family_without_pruning_data() {
        for (path, kind, representation, media) in [
            ("/", PublicationKind::Html, "html", "text/html"),
            (
                "/review-drafts/2026-07/",
                PublicationKind::Html,
                "html",
                "text/html",
            ),
            ("/chapter.HTM", PublicationKind::Html, "html", "text/html"),
            ("/print.PDF", PublicationKind::Pdf, "pdf", "application/pdf"),
            (
                "/review-drafts/2026-07/data.txt",
                PublicationKind::Text,
                "text",
                "text/plain",
            ),
            ("/api.IDL", PublicationKind::Text, "text", "text/plain"),
            (
                "/review-drafts/2026-07/data.json",
                PublicationKind::Json,
                "json",
                "application/json",
            ),
            (
                "/opaque.bin",
                PublicationKind::Raw,
                "raw",
                "application/octet-stream",
            ),
        ] {
            let url = PublicationUrl::new(&format!("https://encoding.spec.whatwg.org{path}"))
                .expect("qualified URL");
            assert_eq!(url.kind(), kind);
            assert_eq!(kind.representation(), representation);
            assert_eq!(url.media_type(), media);
        }
        let standard = Standard {
            id: "encoding".into(),
            title: "Encoding".into(),
            url: "https://encoding.spec.whatwg.org/".into(),
            repository: "whatwg/encoding".into(),
            metadata: json!({}),
        };
        let base = PublicationUrl::new(&standard.url).expect("base");
        let links = vec![
            "/review-drafts/2026-07/data.txt".into(),
            "/review-drafts/2026-07/data.json".into(),
        ];
        let discovered = advertised(&standard, &base, &links);
        assert!(discovered.iter().any(|u| u.kind() == PublicationKind::Text));
        assert!(discovered.iter().any(|u| u.kind() == PublicationKind::Json));
        assert!(
            advertised(
                &standard,
                &PublicationUrl::new(
                    "https://encoding.spec.whatwg.org/review-drafts/2026-07/data.txt"
                )
                .expect("text"),
                &links
            )
            .is_empty()
        );
    }
    #[test]
    fn source_metadata_ignores_tests_scripts_templates_and_body_examples() {
        let bytes=br#"<!doctype html><meta name=repository content=https://github.com/owner/explicit><script><meta name=repository content=https://github.com/evil/script></script><template><meta name=repository content=https://github.com/evil/template></template><body><dl><dt>Participate:<dd><a href=https://github.com/foreign/standard>Source</a><dt>Tests:</dt><dd><a href=https://github.com/test/suite>Tests</a></dd><dt>Resources:</dt><dd><a href=https://github.com/evil/resource>Resource</a></dd></dl><h2 id=body>Body</h2><meta name=repository content=https://github.com/evil/body><a href=https://github.com/evil/example>Example</a>"#;
        let metadata = publication_metadata(bytes, &tokio_util::sync::CancellationToken::new())
            .expect("metadata");
        assert_eq!(
            metadata.repositories,
            vec!["foreign/standard", "owner/explicit"]
        );
        assert!(
            !metadata
                .links
                .iter()
                .any(|link| link.contains("evil/script"))
        );
    }
    #[test]
    fn large_inert_data_href_and_body_definitions_do_not_hide_publications() {
        let body = format!(
            "<body><dl><dt>Participate:<dd><a href=https://github.com/whatwg/html>GitHub</a></dl><h2>Body</h2><dt>{}</dt><a href=\"data:application/xml-dtd;base64,{}\">DTD</a><a href=/review-drafts/2026-07/#anchor>Draft</a><a href=/review-drafts/2026-07/#another>Draft</a>",
            "ordinary body definition ".repeat(100),
            "A".repeat(79_900)
        );
        let metadata =
            publication_metadata(body.as_bytes(), &tokio_util::sync::CancellationToken::new())
                .expect("bounded inert tag");
        assert_eq!(metadata.repositories, vec!["whatwg/html"]);
        assert_eq!(metadata.links.len(), 4);
        assert!(metadata.links.iter().any(|href| href.starts_with("data:")));
        assert!(
            metadata
                .links
                .contains(&"/review-drafts/2026-07/#anchor".into())
        );
        assert!(
            metadata
                .links
                .contains(&"/review-drafts/2026-07/#another".into())
        );
        assert_eq!(metadata.advertisements.len(), 1);
        assert_eq!(metadata.advertisements[0].href, "/review-drafts/2026-07/");
        let too_large = format!(
            "<a href=\"data:text/plain,{}\">inert</a>",
            "A".repeat(129 * 1024)
        );
        assert_eq!(
            publication_metadata(
                too_large.as_bytes(),
                &tokio_util::sync::CancellationToken::new()
            )
            .expect_err("bounded token")
            .code,
            "capacity"
        );
    }
    #[test]
    fn modern_header_source_labels_exclude_test_and_body_repositories() {
        let source=br#"<header id=head class=head><nav><a href=https://github.com/foreign/standard><strong>Contribute on GitHub</strong><code>foreign/standard repository</code></a><a href=https://github.com/tests/suite>Tests</a></nav></header><p><a href=https://github.com/body/example>Source repository</a></p><h2>Body</h2><div class=head><dl><dt>Source:<dd><a rel=source href=https://github.com/evil/reopened>Body example</a></dl></div>"#;
        let metadata = publication_metadata(source, &tokio_util::sync::CancellationToken::new())
            .expect("header metadata");
        assert_eq!(metadata.repositories, vec!["foreign/standard"]);
    }
    fn html_standard() -> Standard {
        Standard {
            id: "html".into(),
            title: "HTML".into(),
            url: "https://html.spec.whatwg.org/".into(),
            repository: "whatwg/html".into(),
            metadata: json!({}),
        }
    }
    #[test]
    fn source_roles_separate_image_examples_and_missing_fragment_references() {
        let source = br#"<header id=head class=head><h1>HTML</h1></header>
<h3 id=content>Content</h3><div class=example><p>In the following example we have
<a href=images/parsing-model-overview.svg>a flowchart</a> in image form.</p></div>
<p>A page restored from <a href=note-bfcache>back/forward cache</a>.</p>
<p>As explained <a href=speculative-loading-state-partitioning>below</a>.</p>
<div id=note-bfcache class=note>Note.</div><h5 id=speculative-loading-state-partitioning>Partitioning</h5>
<p><a href=unknown-publication>Unknown target must remain unresolved.</a></p>"#;
        let metadata = publication_metadata(source, &tokio_util::sync::CancellationToken::new())
            .expect("source roles");
        assert!(metadata.advertisements.is_empty());
        assert_eq!(metadata.exclusions.len(), 3);
        let asset = metadata
            .exclusions
            .iter()
            .find(|edge| edge.href.ends_with(".svg"))
            .expect("asset");
        assert_eq!(asset.role, ExclusionRole::EmbeddedAsset);
        assert_eq!(asset.source_anchor.as_deref(), Some("content"));
        for href in ["note-bfcache", "speculative-loading-state-partitioning"] {
            let reference = metadata
                .exclusions
                .iter()
                .find(|edge| edge.href == href)
                .expect("reference");
            assert_eq!(reference.role, ExclusionRole::MalformedLocalReference);
            assert_eq!(reference.target_anchor.as_deref(), Some(href));
            assert!(metadata.links.iter().any(|raw| raw == href));
        }
        assert!(
            !metadata
                .exclusions
                .iter()
                .any(|edge| edge.href == "unknown-publication")
        );
        let standard = html_standard();
        let base = PublicationUrl::new("https://html.spec.whatwg.org/review-drafts/2025-01/")
            .expect("base");
        let targets = qualified_advertised(&standard, &base, &metadata.advertisements);
        assert!(
            !targets
                .iter()
                .any(|url| url.as_str().contains("note-bfcache") || url.as_str().ends_with(".svg"))
        );
        // This policy has no response-status input: a successfully served illustration
        // remains an illustration, and a missing explicit publication remains advertised.
        assert!(
            !advertised(
                &standard,
                &base,
                &[
                    "images/parsing-model-overview.svg".into(),
                    "note-bfcache".into()
                ]
            )
            .iter()
            .any(|url| url.as_str().ends_with(".svg") || url.as_str().contains("note-bfcache"))
        );
    }
    #[test]
    fn positive_alternates_and_published_data_survive_source_qualification() {
        let source = br#"<header id=head class=head><link rel=ALTERNATE type=application/octet-stream href=opaque-edition></header>
<h3 id=body>Body</h3><div id=opaque-edition>Local ID does not defeat a true alternate.</div>
<p><a href=opaque-edition>Body reference to the same destination.</a></p>
<nav><a href=/review-drafts/2026-07/>Review draft</a><a href=/multipage/forms.html#forms>Forms</a></nav>
<a href=/review-drafts/2026-07/index.txt>Text</a><a href=/review-drafts/2026-07/api.idl>IDL</a>
<a href=/review-drafts/2026-07/data.json>JSON</a><a rel=alternate href=/review-drafts/2026-07/opaque.bin>Raw</a>
<a href=/indexes.json>Root JSON</a><a href=/index.txt>Root text</a><a href=/interfaces.idl>Root IDL</a>
<link rel=alternate href=https://evil.invalid/raw.bin>"#;
        let metadata = publication_metadata(source, &tokio_util::sync::CancellationToken::new())
            .expect("metadata");
        assert!(
            metadata
                .advertisements
                .iter()
                .any(|edge| edge.href == "opaque-edition"
                    && edge.role == AdvertisementRole::ExplicitRepresentation)
        );
        assert!(
            !metadata
                .exclusions
                .iter()
                .any(|edge| edge.href == "opaque-edition")
        );
        assert!(
            metadata
                .links
                .contains(&"/multipage/forms.html#forms".into())
        );
        let targets = qualified_advertised(
            &html_standard(),
            &PublicationUrl::new("https://html.spec.whatwg.org/").expect("base"),
            &metadata.advertisements,
        );
        for suffix in [
            "/opaque-edition",
            "/review-drafts/2026-07/",
            "/multipage/forms.html",
            "/index.txt",
            "/api.idl",
            "/data.json",
            "/opaque.bin",
            "/indexes.json",
            "/index.txt",
            "/interfaces.idl",
        ] {
            assert!(
                targets.iter().any(|url| url.as_str().ends_with(suffix)),
                "missing {suffix}"
            );
        }
        assert!(
            targets
                .iter()
                .all(|url| url.host() == "html.spec.whatwg.org")
        );
    }
    #[test]
    fn example_only_links_cannot_authorize_even_an_alternate_or_document() {
        let body = br#"<h3 id=body>Body</h3><div class=example><a href=/review-drafts/2026-07/demo.html>Example HTML</a><a href=/review-drafts/2026-07/demo.pdf>Example PDF</a><a href=/indexes.json>Example JSON</a><a rel=alternate href=/opaque.bin>Example raw alternate</a><a rel=alternate href=/real.bin>Also a real alternate elsewhere</a></div><nav><a rel=alternate href=/real.bin>Published binary edition</a></nav>"#;
        let metadata =
            publication_metadata(body, &tokio_util::sync::CancellationToken::new()).expect("roles");
        assert_eq!(
            metadata.advertisements,
            vec![PublicationAdvertisement {
                href: "/real.bin".into(),
                role: AdvertisementRole::ExplicitRepresentation
            }]
        );
        for href in [
            "/review-drafts/2026-07/demo.html",
            "/review-drafts/2026-07/demo.pdf",
            "/indexes.json",
            "/opaque.bin",
        ] {
            assert!(metadata.links.contains(&href.into()));
            assert!(
                metadata
                    .exclusions
                    .iter()
                    .any(|edge| edge.href == href && edge.role == ExclusionRole::ExampleReference)
            );
        }
        assert!(
            !metadata
                .exclusions
                .iter()
                .any(|edge| edge.href == "/real.bin")
        );
        let targets = qualified_advertised(
            &html_standard(),
            &PublicationUrl::new("https://html.spec.whatwg.org/").expect("base"),
            &metadata.advertisements,
        );
        assert!(
            targets
                .iter()
                .any(|url| url.as_str().ends_with("/real.bin"))
        );
        assert!(!targets.iter().any(
            |url| url.as_str().ends_with("/opaque.bin") || url.as_str().ends_with("demo.html")
        ));
    }
    #[test]
    fn metadata_cancellation_is_not_a_capacity_observation() {
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        for body in [
            b"".as_slice(),
            b"<h3>Body</h3><a href=/indexes.json>Data</a>".as_slice(),
        ] {
            assert_eq!(
                publication_metadata(body, &cancel)
                    .expect_err("cancelled")
                    .code,
                "cancelled"
            );
        }
    }
    #[test]
    fn local_id_does_not_reclassify_an_explicit_document_fragment_or_filename() {
        let body = br#"<h3>Body</h3><div id=chapter></div><div id=data.bin></div><a href=chapter#part>Document fragment</a><a href=data.bin>Unknown file</a>"#;
        let metadata = publication_metadata(body, &tokio_util::sync::CancellationToken::new())
            .expect("metadata");
        assert!(metadata.exclusions.is_empty());
        assert!(metadata.advertisements.is_empty());
        assert!(metadata.links.contains(&"chapter#part".into()));
        assert!(metadata.links.contains(&"data.bin".into()));
    }
    #[test]
    fn forms_h3_body_definition_is_not_header_repository_metadata() {
        let source = format!(
            "<header id=head class=head><h1>HTML</h1></header><nav><a href=input.html>Next</a></nav><h3 id=forms>Forms</h3><h4>Labels</h4><dl class=domintro><dt><code>control.labels</code><div class=mdn-anno>{}</div><dd>Returns labels.</dl><a href=input.html#input>Input</a>",
            "MDN browser-support annotation ".repeat(60)
        );
        let metadata = publication_metadata(
            source.as_bytes(),
            &tokio_util::sync::CancellationToken::new(),
        )
        .expect("body dt is inert to header metadata");
        assert!(metadata.repositories.is_empty());
        assert!(
            metadata
                .advertisements
                .iter()
                .any(|edge| edge.href == "input.html")
        );
        let targets = qualified_advertised(
            &html_standard(),
            &PublicationUrl::new("https://html.spec.whatwg.org/multipage/forms.html")
                .expect("base"),
            &metadata.advertisements,
        );
        assert!(
            targets
                .iter()
                .any(|url| url.as_str() == "https://html.spec.whatwg.org/multipage/input.html")
        );
        let closed_header = format!(
            "<header id=head class=head><h1>HTML</h1></header><dl><dt>{}<dd>Body without a heading.</dl>",
            "ordinary body definition ".repeat(100)
        );
        publication_metadata(
            closed_header.as_bytes(),
            &tokio_util::sync::CancellationToken::new(),
        )
        .expect("closed header ends label admission");
    }
    #[test]
    fn combined_raw_and_typed_metadata_has_an_aggregate_byte_bound() {
        let mut source = String::from("<h3>Body</h3>");
        for i in 0..1800 {
            source.push_str(&format!(
                "<a href=/review-drafts/2026-07/{}-{i}.html>Document</a>",
                "a".repeat(2400)
            ));
        }
        assert_eq!(
            publication_metadata(
                source.as_bytes(),
                &tokio_util::sync::CancellationToken::new()
            )
            .expect_err("combined metadata exceeds 8 MiB")
            .code,
            "capacity"
        );
    }
    #[test]
    #[ignore = "opt-in local retained public HTML; no provider traffic"]
    fn retained_html_metadata_replay() {
        let path = std::env::var("DEVRES_WHATWG_METADATA_HTML").expect("retained HTML path");
        let body = std::fs::read(path).expect("retained public HTML");
        let metadata = publication_metadata(&body, &tokio_util::sync::CancellationToken::new())
            .expect("complete retained publication discovery");
        assert!(
            metadata
                .repositories
                .iter()
                .any(|repository| repository == "whatwg/html")
        );
        assert!(!metadata.links.is_empty());
    }
    #[test]
    #[ignore = "opt-in local retained forms HTML; no provider traffic"]
    fn retained_forms_metadata_replay() {
        let path = std::env::var("DEVRES_WHATWG_METADATA_FORMS").expect("retained forms path");
        let body = std::fs::read(path).expect("retained forms HTML");
        let metadata = publication_metadata(&body, &tokio_util::sync::CancellationToken::new())
            .expect("forms header/body metadata separation");
        let urls = qualified_advertised(
            &html_standard(),
            &PublicationUrl::new("https://html.spec.whatwg.org/multipage/forms.html")
                .expect("base"),
            &metadata.advertisements,
        );
        assert!(
            urls.iter()
                .any(|url| url.as_str() == "https://html.spec.whatwg.org/multipage/input.html")
        );
        assert!(!metadata.links.is_empty());
    }
    #[test]
    fn draft_inventory_and_multipage_discovery_remain_source_qualified() {
        let standard = Standard {
            id: "dom".into(),
            title: "DOM".into(),
            url: "https://dom.spec.whatwg.org/".into(),
            repository: "whatwg/dom".into(),
            metadata: json!({}),
        };
        let urls = source_publications(
            &standard,
            &[
                "review-drafts/2026-06.bs".into(),
                "review-drafts/2026-99.bs".into(),
                "review-drafts/arbitrary.wattsi".into(),
            ],
        )
        .expect("drafts");
        assert_eq!(urls.len(), 1);
        assert_eq!(
            urls[0].as_str(),
            "https://dom.spec.whatwg.org/review-drafts/2026-06/"
        );
        let base = PublicationUrl::new("https://dom.spec.whatwg.org/").expect("base");
        let urls = advertised(
            &standard,
            &base,
            &[
                "https://evil.invalid/review-drafts/2026-06/".into(),
                "/multipage/infrastructure.html".into(),
            ],
        );
        assert!(
            urls.iter()
                .any(|u| u.as_str().ends_with("/multipage/infrastructure.html"))
        );
        assert!(urls.iter().all(|u| u.host() == "dom.spec.whatwg.org"));
    }
}
