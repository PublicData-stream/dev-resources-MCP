//! Fixed-source HTTPS fetcher. This is not an arbitrary URL proxy.
use async_trait::async_trait;
use devres_application::Fetcher;
use devres_domain::{Error, FetchRequest, FetchResponse, Result, Validators};
use futures::StreamExt;
use std::{collections::HashMap, time::Duration};
use tokio::{
    sync::{Mutex, Semaphore},
    time::Instant,
};
use url::Url;

pub struct HttpFetcher {
    client: reqwest::Client,
    limits: Mutex<HashMap<String, Instant>>,
    slots: Semaphore,
}
impl HttpFetcher {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(
                "dev-resources-MCP/0.0.0 (+https://github.com/PublicData-stream/dev-resources-MCP)",
            )
            .build()
            .map_err(|_| Error::unavailable("HTTP client initialization failed"))?;
        Ok(Self {
            client,
            limits: Mutex::new(HashMap::new()),
            slots: Semaphore::new(2),
        })
    }
    async fn attempt(
        &self,
        request: &FetchRequest,
        validators: Option<&Validators>,
        host: &str,
    ) -> Result<(FetchResponse, u64)> {
        let scheduled = {
            let mut limits = self.limits.lock().await;
            let now = Instant::now();
            let scheduled = *limits.entry(host.to_owned()).or_insert(now);
            let scheduled = scheduled.max(now);
            limits.insert(host.to_owned(), scheduled + Duration::from_secs(1));
            scheduled
        };
        tokio::time::sleep_until(scheduled).await;
        let mut builder = self
            .client
            .get(&request.url)
            .header("Accept", &request.media_type);
        if let Some(validators) = validators {
            if let Some(etag) = &validators.etag {
                builder = builder.header("If-None-Match", etag);
            }
            if let Some(modified) = &validators.last_modified {
                builder = builder.header("If-Modified-Since", modified);
            }
        }
        let response = builder
            .send()
            .await
            .map_err(|_| Error::unavailable("Source connection failed"))?;
        let status = response.status().as_u16();
        let retry = match response.headers().get("retry-after") {
            None => 1,
            Some(value) => value
                .to_str()
                .ok()
                .and_then(|value| {
                    value.parse::<u64>().ok().or_else(|| {
                        httpdate::parse_http_date(value).ok().map(|date| {
                            date.duration_since(std::time::SystemTime::now())
                                .map(|v| v.as_secs().saturating_add(1))
                                .unwrap_or(1)
                        })
                    })
                })
                .unwrap_or(u64::MAX),
        };
        let validators = Validators {
            etag: response
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            last_modified: response
                .headers()
                .get("last-modified")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        };
        // Error responses never need source bodies, and cannot poison captures.
        if status != 200 {
            return Ok((
                FetchResponse {
                    status,
                    body: Vec::new(),
                    validators,
                },
                retry,
            ));
        }
        if response
            .content_length()
            .is_some_and(|v| v > request.max_bytes as u64)
        {
            return Err(Error::capacity("Source body exceeds limit"));
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Error::unavailable("Source body transfer failed"))?;
            if chunk.len() > request.max_bytes.saturating_sub(body.len()) {
                return Err(Error::capacity("Source body exceeds limit"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok((
            FetchResponse {
                status,
                body,
                validators,
            },
            retry,
        ))
    }
}

fn allowed_url(value: &str) -> Result<String> {
    // Inspect the original spelling before URL normalization removes dot segments.
    let after_scheme = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_default();
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let raw_path = after_scheme
        .find('/')
        .map(|start| &after_scheme[start..])
        .unwrap_or("/");
    let raw_path = raw_path.split(['?', '#']).next().unwrap_or_default();
    if value.len() > 4096
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.contains('\\')
        || authority.contains('@')
        || raw_path.contains('%')
        || raw_path.contains("..")
        || raw_path.contains("//")
    {
        return Err(Error::invalid("Source URL spelling is not permitted"));
    }
    let url = Url::parse(value).map_err(|_| Error::invalid("Invalid source URL"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::invalid("Source URL is not permitted"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| Error::invalid("Missing source host"))?;
    let path = url.path();
    // Percent escapes, dots and backslashes cannot smuggle a different source path.
    let safe = path
        .bytes()
        .all(|v| v.is_ascii_alphanumeric() || b"/-_.+".contains(&v))
        && !path.contains("..")
        && !path.contains("//");
    let allowed = safe
        && match host {
            "www.rfc-editor.org" | "rfc-editor.org" => {
                (path == "/rfc-index.xml"
                    || path == "/errata.json"
                    || path == "/api/v1/errata.json"
                    || path == "/in-notes/rfc-index.xml"
                    || path.strip_prefix("/rfc/rfc").is_some_and(|v| {
                        [".txt", ".json", ".xml", ".html", ".pdf"]
                            .iter()
                            .any(|suffix| {
                                v.strip_suffix(suffix).is_some_and(|n| {
                                    !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
                                })
                            })
                    }))
                    && url.query().is_none()
            }
            "crates.io" => path == "/api/v1/crates",
            "index.crates.io" => {
                !path.ends_with('/')
                    && path.len() <= 256
                    && !path.contains('.')
                    && url.query().is_none()
            }
            "static.crates.io" => {
                path.starts_with("/crates/") && path.ends_with(".crate") && url.query().is_none()
            }
            "api.github.com" => {
                path == "/repos/RustSec/advisory-db/commits/main" && url.query().is_none()
            }
            "codeload.github.com" => {
                path.strip_prefix("/RustSec/advisory-db/tar.gz/")
                    .is_some_and(|sha| {
                        sha.len() == 40 && sha.bytes().all(|v| v.is_ascii_hexdigit())
                    })
                    && url.query().is_none()
            }
            _ => false,
        };
    if !allowed || value.len() > 4096 {
        return Err(Error::invalid("Source destination is not permitted"));
    }
    Ok(if host == "rfc-editor.org" {
        "www.rfc-editor.org"
    } else {
        host
    }
    .to_owned())
}

#[async_trait]
impl Fetcher for HttpFetcher {
    async fn fetch(
        &self,
        request: &FetchRequest,
        validators: Option<&Validators>,
    ) -> Result<FetchResponse> {
        let host = allowed_url(&request.url)?;
        let _slot = self
            .slots
            .acquire()
            .await
            .map_err(|_| Error::capacity("Source admission closed"))?;
        // One retry owner. Each attempt reserves the same provider throttle.
        for attempt in 0..2 {
            let (response, retry) = self.attempt(request, validators, &host).await?;
            if attempt == 0 && matches!(response.status, 429 | 500 | 502 | 503 | 504) && retry <= 30
            {
                tokio::time::sleep(Duration::from_secs(retry.max(1))).await;
                continue;
            }
            return Ok(response);
        }
        Err(Error::unavailable("Source attempts exhausted"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_arbitrary_sources_and_redirect_destinations() {
        for url in [
            "http://www.rfc-editor.org/rfc/rfc1.txt",
            "https://127.0.0.1/rfc/rfc1.txt",
            "https://www.rfc-editor.org@evil.test/rfc/rfc1.txt",
            "https://www.rfc-editor.org:444/rfc/rfc1.txt",
            "https://api.github.com/repos/other/advisory-db/commits/main",
            "https://codeload.github.com/RustSec/advisory-db/tar.gz/main",
            "https://index.crates.io/a/%2e%2e/secret",
        ] {
            assert!(allowed_url(url).is_err(), "{url}");
        }
        assert!(allowed_url("https://index.crates.io/se/rd/serde").is_ok());
        assert!(allowed_url("https://www.rfc-editor.org/api/v1/errata.json").is_ok());
        assert!(
            allowed_url("https://www.rfc-editor.org/api/v1/errata.json?url=https://evil.test")
                .is_err()
        );
        assert!(
            allowed_url(
                "https://static.crates.io/crates/zstd-sys/zstd-sys-2.0.16+zstd.1.5.7.crate"
            )
            .is_ok()
        );
        assert!(allowed_url("https://crates.io/api/v1/crates?q=tokio&per_page=20").is_ok());
    }
}
