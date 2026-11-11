//! Serializable upstream cache evidence. Application profiles never override these floors.
use devres_domain::{Error, Result, Validators};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheMetadata {
    pub cache_control: Option<String>,
    pub date: Option<i64>,
    pub age: Option<u64>,
    pub expires: Option<i64>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub request_sent_at: i64,
    pub received_at: i64,
}

impl CacheMetadata {
    pub fn from_headers(
        headers: &HeaderMap,
        request_sent_at: i64,
        received_at: i64,
    ) -> Result<Self> {
        let text = |key: &str| -> Result<Option<String>> {
            let values: Vec<_> = headers.get_all(key).iter().collect();
            if values.len() > 1 && key != "cache-control" {
                return Err(Error::integrity("Ambiguous Wikipedia cache metadata."));
            }
            if values.is_empty() {
                return Ok(None);
            }
            let mut output = String::new();
            for value in values {
                let value = value.to_str().map_err(|_| invalid())?;
                if output.len().saturating_add(value.len()) > 16 * 1024 {
                    return Err(Error::capacity(
                        "Wikipedia cache metadata exceeds its bound.",
                    ));
                }
                if !output.is_empty() {
                    output.push(',');
                }
                output.push_str(value);
            }
            Ok(Some(output))
        };
        let date = |value: Option<String>| -> Result<Option<i64>> {
            value
                .map(|value| {
                    let parsed = httpdate::parse_http_date(&value).map_err(|_| invalid())?;
                    Ok(parsed
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| invalid())?
                        .as_secs()
                        .min(i64::MAX as u64) as i64)
                })
                .transpose()
        };
        let metadata = Self {
            cache_control: text("cache-control")?,
            date: date(text("date")?)?,
            age: text("age")?
                .map(|value| value.parse::<u64>().map_err(|_| invalid()))
                .transpose()?,
            expires: date(text("expires")?)?,
            etag: text("etag")?,
            last_modified: text("last-modified")?,
            request_sent_at,
            received_at,
        };
        metadata.directives()?;
        Ok(metadata)
    }

    pub fn validators(&self) -> Validators {
        Validators {
            etag: self.etag.clone(),
            last_modified: self.last_modified.clone(),
        }
    }

    /// `private` and `no-store` cannot enter this anonymous shared durable corpus.
    pub fn retention_allowed(&self) -> Result<bool> {
        let directives = self.directives()?;
        Ok(!directives.private && !directives.no_store)
    }

    pub fn stale_allowed(&self) -> Result<bool> {
        let directives = self.directives()?;
        Ok(!directives.private
            && !directives.no_store
            && !directives.no_cache
            && !directives.must_revalidate
            && directives.shared_max_age.is_none())
    }

    /// Upstream freshness deadline with corrected age, including transit time.
    /// Shared cache `s-maxage` takes precedence. `no-cache` requires validation.
    pub fn freshness_deadline(&self) -> Result<i64> {
        let directives = self.directives()?;
        if directives.no_cache || directives.no_store || directives.private {
            return Ok(self.received_at);
        }
        let lifetime = directives
            .shared_max_age
            .or(directives.max_age)
            .unwrap_or_else(|| {
                self.expires
                    .map(|expires| {
                        expires
                            .saturating_sub(self.date.unwrap_or(self.received_at))
                            .max(0) as u64
                    })
                    .unwrap_or(0)
            });
        let apparent_age = self
            .date
            .map(|date| self.received_at.saturating_sub(date).max(0) as u64)
            .unwrap_or(0);
        let response_delay = self.received_at.saturating_sub(self.request_sent_at).max(0) as u64;
        let corrected_age = apparent_age.max(self.age.unwrap_or(0).saturating_add(response_delay));
        Ok(self
            .received_at
            .saturating_add(lifetime.saturating_sub(corrected_age).min(i64::MAX as u64) as i64))
    }

    /// A 304 updates supplied fields while retaining omitted stored directives.
    /// Age is from this validation transaction; an omitted Date is receipt time.
    pub fn merged_after_304(&self, previous: &Self) -> Result<Self> {
        let merged = Self {
            cache_control: self
                .cache_control
                .clone()
                .or_else(|| previous.cache_control.clone()),
            date: self.date.or(Some(self.received_at)),
            age: self.age,
            expires: self.expires.or(previous.expires),
            etag: self.etag.clone().or_else(|| previous.etag.clone()),
            last_modified: self
                .last_modified
                .clone()
                .or_else(|| previous.last_modified.clone()),
            request_sent_at: self.request_sent_at,
            received_at: self.received_at,
        };
        merged.directives()?;
        Ok(merged)
    }

    fn directives(&self) -> Result<Directives> {
        let mut parsed = Directives::default();
        let Some(value) = self.cache_control.as_deref() else {
            return Ok(parsed);
        };
        if value.len() > 16 * 1024 {
            return Err(invalid());
        }
        // Field-qualified private/no-cache values can contain commas. Splitting
        // outside quotes preserves their presence and does not invent directives.
        let mut quoted = false;
        let mut escaped = false;
        let mut start = 0;
        let mut pieces = Vec::new();
        for (index, byte) in value.bytes().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            if quoted && byte == b'\\' {
                escaped = true;
                continue;
            }
            if byte == b'"' {
                quoted = !quoted;
            }
            if byte == b',' && !quoted {
                pieces.push(&value[start..index]);
                start = index + 1;
            }
        }
        if quoted || escaped {
            return Err(invalid());
        }
        pieces.push(&value[start..]);
        for piece in pieces {
            let (name, argument) = piece
                .trim()
                .split_once('=')
                .map_or((piece.trim(), None), |(name, value)| {
                    (name.trim(), Some(value.trim()))
                });
            match name.to_ascii_lowercase().as_str() {
                "private" => parsed.private = true,
                "no-store" => parsed.no_store = true,
                "no-cache" => parsed.no_cache = true,
                "must-revalidate" | "proxy-revalidate" => parsed.must_revalidate = true,
                "max-age" | "s-maxage" => {
                    let number = argument
                        .ok_or_else(invalid)?
                        .trim_matches('"')
                        .parse::<u64>()
                        .map_err(|_| invalid())?;
                    let selected = if name.eq_ignore_ascii_case("s-maxage") {
                        &mut parsed.shared_max_age
                    } else {
                        &mut parsed.max_age
                    };
                    if selected.replace(number).is_some() {
                        return Err(invalid());
                    }
                }
                _ => {}
            }
        }
        Ok(parsed)
    }
}

#[derive(Default)]
struct Directives {
    max_age: Option<u64>,
    shared_max_age: Option<u64>,
    private: bool,
    no_store: bool,
    no_cache: bool,
    must_revalidate: bool,
}
fn invalid() -> Error {
    Error::integrity("Invalid Wikipedia cache metadata.")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metadata(control: &str) -> CacheMetadata {
        CacheMetadata {
            cache_control: Some(control.into()),
            date: Some(100),
            age: Some(20),
            request_sent_at: 125,
            received_at: 130,
            ..CacheMetadata::default()
        }
    }
    #[test]
    fn corrected_age_and_shared_directive_precedence() {
        assert_eq!(
            metadata("public, max-age=600, s-maxage=60")
                .freshness_deadline()
                .expect("cache"),
            160
        );
        let mut value = metadata("max-age=60");
        value.age = Some(50);
        assert_eq!(value.freshness_deadline().expect("cache"), 135);
        value.age = Some(999);
        assert_eq!(value.freshness_deadline().expect("cache"), 130);
    }
    #[test]
    fn expiry_no_cache_and_retention_rules() {
        let mut value = metadata("public");
        value.expires = Some(200);
        assert_eq!(value.freshness_deadline().expect("expires"), 200);
        assert_eq!(
            metadata("no-cache, max-age=600")
                .freshness_deadline()
                .expect("no-cache"),
            130
        );
        for control in [
            "private=\"set-cookie, authorization\", max-age=600",
            "no-store, max-age=600",
        ] {
            assert!(!metadata(control).retention_allowed().expect("retention"));
        }
        assert!(metadata("no-cache").retention_allowed().expect("retention"));
        assert!(
            metadata("max-age=2, max-age=3")
                .freshness_deadline()
                .is_err()
        );
        assert!(metadata("s-maxage=invalid").freshness_deadline().is_err());
    }
    #[test]
    fn validation_304_merges_without_reviving_old_age() {
        let old = metadata("max-age=600");
        let fresh = CacheMetadata {
            received_at: 500,
            request_sent_at: 499,
            etag: Some("\"new\"".into()),
            ..CacheMetadata::default()
        };
        let merged = fresh.merged_after_304(&old).expect("merge");
        assert_eq!(merged.freshness_deadline().expect("deadline"), 1099);
        assert_eq!(merged.etag.as_deref(), Some("\"new\""));
        let prohibited = CacheMetadata {
            cache_control: Some("no-store".into()),
            ..fresh
        };
        assert!(
            !prohibited
                .merged_after_304(&old)
                .expect("merge")
                .retention_allowed()
                .expect("retain")
        );
    }
    #[test]
    fn expires_without_date_uses_response_time_and_revalidation_disables_stale() {
        let value = CacheMetadata {
            expires: Some(200),
            received_at: 100,
            request_sent_at: 100,
            ..CacheMetadata::default()
        };
        assert_eq!(value.freshness_deadline().expect("expires"), 200);
        for directive in [
            "no-cache",
            "private",
            "no-store",
            "must-revalidate",
            "proxy-revalidate",
            "public,s-maxage=600",
        ] {
            assert!(!metadata(directive).stale_allowed().expect("stale policy"));
        }
        assert!(
            metadata("public,max-age=600")
                .stale_allowed()
                .expect("stale allowed")
        );
    }
}
