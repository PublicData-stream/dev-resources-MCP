//! Fixed public npm destinations. No package metadata can authorize another origin.
use devres_domain::{Error, Result};

pub const OSV_EXPORT: &str = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";

#[derive(Clone, Debug)]
pub enum Operation {
    Metadata {
        name: String,
    },
    Search {
        query: String,
        offset: usize,
        limit: usize,
    },
    Archive {
        name: String,
        version: String,
        url: String,
    },
    AdvisoryExport,
}

impl Operation {
    pub fn url(&self) -> Result<String> {
        match self {
            Self::Metadata { name } => {
                crate::npm::processing::validate_name(name)?;
                Ok(format!(
                    "https://registry.npmjs.org/{}",
                    name.replace('/', "%2F")
                ))
            }
            Self::Search {
                query,
                offset,
                limit,
            } => {
                if query.is_empty()
                    || query.chars().count() > 256
                    || query.chars().any(char::is_control)
                    || *offset > 10_000
                    || !(1..=100).contains(limit)
                {
                    return Err(Error::invalid("Invalid npm registry search page."));
                }
                let query = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("text", query)
                    .append_pair("from", &offset.to_string())
                    .append_pair("size", &limit.to_string())
                    .finish();
                Ok(format!("https://registry.npmjs.org/-/v1/search?{query}"))
            }
            Self::Archive { name, version, url } => {
                crate::npm::processing::validate_name(name)?;
                crate::npm::processing::parse_version(version)?;
                if version.len() > 256
                    || !version
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
                {
                    return Err(invalid());
                }
                // Published filenames are bound to the selected exact release, including scopes.
                let base = name.rsplit('/').next().ok_or_else(invalid)?;
                let expected = format!("https://registry.npmjs.org/{name}/-/{base}-{version}.tgz");
                if *url != expected {
                    return Err(invalid());
                }
                Ok(expected)
            }
            Self::AdvisoryExport => Ok(OSV_EXPORT.into()),
        }
    }
    pub fn host(&self) -> &'static str {
        if matches!(self, Self::AdvisoryExport) {
            "osv-vulnerabilities.storage.googleapis.com"
        } else {
            "registry.npmjs.org"
        }
    }
    pub fn media_type(&self) -> &'static str {
        match self {
            Self::Archive { .. } => "application/gzip",
            Self::AdvisoryExport => "application/zip",
            _ => "application/json",
        }
    }
}

fn invalid() -> Error {
    Error::invalid("npm source destination is not permitted.")
}

/// Validate raw spelling by reconstructing an admitted typed operation exactly.
/// The exception for scoped-name encoding is confined to the metadata route.
pub fn validate_url(value: &str) -> Result<&'static str> {
    if value.len() > 4096 || value.chars().any(char::is_control) || value.contains('\\') {
        return Err(invalid());
    }
    if value == OSV_EXPORT {
        return Ok("osv-vulnerabilities.storage.googleapis.com");
    }
    let tail = value
        .strip_prefix("https://registry.npmjs.org/")
        .ok_or_else(invalid)?;
    let operation = if tail.starts_with("-/v1/search?") {
        let url = url::Url::parse(value).map_err(|_| invalid())?;
        let pairs: Vec<_> = url.query_pairs().collect();
        if pairs.len() != 3 || pairs[0].0 != "text" || pairs[1].0 != "from" || pairs[2].0 != "size"
        {
            return Err(invalid());
        }
        Operation::Search {
            query: pairs[0].1.to_string(),
            offset: pairs[1].1.parse().map_err(|_| invalid())?,
            limit: pairs[2].1.parse().map_err(|_| invalid())?,
        }
    } else if let Some((name, file)) = tail.split_once("/-/") {
        let base = name.rsplit('/').next().ok_or_else(invalid)?;
        let version = file
            .strip_prefix(&format!("{base}-"))
            .and_then(|s| s.strip_suffix(".tgz"))
            .ok_or_else(invalid)?;
        Operation::Archive {
            name: name.into(),
            version: version.into(),
            url: value.into(),
        }
    } else {
        Operation::Metadata {
            name: tail.replace("%2F", "/"),
        }
    };
    if operation.url()? != value {
        return Err(invalid());
    }
    Ok(operation.host())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_scoped_paths_are_narrow_exceptions() {
        for good in [
            "https://registry.npmjs.org/@types%2Fis-number",
            "https://registry.npmjs.org/@types/is-number/-/is-number-7.0.5.tgz",
            OSV_EXPORT,
        ] {
            assert!(validate_url(good).is_ok(), "{good}");
        }
        for bad in [
            "https://registry.npmjs.org:443/foo",
            "https://registry.npmjs.org/@types%2fis-number",
            "https://registry.npmjs.org/@types%252Fis-number",
            "https://registry.npmjs.org/@types/is-number",
            "https://registry.npmjs.org/foo/-/bar-1.0.0.tgz",
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz?url=http://localhost",
            "https://registry.npmjs.org/%2E%2E/foo",
            "https://registry.npmjs.org@evil.test/foo",
        ] {
            assert!(validate_url(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn search_requires_canonical_query_and_bounds() {
        let op = Operation::Search {
            query: "@types foo".into(),
            offset: 0,
            limit: 20,
        };
        assert!(validate_url(&op.url().expect("query")).is_ok());
        assert!(
            validate_url("https://registry.npmjs.org/-/v1/search?text=foo&from=0&size=20&url=x")
                .is_err()
        );
    }
}
