//! Additive v2 identities. Historical v1 extraction remains immutable.
use super::*;

pub(super) fn canonical(target: AttributionTarget) -> Result<AttributionTarget> {
    if !matches!(
        target.subject.provider.as_str(),
        "mdn" | "whatwg" | "w3c" | "chromium"
    ) {
        return Ok(target);
    }
    let original = &target.evidence["source"];
    if !original.is_object() {
        return Ok(target);
    }
    let mut source = Map::new();
    for field in ["source_url", "body_hash", "oid", "revision", "component"] {
        if let Some(value) = original.get(field).filter(|value| value.is_string()) {
            source.insert(field.into(), value.clone());
        }
    }
    let path = string(original, "source_path").or_else(|| string(original, "path"));
    if let Some(path) = path {
        source.insert("source_path".into(), json!(path));
    }
    if let Ok(url) = url::Url::parse(string(original, "source_url").ok_or_else(invalid)?) {
        let parts: Vec<_> = url.path().trim_start_matches('/').split('/').collect();
        if url.host_str() == Some("github.com")
            && parts.len() >= 4
            && matches!(parts[2], "blob" | "tree")
            && oid(parts[3])
        {
            let repository = format!("{}/{}", parts[0], parts[1]);
            if string(original, "revision").is_some_and(|revision| revision != parts[3]) {
                return Err(invalid());
            }
            if let Some(original_repository) = string(original, "repository") {
                let normalized = match (target.subject.provider.as_str(), original_repository) {
                    ("mdn", "content") => "mdn/content",
                    ("mdn", "compat") => "mdn/browser-compat-data",
                    _ => original_repository
                        .strip_prefix("https://github.com/")
                        .unwrap_or(original_repository)
                        .trim_end_matches(".git"),
                };
                if normalized != repository {
                    return Err(invalid());
                }
            }
            source.insert("repository".into(), json!(repository));
            source.insert("revision".into(), json!(parts[3]));
            if parts[2] == "blob" && parts.len() > 4 {
                let encoded = parts[4..].join("/");
                let parsed_path = percent_encoding::percent_decode_str(&encoded)
                    .decode_utf8()
                    .map_err(|_| invalid())?;
                let synthetic_selector = target.subject.provider == "mdn"
                    && path.is_some_and(|path| path.starts_with('@'))
                    && string(original, "source_path").is_none();
                if !synthetic_selector && path.is_some_and(|path| path != parsed_path) {
                    return Err(invalid());
                }
                source.insert("source_path".into(), json!(parsed_path));
            }
        }
    }
    let evidence = json!({"version":2,"source":source,"license":target.evidence["license"]});
    let fingerprint = crate::integrity::canonical_hash(&evidence)?;
    Ok(AttributionTarget {
        subject: AttributionSubject {
            provider: target.subject.provider,
            namespace: "source".into(),
            key: fingerprint.clone(),
            fingerprint,
        },
        evidence,
    })
}

pub(super) fn targets(source: &str, value: &Value) -> Result<Vec<AttributionTarget>> {
    let mut output = BTreeMap::new();
    for target in targets_v1(source, value)? {
        let target = canonical(target)?;
        output.insert(target.subject.fingerprint.clone(), target);
    }
    Ok(output.into_values().collect())
}

pub(super) fn candidate(
    source: &str,
    namespace: &str,
    key: &str,
    value: &Value,
) -> Result<Option<AttributionTarget>> {
    let Some(target) = candidate_v1(source, namespace, key, value)? else {
        return Ok(None);
    };
    if let Some(dependencies) = target
        .evidence
        .get("dependencies")
        .and_then(Value::as_array)
    {
        let dependencies = dependencies
            .iter()
            .map(|value| canonical(serde_json::from_value(value.clone()).map_err(|_| invalid())?))
            .collect::<Result<Vec<_>>>()?;
        let evidence = json!({"version":2,"dependencies":dependencies});
        let fingerprint = crate::integrity::canonical_hash(&evidence)?;
        return Ok(Some(AttributionTarget {
            subject: AttributionSubject {
                provider: target.subject.provider,
                namespace: "source".into(),
                key: key.into(),
                fingerprint,
            },
            evidence,
        }));
    }
    canonical(target).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contradictory_git_revision_path_and_repository_are_rejected() {
        let source = json!({"source_url":format!("https://github.com/mdn/content/blob/{}/files/example.md","a".repeat(40)),"revision":"a".repeat(40),"source_path":"files/example.md","repository":"content","oid":"b".repeat(40)});
        let expected = targets("mdn", &source).unwrap();
        assert_eq!(expected.len(), 1);
        for (field, value) in [
            ("revision", "c".repeat(40)),
            ("source_path", "files/other.md".into()),
            ("repository", "mdn/other".into()),
        ] {
            let mut contradictory = source.clone();
            contradictory[field] = json!(value);
            assert!(targets("mdn", &contradictory).is_err());
        }
        let mut presentation = source.clone();
        presentation["path"] = presentation["source_path"].clone();
        presentation["representation"] = json!("markdown");
        presentation["id"] = json!("projection-id");
        assert_eq!(targets("mdn", &presentation).unwrap(), expected);
    }
}
