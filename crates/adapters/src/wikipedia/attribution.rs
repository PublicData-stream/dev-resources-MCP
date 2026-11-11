//! Qualification of exact, contemporaneously acquired Wikipedia article evidence.
//! No notice link or response field authorizes an additional network request.
use devres_application::wikipedia::WikipediaStore;
use devres_domain::{Error, Result, attribution::*};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const LICENSE: &str = "https://creativecommons.org/licenses/by-sa/4.0/";

fn unavailable() -> Error {
    Error::unavailable("Wikipedia capture requires qualified acquisition and license evidence.")
}

pub(crate) async fn ensure_public(
    store: &dyn WikipediaStore,
    subject: &AttributionSubject,
) -> Result<()> {
    let before = store
        .wiki_state("visibility:epoch")
        .await?
        .filter(|v| v.as_u64().is_some())
        .ok_or_else(unavailable)?;
    let capture = store
        .wiki_get("captures", &subject.key)
        .await?
        .ok_or_else(unavailable)?;
    let page = capture.data["page_id"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or_else(unavailable)?;
    let revision = capture.data["revision_id"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or_else(unavailable)?;
    if let Some(value) = store
        .wiki_state(&format!("visibility:revision:{page}:{revision}"))
        .await?
        && value["blocked"].as_bool().ok_or_else(unavailable)?
    {
        return Err(Error::new(
            "wikipedia_withheld",
            "Wikipedia source content is withheld.",
        ));
    }
    if let Some(value) = store.wiki_state(&format!("visibility:page:{page}")).await?
        && value["blocked"].as_bool().ok_or_else(unavailable)?
    {
        let allowed = value["verified_revisions"]
            .as_array()
            .is_some_and(|items| items.iter().any(|id| id.as_u64() == Some(revision)));
        let certificate = store
            .wiki_state(&format!("visibility:restored:{page}:{revision}"))
            .await?;
        let certified = value["restore_identity"].as_str().is_some_and(|id| {
            certificate
                .as_ref()
                .and_then(|v| v["restore_identity"].as_str())
                == Some(id)
        });
        if !allowed && !certified {
            return Err(Error::new(
                "wikipedia_withheld",
                "Wikipedia source content is withheld.",
            ));
        }
    }
    if store.wiki_state("visibility:epoch").await?.as_ref() != Some(&before) {
        return Err(unavailable());
    }
    Ok(())
}

/// The sole discovery-only shape contains natural identifiers and constructed
/// links. Extra copied titles/snippets or arbitrary destinations fail closed.
pub(crate) fn is_metadata_only_discovery(value: &Value) -> bool {
    let Some(root) = value.as_object() else {
        return false;
    };
    if root.len() != 4
        || value["metadata_only_discovery"] != true
        || value["source"] != "wikipedia"
        || value["coverage"] != "upstream_discovery"
    {
        return false;
    }
    let Some(items) = value["items"].as_array().filter(|items| items.len() <= 100) else {
        return false;
    };
    items.iter().all(|item| {
        let Some(fields) = item.as_object() else {
            return false;
        };
        if fields.len() != 3 || item["page_id"].as_u64().is_none_or(|n| n == 0) {
            return false;
        }
        let Some(title) = item["fetch_id"]
            .as_str()
            .and_then(|v| v.strip_prefix("wikipedia:"))
        else {
            return false;
        };
        if super::source::validate_title(title).is_err() {
            return false;
        }
        let expected = format!(
            "https://en.wikipedia.org/wiki/{}",
            url::form_urlencoded::byte_serialize(title.replace(' ', "_").as_bytes())
                .collect::<String>()
        );
        item["url"].as_str() == Some(expected.as_str())
    })
}

/// Stable minimal identity shared by tool outputs and retained SQL occurrences.
pub(crate) fn target(value: &Value) -> Result<Option<AttributionTarget>> {
    let Some(id) = value.get("id").and_then(Value::as_str) else {
        return Ok(None);
    };
    let Some(page_id) = value
        .get("page_id")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
    else {
        return Ok(None);
    };
    let Some(revision_id) = value
        .get("revision_id")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
    else {
        return Ok(None);
    };
    let Some(representation) = value
        .get("representation")
        .and_then(Value::as_str)
        .filter(|s| matches!(*s, "html" | "wikitext"))
    else {
        return Ok(None);
    };
    let Some(source_url) = value.get("source_url").and_then(Value::as_str) else {
        return Ok(None);
    };
    let Some(body_hash) = value
        .get("body_hash")
        .and_then(Value::as_str)
        .or_else(|| value.pointer("/artifact/body_hash").and_then(Value::as_str))
    else {
        return Ok(None);
    };
    if !crate::integrity::valid_hash(id)
        || !id.starts_with("blake3:")
        || !crate::integrity::valid_hash(body_hash)
        || !body_hash.starts_with("blake3:")
        || source_url.len() > 4096
    {
        return Err(unavailable());
    }
    let url = url::Url::parse(source_url).map_err(|_| unavailable())?;
    if url.scheme() != "https"
        || url.host_str() != Some("en.wikipedia.org")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
    {
        return Err(unavailable());
    }
    let parts = url
        .path_segments()
        .ok_or_else(unavailable)?
        .collect::<Vec<_>>();
    if parts.len() != if representation == "html" { 6 } else { 5 }
        || parts[..4] != ["w", "rest.php", "v1", "page"]
        || (representation == "html" && parts[5] != "with_html")
    {
        return Err(unavailable());
    }
    let title = percent_encoding::percent_decode_str(parts[4])
        .decode_utf8()
        .map_err(|_| unavailable())?
        .into_owned();
    let operation = if representation == "html" {
        super::source::Operation::ArticleHtml { title }
    } else {
        super::source::Operation::ArticleSource { title }
    };
    if operation.url()? != source_url {
        return Err(unavailable());
    }
    let evidence = json!({"version":1,"source":{"id":id,"page_id":page_id,"revision_id":revision_id,
        "representation":representation,"source_url":source_url,"body_hash":body_hash}});
    Ok(Some(AttributionTarget {
        subject: AttributionSubject {
            provider: "wikipedia".into(),
            namespace: "source".into(),
            key: id.into(),
            fingerprint: crate::integrity::canonical_hash(&evidence)?,
        },
        evidence,
    }))
}

pub(crate) async fn repair(
    store: &dyn WikipediaStore,
    requested: &AttributionTarget,
    cancel: CancellationToken,
) -> Result<AttributionGeneration> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "Wikipedia attribution canceled."));
    }
    if requested.subject.provider != "wikipedia" {
        return Err(unavailable());
    }
    let id = requested
        .evidence
        .pointer("/source/id")
        .and_then(Value::as_str)
        .ok_or_else(unavailable)?;
    let retained = store
        .wiki_get("captures", id)
        .await?
        .ok_or_else(unavailable)?;
    let actual = target(&retained.data)?.ok_or_else(unavailable)?;
    if actual != *requested
        || retained.key != id
        || retained.data["acquisition_policy_epoch"].as_u64()
            != Some(u64::from(ATTRIBUTION_POLICY_EPOCH))
        || retained.data["acquisition_policy_fingerprint"].as_str()
            != Some(ATTRIBUTION_POLICY_FINGERPRINT)
    {
        return Err(unavailable());
    }
    let license = retained
        .data
        .pointer("/license/url")
        .and_then(Value::as_str)
        .ok_or_else(unavailable)?;
    if !matches!(
        license,
        "https://creativecommons.org/licenses/by-sa/4.0/"
            | "https://creativecommons.org/licenses/by-sa/4.0"
            | "https://creativecommons.org/licenses/by-sa/4.0/deed.en"
    ) {
        return Err(unavailable());
    }
    let observed_at = retained.data["observed_at"]
        .as_i64()
        .filter(|n| *n >= 0 && *n <= devres_domain::unix_now().saturating_add(300))
        .ok_or_else(unavailable)?;
    let source = &requested.evidence["source"];
    let revision = source["revision_id"].as_u64().ok_or_else(unavailable)?;
    let mut permalink =
        url::Url::parse("https://en.wikipedia.org/w/index.php").map_err(|_| unavailable())?;
    let title = retained.data["title"].as_str().ok_or_else(unavailable)?;
    super::source::validate_title(title)?;
    permalink
        .query_pairs_mut()
        .append_pair("title", title)
        .append_pair("oldid", &revision.to_string());
    let permalink = permalink.to_string();
    Ok(AttributionGeneration {
        subject: requested.subject.clone(),
        policy_epoch: ATTRIBUTION_POLICY_EPOCH,
        policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
        notices: vec![AttributionNotice {
            source_url: permalink.clone(),
            license: Some("CC-BY-SA-4.0".into()),
            copyright: Some("Wikipedia contributors".into()),
            text: format!(
                "Wikipedia contributors. Article revision {revision}: {permalink}. Licensed under Creative Commons Attribution-ShareAlike 4.0 ({LICENSE}). Readable text and Markdown are derived from the captured HTML; formatting may differ. Original article links preserve contributor attribution. Embedded media is not acquired."
            ),
            evidence: json!({"provider":"wikipedia","capture":id,"page_id":source["page_id"],"revision_id":revision,"body_hash":source["body_hash"],"license_url":LICENSE,"qualification":"contemporaneous_acquisition"}),
        }],
        receipts: vec![
            json!({"kind":"upstream_validation","source_url":source["source_url"],"body_hash":source["body_hash"],"status":200,"validated_at":observed_at,
            "policy_epoch":ATTRIBUTION_POLICY_EPOCH,"policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT,
            "source_fingerprint":requested.subject.fingerprint,"capture":id,"qualification":"contemporaneous_acquisition"}),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source() -> Value {
        json!({"id":crate::integrity::hash(b"capture"),"page_id":1,"revision_id":2,"representation":"html","source_url":"https://en.wikipedia.org/w/rest.php/v1/page/Artificial_intelligence/with_html?redirect=no","artifact":{"body_hash":crate::integrity::hash(b"html")},"license":{"url":LICENSE}})
    }
    #[test]
    fn public_and_retained_capture_compile_to_same_exact_source() {
        let retained = source();
        let mut public = retained.clone();
        public["body_hash"] = public["artifact"]["body_hash"].clone();
        public.as_object_mut().unwrap().remove("artifact");
        public.as_object_mut().unwrap().remove("license");
        assert_eq!(target(&retained).unwrap(), target(&public).unwrap());
        assert!(
            target(&json!({"title":"unqualified article"}))
                .unwrap()
                .is_none()
        );
        public["source_url"] = json!("https://attacker.invalid/w/rest.php/v1/page/X/with_html");
        assert!(target(&public).is_err());
    }
    #[test]
    fn discovery_exemption_cannot_carry_copied_content_or_arbitrary_urls() {
        let discovery = json!({"metadata_only_discovery":true,"source":"wikipedia","coverage":"upstream_discovery","items":[{"page_id":1,"fetch_id":"wikipedia:Artificial intelligence","url":"https://en.wikipedia.org/wiki/Artificial_intelligence"}]});
        assert!(is_metadata_only_discovery(&discovery));
        let mut copied = discovery.clone();
        copied["items"][0]["title"] = json!("copied title");
        assert!(!is_metadata_only_discovery(&copied));
        let mut injected = discovery;
        injected["items"][0]["url"] =
            json!("https://attacker.invalid/wiki/Artificial_intelligence");
        assert!(!is_metadata_only_discovery(&injected));
    }
}
