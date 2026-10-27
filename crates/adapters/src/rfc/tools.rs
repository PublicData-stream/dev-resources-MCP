//! Additive snapshot-pinned RFC research tools.
use crate::{
    research::{Page, capture_json, decode, list_limit, text_limit, text_page},
    rfc::corpus::{
        BODY_LIMIT, RfcCorpus, media_type, representation_key, representation_url,
        select_search_documents,
    },
    rfc::index as rfc_index,
    rfc::source as rfc,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use devres_application::corpus::{Dataset, Snapshot};
use devres_domain::{Error, FetchRequest, Result};
use serde::Deserialize;
use serde_json::{Value, json};
static RESEARCH_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Filters {
    status: Option<String>,
    author: Option<String>,
    keyword: Option<String>,
    stream: Option<String>,
    area: Option<String>,
    working_group: Option<String>,
    published_from: Option<String>,
    published_through: Option<String>,
    series: Option<String>,
}
impl Filters {
    fn checked(&self) -> Result<()> {
        for value in [
            &self.status,
            &self.author,
            &self.keyword,
            &self.stream,
            &self.area,
            &self.working_group,
            &self.series,
        ]
        .into_iter()
        .flatten()
        {
            if value.trim().is_empty() || value.chars().count() > 256 {
                return Err(Error::invalid(
                    "RFC filters must contain 1..256 characters.",
                ));
            }
        }
        for date in [&self.published_from, &self.published_through]
            .into_iter()
            .flatten()
        {
            if date.len() != 7
                || date.as_bytes()[4] != b'-'
                || !date[..4].bytes().all(|b| b.is_ascii_digit())
                || !matches!(date[5..].parse::<u8>(), Ok(1..=12))
            {
                return Err(Error::invalid("RFC publication bounds must be YYYY-MM."));
            }
        }
        if let (Some(from), Some(through)) = (&self.published_from, &self.published_through)
            && from > through
        {
            return Err(Error::invalid("RFC publication range is reversed."));
        }
        Ok(())
    }
    fn matches(&self, record: &Value) -> bool {
        let equal = |field: &str, filter: &Option<String>| {
            filter.as_ref().is_none_or(|s| {
                record[field]
                    .as_str()
                    .is_some_and(|v| v.eq_ignore_ascii_case(s))
            })
        };
        let contains = |field: &str, filter: &Option<String>| {
            filter.as_ref().is_none_or(|s| {
                record[field].as_array().is_some_and(|values| {
                    values.iter().any(|v| {
                        v.as_str()
                            .is_some_and(|v| v.to_lowercase().contains(&s.to_lowercase()))
                    })
                })
            })
        };
        equal("status", &self.status)
            && equal("stream", &self.stream)
            && equal("area", &self.area)
            && equal("working_group", &self.working_group)
            && contains("authors", &self.author)
            && contains("keywords", &self.keyword)
            && self.series.as_ref().is_none_or(|series| {
                record["series"].as_array().is_some_and(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|v| normalize_series(v) == normalize_series(series))
                })
            })
            && self.published_from.as_ref().is_none_or(|from| {
                record["publication"]
                    .as_str()
                    .is_some_and(|date| date >= from.as_str())
            })
            && self.published_through.as_ref().is_none_or(|through| {
                record["publication"]
                    .as_str()
                    .is_some_and(|date| date <= through.as_str())
            })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataInput {
    number: u32,
    #[serde(default)]
    snapshot: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogueInput {
    #[serde(default)]
    query: String,
    #[serde(default)]
    filters: Filters,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "list_limit")]
    limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FulltextInput {
    query: String,
    #[serde(default = "technical")]
    mode: String,
    #[serde(default)]
    filters: Filters,
    #[serde(default)]
    assurance: Option<String>,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "list_limit")]
    limit: usize,
}
fn technical() -> String {
    "technical".into()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FormatInput {
    pub number: u32,
    pub format: String,
    #[serde(default)]
    pub capture: Option<String>,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "text_limit")]
    pub limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrataInput {
    number: u32,
    #[serde(default)]
    status: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "list_limit")]
    limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeriesInput {
    series: String,
    number: u32,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "list_limit")]
    limit: usize,
}

fn check_number(number: u32) -> Result<()> {
    if !(1..=999999).contains(&number) {
        return Err(Error::invalid("RFC number must be 1..999999."));
    }
    Ok(())
}
fn check_query(query: &str, empty: bool) -> Result<()> {
    if (!empty && query.trim().is_empty()) || query.chars().count() > 256 {
        return Err(Error::invalid(
            "RFC query must contain at most 256 characters.",
        ));
    }
    Ok(())
}
fn page(items: Vec<Value>, offset: usize, limit: usize) -> Value {
    let total = items.len();
    let selected = items
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    json!({"items":selected,"total":total,"offset":offset,"next_offset":if offset.saturating_add(limit)<total {Some(offset+limit)}else{None}})
}
async fn dataset_for(corpus: &RfcCorpus, snapshot: &Snapshot, kind: &str) -> Result<Dataset> {
    let id = if kind == "catalogue" {
        Some(snapshot.catalogue_capture.as_str())
    } else {
        snapshot.errata_capture.as_deref()
    };
    let id = id.ok_or_else(|| Error::unavailable("RFC errata coverage is incomplete."))?;
    let mut dataset = corpus
        .store
        .dataset(kind, Some(id))
        .await?
        .ok_or_else(|| Error::integrity("RFC snapshot dataset is missing."))?;
    let observation = if kind == "catalogue" {
        "catalogue_validated_at"
    } else {
        "errata_validated_at"
    };
    if let Some(observed) = snapshot.coverage[observation].as_i64() {
        dataset.capture.validated_at = observed;
    }
    Ok(dataset)
}
fn attach_snapshot(value: &mut Value, snapshot: &Snapshot) {
    value["snapshot"] = json!(snapshot.id);
    value["coverage"] = snapshot.coverage.clone();
    value["snapshot_created_at"] = json!(snapshot.created_at);
    let oldest = snapshot
        .documents
        .iter()
        .map(|d| d.capture.validated_at)
        .chain(snapshot.coverage["catalogue_validated_at"].as_i64())
        .chain(snapshot.coverage["errata_validated_at"].as_i64())
        .min()
        .unwrap_or(snapshot.created_at);
    let age = devres_domain::unix_now().saturating_sub(oldest);
    value["freshness"] = json!({"oldest_validated_at":oldest,"stale":age>86400,"expired":age>7*86400,"coverage_is_at_snapshot_publication":true});
}

pub(crate) async fn call(corpus: &RfcCorpus, tool: &str, input: Value) -> Result<Value> {
    let _admission = RESEARCH_SLOTS
        .try_acquire()
        .map_err(|_| Error::capacity("RFC research capacity exhausted."))?;
    match tool {
        "rfc.metadata" => {
            let input: MetadataInput = decode(input)?;
            check_number(input.number)?;
            let snapshot = corpus.selected_snapshot(input.snapshot.as_deref()).await?;
            let dataset = dataset_for(corpus, &snapshot, "catalogue").await?;
            let record = dataset
                .records
                .iter()
                .find(|r| r["number"].as_u64() == Some(input.number.into()))
                .ok_or_else(|| Error::not_found("RFC metadata not present in this snapshot."))?;
            let mut value =
                json!({"metadata":record,"capture":capture_json(&dataset.capture,86400)});
            attach_snapshot(&mut value, &snapshot);
            Ok(value)
        }
        "rfc.catalog_search" => {
            let input: CatalogueInput = decode(input)?;
            check_query(&input.query, true)?;
            input.filters.checked()?;
            Page {
                offset: input.offset,
                limit: input.limit,
            }
            .checked()?;
            let snapshot = corpus.selected_snapshot(input.snapshot.as_deref()).await?;
            let dataset = dataset_for(corpus, &snapshot, "catalogue").await?;
            let permit = crate::archive::admit()?;
            let mut value=tokio::task::spawn_blocking(move||{
                let _permit=permit;let deadline=std::time::Instant::now()+std::time::Duration::from_secs(15);
                let terms=input.query.to_lowercase().split_whitespace().map(str::to_owned).collect::<std::collections::HashSet<_>>();
                let mut total=0usize;let mut items=Vec::new();
                for record in dataset.records {
                    if std::time::Instant::now()>=deadline{return Err(Error::capacity("RFC metadata search time budget exceeded."));}
                    if !input.filters.matches(&record){continue;}
                    let mut searchable=format!("rfc{} ",record["number"]);
                    for field in ["title","abstract_text","status","published","stream","area","working_group","doi"]{if let Some(text)=record[field].as_str(){searchable.push_str(text);searchable.push(' ');}}
                    for field in ["authors","keywords","series"]{if let Some(values)=record[field].as_array(){for value in values.iter().filter_map(Value::as_str){searchable.push_str(value);searchable.push(' ');}}}
                    let searchable=searchable.to_lowercase();
                    if !terms.iter().all(|term|searchable.contains(term)){continue;}
                    if total>=input.offset&&items.len()<input.limit{items.push(json!({"id":format!("rfc:{}",record["number"]),"metadata":record}));}total+=1;
                }
                Ok::<_,Error>(json!({"items":items,"total":total,"offset":input.offset,"next_offset":if input.offset.saturating_add(input.limit)<total{Some(input.offset+input.limit)}else{None}}))
            }).await.map_err(|_|Error::unavailable("RFC metadata search worker failed."))??;
            value["capture"] = capture_json(&dataset.capture, 86400);
            attach_snapshot(&mut value, &snapshot);
            Ok(value)
        }
        "rfc.fulltext_search" => {
            let input: FulltextInput = decode(input)?;
            check_query(&input.query, false)?;
            input.filters.checked()?;
            Page {
                offset: input.offset,
                limit: input.limit,
            }
            .checked()?;
            if !matches!(input.mode.as_str(), "technical" | "english") {
                return Err(Error::invalid(
                    "RFC search mode must be technical or english.",
                ));
            }
            if input
                .assurance
                .as_ref()
                .is_some_and(|v| v != "https" && v != "rsync")
            {
                return Err(Error::invalid("RFC assurance must be https or rsync."));
            }
            if input.snapshot.is_none() {
                corpus.refresh_partial().await?;
            }
            let snapshot = corpus.selected_snapshot(input.snapshot.as_deref()).await?;
            let dataset = dataset_for(corpus, &snapshot, "catalogue").await?;
            let selected = select_search_documents(&snapshot.search_documents);
            let allowed = dataset
                .records
                .iter()
                .filter(|r| input.filters.matches(r))
                .filter_map(|r| r["number"].as_u64().and_then(|n| u32::try_from(n).ok()))
                .filter(|n| {
                    selected
                        .get(n)
                        .is_some_and(|d| input.assurance.as_ref().is_none_or(|a| &d.assurance == a))
                })
                .collect::<Vec<_>>();
            let root = corpus.root.clone();
            let index = snapshot
                .index_path
                .clone()
                .ok_or_else(|| Error::unavailable("RFC search index is not available."))?;
            let mut value = tokio::task::spawn_blocking(move || {
                rfc_index::search(
                    &root,
                    &index,
                    &input.query,
                    &input.mode,
                    input.offset,
                    input.limit,
                    Some(&allowed),
                )
            })
            .await
            .map_err(|_| Error::unavailable("RFC search processor failed."))??;
            if let Some(items) = value["items"].as_array_mut() {
                for item in items {
                    let number = item["number"].as_u64().unwrap_or(0) as u32;
                    if let Some(document) = selected.get(&number) {
                        item["id"] = json!(format!("rfc:{number}"));
                        item["capture"] = json!(document.capture);
                        item["assurance"] = json!(document.assurance);
                        item["resource_uri"] = json!(format!(
                            "devres://rfc/{number}/{}/{}",
                            document.format, document.capture.id
                        ));
                    }
                }
            }
            attach_snapshot(&mut value, &snapshot);
            Ok(value)
        }
        "rfc.format_get" => format_get(corpus, decode(input)?).await,
        "rfc.errata" => {
            let input: ErrataInput = decode(input)?;
            check_number(input.number)?;
            Page {
                offset: input.offset,
                limit: input.limit,
            }
            .checked()?;
            for filter in [&input.status, &input.kind].into_iter().flatten() {
                check_query(filter, false)?;
            }
            if input.snapshot.is_none() && corpus.store.dataset("errata", None).await?.is_none() {
                corpus.refresh_errata().await?;
                corpus.publish_snapshot().await?;
            }
            let snapshot = corpus.selected_snapshot(input.snapshot.as_deref()).await?;
            let dataset = dataset_for(corpus, &snapshot, "errata").await?;
            let records = dataset
                .records
                .into_iter()
                .filter(|r| {
                    errata_number(r) == Some(input.number)
                        && input.status.as_ref().is_none_or(|s| {
                            r["errata_status_code"]
                                .as_str()
                                .is_some_and(|v| v.eq_ignore_ascii_case(s))
                        })
                        && input.kind.as_ref().is_none_or(|s| {
                            r["errata_type_code"]
                                .as_str()
                                .is_some_and(|v| v.eq_ignore_ascii_case(s))
                        })
                })
                .collect();
            let mut value = page(records, input.offset, input.limit);
            value["capture"] = capture_json(&dataset.capture, 86400);
            attach_snapshot(&mut value, &snapshot);
            Ok(value)
        }
        "rfc.series_get" => {
            let input: SeriesInput = decode(input)?;
            check_number(input.number)?;
            Page {
                offset: input.offset,
                limit: input.limit,
            }
            .checked()?;
            let series = input.series.to_uppercase();
            if !matches!(series.as_str(), "STD" | "BCP" | "FYI") {
                return Err(Error::invalid("RFC series must be STD, BCP, or FYI."));
            }
            let wanted = format!("{series}{}", input.number);
            let snapshot = corpus.selected_snapshot(input.snapshot.as_deref()).await?;
            let dataset = dataset_for(corpus, &snapshot, "catalogue").await?;
            let records = dataset
                .records
                .into_iter()
                .filter(|r| {
                    r["series"].as_array().is_some_and(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .any(|v| normalize_series(v) == wanted)
                    })
                })
                .collect();
            let mut value = page(records, input.offset, input.limit);
            value["series"] = json!(wanted);
            value["capture"] = capture_json(&dataset.capture, 86400);
            attach_snapshot(&mut value, &snapshot);
            Ok(value)
        }
        "rfc.corpus_status" => {
            let _: Empty = decode(input)?;
            corpus.status().await
        }
        _ => Err(Error::not_found("Unknown RFC research tool.")),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
fn normalize_series(value: &str) -> String {
    let value = value.to_uppercase();
    let at = value
        .find(|c: char| c.is_ascii_digit())
        .unwrap_or(value.len());
    format!("{}{}", &value[..at], value[at..].trim_start_matches('0'))
}
fn errata_number(record: &Value) -> Option<u32> {
    record["doc-id"].as_str()?.strip_prefix("RFC")?.parse().ok()
}

pub(crate) async fn format_get(corpus: &RfcCorpus, input: FormatInput) -> Result<Value> {
    check_number(input.number)?;
    let mime = media_type(&input.format)?;
    if input.limit == 0 || input.limit > 32768 {
        return Err(Error::invalid("RFC page limit must be 1..32768 bytes."));
    }
    let mut assurance = "https";
    let unpinned = input.capture.is_none();
    let stored = match input.capture {
        Some(id) => {
            let stored = corpus.retrieval.read_capture(&id).await?;
            let expected = representation_key(input.number, &input.format, "https");
            let mirror = representation_key(input.number, &input.format, "rsync");
            if stored.capture.key == mirror {
                assurance = "rsync";
            } else if stored.capture.key != expected {
                return Err(Error::invalid(
                    "RFC capture belongs to a different number or format.",
                ));
            }
            stored
        }
        None => {
            corpus
                .retrieval
                .get_validated(
                    FetchRequest {
                        key: representation_key(input.number, &input.format, "https"),
                        url: representation_url(input.number, &input.format),
                        ttl_secs: 86400,
                        max_bytes: BODY_LIMIT,
                        media_type: mime.into(),
                    },
                    &rfc::Validator,
                )
                .await?
        }
    };
    let body = stored.body.clone();
    let format = input.format.clone();
    tokio::task::spawn_blocking(move || rfc::validate_representation(&format, &body))
        .await
        .map_err(|_| Error::unavailable("RFC format processor failed."))??;
    if unpinned {
        corpus
            .record_foreground(input.number, &input.format, &stored.capture)
            .await?;
    }
    let page = if input.format == "pdf" {
        if input.offset > stored.body.len() {
            return Err(Error::invalid("RFC byte offset exceeds content."));
        }
        let end = input
            .offset
            .saturating_add(input.limit)
            .min(stored.body.len());
        json!({"encoding":"base64","data":STANDARD.encode(&stored.body[input.offset..end]),"offset":input.offset,"total_bytes":stored.body.len(),"next_offset":if end<stored.body.len(){Some(end)}else{None}})
    } else {
        let text = std::str::from_utf8(&stored.body)
            .map_err(|_| Error::integrity("RFC source is not UTF-8."))?;
        let mut page = text_page(text, input.offset, input.limit)?;
        page["encoding"] = json!("utf-8");
        page
    };
    Ok(
        json!({"id":format!("rfc:{}",input.number),"format":input.format,"media_type":mime,"assurance":assurance,"transport_authenticated":assurance=="https","page":page,"capture":capture_json(&stored.capture,86400),"resource_uri":format!("devres://rfc/{}/{}/{}?offset={}&limit={}",input.number,input.format,stored.capture.id,input.offset,input.limit),"license_notice":"Preserve original RFC copyright and license notices."}),
    )
}

pub(crate) fn format_from_uri(url: &url::Url) -> Result<FormatInput> {
    let parts = url
        .path()
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(Error::invalid("Invalid RFC format resource."));
    }
    let number = parts[0]
        .parse()
        .map_err(|_| Error::invalid("Invalid RFC number."))?;
    let format = parts[1].to_owned();
    media_type(&format)?;
    let mut input = FormatInput {
        number,
        format,
        capture: Some(parts[2].into()),
        offset: 0,
        limit: 32768,
    };
    let mut seen = std::collections::HashSet::new();
    for (k, v) in url.query_pairs() {
        if !seen.insert(k.to_string()) {
            return Err(Error::invalid("Duplicate RFC page parameter."));
        }
        match k.as_ref() {
            "offset" => {
                input.offset = v
                    .parse()
                    .map_err(|_| Error::invalid("Invalid RFC byte offset."))?
            }
            "limit" => {
                input.limit = v
                    .parse()
                    .map_err(|_| Error::invalid("Invalid RFC byte limit."))?
            }
            _ => return Err(Error::invalid("Unknown RFC page parameter.")),
        }
    }
    Ok(input)
}

pub(crate) fn schemas() -> Vec<Value> {
    let text = json!({"type":"string","minLength":1,"maxLength":256});
    let snapshot = json!({"type":"string","pattern":"^[0-9a-f]{64}$"});
    let number = json!({"type":"integer","minimum":1,"maximum":999999});
    let offset = json!({"type":"integer","minimum":0,"maximum":1000000});
    let limit = json!({"type":"integer","minimum":1,"maximum":100,"default":20});
    let mut filter_properties = json!({"status":text,"author":text,"keyword":text,"stream":text,"area":text,"working_group":text,"series":text});
    for name in ["published_from", "published_through"] {
        filter_properties[name] = json!({"type":"string","pattern":"^[0-9]{4}-(0[1-9]|1[0-2])$"});
    }
    let filters =
        json!({"type":"object","additionalProperties":false,"properties":filter_properties});
    let tool = |name: &str, description: &str, properties: Value, required: Vec<&str>| json!({"name":name,"description":description,"inputSchema":{"type":"object","additionalProperties":false,"properties":properties,"required":required},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}});
    vec![
        tool(
            "rfc.metadata",
            "Rich RFC index metadata pinned to a research snapshot.",
            json!({"number":number,"snapshot":snapshot}),
            vec!["number"],
        ),
        tool(
            "rfc.catalog_search",
            "Search rich RFC metadata; filters combine with AND. Reuse snapshot for stable pages.",
            json!({"query":{"type":"string","maxLength":256},"filters":filters,"snapshot":snapshot,"offset":offset,"limit":limit}),
            vec![],
        ),
        tool(
            "rfc.fulltext_search",
            "Search archived RFC text with technical AND tokens or explicit English phrases, OR and minus exclusions. Coverage and provenance are explicit.",
            json!({"query":text,"mode":{"enum":["technical","english"],"default":"technical"},"filters":filters,"assurance":{"enum":["https","rsync"]},"snapshot":snapshot,"offset":offset,"limit":limit}),
            vec!["query"],
        ),
        tool(
            "rfc.format_get",
            "Read published txt/html/xml inert source or base64 pdf bytes; reuse capture for stable paging.",
            json!({"number":number,"format":{"enum":["txt","html","xml","pdf"]},"capture":snapshot,"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":32768,"default":32768}}),
            vec!["number", "format"],
        ),
        tool(
            "rfc.errata",
            "Read original errata records and statuses against a pinned research snapshot; never modifies RFC text.",
            json!({"number":number,"status":text,"type":text,"snapshot":snapshot,"offset":offset,"limit":limit}),
            vec!["number"],
        ),
        tool(
            "rfc.series_get",
            "Resolve STD/BCP/FYI membership without replacing requested RFC identities.",
            json!({"series":{"enum":["STD","BCP","FYI"]},"number":number,"snapshot":snapshot,"offset":offset,"limit":limit}),
            vec!["series", "number"],
        ),
        tool(
            "rfc.corpus_status",
            "Read aggregate RFC collection progress, freshness, snapshots and explicit gaps.",
            json!({}),
            vec![],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filters_validate_unicode_dates_without_panics() {
        for date in ["éé-é", "2025-00", "2025-13", "2025-01"] {
            let f = Filters {
                published_from: Some(date.into()),
                ..Default::default()
            };
            assert_eq!(f.checked().is_ok(), date == "2025-01");
        }
    }
    #[test]
    fn series_and_typed_uri_are_bound() {
        assert_eq!(normalize_series("BCP0014"), "BCP14");
        assert!(
            format_from_uri(&url::Url::parse("devres://rfc/1/pdf/abc?limit=1&limit=2").unwrap())
                .is_err()
        );
    }
}
