//! Repair the existing v1 capture subjects without changing their compiler.
use super::*;
use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
#[path = "rustsec_cluster_tests.rs"]
mod cluster_tests;

const HEAD: &str = "https://api.github.com/repos/RustSec/advisory-db/commits/main";
const BUNDLE: &str = "https://codeload.github.com/RustSec/advisory-db/tar.gz/";

fn bundle_revision(source: &Value) -> Option<&str> {
    string(source, "source_url")?
        .strip_prefix(BUNDLE)
        .filter(|v| oid(v))
}

pub(super) fn supported(source: &Value) -> bool {
    string(source, "body_hash").is_some_and(devres_domain::valid_content_id)
        && (string(source, "source_url") == Some(HEAD) || bundle_revision(source).is_some())
}

#[async_trait]
trait Reader: Sync {
    async fn fetch(&self, source: &Value, cancel: CancellationToken) -> Result<(Vec<u8>, Value)>;
}
struct BrokerReader<'a>(&'a Arc<BulkBroker>);
#[async_trait]
impl Reader for BrokerReader<'_> {
    async fn fetch(&self, source: &Value, cancel: CancellationToken) -> Result<(Vec<u8>, Value)> {
        acquire_core(source, self.0, cancel).await
    }
}

pub(super) async fn repair(
    target: &AttributionTarget,
    broker: &Arc<BulkBroker>,
    cancel: CancellationToken,
) -> Result<AttributionGeneration> {
    repair_with(target, &BrokerReader(broker), cancel).await
}

struct Bundle {
    files: BTreeMap<String, Vec<u8>>,
    notice: AttributionNotice,
}

async fn load_bundle(
    revision: &str,
    expected: Option<&Value>,
    reader: &dyn Reader,
    cancel: CancellationToken,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> Result<(Bundle, Value)> {
    acquisition_cancelled(&cancel)?;
    let source = expected.cloned().unwrap_or_else(
        || json!({"source_url":format!("{BUNDLE}{revision}"),"media_type":"application/gzip"}),
    );
    let (bytes, receipt) = reader.fetch(&source, cancel.clone()).await?;
    if expected.is_some() {
        verify_hash(&bytes, &source)?;
    }
    let revision = revision.to_owned();
    let source_url = format!("{BUNDLE}{revision}");
    let digest = crate::integrity::hash(&bytes);
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let files = crate::archive::rustsec_attribution_files(&bytes, &digest, &revision, deadline)
            .map_err(qualification_error)?;
        let files = files.into_iter().collect::<BTreeMap<_, _>>();
        let notice = bundle_notices(&source_url, &digest, &revision, &files, deadline)?;
        Ok::<_, Error>(Bundle { files, notice })
    })
    .await
    .map_err(|_| Error::unavailable("RustSec attribution worker failed."))??;
    acquisition_cancelled(&cancel)?;
    Ok((result, receipt))
}

fn is_notice(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    ["license", "copying", "copyright", "notice"]
        .iter()
        .any(|prefix| {
            name == *prefix
                || name.starts_with(&format!("{prefix}."))
                || name.starts_with(&format!("{prefix}-"))
        })
}

fn member_terms(path: &str, body: &str) -> Result<Option<(String, Option<String>)>> {
    if !path.starts_with("crates/") {
        return Ok(None);
    }
    let record = if path.ends_with(".md")
        && path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with("RUSTSEC-"))
    {
        let source = body
            .strip_prefix("```toml\n")
            .or_else(|| body.strip_prefix("```toml\r\n"))
            .ok_or_else(unqualified)?;
        let end = source.find("\n```").ok_or_else(unqualified)?;
        let parsed: toml::Value = toml::from_str(&source[..end]).map_err(|_| unqualified())?;
        serde_json::to_value(parsed.get("advisory").ok_or_else(unqualified)?)
            .map_err(|_| invalid_evidence())?
    } else if path.ends_with(".toml") {
        let parsed: toml::Value = toml::from_str(body).map_err(|_| unqualified())?;
        serde_json::to_value(parsed.get("advisory").ok_or_else(unqualified)?)
            .map_err(|_| invalid_evidence())?
    } else if path.ends_with(".json") {
        let parsed: Value = serde_json::from_str(body).map_err(|_| unqualified())?;
        parsed
            .get("database_specific")
            .cloned()
            .unwrap_or(Value::Null)
    } else if path
        .rsplit('/')
        .next()
        .is_some_and(|name| name.starts_with("RUSTSEC-"))
    {
        return Err(unqualified());
    } else {
        return Ok(None);
    };
    let Some(license) = record.get("license") else {
        return Ok(None);
    };
    let license = license
        .as_str()
        .filter(|v| matches!(*v, "CC0-1.0" | "CC-BY-4.0"))
        .ok_or_else(unqualified)?;
    let attribution = string(&record, "attribution_url").or_else(|| string(&record, "url"));
    if license == "CC-BY-4.0" && attribution.is_none() {
        return Err(incomplete());
    }
    Ok(Some((license.into(), attribution.map(str::to_owned))))
}

fn bundle_notices(
    url: &str,
    digest: &str,
    revision: &str,
    files: &BTreeMap<String, Vec<u8>>,
    deadline: std::time::Instant,
) -> Result<AttributionNotice> {
    if !files.contains_key("LICENSE.txt") {
        return Err(incomplete());
    }
    let mut entries = BTreeSet::new();
    let mut used = 0usize;
    let mut add = |entry: String| -> Result<()> {
        if entries.contains(&entry) {
            return Ok(());
        }
        used = used.saturating_add(entry.len()).saturating_add(2);
        if used > MAX_NOTICE {
            return Err(payload_bound(
                "RustSec notices exceed their aggregate bound.",
            ));
        }
        entries.insert(entry);
        Ok(())
    };
    for (path, bytes) in files {
        if std::time::Instant::now() >= deadline {
            return Err(payload_bound(
                "RustSec attribution processing deadline exceeded.",
            ));
        }
        let governing = is_notice(path);
        let text = std::str::from_utf8(bytes).ok();
        if governing {
            let text = text
                .filter(|v| !v.is_empty() && !v.contains('\0'))
                .ok_or_else(invalid_evidence)?;
            add(format!("Original repository notice: {path}\n{text}"))?;
        }
        // A vendored scope must have its own actual governing notice; a root
        // notice does not silently authorize nested third-party content.
        let components = path.split('/').collect::<Vec<_>>();
        if let Some(index) = components.iter().position(|part| {
            matches!(
                *part,
                "third_party" | "third-party" | "vendor" | "vendors" | "node_modules"
            )
        }) {
            let prefix = components[..=index].join("/") + "/";
            if !files.keys().any(|candidate| {
                candidate.starts_with(&prefix)
                    && is_notice(candidate)
                    && candidate
                        .rsplit_once('/')
                        .is_some_and(|(directory, _)| path.starts_with(&format!("{directory}/")))
            }) {
                return Err(unqualified());
            }
        }
        if let Some(text) = text {
            for original in original_member_notices(text)? {
                add(format!("Original member notice: {path}\n{original}"))?;
            }
            if let Some((license, attribution)) = member_terms(path, text)? {
                let mut entry = format!(
                    "Original advisory member: {path}\nOriginal advisory license: {license}"
                );
                if let Some(attribution) = attribution {
                    entry.push_str(&format!("\nOriginal advisory attribution: {attribution}"));
                }
                add(entry)?;
            }
        } else if path.starts_with("crates/") {
            return Err(unqualified());
        }
    }
    let text = entries.into_iter().collect::<Vec<_>>().join("\n\n");
    notice(
        url,
        text.as_bytes(),
        None,
        json!({"version":1,"scope":"verified_repository_members","revision":revision,"body_hash":digest}),
    )
}

async fn repair_with(
    target: &AttributionTarget,
    reader: &dyn Reader,
    cancel: CancellationToken,
) -> Result<AttributionGeneration> {
    let source = &target.evidence["source"];
    if !supported(source) {
        return Err(unsupported());
    }
    acquisition_cancelled(&cancel)?;
    // Admit before retaining compressed bytes; blocking work holds a clone even
    // if the async caller is dropped while its bounded parser finishes.
    let permit = Arc::new(crate::archive::admit().map_err(|error| {
        AttributionFailure::new(
            AttributionPhase::Acquisition,
            AttributionFailureReason::ParserBusy,
            AttributionDisposition::Retry,
        )
        .attach(error)
    })?);
    let mut receipts = Vec::new();
    let notices = if let Some(revision) = bundle_revision(source) {
        let (bundle, receipt) = load_bundle(
            revision,
            Some(source),
            reader,
            cancel.clone(),
            permit.clone(),
        )
        .await?;
        receipts.push(receipt);
        vec![bundle.notice]
    } else {
        let (bytes, receipt) = reader.fetch(source, cancel.clone()).await?;
        verify_hash(&bytes, source)?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(payload_bound("RustSec head exceeds 4 MiB."));
        }
        let revision = crate::rustsec::corpus::revision(&bytes).map_err(qualification_error)?;
        let head: Value = serde_json::from_slice(&bytes).map_err(|_| invalid_evidence())?;
        receipts.push(receipt);
        let parents = head
            .get("parents")
            .map(|v| v.as_array().ok_or_else(unqualified))
            .transpose()?
            .cloned()
            .unwrap_or_default();
        if parents.len() > 1 {
            return Err(unqualified());
        }
        let parent = parents
            .first()
            .map(|v| {
                string(v, "sha")
                    .filter(|s| oid(s))
                    .map(str::to_owned)
                    .ok_or_else(unqualified)
            })
            .transpose()?;
        if parent.as_deref() == Some(revision.as_str()) {
            return Err(unqualified());
        }
        let files = head
            .get("files")
            .map(|v| v.as_array().ok_or_else(unqualified))
            .transpose()?
            .cloned()
            .unwrap_or_default();
        if files.len() > 32 {
            return Err(payload_bound(
                "RustSec head member count exceeds its bound.",
            ));
        }
        let (current, receipt) =
            load_bundle(&revision, None, reader, cancel.clone(), permit.clone()).await?;
        receipts.push(receipt);
        let need_parent = !files.is_empty() && parent.is_some();
        let previous = if need_parent {
            let parent = parent.ok_or_else(unqualified)?;
            let (bundle, receipt) =
                load_bundle(&parent, None, reader, cancel.clone(), permit.clone()).await?;
            receipts.push(receipt);
            Some(bundle)
        } else {
            None
        };
        verify_head_files(&files, &current, previous.as_ref())?;
        let mut notices = vec![current.notice];
        if let Some(previous) = previous {
            notices.push(previous.notice);
        }
        notices
    };
    acquisition_cancelled(&cancel)?;
    if notices.iter().map(|v| v.text.len()).sum::<usize>() > MAX_NOTICE || receipts.len() > 256 {
        return Err(payload_bound(
            "RustSec attribution proof exceeds its bound.",
        ));
    }
    let generation = AttributionGeneration {
        subject: target.subject.clone(),
        policy_epoch: ATTRIBUTION_POLICY_EPOCH,
        policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
        notices,
        receipts,
    };
    if serde_json::to_vec(&generation)
        .map_err(|_| invalid_evidence())?
        .len()
        > 8 * 1024 * 1024
    {
        return Err(payload_bound(
            "RustSec attribution generation exceeds its bound.",
        ));
    }
    Ok(generation)
}

fn verify_head_files(files: &[Value], current: &Bundle, previous: Option<&Bundle>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for file in files {
        let path = string(file, "filename")
            .filter(|path| crate::archive::valid_relative_path(path))
            .ok_or_else(unqualified)?;
        if !seen.insert(path) {
            return Err(unqualified());
        }
        let status = string(file, "status").ok_or_else(unqualified)?;
        let old_path = if status == "renamed" {
            string(file, "previous_filename")
                .filter(|path| crate::archive::valid_relative_path(path))
                .ok_or_else(unqualified)?
        } else {
            path
        };
        let old = match status {
            "added" => &[][..],
            "modified" | "removed" | "renamed" => previous
                .and_then(|b| b.files.get(old_path))
                .map(Vec::as_slice)
                .ok_or_else(unqualified)?,
            _ => return Err(unqualified()),
        };
        let new = if status == "removed" {
            &[][..]
        } else {
            current
                .files
                .get(path)
                .map(Vec::as_slice)
                .ok_or_else(unqualified)?
        };
        if status == "added" && previous.is_some_and(|b| b.files.contains_key(path)) {
            return Err(unqualified());
        }
        if status == "removed" && current.files.contains_key(path) {
            return Err(unqualified());
        }
        if status == "renamed" && (old_path == path || current.files.contains_key(old_path)) {
            return Err(unqualified());
        }
        if let Some(sha) = string(file, "sha") {
            let represented = if status == "removed" { old } else { new };
            if !oid(sha) || crate::chromium::source::object_oid("blob", represented) != sha {
                return Err(source_mismatch(
                    "RustSec head member differs from exact Git object.",
                ));
            }
        }
        match string(file, "patch") {
            Some(patch) => verify_patch(patch, old, new)?,
            None if status == "renamed" && old == new => {}
            None => return Err(unqualified()),
        }
    }
    Ok(())
}

fn range(value: &str, prefix: char) -> Result<(usize, usize)> {
    let value = value.strip_prefix(prefix).ok_or_else(unqualified)?;
    let (start, count) = value.split_once(',').unwrap_or((value, "1"));
    let start = start.parse::<usize>().map_err(|_| unqualified())?;
    let count = count.parse::<usize>().map_err(|_| unqualified())?;
    Ok((
        if count == 0 {
            start
        } else {
            start.checked_sub(1).ok_or_else(unqualified)?
        },
        count,
    ))
}

/// Validate every hunk against both complete captured member bodies. Gaps between
/// hunks and the tail must be identical; truncated or ambiguous patches fail closed.
fn verify_patch(patch: &str, old: &[u8], new: &[u8]) -> Result<()> {
    let old = std::str::from_utf8(old).map_err(|_| unqualified())?;
    let new = std::str::from_utf8(new).map_err(|_| unqualified())?;
    let a = old
        .split_inclusive('\n')
        .map(|v| (v.strip_suffix('\n').unwrap_or(v), v.ends_with('\n')))
        .collect::<Vec<_>>();
    let b = new
        .split_inclusive('\n')
        .map(|v| (v.strip_suffix('\n').unwrap_or(v), v.ends_with('\n')))
        .collect::<Vec<_>>();
    let mut ai = 0usize;
    let mut bi = 0usize;
    let lines = patch.split_terminator('\n').collect::<Vec<_>>();
    let mut cursor = 0usize;
    let mut hunks = 0usize;
    while cursor < lines.len() {
        let header = lines[cursor]
            .strip_prefix("@@ ")
            .and_then(|v| v.split_once(" @@"))
            .map(|v| v.0)
            .ok_or_else(unqualified)?;
        let mut ranges = header.split(' ');
        let (start_a, count_a) = range(ranges.next().ok_or_else(unqualified)?, '-')?;
        let (start_b, count_b) = range(ranges.next().ok_or_else(unqualified)?, '+')?;
        if ranges.next().is_some()
            || start_a < ai
            || start_b < bi
            || start_a > a.len()
            || start_b > b.len()
            || a[ai..start_a] != b[bi..start_b]
        {
            return Err(unqualified());
        }
        ai = start_a;
        bi = start_b;
        let begin_a = ai;
        let begin_b = bi;
        cursor += 1;
        hunks += 1;
        while cursor < lines.len() && !lines[cursor].starts_with("@@ ") {
            let line = lines[cursor];
            cursor += 1;
            let content = line.get(1..).ok_or_else(unqualified)?;
            let newline = lines.get(cursor).copied() != Some("\\ No newline at end of file");
            if !newline {
                cursor += 1;
            }
            match line.as_bytes().first() {
                Some(b' ')
                    if a.get(ai) == Some(&(content, newline))
                        && b.get(bi) == Some(&(content, newline)) =>
                {
                    ai += 1;
                    bi += 1;
                }
                Some(b'-') if a.get(ai) == Some(&(content, newline)) => ai += 1,
                Some(b'+') if b.get(bi) == Some(&(content, newline)) => bi += 1,
                _ => {
                    return Err(source_mismatch(
                        "RustSec patch differs from exact member bytes.",
                    ));
                }
            }
            if ai.saturating_sub(begin_a) > count_a || bi.saturating_sub(begin_b) > count_b {
                return Err(unqualified());
            }
        }
        if ai - begin_a != count_a || bi - begin_b != count_b {
            return Err(unqualified());
        }
    }
    if hunks == 0 || a[ai..] != b[bi..] {
        return Err(unqualified());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::{io::Write, sync::Mutex};

    const REV: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PARENT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TERMS: &str = "Synthetic repository notice: CC0-1.0; explicitly attributed imports retain CC-BY-4.0 and their original attribution.\n";
    fn bundle_notices(
        url: &str,
        digest: &str,
        revision: &str,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<AttributionNotice> {
        super::bundle_notices(
            url,
            digest,
            revision,
            files,
            std::time::Instant::now() + Duration::from_secs(2),
        )
    }
    pub(super) fn archive(revision: &str, files: &[(&str, &str)]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::XGlobalHeader);
        header.set_mode(0o644);
        header.set_size(52);
        header.set_cksum();
        tar.append_data(
            &mut header,
            "pax_global_header",
            format!("52 comment={revision}\n").as_bytes(),
        )
        .unwrap();
        for (path, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(body.len() as u64);
            header.set_cksum();
            tar.append_data(
                &mut header,
                format!("advisory-db-{revision}/{path}"),
                body.as_bytes(),
            )
            .unwrap();
        }
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&tar.into_inner().unwrap()).unwrap();
        gzip.finish().unwrap()
    }
    struct Fixture {
        responses: BTreeMap<String, Vec<u8>>,
        requests: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl Reader for Fixture {
        async fn fetch(
            &self,
            source: &Value,
            cancel: CancellationToken,
        ) -> Result<(Vec<u8>, Value)> {
            acquisition_cancelled(&cancel)?;
            let url = string(source, "source_url").unwrap();
            self.requests.lock().unwrap().push(url.into());
            let body = self
                .responses
                .get(url)
                .ok_or_else(|| Error::not_found("Synthetic response absent."))?
                .clone();
            let receipt = json!({"version":1,"source_url":url,"body_hash":crate::integrity::hash(&body),"status":200,"validated_at":devres_domain::unix_now(),"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT});
            Ok((body, receipt))
        }
    }
    fn fixture(responses: Vec<(String, Vec<u8>)>) -> Fixture {
        Fixture {
            responses: responses.into_iter().collect(),
            requests: Mutex::new(Vec::new()),
        }
    }
    async fn fixture_repair(
        target: &AttributionTarget,
        reader: &Fixture,
    ) -> Result<AttributionGeneration> {
        // Shared parser contention is a separate behavior (classified retry).
        // Fixtures wait only before source I/O, so parallel tests cannot turn a
        // deterministic evidence assertion into an admission-race assertion.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match repair_with(target, reader, CancellationToken::new()).await {
                Err(error)
                    if AttributionFailure::from_error(&error).is_some_and(|failure| {
                        failure.reason == AttributionFailureReason::ParserBusy
                    }) && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                result => return result,
            }
        }
    }
    fn target(url: &str, bytes: &[u8]) -> AttributionTarget {
        targets(
            "rustsec",
            &json!({"source_url":url,"body_hash":crate::integrity::hash(bytes)}),
        )
        .unwrap()
        .pop()
        .unwrap()
    }
    async fn run_head(
        head: Value,
        current: &[(&str, &str)],
        previous: Option<&[(&str, &str)]>,
    ) -> Result<AttributionGeneration> {
        let head = serde_json::to_vec(&head).unwrap();
        let mut responses = vec![
            (HEAD.into(), head.clone()),
            (format!("{BUNDLE}{REV}"), archive(REV, current)),
        ];
        if let Some(previous) = previous {
            responses.push((format!("{BUNDLE}{PARENT}"), archive(PARENT, previous)));
        }
        fixture_repair(&target(HEAD, &head), &fixture(responses)).await
    }
    #[tokio::test]
    async fn bundle_exact_capture_preserves_nested_and_imported_notices() {
        let body = archive(
            REV,
            &[
                ("LICENSE.txt", TERMS),
                (
                    "crates/example/RUSTSEC-2024-0001.md",
                    "```toml\n[advisory]\nid='RUSTSEC-2024-0001'\nlicense='CC-BY-4.0'\nurl='https://github.com/advisories/GHSA-synthetic'\n```\n\n# Fixture advisory\n<!-- Copyright synthetic author; licensed under CC-BY-4.0 -->\n",
                ),
                ("vendor/example/LICENSE", "Synthetic nested governing terms"),
                ("vendor/example/file.txt", "inert synthetic bytes"),
            ],
        );
        let url = format!("{BUNDLE}{REV}");
        let target = target(&url, &body);
        let fixture = fixture(vec![(url.clone(), body)]);
        let generation = fixture_repair(&target, &fixture).await.unwrap();
        assert_eq!(generation.subject, target.subject);
        assert_eq!(generation.policy_epoch, ATTRIBUTION_POLICY_EPOCH);
        assert_eq!(generation.notices.len(), 1);
        for retained in [
            "Synthetic nested governing terms",
            "CC-BY-4.0",
            "https://github.com/advisories/GHSA-synthetic",
            "Copyright synthetic author",
        ] {
            assert!(generation.notices[0].text.contains(retained));
        }
        assert_eq!(*fixture.requests.lock().unwrap(), vec![url]);
    }
    #[tokio::test]
    async fn moved_head_and_changed_bundle_remain_blocked_without_other_requests() {
        for url in [HEAD.to_owned(), format!("{BUNDLE}{REV}")] {
            let fixture = fixture(vec![(url.clone(), b"changed bytes".to_vec())]);
            let error = fixture_repair(&target(&url, b"original bytes"), &fixture)
                .await
                .unwrap_err();
            let failure = AttributionFailure::from_error(&error).unwrap();
            assert_eq!(failure.reason, AttributionFailureReason::SourceMismatch);
            assert_eq!(failure.disposition, AttributionDisposition::Blocked);
            assert_eq!(fixture.requests.lock().unwrap().len(), 1);
        }
    }
    #[tokio::test]
    async fn head_without_patch_qualifies_only_exact_captured_head_and_bundle() {
        let head =
            serde_json::to_vec(&json!({"sha":REV,"parents":[{"sha":PARENT}],"files":[]})).unwrap();
        let fixture = fixture(vec![
            (HEAD.into(), head.clone()),
            (
                format!("{BUNDLE}{REV}"),
                archive(REV, &[("LICENSE.txt", TERMS)]),
            ),
        ]);
        let generation = fixture_repair(&target(HEAD, &head), &fixture)
            .await
            .unwrap();
        assert_eq!(generation.receipts.len(), 2);
        assert_eq!(fixture.requests.lock().unwrap().len(), 2);
        assert!(generation.notices[0].text.contains(TERMS.trim()));
    }
    #[tokio::test]
    async fn head_validates_added_modified_removed_and_renamed_members() {
        let head = json!({"sha":REV,"parents":[{"sha":PARENT}],"files":[
            {"filename":"added.txt","status":"added","patch":"@@ -0,0 +1 @@\n+added"},
            {"filename":"modified.txt","status":"modified","patch":"@@ -1 +1 @@\n-old\n+new"},
            {"filename":"removed.txt","status":"removed","patch":"@@ -1 +0,0 @@\n-removed"},
            {"filename":"renamed.txt","previous_filename":"original.txt","status":"renamed"}
        ]});
        let generation = run_head(
            head,
            &[
                ("LICENSE.txt", TERMS),
                ("added.txt", "added\n"),
                ("modified.txt", "new\n"),
                ("renamed.txt", "same\n"),
            ],
            Some(&[
                ("LICENSE.txt", TERMS),
                ("modified.txt", "old\n"),
                ("removed.txt", "removed\n"),
                ("original.txt", "same\n"),
            ]),
        )
        .await
        .unwrap();
        assert_eq!(generation.receipts.len(), 3);
        assert_eq!(generation.notices.len(), 2);
    }
    #[tokio::test]
    async fn root_addition_is_supported_but_bad_hunks_merges_and_missing_members_are_blocked() {
        let good = json!({"sha":REV,"parents":[],"files":[{"filename":"added.txt","status":"added","patch":"@@ -0,0 +1 @@\n+added"}]});
        assert!(
            run_head(
                good.clone(),
                &[("LICENSE.txt", TERMS), ("added.txt", "added\n")],
                None
            )
            .await
            .is_ok()
        );
        let mut wrong = good.clone();
        wrong["files"][0]["patch"] = json!("@@ -0,0 +1 @@\n+different");
        assert!(
            run_head(
                wrong,
                &[("LICENSE.txt", TERMS), ("added.txt", "added\n")],
                None
            )
            .await
            .is_err()
        );
        assert!(
            run_head(good, &[("LICENSE.txt", TERMS)], None)
                .await
                .is_err()
        );
        let merge = json!({"sha":REV,"parents":[{"sha":PARENT},{"sha":"c".repeat(40)}],"files":[]});
        assert!(
            run_head(merge, &[("LICENSE.txt", TERMS)], None)
                .await
                .is_err()
        );
    }
    #[test]
    fn patch_requires_complete_hunks_both_sides_and_exact_newlines() {
        assert!(verify_patch("@@ -1 +1 @@\n-old\n+new", b"old\n", b"new\n").is_ok());
        assert!(
            verify_patch(
                "@@ -1 +1 @@\n-old\n+new",
                b"old\nextra\n",
                b"new\nchanged\n"
            )
            .is_err()
        );
        assert!(verify_patch("@@ -1,2 +1 @@\n-old\n+new", b"old\n", b"new\n").is_err());
        assert!(verify_patch("@@ -1 +1 @@\n-old\n+new", b"old", b"new\n").is_err());
        assert!(
            verify_patch(
                "@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new",
                b"old",
                b"new\n"
            )
            .is_ok()
        );
        assert!(verify_patch("@@ -1 +1 @@\n-old\r\n+new\r\n", b"old\r\n", b"new\r\n").is_ok());
    }
    #[test]
    fn missing_or_ambiguous_notice_scope_and_oversized_proof_remain_withheld() {
        let make = |files: &[(&str, &str)]| {
            files
                .iter()
                .map(|(p, b)| (p.to_string(), b.as_bytes().to_vec()))
                .collect::<BTreeMap<_, _>>()
        };
        let url = format!("{BUNDLE}{REV}");
        for files in [
            vec![("file.txt", "without license")],
            vec![
                ("LICENSE.txt", TERMS),
                ("vendor/one/LICENSE", "one scope"),
                ("vendor/two/file.txt", "unqualified sibling"),
            ],
            vec![
                ("LICENSE.txt", TERMS),
                (
                    "crates/example/RUSTSEC-2024-0001.md",
                    "```toml\n[advisory]\nlicense='CC-BY-4.0'\n```\n# Missing original attribution\n",
                ),
            ],
        ] {
            assert!(bundle_notices(&url, "blake3:fixture", REV, &make(&files)).is_err());
        }
        let oversized = "x".repeat(MAX_NOTICE + 1);
        assert!(
            bundle_notices(
                &url,
                "blake3:fixture",
                REV,
                &make(&[("LICENSE.txt", &oversized)])
            )
            .is_err()
        );
        let osv = make(&[
            ("LICENSE.txt", TERMS),
            (
                "crates/RUSTSEC-2024-0001.json",
                "{\"database_specific\":{\"license\":\"CC-BY-4.0\",\"url\":\"https://example.invalid/original\"}}",
            ),
        ]);
        assert!(
            bundle_notices(&url, "blake3:fixture", REV, &osv)
                .unwrap()
                .text
                .contains("https://example.invalid/original")
        );
        let toml = make(&[
            ("LICENSE.txt", TERMS),
            (
                "crates/example/RUSTSEC-2024-0001.toml",
                "[advisory]\nlicense='CC-BY-4.0'\nattribution_url='https://example.invalid/historical'\n",
            ),
        ]);
        assert!(
            bundle_notices(&url, "blake3:fixture", REV, &toml)
                .unwrap()
                .text
                .contains("https://example.invalid/historical")
        );
        let missing = make(&[
            ("LICENSE.txt", TERMS),
            (
                "crates/example/RUSTSEC-2024-0001.toml",
                "[advisory]\nlicense='CC-BY-4.0'\n",
            ),
        ]);
        assert!(bundle_notices(&url, "blake3:fixture", REV, &missing).is_err());
    }
    #[test]
    fn archive_revision_duplicate_and_trailer_validation_precede_notices() {
        let checksum = |bytes: &[u8]| crate::integrity::hash(bytes);
        let inspect = |bytes: &[u8], rev: &str| {
            crate::archive::rustsec_attribution_files(
                bytes,
                &checksum(bytes),
                rev,
                std::time::Instant::now() + Duration::from_secs(2),
            )
        };
        let valid = archive(REV, &[("LICENSE.txt", TERMS)]);
        assert!(inspect(&valid, REV).is_ok());
        assert!(inspect(&valid, PARENT).is_err());
        let duplicated = archive(REV, &[("LICENSE.txt", TERMS), ("LICENSE.txt", TERMS)]);
        assert!(inspect(&duplicated, REV).is_err());
        let mut truncated = valid;
        truncated.truncate(truncated.len() - 5);
        assert!(inspect(&truncated, REV).is_err());
    }
    #[test]
    fn recovery_predicate_is_exact_and_keeps_v1_targets_stable() {
        let source = target(HEAD, b"synthetic head");
        let before = targets(
            "rustsec",
            &json!({"source_url":HEAD,"body_hash":crate::integrity::hash(b"synthetic head")}),
        )
        .unwrap();
        assert!(rustsec_capture_supported(&source));
        assert_eq!(before, vec![source.clone()]);
        let mut wrapper = source.clone();
        wrapper.evidence = json!({"version":1,"dependencies":[source]});
        assert!(rustsec_capture_supported(&wrapper));
        for url in [
            "https://api.github.com/repos/RustSec/advisory-db/commits/main?unsafe=1",
            "https://codeload.github.com/RustSec/advisory-db/tar.gz/main",
            "https://evil.invalid/source",
        ] {
            assert!(!rustsec_capture_supported(&target(url, b"synthetic")));
        }
    }
}
