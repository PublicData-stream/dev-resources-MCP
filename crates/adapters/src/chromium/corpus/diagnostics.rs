//! Private, bounded failed-observation identities. Rejected bodies are never retained.
use super::*;
use source::ValidationReason;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Component {
    Src,
    Site,
    Chrome,
    ChromeArchive,
}
impl Component {
    fn as_str(self) -> &'static str {
        match self {
            Self::Src => "src",
            Self::Site => "site",
            Self::Chrome => "chrome",
            Self::ChromeArchive => "chrome-archive",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "src" => Ok(Self::Src),
            "site" => Ok(Self::Site),
            "chrome" => Ok(Self::Chrome),
            "chrome-archive" => Ok(Self::ChromeArchive),
            _ => Err(Error::integrity("Invalid Chromium diagnostic component.")),
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Lane {
    Current,
    History,
}
impl Lane {
    fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::History => "history",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "current" => Ok(Self::Current),
            "history" => Ok(Self::History),
            _ => Err(Error::integrity("Invalid Chromium diagnostic lane.")),
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Step {
    Refs,
    AnnotatedTags,
    Tag,
    Commit,
    Tree,
    Blob,
    Sitemap,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FailedObservation {
    version: u32,
    component: Component,
    lane: Lane,
    operation: Step,
    reason: ValidationReason,
    observed_at: i64,
    body_bytes: u64,
    body_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selected_oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claimed_oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    computed_oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    raw_commit_attempt: Option<source::RawCommitAttempt>,
}

impl FailedObservation {
    fn pointer_key(&self) -> String {
        state_key(
            "validation-failure-v1",
            &format!("{}:{}", self.component.as_str(), self.lane.as_str()),
        )
    }
    fn verify(&self) -> Result<()> {
        if let Some(attempt) = &self.raw_commit_attempt {
            attempt.validate()?;
        }
        if self.version != 1
            || self.observed_at < 0
            || self.body_bytes > source::MAX_METADATA_BYTES as u64
            || !self.body_digest.starts_with("blake3:")
            || !crate::integrity::valid_hash(&self.body_digest)
            || self
                .selected_oid
                .iter()
                .chain(self.claimed_oid.iter())
                .chain(self.computed_oid.iter())
                .any(|id| !source::valid_oid(id))
        {
            return Err(Error::integrity("Invalid Chromium failed observation."));
        }
        Ok(())
    }
}

/// Typed private operator projection; arbitrary source strings are not admitted.
pub(crate) fn diagnose_validation_failure(value: Value) -> Result<Value> {
    let observation: FailedObservation = decode(value)?;
    observation.verify()?;
    encode(&observation)
}

impl ChromiumCorpus {
    pub(super) async fn validate_source<T>(
        &self,
        context: (&str, &str),
        operation: Step,
        response: &source::SourceResponse,
        selected_oid: Option<&str>,
        result: Result<T>,
    ) -> Result<T> {
        let Err(error) = &result else { return result };
        let observation = FailedObservation {
            version: 1,
            component: Component::parse(context.0)?,
            lane: Lane::parse(context.1)?,
            operation,
            reason: source::validation_reason(error),
            observed_at: response.observed_at,
            body_bytes: response.bytes.len() as u64,
            body_digest: inventory::digest(&response.bytes),
            selected_oid: selected_oid.map(str::to_owned),
            claimed_oid: source::diagnostic_oid(error, "chromium_claimed_oid"),
            computed_oid: source::diagnostic_oid(error, "chromium_computed_oid"),
            raw_commit_attempt: source::raw_commit_attempt(error),
        };
        observation.verify()?;
        let data = encode(&observation)?;
        let id = inventory::digest(&serde_json::to_vec(&data).map_err(|_| failure())?);
        self.store
            .chromium_put("validation-failures", &id, &data)
            .await
            .map_err(|error| {
                devres_application::collection::at_phase(
                    error,
                    devres_application::collection::Phase::RawRetention,
                )
            })?;
        // The immutable observation remains retained after a later success/restart.
        // Its identity is private and never added to public collector status.
        self.store
            .chromium_set_state(&observation.pointer_key(), &json!(id))
            .await?;
        result.map_err(|error| {
            devres_application::collection::at_phase(
                error,
                devres_application::collection::Phase::SourceValidation,
            )
        })
    }

    pub(super) fn verify_failed_observation(id: &str, data: &Value) -> Result<()> {
        if !id.starts_with("blake3:") {
            return Err(Error::integrity(
                "Invalid Chromium failure observation identity.",
            ));
        }
        crate::integrity::verify(id, &serde_json::to_vec(data).map_err(|_| failure())?)?;
        let observation: FailedObservation = decode(data.clone())?;
        observation.verify()
    }

    pub(super) fn verify_failed_observation_pointer(
        key: &str,
        id: &str,
        data: &Value,
    ) -> Result<()> {
        Self::verify_failed_observation(id, data)?;
        let observation: FailedObservation = decode(data.clone())?;
        if observation.pointer_key() != key {
            return Err(Error::integrity(
                "Chromium failure observation scope mismatch.",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(bytes: Vec<u8>) -> source::SourceResponse {
        source::SourceResponse {
            status: 200,
            bytes,
            observed_at: 123,
            source_url: "https://untrusted.invalid/private-path".into(),
            next: None,
            retry_at: None,
        }
    }

    #[tokio::test]
    async fn private_failed_observation_survives_restart_and_never_retains_body_or_public_details()
    {
        let broker = Arc::new(BulkBroker::new(Default::default()).unwrap());
        let (root, store, corpus) = super::super::tests::corpus_fixture(broker.clone()).await;
        let selected = "12".repeat(20);
        let bytes = serde_json::to_vec(&json!({
            "commit":selected,"tree":"34".repeat(20),"parents":[],
            "committer":{"time":"invalid-private-date"},"message":"private-upstream-text"
        }))
        .unwrap();
        let response = response(bytes.clone());
        for _ in 0..2 {
            let error = corpus
                .validate_source(
                    ("src", "history"),
                    Step::Commit,
                    &response,
                    Some(&selected),
                    source::parse_commit("src", &bytes),
                )
                .await
                .unwrap_err();
            assert_eq!(
                devres_application::collection::context(&error)
                    .unwrap()
                    .phase,
                devres_application::collection::Phase::SourceValidation
            );
            assert!(
                !error
                    .details
                    .unwrap()
                    .to_string()
                    .contains("chromium_validation")
            );
        }
        let pointer = state_key("validation-failure-v1", "src:history");
        let id = store.chromium_state(&pointer).await.unwrap().unwrap();
        let row = store
            .chromium_get("validation-failures", id.as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.data["reason"], "commit_date");
        assert_eq!(row.data["body_digest"], inventory::digest(&bytes));
        assert_eq!(row.data["body_bytes"], bytes.len());
        assert_eq!(row.data["selected_oid"], selected);
        assert_eq!(
            store
                .chromium_rows("validation-failures", 0, 100, None)
                .await
                .unwrap()
                .len(),
            1
        );
        let serialized = row.data.to_string();
        assert!(!serialized.contains("private"));
        assert!(!serialized.contains("source_url"));
        assert!(!serialized.contains("artifact"));
        assert!(
            ChromiumCorpus::verify_failed_observation_pointer(
                &state_key("validation-failure-v1", "site:current"),
                &row.key,
                &row.data,
            )
            .is_err()
        );
        assert_eq!(
            diagnose_validation_failure(row.data.clone()).unwrap(),
            row.data
        );
        corpus
            .verify_blake3_graph(CancellationToken::new())
            .await
            .unwrap();
        // Canonical private rows survive graph migration without derived rewrites.
        let mut mappings = crate::migration_map::MigrationMap::default();
        corpus
            .migrate_blake3_graph(&mut mappings, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            store
                .chromium_get("validation-failures", &row.key)
                .await
                .unwrap()
                .unwrap()
                .data,
            row.data
        );
        drop(corpus);
        let restarted = ChromiumCorpus::new(
            store.clone(),
            broker.clone(),
            root.path(),
            ChromiumConfig {
                enabled: false,
                min_free_bytes: 64 * 1024 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        restarted.initialize_status().await.unwrap();
        assert_eq!(store.chromium_state(&pointer).await.unwrap(), Some(id));
        let public = restarted.status().await.unwrap().to_string();
        assert!(!public.contains("body_digest"));
        assert!(!public.contains("commit_date"));
        assert_eq!(broker.attempt_count(), 0);
        // A missing private edge is a verification failure, even with no published view.
        store.remove_test_row("validation-failures", &row.key);
        assert!(
            restarted
                .verify_blake3_graph(CancellationToken::new())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn raw_timestamp_proof_graph_checks_coherence_and_keeps_legacy_commit_rows() {
        let broker = Arc::new(BulkBroker::new(Default::default()).unwrap());
        let (_root, store, corpus) = super::super::tests::corpus_fixture(broker).await;
        let commit = Commit {
            revision: "ab".repeat(20),
            tree: "cd".repeat(20),
            parents: vec![],
            committed_at: 123,
        };
        let proof = source::RawTimestampProof {
            version: 1,
            selected_oid: commit.revision.clone(),
            encoded_bytes: 128,
            encoded_digest: inventory::digest(b"synthetic proof bytes"),
            epoch: 123,
        };
        store
            .chromium_put(
                "commits",
                "legacy-natural-key",
                &json!({"component":"src","commit":commit}),
            )
            .await
            .unwrap();
        let data = json!({"component":"site","commit":commit,"timestamp_proof":proof});
        store
            .chromium_put("commits", "proof-natural-key", &data)
            .await
            .unwrap();
        corpus
            .verify_blake3_graph(CancellationToken::new())
            .await
            .unwrap();
        for (field, value) in [
            ("version", json!(2)),
            ("epoch", json!(124)),
            (
                "encoded_bytes",
                json!(source::MAX_RAW_COMMIT_ENCODED_BYTES + 1),
            ),
            ("selected_oid", json!("ef".repeat(20))),
            ("message", json!("must not be admitted")),
        ] {
            store.remove_test_row("commits", "proof-natural-key");
            let mut changed = data.clone();
            changed["timestamp_proof"][field] = value;
            store
                .chromium_put("commits", "proof-natural-key", &changed)
                .await
                .unwrap();
            assert!(
                corpus
                    .verify_blake3_graph(CancellationToken::new())
                    .await
                    .is_err(),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn mismatched_blob_records_only_safe_exact_identities_and_closed_schema() {
        let broker = Arc::new(BulkBroker::new(Default::default()).unwrap());
        let (_root, store, corpus) = super::super::tests::corpus_fixture(broker).await;
        let expected = "ab".repeat(20);
        let body = b"unqualified secret rejected body";
        let response = response(STANDARD.encode(body).into_bytes());
        let error = corpus
            .validate_source(
                ("site", "current"),
                Step::Blob,
                &response,
                Some(&expected),
                source::decode_blob("site", &response.bytes, &expected),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, "integrity");
        let row = store
            .chromium_rows("validation-failures", 0, 1, None)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(row.data["reason"], "blob_object_hash");
        assert_eq!(row.data["computed_oid"], source::object_oid("blob", body));
        assert_eq!(row.data["claimed_oid"], expected);
        assert!(!row.data.to_string().contains("secret"));
        ChromiumCorpus::verify_failed_observation(&row.key, &row.data).unwrap();
        for (field, value) in [
            ("version", json!(2)),
            ("lane", json!("unknown")),
            ("reason", json!("arbitrary-upstream-text")),
            ("body_bytes", json!(source::MAX_METADATA_BYTES as u64 + 1)),
            ("selected_oid", json!("unsafe-identifier")),
            ("body", json!("unexpected-data")),
        ] {
            let mut mutated = row.data.clone();
            mutated[field] = value;
            let id = inventory::digest(&serde_json::to_vec(&mutated).unwrap());
            assert!(
                ChromiumCorpus::verify_failed_observation(&id, &mutated).is_err(),
                "{field}"
            );
        }
    }
}
