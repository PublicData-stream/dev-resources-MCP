use super::*;
use crate::collection::{Phase, context};
use devres_domain::Capture;

fn request() -> FetchRequest {
    FetchRequest {
        key: "rfc:text:1".into(),
        url: "https://www.rfc-editor.org/rfc/rfc1.txt".into(),
        ttl_secs: 10,
        max_bytes: 1024,
        media_type: "text/plain".into(),
    }
}
fn original_error() -> Error {
    Error::unavailable("original failure")
        .with_details(serde_json::json!({"retry_at":123,"private":"secret"}))
}
struct FixtureStore {
    cached: bool,
    failure: Option<Phase>,
}
impl FixtureStore {
    fn stored() -> StoredCapture {
        StoredCapture {
            capture: Capture {
                id: "a".repeat(64),
                key: request().key,
                source_url: request().url,
                body_hash: "b".repeat(64),
                media_type: "text/plain".into(),
                retrieved_at: 100,
                validated_at: 100,
            },
            body: b"retained".to_vec().into(),
        }
    }
}
#[async_trait]
impl Store for FixtureStore {
    async fn latest(&self, _: &str) -> Result<Option<Cached>> {
        if self.failure == Some(Phase::RetainedLookup) {
            return Err(original_error());
        }
        Ok(self.cached.then(|| Cached {
            stored: Self::stored(),
            validators: Validators::default(),
        }))
    }
    async fn capture(&self, _: &str) -> Result<StoredCapture> {
        Ok(Self::stored())
    }
    async fn publish(&self, _: &FetchRequest, _: FetchResponse, _: i64) -> Result<StoredCapture> {
        if self.failure == Some(Phase::ArtifactPublication) {
            Err(original_error())
        } else {
            Ok(Self::stored())
        }
    }
    async fn revalidate(&self, _: &str, _: &str, _: Validators, _: i64) -> Result<StoredCapture> {
        if self.failure == Some(Phase::Revalidation) {
            Err(original_error())
        } else {
            Ok(Self::stored())
        }
    }
}
struct FixtureFetcher {
    status: u16,
    failure: bool,
}
#[async_trait]
impl Fetcher for FixtureFetcher {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        if self.failure {
            Err(original_error())
        } else {
            Ok(FetchResponse {
                status: self.status,
                body: b"fixture".to_vec(),
                validators: Validators::default(),
            })
        }
    }
}
struct Validator {
    diagnostics: bool,
    failure: bool,
}
#[async_trait]
impl ResponseValidator for Validator {
    fn collection_diagnostics(&self) -> bool {
        self.diagnostics
    }
    fn acquisition(&self, _: &FetchRequest) -> Result<Option<acquisition::Acquisition>> {
        Ok(Some(acquisition::Acquisition::RfcRepresentation {
            number: 1,
            format: "txt".into(),
        }))
    }
    async fn validate(&self, _: &FetchRequest, response: FetchResponse) -> Result<FetchResponse> {
        if self.failure {
            Err(original_error())
        } else {
            Ok(response)
        }
    }
}
struct ClockAt(i64);
impl Clock for ClockAt {
    fn now(&self) -> i64 {
        self.0
    }
}
fn retrieval(
    status: u16,
    fetch_failure: bool,
    cached: bool,
    store_failure: Option<Phase>,
    now: i64,
) -> Retrieval {
    Retrieval::with_clock(
        Arc::new(FixtureStore {
            cached,
            failure: store_failure,
        }),
        Arc::new(FixtureFetcher {
            status,
            failure: fetch_failure,
        }),
        Arc::new(ClockAt(now)),
    )
}

#[tokio::test]
async fn opted_in_retrieval_distinguishes_failures_and_preserves_original_metadata() {
    for (phase, status, transport, validation, cached) in [
        (Phase::HttpAcquisition, 200, true, false, false),
        (Phase::SourceValidation, 200, false, true, false),
        (Phase::ArtifactPublication, 200, false, false, false),
        (Phase::RetainedLookup, 200, false, false, false),
        (Phase::Revalidation, 304, false, false, true),
    ] {
        let store_failure = matches!(
            phase,
            Phase::ArtifactPublication | Phase::RetainedLookup | Phase::Revalidation
        )
        .then_some(phase);
        let error = retrieval(status, transport, cached, store_failure, 200)
            .get_validated(
                request(),
                &Validator {
                    diagnostics: true,
                    failure: validation,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(context(&error).unwrap().phase, phase);
        assert_eq!(error.code, "unavailable");
        assert_eq!(error.message, "original failure");
        assert_eq!(error.details.as_ref().unwrap()["retry_at"], 123);
    }
}

#[tokio::test]
async fn http_status_is_bounded_and_non_opted_in_contracts_stay_unchanged() {
    for (status, code) in [(404, "not_found"), (503, "unavailable")] {
        let error = retrieval(status, false, false, None, 200)
            .get_validated(
                request(),
                &Validator {
                    diagnostics: true,
                    failure: false,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, code);
        assert_eq!(context(&error).unwrap().phase, Phase::HttpAcquisition);
        assert_eq!(context(&error).unwrap().http_status, Some(status));
        let original = retrieval(status, false, false, None, 200)
            .get_validated(
                request(),
                &Validator {
                    diagnostics: false,
                    failure: false,
                },
            )
            .await
            .unwrap_err();
        assert!(original.details.is_none());
    }
    let error = retrieval(200, true, false, None, 200)
        .get_validated(
            request(),
            &Validator {
                diagnostics: false,
                failure: false,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.details, original_error().details);
}

#[tokio::test]
async fn diagnostics_preserve_background_stale_fallback_and_strict_refresh() {
    let validator = Validator {
        diagnostics: true,
        failure: false,
    };
    let retrieval = retrieval(503, false, true, None, 200);
    let stored = retrieval
        .get_background_validated(request(), &validator)
        .await
        .unwrap();
    assert_eq!(stored.capture.validated_at, 100);
    let error = retrieval
        .get_fresh_validated(request(), &validator)
        .await
        .unwrap_err();
    assert_eq!(context(&error).unwrap().http_status, Some(503));
    let expired =
        super::retrieval_diagnostics_tests::retrieval(503, false, true, None, 100 + 7 * 86400 + 1)
            .get_background_validated(request(), &validator)
            .await
            .unwrap_err();
    assert_eq!(expired.code, "unavailable");
}

#[tokio::test]
async fn opted_in_retrieval_admission_and_body_limits_are_distinct() {
    let validator = Validator {
        diagnostics: true,
        failure: false,
    };
    let retrieval = retrieval(200, false, false, None, 200);
    let mut invalid = request();
    invalid.max_bytes = 0;
    let error = retrieval
        .get_validated(invalid, &validator)
        .await
        .unwrap_err();
    assert_eq!(context(&error).unwrap().phase, Phase::RetrievalAdmission);
    let mut small = request();
    small.max_bytes = 1;
    let error = retrieval
        .get_validated(small, &validator)
        .await
        .unwrap_err();
    assert_eq!(context(&error).unwrap().phase, Phase::HttpBody);
}

#[tokio::test]
async fn delegated_errors_stay_unchanged_even_with_diagnostics_opt_in() {
    struct UnavailableWriter;
    #[async_trait]
    impl acquisition::AcquisitionDelegate for UnavailableWriter {
        async fn acquire(&self, _: acquisition::Acquisition) -> Result<Capture> {
            Err(original_error())
        }
        async fn effect(&self, _: acquisition::WriterEffect) -> Result<()> {
            Ok(())
        }
    }
    let retrieval =
        retrieval(200, false, false, None, 200).with_delegate(Arc::new(UnavailableWriter));
    let error = retrieval
        .get_validated(
            request(),
            &Validator {
                diagnostics: true,
                failure: false,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.details, original_error().details);
    assert!(context(&error).is_none());
}
