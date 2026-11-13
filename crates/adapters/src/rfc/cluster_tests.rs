//! First-party retained RFC generations in the stopped disposable cluster.
//! This seeds publication fixtures, not evidence of official provider acquisition.
use super::{RfcConfig, RfcCorpus, corpus, source, tools};
use async_trait::async_trait;
use devres_application::{
    Fetcher, Retrieval, Store,
    attribution::AttributionStore,
    collection::{Failure, Phase, http_failure},
    corpus::{Dataset, JobSpec, RfcCorpusStore},
};
use devres_domain::{
    Error, FetchRequest, FetchResponse, Result, Validators, attribution::*, unix_now,
};
use serde_json::json;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

const HISTORICAL: &str =
    "First-party synthetic fixturetransport historicalfixturebody. Not official RFC content.\n";
const CURRENT: &str =
    "First-party synthetic fixturetransport currentfixturebody. Not official RFC content.\n";
const NOTICE: &str = "First-party synthetic retained RFC acceptance by dev-resources-MCP contributors, AGPL-3.0-only. This is not upstream source or upstream licensing evidence.";
struct NoNetwork;
#[async_trait]
impl Fetcher for NoNetwork {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        Err(Error::integrity(
            "Retained RFC fixture attempted provider traffic.",
        ))
    }
}

async fn publish(
    store: &crate::PgBlobStore,
    key: &str,
    url: &str,
    media_type: &str,
    body: &[u8],
) -> devres_domain::Capture {
    store
        .publish(
            &FetchRequest {
                key: key.into(),
                url: url.into(),
                ttl_secs: 86400,
                max_bytes: 65536,
                media_type: media_type.into(),
            },
            FetchResponse {
                status: 200,
                body: body.to_vec(),
                validators: Validators::default(),
            },
            unix_now(),
        )
        .await
        .unwrap()
        .capture
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires stopped disposable cluster writer, PostgreSQL and optional fixture S3"]
async fn rfc_collector_cluster_seed() {
    let root = PathBuf::from(std::env::var("BLOB_DIR").expect("disposable cluster blob root"));
    let database = std::env::var("DATABASE_URL").expect("disposable cluster PostgreSQL");
    let archive = std::env::var_os("DEVRES_TEST_S3_CONFIG")
        .map(|path| toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap());
    let store = Arc::new(
        crate::PgBlobStore::connect_archive_for_maintenance(&database, &root, archive)
            .await
            .unwrap(),
    );
    let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
    let corpus = Arc::new(
        RfcCorpus::new(
            retrieval.clone(),
            store.clone(),
            &root,
            RfcConfig {
                enabled: false,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let entries = [9000,9001,9002].map(|number| format!("<rfc-entry><doc-id>RFC{number}</doc-id><title>First-party synthetic transport fixture</title><format><file-format>TEXT</file-format></format></rfc-entry>")).join("");
    let xml =
        format!("<rfc-index xmlns=\"https://www.rfc-editor.org/rfc-index\">{entries}</rfc-index>");
    let catalogue = publish(
        &store,
        "rfc:index",
        corpus::INDEX_URL,
        "application/xml",
        xml.as_bytes(),
    )
    .await;
    let records = source::parse_index(xml.as_bytes())
        .unwrap()
        .into_iter()
        .map(|record| serde_json::to_value(record).unwrap())
        .collect();
    store
        .save_dataset(
            "catalogue",
            &Dataset {
                capture: catalogue,
                records,
            },
        )
        .await
        .unwrap();
    let errata = publish(
        &store,
        "rfc:errata",
        corpus::ERRATA_URL,
        "application/json",
        b"[]",
    )
    .await;
    store
        .save_dataset(
            "errata",
            &Dataset {
                capture: errata,
                records: vec![],
            },
        )
        .await
        .unwrap();
    let mut historical = None;
    for number in [9000, 9001] {
        let capture = publish(
            &store,
            &corpus::representation_key(number, "txt", "https"),
            &corpus::representation_url(number, "txt"),
            "text/plain",
            HISTORICAL.as_bytes(),
        )
        .await;
        corpus
            .record_foreground(number, "txt", &capture)
            .await
            .unwrap();
        if number == 9000 {
            historical = Some(capture);
        }
    }
    let missing = JobSpec {
        key: "rfc:text:9002".into(),
        number: 9002,
        format: "txt".into(),
        source_url: corpus::representation_url(9002, "txt"),
        assurance: "https".into(),
        due_at: unix_now(),
    };
    store.schedule(&[missing]).await.unwrap();
    let claimed = store.claim(unix_now()).await.unwrap().unwrap();
    assert_eq!(claimed.spec.key, "rfc:text:9002");
    let error = http_failure(
        Error::unavailable("Synthetic acquisition fixture unavailable."),
        Phase::HttpAcquisition,
        503,
    );
    let failure = Failure::from_error(&error, Phase::PublicationAcquisition, unix_now());
    store
        .finish(&claimed.spec.key, None, Some(&failure), unix_now() + 3600)
        .await
        .unwrap();
    let old = corpus.publish_snapshot().await.unwrap();
    assert!(!old.complete);
    assert_eq!(old.coverage["searchable_documents"], 2);
    assert_eq!(old.coverage["missing_representations"], 1);
    let historical = historical.unwrap();
    let current = publish(
        &store,
        "rfc:text:9000",
        &corpus::representation_url(9000, "txt"),
        "text/plain",
        CURRENT.as_bytes(),
    )
    .await;
    corpus
        .record_foreground(9000, "txt", &current)
        .await
        .unwrap();
    let latest = corpus.publish_snapshot().await.unwrap();
    assert_ne!(latest.id, old.id);
    assert!(!latest.complete);
    let research = crate::Research::new(retrieval)
        .await
        .unwrap()
        .with_corpus(corpus.clone());
    let arguments = json!({"snapshot":old.id,"query":"fixturetransport","limit":10});
    let resource = format!("devres://rfc/9000/txt/{}", historical.id);
    let mut targets = BTreeMap::new();
    for value in [
        tools::call(&corpus, "rfc.fulltext_search", arguments.clone())
            .await
            .unwrap(),
        tools::call(
            &corpus,
            "rfc.fulltext_search",
            json!({"query":"fixturetransport","limit":10}),
        )
        .await
        .unwrap(),
        tools::call(
            &corpus,
            "rfc.format_get",
            json!({"number":9000,"format":"txt","capture":historical.id}),
        )
        .await
        .unwrap(),
        research.read_resource(&resource).await.unwrap(),
        research
            .read_resource(&format!("devres://rfc/9000/txt/{}", current.id))
            .await
            .unwrap(),
    ] {
        for target in crate::attribution_providers::targets("rfc", &value).unwrap() {
            targets.insert(serde_json::to_string(&target.subject).unwrap(), target);
        }
    }
    assert!(!targets.is_empty());
    for target in targets.values() {
        store.attribution_enqueue(target, 1).await.unwrap();
    }
    for admission in 0..1024 {
        if targets.is_empty() {
            break;
        }
        let now = unix_now();
        let job = store
            .attribution_claim(&["rfc".into()], now, admission)
            .await
            .unwrap()
            .expect("synthetic attribution claim");
        let key = serde_json::to_string(&job.target.subject).unwrap();
        let Some(target) = targets.remove(&key) else {
            store
                .attribution_fail(&job, Some(now + 300), "fixture_deferred")
                .await
                .unwrap();
            continue;
        };
        let generation = AttributionGeneration {
            subject: target.subject,
            policy_epoch: ATTRIBUTION_POLICY_EPOCH,
            policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
            notices: vec![AttributionNotice {
                source_url: "https://fixtures.invalid/devres/rfc-retained".into(),
                license: Some("AGPL-3.0-only".into()),
                copyright: Some("dev-resources-MCP synthetic fixture authors".into()),
                text: NOTICE.into(),
                evidence: json!({"synthetic":true,"fixture":"rfc-retained-v1"}),
            }],
            receipts: vec![
                json!({"kind":"synthetic_fixture_validation","synthetic":true,"status":200,"source_url":"https://fixtures.invalid/devres/rfc-retained","body_hash":crate::integrity::hash(NOTICE.as_bytes()),"validated_at":now,"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT,"source_fingerprint":job.target.subject.fingerprint}),
            ],
        };
        store.attribution_complete(&job, &generation).await.unwrap();
    }
    assert!(targets.is_empty(), "synthetic attribution claim bound");
    let receipt = json!({"provider":"rfc","tool":"rfc.fulltext_search","arguments":arguments,"resource":resource,"expected":"historicalfixturebody"});
    std::fs::write(
        "/tmp/rfc-collector-receipt.json",
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
}
