//! First-party acceptance attribution. This utility never qualifies upstream data:
//! its fixed selectors name only the synthetic fixtures written by storage-probe.
use super::*;
use async_trait::async_trait;
use devres_application::{Fetcher, Retrieval, attribution::AttributionStore};
use devres_domain::{Error, Result as DomainResult, StoredCapture, attribution::*};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, sync::Arc};

const FIXTURE_NOTICE: &str = "First-party synthetic acceptance fixture by dev-resources-MCP contributors, licensed AGPL-3.0-only. This is not upstream source or upstream licensing evidence.";
struct NoNetwork;
#[async_trait]
impl Fetcher for NoNetwork {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> DomainResult<FetchResponse> {
        Err(Error::integrity(
            "Synthetic attribution qualification cannot contact upstream providers.",
        ))
    }
}

pub(super) async fn seed(
    store: Arc<PgBlobStore>,
    root: &Path,
    capture: &StoredCapture,
) -> Result<(), Box<dyn std::error::Error>> {
    if capture.body.as_ref() != b"Synthetic dev-resources persistence acceptance fixture\n"
        || capture.capture.key != "rfc:fixture-storage-probe"
        || capture.capture.source_url != "https://fixtures.invalid/devres/storage-probe"
    {
        return Err("Synthetic attribution fixture identity differs".into());
    }
    let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
    let broker = Arc::new(devres_adapters::bulk::BulkBroker::new(Default::default())?);
    let advisory = Arc::new(devres_adapters::AdvisoryCorpus::new(
        retrieval.clone(),
        store.clone(),
        broker.clone(),
        root,
        devres_adapters::RustSecConfig {
            enabled: false,
            ..Default::default()
        },
    )?);
    let mdn = Arc::new(devres_adapters::mdn::research::MdnResearch::new(
        store.clone(),
        root,
    )?);
    let whatwg = Arc::new(devres_adapters::WhatwgCorpus::new(
        store.clone(),
        broker.clone(),
        root,
        devres_adapters::WhatwgConfig {
            enabled: false,
            ..Default::default()
        },
    )?);
    let w3c = Arc::new(devres_adapters::W3cCorpus::new(
        store.clone(),
        broker.clone(),
        root,
        devres_adapters::W3cConfig {
            enabled: false,
            ..Default::default()
        },
    )?);
    let chromium = Arc::new(devres_adapters::ChromiumCorpus::new(
        store.clone(),
        broker,
        root,
        devres_adapters::ChromiumConfig {
            enabled: false,
            ..Default::default()
        },
    )?);
    let npm = npm_fixture_corpus(store.clone(), root)?;
    let research = devres_adapters::Research::new(retrieval)
        .await?
        .with_advisory_corpus(advisory)
        .with_mdn_research(mdn)
        .with_whatwg_corpus(whatwg)
        .with_w3c_corpus(w3c)
        .with_chromium_corpus(chromium)
        .with_npm_corpus(npm);
    let mdn_content = fixture_hash(MDN_CONTENT_IDENTITY);
    let mdn_compat = fixture_hash(MDN_COMPAT_IDENTITY);
    let whatwg_snapshot = fixture_hash(WHATWG_IDENTITY);
    let w3c_snapshot = fixture_hash(W3C_IDENTITY);
    let chromium_snapshot = fixture_hash(CHROMIUM_IDENTITY);
    let advisory_snapshot = fixture_hash(FIXTURE_IDENTITY);
    let versions = research
        .call("packages.npm.versions", json!({"name":"npm-fixture"}))
        .await?;
    let npm_snapshot = versions["snapshot"]["id"].clone();
    let npm_advisories = research
        .call(
            "packages.npm.advisory_lookup",
            json!({"name":"npm-fixture","version":"1.0.0"}),
        )
        .await?;
    let npm_advisory_snapshot = npm_advisories["snapshot"]["id"].clone();
    let mut calls = vec![
        (
            "rustsec",
            "packages.crate.advisory_get",
            json!({"id":"RUSTSEC-2024-0001","snapshot":advisory_snapshot}),
        ),
        (
            "rustsec",
            "packages.crate.advisory_catalog_search",
            json!({"snapshot":advisory_snapshot,"filters":{"name":"example","id":"RUSTSEC-2024-0001"}}),
        ),
        (
            "rustsec",
            "packages.crate.advisory_lookup",
            json!({"name":"example","version":"1.0.0","advisory_snapshot":advisory_snapshot}),
        ),
        (
            "rustsec",
            "packages.crate.advisory_lookup",
            json!({"name":"example","version":"1.0.1","advisory_snapshot":advisory_snapshot}),
        ),
        (
            "mdn",
            "mdn.get",
            json!({"slug":"Web/Fixture","snapshot":mdn_content,"compatibility_snapshot":mdn_compat}),
        ),
        (
            "mdn",
            "mdn.get",
            json!({"slug":"Web/Fixture","snapshot":mdn_content,"representation":"source"}),
        ),
        (
            "mdn",
            "mdn.search",
            json!({"query":"fetch","snapshot":mdn_content}),
        ),
        (
            "mdn",
            "mdn.compat_get",
            json!({"feature":"api.fixtureFetch","snapshot":mdn_compat}),
        ),
        (
            "mdn",
            "mdn.compat_search",
            json!({"query":"fetch","snapshot":mdn_compat}),
        ),
        (
            "mdn",
            "mdn.browser_get",
            json!({"browser":"fixture_browser","snapshot":mdn_compat}),
        ),
        (
            "npm",
            "packages.npm.versions",
            json!({"name":"npm-fixture"}),
        ),
        (
            "npm",
            "packages.npm.document_get",
            json!({"name":"npm-fixture","version":"1.0.0","snapshot":npm_snapshot,"path":"README.md"}),
        ),
        (
            "npm",
            "packages.npm.content_search",
            json!({"snapshot":npm_snapshot,"query":"FixtureToken"}),
        ),
        (
            "npm",
            "packages.npm.contract_get",
            json!({"name":"npm-fixture","version":"1.0.0","snapshot":npm_snapshot}),
        ),
        (
            "npm",
            "packages.npm.advisory_lookup",
            json!({"name":"npm-fixture","version":"1.0.0"}),
        ),
        (
            "npm",
            "packages.npm.advisory_get",
            json!({"id":"GHSA-fixt-ure0-npm0","snapshot":npm_advisory_snapshot}),
        ),
    ];
    for (provider, snapshot) in [
        ("whatwg", whatwg_snapshot),
        ("w3c", w3c_snapshot),
        ("chromium", chromium_snapshot),
    ] {
        let base = if provider == "whatwg" {
            json!({"standard":"fixture","snapshot":snapshot})
        } else if provider == "w3c" {
            json!({"specification":"fixture","snapshot":snapshot})
        } else {
            json!({"component":"src","path":"docs/fixture.html","snapshot":snapshot})
        };
        let get = match provider {
            "whatwg" => "whatwg.get",
            "w3c" => "w3c.get",
            _ => "chromium.get",
        };
        let search = match provider {
            "whatwg" => "whatwg.search",
            "w3c" => "w3c.search",
            _ => "chromium.search",
        };
        let symbol = match provider {
            "whatwg" => "whatwg.symbol_get",
            "w3c" => "w3c.symbol_get",
            _ => "chromium.symbol_get",
        };
        calls.push((provider, get, base.clone()));
        let mut original = base.clone();
        original["representation"] = json!("source");
        calls.push((provider, get, original));
        let mut binary = base.clone();
        binary["representation"] = json!("bytes");
        binary["limit"] = json!(8);
        calls.push((provider, get, binary));
        let mut query = json!({"snapshot":snapshot,"query":"token"});
        if provider == "chromium" {
            query["component"] = json!("src");
        }
        calls.push((provider, search, query));
        let mut symbol_args = base;
        symbol_args["name"] = json!("FixtureToken");
        symbol_args["kind"] = json!("definition");
        calls.push((provider, symbol, symbol_args));
    }
    let mut targets = BTreeMap::new();
    collect(
        "rfc",
        &research
            .read_resource(&format!("devres://capture/{}", capture.capture.id))
            .await?,
        &mut targets,
    )?;
    // Every result is a fixed public fixture selection. No audit input or matched
    // private inventory is passed to the target compiler or retained here.
    for (provider, tool, args) in calls {
        let output = research
            .call(tool, args)
            .await
            .map_err(|error| format!("Synthetic attribution selector {tool}: {error}"))?;
        collect(provider, &output, &mut targets)
            .map_err(|error| format!("Synthetic attribution compiler {tool}: {error}"))?;
        if let Some(snapshot) = output.get("snapshot").filter(|v| v.is_object()) {
            collect(provider, &json!({"snapshot":snapshot}), &mut targets).map_err(|error| {
                format!("Synthetic snapshot attribution compiler {tool}: {error}")
            })?;
        }
        if let Some(uri) = output.get("resource_uri").and_then(Value::as_str) {
            let uri = if output["representation"] == "bytes" {
                format!("{uri}?limit=8")
            } else {
                uri.to_owned()
            };
            collect(provider, &research.read_resource(&uri).await?, &mut targets).map_err(
                |error| format!("Synthetic resource attribution compiler {tool}: {error}"),
            )?;
        }
    }
    let mut pending = BTreeMap::new();
    for (identity, target) in targets {
        if store.attribution_ready(&target.subject).await?.is_none() {
            store.attribution_enqueue(&target, 255).await?;
            pending.insert(identity, target);
        }
    }
    qualify_fixtures(store.as_ref(), pending).await
}

async fn qualify_fixtures(
    store: &dyn AttributionStore,
    mut pending: BTreeMap<String, AttributionTarget>,
) -> Result<(), Box<dyn std::error::Error>> {
    let enabled = [
        "rfc", "crates", "rustsec", "mdn", "whatwg", "w3c", "chromium", "npm",
    ]
    .map(str::to_owned);
    let mut deferred = 0;
    while !pending.is_empty() {
        let job = store
            .attribution_claim(&enabled, devres_domain::unix_now())
            .await?
            .ok_or("Synthetic attribution claim absent")?;
        let identity = serde_json::to_string(&job.target.subject)?;
        let Some(target) = pending.remove(&identity) else {
            // Claim fairness also selects unrelated local sweep work. Release
            // only this owned lease, retaining its exact target for later repair.
            store
                .attribution_fail(
                    &job,
                    Some(devres_domain::unix_now().saturating_add(300)),
                    "fixture_deferred",
                )
                .await?;
            deferred += 1;
            if deferred >= 1024 {
                return Err("Synthetic attribution unrelated-job deferral bound exceeded".into());
            }
            continue;
        };
        let generation = AttributionGeneration {
            subject: target.subject,
            policy_epoch: ATTRIBUTION_POLICY_EPOCH,
            policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
            notices: vec![AttributionNotice {
                source_url: "https://fixtures.invalid/devres/storage-probe".into(),
                license: Some("AGPL-3.0-only".into()),
                copyright: Some("dev-resources-MCP synthetic fixture authors".into()),
                text: FIXTURE_NOTICE.into(),
                evidence: json!({"synthetic":true,"fixture":"storage-probe-v1","body_hash":devres_adapters::integrity::hash(FIXTURE_NOTICE.as_bytes())}),
            }],
            receipts: vec![
                json!({"kind":"synthetic_fixture_validation","synthetic":true,"status":200,"source_url":"https://fixtures.invalid/devres/storage-probe","body_hash":devres_adapters::integrity::hash(FIXTURE_NOTICE.as_bytes()),"validated_at":devres_domain::unix_now(),"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT,"source_fingerprint":job.target.subject.fingerprint}),
            ],
        };
        store.attribution_complete(&job, &generation).await?;
    }
    Ok(())
}
fn collect(
    provider: &str,
    value: &Value,
    targets: &mut BTreeMap<String, AttributionTarget>,
) -> Result<(), Box<dyn std::error::Error>> {
    for target in devres_adapters::attribution_providers::targets(provider, value)? {
        let identity = serde_json::to_string(&target.subject)?;
        if let Some(old) = targets.insert(identity, target.clone())
            && old != target
        {
            return Err("Synthetic attribution identity has conflicting evidence".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    #[derive(Default)]
    struct ClaimStore {
        jobs: Mutex<VecDeque<AttributionJob>>,
        deferred: Mutex<Vec<(AttributionJob, Option<i64>, String)>>,
        completed: Mutex<Vec<(AttributionJob, AttributionGeneration)>>,
    }
    #[async_trait]
    impl AttributionStore for ClaimStore {
        async fn attribution_claim(
            &self,
            _: &[String],
            _: i64,
        ) -> DomainResult<Option<AttributionJob>> {
            Ok(self.jobs.lock().unwrap().pop_front())
        }
        async fn attribution_fail(
            &self,
            job: &AttributionJob,
            retry: Option<i64>,
            code: &str,
        ) -> DomainResult<()> {
            self.deferred
                .lock()
                .unwrap()
                .push((job.clone(), retry, code.into()));
            Ok(())
        }
        async fn attribution_complete(
            &self,
            job: &AttributionJob,
            value: &AttributionGeneration,
        ) -> DomainResult<()> {
            self.completed
                .lock()
                .unwrap()
                .push((job.clone(), value.clone()));
            Ok(())
        }
        async fn attribution_enqueue(&self, _: &AttributionTarget, _: u8) -> DomainResult<()> {
            Err(Error::integrity("Unexpected enqueue"))
        }
        async fn attribution_ready(
            &self,
            _: &AttributionSubject,
        ) -> DomainResult<Option<QualifiedAttribution>> {
            Err(Error::integrity("Unexpected readiness lookup"))
        }
        async fn attribution_sweep_page(&self, _: &str) -> DomainResult<Vec<AttributionTarget>> {
            Err(Error::integrity("Unexpected sweep"))
        }
        async fn attribution_bundle(&self, _: &str) -> DomainResult<QualifiedAttribution> {
            Err(Error::integrity("Unexpected bundle lookup"))
        }
        async fn attribution_status(&self) -> DomainResult<Value> {
            Err(Error::integrity("Unexpected status lookup"))
        }
    }

    fn job(key: &str) -> AttributionJob {
        AttributionJob {
            target: AttributionTarget {
                subject: AttributionSubject {
                    provider: "rfc".into(),
                    namespace: "capture".into(),
                    key: key.into(),
                    fingerprint: devres_adapters::integrity::hash(key.as_bytes()),
                },
                evidence: json!({"retained_public_source":key}),
            },
            claim: format!("owned-{key}"),
            attempts: 1,
        }
    }

    #[tokio::test]
    async fn unrelated_claim_is_deferred_without_qualification_or_target_changes() {
        let unrelated = job("unrelated-public-sweep");
        let fixture = job("selected-first-party-fixture");
        let store = ClaimStore {
            jobs: Mutex::new(VecDeque::from([unrelated.clone(), fixture.clone()])),
            ..Default::default()
        };
        let pending = BTreeMap::from([(
            serde_json::to_string(&fixture.target.subject).unwrap(),
            fixture.target.clone(),
        )]);
        let before = devres_domain::unix_now();
        qualify_fixtures(&store, pending).await.unwrap();
        let failures = store.deferred.lock().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, unrelated);
        assert_eq!(failures[0].2, "fixture_deferred");
        assert!(failures[0].1.unwrap() >= before + 300);
        assert!(failures[0].1.unwrap() <= devres_domain::unix_now() + 300);
        let generations = store.completed.lock().unwrap();
        assert_eq!(generations.len(), 1);
        assert_eq!(generations[0].0, fixture);
        assert_eq!(generations[0].1.subject, fixture.target.subject);
    }

    #[tokio::test]
    async fn unrelated_claim_deferrals_have_a_finite_bound_and_release_every_claim() {
        let fixture = job("selected-first-party-fixture");
        let store = ClaimStore {
            jobs: Mutex::new((0..1025).map(|i| job(&format!("unrelated-{i}"))).collect()),
            ..Default::default()
        };
        let pending = BTreeMap::from([(
            serde_json::to_string(&fixture.target.subject).unwrap(),
            fixture.target,
        )]);
        let error = qualify_fixtures(&store, pending).await.unwrap_err();
        assert!(error.to_string().contains("deferral bound exceeded"));
        assert_eq!(store.deferred.lock().unwrap().len(), 1024);
        assert_eq!(store.jobs.lock().unwrap().len(), 1);
        assert!(store.completed.lock().unwrap().is_empty());
    }
}
