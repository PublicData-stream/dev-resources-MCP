//! Operator opt-in acceptance against disposable storage. Never accepts lockfiles.
use devres_adapters::{
    HttpFetcher, PgBlobStore, Research,
    bulk::{BulkBroker, BulkConfig},
    rustsec::AdvisoryCorpus,
    rustsec::git::AdvisoryHistory,
};
use devres_application::{
    Retrieval,
    advisory::{AdvisoryStore, RustSecConfig},
};
use serde_json::json;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mode=match args.as_slice(){[flag,mode] if flag=="--live"&&matches!(mode.as_str(),"current"|"history")=>mode.as_str(),_=>return Err("usage: rustsec-probe --live current|history (disposable DATABASE_URL and BLOB_DIR required)".into())};
    let database = std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required")?;
    let root = PathBuf::from(std::env::var("BLOB_DIR").map_err(|_| "BLOB_DIR is required")?);
    let store = Arc::new(PgBlobStore::connect(&database, &root).await?);
    let max_attempts = std::env::var("DEVRES_RUSTSEC_PROBE_ATTEMPTS")
        .ok()
        .map(|v| v.parse::<usize>())
        .transpose()?
        .unwrap_or(20);
    if !(1..=20).contains(&max_attempts) {
        return Err("probe attempt budget must be 1..20".into());
    }
    let broker =
        Arc::new(BulkBroker::new(BulkConfig::default())?.with_attempt_budget(max_attempts)?);
    let config = RustSecConfig::default();
    let stop = CancellationToken::new();
    let token = stop.clone();
    let signals = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        token.cancel();
    });
    if mode == "current" {
        let retrieval = Arc::new(Retrieval::new(
            store.clone(),
            Arc::new(HttpFetcher::with_broker(broker.clone())?),
        ));
        let corpus = Arc::new(AdvisoryCorpus::new(
            retrieval.clone(),
            store.clone(),
            broker.clone(),
            &root,
            config,
        )?);
        let result = tokio::select! {biased;_=stop.cancelled()=>return Err("current probe canceled".into()),result=tokio::time::timeout(Duration::from_secs(300),corpus.refresh_current())=>result??};
        let snapshot = result["snapshot"]["id"]
            .as_str()
            .ok_or("missing snapshot")?;
        let research = Research::new(retrieval).await?.with_advisory_corpus(corpus);
        let lookup = research
            .call(
                "advisory.lookup",
                json!({"name":"odbc","version":"0.17.0","advisory_snapshot":snapshot}),
            )
            .await?;
        if lookup["complete"] != true
            || !lookup["items"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item["id"] == "RUSTSEC-2022-0039"))
        {
            return Err("current positive advisory lookup failed".into());
        }
        let detail = research
            .call(
                "advisory.get",
                json!({"id":"RUSTSEC-2022-0039","snapshot":snapshot}),
            )
            .await?;
        if detail["page"]["text"].as_str().is_none_or(str::is_empty) {
            return Err("current original-source detail failed".into());
        }
        println!(
            "{}",
            json!({"mode":"current","snapshot":result["snapshot"],"advisories":result["advisories"],"positive_lookup":true,"attempts":broker.attempt_count()})
        );
    } else {
        let history = AdvisoryHistory::new(store.clone(), broker.clone(), &root, config)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3600);
        let mut last = tokio::time::Instant::now() - Duration::from_secs(30);
        loop {
            tokio::select! {biased;_=stop.cancelled()=>return Err("history probe canceled".into()),_=tokio::time::sleep_until(deadline)=>return Err("history acceptance incomplete: one-hour deadline reached; retained checkpoints preserved".into()),result=history.tick(stop.child_token())=>if let Err(error)=result {eprintln!("RustSec source attempts: {}",broker.attempt_count());return Err(error.into());}};
            let state = store
                .advisory_state("history")
                .await?
                .unwrap_or_else(|| json!({}));
            if state["complete"] == true {
                println!(
                    "{}",
                    json!({"mode":"history","processing_finished":true,"state":state,"status":store.advisory_status().await?,"attempts":broker.attempt_count()})
                );
                break;
            }
            if last.elapsed() > Duration::from_secs(30) {
                eprintln!(
                    "RustSec history progress: {} / {} commits; {} source attempts",
                    state["processed"],
                    state["total"],
                    broker.attempt_count()
                );
                last = tokio::time::Instant::now();
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    signals.abort();
    let _ = signals.await;
    Ok(())
}
