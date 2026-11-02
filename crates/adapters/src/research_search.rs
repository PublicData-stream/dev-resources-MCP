//! Request-owned source scheduling. Providers retain their own admission and retry policies.
use devres_domain::{Error, Result};
use futures::{StreamExt, stream};
use serde_json::{Value, json};
use std::{collections::HashSet, future::Future, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub(super) async fn collect<F, Fut>(
    sources: Vec<String>,
    cancel: CancellationToken,
    deadline: Instant,
    invoke: F,
) -> Result<Value>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<Value>>,
{
    let mut unique = HashSet::new();
    if sources.is_empty()
        || sources.len() > 8
        || sources.iter().any(|source| {
            !matches!(
                source.as_str(),
                "rfc" | "cargo" | "rustsec" | "mdn" | "whatwg" | "w3c" | "chromium" | "npm"
            ) || !unique.insert(source)
        })
    {
        return Err(Error::invalid(
            "Select one to eight distinct supported search sources.",
        ));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    let margin = Duration::from_secs(1).min(remaining / 10);
    let work_deadline = deadline - margin;
    let count = sources.len();
    let invoke = &invoke;
    let mut running = stream::iter(sources.into_iter().enumerate())
        .map(|(position, source)| async move {
            let result = if Instant::now() >= work_deadline {
                Err(Error::unavailable(
                    "Search source was not started before the request deadline.",
                ))
            } else {
                let source_deadline = work_deadline.min(Instant::now() + Duration::from_secs(15));
                tokio::time::timeout_at(source_deadline, invoke(source.clone()))
                    .await
                    .unwrap_or_else(|_| Err(Error::unavailable("Search source deadline exceeded.")))
            };
            let row = match result {
                Ok(value) => json!({"source":source,"result":value}),
                Err(error) => json!({"source":source,"error":error.to_string()}),
            };
            (position, row)
        })
        .buffer_unordered(2);
    let mut rows = vec![Value::Null; count];
    loop {
        let next = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(Error::new("cancelled", "Request cancelled.")),
            next = running.next() => next,
        };
        match next {
            Some((position, row)) => rows[position] = row,
            None => break,
        }
    }
    Ok(json!({"sources":rows}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn eight_stalled_sources_receive_four_bounded_waves() {
        let sources = [
            "rfc", "cargo", "rustsec", "mdn", "whatwg", "w3c", "chromium", "npm",
        ];
        let calls = AtomicUsize::new(0);
        let active = Arc::new(AtomicUsize::new(0));
        let peak = AtomicUsize::new(0);
        let start = Instant::now();
        let result = collect(
            sources.map(str::to_owned).to_vec(),
            CancellationToken::new(),
            start + Duration::from_secs(75),
            |_| {
                let active = active.clone();
                let calls = &calls;
                let peak = &peak;
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(count, Ordering::SeqCst);
                    let _guard = Active(active);
                    std::future::pending::<Result<Value>>().await
                }
            },
        )
        .await
        .unwrap();
        let rows = result["sources"].as_array().unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row["source"].as_str().unwrap())
                .collect::<Vec<_>>(),
            sources
        );
        assert!(rows.iter().all(|row| {
            row["error"] == "unavailable: Search source deadline exceeded."
                && row.get("result").is_none()
        }));
        assert_eq!(calls.load(Ordering::SeqCst), 8);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        let elapsed = Instant::now().duration_since(start);
        assert!(elapsed >= Duration::from_secs(60));
        assert!(elapsed < Duration::from_secs(61));
    }

    #[tokio::test]
    async fn cancelling_all_source_search_drops_active_work_without_starting_queued_sources() {
        let cancel = CancellationToken::new();
        let active = Arc::new(AtomicUsize::new(0));
        let calls = AtomicUsize::new(0);
        let started = tokio::sync::Notify::new();
        let run = collect(
            [
                "rfc", "cargo", "rustsec", "mdn", "whatwg", "w3c", "chromium", "npm",
            ]
            .map(str::to_owned)
            .to_vec(),
            cancel.clone(),
            Instant::now() + Duration::from_secs(75),
            |_| {
                let active = active.clone();
                let calls = &calls;
                let started = &started;
                async move {
                    let count = calls.fetch_add(1, Ordering::SeqCst) + 1;
                    active.fetch_add(1, Ordering::SeqCst);
                    let _guard = Active(active);
                    if count == 2 {
                        started.notify_one();
                    }
                    std::future::pending::<Result<Value>>().await
                }
            },
        );
        let stop = async {
            started.notified().await;
            cancel.cancel();
        };
        let (result, ()) = tokio::join!(run, stop);
        assert_eq!(result.unwrap_err().code, "cancelled");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_first_source_keeps_siblings_and_requested_order() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = AtomicUsize::new(0);
        let result = collect(
            ["npm", "mdn", "rustsec", "w3c"].map(str::to_owned).to_vec(),
            CancellationToken::new(),
            Instant::now() + Duration::from_secs(30),
            |source| {
                let active = active.clone();
                let peak = &peak;
                async move {
                    let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(count, Ordering::SeqCst);
                    let _active = Active(active);
                    if source == "npm" {
                        std::future::pending::<()>().await;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if source == "w3c" {
                        Err(Error::unavailable("Fixture evidence unavailable."))
                    } else {
                        Ok(json!({"fixture":source}))
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result["sources"][0]["source"], "npm");
        assert!(result["sources"][0]["error"].is_string());
        assert_eq!(result["sources"][1]["result"]["fixture"], "mdn");
        assert_eq!(result["sources"][2]["result"]["fixture"], "rustsec");
        assert!(result["sources"][3]["error"].is_string());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn shared_deadline_marks_queued_sources_without_dispatch() {
        let calls = AtomicUsize::new(0);
        let start = Instant::now();
        let result = collect(
            ["npm", "rfc", "mdn"].map(str::to_owned).to_vec(),
            CancellationToken::new(),
            start + Duration::from_secs(1),
            |_| async {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<Result<Value>>().await
            },
        )
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(
            result["sources"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["error"].is_string())
        );
        assert!(Instant::now().duration_since(start) < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn invalid_selection_starts_no_work_and_cancellation_drops_active_work() {
        let calls = AtomicUsize::new(0);
        for sources in [vec!["npm", "npm"], vec!["npm", "unknown"], vec![]] {
            let result = collect(
                sources.into_iter().map(str::to_owned).collect(),
                CancellationToken::new(),
                Instant::now() + Duration::from_secs(1),
                |_| async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({}))
                },
            )
            .await;
            assert!(result.is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let cancel = CancellationToken::new();
        let active = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        let run = collect(
            vec!["npm".into()],
            cancel.clone(),
            Instant::now() + Duration::from_secs(30),
            |_| {
                let active = active.clone();
                let started = started.clone();
                async move {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _guard = Active(active);
                    started.notify_one();
                    std::future::pending::<Result<Value>>().await
                }
            },
        );
        let stop = async {
            started.notified().await;
            cancel.cancel();
        };
        let (result, ()) = tokio::join!(run, stop);
        assert_eq!(result.unwrap_err().code, "cancelled");
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
