//! Deterministic coordinator checks plus controlled PostgreSQL/S3 acceptance.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[test]
fn same_path_waiters_cancel_without_cancelling_the_owner() {
    let control = MaterializationControl::default();
    let owner = control
        .claim("same", deadline(), &CancellationToken::new())
        .unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        control.claim("same", deadline(), &cancel).unwrap_err().code,
        "cancelled"
    );
    assert!(
        control
            .claim("other", deadline(), &CancellationToken::new())
            .is_ok()
    );
    drop(owner);
    assert!(
        control
            .claim("same", deadline(), &CancellationToken::new())
            .is_ok()
    );
}

#[test]
fn two_remote_slots_progress_and_a_third_waiter_observes_its_deadline() {
    let control = MaterializationControl::default();
    let acquire = || {
        run_bounded(deadline(), &CancellationToken::new(), async {
            control
                .io
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| unavailable())
        })
        .unwrap()
    };
    let first = acquire();
    let second = acquire();
    let error = run_bounded(
        Instant::now() + Duration::from_millis(10),
        &CancellationToken::new(),
        async {
            control
                .io
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| unavailable())
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "capacity");
    drop(first);
    let recovered = acquire();
    drop((second, recovered));
    assert_eq!(control.io.available_permits(), 2);
}

#[test]
fn cold_download_reservations_prevent_ordinary_writer_overcommit() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let retained = root.path().join("pinned");
    std::fs::write(&retained, [1; 32]).unwrap();
    let mut cache = Cache::scan(root.path()).unwrap();
    cache.files.insert(
        retained.clone(),
        CacheEntry {
            pins: 1,
            touched: 0,
        },
    );
    cache.reserved_bytes = 32;
    assert!(admit_local(root.path(), &mut cache, 0, 64, &[]).is_ok());
    let error = admit_local(root.path(), &mut cache, 1, 64, &[]).unwrap_err();
    assert_eq!(
        devres_application::collection::context(&error)
            .unwrap()
            .limit
            .unwrap()
            .observed,
        Some(65)
    );
    assert!(retained.exists());
    cache.reserved_bytes = 0;
    assert!(admit_local(root.path(), &mut cache, 32, 64, &[]).is_ok());
}

struct Proxy {
    upstream: String,
    client: reqwest::Client,
    gate: tokio::sync::Semaphore,
    enabled: AtomicBool,
    unavailable: AtomicBool,
    corrupt: AtomicBool,
    entered: tokio::sync::Notify,
    active: AtomicUsize,
    peak: AtomicUsize,
    gets: AtomicUsize,
}
impl Default for Proxy {
    fn default() -> Self {
        Self {
            upstream: String::new(),
            client: reqwest::Client::new(),
            gate: tokio::sync::Semaphore::new(0),
            enabled: AtomicBool::new(false),
            unavailable: AtomicBool::new(false),
            corrupt: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            gets: AtomicUsize::new(0),
        }
    }
}
struct Active<'a>(&'a Proxy);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.entered.notify_one();
    }
}
async fn proxy(
    axum::extract::State(state): axum::extract::State<Arc<Proxy>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::body::{Body, to_bytes};
    if state.unavailable.load(Ordering::SeqCst) {
        return axum::response::Response::builder()
            .status(403)
            .body(Body::empty())
            .unwrap();
    }
    let object_get =
        request.method() == http::Method::GET && request.uri().path().contains("/objects/");
    let _active = if object_get {
        state.gets.fetch_add(1, Ordering::SeqCst);
        state.peak.fetch_max(
            state.active.fetch_add(1, Ordering::SeqCst) + 1,
            Ordering::SeqCst,
        );
        state.entered.notify_one();
        Some(Active(&state))
    } else {
        None
    };
    if object_get && state.enabled.load(Ordering::SeqCst) {
        state.gate.acquire().await.unwrap().forget();
    }
    let (parts, body) = request.into_parts();
    let suffix = parts.uri.path_and_query().unwrap().as_str();
    let body = to_bytes(body, 512 * 1024).await.unwrap();
    let response = state
        .client
        .request(parts.method, format!("{}{suffix}", state.upstream))
        .headers(parts.headers)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.unwrap();
    assert!(body.len() <= 512 * 1024);
    let body = if object_get && state.corrupt.load(Ordering::SeqCst) {
        bytes::Bytes::from(vec![0; body.len()])
    } else {
        body
    };
    let mut response = axum::response::Response::builder()
        .status(status)
        .body(Body::from(body))
        .unwrap();
    *response.headers_mut() = headers;
    response
}
async fn entered(state: &Proxy, count: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.active.load(Ordering::SeqCst) < count {
            state.entered.notified().await;
        }
    })
    .await
    .unwrap();
}
async fn drained(state: &Proxy) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.active.load(Ordering::SeqCst) != 0 {
            state.entered.notified().await;
        }
    })
    .await
    .unwrap();
    state.gate.forget_permits(state.gate.available_permits());
}
fn read(path: PathBuf, cancel: CancellationToken) -> tokio::task::JoinHandle<Result<ArchiveLease>> {
    tokio::task::spawn_blocking(move || materialize_file(&path, 4096, deadline(), &cancel))
}
fn evict(path: &Path) {
    std::fs::remove_file(path).unwrap();
    forget_local(path).unwrap();
}
fn assert_clean(archive: &Archive, directory: &Path) {
    assert_eq!(lock_cache(archive).unwrap().reserved_bytes, 0);
    assert!(std::fs::read_dir(directory).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".archive-download-")
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires disposable PostgreSQL and RustFS; run scripts/test-s3.sh"]
async fn s3_materialization_parallel_singleflight_cancellation_and_authority() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
    let selected = std::env::var("DEVRES_TEST_S3_CONFIG").expect("disposable S3 required");
    let mut config: S3Config = toml::from_str(&std::fs::read_to_string(selected).unwrap()).unwrap();
    let state = Arc::new(Proxy {
        upstream: config.endpoint.clone(),
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap(),
        gate: tokio::sync::Semaphore::new(0),
        ..Proxy::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.endpoint = format!("http://{}", listener.local_addr().unwrap());
    config.allow_http = true;
    config.ca_file = None;
    config.cache_max_bytes = 64 * 1024 * 1024;
    config.prefix.push_str("/materialization-concurrency");
    let app = axum::Router::new()
        .fallback(proxy)
        .with_state(state.clone());
    let proxy_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
    let database_name = "devres_s3_materialization_fixture";
    sqlx_core::query::query("CREATE DATABASE devres_s3_materialization_fixture")
        .execute(&admin)
        .await
        .unwrap();
    let mut database = url::Url::parse(&base).unwrap();
    database.set_path(database_name);
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store =
        crate::PgBlobStore::connect_archive(database.as_str(), root.path(), Some(config.clone()))
            .await
            .unwrap();
    let archive = select(root.path()).unwrap().unwrap();
    let directory = root.path().join("materialization");
    std::fs::create_dir(&directory).unwrap();
    let paths = [directory.join("one"), directory.join("two")];
    for (index, path) in paths.iter().enumerate() {
        let bytes = vec![index as u8 + 1; 4096];
        std::fs::write(path, &bytes).unwrap();
        crate::integrity::record_file(
            root.path(),
            path,
            &crate::integrity::hash(&bytes),
            bytes.len() as u64,
        )
        .unwrap();
        evict(path);
    }
    state.enabled.store(true, Ordering::SeqCst);
    let first = read(paths[0].clone(), CancellationToken::new());
    let second = read(paths[1].clone(), CancellationToken::new());
    entered(&state, 2).await;
    assert_eq!(state.peak.load(Ordering::SeqCst), 2);
    let (refused_write, retained_metadata) = {
        let mut cache = archive.cache.try_lock().unwrap();
        assert_eq!(cache.reserved_bytes, 8192);
        let bytes = config.cache_max_bytes - cache.used_bytes - cache.reserved_bytes + 1;
        assert!(cache.used_bytes + bytes <= config.cache_max_bytes);
        // Make the existing working set non-evictable. Otherwise a one-byte
        // capacity excess can correctly evict an unrelated metadata object.
        let paths = cache.files.keys().cloned().collect();
        let lease = ArchiveLease::pin(&archive, &mut cache, paths);
        (bytes, lease)
    };
    let stage = root.path().join("writer-stage");
    std::fs::write(&stage, []).unwrap();
    assert!(with_write_budget(&stage, refused_write, || Ok(())).is_err());
    drop(retained_metadata);
    state.gate.add_permits(2);
    let leases = [
        first.await.unwrap().unwrap(),
        second.await.unwrap().unwrap(),
    ];
    assert_eq!(
        leases.iter().map(ArchiveLease::pinned_files).sum::<usize>(),
        2
    );
    drop(leases);
    assert_clean(&archive, &directory);

    // Both callers reach the same path, but only one cold GET is performed.
    evict(&paths[0]);
    let before = state.gets.load(Ordering::SeqCst);
    let first = read(paths[0].clone(), CancellationToken::new());
    entered(&state, 1).await;
    let second = read(paths[0].clone(), CancellationToken::new());
    state.gate.add_permits(1);
    let leases = [
        first.await.unwrap().unwrap(),
        second.await.unwrap().unwrap(),
    ];
    assert_eq!(state.gets.load(Ordering::SeqCst) - before, 1);
    drop(leases);

    // A canceled same-path waiter must leave its owner's download running.
    evict(&paths[0]);
    let owner_cancel = CancellationToken::new();
    let owner = read(paths[0].clone(), owner_cancel.clone());
    entered(&state, 1).await;
    let waiter_cancel = CancellationToken::new();
    let waiter = read(paths[0].clone(), waiter_cancel.clone());
    waiter_cancel.cancel();
    assert_eq!(waiter.await.unwrap().unwrap_err().code, "cancelled");
    assert!(!owner.is_finished());
    // Canceling the owner cleans staging and allows a fresh caller to lead.
    owner_cancel.cancel();
    assert_eq!(owner.await.unwrap().unwrap_err().code, "cancelled");
    assert_clean(&archive, &directory);
    state.enabled.store(false, Ordering::SeqCst);
    state.gate.add_permits(1); // drain the already accepted proxy request
    drained(&state).await;
    let lease = read(paths[0].clone(), CancellationToken::new())
        .await
        .unwrap()
        .unwrap();
    drop(lease);

    // Corrupt bytes never become a visible local materialization.
    evict(&paths[0]);
    state.corrupt.store(true, Ordering::SeqCst);
    assert_eq!(
        read(paths[0].clone(), CancellationToken::new())
            .await
            .unwrap()
            .unwrap_err()
            .code,
        "integrity"
    );
    assert!(!paths[0].exists());
    assert_clean(&archive, &directory);
    state.corrupt.store(false, Ordering::SeqCst);
    drop(
        read(paths[0].clone(), CancellationToken::new())
            .await
            .unwrap()
            .unwrap(),
    );
    state.unavailable.store(true, Ordering::SeqCst);
    assert_eq!(
        read(paths[0].clone(), CancellationToken::new())
            .await
            .unwrap()
            .unwrap_err()
            .code,
        "unavailable"
    );
    assert!(paths[0].exists());
    state.unavailable.store(false, Ordering::SeqCst);

    // One directory uses both shared slots; successful aggregation retains pins.
    for path in &paths {
        evict(path);
    }
    state.enabled.store(true, Ordering::SeqCst);
    let selected = directory.clone();
    let pipeline = tokio::task::spawn_blocking(move || {
        materialize_directory(&selected, 8192, 2, deadline(), &CancellationToken::new())
    });
    entered(&state, 2).await;
    state.gate.add_permits(2);
    let lease = pipeline.await.unwrap().unwrap();
    assert_eq!(lease.pinned_files(), 2);
    drop(lease);
    assert_clean(&archive, &directory);

    // Deadline failure cancels and joins both owned workers, releasing all
    // partial directory leases and download reservations before returning.
    for path in &paths {
        evict(path);
    }
    let selected = directory.clone();
    let pipeline = tokio::task::spawn_blocking(move || {
        materialize_directory(
            &selected,
            8192,
            2,
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
    });
    entered(&state, 2).await;
    assert_eq!(pipeline.await.unwrap().unwrap_err().code, "capacity");
    assert_clean(&archive, &directory);
    assert!(
        lock_cache(&archive)
            .unwrap()
            .files
            .values()
            .all(|entry| entry.pins == 0)
    );
    state.enabled.store(false, Ordering::SeqCst);
    state.gate.add_permits(2);
    drained(&state).await;
    drop(
        read(paths[0].clone(), CancellationToken::new())
            .await
            .unwrap()
            .unwrap(),
    );
    state.enabled.store(true, Ordering::SeqCst);

    // Losing the exact fixture owner while GET is blocked must reject the final
    // publication, not expose bytes verified under obsolete authority.
    evict(&paths[0]);
    let pending = read(paths[0].clone(), CancellationToken::new());
    entered(&state, 1).await;
    let terminated: bool = sqlx_core::query_scalar::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(archive.owner_pid)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert!(terminated);
    state.gate.add_permits(1);
    assert_eq!(pending.await.unwrap().unwrap_err().code, "unavailable");
    assert!(!paths[0].exists());
    assert_clean(&archive, &directory);
    drop(archive);
    drop(store);
    sqlx_core::query::query("DROP DATABASE devres_s3_materialization_fixture WITH (FORCE)")
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    proxy_task.abort();
    let _ = proxy_task.await;
}
