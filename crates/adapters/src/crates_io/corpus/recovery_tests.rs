use super::*;

#[tokio::test]
async fn failed_worker_cancels_and_fully_drains_siblings_before_return() {
    let global = CancellationToken::new();
    let group = global.child_token();
    let sibling_stop = group.child_token();
    let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut workers = tokio::task::JoinSet::new();
    workers.spawn(async move {
        sibling_stop.cancelled().await;
        cancelled_tx.send(()).unwrap();
        release_rx.await.unwrap();
        Err(Error::unavailable("Cleanup also failed."))
    });
    workers.spawn(async { Err(Error::integrity("Original failure.")) });
    let supervisor = tokio::spawn(supervise_workers(workers, group.clone()));
    tokio::time::timeout(Duration::from_secs(1), cancelled_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(group.is_cancelled());
    assert!(!global.is_cancelled());
    assert!(
        !supervisor.is_finished(),
        "claims cannot reset before cleanup drains"
    );
    release_tx.send(()).unwrap();
    assert_eq!(supervisor.await.unwrap().unwrap_err().code, "integrity");
}

#[tokio::test]
async fn cancelled_group_drains_even_when_one_child_panics() {
    let group = CancellationToken::new();
    group.cancel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut workers = tokio::task::JoinSet::new();
    workers.spawn(async { panic!("fixture worker panic") });
    workers.spawn(async move {
        release_rx.await.unwrap();
        Ok(())
    });
    let supervisor = tokio::spawn(supervise_workers(workers, group));
    tokio::task::yield_now().await;
    assert!(!supervisor.is_finished());
    release_tx.send(()).unwrap();
    assert_eq!(supervisor.await.unwrap().unwrap_err().code, "integrity");
}

#[tokio::test]
async fn fatal_sibling_failure_outranks_the_initial_archive_outage() {
    let group = CancellationToken::new();
    let sibling_stop = group.child_token();
    let mut workers = tokio::task::JoinSet::new();
    workers.spawn(async { Err(Error::unavailable("Archive outage.")) });
    workers.spawn(async move {
        sibling_stop.cancelled().await;
        Err(Error::integrity("Durable corruption."))
    });
    assert_eq!(
        supervise_workers(workers, group).await.unwrap_err().code,
        "integrity"
    );
}

#[tokio::test]
async fn unexpected_successful_worker_exit_is_fatal() {
    let mut workers = tokio::task::JoinSet::new();
    workers.spawn(async { Ok(()) });
    assert_eq!(
        supervise_workers(workers, CancellationToken::new())
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
}

#[tokio::test]
async fn parser_failure_cleanup_joins_the_blocking_descendant() {
    let cancel = CancellationToken::new();
    let (send, receive) = tokio::sync::mpsc::channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let worker = tokio::task::spawn_blocking(move || {
        while send.blocking_send(()).is_ok() {}
        release_rx.recv().unwrap();
        Err::<(), _>(Error::unavailable("Parser channel closed."))
    });
    // Dropping the receiver releases a parser blocked on a full bounded channel.
    drop(receive);
    let token = cancel.clone();
    let cleanup = tokio::spawn(async move {
        finish_parser(
            Err(Error::integrity("Storage rejected projection.")),
            worker,
            &token,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), cancel.cancelled())
        .await
        .unwrap();
    assert!(!cleanup.is_finished());
    release_tx.send(()).unwrap();
    assert_eq!(cleanup.await.unwrap().unwrap_err().code, "integrity");
}

#[tokio::test]
async fn blocking_parser_panic_is_fatal_during_outage_cleanup() {
    let worker = tokio::task::spawn_blocking(|| -> Result<()> { panic!("fixture parser panic") });
    assert_eq!(
        finish_parser(
            Err(Error::unavailable("Archive unavailable.")),
            worker,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .code,
        "integrity"
    );
}
