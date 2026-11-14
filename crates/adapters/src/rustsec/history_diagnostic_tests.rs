use super::*;

async fn history_fixture() -> (tempfile::TempDir, Arc<Memory>, AdvisoryHistory) {
    let root = tempfile::tempdir().unwrap();
    let memory = Arc::new(Memory::default());
    let history = AdvisoryHistory::new(
        memory.clone(),
        Arc::new(BulkBroker::new(Default::default()).unwrap()),
        root.path(),
        config(),
    )
    .unwrap();
    (root, memory, history)
}
async fn diagnostic(memory: &Memory) -> HistoryDiagnostic {
    serde_json::from_value(
        memory
            .advisory_state(HISTORY_DIAGNOSTICS_KEY)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap()
}
#[tokio::test]
async fn history_recovery_requires_the_failed_operation_observation_and_checkpoint() {
    let (_root, memory, history) = history_fixture().await;
    let cancel = CancellationToken::new();
    let first = digest(b"first observation");
    let second = digest(b"second observation");
    memory
        .set_advisory_state("history-error", &json!({"at":1,"code":"unavailable"}))
        .await
        .unwrap();
    let attempt = history
        .begin_stage(HistoryOperation::Synchronize, Some(&first), None)
        .await
        .unwrap();
    history
        .finish_stage(
            attempt,
            Some(&Error::unavailable("secret transport failure")),
            None,
            false,
            &cancel,
        )
        .await
        .unwrap();
    let attempt = history
        .begin_stage(HistoryOperation::Restore, Some(&first), None)
        .await
        .unwrap();
    history
        .finish_stage(attempt, None, None, true, &cancel)
        .await
        .unwrap();
    assert!(diagnostic(&memory).await.failures[0].resolved_at.is_none());
    let attempt = history
        .begin_stage(HistoryOperation::Synchronize, Some(&second), None)
        .await
        .unwrap();
    history
        .finish_stage(attempt, None, None, true, &cancel)
        .await
        .unwrap();
    assert!(diagnostic(&memory).await.failures[0].resolved_at.is_none());
    let attempt = history
        .begin_stage(HistoryOperation::Projection, Some(&first), Some(3))
        .await
        .unwrap();
    history
        .finish_stage(
            attempt,
            Some(&Error::unavailable("secret processing failure")),
            Some(5),
            false,
            &cancel,
        )
        .await
        .unwrap();
    let attempt = history
        .begin_stage(HistoryOperation::Projection, Some(&first), Some(5))
        .await
        .unwrap();
    history
        .finish_stage(attempt, None, Some(5), false, &cancel)
        .await
        .unwrap();
    assert!(
        diagnostic(&memory)
            .await
            .failures
            .iter()
            .all(|failure| failure.resolved_at.is_none())
    );
    let attempt = history
        .begin_stage(HistoryOperation::Projection, Some(&first), Some(5))
        .await
        .unwrap();
    history
        .finish_stage(attempt, None, Some(6), false, &cancel)
        .await
        .unwrap();
    let retained = diagnostic(&memory).await;
    assert!(
        retained
            .failures
            .iter()
            .find(|failure| failure.operation == HistoryOperation::Projection)
            .unwrap()
            .resolved_at
            .is_some()
    );
    assert!(
        retained
            .failures
            .iter()
            .find(|failure| failure.operation == HistoryOperation::Synchronize)
            .unwrap()
            .resolved_at
            .is_none()
    );
    let attempt = history
        .begin_stage(HistoryOperation::Synchronize, Some(&first), None)
        .await
        .unwrap();
    history
        .finish_stage(attempt, None, None, true, &cancel)
        .await
        .unwrap();
    assert!(
        diagnostic(&memory)
            .await
            .failures
            .iter()
            .all(|failure| failure.resolved_at.is_some())
    );
    assert_eq!(
        memory
            .advisory_state("history-error")
            .await
            .unwrap()
            .unwrap(),
        json!({"at":1,"code":"unavailable"})
    );
    assert!(
        !serde_json::to_string(&diagnostic(&memory).await)
            .unwrap()
            .contains("secret")
    );
}
#[tokio::test]
async fn history_cancellation_and_backoff_do_not_resolve_or_overwrite_failure() {
    let (_root, memory, history) = history_fixture().await;
    let observation = digest(b"observation");
    let cancel = CancellationToken::new();
    let attempt = history
        .begin_stage(HistoryOperation::Projection, Some(&observation), Some(1))
        .await
        .unwrap();
    history
        .finish_stage(
            attempt,
            Some(&Error::capacity("fixture failure")),
            Some(1),
            false,
            &cancel,
        )
        .await
        .unwrap();
    let attempt = history
        .begin_stage(HistoryOperation::Projection, Some(&observation), Some(1))
        .await
        .unwrap();
    cancel.cancel();
    history
        .finish_stage(attempt, None, Some(2), true, &cancel)
        .await
        .unwrap();
    let before = memory
        .advisory_state(HISTORY_DIAGNOSTICS_KEY)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before["outcome"], "running");
    assert!(diagnostic(&memory).await.failures[0].resolved_at.is_none());
    memory
        .set_advisory_state(
            "history-retry",
            &json!({"next_attempt":devres_domain::unix_now()+300,"code":"capacity"}),
        )
        .await
        .unwrap();
    history.tick(CancellationToken::new()).await.unwrap();
    assert_eq!(
        memory
            .advisory_state(HISTORY_DIAGNOSTICS_KEY)
            .await
            .unwrap()
            .unwrap(),
        before
    );
}
#[tokio::test]
async fn history_completed_observation_idle_does_not_claim_recovery() {
    let (_root, memory, history) = history_fixture().await;
    let observation = digest(b"observation");
    let cancel = CancellationToken::new();
    let attempt = history
        .begin_stage(HistoryOperation::Restore, None, None)
        .await
        .unwrap();
    history
        .finish_stage(
            attempt,
            Some(&Error::unavailable("fixture restore failure")),
            None,
            false,
            &cancel,
        )
        .await
        .unwrap();
    let state = json!({"manifest":{"body_hash":digest(b"manifest"),"bytes":1,"relative_path":"fixture"},"observation_id":observation,"observed_at":devres_domain::unix_now(),"offset":0,"processed":1,"total":1,"complete":true,"projection_complete":false,"processor_version":ADVISORY_PROCESSOR_VERSION});
    memory.set_advisory_state("history", &state).await.unwrap();
    memory
        .set_advisory_state("history-latest", &state)
        .await
        .unwrap();
    let before = memory
        .advisory_state(HISTORY_DIAGNOSTICS_KEY)
        .await
        .unwrap()
        .unwrap();
    history.tick(cancel).await.unwrap();
    assert_eq!(
        memory
            .advisory_state(HISTORY_DIAGNOSTICS_KEY)
            .await
            .unwrap()
            .unwrap(),
        before
    );
}
