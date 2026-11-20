//! Private rejection evidence must not change public errors or admission policy.
use super::*;
use std::fmt;
use tracing::{Event, Metadata, Subscriber, field::Visit, span};

#[derive(Clone, Default)]
pub(super) struct Events(pub(super) Arc<Mutex<Vec<EventFields>>>);
pub(super) type EventFields = BTreeMap<String, String>;
impl Subscriber for Events {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "devres_private_timings"
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        struct Fields(BTreeMap<String, String>);
        impl Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
                self.0.insert(field.name().into(), format!("{value:?}"));
            }
        }
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        if fields.0.contains_key("rejection_reason") || fields.0.contains_key("archive_stage") {
            self.0.lock().unwrap().push(fields.0);
        }
    }
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

#[test]
fn physical_totals_count_aliases_once_and_preserve_protected_or_unmanaged_bytes() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let pinned = root.path().join("pinned");
    let alias = root.path().join("alias");
    let evictable = root.path().join("evictable");
    let unmanaged = root.path().join("unmanaged");
    for (path, bytes) in [(&pinned, 32), (&evictable, 64), (&unmanaged, 8)] {
        std::fs::write(path, vec![1; bytes]).unwrap();
    }
    std::fs::hard_link(&pinned, &alias).unwrap();
    let mut cache = Cache::scan(root.path()).unwrap();
    for (path, pins) in [(&pinned, 1), (&alias, 0), (&evictable, 0)] {
        cache
            .files
            .insert(path.clone(), CacheEntry { pins, touched: 0 });
    }
    assert_eq!(cache.used_bytes, 104);
    assert_eq!(cache.private_physical_totals(&[]), Some((32, 64)));
    assert_eq!(
        cache.private_physical_totals(std::slice::from_ref(&evictable)),
        Some((32, 0))
    );
    cache.files.get_mut(&pinned).unwrap().pins = 0;
    assert_eq!(cache.private_physical_totals(&[]), Some((0, 96)));
    cache.files.remove(&alias);
    assert_eq!(cache.private_physical_totals(&[]), Some((0, 64)));
}

#[test]
fn bounded_physical_accounting_reports_unknown_instead_of_partial_totals() {
    let mut cache = Cache::default();
    for number in 0..4097 {
        cache
            .paths
            .insert(PathBuf::from(format!("inert-{number}")), (1, number));
    }
    assert_eq!(cache.private_physical_totals(&[]), None);
    // No filesystem paths are needed to classify in-memory physical objects.
    cache.paths.clear();
    cache.objects.insert(
        (1, 1),
        LocalObject {
            bytes: 5,
            paths: [PathBuf::from("inert-physical-alias")].into(),
        },
    );
    cache.files.insert(
        PathBuf::from("inert-physical-alias"),
        CacheEntry {
            pins: 1,
            touched: 0,
        },
    );
    assert_eq!(cache.private_physical_totals(&[]), Some((5, 0)));
}

#[test]
fn private_pressure_event_preserves_inner_public_limit_and_original_evidence() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let path = root.path().join("not-for-logs");
    std::fs::write(&path, [9; 32]).unwrap();
    let mut cache = Cache::scan(root.path()).unwrap();
    cache.files.insert(
        path.clone(),
        CacheEntry {
            pins: 1,
            touched: 0,
        },
    );
    cache.reserved_bytes = 32;
    let events = Events::default();
    let error = tracing::subscriber::with_default(events.clone(), || {
        admit_local(root.path(), &mut cache, 1, 64, &[]).unwrap_err()
    });
    let context = devres_application::collection::context(&error).unwrap();
    assert_eq!(context.phase, Phase::Materialization);
    let limit = context.limit.unwrap();
    assert_eq!(limit.kind, LimitKind::CacheWorkingSet);
    assert_eq!((limit.observed, limit.maximum), (Some(65), Some(64)));
    assert_eq!(error.code, "capacity");
    let events = events.0.lock().unwrap();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["rejection_reason"], "\"cache_working_set\"");
    assert_eq!(event["observed"], "65");
    assert_eq!(event["maximum"], "64");
    assert_eq!(event["resident_bytes"], "32");
    assert_eq!(event["reserved_bytes"], "32");
    assert_eq!(event["pinned_bytes"], "32");
    assert_eq!(event["evictable_bytes"], "0");
    assert!(!format!("{event:?}").contains("not-for-logs"));
    assert!(
        !error
            .details
            .unwrap()
            .to_string()
            .contains("rejection_reason")
    );
    assert_eq!(std::fs::read(path).unwrap(), [9; 32]);
}

#[test]
fn tracked_file_rejection_stays_generic_and_reports_the_actual_path_limit() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let path = root.path().join("new-file");
    std::fs::write(&path, [1]).unwrap();
    let mut cache = Cache::default();
    // Populate bounded bookkeeping without creating hundreds of thousands of files.
    for number in 0..MAX_LOCAL_FILES {
        cache
            .paths
            .insert(PathBuf::from(format!("inert-{number}")), (1, number as u64));
    }
    let events = Events::default();
    let error =
        tracing::subscriber::with_default(events.clone(), || cache.observe(&path).unwrap_err());
    assert_eq!(error.code, capacity().code);
    assert_eq!(error.message, capacity().message);
    assert!(error.details.is_none());
    assert!(devres_application::collection::context(&error).is_none());
    let events = events.0.lock().unwrap();
    let event = &events[0];
    assert_eq!(event["rejection_reason"], "\"tracked_files\"");
    assert_eq!(event["observed"], "262145");
    assert_eq!(event["maximum"], "262144");
    assert_eq!(event["physical_totals_known"], "false");
    assert!(!event.contains_key("pinned_bytes"));
    assert!(!event.contains_key("evictable_bytes"));
    assert_eq!(cache.paths.len(), MAX_LOCAL_FILES);
    assert_eq!(std::fs::read(path).unwrap(), [1]);
}

#[test]
fn expired_reconciliation_and_materialization_keep_their_distinct_public_contexts() {
    let mut cache = Cache::default();
    cache
        .paths
        .insert(PathBuf::from("never-stat-this-path"), (1, 1));
    let events = Events::default();
    tracing::subscriber::with_default(events.clone(), || {
        let error = cache.reconcile(Instant::now()).unwrap_err();
        assert_eq!(error.code, "capacity");
        assert!(error.details.is_none());
        let error = materialization_deadline();
        let context = devres_application::collection::context(&error).unwrap();
        assert_eq!(context.phase, Phase::Materialization);
        assert_eq!(context.limit.unwrap().kind, LimitKind::Deadline);
    });
    let events = events.0.lock().unwrap();
    assert_eq!(events[0]["rejection_reason"], "\"reconcile_deadline\"");
    assert_eq!(
        events[1]["rejection_reason"],
        "\"materialization_deadline\""
    );
    assert_eq!(events[1]["cache_accounting_known"], "false");
    assert!(!events[1].contains_key("resident_bytes"));
}

#[test]
fn eviction_deadline_evidence_excludes_protected_aliases_and_unknown_scope_stays_unknown() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let protected = root.path().join("protected");
    let alias = root.path().join("alias");
    let evictable = root.path().join("evictable");
    std::fs::write(&protected, [1; 32]).unwrap();
    std::fs::hard_link(&protected, &alias).unwrap();
    std::fs::write(&evictable, [2; 8]).unwrap();
    let mut cache = Cache::scan(root.path()).unwrap();
    for path in [&protected, &alias, &evictable] {
        cache.files.insert(
            path.clone(),
            CacheEntry {
                pins: 0,
                touched: 0,
            },
        );
    }
    let events = Events::default();
    tracing::subscriber::with_default(events.clone(), || {
        rejection_protected(
            RejectionReason::EvictionDeadline,
            None,
            None,
            Some(&cache),
            Some(std::slice::from_ref(&protected)),
        );
        // Reconciliation does not know the operation's protected list.
        rejection(RejectionReason::ReconcileDeadline, None, None, Some(&cache));
    });
    let events = events.0.lock().unwrap();
    assert_eq!(events[0]["rejection_reason"], "\"eviction_deadline\"");
    assert_eq!(events[0]["physical_totals_known"], "true");
    assert_eq!(events[0]["pinned_bytes"], "0");
    assert_eq!(events[0]["evictable_bytes"], "8");
    assert_eq!(events[1]["cache_accounting_known"], "true");
    assert_eq!(events[1]["physical_totals_known"], "false");
    assert!(!events[1].contains_key("evictable_bytes"));
    assert_eq!(std::fs::read(protected).unwrap(), [1; 32]);
    assert_eq!(std::fs::read(evictable).unwrap(), [2; 8]);
}
