//! Frozen, disposable compatibility tuples with bounded namespace materialization.
use super::{capacity, invalid};
use crate::{MigrationAliases, MigrationMap};
use devres_domain::Result;
use std::{
    collections::BTreeMap,
    ops::Deref,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

const LIMIT: usize = 64 * 1024 * 1024;
const CACHE: usize = 8 * 1024 * 1024;
const BASE: usize = 64 * 1024;
const RESIDENT_ROWS: usize = 1_000_000;
const ROW_LIMIT: usize = RESIDENT_ROWS - CACHE / 32 - 1;
#[derive(Default)]
struct Budget {
    bytes: AtomicUsize,
    rows: AtomicUsize,
}
static RESIDENT: OnceLock<Arc<Budget>> = OnceLock::new();
fn resident() -> Arc<Budget> {
    Arc::clone(RESIDENT.get_or_init(|| Arc::new(Budget::default())))
}

pub(super) struct Reservation {
    bytes: usize,
    rows: usize,
    used: Arc<Budget>,
}
impl Reservation {
    pub(super) fn new(bytes: usize) -> Result<Self> {
        Self::in_budget(bytes, resident())
    }
    fn in_budget(bytes: usize, used: Arc<Budget>) -> Result<Self> {
        Self::with_rows(bytes, 0, used)
    }
    fn with_rows(bytes: usize, rows: usize, used: Arc<Budget>) -> Result<Self> {
        used.bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(bytes).filter(|n| *n <= LIMIT)
            })
            .map_err(|_| capacity())?;
        if used
            .rows
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(rows).filter(|n| *n <= RESIDENT_ROWS)
            })
            .is_err()
        {
            used.bytes.fetch_sub(bytes, Ordering::AcqRel);
            return Err(capacity());
        }
        Ok(Self { bytes, rows, used })
    }
    fn grow(&mut self, bytes: usize, rows: usize) -> Result<()> {
        let mut extra = Self::with_rows(bytes, rows, Arc::clone(&self.used))?;
        self.bytes += extra.bytes;
        self.rows += extra.rows;
        extra.bytes = 0;
        extra.rows = 0;
        Ok(())
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.used.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        self.used.rows.fetch_sub(self.rows, Ordering::AcqRel);
    }
}
struct Rows {
    old: Vec<String>,
    new: Vec<String>,
    has_targets: bool,
    _reservation: Reservation,
}
#[derive(Clone)]
pub(crate) struct VisibilityValues {
    rows: Arc<Rows>,
    targets: bool,
}
impl VisibilityValues {
    pub(super) fn empty() -> Self {
        Self {
            rows: Arc::new(Rows {
                old: Vec::new(),
                new: Vec::new(),
                has_targets: true,
                _reservation: Reservation {
                    bytes: 0,
                    rows: 0,
                    used: resident(),
                },
            }),
            targets: false,
        }
    }
}
impl AsRef<[String]> for VisibilityValues {
    fn as_ref(&self) -> &[String] {
        if self.targets {
            &self.rows.new
        } else {
            &self.rows.old
        }
    }
}
impl Deref for VisibilityValues {
    type Target = [String];
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

struct Namespace {
    aliases: MigrationAliases,
    bytes: usize,
    old_bytes: usize,
    new_bytes: usize,
    maximum: usize,
    maximum_new: usize,
    count: usize,
}
/// Fields close the redb handles before their shared cache reservation is freed.
pub(super) struct FrozenIndex {
    namespaces: BTreeMap<String, Namespace>,
    map: MigrationMap,
    cached: Mutex<Option<(String, Arc<Rows>)>>,
    reservation: Reservation,
}
impl FrozenIndex {
    pub(super) fn new() -> Result<Self> {
        Self::in_budget(resident())
    }
    fn in_budget(budget: Arc<Budget>) -> Result<Self> {
        Ok(Self {
            namespaces: BTreeMap::new(),
            map: MigrationMap::new(),
            cached: Mutex::new(None),
            reservation: Reservation::with_rows(CACHE + BASE, CACHE / 32, budget)?,
        })
    }
    #[cfg(test)]
    pub(super) fn push(&mut self, namespace: String, old: String, new: String) -> Result<()> {
        self.push_batch(namespace, &[(String::new(), old, new)])
    }
    pub(super) fn push_batch(
        &mut self,
        namespace: String,
        aliases: &[(String, String, String)],
    ) -> Result<()> {
        if aliases.is_empty() {
            return self.map.ensure_healthy();
        }
        let mut bytes = 0_usize;
        let mut maximum = 0_usize;
        let mut old_bytes = 0_usize;
        let mut new_bytes = 0_usize;
        let mut maximum_new = 0_usize;
        for (kind, old, new) in aliases {
            if !kind.is_empty() {
                return Err(invalid());
            }
            let size = old.len().checked_add(new.len()).ok_or_else(capacity)?;
            maximum = maximum.max(size);
            maximum_new = maximum_new.max(new.len());
            old_bytes = old_bytes.checked_add(old.len()).ok_or_else(capacity)?;
            new_bytes = new_bytes.checked_add(new.len()).ok_or_else(capacity)?;
            bytes = bytes.checked_add(size).ok_or_else(capacity)?;
        }
        if !self.namespaces.contains_key(&namespace) {
            self.reservation
                .grow(namespace.len().checked_add(512).ok_or_else(capacity)?, 1)?;
            self.namespaces.insert(
                namespace.clone(),
                Namespace {
                    aliases: MigrationAliases::new(&mut self.map)?,
                    bytes: 0,
                    old_bytes: 0,
                    new_bytes: 0,
                    maximum: 0,
                    maximum_new: 0,
                    count: 0,
                },
            );
        }
        let group = self.namespaces.get_mut(&namespace).ok_or_else(invalid)?;
        let bytes = group.bytes.checked_add(bytes).ok_or_else(capacity)?;
        let count = group
            .count
            .checked_add(aliases.len())
            .ok_or_else(capacity)?;
        group.aliases.extend(aliases)?;
        group.maximum = group.maximum.max(maximum);
        group.maximum_new = group.maximum_new.max(maximum_new);
        group.old_bytes = group
            .old_bytes
            .checked_add(old_bytes)
            .ok_or_else(capacity)?;
        group.new_bytes = group
            .new_bytes
            .checked_add(new_bytes)
            .ok_or_else(capacity)?;
        group.bytes = bytes;
        group.count = count;
        Ok(())
    }
    pub(super) fn aliases(&self, namespace: &str) -> Result<VisibilityValues> {
        self.materialize(namespace, false).map(|pairs| pairs.0)
    }
    pub(super) fn pairs(&self, namespace: &str) -> Result<(VisibilityValues, VisibilityValues)> {
        self.materialize(namespace, true)
    }
    fn materialize(
        &self,
        namespace: &str,
        with_targets: bool,
    ) -> Result<(VisibilityValues, VisibilityValues)> {
        self.map.ensure_healthy()?;
        let Some(group) = self.namespaces.get(namespace) else {
            let empty = VisibilityValues::empty();
            return Ok((empty.clone(), empty));
        };
        let mut cached = self.cached.lock().map_err(|_| invalid())?;
        if let Some((key, rows)) = cached.as_ref()
            && key == namespace
            && (!with_targets || rows.has_targets)
        {
            return Ok(Self::values(Arc::clone(rows)));
        }
        // Release the cache's reference first; outstanding readers retain their
        // own lifetime reservation and prevent over-admission of a second view.
        *cached = None;
        if group.count > ROW_LIMIT {
            return Err(capacity());
        }
        let vector_bytes = group
            .count
            .checked_mul(if with_targets {
                2 * std::mem::size_of::<String>()
            } else {
                std::mem::size_of::<String>()
            })
            .and_then(|n| n.checked_add(group.old_bytes))
            .and_then(|n| n.checked_add(if with_targets { group.new_bytes } else { 0 }))
            .ok_or_else(capacity)?;
        let bytes = group
            .maximum
            .checked_mul(3)
            .and_then(|extra| vector_bytes.checked_add(extra))
            .and_then(|n| {
                let dropped_targets = if with_targets {
                    0
                } else {
                    group.maximum_new.checked_mul(group.count.min(128))?
                };
                n.checked_add(dropped_targets)
            })
            .and_then(|n| {
                n.checked_add(128 * std::mem::size_of::<(String, String, String)>() + 4096)
            })
            .ok_or_else(capacity)?;
        let reservation =
            Reservation::with_rows(bytes, group.count, Arc::clone(&self.reservation.used))?;
        let mut old = Vec::with_capacity(group.count);
        let mut new = Vec::with_capacity(if with_targets { group.count } else { 0 });
        let mut actual = old
            .capacity()
            .checked_add(new.capacity())
            .and_then(|n| n.checked_mul(std::mem::size_of::<String>()))
            .ok_or_else(capacity)?;
        // Bounded pages move directly into exact-size final vectors. Reserved
        // string bytes include every pending decoded field; the extra allowance
        // covers page metadata and the largest encoded/decoded scratch record.
        for page in group.aliases.try_chunks(128) {
            for (kind, prior, target) in page? {
                if !kind.is_empty() || old.len() >= group.count {
                    return Err(invalid());
                }
                actual = actual
                    .checked_add(prior.capacity())
                    .and_then(|n| n.checked_add(if with_targets { target.capacity() } else { 0 }))
                    .ok_or_else(capacity)?;
                if actual > vector_bytes {
                    return Err(capacity());
                }
                old.push(prior);
                if with_targets {
                    new.push(target);
                }
            }
        }
        group.aliases.ensure_healthy()?;
        if old.len() != group.count {
            return Err(invalid());
        }
        let rows = Arc::new(Rows {
            old,
            new,
            has_targets: with_targets,
            _reservation: reservation,
        });
        *cached = Some((namespace.to_owned(), Arc::clone(&rows)));
        Ok(Self::values(rows))
    }
    fn values(rows: Arc<Rows>) -> (VisibilityValues, VisibilityValues) {
        (
            VisibilityValues {
                rows: Arc::clone(&rows),
                targets: false,
            },
            VisibilityValues {
                rows,
                targets: true,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }
    #[test]
    fn frozen_pairs_have_exact_capacities_and_share_one_reservation() {
        let _serial = serial();
        let mut index = FrozenIndex::in_budget(Arc::new(Budget::default())).unwrap();
        for n in 0..129 {
            index
                .push(
                    "mdn:projections".into(),
                    format!("old-{n:04}"),
                    format!("canonical-{n:04}"),
                )
                .unwrap();
        }
        let (old, new) = index.pairs("mdn:projections").unwrap();
        assert_eq!(old.len(), 129);
        assert_eq!(new.len(), 129);
        assert_eq!(old.rows.old.capacity(), 129);
        assert_eq!(old.rows.new.capacity(), 129);
        let (again, _) = index.pairs("mdn:projections").unwrap();
        assert!(Arc::ptr_eq(&old.rows, &again.rows));
        assert_eq!(old.as_ref()[0], "old-0000");
        assert_eq!(new.as_ref()[0], "canonical-0000");
        drop(index);
        assert_eq!(
            old.as_ref()[128],
            "old-0128",
            "views remain frozen after cache owner drops"
        );
    }
    #[test]
    fn namespace_batches_retain_exact_pairs_and_independent_group_statistics() {
        let _serial = serial();
        let mut index = FrozenIndex::in_budget(Arc::new(Budget::default())).unwrap();
        let batch: Vec<_> = (0..MigrationAliases::BATCH_ROWS)
            .map(|n| {
                (
                    String::new(),
                    format!("old-{n:04}"),
                    format!("canonical-{n:04}"),
                )
            })
            .collect();
        index.push_batch("mdn:projections".into(), &batch).unwrap();
        index.push_batch("mdn:headers".into(), &batch[..2]).unwrap();
        index
            .push_batch("mdn:projections".into(), &batch[..1])
            .unwrap();
        let group = &index.namespaces["mdn:projections"];
        let expected_bytes = batch
            .iter()
            .chain(batch[..1].iter())
            .map(|(_, old, new)| old.len() + new.len())
            .sum::<usize>();
        assert_eq!(group.count, 33);
        assert_eq!(group.bytes, expected_bytes);
        assert_eq!(group.maximum, batch[0].1.len() + batch[0].2.len());
        let (old, new) = index.pairs("mdn:projections").unwrap();
        assert_eq!(old.len(), 33);
        assert_eq!(old[31], "old-0031");
        assert_eq!(new[32], "canonical-0000");
        assert_eq!(index.pairs("mdn:headers").unwrap().0.len(), 2);
    }
    #[test]
    fn cached_generation_lifetime_prevents_over_admission() {
        let _serial = serial();
        let mut index = FrozenIndex::in_budget(Arc::new(Budget::default())).unwrap();
        index
            .push(
                "mdn:projections".into(),
                "original".into(),
                "canonical".into(),
            )
            .unwrap();
        index
            .push("mdn:headers".into(), "other".into(), "target".into())
            .unwrap();
        let (old, target) = index.pairs("mdn:projections").unwrap();
        let used = index.reservation.used.bytes.load(Ordering::Acquire);
        let occupied =
            Reservation::in_budget(LIMIT - used, Arc::clone(&index.reservation.used)).unwrap();
        // The identical cached view needs no second reservation.
        assert!(index.pairs("mdn:projections").is_ok());
        assert!(index.pairs("mdn:headers").is_err());
        assert_eq!(old.as_ref(), &["original"]);
        assert_eq!(target.as_ref(), &["canonical"]);
        drop(occupied);
        drop(old);
        drop(target);
        assert_eq!(index.pairs("mdn:headers").unwrap().0.as_ref(), &["other"]);
    }
    #[test]
    fn namespace_bounds_do_not_become_total_history_bounds() {
        let _serial = serial();
        let mut index = FrozenIndex::in_budget(Arc::new(Budget::default())).unwrap();
        index
            .push("mdn:projections".into(), "old".into(), "new".into())
            .unwrap();
        index
            .push("mdn:headers".into(), "header".into(), "new-header".into())
            .unwrap();
        index.namespaces.get_mut("mdn:projections").unwrap().count = ROW_LIMIT + 1;
        assert!(index.pairs("mdn:projections").is_err());
        assert_eq!(index.pairs("mdn:headers").unwrap().0.as_ref(), &["header"]);
        let group = index.namespaces.get_mut("mdn:projections").unwrap();
        group.count = 1;
        group.bytes = LIMIT;
        group.old_bytes = LIMIT;
        assert!(index.pairs("mdn:projections").is_err());
    }
    #[test]
    fn scratch_membership_fault_is_not_an_empty_successful_view() {
        let _serial = serial();
        let mut index = FrozenIndex::in_budget(Arc::new(Budget::default())).unwrap();
        index
            .push("mdn:projections".into(), "old".into(), "new".into())
            .unwrap();
        index.namespaces.get_mut("mdn:projections").unwrap().count = 2;
        assert!(index.pairs("mdn:projections").is_err());
    }
    #[test]
    fn large_opaque_namespace_reserves_decode_headroom_before_materialization() {
        let _serial = serial();
        let mut index = FrozenIndex::in_budget(Arc::new(Budget::default())).unwrap();
        for n in 0..4 {
            let old = format!("{n}{}", "x".repeat(9 * 1024 * 1024));
            index
                .push("mdn:opaque".into(), old, "canonical".into())
                .unwrap();
        }
        let before = index.reservation.used.bytes.load(Ordering::Acquire);
        assert_eq!(index.pairs("mdn:opaque").err().unwrap().code, "capacity");
        assert_eq!(index.reservation.used.bytes.load(Ordering::Acquire), before);
        assert!(index.cached.lock().unwrap().is_none());
    }
    #[test]
    fn old_only_views_preserve_pairs_and_upgrade_cache_without_rewriting_readers() {
        let _serial = serial();
        let mut index = FrozenIndex::in_budget(Arc::new(Budget::default())).unwrap();
        for n in 0..129 {
            index
                .push(
                    "mdn:projections".into(),
                    format!("old-{n:04}"),
                    format!("canonical-{n:04}"),
                )
                .unwrap();
        }
        let old = index.aliases("mdn:projections").unwrap();
        assert_eq!(old.rows.old.capacity(), 129);
        assert_eq!(old.rows.new.capacity(), 0);
        assert!(!old.rows.has_targets);
        let again = index.aliases("mdn:projections").unwrap();
        assert!(Arc::ptr_eq(&old.rows, &again.rows));
        let (paired_old, targets) = index.pairs("mdn:projections").unwrap();
        assert_eq!(old.as_ref(), paired_old.as_ref());
        assert!(!Arc::ptr_eq(&old.rows, &paired_old.rows));
        assert!(paired_old.rows.has_targets);
        assert_eq!(targets[128], "canonical-0128");
        let full_cache_old = index.aliases("mdn:projections").unwrap();
        assert!(Arc::ptr_eq(&paired_old.rows, &full_cache_old.rows));
        drop(index);
        drop(paired_old);
        drop(targets);
        drop(full_cache_old);
        drop(again);
        assert_eq!(
            old[128], "old-0128",
            "old-only readers retain their original reservation and values"
        );
    }
    #[test]
    fn old_only_namespace_fits_when_paired_targets_exceed_available_budget() {
        let _serial = serial();
        let mut index = FrozenIndex::in_budget(Arc::new(Budget::default())).unwrap();
        for n in 0..200 {
            index
                .push(
                    "mdn:projections".into(),
                    format!("{n:064}"),
                    format!("blake3:{n:064}"),
                )
                .unwrap();
        }
        let used = index.reservation.used.bytes.load(Ordering::Acquire);
        // Constrain this isolated fixture to 45KiB of view headroom while
        // keeping the actual production admission arithmetic unchanged.
        let occupied =
            Reservation::in_budget(LIMIT - used - 45_000, Arc::clone(&index.reservation.used))
                .unwrap();
        let old = index.aliases("mdn:projections").unwrap();
        assert_eq!(old.len(), 200);
        assert_eq!(old.rows.new.capacity(), 0);
        assert_eq!(
            index.pairs("mdn:projections").err().unwrap().code,
            "capacity"
        );
        assert_eq!(old[199], format!("{:064}", 199));
        drop(old);
        assert_eq!(
            index.pairs("mdn:projections").err().unwrap().code,
            "capacity"
        );
        assert_eq!(index.aliases("mdn:projections").unwrap().len(), 200);
        drop(occupied);
    }

    #[test]
    fn global_row_admission_survives_cache_eviction_and_reader_clones() {
        let _serial = serial();
        let budget = Arc::new(Budget::default());
        let mut index = FrozenIndex::in_budget(Arc::clone(&budget)).unwrap();
        for namespace in ["mdn:projections", "mdn:headers"] {
            for n in 0..2 {
                index
                    .push(
                        namespace.into(),
                        format!("old-{n:02}"),
                        format!("blake3:{n:064}"),
                    )
                    .unwrap();
            }
        }
        let existing_rows = budget.rows.load(Ordering::Acquire);
        // Leave three row slots, enough for either two-row namespace alone.
        // Bytes remain plentiful: failure must come from shared row admission.
        let occupied =
            Reservation::with_rows(0, RESIDENT_ROWS - existing_rows - 3, Arc::clone(&budget))
                .unwrap();
        let old = index.aliases("mdn:projections").unwrap();
        let clone = old.clone();
        let used_rows = budget.rows.load(Ordering::Acquire);
        let used_bytes = budget.bytes.load(Ordering::Acquire);
        assert!(used_bytes < LIMIT / 2);
        assert!(index.aliases("mdn:projections").is_ok());
        assert_eq!(
            budget.rows.load(Ordering::Acquire),
            used_rows,
            "cached clones share one row reservation"
        );
        assert_eq!(index.aliases("mdn:headers").err().unwrap().code, "capacity");
        assert_eq!(budget.rows.load(Ordering::Acquire), used_rows);
        assert_eq!(
            budget.bytes.load(Ordering::Acquire),
            used_bytes,
            "failed row admission rolls back its byte reservation"
        );
        assert_eq!(old[1], "old-01");
        drop(old);
        assert!(
            index.aliases("mdn:headers").is_err(),
            "last reader clone still owns the old row reservation"
        );
        drop(clone);
        assert_eq!(index.aliases("mdn:headers").unwrap().len(), 2);
        drop(index);
        drop(occupied);
        assert_eq!(budget.rows.load(Ordering::Acquire), 0);
        assert_eq!(budget.bytes.load(Ordering::Acquire), 0);
    }
}
