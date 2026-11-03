//! Bounded owned SQL hashing windows. Connections and publication remain with the reader.
use crate::MigrationExecution;
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const RECORDS: usize = 128;
const JOB_BYTES: usize = 256 * 1024;
const METADATA_BYTES: usize = 8 * 1024 * 1024;
type Sealed = (String, String, String, String);

fn capacity() -> Error {
    Error::capacity("Migration SQL work accounting exceeds its bound.")
}

/// The three existing envelopes deliberately remain distinct.
pub(crate) enum SealData {
    Payload {
        table: String,
        payload: Value,
    },
    Event {
        table: String,
        digest_key: String,
        payload: Value,
    },
    Sequence {
        table: String,
        sequence: i64,
    },
}

pub(crate) struct SealRecord {
    locator: String,
    kind: String,
    key: String,
    expected: Option<String>,
    data: SealData,
    charge: usize,
    metadata: usize,
}

fn sum(parts: impl IntoIterator<Item = usize>) -> Result<usize> {
    parts
        .into_iter()
        .try_fold(0_usize, |a, b| a.checked_add(b).ok_or_else(capacity))
}

/// Conservative allocation charge, not serialized JSON length or a claim about RSS.
/// BTree nodes are deliberately charged per entry with slack for their containers.
fn value_charge(value: &Value, depth: usize) -> Result<usize> {
    if depth > 128 {
        return Err(Error::capacity("Integrity value nesting exceeded."));
    }
    let heap = match value {
        Value::String(value) => value.capacity(),
        Value::Number(value) => value
            .to_string()
            .len()
            .checked_mul(8)
            .ok_or_else(capacity)?,
        Value::Array(values) => sum([
            values
                .capacity()
                .checked_mul(std::mem::size_of::<Value>())
                .ok_or_else(capacity)?,
            values.iter().try_fold(0_usize, |charge, value| {
                sum([charge, value_charge(value, depth + 1)?])
            })?,
        ])?,
        Value::Object(values) => values.iter().try_fold(0_usize, |charge, (key, value)| {
            sum([
                charge,
                2048,
                key.capacity().checked_mul(2).ok_or_else(capacity)?,
                value_charge(value, depth + 1)?,
            ])
        })?,
        _ => 0,
    };
    sum([std::mem::size_of::<Value>(), heap])
}

impl SealRecord {
    pub(crate) fn new(
        locator: String,
        kind: String,
        key: String,
        expected: Option<String>,
        data: SealData,
    ) -> Result<Self> {
        let (table, payload_charge, extra) = match &data {
            SealData::Payload { table, payload } => (table, value_charge(payload, 0)?, 0),
            SealData::Event {
                table,
                digest_key,
                payload,
            } => (table, value_charge(payload, 0)?, digest_key.capacity()),
            SealData::Sequence { table, .. } => (table, 1024, 0),
        };
        let metadata = sum([
            locator.capacity(),
            kind.capacity(),
            key.capacity(),
            table.capacity(),
            expected.as_ref().map_or(0, String::capacity),
            extra,
            512,
        ])?;
        if metadata > METADATA_BYTES {
            return Err(capacity());
        }
        // Retain the original owned input plus the existing cloned hash envelope.
        // Extra identity/scratch slack also covers key cloning during canonical traversal.
        let charge = sum([
            payload_charge.checked_mul(2).ok_or_else(capacity)?,
            metadata.checked_mul(3).ok_or_else(capacity)?,
            4096,
        ])?;
        Ok(Self {
            locator,
            kind,
            key,
            expected,
            data,
            charge,
            metadata,
        })
    }

    fn compute(self, verify_only: bool, cancel: &CancellationToken) -> Result<Option<Sealed>> {
        super::seal_not_cancelled(cancel)?;
        let (envelope, failure) = match &self.data {
            SealData::Payload { table, payload } => (
                json!({"version":1,"namespace":table,"key":[self.kind,self.key],"payload":payload}),
                "Retained SQL payload integrity failed.",
            ),
            SealData::Event {
                table,
                digest_key,
                payload,
            } => (
                json!({"version":1,"namespace":table,"key":digest_key,"payload":payload}),
                "Retained validation metadata integrity failed.",
            ),
            SealData::Sequence { table, sequence } => {
                if *sequence <= 0 {
                    return Err(Error::integrity(
                        "Retained occurrence ordering integrity failed.",
                    ));
                }
                (
                    json!({"version":1,"namespace":table,"kind":self.kind,"key":self.key,"sequence":sequence}),
                    "Retained occurrence ordering integrity failed.",
                )
            }
        };
        let digest = crate::integrity::canonical_hash_with_cancel(&envelope, cancel)?;
        match self.expected {
            Some(expected) if expected == digest => Ok(None),
            Some(_) => Err(Error::integrity(failure)),
            None if verify_only => Err(Error::integrity(failure)),
            None => Ok(Some((self.locator, self.kind, self.key, digest))),
        }
    }
}

/// Snapshot counters include all queued inputs and reserve the envelope clone/scratch.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SealWindowStats {
    pub admitted_records: usize,
    pub payload_charge: usize,
    pub metadata_bytes: usize,
    pub exclusive_oversized: bool,
}

pub(crate) struct SealWindow {
    records: Vec<SealRecord>,
    charge: usize,
    metadata: usize,
    budget: usize,
    job_rows: usize,
    verify_only: bool,
    admitted: u64,
    completed: u64,
    phase: String,
    high_water: SealWindowStats,
}

impl SealWindow {
    pub(crate) fn new(execution: &MigrationExecution, verify_only: bool) -> Self {
        let options = execution.options();
        Self {
            records: Vec::new(),
            charge: 0,
            metadata: 0,
            budget: options.payload_budget_bytes,
            job_rows: RECORDS.div_ceil(options.workers).clamp(1, 64),
            verify_only,
            admitted: 0,
            completed: 0,
            phase: String::new(),
            high_water: SealWindowStats::default(),
        }
    }

    pub(crate) fn needs_flush(&self, candidate: &SealRecord) -> bool {
        !self.records.is_empty()
            && (self.records.len() >= RECORDS
                || self
                    .charge
                    .checked_add(candidate.charge)
                    .is_none_or(|charge| charge > self.budget)
                || self
                    .metadata
                    .checked_add(candidate.metadata)
                    .is_none_or(|bytes| bytes > METADATA_BYTES))
    }

    pub(crate) fn push(&mut self, record: SealRecord) -> Result<()> {
        if self.needs_flush(&record) {
            return Err(capacity());
        }
        self.charge = self
            .charge
            .checked_add(record.charge)
            .ok_or_else(capacity)?;
        self.metadata = self
            .metadata
            .checked_add(record.metadata)
            .ok_or_else(capacity)?;
        if self.phase.is_empty() {
            let (kind, table) = match &record.data {
                SealData::Payload { table, .. } => ("payload", table),
                SealData::Event { table, .. } => ("event", table),
                SealData::Sequence { table, .. } => ("sequence", table),
            };
            self.phase = format!(
                "{}_{}_{}",
                if self.verify_only { "verify" } else { "seal" },
                kind,
                table
            );
        }
        self.records.push(record);
        self.admitted = self.admitted.checked_add(1).ok_or_else(capacity)?;
        let stats = self.stats();
        self.high_water.admitted_records =
            self.high_water.admitted_records.max(stats.admitted_records);
        self.high_water.payload_charge = self.high_water.payload_charge.max(stats.payload_charge);
        self.high_water.metadata_bytes = self.high_water.metadata_bytes.max(stats.metadata_bytes);
        self.high_water.exclusive_oversized |= stats.exclusive_oversized;
        Ok(())
    }

    pub(crate) fn stats(&self) -> SealWindowStats {
        SealWindowStats {
            admitted_records: self.records.len(),
            payload_charge: self.charge,
            metadata_bytes: self.metadata,
            exclusive_oversized: self.records.len() == 1 && self.charge > self.budget,
        }
    }

    pub(crate) async fn flush(
        &mut self,
        execution: &MigrationExecution,
        cancel: &CancellationToken,
    ) -> Result<Vec<Sealed>> {
        execution.report(
            &self.phase,
            self.admitted,
            self.completed,
            0,
            self.high_water.payload_charge,
        );
        let record_count = self.records.len() as u64;
        let records = std::mem::take(&mut self.records);
        self.charge = 0;
        self.metadata = 0;
        let mut jobs = Vec::new();
        let mut batch = Vec::new();
        let mut bytes = 0_usize;
        for record in records {
            if !batch.is_empty()
                && (batch.len() >= self.job_rows
                    || bytes
                        .checked_add(record.charge)
                        .is_none_or(|next| next > JOB_BYTES))
            {
                jobs.push(std::mem::take(&mut batch));
                bytes = 0;
            }
            bytes = bytes.checked_add(record.charge).ok_or_else(capacity)?;
            batch.push(record);
        }
        if !batch.is_empty() {
            jobs.push(batch);
        }
        let verify_only = self.verify_only;
        let output = execution
            .map_ordered(jobs, cancel, move |records, cancel| {
                let mut sealed = Vec::new();
                for record in records {
                    if let Some(record) = record.compute(verify_only, &cancel)? {
                        sealed.push(record);
                    }
                }
                Ok(sealed)
            })
            .await?;
        self.completed = self
            .completed
            .checked_add(record_count)
            .ok_or_else(capacity)?;
        execution.report(
            &self.phase,
            self.admitted,
            self.completed,
            0,
            self.high_water.payload_charge,
        );
        Ok(output.into_iter().flatten().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MigrationExecutionOptions;

    fn record(n: usize, payload: Value) -> SealRecord {
        SealRecord::new(
            n.to_string(),
            "kind".into(),
            n.to_string(),
            None,
            SealData::Payload {
                table: "fixture".into(),
                payload,
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn windows_bound_records_and_charge_and_preserve_hashes() {
        let cancel = CancellationToken::new();
        let execution =
            MigrationExecution::new(MigrationExecutionOptions::new(4, 64 * 1024 * 1024).unwrap())
                .unwrap();
        let mut window = SealWindow::new(&execution, false);
        for n in 0..128 {
            let input = record(n, json!({"public":n}));
            assert!(!window.needs_flush(&input));
            window.push(input).unwrap();
        }
        assert!(window.needs_flush(&record(129, Value::Null)));
        let stats = window.stats();
        assert_eq!(stats.admitted_records, 128);
        assert!(stats.payload_charge <= execution.options().payload_budget_bytes);
        assert!(stats.metadata_bytes <= METADATA_BYTES);
        assert!(!stats.exclusive_oversized);
        let output = window.flush(&execution, &cancel).await.unwrap();
        assert_eq!(output.len(), 128);
        for (n, (_, kind, key, seal)) in output.into_iter().enumerate() {
            assert_eq!(key, n.to_string());
            assert_eq!(
                seal,
                super::super::digest("fixture", &kind, &key, &json!({"public":n})).unwrap()
            );
        }
    }

    #[tokio::test]
    async fn budget_pressure_and_large_row_are_exclusive_without_rejection() {
        let cancel = CancellationToken::new();
        let execution =
            MigrationExecution::new(MigrationExecutionOptions::new(2, 8192).unwrap()).unwrap();
        let mut window = SealWindow::new(&execution, false);
        window.push(record(0, Value::Null)).unwrap();
        let large = record(1, json!({"public":"x".repeat(16384)}));
        assert!(window.needs_flush(&large));
        assert_eq!(window.flush(&execution, &cancel).await.unwrap().len(), 1);
        window.push(large).unwrap();
        assert!(window.stats().exclusive_oversized);
        assert!(window.needs_flush(&record(2, Value::Null)));
        assert_eq!(window.flush(&execution, &cancel).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn existing_seals_and_missing_seals_are_verified_read_only() {
        let cancel = CancellationToken::new();
        let execution = MigrationExecution::default();
        let mut window = SealWindow::new(&execution, true);
        window.push(record(0, json!({"public":true}))).unwrap();
        assert_eq!(
            window.flush(&execution, &cancel).await.unwrap_err().code,
            "integrity"
        );
        let mut input = record(0, json!({"public":true}));
        input.expected =
            Some(super::super::digest("fixture", "kind", "0", &json!({"public":true})).unwrap());
        window.push(input).unwrap();
        assert!(window.flush(&execution, &cancel).await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn distinct_envelopes_and_serial_parallel_results_match() {
        let cancel = CancellationToken::new();
        let mut results = Vec::new();
        for workers in [1, 2, 64] {
            let execution = MigrationExecution::new(
                MigrationExecutionOptions::new(workers, 64 * 1024 * 1024).unwrap(),
            )
            .unwrap();
            let mut window = SealWindow::new(&execution, false);
            window
                .push(
                    SealRecord::new(
                        "event".into(),
                        String::new(),
                        "1".into(),
                        None,
                        SealData::Event {
                            table: "devres_heads".into(),
                            digest_key: "1".into(),
                            payload: json!({"public": "fixture"}),
                        },
                    )
                    .unwrap(),
                )
                .unwrap();
            window
                .push(
                    SealRecord::new(
                        "sequence".into(),
                        "kind".into(),
                        "key".into(),
                        None,
                        SealData::Sequence {
                            table: "devres_mdn_evidence".into(),
                            sequence: 1,
                        },
                    )
                    .unwrap(),
                )
                .unwrap();
            let output = window.flush(&execution, &cancel).await.unwrap();
            assert_eq!(output[0].3, crate::integrity::canonical_hash(&json!({"version":1,"namespace":"devres_heads","key":"1","payload":{"public":"fixture"}})).unwrap());
            assert_eq!(output[1].3, crate::integrity::canonical_hash(&json!({"version":1,"namespace":"devres_mdn_evidence","kind":"kind","key":"key","sequence":1})).unwrap());
            results.push(output);
        }
        assert_eq!(results[0], results[1]);
        assert_eq!(results[0], results[2]);
    }

    #[tokio::test]
    async fn invalid_seal_or_cancellation_discards_entire_hash_window() {
        let execution = MigrationExecution::default();
        let cancel = CancellationToken::new();
        let mut window = SealWindow::new(&execution, false);
        window.push(record(0, Value::Null)).unwrap();
        let mut corrupt = record(1, Value::Null);
        corrupt.expected = Some("blake3:invalid".into());
        window.push(corrupt).unwrap();
        assert_eq!(
            window.flush(&execution, &cancel).await.unwrap_err().code,
            "integrity"
        );
        assert_eq!(window.stats().admitted_records, 0);
        assert_eq!(execution.snapshot().active, 0);
        window.push(record(2, Value::Null)).unwrap();
        cancel.cancel();
        assert_eq!(
            window.flush(&execution, &cancel).await.unwrap_err().code,
            "cancelled"
        );
        assert_eq!(window.stats().admitted_records, 0);
        assert_eq!(execution.snapshot().active, 0);
    }

    #[test]
    fn singleton_object_arrays_reserve_minimum_tree_node_capacity() {
        let payload = Value::Array((0..4096).map(|_| json!({"k":null})).collect());
        let charged = value_charge(&payload, 0).unwrap();
        // A minimally occupied BTree leaf has multiple inline key/value slots;
        // charge a full conservative node allowance for every singleton object.
        assert!(charged >= 4096 * 2048);
        let record = record(0, payload);
        assert!(record.charge >= charged * 2);
    }

    #[test]
    fn accounting_includes_container_allocations_and_checks_overflow() {
        let scalar = value_charge(&json!("x".repeat(1000)), 0).unwrap();
        let many = value_charge(&json!(["x".repeat(1000), "x".repeat(1000)]), 0).unwrap();
        assert!(many > scalar * 2);
        assert_eq!(sum([usize::MAX, 1]).unwrap_err().code, "capacity");
    }
}
