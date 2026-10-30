//! Verified compatibility visibility, frozen in disposable storage once active.
use super::{PgBlobStore, events};
use devres_domain::{Error, Result};
use futures::TryStreamExt;
use serde_json::json;
use sqlx::Row;
#[path = "storage_visibility_spill.rs"]
mod spill;
pub(super) use spill::VisibilityValues;
use std::{collections::BTreeMap, sync::atomic::Ordering};

const CUTOFF_GROUPS: &[&str] = &[
    "mdn",
    "whatwg",
    "w3c",
    "chromium",
    "npm",
    "advisory",
    "crate_inventory",
    "crate_generation",
    "crate_snapshot",
];

const ALIAS_GROUPS: &[&str] = &[
    "body", "capture", "rfc", "advisory", "crate", "npm", "mdn", "whatwg", "w3c", "chromium",
];

/// A bounded streaming commitment to one provider's sorted compatibility graph.
pub(super) struct AliasMembership {
    provider: String,
    hasher: blake3::Hasher,
    count: i64,
    previous: Option<(String, String)>,
}
impl AliasMembership {
    pub(super) fn new(provider: &str) -> Result<Self> {
        if !ALIAS_GROUPS.contains(&provider) {
            return Err(invalid());
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"devres-alias-membership-v1\0");
        hasher.update(&(provider.len() as u64).to_le_bytes());
        hasher.update(provider.as_bytes());
        Ok(Self {
            provider: provider.into(),
            hasher,
            count: 0,
            previous: None,
        })
    }
    pub(super) fn push(&mut self, namespace: &str, legacy: &str, canonical: &str) -> Result<()> {
        if namespace.split_once(':').map_or(namespace, |pair| pair.0) != self.provider
            || self
                .previous
                .as_ref()
                .is_some_and(|(old_namespace, old_legacy)| {
                    (namespace, legacy) <= (old_namespace.as_str(), old_legacy.as_str())
                })
        {
            return Err(invalid());
        }
        let digest = crate::integrity::canonical_hash(&json!([namespace, legacy, canonical]))?;
        self.hasher.update(digest.as_bytes());
        self.count = self.count.checked_add(1).ok_or_else(capacity)?;
        self.previous = Some((namespace.into(), legacy.into()));
        Ok(())
    }
    pub(super) fn finish(self) -> (i64, String) {
        (
            self.count,
            format!("blake3:{}", self.hasher.finalize().to_hex()),
        )
    }
}

pub(super) type VisibilityPairs = (VisibilityValues, VisibilityValues);

pub(super) struct VisibilityRegistry {
    index: Option<spill::FrozenIndex>,
    aliases_empty: bool,
    cutoffs: BTreeMap<String, i64>,
    // The verified sorted membership commitment identifies every frozen edge.
    memberships: BTreeMap<String, (i64, String)>,
    progress: BTreeMap<String, (bool, i64, String, String)>,
}
impl PartialEq for VisibilityRegistry {
    fn eq(&self, other: &Self) -> bool {
        self.cutoffs == other.cutoffs
            && self.memberships == other.memberships
            && self.progress == other.progress
    }
}
impl Eq for VisibilityRegistry {}

fn invalid() -> Error {
    Error::integrity("Retained compatibility visibility integrity failed.")
}
fn capacity() -> Error {
    Error::capacity("Compatibility visibility registry exceeds its memory bound.")
}
fn verify_cutoff(provider: &str, cutoff: i64, expected: &str) -> Result<()> {
    if !CUTOFF_GROUPS.contains(&provider)
        || cutoff < 0
        || events::event_digest(
            "devres_integrity_provider_cutoffs",
            provider,
            &json!({"provider":provider,"legacy_cutoff":cutoff}),
        )? != expected
    {
        return Err(invalid());
    }
    Ok(())
}

impl VisibilityRegistry {
    async fn load(pool: &sqlx::PgPool, active: bool) -> Result<Self> {
        Self::load_inner(pool, active, true).await
    }
    async fn load_inner(pool: &sqlx::PgPool, active: bool, freeze: bool) -> Result<Self> {
        // Admission and loading share one database snapshot: a concurrent pending
        // migration cannot grow the result between its byte check and allocation.
        let mut tx = pool.begin().await.map_err(|_| invalid())?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(|_| invalid())?;
        // Check a single record's transient encodings before loading it. Total
        // historical bytes are never a resident admission criterion.
        let largest: i64 = sqlx::query_scalar("SELECT COALESCE(max(bytes),0)::bigint FROM (SELECT octet_length(namespace)::bigint+octet_length(legacy)+octet_length(canonical)+COALESCE(octet_length(mapping_integrity),0) AS bytes FROM devres_content_aliases UNION ALL SELECT octet_length(provider)::bigint+COALESCE(octet_length(cutoff_integrity),0) FROM devres_integrity_provider_cutoffs UNION ALL SELECT octet_length(provider)::bigint+COALESCE(octet_length(aliases_digest),0)+COALESCE(octet_length(progress_integrity),0) FROM devres_integrity_graph_progress) registry")
            .fetch_one(&mut *tx).await.map_err(|_| invalid())?;
        let transient = usize::try_from(largest)
            .ok()
            .and_then(|n| n.checked_mul(64))
            .and_then(|n| n.checked_add(64 * 1024))
            .ok_or_else(capacity)?;
        let _transient = spill::Reservation::new(transient)?;
        let mut index = if freeze {
            Some(spill::FrozenIndex::new()?)
        } else {
            None
        };
        let mut cutoffs = BTreeMap::new();
        for row in sqlx::query("SELECT provider,legacy_cutoff,cutoff_integrity FROM devres_integrity_provider_cutoffs ORDER BY provider LIMIT 10")
            .fetch_all(&mut *tx).await.map_err(|_| invalid())? {
            let provider: String = row.try_get("provider").map_err(|_| invalid())?;
            let cutoff: i64 = row.try_get("legacy_cutoff").map_err(|_| invalid())?;
            let expected: String = row.try_get("cutoff_integrity").map_err(|_| invalid())?;
            verify_cutoff(&provider, cutoff, &expected)?;
            cutoffs.insert(provider, cutoff);
        }
        if active
            && CUTOFF_GROUPS
                .iter()
                .any(|provider| !cutoffs.contains_key(*provider))
        {
            return Err(invalid());
        }
        let mut aliases_empty = true;
        let mut memberships = ALIAS_GROUPS
            .iter()
            .map(|provider| Ok(((*provider).to_owned(), AliasMembership::new(provider)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut pending_namespace = String::new();
        let mut pending_aliases = Vec::new();
        let mut pending_bytes = 0_usize;
        let mut rows = sqlx::query("SELECT namespace,legacy,canonical,mapping_integrity FROM devres_content_aliases ORDER BY namespace COLLATE \"C\",legacy COLLATE \"C\"")
            .fetch(&mut *tx);
        while let Some(row) = rows.try_next().await.map_err(|_| invalid())? {
            let namespace: String = row.try_get("namespace").map_err(|_| invalid())?;
            let legacy: String = row.try_get("legacy").map_err(|_| invalid())?;
            let canonical: String = row.try_get("canonical").map_err(|_| invalid())?;
            let expected: String = row.try_get("mapping_integrity").map_err(|_| invalid())?;
            if namespace.is_empty()
                || namespace.len() > 128
                || legacy.is_empty()
                || !canonical.starts_with("blake3:")
                || !crate::integrity::valid_hash(&canonical)
                || events::event_digest(
                    "devres_content_aliases",
                    &events::mapping_key(&namespace, &legacy)?,
                    &json!({"namespace":namespace,"legacy":legacy,"canonical":canonical}),
                )? != expected
            {
                return Err(invalid());
            }
            memberships
                .get_mut(
                    namespace
                        .split_once(':')
                        .map_or(namespace.as_str(), |pair| pair.0),
                )
                .ok_or_else(invalid)?
                .push(&namespace, &legacy, &canonical)?;
            aliases_empty = false;
            if let Some(index) = index.as_mut() {
                let bytes = legacy
                    .len()
                    .checked_add(canonical.len())
                    .and_then(|n| n.checked_add(72))
                    .ok_or_else(capacity)?;
                if !pending_aliases.is_empty()
                    && (namespace != pending_namespace
                        || pending_bytes
                            .checked_add(bytes)
                            .is_none_or(|n| n > crate::MigrationAliases::BATCH_BYTES))
                {
                    index.push_batch(std::mem::take(&mut pending_namespace), &pending_aliases)?;
                    pending_aliases.clear();
                    pending_bytes = 0;
                }
                if pending_aliases.is_empty() {
                    pending_namespace = namespace;
                }
                pending_aliases.push((String::new(), legacy, canonical));
                pending_bytes = pending_bytes.checked_add(bytes).ok_or_else(capacity)?;
                if pending_aliases.len() == crate::MigrationAliases::BATCH_ROWS
                    || pending_bytes >= crate::MigrationAliases::BATCH_BYTES
                {
                    index.push_batch(std::mem::take(&mut pending_namespace), &pending_aliases)?;
                    pending_aliases.clear();
                    pending_bytes = 0;
                }
            }
        }
        drop(rows);
        if !pending_aliases.is_empty() {
            index
                .as_mut()
                .ok_or_else(invalid)?
                .push_batch(pending_namespace, &pending_aliases)?;
        }
        let mut actual = memberships
            .into_iter()
            .map(|(provider, membership)| (provider, membership.finish()))
            .collect::<BTreeMap<_, _>>();
        let verified_memberships = actual.clone();
        let mut progress = BTreeMap::new();
        for row in sqlx::query("SELECT provider,complete,aliases_count,aliases_digest,progress_integrity FROM devres_integrity_graph_progress ORDER BY provider LIMIT 11")
            .fetch_all(&mut *tx).await.map_err(|_|invalid())? {
            let provider:String=row.try_get("provider").map_err(|_|invalid())?;
            let complete:bool=row.try_get("complete").map_err(|_|invalid())?;
            if !ALIAS_GROUPS.contains(&provider.as_str()) { return Err(invalid()); }
            let count:i64=row.try_get("aliases_count").map_err(|_|invalid())?;
            let digest:String=row.try_get("aliases_digest").map_err(|_|invalid())?;
            let expected:String=row.try_get("progress_integrity").map_err(|_|invalid())?;
            if count < 0 || !digest.starts_with("blake3:") || !crate::integrity::valid_hash(&digest)
                || events::event_digest("devres_integrity_graph_progress",&provider,
                    &json!({"provider":provider,"complete":complete,"aliases_count":count,"aliases_digest":digest}))? != expected {
                return Err(invalid());
            }
            progress.insert(provider.clone(), (complete, count, digest.clone(), expected));
            if !complete {
                if active { return Err(invalid()); }
                continue;
            }
            if actual.remove(&provider).as_ref() != Some(&(count,digest)) { return Err(invalid()); }
        }
        if active && !actual.is_empty() {
            return Err(invalid());
        }
        tx.commit().await.map_err(|_| invalid())?;
        Ok(Self {
            index,
            aliases_empty,
            cutoffs,
            memberships: verified_memberships,
            progress,
        })
    }
    fn values(
        &self,
        provider: &str,
        kind: &str,
        cutoff: Option<i64>,
        with_targets: bool,
    ) -> Result<VisibilityPairs> {
        let cutoff_provider = match (provider, kind) {
            ("crate", "generations") => "crate_generation",
            ("crate", "inventories") => "crate_inventory",
            ("crate", "snapshots") => "crate_snapshot",
            _ => provider,
        };
        let watermark = self.cutoffs.get(cutoff_provider).ok_or_else(invalid)?;
        if cutoff.is_some_and(|cutoff| cutoff <= *watermark) {
            return Ok((VisibilityValues::empty(), VisibilityValues::empty()));
        }
        let namespace = format!("{provider}:{kind}");
        let index = self.index.as_ref().ok_or_else(invalid)?;
        if with_targets {
            index.pairs(&namespace)
        } else {
            index
                .aliases(&namespace)
                .map(|old| (old, VisibilityValues::empty()))
        }
    }
    #[cfg(test)]
    fn aliases(&self, provider: &str, kind: &str, cutoff: Option<i64>) -> Result<VisibilityValues> {
        self.values(provider, kind, cutoff, false)
            .map(|pairs| pairs.0)
    }
}

impl PgBlobStore {
    pub(super) async fn migration_cutoff(&self, provider: &str) -> Result<Option<i64>> {
        if self.active.load(Ordering::Acquire) {
            return Ok(None);
        }
        let row = sqlx::query("SELECT legacy_cutoff,cutoff_integrity FROM devres_integrity_provider_cutoffs WHERE provider=$1")
            .bind(provider).fetch_optional(&self.pool).await.map_err(|_| invalid())?;
        row.map(|row| {
            let cutoff: i64 = row.try_get("legacy_cutoff").map_err(|_| invalid())?;
            let expected: String = row.try_get("cutoff_integrity").map_err(|_| invalid())?;
            verify_cutoff(provider, cutoff, &expected)?;
            Ok(cutoff)
        })
        .transpose()
    }
    pub(super) async fn visibility_aliases(
        &self,
        provider: &str,
        kind: &str,
        cutoff: Option<i64>,
    ) -> Result<VisibilityValues> {
        self.visibility_values(provider, kind, cutoff, false)
            .await
            .map(|pairs| pairs.0)
    }
    pub(super) async fn visibility_pairs(
        &self,
        provider: &str,
        kind: &str,
        cutoff: Option<i64>,
    ) -> Result<VisibilityPairs> {
        self.visibility_values(provider, kind, cutoff, true).await
    }
    async fn visibility_values(
        &self,
        provider: &str,
        kind: &str,
        cutoff: Option<i64>,
        with_targets: bool,
    ) -> Result<VisibilityPairs> {
        if self.active.load(Ordering::Acquire) {
            return self
                .visibility
                .get_or_try_init(|| VisibilityRegistry::load(&self.pool, true))
                .await?
                .values(provider, kind, cutoff, with_targets);
        }
        let cutoff_provider = match (provider, kind) {
            ("crate", "generations") => "crate_generation",
            ("crate", "inventories") => "crate_inventory",
            ("crate", "snapshots") => "crate_snapshot",
            _ => provider,
        };
        let watermark = self.migration_cutoff(cutoff_provider).await?;
        if cutoff
            .zip(watermark)
            .is_some_and(|(cutoff, watermark)| cutoff <= watermark)
        {
            return Ok((VisibilityValues::empty(), VisibilityValues::empty()));
        }
        let registry = VisibilityRegistry::load(&self.pool, false).await?;
        // Fresh empty stores have no migration cutoff until qualification starts.
        if watermark.is_none() && registry.aliases_empty {
            return Ok((VisibilityValues::empty(), VisibilityValues::empty()));
        }
        registry.values(provider, kind, cutoff, with_targets)
    }
    /// Activation requires completed receipts and watermarks while serving remains pending.
    pub(super) async fn verify_complete_visibility_registry(&self) -> Result<()> {
        let retained = VisibilityRegistry::load_inner(&self.pool, true, false).await?;
        if self
            .visibility
            .get()
            .is_some_and(|cached| cached != &retained)
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// CLI verification reloads durable metadata even after public reads froze it.
    pub(super) async fn verify_visibility_registry(&self) -> Result<()> {
        let retained =
            VisibilityRegistry::load_inner(&self.pool, self.active.load(Ordering::Acquire), false)
                .await?;
        if self
            .visibility
            .get()
            .is_some_and(|cached| cached != &retained)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_membership_commits_to_ordered_provider_edges() {
        let original = crate::integrity::legacy_hash(b"original");
        let target = crate::integrity::hash(b"canonical");
        let mut mdn = AliasMembership::new("mdn").unwrap();
        mdn.push("mdn:projections", &original, &target).unwrap();
        let receipt = mdn.finish();
        assert_eq!(receipt.0, 1);
        assert_ne!(receipt, AliasMembership::new("mdn").unwrap().finish());
        let mut replay = AliasMembership::new("mdn").unwrap();
        replay.push("mdn:projections", &original, &target).unwrap();
        assert_eq!(receipt, replay.finish());
        let mut wrong = AliasMembership::new("npm").unwrap();
        assert!(wrong.push("mdn:projections", &original, &target).is_err());
        let mut duplicate = AliasMembership::new("mdn").unwrap();
        duplicate
            .push("mdn:projections", &original, &target)
            .unwrap();
        assert!(
            duplicate
                .push("mdn:projections", &original, &target)
                .is_err()
        );
    }

    #[test]
    fn visibility_watermarks_bind_provider_and_preserve_legacy_generations() {
        let expected = events::event_digest(
            "devres_integrity_provider_cutoffs",
            "mdn",
            &json!({"provider":"mdn","legacy_cutoff":12}),
        )
        .unwrap();
        verify_cutoff("mdn", 12, &expected).unwrap();
        assert!(verify_cutoff("mdn", 13, &expected).is_err());
        assert!(verify_cutoff("npm", 12, &expected).is_err());
        let mut index = spill::FrozenIndex::new().unwrap();
        index
            .push("mdn:projections".into(), "old".into(), "canonical".into())
            .unwrap();
        index
            .push(
                "crate:inventories".into(),
                "original".into(),
                "canonical".into(),
            )
            .unwrap();
        let registry = VisibilityRegistry {
            index: Some(index),
            aliases_empty: false,
            memberships: BTreeMap::new(),
            progress: BTreeMap::new(),
            cutoffs: BTreeMap::from([("mdn".into(), 12), ("crate_inventory".into(), 20)]),
        };
        assert!(
            registry
                .aliases("mdn", "projections", Some(12))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            registry
                .aliases("mdn", "projections", Some(13))
                .unwrap()
                .as_ref(),
            &["old"]
        );
        assert!(
            registry
                .aliases("crate", "inventories", Some(20))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            registry
                .aliases("crate", "inventories", None)
                .unwrap()
                .as_ref(),
            &["original"]
        );
        assert!(registry.aliases("missing", "projections", None).is_err());
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; verified visibility and frozen cursor generations"]
    async fn sql_visibility_registry_preserves_generations_and_detects_metadata_corruption() {
        use devres_application::mdn::MdnStore;
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let database = format!("devres_visibility_fixture_{suffix}");
        // A locale whose punctuation ordering differs from Rust byte ordering
        // exercises the explicit C collation used by the compatibility receipts.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database} TEMPLATE template0 LOCALE_PROVIDER libc LC_COLLATE 'en_US.utf8' LC_CTYPE 'en_US.utf8'")))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{database}"));
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let store = PgBlobStore::connect(url.as_str(), directory.path())
            .await
            .unwrap();
        store.active.store(false, Ordering::Release);
        sqlx::query("DELETE FROM devres_integrity_graph_progress WHERE provider='mdn'")
            .execute(&store.pool)
            .await
            .unwrap();
        let cutoff = 10;
        let seal = events::event_digest(
            "devres_integrity_provider_cutoffs",
            "mdn",
            &json!({"provider":"mdn","legacy_cutoff":cutoff}),
        )
        .unwrap();
        sqlx::query("INSERT INTO devres_integrity_provider_cutoffs(provider,legacy_cutoff,cutoff_integrity) VALUES('mdn',$1,$2) ON CONFLICT(provider) DO UPDATE SET legacy_cutoff=EXCLUDED.legacy_cutoff,cutoff_integrity=EXCLUDED.cutoff_integrity")
            .bind(cutoff).bind(&seal).execute(&store.pool).await.unwrap();
        let old = crate::integrity::legacy_hash(b"original");
        let canonical = crate::integrity::hash(b"canonical");
        let original = json!({"fixture":"original"});
        let new = json!({"fixture":"canonical"});
        sqlx::query("INSERT INTO devres_mdn_evidence(sequence,kind,key,data,data_integrity,sequence_integrity) VALUES(1,'projections',$1,$2,$3,$4)")
            .bind(&old).bind(sqlx::types::Json(&original))
            .bind(super::super::payload_integrity::digest("devres_mdn_evidence","projections",&old,&original).unwrap())
            .bind(super::super::sequence_integrity::digest("devres_mdn_evidence","projections",&old,1).unwrap())
            .execute(&store.pool).await.unwrap();
        // Reserve the canonical occurrence after the original frozen watermark.
        sqlx::query("SELECT setval(pg_get_serial_sequence('devres_mdn_evidence','sequence'),11)")
            .execute(&store.pool)
            .await
            .unwrap();
        store
            .mdn_put("projections", &canonical, &new)
            .await
            .unwrap();
        for namespace in ["mdn:projections", "mdn:projection-sequences"] {
            let alias_seal = events::event_digest(
                "devres_content_aliases",
                &events::mapping_key(namespace, &old).unwrap(),
                &json!({"namespace":namespace,"legacy":old,"canonical":canonical}),
            )
            .unwrap();
            sqlx::query("INSERT INTO devres_content_aliases(namespace,legacy,canonical,mapping_integrity) VALUES($1,$2,$3,$4)")
                .bind(namespace).bind(&old).bind(&canonical).bind(&alias_seal).execute(&store.pool).await.unwrap();
        }
        assert_eq!(
            store.mdn_rows("projections", 0, 100, None).await.unwrap()[0].key,
            canonical
        );
        assert_eq!(
            store
                .mdn_rows("projections", 0, 100, Some(cutoff))
                .await
                .unwrap()[0]
                .key,
            old
        );
        assert_eq!(
            store
                .mdn_get("projections", &old)
                .await
                .unwrap()
                .unwrap()
                .data,
            original
        );
        sqlx::query(
            "UPDATE devres_integrity_provider_cutoffs SET legacy_cutoff=11 WHERE provider='mdn'",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        assert_eq!(store.mdn_cutoff().await.unwrap_err().code, "integrity");
        sqlx::query(
            "UPDATE devres_integrity_provider_cutoffs SET legacy_cutoff=10 WHERE provider='mdn'",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE devres_content_aliases SET legacy='unsealed' WHERE namespace='mdn:projections'",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        assert_eq!(
            store
                .mdn_rows("projections", 0, 100, None)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        sqlx::query(
            "UPDATE devres_content_aliases SET legacy=$1 WHERE namespace='mdn:projections'",
        )
        .bind(&old)
        .execute(&store.pool)
        .await
        .unwrap();
        let mut membership = AliasMembership::new("mdn").unwrap();
        membership
            .push("mdn:projection-sequences", &old, &canonical)
            .unwrap();
        membership
            .push("mdn:projections", &old, &canonical)
            .unwrap();
        let (count, digest) = membership.finish();
        let receipt=events::event_digest("devres_integrity_graph_progress","mdn",&json!({"provider":"mdn","complete":true,"aliases_count":count,"aliases_digest":digest})).unwrap();
        sqlx::query("INSERT INTO devres_integrity_graph_progress(provider,complete,aliases_count,aliases_digest,progress_integrity) VALUES('mdn',true,$1,$2,$3)")
            .bind(count).bind(&digest).bind(receipt).execute(&store.pool).await.unwrap();
        // Pending verification still accepts incomplete known work, but checks its
        // seal and refuses unknown control families. Activation demands all receipts.
        store.verify_complete_visibility_registry().await.unwrap();
        let incomplete = events::event_digest("devres_integrity_graph_progress","mdn",
            &json!({"provider":"mdn","complete":false,"aliases_count":count,"aliases_digest":digest})).unwrap();
        sqlx::query(
            "UPDATE devres_integrity_graph_progress SET complete=false WHERE provider='mdn'",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(VisibilityRegistry::load(&store.pool, false).await.is_err());
        sqlx::query(
            "UPDATE devres_integrity_graph_progress SET progress_integrity=$1 WHERE provider='mdn'",
        )
        .bind(&incomplete)
        .execute(&store.pool)
        .await
        .unwrap();
        VisibilityRegistry::load(&store.pool, false).await.unwrap();
        assert!(store.verify_complete_visibility_registry().await.is_err());
        let receipt = events::event_digest("devres_integrity_graph_progress","mdn",
            &json!({"provider":"mdn","complete":true,"aliases_count":count,"aliases_digest":digest})).unwrap();
        sqlx::query("UPDATE devres_integrity_graph_progress SET complete=true,progress_integrity=$1 WHERE provider='mdn'")
            .bind(&receipt).execute(&store.pool).await.unwrap();
        sqlx::query("INSERT INTO devres_integrity_graph_progress SELECT 'unknown',false,aliases_count,aliases_digest,progress_integrity FROM devres_integrity_graph_progress WHERE provider='mdn'")
            .execute(&store.pool).await.unwrap();
        assert!(VisibilityRegistry::load(&store.pool, false).await.is_err());
        sqlx::query("DELETE FROM devres_integrity_graph_progress WHERE provider='unknown'")
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE retained_cutoff AS SELECT * FROM devres_integrity_provider_cutoffs WHERE provider='npm'")
            .execute(&mut *store.owner.lock().await).await.unwrap();
        sqlx::query("DELETE FROM devres_integrity_provider_cutoffs WHERE provider='npm'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.verify_complete_visibility_registry().await.is_err());
        sqlx::query("INSERT INTO devres_integrity_provider_cutoffs SELECT * FROM retained_cutoff")
            .execute(&mut *store.owner.lock().await)
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE retained_receipt AS SELECT * FROM devres_integrity_graph_progress WHERE provider='npm'")
            .execute(&mut *store.owner.lock().await).await.unwrap();
        sqlx::query("DELETE FROM devres_integrity_graph_progress WHERE provider='npm'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.verify_complete_visibility_registry().await.is_err());
        sqlx::query("INSERT INTO devres_integrity_graph_progress SELECT * FROM retained_receipt")
            .execute(&mut *store.owner.lock().await)
            .await
            .unwrap();
        store.verify_complete_visibility_registry().await.unwrap();
        store.active.store(true, Ordering::Release);
        assert_eq!(
            store.mdn_rows("projections", 0, 100, None).await.unwrap()[0].key,
            canonical
        );
        sqlx::query("DELETE FROM devres_content_aliases WHERE namespace='mdn:projections'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(VisibilityRegistry::load(&store.pool, true).await.is_err());
        // The active compatibility generation is immutable for serving readers.
        assert_eq!(
            store.mdn_rows("projections", 0, 100, None).await.unwrap()[0].key,
            canonical
        );
        sqlx::query(
            "UPDATE devres_integrity_provider_cutoffs SET legacy_cutoff=11 WHERE provider='mdn'",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(store.verify_visibility_registry().await.is_err());
        drop(store);
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {database} WITH (FORCE)"
        )))
        .execute(&admin)
        .await
        .unwrap();
        admin.close().await;
    }
}
