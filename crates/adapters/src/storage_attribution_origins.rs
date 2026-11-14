//! Bounded forward traversal of immutable origins. No provider I/O or reverse search.
use super::*;

const TABLE: &str = "devres_attribution_origins";
const MAX_ROW: i64 = 16 * 1024 * 1024;
const MAX_STEPS: usize = 128;
const MAX_FRONTIER: usize = 256;
const MAX_PAGE_BYTES: usize = 32 * 1024 * 1024;
const PAGE_STEPS: usize = 16;

pub(crate) const SCHEMA_V18: &str = r#"
CREATE TABLE devres_attribution_origins(provider text PRIMARY KEY,data jsonb NOT NULL,data_integrity text NOT NULL);
"#;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Reference {
    kind: String,
    key: String,
    digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Witness {
    version: u32,
    provider: String,
    chain: Vec<Reference>,
    member: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    kind: String,
    key: String,
    ancestors: Vec<Reference>,
    member: Option<usize>,
    leaf: Option<String>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u32,
    policy_epoch: u32,
    policy_fingerprint: String,
    recipe: String,
    after: i64,
    cutoff: Option<i64>,
    frontier: Vec<Frame>,
    passes: u64,
    #[serde(default)]
    gap: Option<AttributionFailure>,
}

pub(super) fn supports(provider: &str) -> bool {
    matches!(provider, "mdn" | "whatwg" | "w3c" | "chromium")
}
fn table(provider: &str) -> Result<&'static str> {
    match provider {
        "mdn" => Ok("devres_mdn_evidence"),
        "whatwg" => Ok("devres_whatwg_evidence"),
        "w3c" => Ok("devres_w3c_evidence"),
        "chromium" => Ok("devres_chromium_evidence"),
        _ => Err(invalid()),
    }
}
fn kind(value: &str) -> bool {
    matches!(
        value,
        "snapshots"
            | "nodes"
            | "projections"
            | "projection-headers"
            | "projection-sequences"
            | "projection-chunks"
            | "projection-sections"
            | "projection-symbols"
            | "projection-references"
            | "index-documents"
    )
}
fn reference(value: &Reference) -> Result<()> {
    if !kind(&value.kind)
        || value.key.is_empty()
        || value.key.len() > 4096
        || value.key.chars().any(char::is_control)
        || !crate::integrity::valid_hash(&value.digest)
    {
        return Err(invalid());
    }
    Ok(())
}
fn validate_checkpoint(value: &Checkpoint) -> Result<()> {
    if value.version != 1
        || value.policy_epoch != ATTRIBUTION_POLICY_EPOCH
        || value.policy_fingerprint != ATTRIBUTION_POLICY_FINGERPRINT
        || value.recipe != "forward-origins-v2"
        || value.after < 0
        || value.cutoff.is_some_and(|cutoff| cutoff < value.after)
        || value.frontier.len() > MAX_FRONTIER
    {
        return Err(invalid());
    }
    for frame in &value.frontier {
        if !kind(&frame.kind)
            || frame.key.is_empty()
            || frame.key.len() > 4096
            || frame.key.chars().any(char::is_control)
            || frame.ancestors.len() >= MAX_STEPS
            || frame
                .member
                .is_some_and(|member| member >= frame.ancestors.len())
            || frame.leaf.as_deref().is_some_and(|leaf| {
                !matches!(
                    leaf,
                    "projection-chunks"
                        | "projection-sections"
                        | "projection-symbols"
                        | "projection-references"
                        | "index-documents"
                )
            })
        {
            return Err(invalid());
        }
        for item in &frame.ancestors {
            reference(item)?;
        }
    }
    bounded(value)?;
    Ok(())
}

async fn load(
    conn: &mut PgConnection,
    provider: &str,
    kind: &str,
    key: &str,
    charge: &mut usize,
) -> Result<(Reference, Value)> {
    if !self::kind(kind) || key.len() > 4096 {
        return Err(invalid());
    }
    let table = table(provider)?;
    let sql =
        format!("SELECT octet_length(data::text)::bigint FROM {table} WHERE kind=$1 AND key=$2");
    let bytes: Option<i64> =
        sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(sql))
            .bind(kind)
            .bind(key)
            .fetch_optional(&mut *conn)
            .await
            .map_err(source_error)?;
    let bytes = bytes.ok_or_else(|| {
        Error::new(
            "attribution_origin_missing",
            "Exact attribution origin row is missing.",
        )
    })?;
    if !(0..=MAX_ROW).contains(&bytes) {
        return Err(Error::capacity(
            "Attribution origin row exceeds its decoder bound.",
        ));
    }
    *charge = charge
        .checked_add(bytes as usize)
        .filter(|bytes| *bytes <= MAX_PAGE_BYTES)
        .ok_or_else(|| Error::capacity("Attribution origin traversal exceeds its byte bound."))?;
    let sql = format!(
        "SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM {table} WHERE kind=$1 AND key=$2 AND octet_length(data::text)<=$3"
    );
    let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
        .bind(kind)
        .bind(key)
        .bind(MAX_ROW)
        .fetch_one(conn)
        .await
        .map_err(source_error)?;
    let value = payload_integrity::row(table, &row)?;
    // Inventory hashes use the typed serialization order, whereas shared
    // projection objects are hashes of their JSON representation.
    let hashed = match (provider, kind) {
        ("mdn", "nodes") => Some(
            serde_json::to_vec(
                &serde_json::from_value::<devres_application::mdn::InventoryNode>(value.clone())
                    .map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?,
        ),
        ("whatwg", "nodes") => Some(
            serde_json::to_vec(
                &serde_json::from_value::<devres_application::whatwg::InventoryNode>(value.clone())
                    .map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?,
        ),
        ("w3c", "nodes") => Some(
            serde_json::to_vec(
                &serde_json::from_value::<devres_application::w3c::InventoryNode>(value.clone())
                    .map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?,
        ),
        ("chromium", "nodes") => Some(
            serde_json::to_vec(
                &serde_json::from_value::<devres_application::chromium::InventoryNode>(
                    value.clone(),
                )
                .map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?,
        ),
        ("mdn", "projections")
        | (
            _,
            "projection-sequences"
            | "projection-chunks"
            | "projection-sections"
            | "projection-symbols"
            | "projection-references",
        ) => Some(serde_json::to_vec(&value).map_err(|_| invalid())?),
        _ => None,
    };
    if let Some(bytes) = hashed {
        crate::integrity::verify(key, &bytes)?;
    }
    let digest = row.try_get("data_integrity").map_err(|_| invalid())?;
    Ok((
        Reference {
            kind: kind.into(),
            key: key.into(),
            digest,
        },
        value,
    ))
}

fn edge(parent: &Reference, value: &Value, child: &Reference, child_value: &Value) -> Result<()> {
    let equal = |value: &Value| value.as_str() == Some(child.key.as_str());
    let valid = match (parent.kind.as_str(), child.kind.as_str()) {
        ("snapshots", "nodes") => equal(&value["inventory"]),
        ("nodes", "nodes") => ["children", "buckets"].iter().any(|key| {
            value[*key]
                .as_object()
                .is_some_and(|entries| entries.values().any(equal))
        }),
        ("nodes", "projections") => equal(&value["member"]["projection"]),
        ("projections", "projection-headers") => {
            parent.key == child.key
                && ["slug", "redirects"]
                    .iter()
                    .all(|key| value.get(*key) == child_value.get(*key))
                && child_value.as_object().is_some_and(|map| {
                    map.keys()
                        .all(|key| matches!(key.as_str(), "slug" | "redirects"))
                })
        }
        ("projections", "projection-sequences") => {
            ["text", "sections", "symbols", "references"]
                .iter()
                .any(|key| equal(&value["manifest"][*key]))
                || equal(&value["index_membership"])
        }
        ("projection-sequences", "projection-sequences") => value["children"]
            .as_array()
            .is_some_and(|children| children.iter().any(equal)),
        (
            "projection-sequences",
            "projection-chunks"
            | "projection-sections"
            | "projection-symbols"
            | "projection-references"
            | "index-documents",
        ) => value["values"]
            .as_array()
            .is_some_and(|children| children.iter().any(equal)),
        ("projection-sections" | "projection-symbols", "projection-sequences") => {
            equal(&value["text"])
        }
        _ => false,
    };
    if !valid {
        return Err(invalid());
    }
    Ok(())
}

fn source(provider: &str, snapshot: Value, member: Value) -> Result<AttributionTarget> {
    let evidence = match provider {
        "mdn" => crate::mdn::research::attribution_member_evidence(
            &serde_json::from_value(snapshot).map_err(|_| invalid())?,
            &serde_json::from_value(member).map_err(|_| invalid())?,
        ),
        "whatwg" => crate::whatwg::research::attribution_member_evidence(
            &serde_json::from_value(snapshot).map_err(|_| invalid())?,
            &serde_json::from_value(member).map_err(|_| invalid())?,
        ),
        "w3c" => crate::w3c::research::attribution_member_evidence(
            &serde_json::from_value(snapshot).map_err(|_| invalid())?,
            &serde_json::from_value(member).map_err(|_| invalid())?,
        ),
        "chromium" => crate::chromium::research::attribution_member_evidence(
            &serde_json::from_value(snapshot).map_err(|_| invalid())?,
            &serde_json::from_value(member).map_err(|_| invalid())?,
        ),
        _ => return Err(invalid()),
    };
    let mut targets = crate::attribution_providers::targets(provider, &evidence)?;
    if targets.len() != 1 {
        return Err(invalid());
    }
    targets.pop().ok_or_else(invalid)
}

async fn verify_witness(
    conn: &mut PgConnection,
    witness: &Witness,
    charge: &mut usize,
) -> Result<AttributionTarget> {
    if witness.version != 1
        || !supports(&witness.provider)
        || !(2..=MAX_STEPS).contains(&witness.chain.len())
        || witness.member == 0
        || witness.member >= witness.chain.len()
        || witness.chain[0].kind != "snapshots"
        || witness.chain[witness.member].kind != "nodes"
    {
        return Err(invalid());
    }
    if witness.chain[1..=witness.member]
        .iter()
        .any(|item| item.kind != "nodes")
        || witness
            .chain
            .get(witness.member + 1)
            .is_some_and(|item| item.kind != "projections")
        || witness.chain[witness.member + 1..]
            .iter()
            .any(|item| matches!(item.kind.as_str(), "nodes" | "snapshots"))
    {
        return Err(invalid());
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut previous: Option<(Reference, Value)> = None;
    let mut snapshot = Value::Null;
    let mut member = Value::Null;
    for (index, expected) in witness.chain.iter().enumerate() {
        reference(expected)?;
        if !seen.insert((&expected.kind, &expected.key)) {
            return Err(invalid());
        }
        let (actual, value) = load(
            conn,
            &witness.provider,
            &expected.kind,
            &expected.key,
            charge,
        )
        .await?;
        if actual != *expected {
            return Err(invalid());
        }
        if index == 0 {
            if value["id"].as_str() != Some(expected.key.as_str()) {
                return Err(invalid());
            }
            snapshot = value.clone();
        }
        if let Some((parent, parent_value)) = previous {
            edge(&parent, &parent_value, &actual, &value)?;
        }
        if index == witness.member {
            member = value["member"].clone();
            if !member.is_object() {
                return Err(invalid());
            }
        }
        previous = Some((actual, value));
    }
    source(&witness.provider, snapshot, member)
}

pub(super) async fn verify_target(
    conn: &mut PgConnection,
    target: &AttributionTarget,
) -> Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        verify_target_tree(conn, target),
    )
    .await
    .map_err(|_| Error::capacity("Attribution origin verification deadline exceeded."))?
}
async fn verify_target_tree(conn: &mut PgConnection, target: &AttributionTarget) -> Result<()> {
    let mut pending = vec![(target.clone(), 0usize)];
    // One root plus the established maximum of 128 direct dependencies.
    // Publication retains its independent aggregate proof budget.
    let mut remaining = 129usize;
    let mut charge = 0;
    while let Some((target, depth)) = pending.pop() {
        if remaining == 0 || depth > 8 {
            return Err(Error::capacity(
                "Attribution origin dependency bound exceeded.",
            ));
        }
        remaining -= 1;
        checked_target(&target)?;
        verify_target_inner(conn, &target, &mut charge).await?;
        if let Some(children) = target.evidence.get("dependencies") {
            let children = children
                .as_array()
                .filter(|children| children.len() <= remaining)
                .ok_or_else(invalid)?;
            for child in children {
                pending.push((
                    serde_json::from_value(child.clone()).map_err(|_| invalid())?,
                    depth + 1,
                ));
            }
        }
    }
    Ok(())
}
async fn verify_target_inner(
    conn: &mut PgConnection,
    target: &AttributionTarget,
    charge: &mut usize,
) -> Result<()> {
    let Some(value) = target.evidence.get("origin_witness") else {
        return Ok(());
    };
    checked_target(target)?;
    if target.evidence["version"] != 2 || target.subject.namespace != "origin" {
        return Err(invalid());
    }
    let witness: Witness = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    if witness.provider != target.subject.provider {
        return Err(invalid());
    }
    let actual = verify_witness(conn, &witness, charge).await?;
    let expected: AttributionTarget =
        serde_json::from_value(target.evidence["source_target"].clone()).map_err(|_| invalid())?;
    if actual != expected {
        return Err(invalid());
    }
    Ok(())
}

fn target(witness: Witness, source: AttributionTarget) -> Result<AttributionTarget> {
    let evidence = json!({"version":2,"origin_witness":witness,"source_target":source});
    let fingerprint = crate::integrity::canonical_hash(&evidence)?;
    let target = AttributionTarget {
        subject: AttributionSubject {
            provider: witness.provider,
            namespace: "origin".into(),
            key: fingerprint.clone(),
            fingerprint,
        },
        evidence,
    };
    checked_target(&target)?;
    Ok(target)
}

fn push(
    frontier: &mut Vec<Frame>,
    parent: &[Reference],
    member: Option<usize>,
    leaf: Option<&str>,
    kind: &str,
    key: &Value,
) -> Result<()> {
    let Some(key) = key.as_str() else {
        return Err(invalid());
    };
    if frontier.len() >= MAX_FRONTIER || parent.len() >= MAX_STEPS {
        return Err(Error::capacity(
            "Attribution origin frontier exceeds its bound.",
        ));
    }
    let candidate = Frame {
        kind: kind.into(),
        key: key.into(),
        ancestors: parent.into(),
        member,
        leaf: leaf.map(str::to_owned),
    };
    let mut bytes = serde_json::to_vec(&candidate)
        .map_err(|_| invalid())?
        .len()
        .saturating_add(2);
    for frame in frontier.iter() {
        bytes = bytes
            .saturating_add(serde_json::to_vec(frame).map_err(|_| invalid())?.len())
            .saturating_add(1);
        if bytes > MAX_VALUE {
            return Err(Error::capacity(
                "Attribution origin frontier exceeds its byte bound.",
            ));
        }
    }
    if bytes > MAX_VALUE {
        return Err(Error::capacity(
            "Attribution origin frontier exceeds its byte bound.",
        ));
    }
    frontier.push(candidate);
    Ok(())
}

async fn step(
    conn: &mut PgConnection,
    provider: &str,
    frame: Frame,
    frontier: &mut Vec<Frame>,
    charge: &mut usize,
) -> Result<Option<AttributionTarget>> {
    let (current, value) = load(conn, provider, &frame.kind, &frame.key, charge).await?;
    if frame
        .ancestors
        .iter()
        .any(|ancestor| ancestor.kind == current.kind && ancestor.key == current.key)
    {
        return Err(invalid());
    }
    let mut chain = frame.ancestors;
    if let Some(parent) = chain.last() {
        let (_, parent_value) = load(conn, provider, &parent.kind, &parent.key, charge).await?;
        edge(parent, &parent_value, &current, &value)?;
    }
    chain.push(current.clone());
    let mut member = frame.member;
    match frame.kind.as_str() {
        "snapshots" => push(frontier, &chain, None, None, "nodes", &value["inventory"])?,
        "nodes" => {
            for key in ["children", "buckets"] {
                if let Some(children) = value[key].as_object() {
                    for child in children.values().rev() {
                        push(frontier, &chain, None, None, "nodes", child)?;
                    }
                }
            }
            if value["member"].is_object() {
                member = Some(chain.len() - 1);
                if value["member"]["projection"].is_string() {
                    push(
                        frontier,
                        &chain,
                        member,
                        None,
                        "projections",
                        &value["member"]["projection"],
                    )?;
                }
            }
        }
        "projections" => {
            if provider == "mdn" {
                push(
                    frontier,
                    &chain,
                    member,
                    None,
                    "projection-headers",
                    &json!(frame.key),
                )?;
            } else if value["manifest"].is_object() {
                for (key, leaf) in [
                    ("text", "projection-chunks"),
                    ("sections", "projection-sections"),
                    ("symbols", "projection-symbols"),
                    ("references", "projection-references"),
                ] {
                    push(
                        frontier,
                        &chain,
                        member,
                        Some(leaf),
                        "projection-sequences",
                        &value["manifest"][key],
                    )?;
                }
                push(
                    frontier,
                    &chain,
                    member,
                    Some("index-documents"),
                    "projection-sequences",
                    &value["index_membership"],
                )?;
            }
        }
        "projection-sequences" => {
            if let Some(children) = value["children"].as_array() {
                if children.len() > 128 || value.get("values").is_some() {
                    return Err(invalid());
                }
                for child in children.iter().rev() {
                    push(
                        frontier,
                        &chain,
                        member,
                        frame.leaf.as_deref(),
                        "projection-sequences",
                        child,
                    )?;
                }
            } else if let Some(values) = value["values"].as_array() {
                if values.len() > 128 {
                    return Err(invalid());
                }
                let leaf = frame.leaf.as_deref().ok_or_else(invalid)?;
                for child in values.iter().rev() {
                    push(frontier, &chain, member, None, leaf, child)?;
                }
            } else {
                return Err(invalid());
            }
        }
        "projection-sections" | "projection-symbols" if value["text"].is_string() => {
            push(
                frontier,
                &chain,
                member,
                Some("projection-chunks"),
                "projection-sequences",
                &value["text"],
            )?;
        }
        _ => {}
    }
    if let Some(member) = member {
        let witness = Witness {
            version: 1,
            provider: provider.into(),
            chain,
            member,
        };
        let source = verify_witness(conn, &witness, charge).await?;
        return target(witness, source).map(Some);
    }
    Ok(None)
}

impl PgBlobStore {
    pub(super) async fn sweep_attribution_origins(
        &self,
        provider: &str,
    ) -> Result<Vec<AttributionTarget>> {
        if !supports(provider) {
            return Ok(Vec::new());
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.sweep_attribution_origins_inner(provider),
        )
        .await
        .map_err(|_| Error::capacity("Attribution origin sweep deadline exceeded."))?
    }
    async fn sweep_attribution_origins_inner(
        &self,
        provider: &str,
    ) -> Result<Vec<AttributionTarget>> {
        self.owner_fence().await?;
        let mut owner = self.owner.lock().await;
        verify_control(&mut owner).await?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx_core::raw_sql::raw_sql(
            "SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='250ms'",
        )
        .execute(&mut *tx)
        .await
        .map_err(source_error)?;
        let row = sqlx_core::query::query("SELECT data,data_integrity FROM devres_attribution_origins WHERE provider=$1 FOR UPDATE")
            .bind(provider).fetch_optional(&mut *tx).await.map_err(source_error)?;
        let mut checkpoint: Checkpoint = match row {
            Some(row) => {
                serde_json::from_value(checked(TABLE, provider, &row)?).map_err(|_| invalid())?
            }
            None => Checkpoint {
                version: 1,
                policy_epoch: ATTRIBUTION_POLICY_EPOCH,
                policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
                recipe: "forward-origins-v2".into(),
                ..Default::default()
            },
        };
        validate_checkpoint(&checkpoint)?;
        let table = table(provider)?;
        if checkpoint.cutoff.is_none() {
            let sql =
                format!("SELECT COALESCE(max(sequence),0) FROM {table} WHERE kind='snapshots'");
            checkpoint.cutoff = Some(
                sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(sql))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(source_error)?,
            );
        }
        let started = std::time::Instant::now();
        let mut output = Vec::new();
        let mut inserted = Vec::new();
        let mut charge = 0;
        for _ in 0..PAGE_STEPS {
            if started.elapsed() >= std::time::Duration::from_secs(1) {
                break;
            }
            if checkpoint.frontier.is_empty() {
                let sql = format!(
                    "SELECT sequence,key FROM {table} WHERE kind='snapshots' AND sequence>$1 AND sequence<=$2 ORDER BY sequence LIMIT 1"
                );
                let next: Option<(i64, String)> =
                    sqlx_core::query_as::query_as(sqlx_core::sql_str::AssertSqlSafe(sql))
                        .bind(checkpoint.after)
                        .bind(checkpoint.cutoff)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(source_error)?;
                let Some((sequence, key)) = next else {
                    checkpoint.after = 0;
                    checkpoint.cutoff = None;
                    checkpoint.passes = checkpoint.passes.saturating_add(1);
                    break;
                };
                checkpoint.after = sequence;
                checkpoint.frontier.push(Frame {
                    kind: "snapshots".into(),
                    key,
                    ancestors: Vec::new(),
                    member: None,
                    leaf: None,
                });
            }
            let frame = checkpoint.frontier.pop().ok_or_else(invalid)?;
            let original_frontier = checkpoint.frontier.clone();
            let before_charge = charge;
            let result = step(
                &mut tx,
                provider,
                frame.clone(),
                &mut checkpoint.frontier,
                &mut charge,
            )
            .await;
            if before_charge > 0
                && result.as_ref().is_err_and(|error| {
                    error.code == "capacity"
                        && error.message == "Attribution origin traversal exceeds its byte bound."
                })
            {
                checkpoint.frontier = original_frontier;
                checkpoint.frontier.push(frame);
                break;
            }
            match result {
                Ok(Some(target)) => {
                    if enqueue_initial(&mut tx, &target, 0, false).await? {
                        inserted.push(false);
                    }
                    output.push(target);
                    checkpoint.gap = None;
                }
                Ok(None) => {
                    checkpoint.gap = None;
                }
                Err(error)
                    if matches!(
                        error.code.as_str(),
                        "attribution_origin_missing" | "integrity" | "invalid"
                    ) || (error.code == "capacity"
                        && error.message.starts_with("Attribution origin"))
                        || AttributionFailure::from_error(&error).is_some_and(|failure| {
                            failure.disposition == AttributionDisposition::Blocked
                        }) =>
                {
                    // Retain a blocked gap for this exact occurrence and continue
                    // other roots. SQL admission failures roll back the whole page.
                    checkpoint.frontier = original_frontier;
                    let classification =
                        AttributionFailure::from_error(&error).unwrap_or_else(|| {
                            AttributionFailure::new(
                                AttributionPhase::Mapping,
                                match error.code.as_str() {
                                    "capacity" => AttributionFailureReason::PayloadBound,
                                    "integrity" | "invalid" => {
                                        AttributionFailureReason::InvalidEvidence
                                    }
                                    _ => AttributionFailureReason::UnsupportedSource,
                                },
                                AttributionDisposition::Blocked,
                            )
                        });
                    checkpoint.gap = Some(classification);
                    let evidence = json!({"version":2,"origin_gap":{"provider":provider,"frame":frame,"classification":classification}});
                    let fingerprint = crate::integrity::canonical_hash(&evidence)?;
                    let target = AttributionTarget {
                        subject: AttributionSubject {
                            provider: provider.into(),
                            namespace: "origin-gap".into(),
                            key: fingerprint.clone(),
                            fingerprint,
                        },
                        evidence,
                    };
                    if enqueue_initial(&mut tx, &target, 0, false).await? {
                        let mut state = State::new(target.clone(), 0);
                        state.status = "blocked".into();
                        state.failure = Some("attribution_blocked".into());
                        state.classification = Some(classification);
                        save(&mut tx, &state).await?;
                        inserted.push(true);
                    }
                    output.push(target);
                }
                Err(error) => return Err(error),
            }
        }
        validate_checkpoint(&checkpoint)?;
        let data = bounded(&checkpoint)?;
        sqlx_core::query::query("INSERT INTO devres_attribution_origins(provider,data,data_integrity) VALUES($1,$2,$3) ON CONFLICT(provider) DO UPDATE SET data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity")
            .bind(provider).bind(Json(&data)).bind(payload_integrity::digest(TABLE,"",provider,&data)?).execute(&mut *tx).await.map_err(source_error)?;
        self.fence().await?;
        tx.commit().await.map_err(|_| storage_error())?;
        for blocked in inserted {
            self.record_attribution(provider, "enqueued");
            if blocked {
                self.record_attribution(provider, "blocked");
            }
        }
        Ok(output)
    }

    pub(super) async fn verify_attribution_origins(&self) -> Result<()> {
        self.attribution_origin_status().await?;
        Ok(())
    }
    pub(super) async fn attribution_origin_status(&self) -> Result<Vec<Value>> {
        let rows = sqlx_core::query::query("SELECT provider,data,data_integrity FROM devres_attribution_origins ORDER BY provider LIMIT 5").fetch_all(&self.pool).await.map_err(|_| storage_error())?;
        let mut output = Vec::new();
        for row in rows {
            let provider: String = row.try_get("provider").map_err(|_| invalid())?;
            if !supports(&provider) {
                return Err(invalid());
            }
            let value: Checkpoint =
                serde_json::from_value(checked(TABLE, &provider, &row)?).map_err(|_| invalid())?;
            validate_checkpoint(&value)?;
            output.push(json!({"provider":provider,"policy_epoch":value.policy_epoch,"recipe":value.recipe,"completed_passes":value.passes,"pending_frames":value.frontier.len(),"gap":value.gap}));
        }
        Ok(output)
    }

    #[cfg(test)]
    pub(crate) async fn seed_attribution_origins_fixture(&self) -> Value {
        let mut selected = Vec::new();
        for provider in ["mdn", "whatwg", "w3c", "chromium"] {
            let mut target = None;
            for _ in 0..64 {
                let output = self.sweep_attribution_origins(provider).await.unwrap();
                if let Some(found) = output
                    .into_iter()
                    .find(|value| value.evidence.get("origin_witness").is_some())
                {
                    target = Some(found);
                    break;
                }
            }
            let target = target.unwrap_or_else(|| {
                panic!("first-party {provider} corpus fixture needs a retained snapshot/member")
            });
            self.attribution_verify_target(&target).await.unwrap();
            self.attribution_enqueue(&target, 1).await.unwrap();
            let mut completed = false;
            for _ in 0..256 {
                let job = self
                    .attribution_claim(&[provider.into()], devres_domain::unix_now(), 0)
                    .await
                    .unwrap()
                    .unwrap();
                if job.target == target {
                    self.attribution_complete(&job, &tests::generation(&target))
                        .await
                        .unwrap();
                    completed = true;
                    break;
                }
                // Disposable first-party fixtures only: leave unrelated work
                // queued for its normal owner rather than fabricate its proof.
                let disposition = AttributionFailure::new(
                    AttributionPhase::Scheduling,
                    AttributionFailureReason::AdmissionDeferred,
                    AttributionDisposition::Retry,
                );
                self.attribution_fail_classified(
                    &job,
                    Some(devres_domain::unix_now() + 60),
                    "retryable",
                    &disposition,
                )
                .await
                .unwrap();
            }
            assert!(completed, "selected fixture claim must be admitted");
            let source: AttributionTarget =
                serde_json::from_value(target.evidence["source_target"].clone()).unwrap();
            let ready = self
                .attribution_ready(&source.subject)
                .await
                .unwrap()
                .unwrap();
            selected.push(json!({"target":target,"qualified":ready}));
        }
        json!({"version":1,"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"selected":selected})
    }

    #[cfg(test)]
    pub(crate) async fn readback_attribution_origins_fixture(&self, receipt: &Value) {
        assert_eq!(receipt["policy_epoch"], ATTRIBUTION_POLICY_EPOCH);
        let selected = receipt["selected"].as_array().unwrap();
        assert_eq!(selected.len(), 4);
        for value in selected {
            let target: AttributionTarget =
                serde_json::from_value(value["target"].clone()).unwrap();
            self.attribution_verify_target(&target).await.unwrap();
            let source: AttributionTarget =
                serde_json::from_value(target.evidence["source_target"].clone()).unwrap();
            let expected: QualifiedAttribution =
                serde_json::from_value(value["qualified"].clone()).unwrap();
            assert_eq!(
                self.attribution_ready(&source.subject)
                    .await
                    .unwrap()
                    .unwrap(),
                expected
            );
        }
        self.verify_attribution_storage(&CancellationToken::new())
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn put(store: &PgBlobStore, provider: &str, kind: &str, key: &str, data: &Value) {
        match provider {
            "mdn" => devres_application::mdn::MdnStore::mdn_put(store, kind, key, data)
                .await
                .unwrap(),
            "whatwg" => devres_application::whatwg::WhatwgStore::whatwg_put(store, kind, key, data)
                .await
                .unwrap(),
            "w3c" => devres_application::w3c::W3cStore::w3c_put(store, kind, key, data)
                .await
                .unwrap(),
            "chromium" => {
                devres_application::chromium::ChromiumStore::chromium_put(store, kind, key, data)
                    .await
                    .unwrap()
            }
            _ => panic!("unsupported fixture provider"),
        };
    }
    fn json_id(value: &Value) -> String {
        crate::integrity::hash(&serde_json::to_vec(value).unwrap())
    }

    async fn fixture(store: &PgBlobStore, provider: &str, label: &str, revision: char) -> String {
        let chunk = json!(
            "First-party origin witness fixture; shared bytes never imply shared provenance."
        );
        let chunk_id = json_id(&chunk);
        put(store, provider, "projection-chunks", &chunk_id, &chunk).await;
        let sequence = json!({"values":[chunk_id]});
        let sequence_id = json_id(&sequence);
        put(
            store,
            provider,
            "projection-sequences",
            &sequence_id,
            &sequence,
        )
        .await;
        let empty = json!({"values":[]});
        let empty_id = json_id(&empty);
        put(store, provider, "projection-sequences", &empty_id, &empty).await;
        let projection = if provider == "mdn" {
            json!({"slug":"Fixture","redirects":[],"source_path":"files/en-us/fixture/index.md"})
        } else {
            json!({"manifest":{"text":sequence_id,"sections":empty_id,"symbols":empty_id,"references":empty_id},"index_membership":empty_id})
        };
        let projection_id = json_id(&projection);
        put(store, provider, "projections", &projection_id, &projection).await;
        if provider == "mdn" {
            put(
                store,
                provider,
                "projection-headers",
                &projection_id,
                &json!({"slug":"Fixture","redirects":[]}),
            )
            .await;
        }
        let revision = revision.to_string().repeat(40);
        let path = if provider == "mdn" {
            "files/en-us/fixture/index.md"
        } else {
            "fixture.md"
        };
        let source_url = match provider {
            "mdn" => format!("https://github.com/mdn/content/blob/{revision}/{path}"),
            "whatwg" => format!("https://github.com/whatwg/fetch/tree/{revision}"),
            "w3c" => format!("https://github.com/w3c/csswg-drafts/blob/{revision}/{path}"),
            _ => format!("https://chromium.googlesource.com/chromium/src/+/{revision}/{path}"),
        };
        let member = devres_application::whatwg::Member {
            path: path.into(),
            oid: "b".repeat(40),
            mode: "100644".into(),
            kind: "document".into(),
            projection: Some(projection_id),
            raw: Some(
                json!({"source_path":path,"source_url":source_url,"license":{"decision":"approved","notice_path":"LICENSE"}}),
            ),
            gaps: Vec::new(),
        };
        let node = devres_application::whatwg::InventoryNode {
            member: Some(member),
            members: 1,
            searchable: 1,
            ..Default::default()
        };
        let node_id = crate::integrity::hash(&serde_json::to_vec(&node).unwrap());
        put(
            store,
            provider,
            "nodes",
            &node_id,
            &serde_json::to_value(node).unwrap(),
        )
        .await;
        let id = crate::integrity::hash(label.as_bytes());
        let snapshot = json!({"id":id,"standard":"fetch","component":"src","repository":if provider == "mdn" {"content"} else {"whatwg/fetch"},"revision":revision,"tree":"c".repeat(40),"parents":[],"committed_at":0,"inventory":node_id,"processor_version":1,"index":{},"coverage":{"license":{"decision":"approved","notice_path":"LICENSE"}},"source_url":source_url,"representation":"git","validated_at":0});
        put(store, provider, "snapshots", &id, &snapshot).await;
        id
    }

    pub(super) fn generation(target: &AttributionTarget) -> AttributionGeneration {
        let source: AttributionTarget =
            serde_json::from_value(target.evidence["source_target"].clone()).unwrap();
        AttributionGeneration {
            subject: target.subject.clone(),
            policy_epoch: ATTRIBUTION_POLICY_EPOCH,
            policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
            notices: vec![AttributionNotice {
                source_url: source.evidence["source"]["source_url"]
                    .as_str()
                    .unwrap()
                    .into(),
                license: Some("fixture-only".into()),
                copyright: None,
                text: "First-party origin witness fixture notice. UTF-8 원문.".into(),
                evidence: json!({"synthetic":true}),
            }],
            receipts: vec![
                json!({"kind":"synthetic_fixture_validation","synthetic":true,"status":200,"source_url":source.evidence["source"]["source_url"],"body_hash":crate::integrity::hash(b"first-party-origin-fixture"),"source_fingerprint":source.subject.fingerprint,"validated_at":devres_domain::unix_now(),"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT}),
                json!({"kind":"retained_subject_binding","source_target":source,"retained_subject":target.subject}),
            ],
        }
    }

    #[test]
    fn origin_edges_do_not_accept_equal_ids_in_unrelated_fields() {
        let parent = Reference {
            kind: "nodes".into(),
            key: "parent".into(),
            digest: crate::integrity::hash(b"parent"),
        };
        let child = Reference {
            kind: "projections".into(),
            key: "projection".into(),
            digest: crate::integrity::hash(b"child"),
        };
        assert!(
            edge(
                &parent,
                &json!({"unrelated":"projection","member":{"projection":"other"}}),
                &child,
                &Value::Null
            )
            .is_err()
        );
        assert!(
            edge(
                &parent,
                &json!({"member":{"projection":"projection"}}),
                &child,
                &Value::Null
            )
            .is_ok()
        );
    }

    #[tokio::test]
    #[ignore = "requires disposable DEVRES_TEST_DATABASE_URL PostgreSQL"]
    async fn attribution_storage_origins_preserve_context_resume_and_reject_forged_edges() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        let name = format!("devres_origins_{}", std::process::id());
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "CREATE DATABASE {name}"
        )))
        .execute(&admin)
        .await
        .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&name);
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        for provider in ["mdn", "whatwg", "w3c", "chromium"] {
            fixture(&store, provider, &format!("origin-{provider}"), 'a').await;
        }
        fixture(&store, "whatwg", "origin-whatwg-second", 'd').await;
        let mut targets = Vec::new();
        for provider in ["mdn", "whatwg", "w3c", "chromium"] {
            for _ in 0..4 {
                targets.extend(store.sweep_attribution_origins(provider).await.unwrap());
            }
        }
        for provider in ["mdn", "whatwg", "w3c", "chromium"] {
            assert!(
                targets
                    .iter()
                    .any(|target| target.subject.provider == provider
                        && target.evidence.get("origin_witness").is_some()),
                "missing {provider} witness"
            );
        }
        let chunks: Vec<_> = targets
            .iter()
            .filter(|target| {
                target.subject.provider == "whatwg"
                    && target.evidence["origin_witness"]["chain"]
                        .as_array()
                        .is_some_and(|chain| chain.last().unwrap()["kind"] == "projection-chunks")
            })
            .collect();
        assert!(chunks.len() >= 2);
        assert_ne!(chunks[0].subject, chunks[1].subject);
        assert_ne!(
            chunks[0].evidence["source_target"],
            chunks[1].evidence["source_target"]
        );
        for target in &targets {
            if target.evidence.get("origin_witness").is_some() {
                store.attribution_verify_target(target).await.unwrap();
            }
        }
        let first = chunks[0].clone();
        let mut forged = first.clone();
        forged.evidence["source_target"] = chunks[1].evidence["source_target"].clone();
        forged.subject.fingerprint = crate::integrity::canonical_hash(&forged.evidence).unwrap();
        assert!(store.attribution_verify_target(&forged).await.is_err());
        let mut nested = forged.clone();
        nested.evidence = json!({"version":2,"dependencies":[forged]});
        nested.subject.fingerprint = crate::integrity::canonical_hash(&nested.evidence).unwrap();
        assert!(store.attribution_verify_target(&nested).await.is_err());
        let now = devres_domain::unix_now();
        for _ in 0..targets.len() + 8 {
            let Some(job) = store
                .attribution_claim(
                    &[
                        "mdn".into(),
                        "whatwg".into(),
                        "w3c".into(),
                        "chromium".into(),
                    ],
                    now,
                    0,
                )
                .await
                .unwrap()
            else {
                break;
            };
            assert!(job.target.evidence.get("origin_witness").is_some());
            store
                .attribution_complete(&job, &generation(&job.target))
                .await
                .unwrap();
        }
        let source: AttributionTarget =
            serde_json::from_value(first.evidence["source_target"].clone()).unwrap();
        let mut boundary = source.clone();
        boundary.evidence = json!({"version":2,"dependencies":vec![source.clone();128]});
        boundary.subject.fingerprint =
            crate::integrity::canonical_hash(&boundary.evidence).unwrap();
        store.attribution_verify_target(&boundary).await.unwrap();
        boundary.evidence["dependencies"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::to_value(&source).unwrap());
        boundary.subject.fingerprint =
            crate::integrity::canonical_hash(&boundary.evidence).unwrap();
        assert!(store.attribution_verify_target(&boundary).await.is_err());
        assert!(
            store
                .attribution_ready(&source.subject)
                .await
                .unwrap()
                .is_some()
        );
        store
            .verify_attribution_storage(&CancellationToken::new())
            .await
            .unwrap();
        let checkpoint: Json<Value> = sqlx_core::query_scalar::query_scalar(
            "SELECT data FROM devres_attribution_origins WHERE provider='whatwg'",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(checkpoint.0["policy_epoch"], 2);
        drop(store);
        let store = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        store
            .verify_attribution_storage(&CancellationToken::new())
            .await
            .unwrap();
        assert!(
            store
                .attribution_ready(&source.subject)
                .await
                .unwrap()
                .is_some()
        );
        drop(store);
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP DATABASE {name} WITH (FORCE)"
        )))
        .execute(&admin)
        .await
        .unwrap();
    }
}
