//! Foreground selection validates full captures without retaining release history.
use super::{
    JsonBudget, MAX_METADATA, Seed, check_json_input, parse_version, unpublished_time,
    validate_name, validate_release,
};
use devres_domain::{Error, Result};
use serde::de::{self, DeserializeSeed, MapAccess, Visitor};
use serde_json::{Map, Value, json, value::RawValue};
use std::{
    cell::Cell,
    collections::HashSet,
    fmt,
    time::{Duration, Instant},
};

struct Selection<'a> {
    name: &'a str,
    requested: &'a str,
    normalized: String,
    budget: JsonBudget,
}

impl Selection<'_> {
    fn key<E: de::Error>(
        &self,
        keys: &mut HashSet<String>,
        key: String,
    ) -> std::result::Result<(), E> {
        if keys.contains(&key) {
            return Err(E::custom("duplicate npm JSON key"));
        }
        if keys.len() >= 50_000 {
            self.budget.limited.set(true);
            return Err(E::custom("npm JSON object bound exceeded"));
        }
        // Includes both key storage and hash-table overhead. These keys remain
        // charged while later releases are parsed, as does the selected release.
        self.budget.charge::<E>(key.len().saturating_add(128))?;
        keys.insert(key);
        Ok(())
    }

    fn value<E: de::Error>(&self, raw: &RawValue) -> std::result::Result<Value, E> {
        // The existing node bound protects each materialized value. A complete
        // document scan instead remains bounded by bytes, depth and one deadline.
        self.budget.nodes.set(0);
        let mut decoder = serde_json::Deserializer::from_str(raw.get());
        let node = Seed(&self.budget)
            .deserialize(&mut decoder)
            .map_err(E::custom)?;
        decoder.end().map_err(E::custom)?;
        Ok(node.value)
    }
}

struct Versions<'a>(&'a Selection<'a>);
impl<'de> DeserializeSeed<'de> for Versions<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<Value, D::Error> {
        decoder.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for Versions<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("npm release inventory")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut keys = HashSet::new();
        let mut selected = Map::new();
        while let Some(version) = map.next_key::<String>()? {
            self.0.key::<A::Error>(&mut keys, version.clone())?;
            let retained = self.0.budget.expanded.get();
            let raw = map.next_value::<&'de RawValue>()?;
            let record = self.0.value::<A::Error>(raw)?;
            validate_release(self.0.name, &version, &record).map_err(de::Error::custom)?;
            if version == self.0.requested || version == self.0.normalized {
                selected.insert(version, record);
            } else {
                drop(record);
                self.0.budget.expanded.set(retained);
            }
        }
        // The inventory key set is gone; keep its conservative charge until the
        // outer scan finishes so nested allocations can never evade the ceiling.
        Ok(Value::Object(selected))
    }
}

struct Packument<'a>(&'a Selection<'a>);
impl<'de> Visitor<'de> for Packument<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("full npm package metadata")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut keys = HashSet::new();
        let mut document = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            self.0.key::<A::Error>(&mut keys, key.clone())?;
            if key == "versions" {
                document.insert(key, map.next_value_seed(Versions(self.0))?);
                continue;
            }
            let retained = self.0.budget.expanded.get();
            let raw = map.next_value::<&'de RawValue>()?;
            let mut value = self.0.value::<A::Error>(raw)?;
            match key.as_str() {
                "name" | "dist-tags" => {
                    document.insert(key, value);
                }
                "time" => {
                    if let Some(times) = value.as_object_mut() {
                        times.retain(|key, _| {
                            matches!(key.as_str(), "created" | "modified" | "unpublished")
                                || key == self.0.requested
                                || *key == self.0.normalized
                        });
                    }
                    document.insert(key, value);
                }
                _ => {
                    drop(value);
                    self.0.budget.expanded.set(retained);
                }
            }
        }
        if document.get("name").and_then(Value::as_str) != Some(self.0.name) {
            return Err(de::Error::custom("npm metadata package identity mismatch"));
        }
        if !document.contains_key("versions") {
            if !document
                .get("time")
                .and_then(|v| v.get("unpublished"))
                .filter(|v| v.is_object())
                .and_then(|v| v["time"].as_str())
                .is_some_and(unpublished_time)
            {
                return Err(de::Error::custom(
                    "npm version inventory and qualified unpublish evidence are absent",
                ));
            }
            document.insert("versions".into(), json!({}));
        }
        if document.get("dist-tags").is_some_and(|tags| {
            !tags
                .as_object()
                .is_some_and(|tags| tags.values().all(Value::is_string))
        }) {
            return Err(de::Error::custom("Malformed npm dist-tag declarations"));
        }
        Ok(Value::Object(document))
    }
}

pub(crate) fn select_packument(bytes: &[u8], name: &str, version: &str) -> Result<Value> {
    select_before(
        bytes,
        name,
        version,
        Instant::now() + Duration::from_secs(15),
        true,
    )
}

/// Source identities hash the existing distribution representation. Keep that
/// numeric representation while using the same bounded complete-document scan.
pub(crate) fn select_source_packument(bytes: &[u8], name: &str, version: &str) -> Result<Value> {
    select_before(
        bytes,
        name,
        version,
        Instant::now() + Duration::from_secs(15),
        false,
    )
}

fn select_before(
    bytes: &[u8],
    name: &str,
    version: &str,
    deadline: Instant,
    canonical_numbers: bool,
) -> Result<Value> {
    validate_name(name)?;
    let normalized = parse_version(version)?.to_string();
    check_json_input(bytes, MAX_METADATA, deadline)?;
    let selection = Selection {
        name,
        requested: version,
        normalized,
        budget: JsonBudget {
            nodes: Cell::new(0),
            expanded: Cell::new(0),
            limited: Cell::new(false),
            deadline,
            ordered: false,
            canonical_numbers,
        },
    };
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value =
        de::Deserializer::deserialize_map(&mut decoder, Packument(&selection)).map_err(|_| {
            if selection.budget.limited.get() {
                Error::capacity("npm JSON aggregate node, expansion or time budget exceeded.")
            } else {
                Error::integrity("Malformed, duplicate-key or inconsistent npm metadata.")
            }
        })?;
    decoder
        .end()
        .map_err(|_| Error::integrity("Trailing data after npm JSON."))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_includes_scanning_the_complete_input() {
        assert_eq!(
            select_before(
                br#"{"name":"fixture","versions":{}}"#,
                "fixture",
                "1.0.0",
                Instant::now() - Duration::from_secs(1),
                true,
            )
            .unwrap_err()
            .code,
            "capacity"
        );
    }

    #[test]
    fn complete_metadata_validation_does_not_skip_unselected_fields() {
        for bytes in [
            br#"{"name":"fixture","name":"fixture","versions":{}}"#.as_slice(),
            br#"{"name":"fixture","versions":{"1.0.0":{"name":"fixture","version":"1.0.0"},"1.0.0":{"name":"fixture","version":"1.0.0"}}}"#,
            br#"{"name":"fixture","versions":{"2.0.0":{"name":"fixture","version":"2.0.0","extra":{"key":1,"key":2}}}}"#,
            br#"{"name":"fixture","versions":{},"other":{"key":1,"key":2}}"#,
            br#"{"name":"fixture","versions":{},"dist-tags":{"latest":1}}"#,
            br#"{"name":"fixture","time":{"unpublished":{"time":"bad"}}}"#,
            br#"{"name":"fixture","versions":[]}"#,
            br#"{"name":"fixture","versions":{}} trailing"#,
        ] {
            assert_eq!(select_packument(bytes, "fixture", "1.0.0").unwrap_err().code, "integrity");
        }
        let deep = format!(
            "{{\"name\":\"fixture\",\"versions\":{{}},\"extra\":{}0{}}}",
            "[".repeat(64),
            "]".repeat(64)
        );
        assert_eq!(
            select_packument(deep.as_bytes(), "fixture", "1.0.0")
                .unwrap_err()
                .code,
            "capacity"
        );
        let oversized = vec![b' '; MAX_METADATA + 1];
        assert_eq!(
            select_packument(&oversized, "fixture", "1.0.0")
                .unwrap_err()
                .code,
            "capacity"
        );
    }

    #[test]
    fn historical_spelling_and_unpublish_tombstones_remain_supported() {
        let bytes = br#"{"name":"fixture","versions":{"v1.0.0":{"name":"fixture","version":"v1.0.0"},"1.0.0":{"name":"fixture","version":"1.0.0"}},"time":{"v1.0.0":"exact","1.0.0":"normalized","other":"omitted"}}"#;
        let selected = select_packument(bytes, "fixture", "v1.0.0").unwrap();
        assert_eq!(selected["versions"]["v1.0.0"]["version"], "v1.0.0");
        assert_eq!(selected["versions"]["1.0.0"]["version"], "1.0.0");
        assert!(selected["time"].get("other").is_none());
        let unpublished = select_packument(br#"{"name":"fixture","time":{"unpublished":{"time":"2026-10-27T12:00:00.000Z","versions":["1.0.0"]}}}"#,"fixture","1.0.0").unwrap();
        assert_eq!(unpublished["versions"], json!({}));
    }

    #[test]
    fn root_key_capacity_and_duplicate_integrity_remain_distinct() {
        let fields = (0..49_998)
            .map(|index| format!("\"field-{index}\":0"))
            .collect::<Vec<_>>()
            .join(",");
        let root = format!("{{\"name\":\"fixture\",\"versions\":{{}},{fields}");
        let excessive = format!("{root},\"another\":0,\"last\":0}}");
        assert!(excessive.len() < MAX_METADATA);
        assert_eq!(
            select_packument(excessive.as_bytes(), "fixture", "1.0.0")
                .unwrap_err()
                .code,
            "capacity"
        );
        // Duplicate evidence remains invalid even when the set is already full.
        let duplicate = format!("{root},\"field-0\":0}}");
        assert_eq!(
            select_packument(duplicate.as_bytes(), "fixture", "1.0.0")
                .unwrap_err()
                .code,
            "integrity"
        );
    }
}
