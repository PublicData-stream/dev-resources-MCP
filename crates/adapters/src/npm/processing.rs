//! Bounded, inert processing of public npm metadata and published packages.
//! No package is extracted, loaded, resolved, or executed.
use base64::{Engine, engine::general_purpose::STANDARD};
use devres_domain::{Error, Result};
use semver::Version;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{
    collections::HashSet,
    fmt,
    io::{self, Read, Seek, SeekFrom},
    time::{Duration, Instant},
};

pub const MAX_METADATA: usize = 16 * 1024 * 1024;
pub const MAX_ARCHIVE: usize = 32 * 1024 * 1024;
pub const MAX_DOCUMENT: usize = 4 * 1024 * 1024;
const MAX_EXPANDED: u64 = 256 * 1024 * 1024;
const MAX_MEMBERS: usize = 20_000;
const MAX_PROJECTED: usize = 64 * 1024 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const PROCESSOR_VERSION: u32 = 1;

pub fn validate_name(name: &str) -> Result<()> {
    let components: Vec<_> = if let Some(scoped) = name.strip_prefix('@') {
        scoped.split('/').collect()
    } else {
        vec![name]
    };
    if name.is_empty()
        || name.len() > 214
        || (name.starts_with('@') && components.len() != 2)
        || components.iter().any(|part| {
            part.is_empty()
                || part.starts_with(['.', '_'])
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
    {
        return Err(Error::invalid("Invalid public npm package name."));
    }
    Ok(())
}

/// Exact node-semver spelling only; dependency requirements remain inert strings.
pub fn parse_version(value: &str) -> Result<Version> {
    if value.is_empty() || value.len() > 256 || value.trim() != value {
        return Err(Error::invalid("An exact npm version is required."));
    }
    let normalized = value
        .strip_prefix('v')
        .or_else(|| value.strip_prefix('='))
        .unwrap_or(value);
    let parsed = Version::parse(normalized)
        .map_err(|_| Error::invalid("An exact npm semantic version is required."))?;
    if [parsed.major, parsed.minor, parsed.patch]
        .iter()
        .any(|n| *n > MAX_SAFE_INTEGER)
        || parsed.pre.as_str().split('.').any(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && part.parse::<u64>().map_or(true, |n| n > MAX_SAFE_INTEGER)
        })
    {
        return Err(Error::invalid(
            "npm version exceeds supported numeric bounds.",
        ));
    }
    Ok(parsed)
}

// Preserve declaration object order explicitly, while rejecting duplicate JSON keys.
// In particular, conditional exports order must not become BTreeMap key order.
struct Node {
    value: Value,
    ordered: Value,
}
struct JsonBudget {
    nodes: std::cell::Cell<usize>,
    expanded: std::cell::Cell<usize>,
    limited: std::cell::Cell<bool>,
    deadline: Instant,
    ordered: bool,
}
impl JsonBudget {
    fn charge<E: de::Error>(&self, bytes: usize) -> std::result::Result<(), E> {
        let expanded = self.expanded.get().saturating_add(bytes);
        self.expanded.set(expanded);
        if expanded > 64 * 1024 * 1024
            || self.nodes.get() > 200_000
            || Instant::now() > self.deadline
        {
            self.limited.set(true);
            return Err(E::custom("npm JSON aggregate processing bound"));
        }
        Ok(())
    }
    fn node(&self, value: Value) -> Node {
        Node {
            ordered: if self.ordered {
                value.clone()
            } else {
                Value::Null
            },
            value,
        }
    }
}
struct Seed<'a>(&'a JsonBudget);
impl<'de> de::DeserializeSeed<'de> for Seed<'_> {
    type Value = Node;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Node, D::Error> {
        self.0.nodes.set(self.0.nodes.get().saturating_add(1));
        self.0.charge::<D::Error>(128)?;
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Node;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded npm JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Node, E> {
        Ok(self.0.node(json!(v)))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Node, E> {
        Ok(self.0.node(json!(v)))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Node, E> {
        Ok(self.0.node(json!(v)))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Node, E> {
        serde_json::Number::from_f64(v)
            .map(|n| self.0.node(Value::Number(n)))
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Node, E> {
        self.0
            .charge::<E>(v.len().saturating_mul(if self.0.ordered { 2 } else { 1 }))?;
        Ok(self.0.node(json!(v)))
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Node, E> {
        self.0
            .charge::<E>(v.len().saturating_mul(if self.0.ordered { 2 } else { 1 }))?;
        Ok(self.0.node(Value::String(v)))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Node, E> {
        Ok(self.0.node(Value::Null))
    }
    fn visit_none<E: de::Error>(self) -> std::result::Result<Node, E> {
        Ok(self.0.node(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Node, A::Error> {
        let mut values = Vec::new();
        let mut ordered = Vec::new();
        while let Some(child) = seq.next_element_seed(Seed(self.0))? {
            if values.len() >= 50_000 {
                return Err(de::Error::custom("npm JSON array bound"));
            }
            values.push(child.value);
            if self.0.ordered {
                self.0.charge::<A::Error>(64)?;
                ordered.push(child.ordered);
            }
        }
        Ok(Node {
            value: Value::Array(values),
            ordered: if self.0.ordered {
                json!({"array":ordered})
            } else {
                Value::Null
            },
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Node, A::Error> {
        let mut values = Map::new();
        let mut entries = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.len() >= 50_000 || values.contains_key(&key) {
                return Err(de::Error::custom("npm JSON object bound or duplicate key"));
            }
            self.0.charge::<A::Error>(
                key.len()
                    .saturating_mul(if self.0.ordered { 2 } else { 1 })
                    .saturating_add(if self.0.ordered { 256 } else { 64 }),
            )?;
            let child = map.next_value_seed(Seed(self.0))?;
            if self.0.ordered {
                entries.push(json!({"key":key,"value":child.ordered}));
            }
            values.insert(key, child.value);
        }
        Ok(Node {
            value: Value::Object(values),
            ordered: if self.0.ordered {
                json!({"object":entries})
            } else {
                Value::Null
            },
        })
    }
}

fn decode(bytes: &[u8], max: usize, ordered: bool) -> Result<Node> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(Error::capacity("npm JSON processing bound exceeded."));
    }
    // Reject excess structural nesting before constructing recursive values.
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'[' | b'{' => {
                    depth += 1;
                    if depth > 64 {
                        return Err(Error::capacity("npm JSON nesting exceeds 64 levels."));
                    }
                }
                b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    let budget = JsonBudget {
        nodes: std::cell::Cell::new(0),
        expanded: std::cell::Cell::new(0),
        limited: std::cell::Cell::new(false),
        deadline: Instant::now() + Duration::from_secs(15),
        ordered,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = Seed(&budget).deserialize(&mut deserializer).map_err(|_| {
        if budget.limited.get() {
            Error::capacity("npm JSON aggregate node, expansion or time budget exceeded.")
        } else {
            Error::integrity("Malformed, duplicate-key or excessively nested npm JSON.")
        }
    })?;
    deserializer
        .end()
        .map_err(|_| Error::integrity("Trailing data after npm JSON."))?;
    Ok(value)
}

pub(crate) fn parse_json(bytes: &[u8], max: usize) -> Result<Value> {
    Ok(decode(bytes, max, false)?.value)
}

pub fn parse_packument(bytes: &[u8], name: &str) -> Result<Value> {
    validate_name(name)?;
    let mut document = decode(bytes, MAX_METADATA, false)?.value;
    if document["name"].as_str() != Some(name) {
        return Err(Error::integrity("npm metadata package identity mismatch."));
    }
    if document.get("versions").is_none() {
        // npm can retain only a timestamped unpublish tombstone. Normalize its
        // observed empty inventory while retaining the untouched raw capture.
        let unpublished = document
            .pointer("/time/unpublished")
            .filter(|value| value.is_object());
        let valid = unpublished
            .and_then(|value| value["time"].as_str())
            .is_some_and(unpublished_time);
        if !valid {
            return Err(Error::integrity(
                "npm version inventory and qualified unpublish evidence are absent.",
            ));
        }
        document["versions"] = json!({});
    }
    let versions = document["versions"]
        .as_object()
        .ok_or_else(|| Error::integrity("npm version inventory is absent."))?;
    for (version, record) in versions {
        if version.is_empty()
            || version.len() > 256
            || record["name"].as_str() != Some(name)
            || record["version"].as_str() != Some(version)
        {
            return Err(Error::integrity("npm version manifest identity mismatch."));
        }
        for field in [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ] {
            if let Some(dependencies) = record.get(field)
                && !dependencies
                    .as_object()
                    .is_some_and(|entries| entries.values().all(Value::is_string))
            {
                return Err(Error::integrity("Malformed npm dependency declarations."));
            }
        }
    }
    if document.get("dist-tags").is_some_and(|tags| {
        !tags
            .as_object()
            .is_some_and(|t| t.values().all(Value::is_string))
    }) {
        return Err(Error::integrity("Malformed npm dist-tag declarations."));
    }
    Ok(document)
}

fn unpublished_time(value: &str) -> bool {
    if !value.is_ascii() || value.len() < 20 || value.len() > 64 {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    let number = |start, end| {
        value
            .get(start..end)
            .filter(|v| v.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|v| v.parse::<u32>().ok())
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    let suffix = &value[19..];
    let zone = if let Some(fraction) = suffix.strip_prefix('.') {
        let length = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if length == 0 {
            return false;
        }
        &fraction[length..]
    } else {
        suffix
    };
    let zone_valid = zone == "Z"
        || ((zone.starts_with('+') || zone.starts_with('-'))
            && zone.len() == 6
            && zone.as_bytes()[3] == b':'
            && zone[1..3].parse::<u32>().is_ok_and(|n| n <= 23)
            && zone[4..6].parse::<u32>().is_ok_and(|n| n <= 59));
    year > 0
        && (1..=days).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 59
        && zone_valid
}

/// Verify original compressed bytes. A supplied SRI never falls back to shasum.
pub fn verify_integrity(bytes: &[u8], manifest: &Value) -> Result<Value> {
    integrity_matches(
        manifest,
        &Sha512::digest(bytes),
        &Sha384::digest(bytes),
        &Sha256::digest(bytes),
        &Sha1::digest(bytes),
    )
}

/// Apply the identical SRI policy to digests calculated by a bounded stream reader.
pub fn integrity_matches(
    manifest: &Value,
    sha512: &[u8],
    sha384: &[u8],
    sha256: &[u8],
    sha1: &[u8],
) -> Result<Value> {
    let dist = &manifest["dist"];
    if let Some(integrity) = dist.get("integrity") {
        let integrity = integrity
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 8192)
            .ok_or_else(|| Error::integrity("Invalid npm integrity declaration."))?;
        let mut supported = Vec::new();
        for token in integrity.split_ascii_whitespace() {
            let (algorithm, encoded) = token
                .split_once('-')
                .ok_or_else(|| Error::integrity("Malformed npm integrity token."))?;
            let rank = match algorithm {
                "sha512" => 4,
                "sha384" => 3,
                "sha256" => 2,
                "sha1" => 1,
                _ => 0,
            };
            if rank == 0 {
                continue;
            }
            let encoded = encoded
                .split_once('?')
                .map_or(encoded, |(digest, _)| digest);
            let digest = STANDARD
                .decode(encoded)
                .map_err(|_| Error::integrity("Malformed npm integrity digest."))?;
            let length = match rank {
                4 => 64,
                3 => 48,
                2 => 32,
                _ => 20,
            };
            if digest.len() != length {
                return Err(Error::integrity("Invalid npm integrity digest length."));
            }
            supported.push((rank, algorithm, digest));
        }
        let strongest = supported
            .iter()
            .map(|(rank, _, _)| *rank)
            .max()
            .ok_or_else(|| {
                Error::integrity("npm integrity algorithm is unsupported; no fallback was applied.")
            })?;
        let actual = match strongest {
            4 => sha512,
            3 => sha384,
            2 => sha256,
            _ => sha1,
        };
        if !supported
            .iter()
            .any(|(rank, _, expected)| *rank == strongest && expected.as_slice() == actual)
        {
            return Err(Error::integrity("npm archive integrity mismatch."));
        }
        let algorithm = match strongest {
            4 => "sha512",
            3 => "sha384",
            2 => "sha256",
            _ => "sha1",
        };
        Ok(
            json!({"verified":true,"algorithm":algorithm,"assurance":if strongest==1 {"legacy_sha1"} else {"sri"}}),
        )
    } else {
        let checksum = dist["shasum"]
            .as_str()
            .filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| Error::integrity("npm archive checksum is absent or malformed."))?;
        if !hex::encode(sha1).eq_ignore_ascii_case(checksum) {
            return Err(Error::integrity("npm archive shasum mismatch."));
        }
        Ok(json!({"verified":true,"algorithm":"sha1","assurance":"legacy_sha1"}))
    }
}

#[derive(Clone)]
struct ZipBounds {
    directory: u64,
    eocd: u64,
    zip64: Option<u64>,
    count: u64,
}
fn zip_error() -> Error {
    Error::integrity("Unsupported or malformed npm advisory ZIP metadata.")
}
fn zip_bounds(file: &mut std::fs::File) -> Result<ZipBounds> {
    let length = file.seek(SeekFrom::End(0)).map_err(|_| zip_error())?;
    let tail_length = length.min(65557) as usize;
    file.seek(SeekFrom::End(-(tail_length as i64)))
        .map_err(|_| zip_error())?;
    let mut tail = vec![0; tail_length];
    file.read_exact(&mut tail).map_err(|_| zip_error())?;
    let end = tail
        .windows(4)
        .rposition(|bytes| bytes == b"PK\x05\x06")
        .ok_or_else(zip_error)?;
    if tail.len() < end + 22 {
        return Err(zip_error());
    }
    let u16_at = |offset| -> Result<u64> {
        Ok(u16::from_le_bytes(
            tail.get(end + offset..end + offset + 2)
                .ok_or_else(zip_error)?
                .try_into()
                .map_err(|_| zip_error())?,
        ) as u64)
    };
    let u32_at = |offset| -> Result<u64> {
        Ok(u32::from_le_bytes(
            tail.get(end + offset..end + offset + 4)
                .ok_or_else(zip_error)?
                .try_into()
                .map_err(|_| zip_error())?,
        ) as u64)
    };
    if end + 22 + u16_at(20)? as usize != tail.len()
        || u16_at(4)? != 0
        || u16_at(6)? != 0
        || u16_at(8)? != u16_at(10)?
    {
        return Err(zip_error());
    }
    let eocd = length - tail_length as u64 + end as u64;
    let count32 = u16_at(10)?;
    let size32 = u32_at(12)?;
    let offset32 = u32_at(16)?;
    let has_zip64 =
        count32 == u16::MAX as u64 || size32 == u32::MAX as u64 || offset32 == u32::MAX as u64;
    let (count, size, directory, zip64, footer) = if has_zip64 {
        let locator = eocd.checked_sub(20).ok_or_else(zip_error)?;
        file.seek(SeekFrom::Start(locator))
            .map_err(|_| zip_error())?;
        let mut location = [0; 20];
        file.read_exact(&mut location).map_err(|_| zip_error())?;
        if &location[..4] != b"PK\x06\x07"
            || location[4..8] != [0; 4]
            || u32::from_le_bytes(location[16..20].try_into().map_err(|_| zip_error())?) != 1
        {
            return Err(zip_error());
        }
        let position = u64::from_le_bytes(location[8..16].try_into().map_err(|_| zip_error())?);
        if position > locator.saturating_sub(56) {
            return Err(zip_error());
        }
        file.seek(SeekFrom::Start(position))
            .map_err(|_| zip_error())?;
        let mut record = [0; 56];
        file.read_exact(&mut record).map_err(|_| zip_error())?;
        let field = |offset| -> Result<u64> {
            Ok(u64::from_le_bytes(
                record[offset..offset + 8]
                    .try_into()
                    .map_err(|_| zip_error())?,
            ))
        };
        let record_size = field(4)?;
        if &record[..4] != b"PK\x06\x06"
            || !(44..=44 + 1024 * 1024).contains(&record_size)
            || position
                .checked_add(record_size)
                .and_then(|v| v.checked_add(12))
                != Some(locator)
            || record[16..24] != [0; 8]
            || field(24)? != field(32)?
        {
            return Err(zip_error());
        }
        let count = field(32)?;
        let size = field(40)?;
        let directory = field(48)?;
        if (count32 != u16::MAX as u64 && count32 != count)
            || (size32 != u32::MAX as u64 && size32 != size)
            || (offset32 != u32::MAX as u64 && offset32 != directory)
        {
            return Err(zip_error());
        }
        (count, size, directory, Some(position), position)
    } else {
        (count32, size32, offset32, None, eocd)
    };
    if count > 1_000_000
        || size > 64 * 1024 * 1024
        || directory.checked_add(size) != Some(footer)
        || count.checked_mul(46).is_none_or(|minimum| minimum > size)
    {
        return Err(Error::capacity(
            "npm advisory ZIP directory or member allocation exceeds bounds.",
        ));
    }
    file.rewind().map_err(|_| zip_error())?;
    Ok(ZipBounds {
        directory,
        eocd,
        zip64,
        count,
    })
}

/// Header-only preflight. Consumers must use open_advisory_zip to fence ZIP9
/// fallback while it constructs the central-directory index.
pub fn validate_zip_file(file: &mut std::fs::File) -> Result<()> {
    zip_bounds(file).map(|_| ())
}

/// During indexing, reject every footer except the one whose allocation fields
/// were preflighted. After indexing, reads expose the untouched original bytes.
pub struct AdvisoryZipReader {
    file: std::fs::File,
    bounds: ZipBounds,
    indexing: std::sync::Arc<std::sync::atomic::AtomicBool>,
    remaining: u64,
    deadline: Instant,
}
impl Seek for AdvisoryZipReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}
impl Read for AdvisoryZipReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.indexing.load(std::sync::atomic::Ordering::Acquire) && !buffer.is_empty() {
            let position = self.file.stream_position()?;
            if position < self.bounds.directory.saturating_sub(1024)
                || Instant::now() > self.deadline
                || buffer.len() as u64 > self.remaining
            {
                return Err(io::Error::other(
                    "npm ZIP index read exceeds validated bounds",
                ));
            }
            let mut signature = [0; 4];
            let signature_complete = match self.file.read_exact(&mut signature) {
                Ok(()) => true,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => false,
                Err(error) => return Err(error),
            };
            self.file.seek(SeekFrom::Start(position))?;
            if signature_complete
                && ((signature == *b"PK\x05\x06" && position != self.bounds.eocd)
                    || (signature == *b"PK\x06\x06" && Some(position) != self.bounds.zip64))
            {
                return Err(io::Error::other(
                    "npm ZIP alternative footer is not admitted",
                ));
            }
            self.remaining = self.remaining.saturating_sub(buffer.len() as u64);
        }
        self.file.read(buffer)
    }
}

pub fn open_advisory_zip(mut file: std::fs::File) -> Result<zip::ZipArchive<AdvisoryZipReader>> {
    let bounds = zip_bounds(&mut file)?;
    let count = bounds.count;
    let indexing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let reader = AdvisoryZipReader {
        file,
        bounds,
        indexing: indexing.clone(),
        remaining: 128 * 1024 * 1024,
        deadline: Instant::now() + Duration::from_secs(15),
    };
    let archive = zip::ZipArchive::with_config(
        zip::read::Config {
            archive_offset: zip::read::ArchiveOffset::Known(0),
        },
        reader,
    )
    .map_err(|_| zip_error())?;
    if archive.len() as u64 != count {
        return Err(zip_error());
    }
    indexing.store(false, std::sync::atomic::Ordering::Release);
    Ok(archive)
}

struct BudgetReader<R> {
    inner: R,
    remaining: u64,
    deadline: Instant,
}
impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::other("npm archive deadline"));
        }
        let limit = buf.len().min(self.remaining.saturating_add(1) as usize);
        let count = self.inner.read(&mut buf[..limit])?;
        if count as u64 > self.remaining {
            return Err(io::Error::other("npm archive expansion limit"));
        }
        self.remaining -= count as u64;
        Ok(count)
    }
}
fn invalid_archive() -> Error {
    Error::integrity(
        "Unsafe, malformed or oversized npm archive; raw capture is independent of processing.",
    )
}

/// Full archive inspection precedes publication of every returned projection.
/// One consistent package/ or historical package-basename/ root is admitted;
/// package.json must still identify the exact selected registry name and version.
pub fn inspect_package(bytes: &[u8], manifest: &Value) -> Result<Value> {
    inspect(bytes, manifest, None)
}

/// Selected source reads do not depend on the aggregate corpus projection budget.
/// All archive members and package.json still pass the same complete inspection.
pub fn read_member(bytes: &[u8], manifest: &Value, path: &str) -> Result<Value> {
    if !crate::archive::valid_relative_path(path) {
        return Err(Error::invalid("Invalid npm member path."));
    }
    let projected = inspect(bytes, manifest, Some(path))?;
    projected["documents"]
        .as_array()
        .and_then(|documents| {
            documents
                .iter()
                .find(|document| document["path"].as_str() == Some(path))
        })
        .cloned()
        .ok_or_else(|| {
            Error::not_found("npm source member is absent, binary or outside processing bounds.")
        })
}

fn inspect(bytes: &[u8], manifest: &Value, selected: Option<&str>) -> Result<Value> {
    verify_integrity(bytes, manifest)?;
    let name = manifest["name"]
        .as_str()
        .ok_or_else(|| Error::integrity("npm package name is absent."))?;
    let version = manifest["version"]
        .as_str()
        .ok_or_else(|| Error::integrity("npm version is absent."))?;
    validate_name(name)?;
    parse_version(version)?;
    if bytes.len() > MAX_ARCHIVE {
        return Err(Error::capacity(
            "Raw npm archive retained; source processing exceeds 32 MiB.",
        ));
    }
    let mut reader = BudgetReader {
        inner: flate2::read::MultiGzDecoder::new(bytes),
        remaining: MAX_EXPANDED,
        deadline: Instant::now() + Duration::from_secs(15),
    };
    let mut members = Vec::new();
    let mut documents = Vec::new();
    let mut gaps = Vec::new();
    let mut seen = HashSet::new();
    let mut package = None;
    let historical_root = name.rsplit('/').next().ok_or_else(invalid_archive)?;
    let mut archive_root: Option<String> = None;
    let mut total_projected = 0usize;
    {
        let mut archive = tar::Archive::new(&mut reader);
        for (index, entry) in archive
            .entries()
            .map_err(|_| invalid_archive())?
            .enumerate()
        {
            if index >= MAX_MEMBERS {
                return Err(Error::capacity("npm archive member count exceeds limit."));
            }
            let mut entry = entry.map_err(|_| invalid_archive())?;
            let kind = entry.header().entry_type();
            if !kind.is_file() && !kind.is_dir() {
                return Err(Error::integrity(
                    "npm archive links and special members are unsupported.",
                ));
            }
            let raw = entry.path_bytes();
            if kind.is_file() && raw.ends_with(b"/") {
                return Err(invalid_archive());
            }
            let path = std::str::from_utf8(&raw)
                .map_err(|_| invalid_archive())?
                .trim_end_matches('/');
            if !crate::archive::valid_relative_path(path) || !seen.insert(path.to_owned()) {
                return Err(invalid_archive());
            }
            let candidate_root = path.split('/').next().ok_or_else(invalid_archive)?;
            if !matches!(candidate_root, "package") && candidate_root != historical_root {
                return Err(Error::integrity(
                    "Unsupported npm archive root; expected package/ or the exact package basename/.",
                ));
            }
            if let Some(root) = &archive_root {
                if root != candidate_root {
                    return Err(Error::integrity("Mixed npm archive roots are unsupported."));
                }
            } else {
                archive_root = Some(candidate_root.to_owned());
            }
            if path == candidate_root && kind.is_dir() {
                continue;
            }
            let relative = path
                .strip_prefix(candidate_root)
                .and_then(|path| path.strip_prefix('/'))
                .filter(|p| !p.is_empty())
                .ok_or_else(invalid_archive)?
                .to_owned();
            if kind.is_dir() {
                continue;
            }
            let size = entry.size();
            members.push(json!({"path":relative,"size":size}));
            if selected.is_some_and(|path| path != relative && relative != "package.json") {
                io::copy(&mut entry, &mut io::sink()).map_err(|_| invalid_archive())?;
                continue;
            }
            // Reserve room for the manifest regardless of archive member order.
            let projection_limit = if relative == "package.json" {
                MAX_PROJECTED
            } else {
                MAX_PROJECTED - MAX_DOCUMENT
            };
            if size > MAX_DOCUMENT as u64
                || total_projected.saturating_add(size as usize) > projection_limit
            {
                gaps.push(json!({"path":relative,"code":"document_processing_limit"}));
                io::copy(&mut entry, &mut io::sink()).map_err(|_| invalid_archive())?;
                continue;
            }
            let mut body = Vec::new();
            entry
                .by_ref()
                .take(MAX_DOCUMENT as u64 + 1)
                .read_to_end(&mut body)
                .map_err(|_| invalid_archive())?;
            if body.len() as u64 != size {
                return Err(invalid_archive());
            }
            let Ok(text) = std::str::from_utf8(&body) else {
                gaps.push(json!({"path":relative,"code":"binary_document"}));
                continue;
            };
            if text.contains('\0') {
                gaps.push(json!({"path":relative,"code":"binary_document"}));
                continue;
            }
            if relative == "package.json" {
                package = Some(decode(&body, MAX_DOCUMENT, true)?);
            }
            total_projected += text.len();
            let lower = relative.to_ascii_lowercase();
            let filename = lower.rsplit('/').next().unwrap_or("");
            let kind = if relative == "package.json" {
                "manifest"
            } else if ["license", "notice", "copying", "authors"]
                .iter()
                .any(|p| filename.starts_with(p))
            {
                "license"
            } else if filename.starts_with("readme") {
                "readme"
            } else if lower.ends_with(".d.ts")
                || lower.ends_with(".d.mts")
                || lower.ends_with(".d.cts")
            {
                "declaration"
            } else {
                "source"
            };
            documents.push(json!({"path":relative,"kind":kind,"text":text}));
        }
    }
    io::copy(&mut reader, &mut io::sink()).map_err(|_| invalid_archive())?;
    let package = package.ok_or_else(|| {
        Error::integrity("npm archive package.json is absent or exceeds processing limits.")
    })?;
    if package.value["name"].as_str() != Some(name)
        || package.value["version"].as_str() != Some(version)
    {
        return Err(Error::integrity(
            "npm archive package.json identity differs from registry metadata.",
        ));
    }
    let mut declarations = Map::new();
    for field in [
        "main",
        "module",
        "browser",
        "type",
        "exports",
        "imports",
        "types",
        "typings",
        "typesVersions",
        "bin",
    ] {
        if let Some(value) = package.value.get(field) {
            declarations.insert(field.into(), value.clone());
        }
    }
    let ordered = package.ordered["object"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter(|e| {
                    e["key"]
                        .as_str()
                        .is_some_and(|key| declarations.contains_key(key))
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    // Registry manifest and archive manifest are separate evidence; differences
    // must remain visible rather than silently substituting either representation.
    let mut differing = Vec::new();
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "scripts",
        "main",
        "exports",
        "imports",
        "types",
        "typesVersions",
        "license",
    ] {
        if manifest.get(field) != package.value.get(field) {
            differing.push(field);
        }
    }
    if !differing.is_empty() {
        gaps.push(json!({"code":"manifest_difference","fields":differing}));
    }
    members.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    documents.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    Ok(
        json!({"members":members,"documents":documents,"contracts":{"declarations":declarations,"ordered":ordered,"interpretation":"inert published declarations; conditions and patterns are not resolved"},"gaps":gaps,"processor_version":PROCESSOR_VERSION}),
    )
}
