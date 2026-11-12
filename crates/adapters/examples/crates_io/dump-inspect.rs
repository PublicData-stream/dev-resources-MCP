//! Private, offline inspection of one operator-identified retained dump.
//! No configuration, database, archive client, provider request, or staging port.
use devres_adapters::{
    crate_dump::{self, DumpInspection},
    create_diagnosis_output, integrity,
};
use devres_domain::{Error, Result};
use serde::Serialize;
use std::{
    ffi::OsString,
    fs::File,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const COMPRESSED: u64 = 4 * 1024 * 1024 * 1024;
const EXPANDED: u64 = 8 * 1024 * 1024 * 1024;
const SECONDS: u64 = 30 * 60;
const REPORT_BYTES: usize = 16 * 1024;

fn invalid() -> Error {
    Error::invalid("Invalid retained dump inspection arguments.")
}
fn unavailable() -> Error {
    Error::unavailable("Retained dump inspection unavailable.")
}

#[derive(Clone, Debug)]
struct Arguments {
    retained_file: PathBuf,
    capture: String,
    body: String,
    expected_bytes: u64,
    output: PathBuf,
    measure_first_rejection: bool,
}
fn tagged(value: &str) -> bool {
    value.starts_with("blake3:") && integrity::valid_hash(value)
}
fn absolute_clean(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}
impl Arguments {
    fn parse(args: &[OsString]) -> Result<Self> {
        let (mut retained_file, mut capture, mut body, mut expected_bytes, mut output) =
            (None, None, None, None, None);
        let mut measure_first_rejection = false;
        let mut arguments = args.iter();
        while let Some(flag) = arguments.next() {
            if flag == "--measure-first-rejection" && !measure_first_rejection {
                measure_first_rejection = true;
                continue;
            }
            let value = arguments.next().ok_or_else(invalid)?;
            match flag.to_str().ok_or_else(invalid)? {
                "--retained-file" if retained_file.is_none() => {
                    retained_file = Some(PathBuf::from(value))
                }
                "--capture" if capture.is_none() => {
                    capture = Some(value.to_str().ok_or_else(invalid)?.to_owned())
                }
                "--body" if body.is_none() => {
                    body = Some(value.to_str().ok_or_else(invalid)?.to_owned())
                }
                "--expected-bytes" if expected_bytes.is_none() => {
                    let value = value.to_str().ok_or_else(invalid)?;
                    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(invalid());
                    }
                    expected_bytes = Some(value.parse::<u64>().map_err(|_| invalid())?);
                }
                "--output" if output.is_none() => output = Some(PathBuf::from(value)),
                _ => return Err(invalid()),
            }
        }
        let arguments = Self {
            retained_file: retained_file.ok_or_else(invalid)?,
            capture: capture.ok_or_else(invalid)?,
            body: body.ok_or_else(invalid)?,
            expected_bytes: expected_bytes.ok_or_else(invalid)?,
            output: output.ok_or_else(invalid)?,
            measure_first_rejection,
        };
        let basename = arguments.body.strip_prefix("blake3:").ok_or_else(invalid)?;
        if !tagged(&arguments.capture)
            || !tagged(&arguments.body)
            || arguments.expected_bytes > COMPRESSED
            || !absolute_clean(&arguments.retained_file)
            || arguments
                .retained_file
                .file_name()
                .and_then(|name| name.to_str())
                != Some(basename)
            || !absolute_clean(&arguments.output)
            || !arguments.output.starts_with("/tmp")
            || arguments.output.parent() == Some(Path::new("/tmp"))
            || arguments.output.file_name().is_none()
        {
            return Err(invalid());
        }
        Ok(arguments)
    }
    fn preflight(&self) -> Result<()> {
        // Refuse symlink ancestors as well as the final component. No body bytes are read.
        if std::fs::canonicalize(&self.retained_file).map_err(|_| unavailable())?
            != self.retained_file
        {
            return Err(invalid());
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&self.retained_file)
            .map_err(|_| unavailable())?;
        let metadata = file.metadata().map_err(|_| unavailable())?;
        if !metadata.is_file()
            || metadata.len() != self.expected_bytes
            || metadata.len() > COMPRESSED
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Validated,
    Rejected,
    Cancelled,
    BoundedStop,
    Failed,
}
impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::BoundedStop => "bounded_stop",
            Self::Failed => "failed",
        }
    }
}
#[derive(Serialize)]
struct Report {
    version: u32,
    capture: String,
    body_hash: String,
    expected_bytes: u64,
    identity_association: &'static str,
    full_body_hash_reverified: bool,
    prefix_only: bool,
    compressed_limit: u64,
    expanded_limit: u64,
    timeout_secs: u64,
    outcome: Outcome,
    measurement_requested: bool,
    inspection: DumpInspection,
}
impl Report {
    fn new(arguments: &Arguments, inspection: DumpInspection) -> Self {
        let outcome = if inspection.complete {
            Outcome::Validated
        } else {
            match inspection.code.as_deref() {
                Some("cancelled") => Outcome::Cancelled,
                Some("capacity") if inspection.csv.is_none() => Outcome::BoundedStop,
                Some("integrity" | "capacity") => Outcome::Rejected,
                _ => Outcome::Failed,
            }
        };
        Self {
            version: if arguments.measure_first_rejection {
                2
            } else {
                1
            },
            capture: arguments.capture.clone(),
            body_hash: arguments.body.clone(),
            expected_bytes: arguments.expected_bytes,
            identity_association: "operator_supplied",
            full_body_hash_reverified: false,
            prefix_only: !inspection.complete,
            compressed_limit: COMPRESSED,
            expanded_limit: EXPANDED,
            timeout_secs: SECONDS,
            outcome,
            measurement_requested: arguments.measure_first_rejection,
            inspection,
        }
    }
    fn write(&self, mut output: File) -> Result<()> {
        let encoded = serde_json::to_vec_pretty(self).map_err(|_| unavailable())?;
        if encoded.len() > REPORT_BYTES {
            return Err(Error::capacity("Retained dump report exceeds its bound."));
        }
        output
            .write_all(&encoded)
            .and_then(|()| output.write_all(b"\n"))
            .and_then(|()| output.sync_all())
            .map_err(|_| unavailable())
    }
}

/// Signals cancel cooperatively; the caller keeps awaiting this worker until it stops.
async fn join_blocking(
    cancel: CancellationToken,
    operation: impl FnOnce(CancellationToken) -> Result<DumpInspection> + Send + 'static,
) -> Result<DumpInspection> {
    let _guard = cancel.clone().drop_guard();
    tokio::task::spawn_blocking(move || operation(cancel))
        .await
        .map_err(|_| unavailable())?
}
async fn inspect(arguments: &Arguments, cancel: CancellationToken) -> Result<Report> {
    let owned = arguments.clone();
    let inspection = join_blocking(cancel, move |token| {
        owned.preflight()?;
        let scan = if owned.measure_first_rejection {
            crate_dump::measure_first_rejection
        } else {
            crate_dump::inspect_dump
        };
        scan(
            owned.retained_file,
            token,
            Instant::now() + Duration::from_secs(SECONDS),
            COMPRESSED,
            EXPANDED,
        )
    })
    .await?;
    Ok(Report::new(arguments, inspection))
}
async fn run(arguments: Arguments) -> Result<Outcome> {
    arguments.preflight()?;
    let output = create_diagnosis_output(&arguments.output)?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| unavailable())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| unavailable())?;
    let cancel = CancellationToken::new();
    let stopping = cancel.clone();
    let signals = tokio::spawn(async move {
        tokio::select! {_=interrupt.recv()=>{},_=terminate.recv()=>{}}
        stopping.cancel();
    });
    let result = inspect(&arguments, cancel).await;
    signals.abort();
    let _ = signals.await;
    let report = result?;
    let outcome = report.outcome;
    let complete = report.inspection.complete;
    let row = report
        .inspection
        .csv
        .as_ref()
        .map_or(0, |diagnostic| diagnostic.row);
    report.write(output)?;
    println!(
        "dump_inspection outcome={} complete={} row={row}",
        outcome.label(),
        complete
    );
    Ok(outcome)
}
#[tokio::main]
async fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let result = match Arguments::parse(&arguments) {
        Ok(arguments) => run(arguments).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(Outcome::Cancelled) => std::process::exit(130),
        Ok(Outcome::Failed) => std::process::exit(1),
        Ok(_) => {}
        Err(_) => {
            eprintln!("dump_inspection outcome=failed");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Cursor,
        os::unix::fs::{PermissionsExt, symlink},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    fn arguments(root: &Path, size: u64) -> Arguments {
        let body = integrity::hash(b"operator identified inert fixture");
        Arguments {
            retained_file: root.join(body.strip_prefix("blake3:").unwrap()),
            capture: integrity::hash(b"capture association"),
            body,
            expected_bytes: size,
            output: root.join("private/report.json"),
            measure_first_rejection: false,
        }
    }
    fn flags(arguments: &Arguments) -> Vec<OsString> {
        vec![
            "--retained-file".into(),
            arguments.retained_file.as_os_str().to_owned(),
            "--capture".into(),
            arguments.capture.clone().into(),
            "--body".into(),
            arguments.body.clone().into(),
            "--expected-bytes".into(),
            arguments.expected_bytes.to_string().into(),
            "--output".into(),
            arguments.output.as_os_str().to_owned(),
        ]
    }
    #[test]
    fn argument_contract_rejects_unknown_duplicate_identity_path_and_size_variants() {
        let original = arguments(Path::new("/tmp/offline-dump-fixture"), COMPRESSED);
        assert!(Arguments::parse(&flags(&original)).is_ok());
        let mut measured = flags(&original);
        measured.push("--measure-first-rejection".into());
        assert!(Arguments::parse(&measured).unwrap().measure_first_rejection);
        measured.push("--measure-first-rejection".into());
        assert!(Arguments::parse(&measured).is_err());
        let mut too_large = original.clone();
        too_large.expected_bytes = COMPRESSED + 1;
        assert!(Arguments::parse(&flags(&too_large)).is_err());
        for capture in [
            "a".repeat(64),
            format!("blake3:{}", "A".repeat(64)),
            "https://private.invalid".into(),
        ] {
            let mut invalid = original.clone();
            invalid.capture = capture;
            assert!(Arguments::parse(&flags(&invalid)).is_err());
        }
        for path in [
            PathBuf::from("relative"),
            PathBuf::from("/tmp/wrong-basename"),
            PathBuf::from("/tmp/../private/file"),
        ] {
            let mut invalid = original.clone();
            invalid.retained_file = path;
            assert!(Arguments::parse(&flags(&invalid)).is_err());
        }
        for output in [
            "/tmp/report.json",
            "/var/private/report.json",
            "/tmp/../private/report.json",
        ] {
            let mut invalid = original.clone();
            invalid.output = output.into();
            assert!(Arguments::parse(&flags(&invalid)).is_err());
        }
        for extras in [["--body", "duplicate"], ["--network", "enabled"]] {
            let mut invalid = flags(&original);
            invalid.extend(extras.map(OsString::from));
            assert!(Arguments::parse(&invalid).is_err());
        }
        let mut missing = flags(&original);
        missing.pop();
        assert!(Arguments::parse(&missing).is_err());
    }
    #[test]
    fn input_preflight_rejects_size_changes_symlinks_and_directories() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let arguments = arguments(root.path(), 1);
        std::fs::write(&arguments.retained_file, b"x").unwrap();
        arguments.preflight().unwrap();
        std::fs::write(&arguments.retained_file, b"xx").unwrap();
        assert!(arguments.preflight().is_err());
        std::fs::remove_file(&arguments.retained_file).unwrap();
        symlink(root.path().join("target"), &arguments.retained_file).unwrap();
        assert!(arguments.preflight().is_err());
        std::fs::remove_file(&arguments.retained_file).unwrap();
        std::fs::create_dir(&arguments.retained_file).unwrap();
        assert!(arguments.preflight().is_err());
        std::fs::remove_dir(&arguments.retained_file).unwrap();
        std::fs::write(&arguments.retained_file, b"x").unwrap();
        let alias = root.path().join("alias");
        symlink(root.path(), &alias).unwrap();
        let mut through_alias = arguments.clone();
        through_alias.retained_file = alias.join(arguments.retained_file.file_name().unwrap());
        assert!(through_alias.preflight().is_err());
    }
    #[tokio::test]
    async fn cancellation_joins_the_blocking_worker_before_returning() {
        let cancel = CancellationToken::new();
        let stopping = cancel.clone();
        let completed = Arc::new(AtomicBool::new(false));
        let observed = completed.clone();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            join_blocking(stopping, move |token| {
                entered.send(()).unwrap();
                while !token.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                wait.recv().unwrap();
                observed.store(true, Ordering::SeqCst);
                Ok(DumpInspection {
                    complete: false,
                    code: Some("cancelled".into()),
                    csv: None,
                    measurement: None,
                })
            })
            .await
        });
        ready.await.unwrap();
        cancel.cancel();
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert!(!completed.load(Ordering::SeqCst));
        release.send(()).unwrap();
        assert_eq!(
            task.await.unwrap().unwrap().code.as_deref(),
            Some("cancelled")
        );
        assert!(completed.load(Ordering::SeqCst));
    }
    #[tokio::test]
    async fn offline_scan_writes_only_closed_diagnostics_and_explicit_proof_limits() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let ignored = "private-upstream-value".repeat(60_000);
        let csv = format!("id,name,private_header\n1,synthetic,{ignored}\n");
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(gzip);
        for (path, bytes) in [
            ("data/crates.csv", csv.as_bytes()),
            (
                "data/versions.csv",
                b"id,crate_id,num\n2,1,1.0.0\n".as_slice(),
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, path, Cursor::new(bytes))
                .unwrap();
        }
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let mut arguments = arguments(root.path(), bytes.len() as u64);
        arguments.body = integrity::hash(&bytes);
        arguments.retained_file = root
            .path()
            .join(arguments.body.strip_prefix("blake3:").unwrap());
        std::fs::write(&arguments.retained_file, &bytes).unwrap();
        let report = inspect(&arguments, CancellationToken::new()).await.unwrap();
        assert_eq!(report.outcome, Outcome::Rejected);
        let output = create_diagnosis_output(&arguments.output).unwrap();
        report.write(output).unwrap();
        let encoded = std::fs::read_to_string(&arguments.output).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["identity_association"], "operator_supplied");
        assert_eq!(value["full_body_hash_reverified"], false);
        assert_eq!(value["prefix_only"], true);
        assert_eq!(value["inspection"]["csv"]["table"], "crates");
        assert_eq!(value["inspection"]["csv"]["row"], 1);
        assert_eq!(value["inspection"]["csv"]["column"], 2);
        assert_eq!(value["inspection"]["csv"]["selected"], false);
        assert!(!encoded.contains("private_header"));
        assert!(!encoded.contains("private-upstream-value"));
        assert!(!encoded.contains(root.path().to_str().unwrap()));
        assert_eq!(
            std::fs::metadata(&arguments.output)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(create_diagnosis_output(&arguments.output).is_err());
        let mut measured = arguments.clone();
        measured.measure_first_rejection = true;
        let measurement = inspect(&measured, CancellationToken::new()).await.unwrap();
        assert_eq!(measurement.version, 2);
        let observed = measurement.inspection.measurement.as_ref().unwrap();
        assert_eq!(observed.field_kind, crate_dump::CsvFieldKind::Ignored);
        assert_eq!(observed.field_bytes, ignored.len() as u64);
        assert!(
            observed.field_complete
                && observed.field_valid
                && observed.row_complete
                && observed.row_valid
        );
        assert!(observed.failure.is_none());
        assert!(
            !serde_json::to_string(&measurement)
                .unwrap()
                .contains("private_header")
        );
        let cancelled = inspect(&arguments, {
            let token = CancellationToken::new();
            token.cancel();
            token
        })
        .await
        .unwrap();
        assert_eq!(cancelled.outcome, Outcome::Cancelled);
    }
}
