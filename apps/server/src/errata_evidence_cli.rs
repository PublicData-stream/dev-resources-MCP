//! Private RFC errata capture and evidence inspection commands.
use devres_adapters::{RfcErrataCaptureReport, RfcErrataCaptureSelection, create_diagnosis_output};
use devres_domain::{Error, Result};
use devres_server::{ServerError, config::Config};
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;

pub struct Arguments {
    pub bundle: PathBuf,
    pub manifest: PathBuf,
    pub output: PathBuf,
}
pub fn parse(args: &[String]) -> Result<Arguments> {
    let invalid = || {
        Error::invalid(
            "usage: devres-server verify-rfc-errata-evidence /tmp/PRIVATE-BUNDLE --manifest /tmp/PRIVATE/manifest.json --output /tmp/PRIVATE/new-report.json",
        )
    };
    if args.len() != 6
        || args[0] != "verify-rfc-errata-evidence"
        || args[2] != "--manifest"
        || args[4] != "--output"
    {
        return Err(invalid());
    }
    let bundle = PathBuf::from(&args[1]);
    let manifest = PathBuf::from(&args[3]);
    let output = PathBuf::from(&args[5]);
    if !private_bundle(&bundle) {
        return Err(invalid());
    }
    for path in [&manifest, &output] {
        super::collection_recovery_cli::private_path(path)?;
    }
    Ok(Arguments {
        bundle,
        manifest,
        output,
    })
}

fn private_bundle(path: &Path) -> bool {
    path.is_absolute()
        && path.starts_with("/tmp")
        && path != Path::new("/tmp")
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

struct CaptureArguments<'a> {
    config: &'a Path,
    selection: RfcErrataCaptureSelection<'a>,
    export: PathBuf,
    output: &'a Path,
}

fn capture_usage() -> Error {
    Error::invalid(
        "usage: devres-server inspect-rfc-errata-capture CONFIG --export-capture BLAKE3 --export-body BLAKE3 --rfc NUMBER --errata-id ID [--snapshot SNAPSHOT] --bundle /tmp/PRIVATE-BUNDLE --output /tmp/PRIVATE/new-report.json",
    )
}

fn parse_capture(args: &[String]) -> Result<CaptureArguments<'_>> {
    let [command, config, flags @ ..] = args else {
        return Err(capture_usage());
    };
    let (pairs, remainder) = flags.as_chunks::<2>();
    if command != "inspect-rfc-errata-capture"
        || config.is_empty()
        || config.starts_with('-')
        || !remainder.is_empty()
    {
        return Err(capture_usage());
    }
    let mut options = BTreeMap::new();
    for [flag, value] in pairs {
        if !matches!(
            flag.as_str(),
            "--export-capture"
                | "--export-body"
                | "--rfc"
                | "--errata-id"
                | "--snapshot"
                | "--bundle"
                | "--output"
        ) || value.is_empty()
            || value.starts_with('-')
            || options.insert(flag.as_str(), value.as_str()).is_some()
        {
            return Err(capture_usage());
        }
    }
    let required = |flag| options.get(flag).copied().ok_or_else(capture_usage);
    let selection = RfcErrataCaptureSelection {
        snapshot: options.get("--snapshot").copied(),
        export_capture: required("--export-capture")?,
        export_body: required("--export-body")?,
        rfc: required("--rfc")?.parse().map_err(|_| capture_usage())?,
        errata_id: required("--errata-id")?
            .parse()
            .map_err(|_| capture_usage())?,
    };
    selection.validate()?;
    let bundle = Path::new(required("--bundle")?);
    let output = Path::new(required("--output")?);
    if !private_bundle(bundle) || super::collection_recovery_cli::private_path(output).is_err() {
        return Err(capture_usage());
    }
    let digest = selection
        .export_body
        .strip_prefix("blake3:")
        .ok_or_else(capture_usage)?;
    let export = bundle.join(digest);
    if export == output {
        return Err(capture_usage());
    }
    Ok(CaptureArguments {
        config: Path::new(config),
        selection,
        export,
        output,
    })
}

fn write_capture(
    export_path: &Path,
    output: &Path,
    report: &RfcErrataCaptureReport,
    export: &[u8],
    cancel: &CancellationToken,
) -> Result<()> {
    let cancelled = || Error::new("cancelled", "RFC errata capture inspection canceled.");
    if cancel.is_cancelled() {
        return Err(cancelled());
    }
    let report_file = create_diagnosis_output(output)?;
    let mut export_file = create_diagnosis_output(export_path)?;
    let unavailable = || Error::unavailable("RFC errata export output unavailable.");
    for chunk in export.chunks(64 * 1024) {
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        export_file.write_all(chunk).map_err(|_| unavailable())?;
    }
    export_file.sync_all().map_err(|_| unavailable())?;
    if cancel.is_cancelled() {
        return Err(cancelled());
    }
    super::collection_recovery_cli::write_report(report_file, report)
}

pub async fn inspect_capture(args: &[String]) -> std::result::Result<(), ServerError> {
    let arguments = parse_capture(args)?;
    let config = Config::load(arguments.config)
        .await
        .map_err(|_| "RFC errata inspection configuration unavailable.")?;
    let cancel = CancellationToken::new();
    let stopping = cancel.clone();
    let signal = tokio::spawn(async move {
        super::shutdown_signal().await;
        stopping.cancel();
    });
    let result: std::result::Result<(), ServerError> = async {
        let (report, export) = devres_adapters::inspect_rfc_errata_capture(
            &config.storage.database_url,
            &config.storage.blob_dir,
            config.storage.s3,
            arguments.selection,
            cancel.clone(),
        )
        .await?;
        let output = arguments.output.to_owned();
        tokio::task::spawn_blocking(move || {
            write_capture(&arguments.export, &output, &report, &export, &cancel)
        })
        .await
        .map_err(|_| "RFC errata capture output unavailable.")??;
        Ok(())
    }
    .await;
    signal.abort();
    let _ = signal.await;
    result?;
    println!("rfc_errata_capture archive_binding_checked=true publication_authorized=false");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    const DIGEST: &str = "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn capture_args() -> Vec<String> {
        [
            "inspect-rfc-errata-capture",
            "/etc/devres/reader.toml",
            "--export-capture",
            DIGEST,
            "--export-body",
            DIGEST,
            "--rfc",
            "9525",
            "--errata-id",
            "8173",
            "--bundle",
            "/tmp/owned-bundle",
            "--output",
            "/tmp/owned-bundle/report.json",
        ]
        .map(str::to_owned)
        .into()
    }

    #[test]
    fn accepts_private_bundle_directly_below_tmp() {
        let args = [
            "verify-rfc-errata-evidence",
            "/tmp/owned-bundle",
            "--manifest",
            "/tmp/owned/manifest.json",
            "--output",
            "/tmp/owned/report.json",
        ]
        .map(str::to_owned);
        assert!(parse(&args).is_ok());
        let mut invalid = args;
        invalid[1] = "/tmp".into();
        assert!(parse(&invalid).is_err());
    }

    #[test]
    fn capture_inspection_fixes_export_filename_and_accepts_snapshot() {
        let mut args = capture_args();
        let command = parse_capture(&args).unwrap();
        assert_eq!(command.selection.snapshot, None);
        args.extend(["--snapshot".into(), DIGEST.into()]);
        let command = parse_capture(&args).unwrap();
        assert_eq!(command.config, Path::new("/etc/devres/reader.toml"));
        assert_eq!(command.selection.snapshot, Some(DIGEST));
        assert_eq!(command.selection.rfc, 9525);
        assert_eq!(command.selection.errata_id, 8173);
        assert_eq!(command.output, Path::new("/tmp/owned-bundle/report.json"));
        assert_eq!(
            command.export,
            Path::new("/tmp/owned-bundle").join(&DIGEST[7..])
        );
    }

    #[test]
    fn capture_inspection_rejects_invalid_identity_paths_and_flags() {
        for (idx, value) in [
            (3, "not-an-export-capture"),
            (5, "not-an-export-digest"),
            (7, "100000"),
            (9, "0"),
            (11, "/tmp"),
            (11, "/tmp/owned-bundle/../other"),
            (13, "/tmp/report.json"),
            (13, "/home/report.json"),
        ] {
            let mut args = capture_args();
            args[idx] = value.into();
            assert!(parse_capture(&args).is_err());
        }
        let mut args = capture_args();
        args[13] = format!("/tmp/owned-bundle/{}", &DIGEST[7..]);
        assert!(parse_capture(&args).is_err());
        for flags in [
            ["--snapshot", "invalid"],
            ["--output", "/tmp/owned-bundle/duplicate.json"],
            ["--unknown", "value"],
        ] {
            let mut args = capture_args();
            args.extend(flags.map(str::to_owned));
            assert!(parse_capture(&args).is_err());
        }
        let mut args = capture_args();
        args.pop();
        assert!(parse_capture(&args).is_err());
    }

    #[test]
    fn writes_exact_export_and_sanitized_report_to_distinct_private_files() {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
            .unwrap();
        let body = b"[ { \"orig_text\": \"private prose sentinel\" } ]\n";
        let report = RfcErrataCaptureReport {
            version: 1,
            snapshot: DIGEST.into(),
            export_capture: DIGEST.into(),
            export_body: devres_adapters::integrity::hash(body),
            member_body: DIGEST.into(),
            rfc: 9525,
            errata_id: 8173,
            captured_at: 1,
            export_bytes: body.len() as u64,
            archive_backend: "filesystem",
            archive_binding_checked: true,
            applicability_approved: false,
            publication_authorized: false,
        };
        let export = temp.path().join(&report.export_body[7..]);
        let output = temp.path().join("report.json");
        let cancel = CancellationToken::new();
        write_capture(&export, &output, &report, body, &cancel).unwrap();
        assert_eq!(fs::read(&export).unwrap(), body);
        let text = fs::read_to_string(&output).unwrap();
        assert!(!text.contains("private prose sentinel"));
        let saved: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(saved["archive_binding_checked"], true);
        assert_eq!(saved["applicability_approved"], false);
        assert_eq!(saved["publication_authorized"], false);
        for path in [&export, &output] {
            let mode = fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }
        assert!(write_capture(&export, &output, &report, b"changed", &cancel).is_err());
        assert_eq!(fs::read(&export).unwrap(), body);
        assert_eq!(fs::read_to_string(&output).unwrap(), text);

        cancel.cancel();
        let cancelled = temp.path().join("cancelled.json");
        assert_eq!(
            write_capture(&export, &cancelled, &report, body, &cancel)
                .unwrap_err()
                .code,
            "cancelled"
        );
        assert!(!cancelled.exists());
    }
}
