//! Private operator command; never registers a transport or starts collection.
use devres_adapters::{DiagnosisOptions, DiagnosisProvider};
use devres_domain::{Error, Result};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

pub struct Arguments {
    pub config: PathBuf,
    pub options: DiagnosisOptions,
    pub output: PathBuf,
}

pub fn parse(args: &[String]) -> Result<Arguments> {
    let invalid = || {
        Error::invalid(
            "usage: devres-server diagnose-collection CONFIG.toml --provider w3c|chromium|crates --output /tmp/PRIVATE-DIRECTORY/report.json [--latest-failure] [--max-total-bytes N] [--timeout-secs N] [--scan-retained-dump]",
        )
    };
    if args.len() < 2 || args[0] != "diagnose-collection" {
        return Err(invalid());
    }
    let mut provider = None;
    let mut output = None;
    let mut bytes = None;
    let mut timeout = None;
    let mut latest = false;
    let mut scan = false;
    let mut index = 2;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        if flag == "--latest-failure" && !latest {
            latest = true;
            continue;
        }
        if flag == "--scan-retained-dump" && !scan {
            scan = true;
            continue;
        }
        let value = args.get(index).ok_or_else(invalid)?;
        index += 1;
        match flag {
            "--provider" if provider.is_none() => {
                provider = Some(match value.as_str() {
                    "w3c" => DiagnosisProvider::W3c,
                    "chromium" => DiagnosisProvider::Chromium,
                    "crates" => DiagnosisProvider::Crates,
                    _ => return Err(invalid()),
                })
            }
            "--output" if output.is_none() => output = Some(PathBuf::from(value)),
            "--max-total-bytes" if bytes.is_none() => {
                bytes = Some(value.parse::<u64>().map_err(|_| invalid())?)
            }
            "--timeout-secs" if timeout.is_none() => {
                timeout = Some(value.parse::<u64>().map_err(|_| invalid())?)
            }
            _ => return Err(invalid()),
        }
    }
    let options = DiagnosisOptions {
        provider: provider.ok_or_else(invalid)?,
        max_total_bytes: bytes.unwrap_or(64 * 1024 * 1024),
        timeout_secs: timeout.unwrap_or(300),
        scan_retained_dump: scan,
    };
    options.validate()?;
    let output = output.ok_or_else(invalid)?;
    validate_output_path(&output)?;
    Ok(Arguments {
        config: PathBuf::from(&args[1]),
        options,
        output,
    })
}

fn failed() -> Error {
    Error::invalid(
        "Diagnosis output requires a private owned directory below /tmp and a new regular file.",
    )
}
fn validate_output_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || !path.starts_with("/tmp")
        || path.parent() == Some(Path::new("/tmp"))
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || path.file_name().is_none()
    {
        return Err(failed());
    }
    Ok(())
}
pub fn open_output(path: &Path) -> Result<File> {
    validate_output_path(path)?;
    devres_adapters::create_diagnosis_output(path)
}
pub fn write_report(mut file: File, report: &devres_adapters::CollectionDiagnosis) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report).map_err(|_| failed())?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error::capacity("Diagnosis report exceeds its bound."));
    }
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| failed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn arguments(extra: &[&str]) -> Vec<String> {
        [
            "diagnose-collection",
            "private.toml",
            "--provider",
            "w3c",
            "--output",
            "/tmp/diagnosis-owned/report.json",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn invalid_options_fail_before_config_or_storage() {
        assert!(parse(&arguments(&[])).is_ok());
        for extra in [
            vec!["--max-total-bytes", "0"],
            vec!["--timeout-secs", "301"],
            vec!["--provider", "w3c"],
            vec!["--scan-retained-dump"],
            vec!["--latest-failure", "--latest-failure"],
        ] {
            assert!(parse(&arguments(&extra)).is_err());
        }
    }
    #[test]
    fn output_cannot_overwrite_or_follow_links() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let parent = root.path().join("private");
        let output = parent.join("report.json");
        let file = open_output(&output).unwrap();
        drop(file);
        assert!(open_output(&output).is_err());
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&parent, &link).unwrap();
        assert!(open_output(&link.join("new.json")).is_err());
        assert!(open_output(&link.join("new-directory/new.json")).is_err());
        assert!(!parent.join("new-directory").exists());
        assert!(open_output(Path::new("/tmp/report.json")).is_err());
    }
}
