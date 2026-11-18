//! Private, exact offline commands. Parsing finishes before configuration or storage I/O.
use devres_adapters::{
    DiagnosisOptions, DiagnosisProvider, collection_recovery::CollectionRecoveryOptions,
};
use devres_domain::{Error, Result};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Verify,
    DryRun,
    Apply,
    Run,
}
pub enum Selection {
    Npm(CollectionRecoveryOptions),
    Rfc(DiagnosisOptions),
    Queued(String),
}
pub struct Arguments {
    pub action: Action,
    pub config: PathBuf,
    pub output: PathBuf,
    pub selection: Selection,
    pub artifact: Option<PathBuf>,
    pub evidence: Option<PathBuf>,
    pub checkpoint: Option<PathBuf>,
    pub connect_readiness: bool,
}
fn invalid() -> Error {
    Error::invalid("Invalid exact offline recovery command; see docs/terminal-recovery-design.md.")
}
pub fn parse(args: &[String]) -> Result<Arguments> {
    if args.len() < 3 || args[0] != "recover-collection" || args[2].starts_with('-') {
        return Err(invalid());
    }
    let action = match args[1].as_str() {
        "verify-evidence" => Action::Verify,
        "dry-run" => Action::DryRun,
        "apply" => Action::Apply,
        "run" => Action::Run,
        _ => return Err(invalid()),
    };
    let mut flags = BTreeMap::new();
    let mut i = 3;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = args.get(i + 1).ok_or_else(invalid)?;
        if !matches!(
            flag,
            "--provider"
                | "--job-id"
                | "--revision"
                | "--recipe"
                | "--artifact"
                | "--evidence"
                | "--expected-state"
                | "--operation-id"
                | "--checkpoint"
                | "--output"
                | "--snapshot"
                | "--job-key"
                | "--attribution-target"
                | "--phase-file"
                | "--connect-readiness"
        ) || value.starts_with('-')
            || flags.insert(flag, value.clone()).is_some()
        {
            return Err(invalid());
        }
        i += 2;
    }
    let config = PathBuf::from(&args[2]);
    let provider = flags.remove("--provider").ok_or_else(invalid)?;
    let connect_readiness = match flags.remove("--connect-readiness").as_deref() {
        None => false,
        Some("wait") if action == Action::DryRun && provider == "npm" => true,
        Some(_) => return Err(invalid()),
    };
    let output = PathBuf::from(flags.remove("--output").ok_or_else(invalid)?);
    private_path(&output)?;
    let phase_file = flags.remove("--phase-file").map(PathBuf::from);
    if let Some(path) = &phase_file {
        private_path(path)?;
        if action != Action::DryRun || provider != "npm" || path.parent() == output.parent() {
            return Err(invalid());
        }
    }
    let artifact = flags.remove("--artifact").map(PathBuf::from);
    if let Some(p) = &artifact {
        private_path(p)?;
    }
    let evidence = flags.remove("--evidence").map(PathBuf::from);
    if let Some(p) = &evidence {
        private_path(p)?;
    }
    let checkpoint = flags.remove("--checkpoint").map(PathBuf::from);
    if let Some(p) = &checkpoint {
        private_path(p)?;
    }
    let selection = if provider == "rfc" {
        if action != Action::DryRun
            || artifact.is_some()
            || evidence.is_some()
            || checkpoint.is_some()
        {
            return Err(invalid());
        }
        let options = DiagnosisOptions {
            provider: DiagnosisProvider::Rfc,
            max_total_bytes: 64 * 1024 * 1024,
            timeout_secs: 300,
            scan_retained_dump: false,
            snapshot: Some(flags.remove("--snapshot").ok_or_else(invalid)?),
            job_keys: vec![flags.remove("--job-key").ok_or_else(invalid)?],
            commit: None,
            attribution_target: Some(flags.remove("--attribution-target").ok_or_else(invalid)?),
        };
        options.validate()?;
        Selection::Rfc(options)
    } else if provider == "npm" {
        if action == Action::Run {
            let operation = flags.remove("--operation-id").ok_or_else(invalid)?;
            if !hash(&operation) || artifact.is_none() || evidence.is_some() || checkpoint.is_some()
            {
                return Err(invalid());
            }
            Selection::Queued(operation)
        } else {
            let options = CollectionRecoveryOptions {
                job_id: flags.remove("--job-id").ok_or_else(invalid)?,
                revision: flags
                    .remove("--revision")
                    .ok_or_else(invalid)?
                    .parse()
                    .map_err(|_| invalid())?,
                recipe: flags.remove("--recipe").ok_or_else(invalid)?,
                expected_state: flags.remove("--expected-state"),
                operation_id: flags.remove("--operation-id"),
            };
            options.validate(action == Action::Apply)?;
            match action {
                Action::Verify
                    if artifact.is_some()
                        && evidence.is_none()
                        && checkpoint.is_none()
                        && options.expected_state.is_none()
                        && options.operation_id.is_none() => {}
                Action::DryRun
                    if artifact.is_none()
                        && checkpoint.is_none()
                        && options.expected_state.is_none()
                        && options.operation_id.is_none() => {}
                Action::Apply
                    if artifact.is_some() && evidence.is_some() && checkpoint.is_some() => {}
                _ => return Err(invalid()),
            }
            Selection::Npm(options)
        }
    } else {
        return Err(invalid());
    };
    if !flags.is_empty() {
        return Err(invalid());
    }
    Ok(Arguments {
        action,
        config,
        output,
        selection,
        artifact,
        evidence,
        checkpoint,
        connect_readiness,
    })
}
fn hash(v: &str) -> bool {
    v.starts_with("blake3:") && devres_adapters::integrity::valid_hash(v)
}
pub fn private_path(p: &std::path::Path) -> Result<()> {
    if !p.is_absolute()
        || !p.starts_with("/tmp")
        || p.parent() == Some(std::path::Path::new("/tmp"))
        || p.components().any(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(invalid());
    }
    Ok(())
}
/// Admit the optional phase sink before full parsing, so parse failures can be
/// observed. Invalid/missing telemetry remains disabled and never changes outcome.
pub fn diagnostics(
    args: &[String],
) -> devres_adapters::collection_recovery::diagnostics::Diagnostics {
    use devres_adapters::collection_recovery::diagnostics::Diagnostics;
    let paths: Vec<_> = args
        .get(3..)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .filter(|pair| pair[0] == "--phase-file")
        .map(|pair| std::path::Path::new(&pair[1]))
        .collect();
    if paths.len() == 1 && private_path(paths[0]).is_ok() {
        Diagnostics::open(paths[0])
    } else {
        Diagnostics::default()
    }
}
pub fn write_report(file: std::fs::File, report: &impl serde::Serialize) -> Result<()> {
    write_report_with_diagnostics(file, report, &Default::default())
}
pub fn write_report_with_diagnostics(
    mut file: std::fs::File,
    report: &impl serde::Serialize,
    diagnostics: &devres_adapters::collection_recovery::diagnostics::Diagnostics,
) -> Result<()> {
    write_report_to(&mut file, report, diagnostics, |file| file.sync_all())
}
fn write_report_to<W: std::io::Write>(
    file: &mut W,
    report: &impl serde::Serialize,
    diagnostics: &devres_adapters::collection_recovery::diagnostics::Diagnostics,
    sync: impl FnOnce(&mut W) -> std::io::Result<()>,
) -> Result<()> {
    use devres_adapters::collection_recovery::diagnostics::{Phase, Reason};
    diagnostics.start(Phase::ReportSerialize);
    let bytes = serde_json::to_vec_pretty(report).map_err(|_| {
        diagnostics.fail(Phase::ReportSerialize, Reason::Invalid);
        invalid()
    })?;
    if bytes.len() > 1024 * 1024 {
        diagnostics.fail(Phase::ReportSerialize, Reason::Capacity);
        return Err(Error::capacity("Recovery report exceeds its bound."));
    }
    diagnostics.ok(Phase::ReportSerialize);
    diagnostics.start(Phase::ReportWrite);
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|error| {
            diagnostics.fail(Phase::ReportWrite, Reason::io(&error));
            Error::unavailable("Recovery report publication failed.")
        })?;
    diagnostics.ok(Phase::ReportWrite);
    diagnostics.start(Phase::ReportSync);
    sync(file).map_err(|error| {
        diagnostics.fail(Phase::ReportSync, Reason::io(&error));
        Error::unavailable("Recovery report publication failed.")
    })?;
    diagnostics.ok(Phase::ReportSync);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(action: &str, extra: &[&str]) -> Vec<String> {
        [
            "recover-collection",
            action,
            "private.toml",
            "--provider",
            "npm",
            "--output",
            "/tmp/owned/new.json",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn rejects_ambiguous_mutations_before_config_io() {
        for action in ["apply", "verify-evidence", "run"] {
            assert!(parse(&args(action, &[])).is_err());
        }
        let id = format!("blake3:{}", "a".repeat(64));
        let base = [
            "--job-id",
            &id,
            "--revision",
            "1",
            "--recipe",
            devres_adapters::collection_recovery::NPM_RECOVERY_RECIPE,
        ];
        assert!(parse(&args("dry-run", &base)).is_ok());
        for extra in [
            ["--revision", "2"],
            ["--unknown", "anything"],
            ["--output", "/tmp/report.json"],
            ["--artifact", "https://example.test/export"],
        ] {
            let mut v = args("dry-run", &base);
            v.extend(extra.map(str::to_owned));
            assert!(parse(&v).is_err());
        }
        assert!(
            parse(&args(
                "run",
                &["--operation-id", &id, "--artifact", "/tmp/owned/export"]
            ))
            .is_ok()
        );
    }
    #[test]
    fn rfc_has_no_apply_path_without_registered_recipe() {
        let mut v = args("apply", &[]);
        v[4] = "rfc".into();
        assert!(parse(&v).is_err());
    }
    #[test]
    fn telemetry_is_separate_and_only_admitted_for_readonly_npm() {
        let id = format!("blake3:{}", "a".repeat(64));
        let base = [
            "--job-id",
            &id,
            "--revision",
            "1",
            "--recipe",
            devres_adapters::collection_recovery::NPM_RECOVERY_RECIPE,
            "--phase-file",
            "/tmp/phases/status",
        ];
        assert!(parse(&args("dry-run", &base)).is_ok());
        let mut same_parent = args("dry-run", &base);
        *same_parent.last_mut().unwrap() = "/tmp/owned/status".into();
        assert!(parse(&same_parent).is_err());
        assert!(parse(&args("apply", &base)).is_err());
    }
    #[test]
    fn connect_readiness_is_an_explicit_npm_dry_run_option() {
        let id = format!("blake3:{}", "a".repeat(64));
        let base = [
            "--job-id",
            &id,
            "--revision",
            "1",
            "--recipe",
            devres_adapters::collection_recovery::NPM_RECOVERY_RECIPE,
        ];
        assert!(!parse(&args("dry-run", &base)).unwrap().connect_readiness);
        let mut ready = args("dry-run", &base);
        ready.extend(["--connect-readiness", "wait"].map(str::to_owned));
        assert!(parse(&ready).unwrap().connect_readiness);
        for action in ["verify-evidence", "apply", "run"] {
            let mut rejected = ready.clone();
            rejected[1] = action.into();
            assert!(parse(&rejected).is_err());
        }
        let mut rejected = ready.clone();
        rejected[4] = "rfc".into();
        assert!(parse(&rejected).is_err());
        let mut duplicate = ready.clone();
        duplicate.extend(["--connect-readiness", "wait"].map(str::to_owned));
        assert!(parse(&duplicate).is_err());
        *ready.last_mut().unwrap() = "forever".into();
        assert!(parse(&ready).is_err());
    }
    #[test]
    fn real_report_write_and_sync_failures_have_distinct_closed_phases() {
        use devres_adapters::collection_recovery::diagnostics::Diagnostics;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        for fail_write in [true, false] {
            let root = tempfile::tempdir_in("/tmp").unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = root.path().join("status");
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            let diagnostics = Diagnostics::open(&path);
            let mut bytes = Vec::new();
            let result = if fail_write {
                // /dev/full returns a genuine write error, without modifying a file.
                let mut full = std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/full")
                    .unwrap();
                write_report_to(
                    &mut full,
                    &serde_json::json!({"outcome":"fixture"}),
                    &diagnostics,
                    |_| panic!("sync must not run after write failure"),
                )
            } else {
                write_report_to(
                    &mut bytes,
                    &serde_json::json!({"outcome":"fixture"}),
                    &diagnostics,
                    |_| Err(std::io::Error::other("secret sync detail")),
                )
            };
            assert_eq!(result.unwrap_err().code, "unavailable");
            let phases = std::fs::read_to_string(&path).unwrap();
            assert!(phases.contains(if fail_write {
                "report_write\terror\tio"
            } else {
                "report_sync\terror\tio"
            }));
            assert!(!phases.contains("secret"));
            if !fail_write {
                assert!(!bytes.is_empty());
            }
        }
    }
}
