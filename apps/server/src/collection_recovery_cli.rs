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
        ) || value.starts_with('-')
            || flags.insert(flag, value.clone()).is_some()
        {
            return Err(invalid());
        }
        i += 2;
    }
    let config = PathBuf::from(&args[2]);
    let provider = flags.remove("--provider").ok_or_else(invalid)?;
    let output = PathBuf::from(flags.remove("--output").ok_or_else(invalid)?);
    private_path(&output)?;
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
pub fn write_report(mut file: std::fs::File, report: &impl serde::Serialize) -> Result<()> {
    use std::io::Write;
    let bytes = serde_json::to_vec_pretty(report).map_err(|_| invalid())?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error::capacity("Recovery report exceeds its bound."));
    }
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| Error::unavailable("Recovery report publication failed."))
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
}
