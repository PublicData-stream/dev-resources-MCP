//! Exact offline recovery; never registers a public tool or starts collection.
use devres_adapters::{RustSecRecoveryOptions, RustSecRecoveryReport};
use devres_domain::{Error, Result};
use std::{io::Write, path::PathBuf};

pub struct Arguments {
    pub config: PathBuf,
    pub output: PathBuf,
    pub options: RustSecRecoveryOptions,
    pub apply: bool,
}

pub fn parse(args: &[String]) -> Result<Arguments> {
    let invalid = || {
        Error::invalid(
            "usage: devres-server recover-rustsec-attribution CONFIG.toml --target ID --output /tmp/PRIVATE-DIRECTORY/report.json [--apply --expected-state HASH --policy-epoch N --policy-fingerprint FINGERPRINT --repair-version VERSION]",
        )
    };
    if args.len() < 2 || args[0] != "recover-rustsec-attribution" || args[1].starts_with('-') {
        return Err(invalid());
    }
    let mut options = RustSecRecoveryOptions::default();
    let (mut target, mut expected, mut epoch, mut fingerprint, mut recipe, mut output, mut apply) =
        (None, None, None, None, None, None, false);
    let mut index = 2;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        if flag == "--apply" && !apply {
            apply = true;
            continue;
        }
        let value = args.get(index).ok_or_else(invalid)?;
        index += 1;
        match flag {
            "--target" if target.is_none() => target = Some(value.clone()),
            "--expected-state" if expected.is_none() => expected = Some(value.clone()),
            "--policy-epoch" if epoch.is_none() => {
                epoch = Some(value.parse::<u32>().map_err(|_| invalid())?)
            }
            "--policy-fingerprint" if fingerprint.is_none() => fingerprint = Some(value.clone()),
            "--repair-version" if recipe.is_none() => recipe = Some(value.clone()),
            "--output" if output.is_none() => output = Some(PathBuf::from(value)),
            _ => return Err(invalid()),
        }
    }
    if apply && (expected.is_none() || epoch.is_none() || fingerprint.is_none() || recipe.is_none())
    {
        return Err(invalid());
    }
    options.target_id = target.ok_or_else(invalid)?;
    options.expected_state = expected;
    if let Some(epoch) = epoch {
        options.policy_epoch = epoch;
    }
    if let Some(fingerprint) = fingerprint {
        options.policy_fingerprint = fingerprint;
    }
    if let Some(recipe) = recipe {
        options.repair_version = recipe;
    }
    options.validate(apply)?;
    let output = output.ok_or_else(invalid)?;
    // The descriptor-based output opener validates private ownership and rejects symlinks.
    if !output.starts_with("/tmp")
        || output.parent() == Some(std::path::Path::new("/tmp"))
        || output.components().any(|part| {
            !matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(invalid());
    }
    Ok(Arguments {
        config: PathBuf::from(&args[1]),
        output,
        options,
        apply,
    })
}

pub fn write_report(mut file: std::fs::File, report: &RustSecRecoveryReport) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report)
        .map_err(|_| Error::integrity("Invalid recovery report."))?;
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
    fn args(extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "recover-rustsec-attribution".into(),
            "missing.toml".into(),
            "--target".into(),
            format!("blake3:{}", "a".repeat(64)),
            "--output".into(),
            "/tmp/recovery-private/report.json".into(),
        ];
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        args
    }
    #[test]
    fn apply_requires_exact_explicit_guards_before_config_io() {
        assert!(parse(&args(&[])).is_ok());
        for extra in [
            &["--apply"][..],
            &["--apply", "--apply"],
            &["--target", "bad"],
            &["--unknown", "x"],
            &["--output", "/tmp/report.json"],
        ] {
            assert!(parse(&args(extra)).is_err());
        }
        let digest = format!("blake3:{}", "b".repeat(64));
        let extra = [
            "--apply",
            "--expected-state",
            digest.as_str(),
            "--policy-epoch",
            "1",
            "--policy-fingerprint",
            devres_domain::attribution::ATTRIBUTION_POLICY_FINGERPRINT,
            "--repair-version",
            devres_adapters::RUSTSEC_CAPTURE_REPAIR_VERSION,
        ];
        assert!(parse(&args(&extra)).unwrap().apply);
        let mut wrong = extra;
        wrong[4] = "--wrong-policy";
        assert!(parse(&args(&wrong)).is_err());
    }
}
