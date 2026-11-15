//! Local evidence-only errata packaging inspection. No configuration or provider client.
use devres_domain::{Error, Result};
use std::path::PathBuf;
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
    if !bundle.is_absolute()
        || !bundle.starts_with("/tmp")
        || bundle == std::path::Path::new("/tmp")
        || bundle.components().any(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
