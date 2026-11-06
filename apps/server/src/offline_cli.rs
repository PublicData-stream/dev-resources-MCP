//! Strict parsing before offline commands access configuration or storage.
use devres_adapters::{MigrationExecutionOptions, MigrationGraphOptions};

pub(crate) struct OfflineArgs {
    pub command: String,
    pub path: String,
    pub options: MigrationExecutionOptions,
    pub graph_options: MigrationGraphOptions,
}

pub(crate) fn parse(args: &[String]) -> Result<OfflineArgs, String> {
    let usage = "usage: devres-server migrate-storage CONFIG.toml --to blake3 | verify-storage CONFIG.toml | activate-storage CONFIG.toml [--workers N] [--payload-budget-mib N] [--graph-memory-budget-mib N]";
    if args.len() < 2
        || !matches!(
            args[0].as_str(),
            "migrate-storage" | "verify-storage" | "activate-storage"
        )
        || args[1].starts_with('-')
    {
        return Err(usage.into());
    }
    let mut options = MigrationExecutionOptions::default();
    let mut graph_options = MigrationGraphOptions::default();
    let (mut workers, mut budget, mut graph_budget, mut to) = (false, false, false, false);
    let mut remaining = &args[2..];
    while !remaining.is_empty() {
        if remaining.len() < 2 {
            return Err(usage.into());
        }
        let value = &remaining[1];
        match remaining[0].as_str() {
            "--to" if args[0] == "migrate-storage" && !to && value == "blake3" => to = true,
            "--workers" if !workers => {
                options.workers = integer(value)?;
                workers = true;
            }
            "--payload-budget-mib" if !budget => {
                options.payload_budget_bytes = integer(value)?
                    .checked_mul(1024 * 1024)
                    .ok_or("offline payload budget overflow")?;
                budget = true;
            }
            "--graph-memory-budget-mib" if !graph_budget => {
                graph_options.memory_budget_bytes = integer(value)?
                    .checked_mul(1024 * 1024)
                    .ok_or("offline graph memory budget overflow")?;
                graph_budget = true;
            }
            _ => return Err(usage.into()),
        }
        remaining = &remaining[2..];
    }
    if args[0] == "migrate-storage" && !to {
        return Err(usage.into());
    }
    let options = MigrationExecutionOptions::new(options.workers, options.payload_budget_bytes)
        .map_err(|_| "invalid offline execution options")?;
    let graph_options = MigrationGraphOptions::new(graph_options.memory_budget_bytes)
        .map_err(|_| "invalid offline graph execution options")?;
    Ok(OfflineArgs {
        command: args[0].clone(),
        path: args[1].clone(),
        options,
        graph_options,
    })
}

fn integer(value: &str) -> Result<usize, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid offline option integer".into());
    }
    value
        .parse()
        .map_err(|_| "offline option integer overflow".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(value: &str) -> Vec<String> {
        value.split_whitespace().map(str::to_owned).collect()
    }
    #[test]
    fn legacy_and_options_are_accepted() {
        for command in [
            "migrate-storage missing.toml --to blake3",
            "verify-storage missing.toml",
            "activate-storage missing.toml",
        ] {
            assert!(parse(&args(command)).is_ok());
        }
        let parsed = parse(&args(
            "migrate-storage missing.toml --workers 64 --to blake3 --payload-budget-mib 1",
        ))
        .unwrap();
        assert_eq!(parsed.options.workers, 64);
        assert_eq!(parsed.options.payload_budget_bytes, 1024 * 1024);
        assert_eq!(parsed.graph_options.memory_budget_bytes, 1024 * 1024 * 1024);
        for command in [
            "migrate-storage missing.toml --to blake3 --graph-memory-budget-mib 7",
            "verify-storage missing.toml --graph-memory-budget-mib 7",
            "activate-storage missing.toml --graph-memory-budget-mib 7",
        ] {
            assert_eq!(
                parse(&args(command))
                    .unwrap()
                    .graph_options
                    .memory_budget_bytes,
                7 * 1024 * 1024
            );
        }
    }
    #[test]
    fn invalid_options_fail_without_opening_the_missing_configuration() {
        for command in [
            "migrate-storage missing.toml",
            "verify-storage missing.toml --to blake3",
            "verify-storage missing.toml --workers",
            "verify-storage missing.toml --workers 0",
            "verify-storage missing.toml --workers 65",
            "verify-storage missing.toml --workers +2",
            "verify-storage missing.toml --workers 2 --workers 2",
            "verify-storage missing.toml --unknown 1",
            "verify-storage missing.toml --payload-budget-mib 0",
            "verify-storage missing.toml --payload-budget-mib -1",
            "verify-storage missing.toml --payload-budget-mib 999999999999999999999999",
            "verify-storage missing.toml --payload-budget-mib 18446744073709551615",
            "verify-storage missing.toml --payload-budget-mib 1 --payload-budget-mib 1",
            "migrate-storage missing.toml --to blake3 --to blake3",
            "verify-storage missing.toml --graph-memory-budget-mib",
            "verify-storage missing.toml --graph-memory-budget-mib 0",
            "verify-storage missing.toml --graph-memory-budget-mib -1",
            "verify-storage missing.toml --graph-memory-budget-mib +1",
            "verify-storage missing.toml --graph-memory-budget-mib 18446744073709551615",
            "verify-storage missing.toml --graph-memory-budget-mib 999999999999999999999999",
            "verify-storage missing.toml --graph-memory-budget-mib 1 --graph-memory-budget-mib 1",
        ] {
            assert!(parse(&args(command)).is_err(), "{command}");
        }
    }
}
