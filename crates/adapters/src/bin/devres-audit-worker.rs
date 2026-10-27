//! Private fixed analysis helper. Never executes inspected package code.
fn main() -> std::process::ExitCode {
    if devres_adapters::rustsec::audit_worker_main().is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
