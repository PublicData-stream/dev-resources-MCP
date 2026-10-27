//! Fixed first-party PDF text projection helper. Inspected source never executes.
fn main() -> std::process::ExitCode {
    if devres_adapters::whatwg::processing::pdf_worker_main().is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
