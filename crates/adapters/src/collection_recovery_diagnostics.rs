//! Optional closed offline assessment phases. Never formats an error or payload.
use devres_domain::Error;
use std::{fs::File, io::Write, path::Path, sync::Mutex, time::Instant};

pub const MAX_PHASE_BYTES: usize = 3072;
pub const MAX_PHASE_EVENTS: usize = 48;
const CLI_BYTES: usize = 2304;
const CLI_EVENTS: usize = 40;
/// Kubelet supplies this writable bind mount separately from the private file.
pub const TERMINATION_FILE: &str = "/tmp/devres-assessment-termination";

#[derive(Clone, Copy)]
pub enum Phase {
    Parse,
    OutputCreate,
    ConfigLoad,
    SqlConnect,
    SqlConnectRetry,
    SqlSetup,
    Lifecycle,
    Schema,
    Policy,
    Transaction,
    HistorySelect,
    StateSelect,
    Eligibility,
    Rollback,
    ReportSerialize,
    ReportWrite,
    ReportSync,
}
impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::OutputCreate => "output_create",
            Self::ConfigLoad => "config_load",
            Self::SqlConnect => "sql_connect",
            Self::SqlConnectRetry => "sql_connect_retry",
            Self::SqlSetup => "sql_setup",
            Self::Lifecycle => "lifecycle",
            Self::Schema => "schema",
            Self::Policy => "policy",
            Self::Transaction => "transaction",
            Self::HistorySelect => "history_select",
            Self::StateSelect => "state_select",
            Self::Eligibility => "eligibility",
            Self::Rollback => "rollback",
            Self::ReportSerialize => "report_serialize",
            Self::ReportWrite => "report_write",
            Self::ReportSync => "report_sync",
        }
    }
}
#[derive(Clone, Copy)]
pub enum Reason {
    None,
    Invalid,
    Unavailable,
    Permission,
    Authentication,
    Connection,
    Timeout,
    Cancelled,
    LockBusy,
    Schema,
    Integrity,
    Missing,
    Io,
    Capacity,
    Unknown,
}
impl Reason {
    fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Invalid => "invalid",
            Self::Unavailable => "unavailable",
            Self::Permission => "permission",
            Self::Authentication => "authentication",
            Self::Connection => "connection",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::LockBusy => "lock_busy",
            Self::Schema => "schema",
            Self::Integrity => "integrity",
            Self::Missing => "missing",
            Self::Io => "io",
            Self::Capacity => "capacity",
            Self::Unknown => "unknown",
        }
    }
    pub fn domain(error: &Error) -> Self {
        match error.code.as_str() {
            "invalid_input" | "invalid_argument" | "invalid" => Self::Invalid,
            "unavailable" => Self::Unavailable,
            "integrity" | "integrity_error" => Self::Integrity,
            "not_found" => Self::Missing,
            "capacity" | "capacity_exceeded" => Self::Capacity,
            _ => Self::Unknown,
        }
    }
    pub fn io(error: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        match error.kind() {
            ErrorKind::PermissionDenied => Self::Permission,
            ErrorKind::NotFound => Self::Missing,
            ErrorKind::TimedOut => Self::Timeout,
            ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected => Self::Connection,
            _ => Self::Io,
        }
    }
    pub fn sql(error: &sqlx_core::Error) -> Self {
        match error {
            sqlx_core::Error::Database(value) => match value.code().as_deref() {
                Some("28P01" | "28000") => Self::Authentication,
                Some("42501") => Self::Permission,
                Some("57014") => Self::Timeout,
                Some("55P03" | "40P01") => Self::LockBusy,
                Some("08000" | "08001" | "08003" | "08006" | "57P01") => Self::Connection,
                _ => Self::Unavailable,
            },
            sqlx_core::Error::Io(value) => Self::io(value),
            sqlx_core::Error::RowNotFound => Self::Missing,
            _ => Self::Unavailable,
        }
    }
}
struct Sink {
    file: File,
    termination: Option<File>,
    bytes: usize,
    events: usize,
    failed: bool,
}
pub struct Diagnostics {
    sink: Option<Mutex<Sink>>,
    start: Instant,
}
impl Default for Diagnostics {
    fn default() -> Self {
        Self {
            sink: None,
            start: Instant::now(),
        }
    }
}
impl Diagnostics {
    /// The wrapper creates this separate private file. Failure disables observation,
    /// preserving the original assessment result and report create-new semantics.
    pub fn open(path: &Path) -> Self {
        Self {
            sink: open_private(path).ok().map(|file| {
                Mutex::new(Sink {
                    file,
                    termination: open_termination().ok(),
                    bytes: 0,
                    events: 0,
                    failed: false,
                })
            }),
            start: Instant::now(),
        }
    }
    pub fn start(&self, phase: Phase) {
        self.record(phase, "start", Reason::None);
    }
    pub fn ok(&self, phase: Phase) {
        self.record(phase, "ok", Reason::None);
    }
    pub fn fail(&self, phase: Phase, reason: Reason) {
        self.record(phase, "error", reason);
    }
    pub fn domain<T>(
        &self,
        phase: Phase,
        result: devres_domain::Result<T>,
    ) -> devres_domain::Result<T> {
        match &result {
            Ok(_) => self.ok(phase),
            Err(error) => self.fail(phase, Reason::domain(error)),
        }
        result
    }
    fn record(&self, phase: Phase, outcome: &'static str, reason: Reason) {
        let Some(sink) = &self.sink else {
            return;
        };
        let Ok(mut sink) = sink.lock() else {
            return;
        };
        if sink.failed {
            return;
        }
        let millis = self.start.elapsed().as_millis().min(i64::MAX as u128);
        let row = format!(
            "1\t{}\t{outcome}\t{}\t{millis}\t-\n",
            phase.label(),
            reason.label()
        );
        if sink.events >= CLI_EVENTS || sink.bytes + row.len() > CLI_BYTES {
            sink.failed = true;
            return;
        }
        // Charge before writing; a failed or partial record is never retried.
        sink.events += 1;
        sink.bytes += row.len();
        if sink.file.write_all(row.as_bytes()).is_err() {
            sink.failed = true;
        }
        if let Some(file) = &mut sink.termination
            && file.write_all(row.as_bytes()).is_err()
        {
            sink.termination = None;
        }
    }
}
fn open_termination() -> std::io::Result<File> {
    use nix::{
        fcntl::{OFlag, open},
        sys::stat::{Mode, SFlag, fstat},
    };
    let fd = open(
        Path::new(TERMINATION_FILE),
        OFlag::O_WRONLY
            | OFlag::O_APPEND
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK
            | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    let info = fstat(&fd)?;
    if SFlag::from_bits_truncate(info.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || info.st_nlink != 1
        || info.st_size < 0
        || info.st_size > 768
    {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    Ok(File::from(fd))
}
fn open_private(path: &Path) -> std::io::Result<File> {
    use nix::{
        fcntl::{OFlag, open, openat},
        sys::stat::{Mode, SFlag, fstat},
    };
    use std::io::{Error as IoError, ErrorKind};
    let refused = || IoError::from(ErrorKind::PermissionDenied);
    let parts = path
        .strip_prefix("/tmp")
        .map_err(|_| refused())?
        .components()
        .map(|part| match part {
            std::path::Component::Normal(name) => Ok(name),
            _ => Err(refused()),
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    if parts.len() < 2 {
        return Err(refused());
    }
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut dir = open(Path::new("/tmp"), flags, Mode::empty())?;
    for name in &parts[..parts.len() - 1] {
        dir = openat(&dir, *name, flags, Mode::empty())?;
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|uid| uid.parse::<u32>().ok())
        .ok_or_else(refused)?;
    let parent = fstat(&dir)?;
    if parent.st_uid != uid || parent.st_mode & 0o077 != 0 {
        return Err(refused());
    }
    let fd = openat(
        &dir,
        parts[parts.len() - 1],
        OFlag::O_WRONLY
            | OFlag::O_APPEND
            | OFlag::O_NONBLOCK
            | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    let info = fstat(&fd)?;
    if info.st_uid != uid
        || info.st_mode & 0o777 != 0o600
        || info.st_nlink != 1
        || SFlag::from_bits_truncate(info.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || info.st_size < 0
        || info.st_size > 768
    {
        return Err(refused());
    }
    Ok(File::from(fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::Builder::new()
            .prefix("recovery-phases-")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("status");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        (dir, path)
    }
    #[test]
    fn bounded_closed_records_preserve_failure_without_payloads() {
        let (_dir, path) = fixture();
        let diagnostics = Diagnostics::open(&path);
        diagnostics.start(Phase::ConfigLoad);
        assert!(
            diagnostics
                .domain::<()>(Phase::Parse, Err(Error::invalid("private option")))
                .is_err()
        );
        let error = Error::unavailable("secret=password; supplied lockfile marker");
        assert!(
            diagnostics
                .domain::<()>(Phase::ConfigLoad, Err(error))
                .is_err()
        );
        for _ in 0..100 {
            diagnostics.ok(Phase::HistorySelect);
        }
        let body = std::fs::read_to_string(path).unwrap();
        assert!(body.len() <= CLI_BYTES && body.lines().count() <= CLI_EVENTS);
        assert!(body.contains("config_load\terror\tunavailable"));
        assert!(body.contains("parse\terror\tinvalid"));
        assert!(!body.contains("secret") && !body.contains("lockfile"));
    }
    #[test]
    fn refuses_symlink_hardlink_shared_parent_and_special_output() {
        let (dir, path) = fixture();
        let alias = dir.path().join("alias");
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(open_private(&path).is_err());
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(open_private(&alias).is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(open_private(&path).is_err());
        assert!(open_private(Path::new("/dev/null")).is_err());
    }
    #[test]
    fn telemetry_failure_does_not_change_domain_result() {
        let diagnostics = Diagnostics::open(Path::new("/tmp/nonexistent-recovery-parent/status"));
        let error = Error::unavailable("private");
        let returned = diagnostics
            .domain::<()>(Phase::SqlConnect, Err(error.clone()))
            .unwrap_err();
        assert_eq!(returned.code, error.code);
        assert_eq!(returned.message, error.message);
    }
}
