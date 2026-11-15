//! Optional private diagnostics for the native probe, never an acceptance substitute.
use devres_server::{ServerError, framing::FrameProgress};
use serde::Serialize;
use std::{cell::RefCell, fs::File, io::Write, path::Path, time::Instant};

const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVENTS: usize = 8192;
const MAX_OPERATIONS: u32 = 4096;

tokio::task_local! {
    pub static TRACE: RefCell<Trace>;
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Setup,
    Connect,
    OpenStream,
    InitializedNotificationWrite,
    Write,
    Read,
    Decode,
    MatchResponse,
    Assertions,
    Shutdown,
    Complete,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Begin,
    Ready,
    Failed,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ResultCode {
    Ok,
    TimedOut,
    InvalidData,
    OutOfMemory,
    Closed,
    Io,
    Json,
    Assertion,
    Other,
}

#[derive(Serialize)]
struct Entry<'a> {
    version: u8,
    operation: u32,
    label: &'a str,
    stage: Stage,
    event: Event,
    result: ResultCode,
    elapsed_micros: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    frame: Option<FrameProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_frame_bytes: Option<usize>,
}

pub struct Trace {
    file: File,
    started: Instant,
    operation: u32,
    label: String,
    stage: Stage,
    bytes: usize,
    events: usize,
    terminal: bool,
}

impl Trace {
    pub fn create(path: &Path) -> Result<Self, ServerError> {
        let file = devres_adapters::create_diagnosis_output(path)
            .map_err(|_| "diagnostic output unavailable")?;
        Ok(Self {
            file,
            started: Instant::now(),
            operation: 0,
            label: "session".into(),
            stage: Stage::Setup,
            bytes: 0,
            events: 0,
            terminal: false,
        })
    }

    fn append(
        &mut self,
        stage: Stage,
        event: Event,
        result: ResultCode,
        frame: Option<FrameProgress>,
        completed_frame_bytes: Option<usize>,
    ) -> Result<(), ServerError> {
        let entry = Entry {
            version: 1,
            operation: self.operation,
            label: &self.label,
            stage,
            event,
            result,
            elapsed_micros: u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX),
            frame,
            completed_frame_bytes,
        };
        let mut bytes = serde_json::to_vec(&entry).map_err(|_| "diagnostic encoding failed")?;
        bytes.push(b'\n');
        if self.events >= MAX_EVENTS || bytes.len() > MAX_BYTES.saturating_sub(self.bytes) {
            return Err("diagnostic trace capacity exhausted".into());
        }
        // Charge attempted bytes even after a partial write, so a failing sink
        // cannot reopen space in the trace budget.
        self.bytes += bytes.len();
        self.events += 1;
        self.stage = stage;
        let written = self.file.write_all(&bytes);
        self.terminal = matches!(event, Event::Failed) || written.is_err();
        written.map_err(|_| "diagnostic output unavailable".into())
    }
}

pub fn operation(label: impl FnOnce() -> String) -> Result<(), ServerError> {
    with_trace(|trace| {
        let label = label();
        let allowed = matches!(
            label.as_str(),
            "initialize"
                | "server/discover"
                | "tools/list"
                | "resources/read"
                | "tools/call unlisted-tool"
                | "unlisted-method"
        ) || label.strip_prefix("tools/call ").is_some_and(|name| {
            serde_json::from_str::<Vec<String>>(include_str!("../../../tests/tool-names.json"))
                .is_ok_and(|inventory| inventory.iter().any(|allowed| allowed == name))
        });
        if !allowed {
            return Err("diagnostic label refused".into());
        }
        if trace.operation >= MAX_OPERATIONS {
            return Err("diagnostic operation capacity exhausted".into());
        }
        trace.operation += 1;
        trace.label = label;
        Ok(())
    })
}

fn with_trace(
    action: impl FnOnce(&mut Trace) -> Result<(), ServerError>,
) -> Result<(), ServerError> {
    TRACE
        .try_with(|trace| action(&mut trace.borrow_mut()))
        .unwrap_or(Ok(()))
}

pub fn mark(stage: Stage, event: Event) -> Result<(), ServerError> {
    with_trace(|trace| trace.append(stage, event, ResultCode::Ok, None, None))
}

pub fn frame_ready(bytes: usize) -> Result<(), ServerError> {
    with_trace(|trace| trace.append(Stage::Read, Event::Ready, ResultCode::Ok, None, Some(bytes)))
}

pub fn read_failed(progress: FrameProgress, error: Option<&std::io::Error>) {
    let code = error.map_or(ResultCode::Closed, io_code);
    let _ =
        with_trace(|trace| trace.append(Stage::Read, Event::Failed, code, Some(progress), None));
}

pub fn failed(error: &(dyn std::error::Error + Send + Sync + 'static)) {
    let _ = with_trace(|trace| {
        if trace.terminal {
            return Ok(());
        }
        let code = if let Some(error) = error.downcast_ref::<std::io::Error>() {
            io_code(error)
        } else if error.is::<tokio::time::error::Elapsed>() {
            ResultCode::TimedOut
        } else if error.is::<serde_json::Error>() {
            ResultCode::Json
        } else if matches!(trace.stage, Stage::Assertions) {
            ResultCode::Assertion
        } else {
            ResultCode::Other
        };
        trace.append(trace.stage, Event::Failed, code, None, None)
    });
}

fn io_code(error: &std::io::Error) -> ResultCode {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::TimedOut => ResultCode::TimedOut,
        ErrorKind::InvalidData => ResultCode::InvalidData,
        ErrorKind::OutOfMemory => ResultCode::OutOfMemory,
        ErrorKind::UnexpectedEof | ErrorKind::BrokenPipe | ErrorKind::ConnectionReset => {
            ResultCode::Closed
        }
        _ => ResultCode::Io,
    }
}

#[cfg(test)]
mod tests;
