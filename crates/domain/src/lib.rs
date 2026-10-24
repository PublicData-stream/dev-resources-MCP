//! Transport-independent public-source capture and retrieval contracts.
use serde::{Deserialize, Serialize};
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

/// Deliberately sanitized error; private diagnostics must never carry input bodies.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Error {
    pub code: String,
    pub message: String,
}
impl Error {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid_input", message)
    }
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new("unavailable", message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message)
    }
    pub fn capacity(message: impl Into<String>) -> Self {
        Self::new("capacity", message)
    }
    pub fn integrity(message: impl Into<String>) -> Self {
        Self::new("integrity", message)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for Error {}

/// Constructed by trusted provider adapters, never directly from caller URLs.
#[derive(Clone, Debug)]
pub struct FetchRequest {
    pub key: String,
    pub url: String,
    pub ttl_secs: u64,
    pub max_bytes: usize,
    pub media_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capture {
    pub id: String,
    pub key: String,
    pub source_url: String,
    pub body_hash: String,
    pub media_type: String,
    pub retrieved_at: i64,
    pub validated_at: i64,
}

#[derive(Clone, Debug)]
pub struct StoredCapture {
    pub capture: Capture,
    pub body: Body,
}

#[derive(Clone, Debug, Default)]
pub struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FetchResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub validators: Validators,
}

/// Unix seconds. Policy logic receives this through a Clock port.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

/// Shared immutable source bytes. Opaque leases keep adapter resource admission
/// alive through every clone and through caller projection, without domain I/O.
#[derive(Clone)]
pub struct Body(std::sync::Arc<BodyInner>);
struct BodyInner {
    bytes: Vec<u8>,
    _lease: Option<Box<dyn Lease>>,
}
trait Lease: Send + Sync {}
impl<T: Send + Sync> Lease for T {}
impl Body {
    pub fn with_lease(bytes: Vec<u8>, lease: impl Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(BodyInner {
            bytes,
            _lease: Some(Box::new(lease)),
        }))
    }
}
impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Self {
        Self(std::sync::Arc::new(BodyInner {
            bytes,
            _lease: None,
        }))
    }
}
impl Default for Body {
    fn default() -> Self {
        Vec::new().into()
    }
}
impl std::ops::Deref for Body {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0.bytes
    }
}
impl AsRef<[u8]> for Body {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Body")
            .field("length", &self.len())
            .finish_non_exhaustive()
    }
}
impl PartialEq for Body {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}
impl Eq for Body {}
impl<const N: usize> PartialEq<&[u8; N]> for Body {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_ref() == other.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Guard(Arc<AtomicUsize>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn body_clones_share_bytes_and_retain_resource_lease() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let body = Body::with_lease(b"public source".to_vec(), Guard(dropped.clone()));
        let clone = body.clone();
        assert_eq!(body.as_ptr(), clone.as_ptr());
        drop(body);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert_eq!(clone, b"public source");
        drop(clone);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
}
