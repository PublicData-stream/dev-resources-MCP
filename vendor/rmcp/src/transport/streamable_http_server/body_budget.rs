//! Optional first-party transport allocation accounting. Protocol handling is unchanged.
//!
//! First-party additions: AGPL-3.0-only. Upstream rmcp remains Apache-2.0.
//! Reservations follow Bytes owners,
//! including clones and slices. This is encoded-buffer accounting, not an RSS cap.
use bytes::Bytes;
use serde::Serialize;
use std::{
    fmt,
    io::{self, Write},
    sync::Arc,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Default)]
pub struct BodyCapacityFailure(Arc<std::sync::atomic::AtomicBool>);
impl BodyCapacityFailure {
    pub fn failed(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn set(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

#[derive(Clone, Debug)]
pub struct BodyBudget {
    permits: Arc<Semaphore>,
    maximum: usize,
    cancel: CancellationToken,
}
#[derive(Clone, Copy, Debug)]
pub struct BudgetError;
impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HTTP body capacity unavailable")
    }
}
impl std::error::Error for BudgetError {}

/// A trusted collector transfers bytes produced by the same budget through this
/// explicit handoff. The SDK borrows them without a second encoded copy.
#[derive(Clone)]
pub struct ChargedRequestBody(pub(crate) Bytes);
impl fmt::Debug for ChargedRequestBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChargedRequestBody")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

struct OwnedBytes {
    bytes: Box<[u8]>,
    _permit: OwnedSemaphorePermit,
}
impl AsRef<[u8]> for OwnedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl BodyBudget {
    pub fn new(permits: Arc<Semaphore>, maximum: usize, cancel: CancellationToken) -> Self {
        Self {
            permits,
            maximum,
            cancel,
        }
    }
    pub fn maximum(&self) -> usize {
        self.maximum
    }
    pub fn reserve(&self, bytes: usize) -> Result<OwnedSemaphorePermit, BudgetError> {
        if self.cancel.is_cancelled() || bytes > self.maximum {
            return Err(BudgetError);
        }
        self.permits
            .clone()
            .try_acquire_many_owned(u32::try_from(bytes).map_err(|_| BudgetError)?)
            .map_err(|_| BudgetError)
    }
    /// Takes an exactly sized allocation and its reservation without copying.
    pub fn owned(
        &self,
        bytes: Box<[u8]>,
        permit: OwnedSemaphorePermit,
    ) -> Result<Bytes, BudgetError> {
        if bytes.len() > permit.num_permits()
            || bytes.len() > self.maximum
            || self.cancel.is_cancelled()
        {
            return Err(BudgetError);
        }
        Ok(Bytes::from_owner(OwnedBytes {
            bytes,
            _permit: permit,
        }))
    }
    /// The caller must use bytes returned by this budget's `owned` or codec.
    /// This trusted integration seam cannot be populated by HTTP headers.
    pub fn request(&self, bytes: Bytes) -> ChargedRequestBody {
        ChargedRequestBody(bytes)
    }
    pub fn encode_json<T: Serialize + ?Sized>(&self, value: &T) -> Result<Bytes, BudgetError> {
        self.encode(|output| serde_json::to_writer(output, value).map_err(io::Error::other))
    }
    pub fn encode_display(&self, value: impl fmt::Display) -> Result<Bytes, BudgetError> {
        self.encode(|output| write!(output, "{value}"))
    }
    pub(crate) fn encode(
        &self,
        encode: impl Fn(&mut dyn Write) -> io::Result<()>,
    ) -> Result<Bytes, BudgetError> {
        let mut count = Count {
            length: 0,
            maximum: self.maximum,
        };
        encode(&mut count).map_err(|_| BudgetError)?;
        let permit = self.reserve(count.length)?;
        let mut output = Fixed {
            bytes: exact_zeroed(count.length)?,
            used: 0,
        };
        encode(&mut output).map_err(|_| BudgetError)?;
        if output.used != count.length {
            return Err(BudgetError);
        }
        self.owned(output.bytes, permit)
    }
}
struct Count {
    length: usize,
    maximum: usize,
}
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.length = self
            .length
            .checked_add(bytes.len())
            .filter(|length| *length <= self.maximum)
            .ok_or_else(|| io::Error::other(BudgetError))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Fixed {
    bytes: Box<[u8]>,
    used: usize,
}
impl Write for Fixed {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .used
            .checked_add(bytes.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| io::Error::other(BudgetError))?;
        self.bytes[self.used..end].copy_from_slice(bytes);
        self.used = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Fallible allocation with no capacity slack or shrinking copy. Global allocator
/// metadata is outside encoded capacity accounting, as for the transport pool.
pub fn exact_zeroed(length: usize) -> Result<Box<[u8]>, BudgetError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| BudgetError)?;
    if bytes.capacity() != length {
        return Err(BudgetError);
    }
    bytes.resize(length, 0);
    Ok(bytes.into_boxed_slice())
}
