// Adapted from OpenLegal 7a592e0c (AGPL-3.0-only); first-party bounded replay changes are AGPL-3.0-only.
//! Inspect the first SDK SSE event through charged slices, without a second body.
use axum::{
    body::{Body, BodyDataStream, Bytes},
    http::{StatusCode, header, response::Parts},
    response::{IntoResponse, Response},
};
use futures::{StreamExt, stream};
use rmcp::transport::streamable_http_server::{BodyBudget, BodyCapacityFailure};
use serde::Deserialize;
use std::{
    io::{self, Read},
    ops::Range,
};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct FirstData {
    position: usize,
    line: usize,
    head: [u8; 6],
    head_used: usize,
    data: Option<Range<usize>>,
    multiline: bool,
    previous: Option<u8>,
}
impl FirstData {
    fn scan(&mut self, bytes: &[u8]) -> Option<Option<Range<usize>>> {
        for &byte in bytes {
            let position = self.position;
            self.position += 1;
            if byte == b'\n' {
                let end = position - usize::from(self.previous == Some(b'\r'));
                let length = end - self.line;
                if length == 0 {
                    if let Some(data) = self.data.take() {
                        return Some((!self.multiline).then_some(data));
                    }
                } else if self.head_used >= 5 && &self.head[..5] == b"data:" {
                    let start = self.line + 5 + usize::from(length > 5 && self.head[5] == b' ');
                    self.multiline |= self.data.is_some();
                    self.data = Some(start..end);
                }
                self.line = self.position;
                self.head_used = 0;
            } else if self.head_used < self.head.len() {
                self.head[self.head_used] = byte;
                self.head_used += 1;
            }
            self.previous = Some(byte);
        }
        None
    }
}
#[derive(Deserialize)]
struct ErrorCode {
    code: i32,
}
#[derive(Deserialize)]
struct ErrorHeader {
    jsonrpc: String,
    #[serde(rename = "id")]
    _id: serde::de::IgnoredAny,
    error: ErrorCode,
}
struct SliceReader<'a> {
    parts: &'a [Bytes],
    range: Range<usize>,
    position: usize,
    index: usize,
}
impl Read for SliceReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        while let Some(bytes) = self.parts.get(self.index) {
            let end = self.position + bytes.len();
            if self.range.start >= end {
                self.position = end;
                self.index += 1;
                continue;
            }
            if self.range.start >= self.range.end {
                return Ok(0);
            }
            let start = self.range.start - self.position;
            let count = output
                .len()
                .min(bytes.len() - start)
                .min(self.range.end - self.range.start);
            output[..count].copy_from_slice(&bytes[start..start + count]);
            self.range.start += count;
            return Ok(count);
        }
        Ok(0)
    }
}
fn invalid_params(parts: &[Bytes], range: Range<usize>) -> bool {
    let reader = SliceReader {
        parts,
        range,
        position: 0,
        index: 0,
    };
    serde_json::from_reader::<_, ErrorHeader>(reader)
        .is_ok_and(|message| message.jsonrpc == "2.0" && message.error.code == -32602)
}
#[derive(Default)]
struct Prefix {
    parts: Vec<Bytes>,
    _permit: Option<OwnedSemaphorePermit>,
}
impl Prefix {
    fn push(&mut self, bytes: Bytes, budget: Option<&BodyBudget>) -> Result<(), ()> {
        if self.parts.len() == self.parts.capacity() {
            let capacity = self.parts.capacity().max(4).checked_mul(2).ok_or(())?;
            // Account both allocations during vector growth. Payloads themselves
            // remain owner-charged Bytes from the SDK; only handles move here.
            let permit = budget
                .map(|budget| budget.reserve(capacity * std::mem::size_of::<Bytes>()))
                .transpose()
                .map_err(|_| ())?;
            let mut next = Vec::new();
            next.try_reserve_exact(capacity).map_err(|_| ())?;
            if next.capacity() != capacity {
                return Err(());
            }
            next.append(&mut self.parts);
            self.parts = next;
            self._permit = permit;
        }
        self.parts.push(bytes);
        Ok(())
    }
    fn select(&mut self, range: Range<usize>) {
        let mut position = 0;
        self.parts.retain_mut(|bytes| {
            let end = position + bytes.len();
            let start = range.start.saturating_sub(position).min(bytes.len());
            let stop = range.end.saturating_sub(position).min(bytes.len());
            position = end;
            if start >= stop {
                return false;
            }
            *bytes = bytes.slice(start..stop);
            true
        });
    }
}
fn replay(
    parts: Parts,
    prefix: Prefix,
    deferred: Option<Result<Bytes, axum::Error>>,
    source: BodyDataStream,
) -> Response {
    let Prefix {
        parts: chunks,
        _permit,
    } = prefix;
    let first = stream::unfold(
        (chunks.into_iter(), _permit),
        |(mut chunks, permit)| async move {
            chunks
                .next()
                .map(|bytes| (Ok::<_, axum::Error>(bytes), (chunks, permit)))
        },
    );
    Response::from_parts(
        parts,
        Body::from_stream(first.chain(stream::iter(deferred)).chain(source)),
    )
}
pub(crate) async fn preserve_invalid_params_status(
    response: Response,
    modern: bool,
    limit: usize,
    deadline: Instant,
    cancel: &CancellationToken,
    budget: Option<&BodyBudget>,
) -> Response {
    if response.status() != StatusCode::OK
        || response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            != Some("text/event-stream")
    {
        return response;
    }
    let capacity = response.extensions().get::<BodyCapacityFailure>().cloned();
    let (mut parts, body) = response.into_parts();
    let mut source = body.into_data_stream();
    let mut prefix = Prefix::default();
    let mut used = 0usize;
    let mut first = FirstData::default();
    loop {
        let chunk = tokio::select! {
            biased;
            _ = cancel.cancelled() => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            result = tokio::time::timeout_at(deadline, source.next()) => match result {
                Ok(chunk) => chunk,
                Err(_) => return StatusCode::GATEWAY_TIMEOUT.into_response(),
            },
        };
        if capacity.as_ref().is_some_and(BodyCapacityFailure::failed) {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let Some(chunk) = chunk else {
            return replay(parts, prefix, None, source);
        };
        let bytes = match chunk {
            Ok(bytes) if bytes.len() <= limit - used => bytes,
            deferred => return replay(parts, prefix, Some(deferred), source),
        };
        used += bytes.len();
        let data = first.scan(&bytes);
        if prefix.push(bytes, budget).is_err() {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        if !modern {
            return replay(parts, prefix, None, source);
        }
        if let Some(data) = data {
            if let Some(data) = data.filter(|range| invalid_params(&prefix.parts, range.clone())) {
                parts.status = StatusCode::BAD_REQUEST;
                parts.headers.insert(
                    header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                );
                parts.headers.remove(header::CONTENT_LENGTH);
                prefix.select(data);
                // Only slices of the first event survive; trailing messages are
                // dropped, cancelling the SDK stream and its request owner.
                let empty = Body::empty().into_data_stream();
                return replay(parts, prefix, None, empty);
            }
            return replay(parts, prefix, None, source);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use std::time::Duration;

    fn sse(chunks: Vec<Vec<u8>>) -> Response {
        let body = Body::from_stream(stream::iter(
            chunks
                .into_iter()
                .map(|bytes| Ok::<_, io::Error>(Bytes::from(bytes))),
        ));
        Response::builder()
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(body)
            .unwrap()
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(1)
    }

    #[tokio::test]
    async fn fragmented_first_error_preserves_json_status_id_and_payload() {
        let json = br#"{"jsonrpc":"2.0","id":"request-a","error":{"code":-32602,"message":"invalid tool arguments"}}"#;
        for newline in ["\n", "\r\n"] {
            let wire = format!(
                ": keepalive{newline}{newline}event: message{newline}data: {}{newline}{newline}",
                std::str::from_utf8(json).unwrap()
            );
            let chunks = wire.as_bytes().iter().map(|b| vec![*b]).collect();
            let response = preserve_invalid_params_status(
                sse(chunks),
                true,
                1024,
                deadline(),
                &CancellationToken::new(),
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(
                to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
                json
            );
        }
    }

    #[tokio::test]
    async fn first_notification_replays_comments_and_later_error_exactly() {
        let wire = b": keepalive\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"invalid\"}}\n\n";
        let response = preserve_invalid_params_status(
            sse(vec![wire.to_vec()]),
            true,
            1024,
            deadline(),
            &CancellationToken::new(),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
            wire
        );
    }

    #[tokio::test]
    async fn legacy_other_errors_and_unsupported_framing_are_not_rewritten() {
        for (modern, wire) in [
            (
                false,
                "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602}}\n\n",
            ),
            (
                true,
                "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32603}}\n\n",
            ),
            (
                true,
                "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"error\":{\"code\":-32602}}\n\n",
            ),
        ] {
            let response = preserve_invalid_params_status(
                sse(vec![wire.as_bytes().to_vec()]),
                modern,
                1024,
                deadline(),
                &CancellationToken::new(),
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
                wire.as_bytes()
            );
        }
    }

    #[tokio::test]
    async fn prefix_ceiling_replays_the_overlimit_chunk_without_extending_probe() {
        let wire = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602}}\n\n";
        let response = preserve_invalid_params_status(
            sse(vec![wire[..4].to_vec(), wire[4..].to_vec()]),
            true,
            16,
            deadline(),
            &CancellationToken::new(),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
            wire
        );
    }

    #[tokio::test]
    async fn cancellation_and_absolute_deadline_drop_a_stalled_probe() {
        for canceled in [false, true] {
            let cancel = CancellationToken::new();
            if canceled {
                cancel.cancel();
            }
            let response = Response::builder()
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(
                    stream::pending::<Result<Bytes, io::Error>>(),
                ))
                .unwrap();
            let response = tokio::time::timeout(
                Duration::from_secs(1),
                preserve_invalid_params_status(
                    response,
                    true,
                    1024,
                    Instant::now() + Duration::from_millis(10),
                    &cancel,
                    None,
                ),
            )
            .await
            .unwrap();
            assert_eq!(
                response.status(),
                if canceled {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::GATEWAY_TIMEOUT
                }
            );
            assert!(
                to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
}
