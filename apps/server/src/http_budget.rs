//! Capacity follows retained encoded allocations; protocol/application heaps and
//! the connection's separately bounded transport buffers are outside this ledger.
use axum::{
    body::{Body, Bytes},
    http::StatusCode,
};
use futures::StreamExt;
use rmcp::transport::streamable_http_server::BodyBudget;
use tokio::sync::OwnedSemaphorePermit;

const CHUNK: usize = 64 * 1024;

pub(crate) fn declared_length(
    headers: &http::HeaderMap,
    maximum: usize,
) -> Result<Option<usize>, StatusCode> {
    if headers.get_all(http::header::CONTENT_LENGTH).iter().count() > 1 {
        return Err(StatusCode::BAD_REQUEST);
    }
    headers
        .get(http::header::CONTENT_LENGTH)
        .map(|value| {
            let length = value
                .to_str()
                .ok()
                .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or(StatusCode::BAD_REQUEST)?;
            if length > maximum {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            Ok(length)
        })
        .transpose()
}

pub(crate) async fn collect(
    body: Body,
    declared: Option<usize>,
    initial: Option<OwnedSemaphorePermit>,
    budget: &BodyBudget,
) -> Result<Bytes, StatusCode> {
    let mut stream = body.into_data_stream();
    if let Some(length) = declared {
        let permit = initial.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let mut bytes = rmcp::transport::streamable_http_server::body_budget::exact_zeroed(length)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let mut used = 0usize;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
            let end = used
                .checked_add(chunk.len())
                .filter(|end| *end <= length)
                .ok_or(StatusCode::BAD_REQUEST)?;
            // Incoming frames are transport-owned. Charge their retained staging
            // while copying, in addition to the already reserved destination.
            let _staging = budget
                .reserve(chunk.len())
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            bytes[used..end].copy_from_slice(&chunk);
            used = end;
        }
        if used != length {
            return Err(StatusCode::BAD_REQUEST);
        }
        return budget
            .owned(bytes, permit)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE);
    }
    // Fixed-capacity blocks bound metadata even for one-byte HTTP frames. Never
    // wait while retaining a partial request: growth failure releases everything.
    let mut blocks: Vec<(Box<[u8]>, OwnedSemaphorePermit)> = Vec::new();
    let mut used = 0usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        let end = used
            .checked_add(chunk.len())
            .filter(|end| *end <= budget.maximum())
            .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
        let _staging = budget
            .reserve(chunk.len())
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let mut input = chunk.as_ref();
        while !input.is_empty() {
            if used.is_multiple_of(CHUNK) {
                let size = CHUNK.min(budget.maximum() - used);
                let permit = budget
                    .reserve(size)
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                blocks.push((
                    rmcp::transport::streamable_http_server::body_budget::exact_zeroed(size)
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
                    permit,
                ));
            }
            let block = &mut blocks.last_mut().ok_or(StatusCode::BAD_REQUEST)?.0;
            let offset = used % CHUNK;
            let count = input.len().min(block.len() - offset);
            block[offset..offset + count].copy_from_slice(&input[..count]);
            input = &input[count..];
            used += count;
        }
        debug_assert_eq!(used, end);
    }
    let permit = budget
        .reserve(used)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut bytes = rmcp::transport::streamable_http_server::body_budget::exact_zeroed(used)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut offset = 0;
    for (block, _charge) in blocks {
        let count = block.len().min(used - offset);
        bytes[offset..offset + count].copy_from_slice(&block[..count]);
        offset += count;
    }
    budget
        .owned(bytes, permit)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    use tokio_util::sync::CancellationToken;
    fn budget(bytes: usize, maximum: usize) -> (Arc<Semaphore>, BodyBudget) {
        let pool = Arc::new(Semaphore::new(bytes));
        let budget = BodyBudget::new(pool.clone(), maximum, CancellationToken::new());
        (pool, budget)
    }
    #[tokio::test]
    async fn exact_known_input_and_last_slice_keep_their_charge() {
        let (pool, budget) = budget(128, 64);
        let bytes = collect(
            Body::from("example"),
            Some(7),
            Some(budget.reserve(7).unwrap()),
            &budget,
        )
        .await
        .unwrap();
        assert_eq!(pool.available_permits(), 121);
        let slice = bytes.slice(1..3);
        drop(bytes);
        assert_eq!(pool.available_permits(), 121);
        drop(slice);
        assert_eq!(pool.available_permits(), 128);
    }
    #[tokio::test]
    async fn content_length_mismatch_never_reaches_dispatch_or_leaks_permits() {
        let (pool, budget) = budget(128, 64);
        for length in [1, 20] {
            assert_eq!(
                collect(
                    Body::from("example"),
                    Some(length),
                    Some(budget.reserve(length).unwrap()),
                    &budget
                )
                .await
                .unwrap_err(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(pool.available_permits(), 128);
        }
    }
    #[tokio::test]
    async fn unknown_growth_fails_without_waiting_and_recovers() {
        let (pool, budget) = budget(64, 64);
        let body = Body::from_stream(futures::stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(b"first")),
            Ok(Bytes::from_static(b"second")),
        ]));
        assert_eq!(
            collect(body, None, None, &budget).await.unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(pool.available_permits(), 64);
        let bytes = collect(
            Body::from("ok"),
            Some(2),
            Some(budget.reserve(2).unwrap()),
            &budget,
        )
        .await
        .unwrap();
        assert_eq!(&bytes[..], b"ok");
    }

    #[tokio::test]
    async fn ten_retained_responses_share_bytes_with_webtransport_frames() {
        const MIB: usize = 1024 * 1024;
        let (pool, budget) = budget(64 * MIB, 8 * MIB);
        let mut responses = Vec::new();
        for id in 0..10 {
            responses.push(
                budget
                    .encode_json(&serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"ok":true}}))
                    .unwrap(),
            );
        }
        let charged: usize = responses.iter().map(Bytes::len).sum();
        assert_eq!(pool.available_permits(), 64 * MIB - charged);
        let (mut writer, reader) = tokio::io::duplex(64);
        use tokio::io::AsyncWriteExt;
        writer.write_all(b"{\"fixture\":true}\n").await.unwrap();
        let mut reader = crate::framing::FrameReader::new(
            reader,
            8 * MIB,
            pool.clone(),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        );
        let frame = reader.read().await.unwrap().unwrap();
        assert_eq!(pool.available_permits(), 56 * MIB - charged - 8192);
        crate::framing::write_json(
            &mut tokio::io::sink(),
            &serde_json::json!({"ok":true}),
            8 * MIB,
            &pool,
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        drop(frame);
        drop(reader);
        assert_eq!(pool.available_permits(), 64 * MIB - charged);
        let final_slice = responses[0].slice(1..2);
        let first_charge = responses[0].len();
        responses.clear();
        assert_eq!(pool.available_permits(), 64 * MIB - first_charge);
        drop(final_slice);
        assert_eq!(pool.available_permits(), 64 * MIB);
    }

    #[test]
    fn exact_codec_bounds_changed_second_pass_and_shutdown_fail_cleanly() {
        use serde::{Serialize, Serializer};
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Changed(AtomicBool);
        impl Serialize for Changed {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(if self.0.swap(true, Ordering::SeqCst) {
                    "longer"
                } else {
                    "short"
                })
            }
        }
        let (pool, budget) = budget(4096, 1024);
        let bytes = budget.encode_json(&"x".repeat(1022)).unwrap();
        assert_eq!(bytes.len(), 1024);
        assert_eq!(pool.available_permits(), 3072);
        assert!(budget.encode_json(&"x".repeat(1023)).is_err());
        assert!(
            budget
                .encode_json(&Changed(AtomicBool::new(false)))
                .is_err()
        );
        assert_eq!(pool.available_permits(), 3072);
        drop(bytes);
        assert_eq!(pool.available_permits(), 4096);
        let cancel = CancellationToken::new();
        let stopped = BodyBudget::new(pool.clone(), 1024, cancel.clone());
        cancel.cancel();
        assert!(
            stopped
                .encode_json(&serde_json::json!({"ok":true}))
                .is_err()
        );
        assert_eq!(pool.available_permits(), 4096);
    }

    #[tokio::test]
    async fn dropped_stalled_collector_releases_its_complete_reservation() {
        let (pool, budget) = budget(1024, 512);
        let initial = budget.reserve(512).unwrap();
        let body = Body::from_stream(futures::stream::pending::<Result<Bytes, std::io::Error>>());
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                collect(body, Some(512), Some(initial), &budget)
            )
            .await
            .is_err()
        );
        assert_eq!(pool.available_permits(), 1024);
    }

    #[tokio::test]
    async fn unknown_near_ceiling_body_requires_only_its_exact_peak_ledger() {
        const MAXIMUM: usize = 128 * 1024;
        const LENGTH: usize = MAXIMUM - 1;
        // Two fixed 64KiB blocks plus the final exact allocation coexist.
        const PEAK: usize = MAXIMUM + LENGTH;
        for capacity in [PEAK - 1, PEAK] {
            let (pool, budget) = budget(capacity, MAXIMUM);
            let body = Body::from_stream(futures::stream::iter([
                Ok::<_, std::io::Error>(Bytes::from(vec![b'a'; CHUNK])),
                Ok(Bytes::from(vec![b'b'; CHUNK - 1])),
            ]));
            let result = collect(body, None, None, &budget).await;
            if capacity < PEAK {
                assert_eq!(result.unwrap_err(), StatusCode::SERVICE_UNAVAILABLE);
            } else {
                let bytes = result.unwrap();
                assert_eq!(bytes.len(), LENGTH);
                assert!(bytes[..CHUNK].iter().all(|byte| *byte == b'a'));
                assert!(bytes[CHUNK..].iter().all(|byte| *byte == b'b'));
                assert_eq!(pool.available_permits(), capacity - LENGTH);
                drop(bytes);
            }
            assert_eq!(pool.available_permits(), capacity);
        }
    }
}
