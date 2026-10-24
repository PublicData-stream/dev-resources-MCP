//! Shared MCP dispatch. Request bodies and audit reports never enter diagnostics.
use crate::{
    ServerError,
    config::{Limits, SourceOffer},
    progress::{ProgressReporter, ProgressStage, validate_progress_token},
    rate_limit::RateLimiter,
    registry::{ToolRegistry, ensure_serialized_limit},
};
use rmcp::{ErrorData, RoleServer, ServerHandler, model::*, service::RequestContext};
use std::{
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;

#[derive(Default)]
pub struct Counters {
    pub calls: AtomicU64,
    pub failures: AtomicU64,
    pub rate_limited: AtomicU64,
}
#[derive(Clone)]
pub struct McpHandler {
    registry: Arc<ToolRegistry>,
    source: SourceOffer,
    limits: Arc<Limits>,
    calls: Arc<Semaphore>,
    rate: Arc<RateLimiter>,
    verified_rate: Option<Arc<RateLimiter>>,
    verified_tunnel: bool,
    pub counters: Arc<Counters>,
}
impl McpHandler {
    pub fn new(
        registry: ToolRegistry,
        limits: Arc<Limits>,
        source: SourceOffer,
    ) -> Result<Self, ServerError> {
        limits.validate()?;
        ensure_serialized_limit(
            &crate::registry::server_info(&source),
            limits.tool_result_limit(),
        )?;
        let tools: Vec<_> = registry.tools.values().map(|v| &v.definition).collect();
        ensure_serialized_limit(&tools, limits.max_message_bytes / 2)?;
        Ok(Self {
            registry: Arc::new(registry),
            source,
            calls: Arc::new(Semaphore::new(limits.max_in_flight)),
            rate: Arc::new(RateLimiter::new(
                limits.rate_limit.enabled,
                limits.rate_limit.calls_per_second,
                limits.rate_limit.burst,
            )),
            verified_rate: limits
                .rate_limit
                .verified_tunnel
                .as_ref()
                .map(|v| Arc::new(RateLimiter::verified_tunnel(v))),
            verified_tunnel: false,
            limits,
            counters: Arc::new(Counters::default()),
        })
    }
    pub(crate) fn for_verified_tunnel(&self) -> Self {
        let mut handler = self.clone();
        handler.verified_tunnel = true;
        handler
    }
    async fn admit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, ErrorData> {
        let permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorData::internal_error("server busy", None))?;
        self.counters.calls.fetch_add(1, Ordering::Relaxed);
        let rate = if self.verified_tunnel {
            self.verified_rate.as_ref().unwrap_or(&self.rate)
        } else {
            &self.rate
        };
        if !rate.try_admit().await {
            self.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(ErrorData::internal_error(
                "request rate limit exceeded",
                None,
            ));
        }
        Ok(permit)
    }
}
impl ServerHandler for McpHandler {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![
            ProtocolVersion::V_2026_07_28,
            ProtocolVersion::V_2025_11_25,
        ])
    }
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::default();
        info.capabilities = if self.registry.resource_reader.is_some() {
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build()
        } else {
            ServerCapabilities::builder().enable_tools().build()
        };
        info.server_info = Implementation::new("dev-resources-MCP", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(format!(
            "Read-only developer research. Public source references identify exact captures. Supplied lockfiles and audit results are request-only. Licensed under {} ({}). Corresponding source for this running server: {}",
            SourceOffer::LICENSE,
            SourceOffer::LICENSE_URL,
            self.source.url()
        ));
        info
    }
    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.registry.tools.get(name).map(|v| v.definition.clone())
    }
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        if request.and_then(|v| v.cursor).is_some() {
            return Err(ErrorData::invalid_params("unsupported cursor", None));
        }
        Ok(ListToolsResult {
            tools: self
                .registry
                .tools
                .values()
                .map(|v| v.definition.clone())
                .collect(),
            ..Default::default()
        })
    }
    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        if request.and_then(|v| v.cursor).is_some() {
            return Err(ErrorData::invalid_params("unsupported cursor", None));
        }
        // Captures are addressed by references returned from tools, not enumerated publicly.
        Ok(ListResourcesResult::default())
    }
    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        if request.and_then(|v| v.cursor).is_some() {
            return Err(ErrorData::invalid_params("unsupported cursor", None));
        }
        Ok(ListResourceTemplatesResult::default())
    }
    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        if request.uri.len() > 16 * 1024 {
            return Err(ErrorData::invalid_params(
                "resource URI exceeds limit",
                None,
            ));
        }
        let reader = self
            .registry
            .resource_reader
            .as_ref()
            .ok_or_else(|| ErrorData::invalid_params("resource unavailable", None))?;
        let _permit = self.admit().await?;
        let cancel = context.ct.child_token();
        let _guard = cancel.clone().drop_guard();
        let value = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(ErrorData::internal_error("request cancelled", None)),
            result = tokio::time::timeout(Duration::from_secs(self.limits.call_timeout_secs), reader(request.uri, cancel.clone())) => result.map_err(|_| ErrorData::internal_error("resource deadline exceeded", None))?.map_err(|_| ErrorData::invalid_params("resource unavailable", None))?,
        };
        ensure_serialized_limit(&value, self.limits.tool_result_limit())
            .map_err(|_| ErrorData::internal_error("resource exceeds limit", None))?;
        let result: ReadResourceResult = serde_json::from_value(value)
            .map_err(|_| ErrorData::internal_error("invalid resource representation", None))?;
        Ok(result.into())
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let token = context.meta.get_progress_token();
        if (context.meta.contains_key("progressToken") && token.is_none())
            || token.as_ref().is_some_and(|v| !validate_progress_token(v))
        {
            return Err(ErrorData::invalid_params("invalid progress token", None));
        }
        let tool = self
            .registry
            .tools
            .get(request.name.as_ref())
            .ok_or_else(|| ErrorData::invalid_params("unknown tool", None))?;
        let arguments = serde_json::Value::Object(request.arguments.unwrap_or_default());
        if !tool.validator.is_valid(&arguments) {
            return Err(ErrorData::invalid_params("invalid tool arguments", None));
        }
        let _permit = self.admit().await?;
        let cancel = context.ct.child_token();
        let _guard = cancel.clone().drop_guard();
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(self.limits.call_timeout_secs);
        let progress = ProgressReporter::new(
            context.peer.clone(),
            token,
            cancel.clone(),
            deadline,
            self.limits.max_message_bytes / 4,
        );
        let _progress_guard = progress.close_guard();
        let _ = progress.report(ProgressStage::Processing).await;
        let value = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(ErrorData::internal_error("request cancelled", None)),
            result = tokio::time::timeout_at(deadline, (tool.invoke)(arguments, cancel.clone())) => {
                match result {
                    Ok(Ok(value)) => value,
                    Ok(Err(error)) => {
                        self.counters.failures.fetch_add(1, Ordering::Relaxed);
                        if error.code == "invalid_input" { return Err(ErrorData::invalid_params(error.message, None)); }
                        return Ok(CallToolResult::structured_error(serde_json::json!({"code":error.code,"message":error.message})).into());
                    }
                    Err(_) => { self.counters.failures.fetch_add(1, Ordering::Relaxed); return Err(ErrorData::internal_error("tool deadline exceeded", None)); }
                }
            }
        };
        if !value.is_object()
            || ensure_serialized_limit(&value, self.limits.tool_result_limit()).is_err()
        {
            self.counters.failures.fetch_add(1, Ordering::Relaxed);
            return Ok(CallToolResult::structured_error(serde_json::json!({"code":"resource_limit","message":"Tool result exceeds its limit."})).into());
        }
        let links = capture_links(&value);
        let mut result = CallToolResult::structured(value);
        result.content.extend(links);
        ensure_serialized_limit(&result, self.limits.max_message_bytes / 2)
            .map_err(|_| ErrorData::internal_error("tool result exceeds limit", None))?;
        let _ = progress.report(ProgressStage::Complete).await;
        Ok(result.into())
    }
}

/// Only application-owned provenance slots become native MCP references.
fn capture_links(value: &serde_json::Value) -> Vec<ContentBlock> {
    let mut uris = std::collections::BTreeSet::new();
    let mut add = |value: &serde_json::Value| {
        if let Some(uri) = value
            .get("resource_uri")
            .and_then(serde_json::Value::as_str)
            && uri.len() <= 16 * 1024
            && (uri.starts_with("devres://capture/")
                || uri.starts_with("devres://source/")
                || uri.starts_with("devres://rfc/"))
            && uris.len() < 20
        {
            uris.insert(uri.to_owned());
        }
    };
    add(value);
    for key in ["capture", "metadata_capture"] {
        add(&value[key]);
    }
    if let Some(files) = value.get("files").and_then(serde_json::Value::as_array) {
        for file in files.iter().take(20) {
            add(file);
        }
    }
    uris.into_iter()
        .map(|uri| ContentBlock::resource_link(Resource::new(uri, "Public source capture")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_references_only_use_public_provenance_slots() {
        let value = serde_json::json!({"resource_uri":"devres://capture/abc", "capture":{"resource_uri":"devres://capture/abc"}, "private_input":{"resource_uri":"https://evil.test"}});
        assert_eq!(capture_links(&value).len(), 1);
        assert!(
            capture_links(&serde_json::json!({"resource_uri":"file:///etc/passwd"})).is_empty()
        );
    }
}
