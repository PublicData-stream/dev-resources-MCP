//! Startup-only schema registration. No dynamically loaded code or remote schemas.
use crate::{ServerError, config::SourceOffer};
use devres_domain::Result;
use futures::{FutureExt, future::BoxFuture};
use rmcp::model::Tool;
use serde_json::{Value, json};
use std::{collections::BTreeMap, future::Future, sync::Arc};
use tokio_util::sync::CancellationToken;

const MAX_REGISTERED_TOOLS: usize = 128;

type Invoke = dyn Fn(Value, CancellationToken) -> BoxFuture<'static, Result<Value>> + Send + Sync;
type ResourceRead =
    dyn Fn(String, CancellationToken) -> BoxFuture<'static, Result<Value>> + Send + Sync;
pub(crate) struct RegisteredTool {
    pub definition: Tool,
    pub validator: jsonschema::Validator,
    pub invoke: Arc<Invoke>,
}
#[derive(Default)]
pub struct ToolRegistry {
    pub(crate) tools: BTreeMap<String, RegisteredTool>,
    pub(crate) resource_reader: Option<Arc<ResourceRead>>,
}
impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    /// Register a trusted, bounded, read-only tool before listeners bind.
    pub fn register<F, Fut>(
        &mut self,
        descriptor: Value,
        handler: F,
    ) -> std::result::Result<(), ServerError>
    where
        F: Fn(Value, CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value>> + Send + 'static,
    {
        ensure_serialized_limit(&descriptor, 64 * 1024)?;
        let tool: Tool = serde_json::from_value(descriptor.clone())?;
        let name = tool.name.as_ref();
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            || self.tools.len() >= MAX_REGISTERED_TOOLS
            || self.tools.contains_key(name)
        {
            return Err("invalid, duplicate, or excessive tool registration".into());
        }
        let schema = descriptor
            .get("inputSchema")
            .ok_or("missing input schema")?;
        if schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err("tool schema must describe an object".into());
        }
        reject_external_refs(schema)?;
        let validator = jsonschema::validator_for(schema).map_err(|_| "invalid tool schema")?;
        if descriptor.pointer("/annotations/readOnlyHint") != Some(&Value::Bool(true)) {
            return Err("tools must declare readOnlyHint".into());
        }
        self.tools.insert(
            name.to_owned(),
            RegisteredTool {
                definition: tool,
                validator,
                invoke: Arc::new(move |value, cancel| handler(value, cancel).boxed()),
            },
        );
        Ok(())
    }
    pub fn with_resource_reader<F, Fut>(&mut self, reader: F)
    where
        F: Fn(String, CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value>> + Send + 'static,
    {
        self.resource_reader = Some(Arc::new(move |uri, cancel| reader(uri, cancel).boxed()));
    }
    pub fn register_research(
        &mut self,
        research: Arc<devres_adapters::Research>,
    ) -> std::result::Result<(), ServerError> {
        for descriptor in devres_adapters::Research::tool_schemas() {
            let name = descriptor
                .get("name")
                .and_then(Value::as_str)
                .ok_or("missing tool name")?
                .to_owned();
            let research = research.clone();
            self.register(descriptor, move |value, _cancel| {
                let research = research.clone();
                let name = name.clone();
                async move { research.call(&name, value).await }
            })?;
        }
        self.with_resource_reader(move |uri, _cancel| {
            let research = research.clone();
            async move { research.read_resource(&uri).await }
        });
        Ok(())
    }
}
fn reject_external_refs(value: &Value) -> std::result::Result<(), ServerError> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "$ref" && value.as_str().is_none_or(|v| !v.starts_with('#')) {
                    return Err("external schema references are forbidden".into());
                }
                reject_external_refs(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_external_refs(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}
/// Count bytes without allocating a second copy of caller-controlled result bodies.
pub(crate) fn ensure_serialized_limit(
    value: &impl serde::Serialize,
    limit: usize,
) -> std::result::Result<(), ServerError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(bytes.len())
                .ok_or_else(|| std::io::Error::other("serialized result exceeds limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter(limit), value)?;
    Ok(())
}
pub fn server_info(source: &SourceOffer) -> Value {
    json!({"product":"dev-resources-MCP","version":env!("CARGO_PKG_VERSION"),"license":SourceOffer::LICENSE,"licenseUrl":SourceOffer::LICENSE_URL,"sourceUrl":source.url(),"transports":["streamable-http","webtransport-v1"],"protocolVersions":["2026-07-28","2025-11-25"]})
}
pub fn server_info_registry(source: SourceOffer) -> std::result::Result<ToolRegistry, ServerError> {
    let mut registry = ToolRegistry::new();
    registry.register(json!({"name":"server_info","description":"Read service identity, license, corresponding source, and supported protocols.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}), move |_, _| {
        let source = source.clone(); async move { Ok(server_info(&source)) }
    })?;
    Ok(registry)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_research_tools_pass_real_startup_registration() {
        let mut registry =
            server_info_registry(SourceOffer::new("https://source.test").unwrap()).unwrap();
        for descriptor in devres_adapters::Research::tool_schemas() {
            registry
                .register(descriptor, |_, _| async { Ok(json!({})) })
                .unwrap();
        }
        for name in [
            "crate_versions",
            "crate_catalog_search",
            "crate_document_get",
            "crate_dependencies",
            "crate_compare",
            "crate_content_search",
            "crate_api_search",
            "crate_api_get",
            "crate_corpus_status",
        ] {
            assert!(registry.tools.contains_key(name));
            assert!(
                !registry.tools[name]
                    .validator
                    .is_valid(&json!({"unexpected":"field"}))
            );
        }
    }
    #[test]
    fn registration_rejects_duplicates_and_external_refs() {
        let mut registry =
            server_info_registry(SourceOffer::new("https://source.test").unwrap()).unwrap();
        let descriptor = serde_json::to_value(&registry.tools["server_info"].definition).unwrap();
        assert!(
            registry
                .register(descriptor, |_, _| async { Ok(json!({})) })
                .is_err()
        );
        let descriptor = json!({"name":"bad","inputSchema":{"type":"object","properties":{"input":{"$ref":"https://evil.test/schema"}}},"annotations":{"readOnlyHint":true}});
        assert!(
            registry
                .register(descriptor, |_, _| async { Ok(json!({})) })
                .is_err()
        );
    }
    #[test]
    fn mdn_selectors_and_generic_source_defaults_remain_strict() {
        let mut registry =
            server_info_registry(SourceOffer::new("https://source.test").unwrap()).unwrap();
        for descriptor in devres_adapters::Research::tool_schemas() {
            registry
                .register(descriptor, |_, _| async { Ok(json!({})) })
                .unwrap();
        }
        assert!(registry.tools.len() <= MAX_REGISTERED_TOOLS);
        let get = &registry.tools["mdn_get"].validator;
        assert!(get.is_valid(&json!({"slug":"Web/API/Window/fetch"})));
        assert!(!get.is_valid(&json!({})));
        assert!(!get.is_valid(&json!({"slug":"A","path":"B"})));
        assert!(!get.is_valid(&json!({"slug":"A","url":"https://example.com"})));
        let history = &registry.tools["mdn_history"].validator;
        assert!(history.is_valid(&json!({"feature":"api.fetch","repository":"compat"})));
        assert!(!history.is_valid(&json!({"slug":"A","path":"B"})));
        assert!(
            registry.tools["search"]
                .validator
                .is_valid(&json!({"query":"fetch","sources":["mdn"]}))
        );
        assert!(
            !registry.tools["search"]
                .validator
                .is_valid(&json!({"query":"fetch","sources":["arbitrary"]}))
        );
    }

    #[test]
    fn whatwg_interfaces_admit_only_local_evidence_selectors() {
        let mut registry =
            server_info_registry(SourceOffer::new("https://source.test").unwrap()).unwrap();
        for descriptor in devres_adapters::Research::tool_schemas() {
            registry
                .register(descriptor, |_, _| async { Ok(json!({})) })
                .unwrap();
        }
        assert!(
            registry.tools["whatwg_get"]
                .validator
                .is_valid(&json!({"standard":"dom","anchor":"event"}))
        );
        assert!(
            !registry.tools["whatwg_get"]
                .validator
                .is_valid(&json!({"standard":"dom","url":"https://example.com"}))
        );
        assert!(
            !registry.tools["whatwg_catalog_search"]
                .validator
                .is_valid(&json!({"snapshot":"a".repeat(64)}))
        );
        assert!(
            registry.tools["whatwg_symbol_get"]
                .validator
                .is_valid(&json!({"standard":"dom","name":"Event","limit":32768}))
        );
        assert!(
            !registry.tools["whatwg_symbol_get"]
                .validator
                .is_valid(&json!({"standard":"dom","name":"Event","limit":32769}))
        );
        assert!(
            !registry.tools["whatwg_corpus_status"]
                .validator
                .is_valid(&json!({"enabled":true}))
        );
        assert!(
            registry.tools["search"]
                .validator
                .is_valid(&json!({"query":"event","sources":["whatwg"]}))
        );
    }

    #[test]
    fn w3c_interfaces_preserve_the_local_read_boundary() {
        let mut registry =
            server_info_registry(SourceOffer::new("https://source.test").unwrap()).unwrap();
        for descriptor in devres_adapters::Research::tool_schemas() {
            registry
                .register(descriptor, |_, _| async { Ok(json!({})) })
                .unwrap();
        }
        assert!(registry.tools.len() <= MAX_REGISTERED_TOOLS);
        assert!(
            registry.tools["w3c_get"]
                .validator
                .is_valid(&json!({"specification":"css-color-4","anchor":"color"}))
        );
        for input in [
            json!({"specification":"css-color-4","url":"https://untrusted.invalid"}),
            json!({"standard":"css-color-4"}),
            json!({"specification":"css-color-4","limit":32769}),
        ] {
            assert!(!registry.tools["w3c_get"].validator.is_valid(&input));
        }
        assert!(
            !registry.tools["w3c_corpus_status"]
                .validator
                .is_valid(&json!({"enabled":true}))
        );
        assert!(registry.tools["search"].validator.is_valid(
            &json!({"query":"color","sources":["rfc","cargo","rustsec","mdn","whatwg","w3c"]})
        ));
    }
    #[test]
    fn chromium_interfaces_bind_documents_and_reject_remote_inputs() {
        let mut registry =
            server_info_registry(SourceOffer::new("https://source.test").unwrap()).unwrap();
        for descriptor in devres_adapters::Research::tool_schemas() {
            registry
                .register(descriptor, |_, _| async { Ok(json!({})) })
                .unwrap();
        }
        let get = &registry.tools["chromium_get"].validator;
        assert!(get.is_valid(&json!({"component":"src","path":"docs/README.md"})));
        for input in [
            json!({"component":"src"}),
            json!({"component":"unknown","path":"docs/a.md"}),
            json!({"component":"src","path":"docs/a.md","url":"https://untrusted.invalid"}),
            json!({"component":"src","path":"docs/a.md","limit":32769}),
            json!({"component":"src","path":"docs/a.md","snapshot":"a".repeat(64),"view":"b".repeat(64)}),
        ] {
            assert!(!get.is_valid(&input));
        }
        assert!(registry.tools["search"].validator.is_valid(&json!({"query":"chromium","sources":["rfc","cargo","rustsec","mdn","whatwg","w3c","chromium"]})));
        assert!(
            !registry.tools["chromium_corpus_status"]
                .validator
                .is_valid(&json!({"enabled":true}))
        );
    }

    #[test]
    fn trusted_registration_capacity_remains_bounded() {
        let mut registry = ToolRegistry::new();
        for i in 0..MAX_REGISTERED_TOOLS {
            registry.register(json!({"name":format!("bounded_{i}"),"inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}), |_,_|async { Ok(json!({})) }).unwrap();
        }
        assert!(registry.register(json!({"name":"overflow","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}), |_,_|async { Ok(json!({})) }).is_err());
    }
}
