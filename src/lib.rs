//! Zentinel ModSecurity Agent Library
//!
//! A Web Application Firewall agent for Zentinel proxy that uses libmodsecurity
//! for full OWASP Core Rule Set (CRS) support.
//!
//! # Example
//!
//! ```ignore
//! use zentinel_agent_modsec::{ModSecAgent, ModSecConfig};
//! use zentinel_agent_protocol::AgentServer;
//!
//! let config = ModSecConfig {
//!     rules_paths: vec!["/etc/modsecurity/crs/rules/*.conf".to_string()],
//!     ..Default::default()
//! };
//! let agent = ModSecAgent::new(config)?;
//! let server = AgentServer::new("modsec", "/tmp/modsec.sock", Box::new(agent));
//! server.run().await?;
//! ```

use anyhow::Result;
use base64::Engine;
use modsecurity::{ModSecurity, Rules};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use zentinel_agent_protocol::{
    AgentHandler, AgentResponse, AuditMetadata, ConfigureEvent, HeaderOp, RequestBodyChunkEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent, EventType,
    v2::{
        AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, DrainReason,
        HealthStatus, MetricsReport, ShutdownReason,
    },
};

/// ModSecurity configuration
#[derive(Debug, Clone)]
pub struct ModSecConfig {
    /// Paths to ModSecurity rule files
    pub rules_paths: Vec<String>,
    /// Block mode (true) or detect-only mode (false)
    pub block_mode: bool,
    /// Paths to exclude from inspection
    pub exclude_paths: Vec<String>,
    /// Enable request body inspection
    pub body_inspection_enabled: bool,
    /// Maximum body size to inspect in bytes
    pub max_body_size: usize,
    /// Enable response body inspection
    pub response_inspection_enabled: bool,
}

impl Default for ModSecConfig {
    fn default() -> Self {
        Self {
            rules_paths: vec![],
            block_mode: true,
            exclude_paths: vec![],
            body_inspection_enabled: true,
            max_body_size: 1048576, // 1MB
            response_inspection_enabled: false,
        }
    }
}

/// JSON-serializable configuration for ModSecurity agent
///
/// Used for parsing configuration from the proxy's agent config.
/// Field names use kebab-case to match YAML/JSON config conventions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ModSecConfigJson {
    /// Paths to ModSecurity rule files (glob patterns supported)
    #[serde(default)]
    pub rules_paths: Vec<String>,
    /// Block mode (true) or detect-only mode (false)
    #[serde(default = "default_block_mode")]
    pub block_mode: bool,
    /// Paths to exclude from inspection
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// Enable request body inspection
    #[serde(default = "default_body_inspection")]
    pub body_inspection_enabled: bool,
    /// Maximum body size to inspect in bytes
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    /// Enable response body inspection
    #[serde(default)]
    pub response_inspection_enabled: bool,
}

fn default_block_mode() -> bool {
    true
}

fn default_body_inspection() -> bool {
    true
}

fn default_max_body_size() -> usize {
    1048576 // 1MB
}

impl From<ModSecConfigJson> for ModSecConfig {
    fn from(json: ModSecConfigJson) -> Self {
        Self {
            rules_paths: json.rules_paths,
            block_mode: json.block_mode,
            exclude_paths: json.exclude_paths,
            body_inspection_enabled: json.body_inspection_enabled,
            max_body_size: json.max_body_size,
            response_inspection_enabled: json.response_inspection_enabled,
        }
    }
}

/// Detection result from ModSecurity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub rule_id: String,
    pub message: String,
    pub severity: Option<String>,
}

/// ModSecurity engine wrapper
pub struct ModSecEngine {
    modsec: ModSecurity,
    rules: Rules,
    pub config: ModSecConfig,
}

impl ModSecEngine {
    /// Create a new ModSecurity engine with the given configuration
    pub fn new(config: ModSecConfig) -> Result<Self> {
        let modsec = ModSecurity::default();
        let mut rules = Rules::new();

        // Enable the rule engine (required for blocking to work)
        rules
            .add_plain("SecRuleEngine On")
            .map_err(|e| anyhow::anyhow!("Failed to enable SecRuleEngine: {}", e))?;

        // Load rules from configured paths
        let mut loaded_count = 0;
        for path_pattern in &config.rules_paths {
            // Handle glob patterns
            let paths = glob::glob(path_pattern)
                .map_err(|e| anyhow::anyhow!("Invalid glob pattern '{}': {}", path_pattern, e))?;

            for entry in paths {
                match entry {
                    Ok(path) => {
                        if path.is_file() {
                            let content = fs::read_to_string(&path).map_err(|e| {
                                anyhow::anyhow!("Failed to read rule file {:?}: {}", path, e)
                            })?;
                            rules.add_plain(&content).map_err(|e| {
                                anyhow::anyhow!("Failed to parse rules from {:?}: {}", path, e)
                            })?;
                            loaded_count += 1;
                            debug!(path = ?path, "Loaded rule file");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Error reading glob entry");
                    }
                }
            }
        }

        info!(rules_files = loaded_count, "ModSecurity engine initialized");

        Ok(Self {
            modsec,
            rules,
            config,
        })
    }

    /// Check if path should be excluded
    pub fn is_excluded(&self, path: &str) -> bool {
        self.config
            .exclude_paths
            .iter()
            .any(|p| path.starts_with(p))
    }
}

/// Body accumulator for tracking in-progress bodies
#[derive(Debug, Default)]
struct BodyAccumulator {
    data: Vec<u8>,
}

/// Pending transaction for body accumulation
struct PendingTransaction {
    body: BodyAccumulator,
    method: String,
    uri: String,
    headers: HashMap<String, Vec<String>>,
    client_ip: String,
}

/// ModSecurity agent
pub struct ModSecAgent {
    engine: Arc<RwLock<ModSecEngine>>,
    pending_requests: Arc<RwLock<HashMap<String, PendingTransaction>>>,
}

impl ModSecAgent {
    pub fn new(config: ModSecConfig) -> Result<Self> {
        let engine = ModSecEngine::new(config)?;
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Reconfigure the agent with new settings
    ///
    /// This rebuilds the ModSecurity engine with the new configuration.
    /// In-flight requests using the old engine will complete normally.
    pub async fn reconfigure(&self, config: ModSecConfig) -> Result<()> {
        info!("Reconfiguring ModSecurity engine");
        let new_engine = ModSecEngine::new(config)?;
        let mut engine = self.engine.write().await;
        *engine = new_engine;
        // Clear pending requests since rules may have changed
        let mut pending = self.pending_requests.write().await;
        pending.clear();
        info!("ModSecurity engine reconfigured successfully");
        Ok(())
    }

    /// Process a complete request through ModSecurity
    async fn process_request(
        &self,
        correlation_id: &str,
        method: &str,
        uri: &str,
        headers: &HashMap<String, Vec<String>>,
        body: Option<&[u8]>,
        _client_ip: &str,
    ) -> Result<Option<(u16, String)>> {
        let engine = self.engine.read().await;

        // Build transaction
        let mut tx = engine
            .modsec
            .transaction_builder()
            .with_rules(&engine.rules)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to create transaction: {}", e))?;

        // Process URI
        tx.process_uri(uri, method, "1.1")
            .map_err(|e| anyhow::anyhow!("process_uri failed: {}", e))?;

        // Add headers
        for (name, values) in headers {
            for value in values {
                tx.add_request_header(name, value)
                    .map_err(|e| anyhow::anyhow!("add_request_header failed: {}", e))?;
            }
        }

        // Process request headers (phase 1)
        tx.process_request_headers()
            .map_err(|e| anyhow::anyhow!("process_request_headers failed: {}", e))?;

        // Check for intervention after headers
        if let Some(intervention) = tx.intervention() {
            let status = intervention.status() as u16;
            if status != 0 && status != 200 {
                debug!(
                    correlation_id = correlation_id,
                    status = status,
                    "ModSecurity intervention (headers)"
                );
                return Ok(Some((status, "Blocked by ModSecurity".to_string())));
            }
        }

        // Process body if provided (phase 2)
        if let Some(body_data) = body {
            if !body_data.is_empty() {
                tx.append_request_body(body_data)
                    .map_err(|e| anyhow::anyhow!("append_request_body failed: {}", e))?;
                tx.process_request_body()
                    .map_err(|e| anyhow::anyhow!("process_request_body failed: {}", e))?;

                // Check for intervention after body
                if let Some(intervention) = tx.intervention() {
                    let status = intervention.status() as u16;
                    if status != 0 && status != 200 {
                        debug!(
                            correlation_id = correlation_id,
                            status = status,
                            "ModSecurity intervention (body)"
                        );
                        return Ok(Some((status, "Blocked by ModSecurity".to_string())));
                    }
                }
            }
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl AgentHandlerV2 for ModSecAgent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(
            "zentinel-modsec-agent",
            "ModSecurity WAF Agent",
            env!("CARGO_PKG_VERSION"),
        )
        .with_event(EventType::RequestHeaders)
        .with_event(EventType::RequestBodyChunk)
        .with_event(EventType::ResponseHeaders)
        .with_event(EventType::ResponseBodyChunk)
        .with_features(AgentFeatures {
            streaming_body: true,
            websocket: false,
            guardrails: false,
            config_push: true,
            metrics_export: true,
            concurrent_requests: 100,
            cancellation: true,
            flow_control: false,
            health_reporting: true,
        })
        .with_limits(AgentLimits {
            max_body_size: 10 * 1024 * 1024, // 10MB
            max_concurrency: 100,
            preferred_chunk_size: 64 * 1024,
            max_memory: None,
            max_processing_time_ms: Some(5000),
        })
    }

    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        debug!(version = ?version, "Received configure event");

        // Parse the JSON config into ModSecConfigJson
        let config_json: ModSecConfigJson = match serde_json::from_value(config) {
            Ok(config) => config,
            Err(e) => {
                warn!(error = %e, "Failed to parse ModSecurity configuration");
                // Return false to indicate configuration was not accepted
                return false;
            }
        };

        // Convert to internal config and reconfigure the engine
        let config: ModSecConfig = config_json.into();
        if let Err(e) = self.reconfigure(config).await {
            warn!(error = %e, "Failed to reconfigure ModSecurity engine");
            return false;
        }

        info!(version = ?version, "ModSecurity agent configured successfully");
        true
    }

    fn health_status(&self) -> HealthStatus {
        // Return healthy status with agent ID
        HealthStatus::healthy("zentinel-modsec-agent")
    }

    fn metrics_report(&self) -> Option<MetricsReport> {
        // Basic metrics report - can be extended to include more detailed metrics
        Some(MetricsReport::new("zentinel-modsec-agent", 10_000))
    }

    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "ModSecurity agent shutting down"
        );
        // Clear pending requests on shutdown
        let mut pending = self.pending_requests.write().await;
        pending.clear();
    }

    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            reason = ?reason,
            duration_ms = duration_ms,
            "ModSecurity agent draining"
        );
        // Stop accepting new requests - clear pending to signal draining
        let mut pending = self.pending_requests.write().await;
        pending.clear();
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let path = &event.uri;
        let correlation_id = &event.metadata.correlation_id;

        // Check exclusions
        {
            let engine = self.engine.read().await;
            if engine.is_excluded(path) {
                debug!(path = path, "Path excluded from ModSecurity");
                return AgentResponse::default_allow();
            }
        }

        // Always process headers immediately (ModSecurity phase 1)
        // This detects attacks in URI, query string, and headers
        match self
            .process_request(
                correlation_id,
                &event.method,
                &event.uri,
                &event.headers,
                None,
                &event.metadata.client_ip,
            )
            .await
        {
            Ok(Some((status, message))) => {
                let engine = self.engine.read().await;
                if engine.config.block_mode {
                    info!(
                        correlation_id = correlation_id,
                        status = status,
                        "Request blocked by ModSecurity"
                    );
                    AgentResponse::block(status, Some("Forbidden".to_string()))
                        .add_response_header(HeaderOp::Set {
                            name: "X-WAF-Blocked".to_string(),
                            value: "true".to_string(),
                        })
                        .add_response_header(HeaderOp::Set {
                            name: "X-WAF-Message".to_string(),
                            value: message.clone(),
                        })
                        .with_audit(AuditMetadata {
                            tags: vec!["modsec".to_string(), "blocked".to_string()],
                            reason_codes: vec![message],
                            ..Default::default()
                        })
                } else {
                    info!(
                        correlation_id = correlation_id,
                        "ModSecurity detection (detect-only mode)"
                    );
                    AgentResponse::default_allow()
                        .add_request_header(HeaderOp::Set {
                            name: "X-WAF-Detected".to_string(),
                            value: message.clone(),
                        })
                        .with_audit(AuditMetadata {
                            tags: vec!["modsec".to_string(), "detected".to_string()],
                            reason_codes: vec![message],
                            ..Default::default()
                        })
                }
            }
            Ok(None) => {
                // Headers passed - if body inspection enabled, store for body processing
                let engine = self.engine.read().await;
                if engine.config.body_inspection_enabled {
                    let mut pending = self.pending_requests.write().await;
                    pending.insert(
                        correlation_id.clone(),
                        PendingTransaction {
                            body: BodyAccumulator::default(),
                            method: event.method.clone(),
                            uri: event.uri.clone(),
                            headers: event.headers.clone(),
                            client_ip: event.metadata.client_ip.clone(),
                        },
                    );
                }
                AgentResponse::default_allow()
            }
            Err(e) => {
                warn!(error = %e, "ModSecurity processing error");
                AgentResponse::default_allow()
            }
        }
    }

    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;

        // Check if we have a pending request
        let pending_exists = {
            let pending = self.pending_requests.read().await;
            pending.contains_key(correlation_id)
        };

        if !pending_exists {
            // No pending request - body inspection might be disabled
            return AgentResponse::default_allow();
        }

        // Decode base64 chunk
        let chunk = match base64::engine::general_purpose::STANDARD.decode(&event.data) {
            Ok(data) => data,
            Err(e) => {
                warn!(error = %e, "Failed to decode body chunk");
                return AgentResponse::default_allow();
            }
        };

        // Accumulate chunk
        let should_process = {
            let mut pending = self.pending_requests.write().await;
            if let Some(tx) = pending.get_mut(correlation_id) {
                let engine = self.engine.read().await;

                // Check size limit
                if tx.body.data.len() + chunk.len() > engine.config.max_body_size {
                    debug!(
                        correlation_id = correlation_id,
                        "Body exceeds max size, skipping inspection"
                    );
                    pending.remove(correlation_id);
                    return AgentResponse::default_allow();
                }

                tx.body.data.extend(chunk);
                event.is_last
            } else {
                false
            }
        };

        // If this is the last chunk, process the complete request
        if should_process {
            let pending_tx = {
                let mut pending = self.pending_requests.write().await;
                pending.remove(correlation_id)
            };

            if let Some(tx) = pending_tx {
                match self
                    .process_request(
                        correlation_id,
                        &tx.method,
                        &tx.uri,
                        &tx.headers,
                        Some(&tx.body.data),
                        &tx.client_ip,
                    )
                    .await
                {
                    Ok(Some((status, message))) => {
                        let engine = self.engine.read().await;
                        if engine.config.block_mode {
                            info!(
                                correlation_id = correlation_id,
                                status = status,
                                "Request blocked by ModSecurity (body inspection)"
                            );
                            return AgentResponse::block(status, Some("Forbidden".to_string()))
                                .add_response_header(HeaderOp::Set {
                                    name: "X-WAF-Blocked".to_string(),
                                    value: "true".to_string(),
                                })
                                .add_response_header(HeaderOp::Set {
                                    name: "X-WAF-Message".to_string(),
                                    value: message.clone(),
                                })
                                .with_audit(AuditMetadata {
                                    tags: vec![
                                        "modsec".to_string(),
                                        "blocked".to_string(),
                                        "body".to_string(),
                                    ],
                                    reason_codes: vec![message],
                                    ..Default::default()
                                });
                        } else {
                            info!(
                                correlation_id = correlation_id,
                                "ModSecurity detection in body (detect-only mode)"
                            );
                            return AgentResponse::default_allow()
                                .add_request_header(HeaderOp::Set {
                                    name: "X-WAF-Detected".to_string(),
                                    value: message.clone(),
                                })
                                .with_audit(AuditMetadata {
                                    tags: vec![
                                        "modsec".to_string(),
                                        "detected".to_string(),
                                        "body".to_string(),
                                    ],
                                    reason_codes: vec![message],
                                    ..Default::default()
                                });
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(error = %e, "ModSecurity body processing error");
                    }
                }
            }
        }

        AgentResponse::default_allow()
    }

    async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse {
        // Response body inspection not yet implemented
        // ModSecurity can inspect response bodies but the API is more complex
        let _ = event;
        AgentResponse::default_allow()
    }
}

/// v1 AgentHandler implementation for backward compatibility with UDS transport.
///
/// This delegates to the v2 implementation methods for the core event handling,
/// allowing the agent to work with both v1 (UDS) and v2 (gRPC) servers.
#[async_trait::async_trait]
impl AgentHandler for ModSecAgent {
    async fn on_configure(&self, event: ConfigureEvent) -> AgentResponse {
        // Delegate to v2 configure, converting result to AgentResponse
        let accepted = <Self as AgentHandlerV2>::on_configure(self, event.config, None).await;
        if accepted {
            AgentResponse::default_allow()
        } else {
            // v1 doesn't have a way to signal config rejection, so just return allow
            // but the warning is logged in the v2 method
            AgentResponse::default_allow()
        }
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        <Self as AgentHandlerV2>::on_request_headers(self, event).await
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        <Self as AgentHandlerV2>::on_request_body_chunk(self, event).await
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        <Self as AgentHandlerV2>::on_response_headers(self, event).await
    }

    async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse {
        <Self as AgentHandlerV2>::on_response_body_chunk(self, event).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ModSecConfig::default();
        assert!(config.rules_paths.is_empty());
        assert!(config.block_mode);
        assert!(config.body_inspection_enabled);
        assert!(!config.response_inspection_enabled);
        assert_eq!(config.max_body_size, 1048576);
    }

    #[test]
    fn test_modsec_engine_direct() {
        // Test ModSecurity engine directly without the agent wrapper
        let modsec = ModSecurity::default();
        let mut rules = Rules::new();

        // Enable the rule engine and add a simple test rule
        rules
            .add_plain("SecRuleEngine On")
            .expect("Failed to enable engine");
        let rule = r#"SecRule QUERY_STRING "@contains attack" "id:1,phase:1,deny,status:403""#;
        rules.add_plain(rule).expect("Failed to add rule");

        // Create transaction
        let mut tx = modsec
            .transaction_builder()
            .with_rules(&rules)
            .build()
            .expect("Failed to create transaction");

        // Process a malicious request
        tx.process_uri("/test?q=attack", "GET", "1.1")
            .expect("process_uri failed");
        tx.process_request_headers()
            .expect("process_request_headers failed");

        // Check intervention
        let intervention = tx.intervention();
        println!("Intervention: {:?}", intervention.is_some());
        if let Some(i) = &intervention {
            println!("Status: {}", i.status());
        }

        assert!(
            intervention.is_some(),
            "Expected intervention for attack in query string"
        );
    }

    #[test]
    fn test_modsec_engine_clean_request() {
        let modsec = ModSecurity::default();
        let mut rules = Rules::new();

        rules
            .add_plain("SecRuleEngine On")
            .expect("Failed to enable engine");
        let rule = r#"SecRule QUERY_STRING "@contains attack" "id:1,phase:1,deny,status:403""#;
        rules.add_plain(rule).expect("Failed to add rule");

        let mut tx = modsec
            .transaction_builder()
            .with_rules(&rules)
            .build()
            .expect("Failed to create transaction");

        // Process a clean request
        tx.process_uri("/test?q=hello", "GET", "1.1")
            .expect("process_uri failed");
        tx.process_request_headers()
            .expect("process_request_headers failed");

        let intervention = tx.intervention();
        assert!(
            intervention.is_none() || intervention.as_ref().map(|i| i.status()) == Some(200),
            "Clean request should not trigger intervention"
        );
    }
}
