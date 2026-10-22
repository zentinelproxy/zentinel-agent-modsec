//! Zentinel ModSecurity Agent Library
//!
//! A Web Application Firewall agent for Zentinel proxy that uses libmodsecurity
//! for full OWASP Core Rule Set (CRS) support.
//!
//! # Example
//!
//! ```ignore
//! use zentinel_agent_modsec::{ModSecAgent, ModSecConfig};
//! use zentinel_agent_protocol::v2::UdsAgentServerV2;
//!
//! let config = ModSecConfig {
//!     rules_paths: vec!["/etc/modsecurity/crs/rules/*.conf".to_string()],
//!     ..Default::default()
//! };
//! let agent = ModSecAgent::new(config)?;
//! let server = UdsAgentServerV2::new("modsec", "/tmp/modsec.sock", Box::new(agent));
//! server.run().await?;
//! ```

use anyhow::Result;
use base64::Engine;
use modsecurity::{ModSecurity, Rules};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use zentinel_agent_protocol::{
    v2::{
        AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, DrainReason, HealthStatus,
        MetricsReport, ShutdownReason,
    },
    AgentResponse, AuditMetadata, EventType, HeaderOp, RequestBodyChunkEvent, RequestCompleteEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent,
};

/// ModSecurity configuration
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl ModSecConfig {
    /// Names (as written in a `config { }` block) of the settings that differ
    /// between `self` and `other`. Used to log what a configure changed
    /// without logging the values.
    pub fn changed_keys(&self, other: &ModSecConfig) -> Vec<&'static str> {
        let mut keys = Vec::new();
        if self.rules_paths != other.rules_paths {
            keys.push("rules-paths");
        }
        if self.block_mode != other.block_mode {
            keys.push("block-mode");
        }
        if self.exclude_paths != other.exclude_paths {
            keys.push("exclude-paths");
        }
        if self.body_inspection_enabled != other.body_inspection_enabled {
            keys.push("body-inspection-enabled");
        }
        if self.max_body_size != other.max_body_size {
            keys.push("max-body-size");
        }
        if self.response_inspection_enabled != other.response_inspection_enabled {
            keys.push("response-inspection-enabled");
        }
        keys
    }

    /// Whether going from `self` to `other` needs the rule set rebuilt.
    /// Only the rule files and body inspection (which adds engine
    /// directives) shape the compiled rules; the other settings are read per
    /// request and can change in place.
    fn needs_rebuild(&self, other: &ModSecConfig) -> bool {
        self.rules_paths != other.rules_paths
            || self.body_inspection_enabled != other.body_inspection_enabled
    }
}

/// The agent's `config { }` block, as the proxy sends it in Configure.
///
/// Every field is optional: a field that is absent keeps the value from the
/// command line / environment (see [`ModSecConfigJson::apply_to`]). Unknown
/// keys are rejected, so a misspelled key fails the configure instead of being
/// ignored. Keys are kebab-case; `rules`, `body-inspection` and
/// `response-inspection` are accepted as aliases matching the CLI flags. A
/// list may be given as a single string (the proxy turns a one-argument KDL
/// node into a scalar).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ModSecConfigJson {
    /// Paths to ModSecurity rule files (glob patterns supported)
    #[serde(
        default,
        alias = "rules",
        deserialize_with = "one_or_many",
        skip_serializing_if = "Option::is_none"
    )]
    pub rules_paths: Option<Vec<String>>,
    /// Block mode (true) or detect-only mode (false)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_mode: Option<bool>,
    /// Paths to exclude from inspection
    #[serde(
        default,
        deserialize_with = "one_or_many",
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_paths: Option<Vec<String>>,
    /// Enable request body inspection
    #[serde(
        default,
        alias = "body-inspection",
        skip_serializing_if = "Option::is_none"
    )]
    pub body_inspection_enabled: Option<bool>,
    /// Maximum body size to inspect in bytes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_size: Option<usize>,
    /// Enable response body inspection
    #[serde(
        default,
        alias = "response-inspection",
        skip_serializing_if = "Option::is_none"
    )]
    pub response_inspection_enabled: Option<bool>,
}

/// Accept a list as a JSON array or as a single string.
fn one_or_many<'de, D>(deserializer: D) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(Some(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    }))
}

/// Trim the entries of a list from the config block and drop empty ones.
/// A list that was given but has nothing left is an error: it is almost
/// always a mistake (`rules-paths ""`), and taking it literally would turn
/// inspection off.
fn clean_list(key: &str, list: &[String]) -> std::result::Result<Vec<String>, String> {
    let cleaned: Vec<String> = list
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if cleaned.is_empty() {
        return Err(format!(
            "`{key}` is empty; omit it to keep the value from the command line"
        ));
    }
    Ok(cleaned)
}

impl ModSecConfigJson {
    /// Parse a configure payload. Rejects anything but an object, unknown
    /// keys and wrongly typed values.
    pub fn from_value(value: serde_json::Value) -> std::result::Result<Self, String> {
        if !value.is_object() {
            return Err(format!("expected an object, got {}", json_kind(&value)));
        }
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    /// Overlay these settings on `base`: a field that is present replaces the
    /// base value, an absent one keeps it.
    pub fn apply_to(&self, base: &ModSecConfig) -> std::result::Result<ModSecConfig, String> {
        let mut config = base.clone();
        if let Some(rules) = &self.rules_paths {
            config.rules_paths = clean_list("rules-paths", rules)?;
        }
        if let Some(block_mode) = self.block_mode {
            config.block_mode = block_mode;
        }
        if let Some(exclude) = &self.exclude_paths {
            config.exclude_paths = if exclude.is_empty() {
                Vec::new()
            } else {
                clean_list("exclude-paths", exclude)?
            };
        }
        if let Some(body) = self.body_inspection_enabled {
            config.body_inspection_enabled = body;
        }
        if let Some(max) = self.max_body_size {
            if max == 0 {
                return Err("`max-body-size` must be greater than 0".to_string());
            }
            config.max_body_size = max;
        }
        if let Some(response) = self.response_inspection_enabled {
            config.response_inspection_enabled = response;
        }
        Ok(config)
    }
}

fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// A stable hash of a JSON value, independent of object key order: FNV-1a
/// over the value serialized with every object's keys sorted.
pub fn config_hash(value: &serde_json::Value) -> u64 {
    fn canonical(value: &serde_json::Value, out: &mut String) {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (i, key) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::Value::String(key.clone()).to_string());
                    out.push(':');
                    canonical(&map[key], out);
                }
                out.push('}');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    canonical(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut text = String::new();
    canonical(value, &mut text);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
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
    /// Number of rule files loaded from `config.rules_paths`
    pub rule_files: usize,
}

impl ModSecEngine {
    /// Create a new ModSecurity engine with the given configuration
    pub fn new(config: ModSecConfig) -> Result<Self> {
        Self::build(config, false)
    }

    /// Like [`ModSecEngine::new`], but every rules pattern must match at
    /// least one file. Used when the rules came from a `config { }` block, so
    /// a misspelled path fails the configure instead of silently loading
    /// fewer (or zero) rules.
    pub fn new_strict(config: ModSecConfig) -> Result<Self> {
        Self::build(config, true)
    }

    fn build(config: ModSecConfig, strict: bool) -> Result<Self> {
        // Log callbacks must be enabled on the instance for the per-transaction
        // callback (rule id and msg of every hit) to be invoked.
        let modsec = ModSecurity::builder().with_log_callbacks().build();
        let mut rules = Rules::new();

        // Enable the rule engine (required for blocking to work)
        rules
            .add_plain("SecRuleEngine On")
            .map_err(|e| anyhow::anyhow!("Failed to enable SecRuleEngine: {}", e))?;

        // Without SecRequestBodyAccess, libmodsecurity never parses the body
        // it is given, so ARGS_POST / REQUEST_BODY stay empty and no body rule
        // can match. Stock CRS does not set it (modsecurity.conf does), so set
        // it here whenever body inspection is on; a rule file may still
        // override it.
        if config.body_inspection_enabled {
            rules
                .add_plain("SecRequestBodyAccess On")
                .map_err(|e| anyhow::anyhow!("Failed to enable SecRequestBodyAccess: {}", e))?;
            // The body processors from modsecurity.conf-recommended (same
            // ids). Without them a JSON or XML body is never parsed into
            // ARGS, which is what the CRS injection rules inspect.
            rules
                .add_plain(concat!(
                    "SecRule REQUEST_HEADERS:Content-Type \"^(?:application(?:/soap\\+|/)|text/)xml\" ",
                    "\"id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML\"\n",
                    "SecRule REQUEST_HEADERS:Content-Type \"^application/json\" ",
                    "\"id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON\""
                ))
                .map_err(|e| anyhow::anyhow!("Failed to add body processor rules: {}", e))?;
        }

        // Load rules from configured paths
        let mut loaded_count = 0;
        for path_pattern in &config.rules_paths {
            let before = loaded_count;
            // Handle glob patterns
            let paths = glob::glob(path_pattern)
                .map_err(|e| anyhow::anyhow!("Invalid glob pattern '{}': {}", path_pattern, e))?;

            for entry in paths {
                match entry {
                    Ok(path) => {
                        if path.is_file() {
                            // Load by path, not by contents: libmodsecurity
                            // resolves `@pmFromFile` and other relative data
                            // files against the rule file's directory, which
                            // it only knows when given the file. Passing the
                            // text made stock CRS fail on its first data file
                            // (REQUEST-913, scanners-user-agents.data).
                            rules.add_file(&path).map_err(|e| {
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
            if strict && loaded_count == before {
                anyhow::bail!("rules pattern '{}' matched no rule file", path_pattern);
            }
        }

        info!(rules_files = loaded_count, "ModSecurity engine initialized");

        Ok(Self {
            modsec,
            rules,
            config,
            rule_files: loaded_count,
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

/// A rule that fired, as reported by libmodsecurity's log callback.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleHit {
    id: String,
    message: String,
}

/// Outcome of an intervention: HTTP status plus the rules behind it.
#[derive(Debug, Clone)]
struct Verdict {
    status: u16,
    /// msg of the rule that triggered the intervention
    message: String,
    /// id of the rule that triggered the intervention
    trigger: Option<String>,
    /// every rule that logged during the transaction (deduplicated, in order)
    hits: Vec<RuleHit>,
}

impl Verdict {
    fn rule_ids(&self) -> Vec<String> {
        self.hits.iter().map(|h| h.id.clone()).collect()
    }
}

/// Message reported when libmodsecurity gives no `msg` for the intervention.
const DEFAULT_MESSAGE: &str = "Blocked by ModSecurity";

/// Extract `value` from a `[key "value"]` field of a libmodsecurity log line.
fn bracket_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("[{key} \"");
    let start = line.find(&needle)? + needle.len();
    let end = line[start..].find("\"]")?;
    Some(&line[start..start + end])
}

/// Parse the hits out of the lines captured by the log callback.
fn hits_from_logs(lines: &[String]) -> Vec<RuleHit> {
    let mut hits: Vec<RuleHit> = Vec::new();
    for line in lines {
        let Some(id) = bracket_field(line, "id") else {
            continue;
        };
        if hits.iter().any(|h| h.id == id) {
            continue;
        }
        hits.push(RuleHit {
            id: id.to_string(),
            message: bracket_field(line, "msg").unwrap_or_default().to_string(),
        });
    }
    hits
}

/// Make a rule message safe for an audit string and a log line.
fn sanitize_message(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(200)
        .collect();
    if cleaned.is_empty() {
        DEFAULT_MESSAGE.to_string()
    } else {
        cleaned
    }
}

/// ModSecurity agent
pub struct ModSecAgent {
    engine: Arc<RwLock<ModSecEngine>>,
    pending_requests: Arc<RwLock<HashMap<String, PendingTransaction>>>,
    /// The configuration from the command line / environment. A `config { }`
    /// block is overlaid on this, never on a previous block.
    base_config: ModSecConfig,
    /// Hash of the last accepted configure payload. Also serializes
    /// configures: the proxy sends one per pooled connection, concurrently.
    last_configure: tokio::sync::Mutex<Option<u64>>,
}

impl ModSecAgent {
    pub fn new(config: ModSecConfig) -> Result<Self> {
        let engine = ModSecEngine::new(config.clone())?;
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            base_config: config,
            last_configure: tokio::sync::Mutex::new(None),
        })
    }

    /// The configuration currently in effect.
    pub async fn active_config(&self) -> ModSecConfig {
        self.engine.read().await.config.clone()
    }

    /// Number of requests whose body is being buffered for inspection.
    pub async fn pending_count(&self) -> usize {
        self.pending_requests.read().await.len()
    }

    /// Reconfigure the agent with new settings
    ///
    /// The rule set is rebuilt only when the rule files or body inspection
    /// changed; other settings are updated in place. Requests whose body is
    /// still being buffered are kept and inspected with the new settings.
    pub async fn reconfigure(&self, config: ModSecConfig) -> Result<()> {
        self.apply(config, false).await.map(|_| ())
    }

    /// Make `config` the active configuration. Returns the names of the
    /// settings that changed (empty: nothing to do).
    async fn apply(&self, config: ModSecConfig, strict: bool) -> Result<Vec<&'static str>> {
        let current = self.active_config().await;
        let changed = current.changed_keys(&config);
        if changed.is_empty() {
            return Ok(changed);
        }
        if current.needs_rebuild(&config) {
            let new_engine = if strict {
                ModSecEngine::new_strict(config)?
            } else {
                ModSecEngine::new(config)?
            };
            *self.engine.write().await = new_engine;
        } else {
            self.engine.write().await.config = config;
        }
        Ok(changed)
    }

    /// Handle a configure payload (the agent's `config { }` block): see the
    /// README's Configuration section for the rules.
    pub async fn configure(&self, config: serde_json::Value) -> std::result::Result<(), String> {
        let hash = config_hash(&config);
        let mut last = self.last_configure.lock().await;
        if *last == Some(hash) {
            debug!(
                config_hash = format!("{hash:016x}"),
                "Configuration unchanged"
            );
            return Ok(());
        }

        let overlay = ModSecConfigJson::from_value(config)
            .map_err(|e| format!("invalid ModSecurity configuration: {e}"))?;
        let effective = overlay
            .apply_to(&self.base_config)
            .map_err(|e| format!("invalid ModSecurity configuration: {e}"))?;
        let rules_from_block = overlay.rules_paths.is_some();

        let changed = self
            .apply(effective, rules_from_block)
            .await
            .map_err(|e| format!("failed to load ModSecurity rules: {e:#}"))?;
        if rules_from_block && self.engine.read().await.rule_files == 0 {
            // Cannot happen with strict loading, but never report success
            // for a configure that asked for rules and loaded none.
            return Err("the configured rules loaded no rule file".to_string());
        }

        *last = Some(hash);
        info!(
            config_hash = format!("{hash:016x}"),
            changed = ?changed,
            "ModSecurity agent configured"
        );
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
    ) -> Result<Option<Verdict>> {
        let engine = self.engine.read().await;

        // Every rule that logs during this transaction ends up here.
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&logs);

        // Build transaction
        let mut tx = engine
            .modsec
            .transaction_builder()
            .with_rules(&engine.rules)
            .with_logging(move |msg| {
                if let (Some(msg), Ok(mut lines)) = (msg, sink.lock()) {
                    lines.push(msg.to_string());
                }
            })
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
        if let Some(verdict) = Self::verdict(&mut tx, &logs, correlation_id) {
            return Ok(Some(verdict));
        }

        // Phase 2. `None` means a body is still coming and will be processed
        // by a later call; `Some` (possibly empty) runs phase 2 now. Phase 2
        // must run even without a body: CRS evaluates ARGS (the query
        // string) for SQLi/XSS, and makes its anomaly-score blocking
        // decision (949110), in phase 2. Skipping it for bodyless requests
        // meant no GET was ever blocked under stock CRS.
        if let Some(body_data) = body {
            if !body_data.is_empty() {
                tx.append_request_body(body_data)
                    .map_err(|e| anyhow::anyhow!("append_request_body failed: {}", e))?;
            }
            tx.process_request_body()
                .map_err(|e| anyhow::anyhow!("process_request_body failed: {}", e))?;

            // Check for intervention after body
            if let Some(verdict) = Self::verdict(&mut tx, &logs, correlation_id) {
                return Ok(Some(verdict));
            }
        }

        let seen = logs.lock().map(|l| hits_from_logs(&l)).unwrap_or_default();
        if !seen.is_empty() {
            debug!(
                correlation_id,
                rules = %seen.iter().map(|h| h.id.as_str()).collect::<Vec<_>>().join(","),
                "ModSecurity rules matched, no intervention"
            );
        }
        Ok(None)
    }

    /// Build a verdict from the transaction's intervention, if there is one.
    ///
    /// The rule that triggered the intervention is read from the intervention's
    /// own log line; the callback lines supply every other rule that logged.
    fn verdict(
        tx: &mut modsecurity::Transaction<'_>,
        logs: &Arc<Mutex<Vec<String>>>,
        correlation_id: &str,
    ) -> Option<Verdict> {
        let intervention = tx.intervention()?;
        let status = intervention.status() as u16;
        if status == 0 || status == 200 {
            return None;
        }
        let iv_log = intervention.log().unwrap_or_default().to_string();
        let lines = logs.lock().map(|l| l.clone()).unwrap_or_default();
        let mut hits = hits_from_logs(&lines);
        // Without an `id` in the intervention's log line, the last rule that
        // logged is the best guess; it may be one that did not disrupt.
        let trigger = bracket_field(&iv_log, "id")
            .map(str::to_string)
            .or_else(|| hits.last().map(|h| h.id.clone()));
        let message = bracket_field(&iv_log, "msg")
            .map(str::to_string)
            .or_else(|| {
                trigger
                    .as_ref()
                    .and_then(|t| hits.iter().find(|h| &h.id == t))
                    .map(|h| h.message.clone())
            })
            .filter(|m| !m.is_empty())
            .map(|m| sanitize_message(&m))
            .unwrap_or_else(|| DEFAULT_MESSAGE.to_string());
        // The trigger may only appear in the intervention log, not the callback.
        if let Some(t) = &trigger {
            if !hits.iter().any(|h| &h.id == t) {
                hits.push(RuleHit {
                    id: t.clone(),
                    message: message.clone(),
                });
            }
        }
        debug!(
            correlation_id,
            status,
            trigger = trigger.as_deref().unwrap_or(""),
            "ModSecurity intervention"
        );
        Some(Verdict {
            status,
            message,
            trigger,
            hits,
        })
    }

    /// Turn a verdict into a response according to block / detect-only mode.
    ///
    /// The rule id and text go to the log and the audit metadata only; the
    /// client sees a constant message and no rule id.
    async fn respond(&self, verdict: Verdict, stage: &str, correlation_id: &str) -> AgentResponse {
        let block_mode = self.engine.read().await.config.block_mode;
        let rule_ids = verdict.rule_ids();
        let mut tags = vec!["modsec".to_string()];
        tags.push(if block_mode { "blocked" } else { "detected" }.to_string());
        if stage == "body" {
            tags.push("body".to_string());
        }
        let audit = AuditMetadata {
            tags,
            rule_ids: rule_ids.clone(),
            reason_codes: vec![verdict.message.clone()],
            ..Default::default()
        };

        if block_mode {
            info!(
                correlation_id,
                status = verdict.status,
                stage,
                trigger = verdict.trigger.as_deref().unwrap_or(""),
                rules = %rule_ids.join(","),
                rule_msg = %verdict.message,
                "Request blocked by ModSecurity"
            );
            let resp = AgentResponse::block(verdict.status, Some("Forbidden".to_string()))
                .add_response_header(HeaderOp::Set {
                    name: "X-WAF-Blocked".to_string(),
                    value: "true".to_string(),
                })
                .add_response_header(HeaderOp::Set {
                    name: "X-WAF-Message".to_string(),
                    value: DEFAULT_MESSAGE.to_string(),
                });
            resp.with_audit(audit)
        } else {
            info!(
                correlation_id,
                stage,
                trigger = verdict.trigger.as_deref().unwrap_or(""),
                rules = %rule_ids.join(","),
                rule_msg = %verdict.message,
                "ModSecurity detection (detect-only mode)"
            );
            AgentResponse::default_allow()
                .add_request_header(HeaderOp::Set {
                    name: "X-WAF-Detected".to_string(),
                    value: DEFAULT_MESSAGE.to_string(),
                })
                .with_audit(audit)
        }
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
        match self.configure(config).await {
            Ok(()) => true,
            Err(e) => {
                warn!(version = ?version, error = %e, "Rejected configuration");
                false
            }
        }
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

        // Run phases 1 and 2 now, with an empty body, so attacks in the URI,
        // query string and headers are decided here. With body inspection on,
        // the whole transaction runs again with the body once it has arrived
        // (on_request_body_chunk). Whether a body follows cannot be known from
        // the headers (HTTP/2 needs no Content-Length), so always wait for it.
        let defer_body = {
            let engine = self.engine.read().await;
            engine.config.body_inspection_enabled
        };
        let empty: &[u8] = &[];

        match self
            .process_request(
                correlation_id,
                &event.method,
                &event.uri,
                &event.headers,
                Some(empty),
                &event.metadata.client_ip,
            )
            .await
        {
            Ok(Some(verdict)) => self.respond(verdict, "headers", correlation_id).await,
            Ok(None) => {
                // Headers passed - if a body is coming, store for body processing
                if defer_body {
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

    async fn on_request_complete(&self, event: RequestCompleteEvent) -> AgentResponse {
        // A request that never sent a body leaves its pending entry behind;
        // drop it when the proxy reports the request finished.
        self.pending_requests
            .write()
            .await
            .remove(&event.correlation_id);
        AgentResponse::default_allow()
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
                    Ok(Some(verdict)) => {
                        return self.respond(verdict, "body", correlation_id).await;
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
    fn test_bracket_field() {
        let line = r#"ModSecurity: Access denied with code 403 (phase 2). [file "/r.conf"] [line "1"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [tag "x"]"#;
        assert_eq!(bracket_field(line, "id"), Some("949110"));
        assert_eq!(
            bracket_field(line, "msg"),
            Some("Inbound Anomaly Score Exceeded (Total Score: 5)")
        );
        assert_eq!(bracket_field(line, "severity"), None);
        assert_eq!(bracket_field("[id \"1", "id"), None);
    }

    #[test]
    fn test_hits_from_logs_keeps_order_and_drops_duplicates() {
        let lines = vec![
            r#"[id "920350"] [msg "Host header is a numeric IP address"]"#.to_string(),
            "no fields on this line".to_string(),
            r#"[id "942100"] [msg "SQL Injection Attack"]"#.to_string(),
            r#"[id "920350"] [msg "again"]"#.to_string(),
            r#"[id "949110"]"#.to_string(),
        ];
        let hits = hits_from_logs(&lines);
        let ids: Vec<&str> = hits.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, ["920350", "942100", "949110"]);
        assert_eq!(hits[0].message, "Host header is a numeric IP address");
        assert_eq!(hits[2].message, "");
    }

    #[test]
    fn test_sanitize_message() {
        assert_eq!(sanitize_message("plain text"), "plain text");
        assert_eq!(sanitize_message("a\r\nb\u{3042}"), "a??b?");
        assert_eq!(sanitize_message(""), DEFAULT_MESSAGE);
        assert_eq!(sanitize_message(&"x".repeat(500)).len(), 200);
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

    /// Rules are loaded by path, so a relative `@pmFromFile` resolves next to
    /// the rule file (stock CRS depends on this), and phase 2 runs for a
    /// request without a body (CRS inspects ARGS and blocks in phase 2).
    #[tokio::test]
    async fn test_phase2_rule_with_data_file_blocks_bodyless_get() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("words.data"), "evilword\n").unwrap();
        std::fs::write(
            dir.path().join("rules.conf"),
            r#"SecRule ARGS "@pmFromFile words.data" "id:10,phase:2,deny,status:403""#,
        )
        .unwrap();
        let config = ModSecConfig {
            rules_paths: vec![dir.path().join("*.conf").display().to_string()],
            ..Default::default()
        };
        let agent = ModSecAgent::new(config).expect("rules with a data file must load");
        let headers = HashMap::new();
        let empty: &[u8] = &[];

        let blocked = agent
            .process_request(
                "c1",
                "GET",
                "/s?q=evilword",
                &headers,
                Some(empty),
                "127.0.0.1",
            )
            .await
            .unwrap();
        let blocked = blocked.expect("phase 2 must block the query string");
        assert_eq!(blocked.status, 403);
        assert_eq!(blocked.trigger.as_deref(), Some("10"));

        let clean = agent
            .process_request(
                "c2",
                "GET",
                "/s?q=hello",
                &headers,
                Some(empty),
                "127.0.0.1",
            )
            .await
            .unwrap();
        assert!(clean.is_none());
    }
}
