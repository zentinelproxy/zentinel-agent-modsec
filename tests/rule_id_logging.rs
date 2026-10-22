//! Tests that a block says which rule caused it.
//!
//! The rules are written inline (no CRS needed). The handler is called
//! directly, and the log output is captured with a thread-local subscriber, so
//! the tests need the default single-threaded `#[tokio::test]` runtime.

use base64::Engine;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;
use tracing_subscriber::fmt::MakeWriter;
use zentinel_agent_modsec::{ModSecAgent, ModSecConfig};
use zentinel_agent_protocol::{
    v2::AgentHandlerV2, AgentResponse, Decision, HeaderOp, RequestBodyChunkEvent,
    RequestHeadersEvent, RequestMetadata,
};

const RULES: &str = r#"
SecRuleEngine On

# Phase 1: a request header
SecRule REQUEST_HEADERS:X-Probe "@contains block-me" "id:10001,phase:1,deny,status:403,log,msg:'Probe header rejected'"

# Phase 2, on the query string: decided when the headers arrive, with no body
SecRule ARGS:q "@contains evil" "id:10020,phase:2,deny,status:403,log,msg:'Query rejected in phase 2'"

# Phase 2: two rules that score, then one that blocks on the total
SecAction "id:10009,phase:2,pass,nolog,setvar:tx.score=0"
SecRule REQUEST_BODY "@contains alpha" "id:10010,phase:2,pass,log,msg:'Alpha pattern',setvar:tx.score=+3"
SecRule REQUEST_BODY "@contains beta" "id:10011,phase:2,pass,log,msg:'Beta pattern',setvar:tx.score=+3"
SecRule TX:SCORE "@ge 5" "id:10019,phase:2,deny,status:403,log,msg:'Score threshold exceeded (Total Score: %{tx.score})'"
"#;

/// Collects everything the agent logs.
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = LogBuffer;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture_logs() -> (LogBuffer, tracing::subscriber::DefaultGuard) {
    let buffer = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_max_level(tracing::Level::INFO)
        .json()
        .finish();
    (buffer, tracing::subscriber::set_default(subscriber))
}

fn agent(block_mode: bool) -> (tempfile::TempDir, ModSecAgent) {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("rules.conf");
    std::fs::write(&path, RULES).expect("write rules");
    let config = ModSecConfig {
        rules_paths: vec![path.to_string_lossy().into_owned()],
        block_mode,
        ..Default::default()
    };
    (dir, ModSecAgent::new(config).expect("agent"))
}

fn metadata() -> RequestMetadata {
    let id = uuid::Uuid::new_v4().to_string();
    RequestMetadata {
        correlation_id: id.clone(),
        request_id: id,
        client_ip: "127.0.0.1".to_string(),
        client_port: 12345,
        server_name: Some("example.com".to_string()),
        protocol: "HTTP/1.1".to_string(),
        tls_version: None,
        tls_cipher: None,
        route_id: None,
        upstream_id: None,
        timestamp: "2025-01-01T00:00:00Z".to_string(),
        traceparent: None,
    }
}

fn headers_event(method: &str, headers: &[(&str, &str)]) -> RequestHeadersEvent {
    headers_event_for(method, "/submit", headers)
}

fn headers_event_for(method: &str, uri: &str, headers: &[(&str, &str)]) -> RequestHeadersEvent {
    let headers: HashMap<String, Vec<String>> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
        .collect();
    RequestHeadersEvent {
        metadata: metadata(),
        method: method.to_string(),
        uri: uri.to_string(),
        headers,
    }
}

fn body_event(correlation_id: &str, data: &str) -> RequestBodyChunkEvent {
    RequestBodyChunkEvent {
        correlation_id: correlation_id.to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(data),
        is_last: true,
        total_size: None,
        chunk_index: 0,
        bytes_received: data.len(),
    }
}

/// Send a POST with a body through the handler (headers, then the last chunk).
async fn post(agent: &ModSecAgent, body: &str) -> AgentResponse {
    let event = headers_event("POST", &[("Transfer-Encoding", "chunked")]);
    let id = event.metadata.correlation_id.clone();
    let response = agent.on_request_headers(event).await;
    assert!(matches!(response.decision, Decision::Allow));
    agent.on_request_body_chunk(body_event(&id, body)).await
}

/// The client gets a fixed body, and neither rule text nor rule id.
fn assert_client_sees_no_rule_text(response: &AgentResponse) {
    match &response.decision {
        Decision::Block { status, body, .. } => {
            assert_eq!(*status, 403);
            assert_eq!(body.as_deref(), Some("Forbidden"));
        }
        other => panic!("expected Block, got {other:?}"),
    }
    for op in &response.response_headers {
        if let HeaderOp::Set { name, value } = op {
            for leaked in ["rejected", "Score threshold", "10001", "10019", "10020"] {
                assert!(
                    !value.contains(leaked) && !name.to_ascii_lowercase().contains("rule"),
                    "rule id or text leaked into response header {name}: {value}"
                );
            }
        }
    }
}

#[tokio::test]
async fn header_block_reports_rule_id_and_message() {
    let (logs, _guard) = capture_logs();
    let (_dir, agent) = agent(true);

    let response = agent
        .on_request_headers(headers_event("GET", &[("X-Probe", "block-me")]))
        .await;

    assert_client_sees_no_rule_text(&response);
    assert_eq!(response.audit.rule_ids, vec!["10001"]);
    assert_eq!(response.audit.reason_codes, vec!["Probe header rejected"]);

    let text = logs.text();
    assert!(text.contains("Request blocked by ModSecurity"), "{text}");
    assert!(
        text.contains(r#""trigger":"10001""#) && text.contains(r#""rules":"10001""#),
        "rule id missing from log: {text}"
    );
    assert!(
        text.contains("Probe header rejected"),
        "msg missing from log: {text}"
    );
}

#[tokio::test]
async fn body_block_reports_triggering_rule_and_every_rule_that_logged() {
    let (logs, _guard) = capture_logs();
    let (_dir, agent) = agent(true);

    let response = post(&agent, "alpha and beta").await;

    assert_client_sees_no_rule_text(&response);
    // The blocking rule is the trigger; the two scoring rules that logged
    // before it are reported as well.
    assert_eq!(
        response.audit.rule_ids.last().map(String::as_str),
        Some("10019")
    );
    for id in ["10010", "10011", "10019"] {
        assert!(
            response.audit.rule_ids.iter().any(|r| r == id),
            "{id} missing from {:?}",
            response.audit.rule_ids
        );
    }
    assert_eq!(response.audit.reason_codes.len(), 1);
    assert!(
        response.audit.reason_codes[0].starts_with("Score threshold exceeded"),
        "{:?}",
        response.audit.reason_codes
    );
    assert!(response.audit.tags.iter().any(|t| t == "body"));

    let text = logs.text();
    assert!(text.contains(r#""trigger":"10019""#), "{text}");
    assert!(
        text.contains(r#""rules":"10010,10011,10019""#),
        "ids not comma separated in order: {text}"
    );
    assert!(
        !text.contains("Some("),
        "Debug formatting in the log: {text}"
    );
    assert!(text.contains("Score threshold exceeded"), "{text}");
}

/// A GET has no body, so its phase 2 runs when the headers arrive; the rule id
/// must be reported from there too.
#[tokio::test]
async fn bodyless_get_blocked_in_phase_2_reports_rule_id_and_message() {
    let (logs, _guard) = capture_logs();
    let (_dir, agent) = agent(true);

    let response = agent
        .on_request_headers(headers_event_for("GET", "/submit?q=evil", &[]))
        .await;

    assert_client_sees_no_rule_text(&response);
    assert_eq!(response.audit.rule_ids, vec!["10020"]);
    assert_eq!(
        response.audit.reason_codes,
        vec!["Query rejected in phase 2"]
    );
    assert!(!response.audit.tags.iter().any(|t| t == "body"));

    let text = logs.text();
    assert!(text.contains(r#""trigger":"10020""#), "{text}");
    assert!(text.contains("Query rejected in phase 2"), "{text}");
    // Nothing is left waiting for a body that will not come.
    assert_eq!(agent.pending_count().await, 0);
}

/// A POST whose query string is clean at the headers event is still checked
/// against its body when the last chunk arrives (phases 1 and 2 run again).
#[tokio::test]
async fn body_block_after_a_clean_headers_event_reports_rule_id() {
    let (_logs, _guard) = capture_logs();
    let (_dir, agent) = agent(true);

    let event = headers_event_for(
        "POST",
        "/submit?q=fine",
        &[("Transfer-Encoding", "chunked")],
    );
    let id = event.metadata.correlation_id.clone();
    assert!(matches!(
        agent.on_request_headers(event).await.decision,
        Decision::Allow
    ));
    assert_eq!(agent.pending_count().await, 1);

    let response = agent
        .on_request_body_chunk(body_event(&id, "alpha beta"))
        .await;
    assert_client_sees_no_rule_text(&response);
    assert!(response.audit.rule_ids.iter().any(|r| r == "10019"));
    assert_eq!(agent.pending_count().await, 0);
}

#[tokio::test]
async fn detect_only_mode_reports_the_rule_without_blocking() {
    let (logs, _guard) = capture_logs();
    let (_dir, agent) = agent(false);

    let response = agent
        .on_request_headers(headers_event("GET", &[("X-Probe", "block-me")]))
        .await;

    assert!(matches!(response.decision, Decision::Allow));
    assert_eq!(response.audit.rule_ids, vec!["10001"]);
    assert!(response.audit.tags.iter().any(|t| t == "detected"));
    let text = logs.text();
    assert!(text.contains("detect-only"), "{text}");
    assert!(text.contains("10001"), "{text}");
}

#[tokio::test]
async fn clean_request_reports_no_rules() {
    let (logs, _guard) = capture_logs();
    let (_dir, agent) = agent(true);

    let response = post(&agent, "nothing to see").await;

    assert!(matches!(response.decision, Decision::Allow));
    assert!(response.audit.rule_ids.is_empty());
    assert!(!logs.text().contains("blocked"), "{}", logs.text());
}
