//! Integration tests for the ModSecurity WAF agent using the zentinel-agent-protocol.
//!
//! These tests spin up an actual AgentServer and connect via AgentClient
//! to verify the full protocol flow.
//!
//! Note: These tests use inline ModSecurity rules for testing. In production,
//! you would typically use the full OWASP CRS ruleset.

use base64::Engine;
use zentinel_agent_modsec::{ModSecAgent, ModSecConfig};
use zentinel_agent_protocol::{
    AgentClient, AgentServer, Decision, EventType, RequestBodyChunkEvent, RequestHeadersEvent,
    RequestMetadata, ResponseBodyChunkEvent,
};
use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;
use tempfile::tempdir;

/// Basic ModSecurity rules for testing
/// These are simplified rules that mirror common attack patterns
const TEST_RULES: &str = r#"
# Enable the rule engine
SecRuleEngine On

# SQL Injection detection - using @contains for simpler matching
SecRule QUERY_STRING "@contains ' OR '" "id:1001,phase:1,deny,status:403,msg:'SQL Injection detected'"
SecRule QUERY_STRING "@contains UNION SELECT" "id:1002,phase:1,deny,status:403,msg:'SQL Injection - UNION SELECT'"
SecRule QUERY_STRING "@contains ' AND '" "id:1003,phase:1,deny,status:403,msg:'SQL Injection - AND'"

# XSS detection
SecRule QUERY_STRING "@contains <script" "id:2001,phase:1,deny,status:403,msg:'XSS - script tag'"
SecRule QUERY_STRING "@contains javascript:" "id:2002,phase:1,deny,status:403,msg:'XSS - javascript URI'"
SecRule QUERY_STRING "@contains onerror=" "id:2003,phase:1,deny,status:403,msg:'XSS - onerror handler'"
SecRule QUERY_STRING "@contains onload=" "id:2004,phase:1,deny,status:403,msg:'XSS - onload handler'"
SecRule REQUEST_HEADERS "@contains <script" "id:2005,phase:1,deny,status:403,msg:'XSS in header'"

# Path traversal detection
SecRule REQUEST_URI "@contains ../" "id:3001,phase:1,deny,status:403,msg:'Path traversal'"
SecRule REQUEST_URI "@contains %2e%2e%2f" "id:3002,phase:1,deny,status:403,msg:'Path traversal encoded'"
SecRule REQUEST_URI "@contains %2e%2e/" "id:3003,phase:1,deny,status:403,msg:'Path traversal partial encoded'"

# Command injection detection
SecRule QUERY_STRING "@rx \x60[^\x60]+\x60" "id:4001,phase:1,deny,status:403,msg:'Command injection - backticks'"
SecRule QUERY_STRING "@contains | cat" "id:4002,phase:1,deny,status:403,msg:'Command injection - pipe cat'"

# Scanner detection
SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:5001,phase:1,deny,status:403,msg:'Scanner detected - sqlmap'"
SecRule REQUEST_HEADERS:User-Agent "@contains nikto" "id:5002,phase:1,deny,status:403,msg:'Scanner detected - nikto'"

# Request body rules (phase 2)
SecRule REQUEST_BODY "@contains ' OR '" "id:6001,phase:2,deny,status:403,msg:'SQL Injection in body'"
SecRule REQUEST_BODY "@contains UNION SELECT" "id:6002,phase:2,deny,status:403,msg:'SQL Injection in body - UNION'"
SecRule REQUEST_BODY "@contains <script" "id:6003,phase:2,deny,status:403,msg:'XSS in body'"
"#;

/// Helper to create a temporary rules file
fn create_rules_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let rules_path = dir.path().join("test-rules.conf");
    let mut file = std::fs::File::create(&rules_path).expect("Failed to create rules file");
    file.write_all(TEST_RULES.as_bytes())
        .expect("Failed to write rules");
    rules_path
}

/// Helper to start a ModSec agent server and return the socket path
async fn start_test_server(config: ModSecConfig) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().expect("Failed to create temp dir");
    let socket_path = dir.path().join("modsec-test.sock");

    let agent = ModSecAgent::new(config).expect("Failed to create ModSec agent");
    let server = AgentServer::new("test-modsec", socket_path.clone(), Box::new(agent));

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    (dir, socket_path)
}

/// Helper to start a test server with default test rules
async fn start_test_server_with_rules() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().expect("Failed to create temp dir");
    let rules_path = create_rules_file(&dir);
    let socket_path = dir.path().join("modsec-test.sock");

    let config = ModSecConfig {
        rules_paths: vec![rules_path.to_string_lossy().to_string()],
        ..Default::default()
    };

    let agent = ModSecAgent::new(config).expect("Failed to create ModSec agent");
    let server = AgentServer::new("test-modsec", socket_path.clone(), Box::new(agent));

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    (dir, socket_path)
}

/// Create a client connected to the test server
async fn create_client(socket_path: &std::path::Path) -> AgentClient {
    AgentClient::unix_socket("test-client", socket_path, Duration::from_secs(5))
        .await
        .expect("Failed to connect to agent")
}

/// Create a basic request metadata
fn make_metadata() -> RequestMetadata {
    let id = uuid::Uuid::new_v4().to_string();
    RequestMetadata {
        correlation_id: id.clone(),
        request_id: id,
        client_ip: "127.0.0.1".to_string(),
        client_port: 12345,
        server_name: Some("example.com".to_string()),
        protocol: "HTTP/1.1".to_string(),
        tls_version: Some("TLSv1.3".to_string()),
        tls_cipher: None,
        route_id: Some("default".to_string()),
        upstream_id: None,
        timestamp: "2025-01-01T00:00:00Z".to_string(),
        traceparent: None,
    }
}

/// Create a basic request headers event
fn make_request_headers(uri: &str, headers: HashMap<String, Vec<String>>) -> RequestHeadersEvent {
    RequestHeadersEvent {
        metadata: make_metadata(),
        method: "GET".to_string(),
        uri: uri.to_string(),
        headers,
    }
}

/// Create a request body chunk event
fn make_body_chunk(correlation_id: &str, data: &str, is_last: bool) -> RequestBodyChunkEvent {
    RequestBodyChunkEvent {
        correlation_id: correlation_id.to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(data),
        is_last,
        total_size: None,
        chunk_index: 0,
        bytes_received: data.len(),
    }
}

/// Create a response body chunk event
fn make_response_body_chunk(
    correlation_id: &str,
    data: &str,
    is_last: bool,
) -> ResponseBodyChunkEvent {
    ResponseBodyChunkEvent {
        correlation_id: correlation_id.to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(data),
        is_last,
        total_size: None,
        chunk_index: 0,
        bytes_sent: data.len(),
    }
}

/// Check if decision is Block
fn is_block(decision: &Decision) -> bool {
    matches!(decision, Decision::Block { .. })
}

/// Check if decision is Allow
fn is_allow(decision: &Decision) -> bool {
    matches!(decision, Decision::Allow)
}

// ============================================================================
// SQL Injection Tests
// ============================================================================

#[tokio::test]
async fn test_sqli_in_query_string_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("/search?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");

    // Check for WAF headers
    let has_waf_blocked = response.response_headers.iter().any(|h| match h {
        zentinel_agent_protocol::HeaderOp::Set { name, value } => {
            name == "X-WAF-Blocked" && value == "true"
        }
        _ => false,
    });
    assert!(has_waf_blocked, "Expected X-WAF-Blocked header");
}

#[tokio::test]
async fn test_sqli_union_select_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("/api?q=1 UNION SELECT * FROM users", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_sqli_detect_only_mode() {
    let dir = tempdir().expect("Failed to create temp dir");
    let rules_path = create_rules_file(&dir);
    let socket_path = dir.path().join("modsec-test.sock");

    let config = ModSecConfig {
        rules_paths: vec![rules_path.to_string_lossy().to_string()],
        block_mode: false, // Detect-only mode
        ..Default::default()
    };

    let agent = ModSecAgent::new(config).expect("Failed to create ModSec agent");
    let server = AgentServer::new("test-modsec", socket_path.clone(), Box::new(agent));

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("/search?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    // Should allow but add detection header
    assert!(is_allow(&response.decision), "Expected Allow decision");

    let has_waf_detected = response.request_headers.iter().any(|h| match h {
        zentinel_agent_protocol::HeaderOp::Set { name, .. } => name == "X-WAF-Detected",
        _ => false,
    });
    assert!(has_waf_detected, "Expected X-WAF-Detected header");
}

// ============================================================================
// XSS Tests
// ============================================================================

#[tokio::test]
async fn test_xss_script_tag_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("/page?name=<script>alert('xss')</script>", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_xss_event_handler_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("/page?input=<img src=x onerror=alert(1)>", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_xss_javascript_uri_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("/redirect?url=javascript:alert(1)", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_xss_in_header_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "X-Custom".to_string(),
        vec!["<script>evil()</script>".to_string()],
    );

    let event = make_request_headers("/api", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

// ============================================================================
// Path Traversal Tests
// ============================================================================

#[tokio::test]
async fn test_path_traversal_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("/files/../../../etc/passwd", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_path_traversal_encoded_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("/files/%2e%2e%2f%2e%2e%2fetc/passwd", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

// ============================================================================
// Command Injection Tests
// ============================================================================

#[tokio::test]
async fn test_command_injection_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("/run?cmd=`whoami`", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_command_injection_pipe_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("/exec?input=foo | cat /etc/passwd", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

// ============================================================================
// Path Exclusion Tests
// ============================================================================

#[tokio::test]
async fn test_excluded_path_allows_attack() {
    let dir = tempdir().expect("Failed to create temp dir");
    let rules_path = create_rules_file(&dir);
    let socket_path = dir.path().join("modsec-test.sock");

    let config = ModSecConfig {
        rules_paths: vec![rules_path.to_string_lossy().to_string()],
        exclude_paths: vec!["/health".to_string(), "/api/internal".to_string()],
        ..Default::default()
    };

    let agent = ModSecAgent::new(config).expect("Failed to create ModSec agent");
    let server = AgentServer::new("test-modsec", socket_path.clone(), Box::new(agent));

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = create_client(&socket_path).await;

    // Attack on excluded path should be allowed
    let event = make_request_headers("/health?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow decision");
}

#[tokio::test]
async fn test_non_excluded_path_blocks_attack() {
    let dir = tempdir().expect("Failed to create temp dir");
    let rules_path = create_rules_file(&dir);
    let socket_path = dir.path().join("modsec-test.sock");

    let config = ModSecConfig {
        rules_paths: vec![rules_path.to_string_lossy().to_string()],
        exclude_paths: vec!["/health".to_string()],
        ..Default::default()
    };

    let agent = ModSecAgent::new(config).expect("Failed to create ModSec agent");
    let server = AgentServer::new("test-modsec", socket_path.clone(), Box::new(agent));

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = create_client(&socket_path).await;

    // Attack on non-excluded path should be blocked
    let event = make_request_headers("/api?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

// ============================================================================
// Request Body Inspection Tests
// ============================================================================

#[tokio::test]
async fn test_body_sqli_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    // First send headers (will pass)
    let headers_event = make_request_headers("/api/users", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &headers_event)
        .await
        .expect("Failed to send headers event");
    assert!(is_allow(&response.decision), "Expected Allow decision");

    // Then send malicious body
    let body_event = make_body_chunk(
        &headers_event.metadata.correlation_id,
        r#"{"query": "SELECT * FROM users WHERE id=' OR '1'='1"}"#,
        true,
    );
    let response = client
        .send_event(EventType::RequestBodyChunk, &body_event)
        .await
        .expect("Failed to send body event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_body_xss_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let headers_event = make_request_headers("/api/comments", HashMap::new());
    let _ = client
        .send_event(EventType::RequestHeaders, &headers_event)
        .await
        .expect("Failed to send headers event");

    let body_event = make_body_chunk(
        &headers_event.metadata.correlation_id,
        r#"{"comment": "<script>document.cookie</script>"}"#,
        true,
    );
    let response = client
        .send_event(EventType::RequestBodyChunk, &body_event)
        .await
        .expect("Failed to send body event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

#[tokio::test]
async fn test_body_inspection_disabled_allows_attack() {
    let dir = tempdir().expect("Failed to create temp dir");
    let rules_path = create_rules_file(&dir);
    let socket_path = dir.path().join("modsec-test.sock");

    let config = ModSecConfig {
        rules_paths: vec![rules_path.to_string_lossy().to_string()],
        body_inspection_enabled: false,
        ..Default::default()
    };

    let agent = ModSecAgent::new(config).expect("Failed to create ModSec agent");
    let server = AgentServer::new("test-modsec", socket_path.clone(), Box::new(agent));

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = create_client(&socket_path).await;

    let headers_event = make_request_headers("/api/users", HashMap::new());
    let _ = client
        .send_event(EventType::RequestHeaders, &headers_event)
        .await
        .expect("Failed to send headers event");

    let body_event = make_body_chunk(
        &headers_event.metadata.correlation_id,
        r#"{"query": "SELECT * FROM users WHERE id=' OR '1'='1"}"#,
        true,
    );
    let response = client
        .send_event(EventType::RequestBodyChunk, &body_event)
        .await
        .expect("Failed to send body event");

    // Should allow when body inspection is disabled
    assert!(is_allow(&response.decision), "Expected Allow decision");
}

#[tokio::test]
async fn test_body_exceeds_max_size_skips_inspection() {
    let dir = tempdir().expect("Failed to create temp dir");
    let rules_path = create_rules_file(&dir);
    let socket_path = dir.path().join("modsec-test.sock");

    let config = ModSecConfig {
        rules_paths: vec![rules_path.to_string_lossy().to_string()],
        max_body_size: 50, // Very small limit
        ..Default::default()
    };

    let agent = ModSecAgent::new(config).expect("Failed to create ModSec agent");
    let server = AgentServer::new("test-modsec", socket_path.clone(), Box::new(agent));

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = create_client(&socket_path).await;

    let headers_event = make_request_headers("/api/upload", HashMap::new());
    let _ = client
        .send_event(EventType::RequestHeaders, &headers_event)
        .await
        .expect("Failed to send headers event");

    // Send a body that exceeds max size with an attack
    let large_body = format!(
        r#"{{"data": "{}' OR '1'='1"}}"#,
        "x".repeat(100) // Exceeds 50 byte limit
    );
    let body_event = make_body_chunk(&headers_event.metadata.correlation_id, &large_body, true);
    let response = client
        .send_event(EventType::RequestBodyChunk, &body_event)
        .await
        .expect("Failed to send body event");

    // Should allow because body exceeds max size (skip inspection)
    assert!(is_allow(&response.decision), "Expected Allow decision");
}

// ============================================================================
// Response Body Tests (placeholder - not fully implemented in agent)
// ============================================================================

#[tokio::test]
async fn test_response_body_not_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let correlation_id = uuid::Uuid::new_v4().to_string();
    let response_body = make_response_body_chunk(
        &correlation_id,
        "<html><script>alert('reflected')</script></html>",
        true,
    );
    let response = client
        .send_event(EventType::ResponseBodyChunk, &response_body)
        .await
        .expect("Failed to send response body event");

    // Response body inspection not yet implemented - should allow
    assert!(is_allow(&response.decision), "Expected Allow decision");
}

// ============================================================================
// Clean Request Tests
// ============================================================================

#[tokio::test]
async fn test_clean_request_allowed() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["Mozilla/5.0".to_string()]);
    headers.insert("Accept".to_string(), vec!["text/html".to_string()]);

    let event = make_request_headers("/api/users?page=1&limit=10", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow decision");
    assert!(response.response_headers.is_empty());
}

#[tokio::test]
async fn test_clean_body_allowed() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let headers_event = make_request_headers("/api/users", HashMap::new());
    let _ = client
        .send_event(EventType::RequestHeaders, &headers_event)
        .await
        .expect("Failed to send headers event");

    let body_event = make_body_chunk(
        &headers_event.metadata.correlation_id,
        r#"{"name": "John Doe", "email": "john@example.com"}"#,
        true,
    );
    let response = client
        .send_event(EventType::RequestBodyChunk, &body_event)
        .await
        .expect("Failed to send body event");

    assert!(is_allow(&response.decision), "Expected Allow decision");
}

// ============================================================================
// Scanner Detection Tests
// ============================================================================

#[tokio::test]
async fn test_scanner_user_agent_blocked() {
    let (_dir, socket_path) = start_test_server_with_rules().await;
    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["sqlmap/1.0".to_string()]);

    let event = make_request_headers("/api", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision");
}

// ============================================================================
// No Rules Tests
// ============================================================================

#[tokio::test]
async fn test_no_rules_allows_attack() {
    let config = ModSecConfig {
        rules_paths: vec![], // No rules
        ..Default::default()
    };
    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    // Even attacks should be allowed without rules
    let event = make_request_headers("/search?id=' OR '1'='1", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow decision");
}
