//! Regression tests for unbounded `pending_requests` growth and fail-closed body handling.

use std::collections::HashMap;

use base64::Engine;
use tempfile::tempdir;
use zentinel_agent_modsec::{ModSecAgent, ModSecConfig};
use zentinel_agent_protocol::{
    v2::AgentHandlerV2, Decision, RequestBodyChunkEvent, RequestHeadersEvent, RequestMetadata,
    ResponseHeadersEvent,
};

fn metadata(id: &str) -> RequestMetadata {
    RequestMetadata {
        correlation_id: id.to_string(),
        request_id: id.to_string(),
        client_ip: "127.0.0.1".to_string(),
        client_port: 12345,
        server_name: None,
        protocol: "HTTP/1.1".to_string(),
        tls_version: None,
        tls_cipher: None,
        route_id: None,
        upstream_id: None,
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        traceparent: None,
    }
}

fn headers_event(
    id: &str,
    method: &str,
    uri: &str,
    headers: HashMap<String, Vec<String>>,
) -> RequestHeadersEvent {
    RequestHeadersEvent {
        metadata: metadata(id),
        method: method.to_string(),
        uri: uri.to_string(),
        headers,
    }
}

fn body_chunk(id: &str, data: &[u8], is_last: bool) -> RequestBodyChunkEvent {
    RequestBodyChunkEvent {
        correlation_id: id.to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(data),
        is_last,
        total_size: Some(data.len()),
        chunk_index: 0,
        bytes_received: data.len(),
    }
}

fn minimal_agent() -> (tempfile::TempDir, ModSecAgent) {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("rules.conf"), "# pending leak regression\n").unwrap();
    let config = ModSecConfig {
        rules_paths: vec![dir.path().join("rules.conf").display().to_string()],
        ..Default::default()
    };
    (dir, ModSecAgent::new(config).unwrap())
}

/// Known-empty bodies (`Content-Length: 0`) must not park when body inspection is on (10k soak).
#[tokio::test]
async fn ten_thousand_bodyless_gets_do_not_grow_pending() {
    let (_dir, agent) = minimal_agent();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), vec!["0".to_string()]);
    for i in 0..10_000 {
        let id = format!("get-{i}");
        let response = agent
            .on_request_headers(headers_event(&id, "GET", "/health", headers.clone()))
            .await;
        assert!(
            matches!(response.decision, Decision::Allow),
            "unexpected block for {id}"
        );
    }
    assert_eq!(
        agent.pending_count().await,
        0,
        "pending map must stay empty for Content-Length: 0 requests"
    );
}

/// `POST` with `Content-Length: 0` runs phase 2 on headers and never parks.
#[tokio::test]
async fn post_with_content_length_zero_blocks_in_phase_two_without_parking() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("rules.conf"),
        r#"SecRule ARGS "@contains evil" "id:10,phase:2,deny,status:403""#,
    )
    .unwrap();
    let config = ModSecConfig {
        rules_paths: vec![dir.path().join("rules.conf").display().to_string()],
        ..Default::default()
    };
    let agent = ModSecAgent::new(config).unwrap();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), vec!["0".to_string()]);

    let blocked = agent
        .on_request_headers(headers_event(
            "cl0",
            "POST",
            "/search?q=evil",
            headers.clone(),
        ))
        .await;
    assert!(matches!(
        blocked.decision,
        Decision::Block { status: 403, .. }
    ));
    assert_eq!(agent.pending_count().await, 0);

    let allowed = agent
        .on_request_headers(headers_event("cl0-clean", "POST", "/search?q=ok", headers))
        .await;
    assert!(matches!(allowed.decision, Decision::Allow));
    assert_eq!(agent.pending_count().await, 0);
}

// Cap-at-limit and stale-pending sweep: see `src/lib.rs` unit tests (`PENDING_REQUESTS_MAX` is 10).

/// Bodied POST still parks until the last body chunk (unchanged behavior).
#[tokio::test]
async fn bodied_post_still_parks_until_last_chunk() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("rules.conf"),
        r#"SecRule REQUEST_BODY "@contains attack" "id:2,phase:2,deny,status:403""#,
    )
    .unwrap();
    let config = ModSecConfig {
        rules_paths: vec![dir.path().join("rules.conf").display().to_string()],
        ..Default::default()
    };
    let agent = ModSecAgent::new(config).unwrap();

    let headers = agent
        .on_request_headers(headers_event("bodied", "POST", "/submit", HashMap::new()))
        .await;
    assert!(matches!(headers.decision, Decision::Allow));
    assert_eq!(agent.pending_count().await, 1);

    let body = agent
        .on_request_body_chunk(body_chunk("bodied", b"payload attack", true))
        .await;
    assert!(matches!(body.decision, Decision::Block { .. }));
    assert_eq!(agent.pending_count().await, 0);
}

/// Response headers must drop a pending buffer so a late body chunk is denied.
#[tokio::test]
async fn response_headers_clear_pending_before_late_body_chunk() {
    let (_dir, agent) = minimal_agent();

    agent
        .on_request_headers(headers_event("late", "POST", "/x", HashMap::new()))
        .await;
    assert_eq!(agent.pending_count().await, 1);

    agent
        .on_response_headers(ResponseHeadersEvent {
            correlation_id: "late".to_string(),
            status: 200,
            headers: HashMap::new(),
        })
        .await;
    assert_eq!(agent.pending_count().await, 0);

    let denied = agent
        .on_request_body_chunk(body_chunk("late", b"after-response", true))
        .await;
    assert!(
        matches!(denied.decision, Decision::Block { status: 403, .. }),
        "late body after response must fail closed"
    );
}
