# Architecture

How a request moves through the agent, and where state lives. Everything here is in `src/lib.rs` unless noted; `src/main.rs` only parses flags and starts the server.

## Pieces

```
Zentinel proxy ──(agent protocol v2: UDS or gRPC)──> UdsAgentServerV2 / GrpcAgentServerV2
                                                        │  (zentinel-agent-protocol crate)
                                                        ▼
                                                   ModSecAgent  (AgentHandlerV2)
                                                   ├── engine: Arc<RwLock<ModSecEngine>>
                                                   │     ├── ModSecurity   (libmodsecurity instance)
                                                   │     ├── Rules         (compiled rule set)
                                                   │     └── ModSecConfig  (settings in effect)
                                                   ├── pending_requests: RwLock<HashMap<correlation id, PendingTransaction>>
                                                   ├── base_config       (flags + environment)
                                                   ├── last_configure    (hash of the last accepted config block)
                                                   └── draining_until_ms (end of the drain window, 0 if none)
```

- **`ModSecEngine`** owns one libmodsecurity instance and one compiled rule set. It is built at startup from the command line, and rebuilt by a configure that changes `rules-paths` or `body-inspection-enabled`. Building it adds `SecRuleEngine On`; with body inspection, also `SecRequestBodyAccess On` and the JSON and XML body processor rules (ids 200000 and 200001, from `modsecurity.conf-recommended`), then loads each rule file by path in the order given.
- **`ModSecAgent`** implements the protocol handler. It holds the engine behind a `tokio::sync::RwLock`: requests take a read lock, a configure takes the write lock to swap the engine or its settings.
- **Pending map.** A request whose headers passed and whose body may still come has a `PendingTransaction` here: method, URI, a copy of the headers, client IP and the body bytes received so far. A request whose body is not inspected by configuration has a marker instead (no copy of the request), so its chunks are recognised. Entries are keyed by the proxy's correlation id.

## Request lifecycle

The proxy sends events per request; the agent advertises `request_headers`, `request_body_chunk`, `response_headers` and `response_body_chunk`. Only the first two do any inspection.

### `request_headers`

"A body may follow" below means body inspection is on and the request does not have `Content-Length: 0` (every value). Nothing else proves there is no body: the proxy reports `HTTP/1.1` for every request and HTTP/2 needs no `Content-Length`. Parking is subject to the cap (see Pending map lifetime).

1. If the path starts with an `exclude-paths` prefix: Allow. If a body may follow, park a marker: the body is allowed uninspected.
2. Run a libmodsecurity transaction (`process_request`) with an empty body: `process_uri`, every request header, `process_request_headers` (phase 1), then `process_request_body` on zero bytes (phase 2). Phase 2 runs here because CRS evaluates `ARGS` (the query string) and makes its anomaly-score blocking decision (rule 949110) in phase 2; without it no `GET` is blocked under stock CRS.
3. Intervention → the verdict is answered (see Decisions). In block mode nothing is parked. In detect-only mode, if a body may follow, a marker is parked; the body is not inspected again.
4. No intervention and a body may follow → park a `PendingTransaction` and Allow.
5. No intervention and no body can follow → Allow. Nothing is parked.
6. Engine error → `warn` log and Allow. If a body may follow, park a marker: the body is allowed too.

### `request_body_chunk`

1. Body inspection off → Allow.
2. No pending entry for the correlation id → block mode: fail-closed `403` (tag `fail-closed`); detect-only: `warn` and Allow. A body chunk arrives without an entry only if the entry was released (response started, idle timeout) or never made (refused at the cap); the agent does not let a body through because its state is missing.
3. Refresh the entry's idle timer.
4. Decode the chunk (base64). If decoding fails: block mode → remove the entry and fail-closed `403`; detect-only → `warn`, mark the entry as not inspected and Allow.
5. Marker → Allow; on the last chunk, remove it.
6. If the buffered body plus this chunk exceeds `max-body-size` → free the buffer, turn the entry into a marker and Allow. The rest of the body passes uninspected; this is the documented `max-body-size` behavior.
7. Append the chunk. If it is not the last chunk → Allow.
8. On the last chunk, remove the entry and run the whole transaction again, with the method, URI and headers saved at step 4 above and the full body. Phases 1 and 2 both run again, now with the body parsed by the body processor libmodsecurity selected (URL-encoded, multipart, JSON or XML).
9. Intervention → verdict; otherwise Allow. Engine error → `warn` and Allow.

The engine used in step 8 is the one in effect when the last chunk arrives, so a request whose body straddles a configure is inspected with the new settings.

### `response_headers`

Removes the pending entry for that correlation id, if any, and allows: once the response has started, no request body is inspected. This releases the entry of a request that sent no body, whether or not the proxy sends `RequestComplete`.

### `response_body_chunk`

Allow. Response inspection is not implemented; `--response-inspection` is accepted and ignored.

### `request_complete`

Removes the pending entry for that correlation id, if any, and allows.

## Transactions

One libmodsecurity transaction is created per `process_request` call, so a request with a body uses two: one at headers, one at the last chunk. The transaction borrows the engine's `Rules` under the read lock and is dropped before the function returns; nothing awaits while it is alive. The log callback collects every line libmodsecurity logs during the transaction, from which the agent reads the ids and `msg` of the rules that logged.

## Decisions

A transaction's intervention with status 0 or 200 is ignored. Otherwise the agent builds a verdict: the status from the intervention, the triggering rule id and `msg` from the intervention's own log line (falling back to the last rule that logged), and the list of every rule that logged.

| Mode | Response to the proxy |
|---|---|
| Block mode | `Block` with the intervention status, body `Forbidden`, response headers `X-WAF-Blocked: true`, `X-WAF-Message: Blocked by ModSecurity` |
| Detect-only (`block-mode false`) | `Allow`, request header `X-WAF-Detected: Blocked by ModSecurity` added upstream |

Both carry `AuditMetadata` with tags (`modsec`, `blocked` or `detected`, and `body` for body-stage decisions), `rule_ids` and `reason_codes` (the sanitized rule message), and both are logged at `info` (see [operations.md](operations.md#logging-of-blocks)). The client never sees rule ids or messages.

In detect-only mode a detection at the headers stage parks a marker, so that request's body is allowed without being inspected again. Detect-only mode never blocks: where block mode fails closed (no pending entry, undecodable chunk, cap reached), detect-only logs a warning and allows.

## Pending map lifetime

An entry (or marker) is created by `request_headers` when a body may follow, and removed by:

- the last body chunk,
- `on_response_headers` (the response has started),
- `on_request_complete`,
- the idle sweep: an entry with no event (headers or body chunk) for 120 s is dropped. Each chunk refreshes the timer, so a slow upload is not dropped while it streams. The sweep runs when a request is parked, at most once a second,
- `on_shutdown` (clears the map).

It is **not** removed by a configure (#7) or a drain (#11). Both used to clear it, which let a body that straddled them through uninspected.

The map is capped at 100 000 entries. At the cap a new request that would be parked is refused: block mode answers a fail-closed `403`, detect-only allows it without parking. No entry is evicted to make room, so a client cannot push its own parked request out with new requests and then send the body uninspected. A body chunk for a released entry fails closed in block mode.

## Configure

The proxy sends the agent's `config { }` block in a `Configure` message on every connection it opens. `configure()`:

1. Hashes the payload (`config_hash`: FNV-1a over canonical JSON with sorted keys). Same hash as the last accepted payload → nothing to do.
2. Parses it strictly (`ModSecConfigJson`, `deny_unknown_fields`, typed values, lists may be a single string).
3. Overlays it on `base_config` (the flags and environment), never on a previous block.
4. Applies it: rebuild the engine (strictly: every `rules-paths` pattern must match a file) if `rules-paths` or `body-inspection-enabled` changed, otherwise update the settings in place. Any error leaves the active engine and settings unchanged and the configure is refused.
5. Logs the hash and the names of the changed settings.

Configures are serialized by the `last_configure` mutex, since the proxy sends one per pooled connection concurrently.

## Drain and health

`on_drain(duration_ms)` records `now + duration_ms` in `draining_until_ms` and does nothing else. `health_status` reports `Draining { eta_ms }` until that time, then `Healthy` again (the protocol has no resume message). Requests that arrive during a drain are inspected normally: refusing them with a `Block` would reach clients as a WAF decision instead of the route's failure mode, and routing around a draining agent is the proxy's job. Pending bodies are kept (#8, fixed in #11).

`on_shutdown` logs and clears the pending map.

## Transport notes (zentinel-agent-protocol 0.6.50)

These are properties of the protocol crate version in `Cargo.lock`, not of this agent; recheck them when it is bumped.

- UDS dispatches `Configure` to `on_configure`; the gRPC server does not, so the `config { }` block has no effect over gRPC.
- Neither server calls `on_drain` or `on_shutdown`, and `Cancel` is only logged. The drain and shutdown handling above is correct but not reachable yet, and a cancelled request's entry stays until `RequestComplete`.
- The gRPC server polls `health_status` but only logs it at `trace`; its heartbeat to the proxy does not carry the state. The UDS server does not read it. `metrics_report` is never called (and returns an empty report). So `Draining` is not yet visible to the proxy either.

## FFI boundary

All calls into libmodsecurity go through the `modsecurity` crate (1.0), which wraps `modsecurity-sys`. This crate has no `unsafe` code. `modsecurity-sys` links the system library found by `pkg-config` (`modsecurity` >= 3.0.13) and cannot vendor it, so the agent binary depends on `libmodsecurity.so.3` / `libmodsecurity.3.dylib` at run time.

Assumptions the agent relies on:

- `ModSecurity` and `Rules` are shared across tasks (the crate marks them `Send` and `Sync`); libmodsecurity supports concurrent transactions over one compiled rule set.
- A `Transaction` is used by one task at a time and never outlives the read lock on the engine whose `Rules` it borrows. A configure that rebuilds the engine waits for in-flight transactions to finish.
- Strings from libmodsecurity (log lines, rule messages) are treated as untrusted: rule messages are cut to 200 characters and non-printable characters replaced before they are logged or put in audit metadata.
