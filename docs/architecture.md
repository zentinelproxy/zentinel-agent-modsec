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
- **Pending map.** A request whose headers passed and whose body is still to come has a `PendingTransaction` here: method, URI, a copy of the headers, client IP and the body bytes received so far. It is keyed by the proxy's correlation id.

## Request lifecycle

The proxy sends events per request; the agent advertises `request_headers`, `request_body_chunk`, `response_headers` and `response_body_chunk`. Only the first two do any inspection.

### `request_headers`

1. If the path starts with an `exclude-paths` prefix: Allow. Nothing is parked, so the body is not inspected either.
2. Run a libmodsecurity transaction (`process_request`) with an empty body: `process_uri`, every request header, `process_request_headers` (phase 1), then `process_request_body` on zero bytes (phase 2). Phase 2 runs here because CRS evaluates `ARGS` (the query string) and makes its anomaly-score blocking decision (rule 949110) in phase 2; without it no `GET` is blocked under stock CRS.
3. Intervention → the verdict is answered (see Decisions). Nothing is parked.
4. No intervention and body inspection on → park a `PendingTransaction` and Allow. The agent always parks, because whether a body follows cannot be known from the headers (HTTP/2 needs no `Content-Length`).
5. No intervention and body inspection off → Allow.
6. Engine error → `warn` log and Allow. Nothing is parked.

### `request_body_chunk`

1. No pending entry for the correlation id (excluded path, inspection off, headers blocked or errored, body already over the limit) → Allow.
2. Decode the chunk (base64). If decoding fails: `warn` and Allow for this chunk; the entry stays.
3. If the buffered body plus this chunk exceeds `max-body-size` → remove the entry and Allow. The rest of the body passes uninspected; this is the documented `max-body-size` behavior.
4. Append the chunk. If it is not the last chunk → Allow.
5. On the last chunk, remove the entry and run the whole transaction again, with the method, URI and headers saved at step 4 above and the full body. Phases 1 and 2 both run again, now with the body parsed by the body processor libmodsecurity selected (URL-encoded, multipart, JSON or XML).
6. Intervention → verdict; otherwise Allow. Engine error → `warn` and Allow.

The engine used in step 5 is the one in effect when the last chunk arrives, so a request whose body straddles a configure is inspected with the new settings.

### `response_headers`, `response_body_chunk`

Allow. Response inspection is not implemented; `--response-inspection` is accepted and ignored.

### `request_complete`

Removes the pending entry for that correlation id, if any, and allows. This is the only path that releases a body-less request's entry (see Pending map lifetime).

## Transactions

One libmodsecurity transaction is created per `process_request` call, so a request with a body uses two: one at headers, one at the last chunk. The transaction borrows the engine's `Rules` under the read lock and is dropped before the function returns; nothing awaits while it is alive. The log callback collects every line libmodsecurity logs during the transaction, from which the agent reads the ids and `msg` of the rules that logged.

## Decisions

A transaction's intervention with status 0 or 200 is ignored. Otherwise the agent builds a verdict: the status from the intervention, the triggering rule id and `msg` from the intervention's own log line (falling back to the last rule that logged), and the list of every rule that logged.

| Mode | Response to the proxy |
|---|---|
| Block mode | `Block` with the intervention status, body `Forbidden`, response headers `X-WAF-Blocked: true`, `X-WAF-Message: Blocked by ModSecurity` |
| Detect-only (`block-mode false`) | `Allow`, request header `X-WAF-Detected: Blocked by ModSecurity` added upstream |

Both carry `AuditMetadata` with tags (`modsec`, `blocked` or `detected`, and `body` for body-stage decisions), `rule_ids` and `reason_codes` (the sanitized rule message), and both are logged at `info` (see [operations.md](operations.md#logging-of-blocks)). The client never sees rule ids or messages.

In detect-only mode a detection at the headers stage parks nothing, so that request's body is not inspected.

## Pending map lifetime

An entry is created at step 4 of `request_headers` and removed by:

- the last body chunk (inspected),
- a chunk that takes the body over `max-body-size` (allowed by configuration),
- `on_request_complete`,
- `on_shutdown` (clears the map).

It is **not** removed by a configure (#7) or a drain (#11). Both used to clear it, which let a body that straddled them through uninspected.

A request that sends no body is released by `RequestComplete`, which Zentinel sends to participating agents from release 26.11_3. See [operations.md](operations.md#resource-limits).

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
