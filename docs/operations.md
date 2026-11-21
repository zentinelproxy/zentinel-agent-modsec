# Operations

Running the agent in production: what to configure, what it tells you, and how it fails. The [README](../README.md) is the reference for installation, every flag, and the `config { }` block; this page does not repeat it.

## Configuration in brief

| Setting | Flag / env | `config { }` key | Default |
|---|---|---|---|
| Rule files (globs, in order) | `--rules` / `MODSEC_RULES` | `rules-paths` (`rules`) | none: nothing is blocked |
| Block or detect-only | `--block-mode` / `MODSEC_BLOCK_MODE` | `block-mode` | block |
| Path prefixes to skip | `--exclude-paths` / `MODSEC_EXCLUDE_PATHS` | `exclude-paths` | none |
| Request body inspection | `--body-inspection` / `MODSEC_BODY_INSPECTION` | `body-inspection-enabled` (`body-inspection`) | on |
| Largest body inspected | `--max-body-size` / `MODSEC_MAX_BODY_SIZE` | `max-body-size` | 1 MiB |
| Response inspection | `--response-inspection` | `response-inspection-enabled` | off; not implemented |

- Load `crs-setup.conf` first, then the rule files; the agent loads them in the order given. Paranoia level, anomaly thresholds and exclusions belong in the rules, not in agent settings.
- The `config { }` block is overlaid on the flags; it is applied over the Unix socket only (see [architecture.md](architecture.md#transport-notes-zentinel-agent-protocol-0650)). A block that cannot be applied is refused, the previous configuration stays in effect, and the proxy does not use that connection.
- The boolean flags are switches; turn one off with its environment variable (`MODSEC_BLOCK_MODE=false`).
- Request bodies reach the agent only if the proxy's `waf { body-inspection { inspect-request-body #true } }` is set and the agent's `events` include `"request_body"`. If the proxy does not send bodies, also run the agent with `MODSEC_BODY_INSPECTION=false`: with body inspection on, the agent buffers state for every request in anticipation of a body (see Resource limits). Query-string and header attacks are still caught, because phase 2 runs at the headers stage either way.

## Failure modes

The agent decides Allow or Block; what happens when the agent cannot answer is the proxy's setting.

- `failure-mode "closed"` on the agent and filter: requests are refused while the agent is unreachable or times out. Use this for a WAF in front of anything that matters.
- `failure-mode "open"`: requests pass uninspected while the agent is down. Every attack the rules would have blocked passes too.
- The agent itself fails open on an engine error (libmodsecurity returns an error for a transaction): it logs `ModSecurity processing error` or `ModSecurity body processing error` at `warn` and allows. A steady stream of these needs investigating; it is not normal operation.
- Configured exclusions, bodies over `max-body-size`, and detect-only mode all allow by design. A detect-only detection at the headers stage also skips inspection of that request's body.
- Keep `timeout-ms` on the agent above the time CRS takes on your largest inspected body. The agent advertises a 5 s maximum processing time.

## Health and draining

When the proxy drains the agent, the agent reports `Draining` with the remaining time through its health status and keeps inspecting every request it receives, including bodies that were being buffered when the drain began. It does not refuse new requests; moving traffic away from a draining agent is the proxy's job. After the drain window ends it reports `Healthy` again.

With `zentinel-agent-protocol` 0.6.50 (the version this release is built with), the protocol servers do not deliver drain or shutdown to the agent and do not forward its health state to the proxy, so in practice health is always `Healthy` and a drain has no effect on the agent. Monitor the agent process itself.

A rule file that fails to parse at startup is fatal (the process exits with the error); at configure time it only refuses the configure.

## Logging of blocks

Logs are JSON on stdout. Every decision that matched is logged at `info`:

- `Request blocked by ModSecurity` (block mode) or `ModSecurity detection (detect-only mode)`
- fields: `correlation_id`, `status` (block mode), `stage` (`headers` or `body`), `trigger` (id of the rule that caused the intervention), `rules` (ids of every rule that logged, comma separated), `rule_msg` (the triggering rule's `msg`, sanitized)

The same ids and message are attached to the agent's response as audit metadata (`rule_ids`, `reason_codes`) for the proxy's audit log. The client sees only `Forbidden` and `X-WAF-Blocked: true`.

Rules that matched without an intervention are logged at `debug` (`--verbose` / `MODSEC_VERBOSE=true`), together with everything else at that level.

The log level is set only by `--verbose`; `RUST_LOG` is not read. Configures are logged with the payload hash and the names of the changed settings, never their values. Rejected configures are logged at `warn` with the reason.

Note: rule id reporting landed after 0.4.1. With 0.4.1 and earlier, the block line does not carry `trigger`, `rules` or `rule_msg`.

## Resource limits

| Resource | Bound | Notes |
|---|---|---|
| Body buffer per request | `max-body-size` (default 1 MiB) | A body over the limit is passed uninspected and its buffer freed. Match it to the proxy's `max-inspection-bytes` so the two agree on what gets inspected. |
| Pending requests | released on the last body chunk, an oversized body, or `RequestComplete` | One entry per request waiting for its body: method, URI, a copy of all headers, client IP and the body so far. Run Zentinel 26.11_3 or later, which sends `RequestComplete`. |
| Rule set | one copy | Shared by all requests. A configure that changes rules builds the new set before swapping it in, so memory briefly holds two. |
| Concurrency | advertised 100 | `max_concurrency` and `concurrent_requests` in the capabilities; the agent itself does not enforce a limit. |

Run the agent under a process memory limit (systemd `MemoryMax=`, a container limit) in any case, sized for the rule set plus `max-body-size` times your concurrent uploads.
