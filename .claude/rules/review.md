# Review rules

What a change to this agent must satisfy before it merges. Each rule names the change that made it a rule.

---

## 1. libmodsecurity v3 is the reference

- How a request is evaluated (phases, variables, transformations, body processors, intervention status) is whatever libmodsecurity 3 does with the same rules. Do not reimplement SecLang behavior in Rust or special-case CRS rule ids.
- The agent only adds what libmodsecurity needs from its host and stock CRS does not set: `SecRuleEngine On`, and with body inspection `SecRequestBodyAccess On` plus the JSON/XML body processor rules (ids 200000, 200001) from `modsecurity.conf-recommended`. A new directive added in code needs the same justification.
- Rule files are loaded by path (`Rules::add_file`), never as text: libmodsecurity resolves `@pmFromFile` and other data files relative to the rule file (#6).
- Phase 2 runs for every request, with an empty body if there is none: CRS evaluates `ARGS` and makes its blocking decision (949110) in phase 2 (#6).
- A test of CRS behavior runs against stock CRS at the commit CI pins, not a hand-written imitation of a CRS rule.

## 2. Every request body ends inspected, or allowed by configuration

For each request that passes `on_request_headers`, its body must end in one of:

- inspected by `process_request` when the last chunk arrives, or
- allowed because configuration says so: path in `exclude-paths`, body inspection off, body larger than `max-body-size`, or detect-only mode.

It must never be allowed because agent state was lost. The example is #8, fixed in #11: `on_drain` cleared `pending_requests`, so a body that straddled a drain found no pending entry and its last chunk was allowed uninspected. Hence:

- `on_drain` must not touch `pending_requests`. Draining is signalled through `health_status` (`Draining { eta_ms }`) only; requests that arrive during a drain are inspected as usual. Do not return a Block to refuse them: the proxy treats it as a WAF decision, not a failure mode.
- `on_configure` must not drop pending entries, including when it rebuilds the engine (#7). Pending bodies are inspected with the engine in effect when their last chunk arrives.
- Any new path that removes a pending entry, or returns Allow from `on_request_body_chunk`, needs a test showing which of the two outcomes above it is.

Known gaps on `main` to keep in mind (do not copy the pattern): a headers-phase engine error allows the request and parks nothing, so its body is not inspected; an undecodable chunk is allowed and dropped from the buffer while the entry stays.

## 3. Pending state is bounded

`pending_requests` holds one entry (method, URI, cloned headers, client IP, body so far) per request that is waiting for its body. Every entry must have a bounded lifetime that does not depend on the client sending a body.

- Today entries leave on the last chunk, on an oversized body, on `on_request_complete`, and on shutdown. With body inspection on, every request that passes the headers is parked, including body-less ones, and only `RequestComplete` removes those. Zentinel sends it from 26.11_3; earlier proxies never do, and the map then grows by one entry per request. PR #9 (open) adds release on response headers, no parking for `Content-Length: 0`, an idle timeout and a cap.
- A change must not add another unbounded growth path, and must not rely on the proxy alone to release state.
- A cap or eviction must fail closed and must not let a client evict its own parked request to get its body through uninspected (see the review of #9). Detect-only mode must never block because of a cap or unknown state.
- Body buffers are limited by `max-body-size`; keep the check before the append.

## 4. Configure is idempotent, merging and strict (#7)

- Identical payload (by `config_hash`) changes nothing. The proxy sends the block on every pooled connection and reconnect.
- The block is overlaid on the CLI/environment config (`base_config`), never on a previous block. An absent key keeps the CLI value.
- Reject, and keep the active config, for: unknown key (`deny_unknown_fields`), wrong type, a list empty after trimming, `max-body-size 0`, a `rules-paths` pattern matching no file (`new_strict`), a rule file that does not parse. A configure that names rules never leaves zero rules loaded.
- Rebuild the rule set only when `rules-paths` or `body-inspection-enabled` changed.
- Log the hash and the names of changed keys, never values.
- A new setting gets a `ModSecConfigJson` field, an entry in `changed_keys`, a decision on `needs_rebuild`, a README table row, and a test in `tests/configure.rs`.

## 5. A block names its rule (#4)

- The `Request blocked by ModSecurity` (or detect-only) log line at `info` carries `trigger` (id of the intervening rule), `rules` (every rule that logged) and `rule_msg`; the response carries `rule_ids` and `reason_codes` in `AuditMetadata`.
- The client never sees rule ids or rule text: body `Forbidden`, `X-WAF-Message: Blocked by ModSecurity`. Rule messages are sanitized (printable ASCII, 200 chars) before logging.
- `tests/rule_id_logging.rs` covers headers, body, body-less phase 2 and detect-only; extend it for new block paths.

## 6. FFI and concurrency

- No `unsafe` in this crate. If an FFI gap needs it, fix the `modsecurity` crate or justify it in the PR with a `// SAFETY:` comment.
- A `Transaction` borrows the `Rules` of the engine under the read lock; keep it inside `process_request`, with no `.await` while it is alive.
- Engine errors are logged at `warn` and allow (documented in the README). Do not turn them into silent allows elsewhere.

## 7. CI and release

- Changes to `.github/workflows/` (including the libmodsecurity build, the `CRS_COMMIT` and `ZENTINEL_RELEASE` pins, cache keys) need sign-off from a maintainer. The smoke test is what keeps a broken release from shipping (0.3.0 could not complete the v2 handshake while every test passed).
- `scripts/smoke-test.sh` is shared with `release.yml`; a change to it is a change to the release gate.
- Before merging: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (with CRS present for anything touching detection).
