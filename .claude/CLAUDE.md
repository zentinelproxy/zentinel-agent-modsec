# zentinel-agent-modsec

> **Zentinel agent that runs ModSecurity rules, including the OWASP Core Rule Set, through the C library libmodsecurity 3.**

The agent is an external process that the Zentinel proxy calls over agent protocol v2 (Unix socket, or gRPC with `--grpc-address`). For every request it builds a libmodsecurity transaction, runs the rules on the URI, headers and (optionally) the body, and answers Allow or Block. It links libmodsecurity dynamically through the `modsecurity` / `modsecurity-sys` crates, so the library must be present to build and to run.

## Which WAF agent is this?

| Repository | Engine | Rule language |
|---|---|---|
| `zentinel-agent-modsec` (this one) | libmodsecurity 3 (C, via FFI) | SecLang, stock CRS |
| `zentinel-agent-zentinelsec` | `zentinel-modsec`, a pure-Rust SecLang engine | SecLang, stock CRS |
| `zentinel-agent-waf` | Zentinel's own pure-Rust detector | Its own rule set, no SecLang |

This agent is the reference: when it and zentinelsec disagree on a CRS request, libmodsecurity v3 behavior is what is expected. Do not port behavior from the siblings into this repo without checking it against libmodsecurity.

## Module map

| Path | Purpose |
|---|---|
| `src/main.rs` | CLI (`clap`, flags and env vars), JSON logging, starts `UdsAgentServerV2` or `GrpcAgentServerV2` |
| `src/lib.rs` | Everything else: `ModSecConfig`, `ModSecConfigJson` (the `config { }` block), `ModSecEngine` (rule loading), `ModSecAgent` (the `AgentHandlerV2` impl, pending map, verdicts, drain state) |
| `tests/integration.rs` | Small inline rule set over a real UDS server and client |
| `tests/crs_integration.rs` | Stock CRS; skips without `testdata/crs`, fails on CI (`CI` set) without it |
| `tests/configure.rs` | Configure: idempotent, merging, strict; pending bodies survive it |
| `tests/drain.rs` | Drain keeps pending bodies; health reports `Draining` |
| `tests/rule_id_logging.rs` | Block log line and audit metadata carry rule id and message |
| `scripts/smoke-test.sh` | Release binary + stock CRS behind a real Zentinel |
| `docs/` | `architecture.md`, `operations.md`, `building-libmodsecurity.md` |

There is no `unsafe` in this repo; all FFI goes through the `modsecurity` crate.

## Commands

Building needs Rust 1.94.1+ (`rust-version` in `Cargo.toml`), `protoc` (the protocol crate compiles its protobufs), `pkg-config`, and libmodsecurity >= 3.0.13 visible to `pkg-config` (`modsecurity-sys` probes `modsecurity` with `atleast_version("3.0.13")` and cannot vendor it). On Linux, build libmodsecurity with `--with-pcre2`; see `docs/building-libmodsecurity.md`. On macOS, `brew install modsecurity protobuf`.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --locked
```

The CRS tests pass vacuously without a CRS checkout. To run them for real, fetch the commit CI pins (`CRS_COMMIT` in `.github/workflows/ci.yml`) the same way the `Tests` job does:

```bash
CRS_COMMIT=<from ci.yml>
git init -q testdata/crs-src
git -C testdata/crs-src fetch -q --depth 1 https://github.com/coreruleset/coreruleset.git "$CRS_COMMIT"
git -C testdata/crs-src checkout -q FETCH_HEAD
mkdir -p testdata/crs
cp -R testdata/crs-src/rules testdata/crs/
cp testdata/crs-src/crs-setup.conf.example testdata/crs/crs-setup.conf
CI=1 cargo test --test crs_integration   # CI=1: fail instead of skip if missing
```

`testdata/crs*` is git-ignored.

### Smoke test behind Zentinel

The `smoke` CI job (and every platform in `release.yml`) runs `scripts/smoke-test.sh`: it starts the agent with stock CRS, starts a real Zentinel in front of a Python upstream, and checks a clean request (200), three attacks (403, never reaching the upstream), and that stopping the agent stops traffic under fail-closed. It runs on Linux and macOS and needs bash, curl and python3. Locally:

```bash
cargo build --release --locked
# a Zentinel release (CI pins ZENTINEL_RELEASE in ci.yml); pick your platform's asset
gh release download <release> --repo zentinelproxy/zentinel --pattern 'zentinel-<release>-darwin-arm64.tar.gz'
tar xzf zentinel-<release>-darwin-arm64.tar.gz
# a CRS checkout at CRS_COMMIT, as above
CRS_DIR=/path/to/coreruleset scripts/smoke-test.sh target/release/zentinel-modsec-agent ./zentinel
```

`KEEP_WORK=1` keeps the work directory with the agent, proxy and upstream logs.

## Protocol facts worth knowing

Pinned `zentinel-agent-protocol` is 0.6.50 (`Cargo.lock`). In that version:

- The UDS server dispatches `Configure`; the gRPC server does not, so a `config { }` block only applies over UDS.
- Neither server dispatches drain or shutdown to the handler, or `Cancel` (it is only logged). `on_drain` and `on_shutdown` are correct but latent.
- `health_status` never reaches the proxy (gRPC polls it and logs at `trace`; UDS ignores it); `metrics_report` is never called.
- `RequestComplete` is dispatched to `on_request_complete`. Zentinel sends it from release 26.11_3; earlier proxies never do.

Check these again when bumping the protocol crate; `docs/architecture.md` depends on them.

## Review rules

See [rules/review.md](rules/review.md). The short version: libmodsecurity v3 is the reference; no request body is ever allowed by accident; pending state is bounded; configure is idempotent, merging and strict; blocks name the rule; CI workflow changes need maintainer sign-off.

## Documentation

- `README.md` is the user-facing page (install, flags, `config { }` block, logs). Keep it in the shared Zentinel README format; put depth in `docs/`.
- When behavior changes, update `README.md` (if user-visible) and the matching file in `docs/` in the same PR.
- Site docs live in `zentinelproxy.io-docs`; the registry page is <https://registry.zentinelproxy.io/modsec/>.

## Checklist before a PR

- [ ] Behavior matches libmodsecurity v3 on stock CRS (CRS tests run with `testdata/crs` present)
- [ ] No new path lets a request body through uninspected unless configuration says so
- [ ] Pending state stays bounded; nothing new waits on the client to be released
- [ ] New settings are wired through flags, `ModSecConfigJson`, `changed_keys` and the README table
- [ ] Blocks still log `trigger`, `rules` and `rule_msg`, and the client still sees no rule text
- [ ] `cargo fmt --all --check`, clippy with `-D warnings`, `cargo test --workspace` pass
- [ ] `README.md` and `docs/` updated if behavior or operations changed
- [ ] No `.github/workflows/` change without maintainer sign-off
