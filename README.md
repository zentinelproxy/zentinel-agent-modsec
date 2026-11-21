<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/banner/zentinel-agent-modsec-banner-on-dark.svg">
      <img alt="Zentinel ModSecurity agent" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/banner/zentinel-agent-modsec-banner-on-light.svg" height="64">
    </picture>
  </a>
</p>

<h3 align="center">ModSecurity agent</h3>

<p align="center">Runs ModSecurity rules, including the OWASP Core Rule Set, through the C libmodsecurity library on request headers and bodies.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-modsec/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-modsec/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Rust 1.94.1+" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&labelColor=1f161e&logo=rust&logoColor=white">
  <img alt="Agent protocol v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/modsec/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

This agent hands each request to [libmodsecurity](https://github.com/owasp-modsecurity/ModSecurity)
3, the reference implementation of SecLang, and blocks with the status the rules
ask for. Use it when you need the reference engine or already run ModSecurity
rule sets. It links against the C library, so the library has to be installed
wherever the agent runs.

**Which ModSecurity agent?** This one wraps the C library. Its sibling
[zentinel-agent-zentinelsec](https://github.com/zentinelproxy/zentinel-agent-zentinelsec)
runs the same rule language on [zentinel-modsec](https://github.com/zentinelproxy/zentinel-modsec),
a pure-Rust engine with no C dependency, whose CRS conformance is measured
against the upstream regression suite. Choose this agent for the reference
behavior, zentinelsec for a single static binary.

> **Known limitations** (checked against stock CRS on 2026-10-21, and against `main` on 2026-11-21):
>
> - Up to 0.3.0, phase 2 rules ran only when a request had a body, so under
>   CRS (whose detection and 949110 blocking are phase 2) an attack in the
>   query string of a `GET` passed; rule files were loaded as text, so CRS
>   data files (`@pmFromFile scanners-user-agents.data`) were not found unless
>   the agent ran from the CRS `rules/` directory; and JSON bodies were never
>   parsed. All three are fixed in 0.4.0.
> - A body larger than `--max-body-size` is passed on uninspected.
> - `--response-inspection` is accepted but response bodies are not inspected.
> - Release 0.3.0 was tagged before the UDS transport moved to the v2
>   protocol: the proxy's handshake fails with `Invalid message format` and
>   every request gets a 503. Fixed in 0.4.0. The bundle installs 0.4.1 from
>   Zentinel 26.10_8 on; earlier releases install 0.3.0.
> - Up to 0.4.1, a drain dropped request bodies that were being buffered, so
>   their last chunk passed uninspected (#8). Fixed in 0.4.2 (#11); not
>   reachable with the current protocol crate, which does not deliver drains
>   to the agent.

## Quick start

```bash
# 1. libmodsecurity (>= 3.0.13) and the OWASP CRS
brew install modsecurity          # macOS; on Linux see Install
sudo git clone https://github.com/coreruleset/coreruleset /etc/modsecurity/crs
sudo cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf

# 2. The agent
zentinel bundle install modsec

# 3. Run it with the CRS setup file and every rule file
zentinel-modsec-agent \
  --socket /var/run/zentinel/modsec.sock \
  --rules /etc/modsecurity/crs/crs-setup.conf \
  --rules "/etc/modsecurity/crs/rules/*.conf"
```

Then point Zentinel at the socket. Request bodies reach agents only when the
top-level `waf` block enables body inspection:

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "127.0.0.1:8080"
        protocol "http"
    }
}

// Request bodies reach agents only when this block enables them.
waf {
    mode "off"
    body-inspection {
        inspect-request-body #true
        max-inspection-bytes 1048576
    }
}

agents {
    agent "modsec" type="waf" {
        unix-socket "/var/run/zentinel/modsec.sock"
        events "request_headers" "request_body"
        timeout-ms 200
        failure-mode "closed"
    }
}

filters {
    filter "modsec" {
        type "agent"
        agent "modsec"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
        filters "modsec"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}
```

`failure-mode "closed"` on the filter rejects requests while the agent is
unreachable; use `"open"` to forward them uninspected instead.

```bash
curl -i -d "id=1' OR '1'='1" http://127.0.0.1:8080/   # 403 with CRS loaded
```

## Install

The agent needs libmodsecurity 3.0.13 or newer, both to build and to run (the
binary links it dynamically).

```bash
# macOS
brew install modsecurity
```

On Linux, install your distribution's `libmodsecurity3` if it is 3.0.13 or
newer, or build it from source against PCRE2 the way CI does (see
[docs/building-libmodsecurity.md](docs/building-libmodsecurity.md)):

```bash
sudo apt-get install -y build-essential libtool autoconf automake pkg-config \
  libcurl4-openssl-dev libpcre2-dev libyajl-dev libxml2-dev
git clone --depth 1 --branch v3.0.14 https://github.com/owasp-modsecurity/ModSecurity
cd ModSecurity && git submodule update --init
./build.sh && ./configure --prefix=/usr/local --without-lmdb --with-pcre2
make -j"$(nproc)" && sudo make install && sudo ldconfig
```

### Bundle

```bash
zentinel bundle install modsec
```

Installs the release pinned in the proxy's bundle lock: 0.4.1 from Zentinel
26.10_8 on (`linux-x86_64`, `linux-aarch64`, `darwin-aarch64`). Earlier
releases pin 0.3.0, which does not work with the current proxy (see Known
limitations). See the
[bundle documentation](https://docs.zentinelproxy.io/deployment/bundle/).

### Release binaries

From 0.4.0, each release ships `linux-x86_64`, `linux-aarch64` and
`darwin-aarch64`, each with a `.sha256`, and every asset has passed
`scripts/smoke-test.sh` (stock CRS behind a real Zentinel) before it was
published. The binary links libmodsecurity 3 dynamically, so the host needs it
(`apt install libmodsecurity3`, `brew install modsecurity`). 0.3.0 has the
limitation above.

```bash
VERSION=0.4.2
PLATFORM=linux-x86_64   # or linux-aarch64, darwin-aarch64
curl -fsSL -o zentinel-modsec-agent.tar.gz \
  "https://github.com/zentinelproxy/zentinel-agent-modsec/releases/download/v${VERSION}/zentinel-modsec-agent-${VERSION}-${PLATFORM}.tar.gz"
tar -xzf zentinel-modsec-agent.tar.gz
sudo install -m 0755 zentinel-modsec-agent /usr/local/bin/
```

### Cargo

The crate is not on crates.io; install from the repository (needs `protoc`,
`pkg-config` and the libmodsecurity headers):

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-modsec
```

This installs the `zentinel-modsec-agent` binary built from `main`, which has
fixes not yet in a release (rule ids in the block log, drain handling).

### From source

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-modsec
cd zentinel-agent-modsec
cargo build --release
```

## Configuration

The agent is configured with command-line flags or environment variables,
and, from Zentinel releases that deliver it, with a `config { }` block on the
proxy's `agent` definition (see [below](#the-config--block)).

| Option | Default | Meaning |
|---|---|---|
| `--socket` (`AGENT_SOCKET`) | `/tmp/zentinel-modsec.sock` | Unix socket to listen on |
| `--grpc-address` (`AGENT_GRPC_ADDRESS`) | unset | Listen on gRPC at this address (e.g. `127.0.0.1:50051`) instead of the socket |
| `--rules` (`MODSEC_RULES`) | none | Rule file or glob; repeat the flag or comma-separate. Loaded in order, so put `crs-setup.conf` first. With no rules nothing is blocked |
| `--block-mode` (`MODSEC_BLOCK_MODE`) | `true` | Block on an intervention; `false` is detect-only |
| `--exclude-paths` (`MODSEC_EXCLUDE_PATHS`) | none | Comma-separated path prefixes that skip inspection |
| `--body-inspection` (`MODSEC_BODY_INSPECTION`) | `true` | Inspect request bodies |
| `--max-body-size` (`MODSEC_MAX_BODY_SIZE`) | `1048576` | Largest body inspected, in bytes; larger bodies pass uninspected |
| `--response-inspection` (`MODSEC_RESPONSE_INSPECTION`) | `false` | Accepted, not implemented |
| `-v`, `--verbose` (`MODSEC_VERBOSE`) | `false` | Debug logging |

The boolean options are switches: `--block-mode` cannot take a value, so
`--block-mode=false` is rejected. To turn one off, set the environment
variable, e.g. `MODSEC_BLOCK_MODE=false`.

### The `config { }` block

```kdl
agents {
    agent "modsec" type="waf" {
        unix-socket path="/var/run/zentinel/modsec.sock"
        events "request_headers" "request_body"
        config {
            rules-paths "/etc/modsecurity/crs/crs-setup.conf" "/etc/modsecurity/crs/rules/*.conf"
            block-mode #true
            exclude-paths "/health" "/metrics"
            max-body-size 1048576
        }
    }
}
```

Keys: `rules-paths` (alias `rules`), `block-mode`, `exclude-paths`,
`body-inspection-enabled` (alias `body-inspection`), `max-body-size`,
`response-inspection-enabled` (alias `response-inspection`). A list may be a
single value.

The proxy sends this block on every connection it opens to the agent: once per
pooled connection at startup and again on every reconnect. The agent applies
it by these rules:

1. **Idempotent.** A block identical to the one already in effect (compared
   by a hash of its canonical JSON) changes nothing. When the block does
   change, the rule set is rebuilt only if `rules-paths` or
   `body-inspection-enabled` changed; the other settings change in place.
   Requests whose body is being buffered are never dropped by a configure:
   they are inspected when their last chunk arrives.
2. **Merge, don't replace.** The block is overlaid on the flags and
   environment: a key that is absent keeps the value from the command line,
   so `config { block-mode #false }` keeps your `--rules`.
3. **Reject what cannot be applied.** The configure fails (the proxy does not
   use the connection, and the active configuration stays as it was) for an
   unknown or misspelled key, a value of the wrong type, a list that is empty
   after parsing (`rules-paths ""`), `max-body-size 0`, a `rules-paths`
   pattern that matches no file, or a rule file that does not parse. A block
   that names rules can therefore never leave the agent running with zero
   rules.
4. **No secrets in logs.** A configure is logged with the hash of the block
   and the names of the settings it changed, never the values.

Paranoia level, anomaly thresholds and rule exclusions are set in the rules
themselves (`crs-setup.conf`, or your own file loaded with `--rules`), as with
any ModSecurity deployment. Proxy-side agent options are in the
[agents reference](https://docs.zentinelproxy.io/configuration/agents/).

## How it works

On `request_headers` the agent runs a ModSecurity transaction on the URI,
query string and headers, through phase 1 and phase 2 with an empty body (CRS
inspects `ARGS` and makes its blocking decision in phase 2). If that passes and
body inspection is on, it buffers the body and, when the last chunk arrives,
runs the transaction again with the body. [docs/architecture.md](docs/architecture.md)
describes the request lifecycle, and [docs/operations.md](docs/operations.md)
health, failure modes and resource limits.

| Outcome | What the agent returns |
|---|---|
| Intervention, block mode | The rule's status, body `Forbidden`, response headers `X-WAF-Blocked: true` and `X-WAF-Message: Blocked by ModSecurity` |
| Intervention, detect-only | Allow, with `X-WAF-Detected` added to the request sent upstream |
| Engine error | Allow, logged as a warning |

### Which rule blocked a request

When a request is blocked (or detected, in detect-only mode) the agent logs one
`Request blocked by ModSecurity` / `ModSecurity detection` line at `info`
level with the triggering rule id (`trigger`), the ids of every rule that
logged during the transaction (`rules`, comma separated) and the `msg` of the
triggering rule (`rule_msg`). The same data is attached to the response as audit metadata:
`rule_ids` and `reason_codes`.

```json
{"level":"INFO","fields":{"message":"Request blocked by ModSecurity","status":403,"stage":"body","trigger":"949110","rules":"920350,942100,949110","rule_msg":"Inbound Anomaly Score Exceeded (Total Score: 8)"}}
```

Rules that matched but did not cause a block are listed at `debug` level
(`--verbose`).

Rule ids and rule text are never sent to the client; they are in the log and the audit metadata only.

Rule ids in the log and audit metadata are reported from 0.4.2; 0.4.1 and
earlier do not report them.

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Building needs Rust 1.94.1+, libmodsecurity 3.0.13+ and `protoc`. The CRS
tests skip themselves without a CRS checkout in `testdata/crs` (CI fetches the
commit pinned as `CRS_COMMIT` in `.github/workflows/ci.yml`), and
`scripts/smoke-test.sh` runs the release binary with stock CRS behind a real
Zentinel; its header lists what it needs. Building libmodsecurity is covered in
[docs/building-libmodsecurity.md](docs/building-libmodsecurity.md).


## Related

- [docs/architecture.md](docs/architecture.md): request lifecycle, pending
  bodies, decisions, configure, drain, the libmodsecurity boundary
- [docs/operations.md](docs/operations.md): configuration summary, failure
  modes, health and draining, block logs, resource limits
- [docs/building-libmodsecurity.md](docs/building-libmodsecurity.md):
  building libmodsecurity 3 with PCRE2 on Linux and macOS
- [Registry page](https://registry.zentinelproxy.io/modsec/)
- [zentinel-agent-zentinelsec](https://github.com/zentinelproxy/zentinel-agent-zentinelsec): the same rules on the pure-Rust engine
- [zentinel-modsec](https://github.com/zentinelproxy/zentinel-modsec): that engine
- [zentinel-agent-waf](https://github.com/zentinelproxy/zentinel-agent-waf): Zentinel's own rule set, no SecLang
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
