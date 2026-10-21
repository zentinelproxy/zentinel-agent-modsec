<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">ModSecurity agent</h3>

<p align="center">Runs ModSecurity rules, including the OWASP Core Rule Set, through the C libmodsecurity library on request headers and bodies.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-modsec/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-modsec/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Rust: 1.94.1+" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&labelColor=1f161e&logo=rust&logoColor=white">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
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

> **Known limitations** (checked against stock CRS on 2026-10-21):
>
> - Phase 2 rules run only when a request has a body. Most CRS detection, and
>   the blocking evaluation in rule 949110, is phase 2, so an attack in the
>   query string of a `GET` is detected by nothing and passes. `POST` bodies are
>   inspected and blocked.
> - Rule files are loaded as text, so data files that CRS references by
>   relative path (`@pmFromFile scanners-user-agents.data`) are looked up in the
>   working directory. Start the agent from the CRS `rules/` directory, or it
>   exits at startup with `Failed to open file: 'scanners-user-agents.data'`.
> - A body larger than `--max-body-size` is passed on uninspected.
> - `--response-inspection` is accepted but response bodies are not inspected.
> - The released binary (0.3.0, which `zentinel bundle install modsec` also
>   installs) does not speak the current agent protocol: the proxy's handshake
>   fails with `Invalid message format` and every request gets a 503. Build
>   from `main` until a new release ships.

## Quick start

```bash
# 1. libmodsecurity (>= 3.0.13) and the OWASP CRS
brew install modsecurity          # macOS; on Linux see Install
sudo git clone https://github.com/coreruleset/coreruleset /etc/modsecurity/crs
sudo cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf

# 2. The agent, built from main (see Known limitations)
cargo install --git https://github.com/zentinelproxy/zentinel-agent-modsec

# 3. Run it from the rules directory (see Known limitations)
cd /etc/modsecurity/crs/rules
zentinel-modsec-agent \
  --socket /var/run/zentinel/modsec.sock \
  --rules ../crs-setup.conf \
  --rules "*.conf"
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

# Linux: build from source if your distribution ships an older version
git clone --depth 1 --branch v3.0.13 https://github.com/owasp-modsecurity/ModSecurity
cd ModSecurity && git submodule update --init
./build.sh && ./configure && make && sudo make install
```

### Cargo (recommended for now)

The crate is not on crates.io; install from the repository (needs
`pkg-config` and the libmodsecurity headers):

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-modsec
```

This installs the `zentinel-modsec-agent` binary built from `main`.

### Bundle

```bash
zentinel bundle install modsec
```

Installs release 0.3.0 (`linux-x86_64` and `darwin-aarch64` only), which does
not work with the current proxy (see Known limitations). See the
[bundle documentation](https://docs.zentinelproxy.io/deployment/bundle/).

### Release binaries

These are release 0.3.0, with the limitation above.

```bash
VERSION=0.3.0
PLATFORM=linux-x86_64   # or darwin-aarch64
curl -fsSL -o zentinel-modsec-agent.tar.gz \
  "https://github.com/zentinelproxy/zentinel-agent-modsec/releases/download/v${VERSION}/zentinel-modsec-agent-${VERSION}-${PLATFORM}.tar.gz"
tar -xzf zentinel-modsec-agent.tar.gz
sudo install -m 0755 zentinel-modsec-agent /usr/local/bin/
```

### From source

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-modsec
cd zentinel-agent-modsec
cargo build --release
```

## Configuration

The agent is configured with command-line flags or environment variables. A
`config { }` block on the proxy's `agent` definition does not reach it.

| Option | Environment | Default | Meaning |
|---|---|---|---|
| `--socket` | `AGENT_SOCKET` | `/tmp/zentinel-modsec.sock` | Unix socket to listen on |
| `--grpc-address` | `AGENT_GRPC_ADDRESS` | unset | Listen on gRPC at this address (e.g. `127.0.0.1:50051`) instead of the socket |
| `--rules` | `MODSEC_RULES` | none | Rule file or glob; repeat the flag or comma-separate. Loaded in order, so put `crs-setup.conf` first. With no rules nothing is blocked |
| `--block-mode` | `MODSEC_BLOCK_MODE` | `true` | Block on an intervention; `false` is detect-only |
| `--exclude-paths` | `MODSEC_EXCLUDE_PATHS` | none | Comma-separated path prefixes that skip inspection |
| `--body-inspection` | `MODSEC_BODY_INSPECTION` | `true` | Inspect request bodies |
| `--max-body-size` | `MODSEC_MAX_BODY_SIZE` | `1048576` | Largest body inspected, in bytes; larger bodies pass uninspected |
| `--response-inspection` | `MODSEC_RESPONSE_INSPECTION` | `false` | Accepted, not implemented |
| `-v`, `--verbose` | `MODSEC_VERBOSE` | `false` | Debug logging |

The boolean options are switches: `--block-mode` cannot take a value, so
`--block-mode=false` is rejected. To turn one off, set the environment
variable, e.g. `MODSEC_BLOCK_MODE=false`.

Paranoia level, anomaly thresholds and rule exclusions are set in the rules
themselves (`crs-setup.conf`, or your own file loaded with `--rules`), as with
any ModSecurity deployment. Proxy-side agent options are in the
[agents reference](https://docs.zentinelproxy.io/configuration/agents/).

## How it works

On `request_headers` the agent runs ModSecurity phase 1 (URI, query string,
headers). If that passes and body inspection is on, it buffers the body and
runs phase 2 when the last chunk arrives.

| Outcome | What the agent returns |
|---|---|
| Intervention, block mode | The rule's status, body `Forbidden`, response headers `X-WAF-Blocked: true` and `X-WAF-Message: Blocked by ModSecurity` |
| Intervention, detect-only | Allow, with `X-WAF-Detected` added to the request sent upstream |
| Engine error | Allow, logged as a warning |

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Building needs Rust 1.94.1+, libmodsecurity 3.0.13+ and `protoc`.

## Related

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
