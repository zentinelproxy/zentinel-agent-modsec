# sentinel-agent-modsec

ModSecurity WAF agent for [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy. Provides full OWASP Core Rule Set (CRS) support via libmodsecurity.

> **Note:** This agent uses libmodsecurity bindings and requires the library to be installed on your system. For a lightweight, zero-dependency alternative with basic detection rules, see [sentinel-agent-waf](https://github.com/raskell-io/sentinel-agent-waf).

## Features

- **Full OWASP CRS support** - 800+ detection rules
- **SecLang compatibility** - Load any ModSecurity rules
- **Request body inspection** - JSON, form data, XML, and all content types
- **Response body inspection** - Detect data leakage (opt-in)
- **Block or detect-only mode** - Monitor before blocking
- **Path exclusions** - Skip inspection for trusted paths

## Prerequisites

### libmodsecurity

This agent requires libmodsecurity >= 3.0.13 installed on your system:

**macOS:**
```bash
brew install modsecurity
```

**Ubuntu/Debian:**
```bash
apt install libmodsecurity-dev
```

**From source:**
```bash
git clone https://github.com/owasp-modsecurity/ModSecurity
cd ModSecurity
git submodule init && git submodule update
./build.sh
./configure
make && make install
```

## Installation

### From crates.io

```bash
cargo install sentinel-agent-modsec
```

### From source

```bash
git clone https://github.com/raskell-io/sentinel-agent-modsec
cd sentinel-agent-modsec
cargo build --release
```

## OWASP Core Rule Set (CRS) Setup

The OWASP Core Rule Set provides comprehensive protection against common web attacks. Follow these steps to download, configure, and use the CRS with this agent.

### Step 1: Download CRS

**Option A: Using Git (recommended)**
```bash
# Create the modsecurity directory
sudo mkdir -p /etc/modsecurity

# Clone the CRS repository
sudo git clone https://github.com/coreruleset/coreruleset /etc/modsecurity/crs

# Or for a specific version (e.g., v4.0.0)
sudo git clone --branch v4.0.0 https://github.com/coreruleset/coreruleset /etc/modsecurity/crs
```

**Option B: Download release archive**
```bash
# Download latest release
curl -L https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.0.0.tar.gz -o crs.tar.gz
sudo mkdir -p /etc/modsecurity
sudo tar -xzf crs.tar.gz -C /etc/modsecurity
sudo mv /etc/modsecurity/coreruleset-4.0.0 /etc/modsecurity/crs
```

### Step 2: Configure CRS

```bash
# Copy the example configuration
sudo cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
```

Edit `/etc/modsecurity/crs/crs-setup.conf` to customize settings:

```apache
# Set paranoia level (1-4, higher = more rules, more false positives)
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1"

# Set detection paranoia level (for logging without blocking)
SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=1"

# Anomaly scoring thresholds
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=5"
SecAction "id:900111,phase:1,pass,t:none,nolog,setvar:tx.outbound_anomaly_score_threshold=4"
```

### Step 3: Directory Structure

After setup, your directory should look like:

```
/etc/modsecurity/
└── crs/
    ├── crs-setup.conf              # Your configuration (copy from .example)
    ├── crs-setup.conf.example      # Example configuration
    ├── rules/
    │   ├── REQUEST-901-INITIALIZATION.conf
    │   ├── REQUEST-905-COMMON-EXCEPTIONS.conf
    │   ├── REQUEST-910-IP-REPUTATION.conf
    │   ├── REQUEST-911-METHOD-ENFORCEMENT.conf
    │   ├── REQUEST-913-SCANNER-DETECTION.conf
    │   ├── REQUEST-920-PROTOCOL-ENFORCEMENT.conf
    │   ├── REQUEST-921-PROTOCOL-ATTACK.conf
    │   ├── REQUEST-930-APPLICATION-ATTACK-LFI.conf
    │   ├── REQUEST-931-APPLICATION-ATTACK-RFI.conf
    │   ├── REQUEST-932-APPLICATION-ATTACK-RCE.conf
    │   ├── REQUEST-933-APPLICATION-ATTACK-PHP.conf
    │   ├── REQUEST-934-APPLICATION-ATTACK-GENERIC.conf
    │   ├── REQUEST-941-APPLICATION-ATTACK-XSS.conf
    │   ├── REQUEST-942-APPLICATION-ATTACK-SQLI.conf
    │   ├── REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
    │   ├── REQUEST-944-APPLICATION-ATTACK-JAVA.conf
    │   ├── REQUEST-949-BLOCKING-EVALUATION.conf
    │   ├── RESPONSE-950-DATA-LEAKAGES.conf
    │   ├── RESPONSE-951-DATA-LEAKAGES-SQL.conf
    │   ├── RESPONSE-952-DATA-LEAKAGES-JAVA.conf
    │   ├── RESPONSE-953-DATA-LEAKAGES-PHP.conf
    │   ├── RESPONSE-954-DATA-LEAKAGES-IIS.conf
    │   ├── RESPONSE-959-BLOCKING-EVALUATION.conf
    │   └── RESPONSE-980-CORRELATION.conf
    └── plugins/                     # Optional plugins
```

### Step 4: Run the Agent with CRS

**Basic usage with full CRS:**
```bash
sentinel-modsec-agent \
  --socket /var/run/sentinel/modsec.sock \
  --rules /etc/modsecurity/crs/crs-setup.conf \
  --rules "/etc/modsecurity/crs/rules/*.conf"
```

**Important:** The order of rules matters. Always load `crs-setup.conf` first, then the rules directory.

**Using environment variables:**
```bash
export MODSEC_RULES="/etc/modsecurity/crs/crs-setup.conf,/etc/modsecurity/crs/rules/*.conf"
sentinel-modsec-agent --socket /var/run/sentinel/modsec.sock
```

### Step 5: Custom Rules (Optional)

You can add custom rules before or after the CRS rules:

```bash
# Create custom rules directory
sudo mkdir -p /etc/modsecurity/custom

# Create a custom rules file
sudo tee /etc/modsecurity/custom/custom-rules.conf << 'EOF'
# Block specific User-Agent
SecRule REQUEST_HEADERS:User-Agent "@contains BadBot" \
    "id:10001,phase:1,deny,status:403,msg:'Bad bot blocked'"

# Whitelist specific IP
SecRule REMOTE_ADDR "@ipMatch 192.168.1.100" \
    "id:10002,phase:1,allow,nolog"
EOF
```

**Load order with custom rules:**
```bash
sentinel-modsec-agent \
  --socket /var/run/sentinel/modsec.sock \
  --rules /etc/modsecurity/crs/crs-setup.conf \
  --rules "/etc/modsecurity/crs/rules/REQUEST-901-INITIALIZATION.conf" \
  --rules "/etc/modsecurity/custom/custom-rules.conf" \
  --rules "/etc/modsecurity/crs/rules/REQUEST-9*.conf" \
  --rules "/etc/modsecurity/crs/rules/RESPONSE-*.conf"
```

### Minimal CRS Configuration

For testing or minimal setups, you can load only specific rule categories:

```bash
# SQLi and XSS protection only
sentinel-modsec-agent \
  --socket /var/run/sentinel/modsec.sock \
  --rules /etc/modsecurity/crs/crs-setup.conf \
  --rules /etc/modsecurity/crs/rules/REQUEST-901-INITIALIZATION.conf \
  --rules /etc/modsecurity/crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf \
  --rules /etc/modsecurity/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf \
  --rules /etc/modsecurity/crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf
```

## Usage

```bash
sentinel-modsec-agent \
  --socket /var/run/sentinel/modsec.sock \
  --rules /etc/modsecurity/crs/crs-setup.conf \
  --rules "/etc/modsecurity/crs/rules/*.conf"
```

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/sentinel-modsec.sock` |
| `--rules` | `MODSEC_RULES` | Paths to rule files (comma-separated or multiple flags) | - |
| `--block-mode` | `MODSEC_BLOCK_MODE` | Block (true) or detect-only (false) | `true` |
| `--exclude-paths` | `MODSEC_EXCLUDE_PATHS` | Paths to exclude (comma-separated) | - |
| `--body-inspection` | `MODSEC_BODY_INSPECTION` | Enable request body inspection | `true` |
| `--max-body-size` | `MODSEC_MAX_BODY_SIZE` | Maximum body size to inspect (bytes) | `1048576` (1MB) |
| `--response-inspection` | `MODSEC_RESPONSE_INSPECTION` | Enable response body inspection | `false` |
| `--verbose` | `MODSEC_VERBOSE` | Enable debug logging | `false` |

## Configuration

### Sentinel Proxy Configuration

```kdl
agents {
    agent "modsec" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/sentinel/modsec.sock"
        }
        events ["request_headers", "request_body_chunk", "response_body_chunk"]
        timeout-ms 100
        failure-mode "open"
    }
}

routes {
    route "all" {
        matches { path-prefix "/" }
        upstream "backend"
        agents ["modsec"]
    }
}
```

### Docker/Kubernetes

```yaml
# Environment variables
MODSEC_RULES: "/etc/modsecurity/crs/crs-setup.conf,/etc/modsecurity/crs/rules/*.conf"
MODSEC_BLOCK_MODE: "true"
MODSEC_EXCLUDE_PATHS: "/health,/metrics"
```

## Response Headers

On blocked requests:
- `X-WAF-Blocked: true`
- `X-WAF-Message: <modsecurity message>`

In detect-only mode, the request continues but includes:
- `X-WAF-Detected: <message>`

## OWASP CRS Paranoia Levels

The CRS supports paranoia levels 1-4. Higher levels enable more rules but may cause false positives.

### Configuring Paranoia Level

Edit `/etc/modsecurity/crs/crs-setup.conf`:

```apache
# Blocking paranoia level - requests matching rules at this level are blocked
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1"

# Detection paranoia level - requests are logged but not blocked above blocking level
SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=2"
```

### Paranoia Level Guide

| Level | Description | Use Case |
|-------|-------------|----------|
| 1 | Standard protection, minimal false positives | Production - most applications |
| 2 | Elevated protection, some false positives | Production - security-sensitive apps |
| 3 | High protection, moderate false positives | Staging/testing, or with tuning |
| 4 | Maximum protection, high false positives | Security research, highly tuned setups |

### Recommended Approach

1. **Start with detect-only mode** to identify false positives:
   ```bash
   sentinel-modsec-agent --block-mode=false --rules ...
   ```

2. **Begin at Paranoia Level 1** and monitor logs

3. **Gradually increase** if needed, tuning exclusions for false positives

4. **Use detection paranoia** to log higher-level matches without blocking:
   ```apache
   # Block at level 1, but log detections at level 2
   SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1"
   SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=2"
   ```

### Rule Exclusions

To handle false positives, add exclusions in a custom rules file:

```apache
# Exclude a specific rule for a path
SecRule REQUEST_URI "@beginsWith /api/upload" \
    "id:1001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"

# Exclude a rule for a specific parameter
SecRule ARGS:content "@rx .*" \
    "id:1002,phase:2,pass,nolog,ctl:ruleRemoveTargetById=941100;ARGS:content"
```

## Comparison with sentinel-agent-waf

| Feature | sentinel-agent-modsec | sentinel-agent-waf |
|---------|----------------------|-------------------|
| Detection Rules | 800+ CRS rules | ~20 regex rules |
| SecLang Support | ✓ | - |
| Custom Rules | ✓ | - |
| Body Inspection | ✓ | ✓ |
| Dependencies | libmodsecurity (C) | Pure Rust |
| Binary Size | ~50MB | ~5MB |
| Memory Usage | Higher | Lower |
| Installation | Requires libmodsecurity | `cargo install` |

**When to use this agent:**
- You need full OWASP CRS compatibility
- You have existing ModSecurity/SecLang rules
- You require comprehensive protection with 800+ detection rules

**When to use [sentinel-agent-waf](https://github.com/raskell-io/sentinel-agent-waf):**
- You want simple, zero-dependency deployment
- You need low latency and minimal resource usage
- Basic attack detection is sufficient

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run -- --socket /tmp/test.sock --rules test-rules.conf

# Run tests
cargo test

# Check formatting and lints
cargo fmt --check
cargo clippy
```

## License

Apache-2.0
