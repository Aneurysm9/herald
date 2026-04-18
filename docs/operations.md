# Herald Operations Guide

This guide covers deployment, configuration, monitoring, and troubleshooting for Herald in production.

## Deployment Options

Herald is designed to run as a single static binary. Deployment options:

1. **NixOS module** (recommended) — Declarative configuration with built-in systemd service, secret management, and firewall rules
2. **Standalone systemd** — Manual systemd unit file for non-NixOS systems
3. **Static binary** — Direct execution from the command line or custom init systems
4. **Docker** (future) — Containerized deployment

## NixOS Module

Herald includes a NixOS module (`services.herald`) in the [nixos repo](https://github.com/Aneurysm9/nixos). The module:

- Runs herald as a systemd service
- Serializes `settings` attrset to `/etc/herald/config.yaml`
- Manages sops secrets and passes paths via config
- Opens firewall on Tailscale interface only

### Example Configuration

```nix
{ config, pkgs, ... }:
{
  services.herald = {
    enable = true;
    settings = {
      listen = "[::]:8443";
      tls = {
        cert_file = config.sops.secrets.herald_tls_cert.path;
        key_file = config.sops.secrets.herald_tls_key.path;
      };
      tokens_file = config.sops.secrets.herald_tokens.path;

      backends.cloudflare = {
        zones = [ "example.com" "internal.example.org" ];
        token_file = config.sops.secrets.herald_cloudflare_token.path;
      };

      providers = {
        static.records = [
          {
            name = "www.example.com";
            type = "CNAME";
            value = "example.com";
            ttl = 300;
            zone = "example.com";
          }
        ];

        mirror = {
          source = {
            type = "technitium";
            url = "http://ns01.internal.example.org:5380";
            zone = "internal.example.org";
            token_file = config.sops.secrets.herald_technitium_token.path;
          };
          rules = [
            {
              match.type = "AAAA";
              transform = {
                suffix = "example.com";
                zone = "example.com";
              };
            }
          ];
          interval = "5m";
        };

        acme = {
          zone = "example.com";
          domain = "acme.example.com";
          clients = {
            service1.allowed_domains = [ "service1.example.org" "*.example.org" ];
            service2.allowed_domains = [ "service2.example.org" ];
          };
        };

        dynamic = {
          clients = {
            opnsense = {
              allowed_domains = [ "*.example.com" ];
              allowed_zones = [ "example.com" ];
            };
          };
        };
      };

      reconciler = {
        interval = "1m";
        dry_run = false;
      };

      telemetry = {
        enabled = true;
        otlp_endpoint = "http://localhost:4318";
      };
    };
  };

  # sops-nix secret configuration
  sops.secrets = {
    herald_tls_cert = {
      sopsFile = ./secrets.yaml;
      owner = "herald";
      format = "binary";  # PEM certificate chain
    };
    herald_tls_key = {
      sopsFile = ./secrets.yaml;
      owner = "herald";
      format = "binary";  # PEM private key
    };
    herald_cloudflare_token = {
      sopsFile = ./secrets.yaml;
      owner = "herald";
    };
    herald_technitium_token = {
      sopsFile = ./secrets.yaml;
      owner = "herald";
    };
    herald_tokens = {
      sopsFile = ./secrets.yaml;
      owner = "herald";
      format = "binary";  # JSON file: {"client_name": "token", ...}
    };
  };
}
```

### Flake Reference

To use the Herald package from the flake:

```nix
{
  inputs.herald.url = "github:Aneurysm9/herald";

  outputs = { self, nixpkgs, herald }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        herald.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
```

## Standalone Systemd

For non-NixOS systems, use a systemd unit file:

```ini
[Unit]
Description=Herald DNS Control Plane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/herald --config /etc/herald/config.yaml
Restart=on-failure
RestartSec=10s

# Security hardening
DynamicUser=yes
StateDirectory=herald
RuntimeDirectory=herald
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/herald

# Environment
Environment="RUST_LOG=herald=info"

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now herald
```

## Configuration Reference

All configuration keys with types, defaults, and environment variable overrides.

| Key | Type | Default | Env Override | Description |
|-----|------|---------|--------------|-------------|
| `listen` | string | `"[::]:8443"` | `HERALD_LISTEN` | API server listen address (dual-stack; use `"0.0.0.0:8443"` on IPv4-only hosts) |
| `tls.cert_file` | string | (required) | — | Path to PEM-encoded TLS certificate chain file |
| `tls.key_file` | string | (required) | — | Path to PEM-encoded TLS private key file |
| `tokens_file` | string | (optional) | `HERALD_TOKENS_FILE` | Path to JSON file with client tokens (shared by ACME and dynamic DNS) |
| `backends.cloudflare.zones` | array | (required) | (not supported) | List of Cloudflare zone names to manage |
| `backends.cloudflare.token_file` | string | (required) | `HERALD_BACKENDS_CLOUDFLARE_TOKEN_FILE` | Path to Cloudflare API token file |
| `providers.static.records` | array | `[]` | (not supported) | Static DNS records to manage |
| `providers.mirror.source.type` | string | — | — | Mirror source type (`technitium` or `dns`) |
| `providers.mirror.source.url` | string | — | — | Source API or DNS server URL |
| `providers.mirror.source.zone` | string | — | — | Source zone to mirror |
| `providers.mirror.source.token_file` | string | — | — | API token file (for Technitium) |
| `providers.mirror.rules` | array | — | — | Transformation rules (match + transform) |
| `providers.mirror.interval` | string | `"5m"` | — | Mirror polling interval |
| `providers.acme.zone` | string | (required if acme enabled) | — | Target zone for ACME challenges |
| `providers.acme.domain` | string | (required if acme enabled) | — | Base domain for ACME challenges |
| `providers.acme.clients` | map | — | — | Client configurations with allowed_domains |
| `providers.dynamic.clients` | map | — | — | Dynamic DNS client configs with allowed_domains and allowed_zones |
| `reconciler.interval` | string | `"1m"` | `HERALD_RECONCILER_INTERVAL` | Reconciliation interval |
| `reconciler.dry_run` | bool | `false` | `HERALD_RECONCILER_DRY_RUN` | Dry-run mode (log only, don't apply) |
| `telemetry.enabled` | bool | `false` | `HERALD_TELEMETRY_ENABLED` | Enable OpenTelemetry metrics export |
| `telemetry.otlp_endpoint` | string | (from env) | `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP HTTP endpoint URL |

### Duration Format

Interval values use the `humantime` format:
- `1m` = 1 minute
- `5m` = 5 minutes
- `1h30m` = 1 hour 30 minutes
- `30s` = 30 seconds

## Secret Management

Herald expects all secrets to be provided as file paths, not inline values. This integrates with secret management tools like sops-nix, Vault, or Kubernetes secrets.

### File Formats

**Cloudflare token** (`token_file`):
```
<cloudflare-api-token>
```

**Technitium token** (`token_file`):
```
<technitium-api-token>
```

**Client tokens** (`tokens_file` — shared by ACME and dynamic DNS):
```json
{
  "service1": "token-for-service1",
  "service2": "token-for-service2",
  "opnsense": "token-for-opnsense-dynamic-dns"
}
```

### File Permissions

Secret files should be:
- Readable by the herald user/group
- Mode `0400` or `0440`
- Owned by the herald user or a restricted group

Example:
```bash
sudo chown herald:herald /run/secrets/herald_cloudflare_token
sudo chmod 400 /run/secrets/herald_cloudflare_token
```

### sops-nix Integration

Herald works seamlessly with sops-nix:

```nix
sops.secrets = {
  herald_tls_cert = {
    sopsFile = ./secrets.yaml;
    owner = "herald";
    mode = "0400";
    format = "binary";  # PEM certificate chain
  };
  herald_tls_key = {
    sopsFile = ./secrets.yaml;
    owner = "herald";
    mode = "0400";
    format = "binary";  # PEM private key
  };
  herald_cloudflare_token = {
    sopsFile = ./secrets.yaml;
    owner = "herald";
    mode = "0400";
  };
  herald_tokens = {
    sopsFile = ./secrets.yaml;
    owner = "herald";
    mode = "0400";
    format = "binary";  # JSON file
  };
};

services.herald.settings = {
  tls = {
    cert_file = config.sops.secrets.herald_tls_cert.path;
    key_file = config.sops.secrets.herald_tls_key.path;
  };
  tokens_file = config.sops.secrets.herald_tokens.path;
  backends.cloudflare.token_file =
    config.sops.secrets.herald_cloudflare_token.path;
};
```

## TLS

Herald requires TLS for all API traffic. The `tls` config section is mandatory — Herald will fail to start without it.

### Certificate Setup

Herald expects PEM-encoded files:
- **`cert_file`**: Full certificate chain (leaf certificate followed by intermediates)
- **`key_file`**: Private key (PKCS#8 or RSA format)

```yaml
tls:
  cert_file: "/etc/herald/tls/cert.pem"
  key_file: "/etc/herald/tls/key.pem"
```

### Self-Signed Certificates (Development)

Generate a self-signed certificate for testing:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

Then use `-k` with curl to skip verification:

```bash
curl -k https://localhost:8443/health
```

### Let's Encrypt Integration

For production, use Let's Encrypt certificates. On NixOS with sops-nix:

```nix
sops.secrets = {
  herald_tls_cert = {
    sopsFile = ./secrets.yaml;
    owner = "herald";
    format = "binary";
  };
  herald_tls_key = {
    sopsFile = ./secrets.yaml;
    owner = "herald";
    format = "binary";
  };
};

services.herald.settings.tls = {
  cert_file = config.sops.secrets.herald_tls_cert.path;
  key_file = config.sops.secrets.herald_tls_key.path;
};
```

### Certificate Renewal

Herald does not hot-reload certificates. After renewal, restart the service:

```bash
sudo systemctl restart herald
```

### Troubleshooting TLS

**Certificate file not found**: Verify the file exists and herald has read permission (`chmod 400`).

**TLS handshake failures**: Check that the cert file contains the full chain (leaf + intermediates). Use `openssl s_client -connect localhost:8443` to debug.

**Certificate expired**: Check expiry with `openssl x509 -in cert.pem -noout -dates`. Renew and restart.

## Monitoring

Herald exposes OpenTelemetry metrics via OTLP (HTTP). Metrics are exported to a collector like the OpenTelemetry Collector, which can forward them to Prometheus, Grafana Cloud, or other backends.

### OpenTelemetry Setup

Enable telemetry in the config:

```yaml
telemetry:
  enabled: true
  otlp_endpoint: "http://localhost:4318"
```

Or via environment:
```bash
export HERALD_TELEMETRY_ENABLED=true
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

### Metrics Reference

All metrics use the `herald.*` namespace. 14 metrics are exported:

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `herald.reconciliation.runs` | Counter | — | Number of reconciliation passes |
| `herald.reconciliation.duration` | Histogram | — | Duration of reconciliation passes (seconds) |
| `herald.reconciliation.changes` | Counter | — | Changes produced by reconciliation |
| `herald.provider.records` | Gauge | `provider` | Number of records from each provider |
| `herald.provider.errors` | Counter | `provider` | Number of provider errors |
| `herald.acme.challenges.active` | UpDownCounter | — | Number of active ACME challenges |
| `herald.acme.operations` | Counter | `operation`, `status` | ACME operations (`operation=set/clear`, `status=success/error`) |
| `herald.mirror.polls` | Counter | — | Number of mirror poll operations |
| `herald.mirror.poll_duration` | Histogram | — | Duration of mirror polls (seconds) |
| `herald.mirror.records` | Gauge | — | Number of mirrored records |
| `herald.dynamic.operations` | Counter | `operation`, `status` | Dynamic DNS operations (`operation=set/delete`, `status=success/error`) |
| `herald.dynamic.records.active` | Gauge | — | Number of active dynamic DNS records |
| `herald.backend.api_calls` | Counter | `operation`, `status` | Backend API calls (`operation=get_records/create/update/delete`, `status=success/error`) |
| `herald.backend.api_duration` | Histogram | `operation` | Duration of backend API calls (seconds) |

### Prometheus Integration

Use the OpenTelemetry Collector to scrape OTLP and expose Prometheus metrics:

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: "0.0.0.0:4318"

exporters:
  prometheus:
    endpoint: "0.0.0.0:9090"

service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheus]
```

Then scrape `http://otel-collector:9090/metrics` with Prometheus.

### Grafana Dashboard

Key queries for a Herald dashboard:

**Reconciliation rate**:
```promql
rate(herald_reconciliation_runs_total[5m])
```

**Change breakdown**:
```promql
sum by (change_type) (rate(herald_reconciliation_changes_total[5m]))
```

**Active ACME challenges**:
```promql
herald_acme_challenges_active
```

**Backend API error rate**:
```promql
sum(rate(herald_backend_api_calls_total{status="error"}[5m]))
```

**P95 reconciliation duration**:
```promql
histogram_quantile(0.95, rate(herald_reconciliation_duration_bucket[5m]))
```

## ACME Integration

Herald acts as a DNS-01 challenge proxy for ACME clients (lego, acme.sh, certbot with exec hooks).

### lego Exec Hook (NixOS)

The NixOS `security.acme` module can be configured to use lego's `exec` provider. Create a hook script:

```bash
#!/usr/bin/env bash
# /etc/lego-herald-hook.sh
set -euo pipefail

HERALD_URL="${HERALD_URL:-https://localhost:8443}"
TOKEN=$(cat /run/secrets/acme_service_token)

case "${EXEC_MODE}" in
  present)
    curl -sf -X POST "${HERALD_URL}/api/v1/acme/challenge" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"domain\": \"${CERTBOT_DOMAIN}\", \"value\": \"${CERTBOT_VALIDATION}\"}"
    # Wait for DNS propagation
    sleep 15
    ;;
  cleanup)
    curl -sf -X POST "${HERALD_URL}/api/v1/acme/challenge/clear" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"domain\": \"${CERTBOT_DOMAIN}\"}"
    ;;
esac
```

Configure `security.acme`:

```nix
security.acme.certs."service1.example.org" = {
  domain = "service1.example.org";
  dnsProvider = "exec";
  credentialsFile = "/dev/null";  # Not used
  extraLegoFlags = [
    "--dns.exec=/etc/lego-herald-hook.sh"
  ];
};

environment.etc."lego-herald-hook.sh" = {
  source = ./lego-herald-hook.sh;
  mode = "0755";
};
```

### acme.sh Hook (Proxmox, OPNsense)

For non-NixOS systems, create an acme.sh DNS hook:

```bash
#!/usr/bin/env bash
# dns_herald.sh - place in ~/.acme.sh/dnsapi/
HERALD_URL="${HERALD_URL:-https://localhost:8443}"
HERALD_TOKEN="${HERALD_TOKEN}"

dns_herald_add() {
  local fulldomain="$1" txtvalue="$2"
  local domain="${fulldomain#_acme-challenge.}"

  _info "Setting challenge for ${domain}"

  curl -sf -X POST "${HERALD_URL}/api/v1/acme/challenge" \
    -H "Authorization: Bearer ${HERALD_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"${domain}\", \"value\": \"${txtvalue}\"}" || return 1

  sleep 15  # DNS propagation
  return 0
}

dns_herald_rm() {
  local fulldomain="$1"
  local domain="${fulldomain#_acme-challenge.}"

  _info "Clearing challenge for ${domain}"

  curl -sf -X POST "${HERALD_URL}/api/v1/acme/challenge/clear" \
    -H "Authorization: Bearer ${HERALD_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"${domain}\"}" || return 1

  return 0
}
```

Usage:
```bash
export HERALD_URL="https://herald.internal.example.org:8443"
export HERALD_TOKEN="token-for-service1"
acme.sh --issue --dns dns_herald -d service1.example.org
```

### Client Token Setup

1. Add the client to Herald's config (ACME or dynamic):
   ```yaml
   providers:
     acme:
       clients:
         service1:
           allowed_domains:
             - "service1.example.org"
             - "*.service1.example.org"
   ```

2. Add the token to the shared tokens file:
   ```json
   {
     "service1": "randomly-generated-token-here"
   }
   ```

3. Distribute the token securely to the ACME client (sops, Vault, manual).

## Dynamic DNS Integration

Herald acts as a DNS record management API for systems like OPNsense, allowing authenticated clients to create, update, and delete DNS records with fine-grained domain and zone permission scoping.

### Configuration

1. Enable the dynamic provider:
   ```yaml
   providers:
     dynamic:
       clients:
         opnsense:
           allowed_domains:
             - "*.example.com"      # Wildcard matches any subdomain
           allowed_zones:
             - "example.com"        # Can only target this zone
   ```

2. Add the client token to the shared tokens file:
   ```json
   {
     "opnsense": "token-for-opnsense-dynamic-dns"
   }
   ```

### API Endpoints

#### Set DNS Record

```bash
curl -X POST https://localhost:8443/api/v1/dns/record \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "zone": "example.com",
    "name": "wan.example.com",
    "type": "A",
    "value": "198.51.100.1",
    "ttl": 60
  }'
# {"success": true}
```

#### Delete DNS Record

```bash
curl -X POST https://localhost:8443/api/v1/dns/record/delete \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "zone": "example.com",
    "name": "wan.example.com",
    "type": "A"
  }'
# {"success": true}
```

### Permission Scoping

Each dynamic DNS client is scoped by:
- **`allowed_domains`**: Domain patterns (glob) that the client can manage. Use `*.example.com` for all subdomains, or exact domains like `wan.example.com`.
- **`allowed_zones`**: List of Cloudflare zones the client can target. A client attempting to write to `zone.example.org` when only `example.com` is allowed will be rejected.

A request must pass both checks to succeed.

### Ownership and Deletion

Records created via the dynamic DNS API are tagged with the client name. Only the client that created a record can delete it. Attempting to delete another client's record will fail with a 403 error.

### Multi-Zone Setup

To manage records across multiple Cloudflare zones with a single OPNsense instance:

```yaml
providers:
  dynamic:
    clients:
      opnsense:
        allowed_domains:
          - "*.example.com"
          - "*.internal.example.org"
        allowed_zones:
          - "example.com"
          - "internal.example.org"
```

The client can now set records in either zone, but only for domains matching the allowed patterns.

## RFC 2136 Backend

Herald can manage DNS records on any RFC 2136-compatible authoritative DNS server (BIND, Knot, PowerDNS) by sending DNS UPDATE messages. Unlike the Cloudflare and Technitium backends, RFC 2136 has no native comment/tag field, so Herald tracks managed records in a local SQLite database.

### Key characteristics

- **Managed record tracking**: Herald only touches records it created. Pre-existing records in the zone are invisible to the reconciler and will never be modified or deleted.
- **Prerequisite enforcement**: DNS UPDATE messages include RFC 2136 prerequisite assertions to detect state drift between Herald and the authoritative server. CREATE requires the RRset to not already exist (§2.4.3). UPDATE uses atomic compare-and-swap, asserting the current value matches before swapping (§2.4.2). DELETE has no prerequisite (idempotent).
- **Self-healing on drift**: When a prerequisite fails (e.g., someone edited a record out-of-band), Herald queries the authoritative server to discover the actual state and updates its local SQLite ledger. The next reconciliation cycle then converges correctly.
- **Atomic updates**: UPDATE operations are sent as a single DNS UPDATE message (compare-and-swap) rather than separate delete + create messages, eliminating races where one could succeed and the other fail.
- **TSIG authentication**: All DNS UPDATE messages can be signed with TSIG (RFC 2845/8945). HMAC-SHA256 is the default; the full RFC 8945 algorithm set is supported via hickory-dns. Without a TSIG key, updates are sent unsigned — only use this on trusted networks with server-side IP ACLs.
- **TCP transport**: All DNS UPDATE messages are sent over TCP.
- **State database**: Stored at `{state_dir}/rfc2136-{name}.db` — back this up along with your config.

### Configuration

```yaml
backends:
  rfc2136:
    - name: "bind-internal"          # optional; defaults to "rfc2136-{index}"
      zones:
        - "internal.example.com"
      primary_nameserver: "ns1.internal.example.com:53"  # port defaults to 53 if omitted
      tsig_key_file: "/run/secrets/herald_tsig_key"      # base64 HMAC-SHA256 secret
      tsig_key_name: "herald.internal.example.com"       # key name as used in nsupdate/BIND config
```

### TSIG key setup (BIND)

```bash
# Generate a TSIG key
tsig-keygen -a hmac-sha256 herald.internal.example.com > /etc/bind/herald.key

# Add to named.conf
key "herald.internal.example.com" {
    algorithm hmac-sha256;
    secret "<base64-secret-from-tsig-keygen>";
};

# Allow updates from Herald
zone "internal.example.com" {
    type master;
    file "internal.example.com.zone";
    allow-update { key herald.internal.example.com; };
};
```

Extract the secret for Herald's `tsig_key_file`:
```bash
grep secret /etc/bind/herald.key | awk -F'"' '{print $2}' > /run/secrets/herald_tsig_key
```

### Firewall requirements

Herald connects outbound to the primary nameserver on TCP port 53 (or the configured port). Ensure:
- Herald host can reach the nameserver on TCP/53
- The nameserver's ACL allows updates from Herald's IP

### Mirror source (AXFR zone transfer)

The RFC 2136 mirror source type uses AXFR zone transfer to enumerate all records in a zone, without requiring API access:

```yaml
providers:
  mirror:
    source:
      type: rfc2136
      zone: "internal.example.com"
      nameserver: "ns1.internal.example.com:53"
      tsig_key_file: "/run/secrets/axfr_key"    # optional TSIG for AXFR authentication
      tsig_key_name: "axfr.internal.example.com"
    rules:
      - match:
          type: AAAA
        transform:
          suffix: "example.org"
```

AXFR requires that the authoritative server permits zone transfers from Herald's IP. In BIND:
```
zone "internal.example.com" {
    allow-transfer { key axfr.internal.example.com; };  # or IP-based ACL
};
```

## DNS UPDATE Receiver

Herald can act as a DNS UPDATE target (RFC 2136 server), accepting `nsupdate`-compatible messages over UDP and TCP. Incoming records are stored in the dynamic provider and a reconciliation pass is triggered automatically.

This provides an alternative transport to the HTTP API, useful for:
- **OPNsense** — via its "Services > Dynamic DNS > RFC 2136" plugin
- **nsupdate** — standard BIND utility for DNS updates
- **Any RFC 2136-compatible client**

### Prerequisites

The DNS UPDATE receiver requires the dynamic provider to be configured. Incoming records are managed under the specified TSIG key's associated client name.

### Configuration

```yaml
# Dynamic provider (must be configured)
providers:
  dynamic:
    clients:
      opnsense:
        allowed_domains:
          - "*.example.com"
        allowed_zones:
          - "example.com"

# DNS UPDATE receiver
dns_server:
  listen: "[::]:5353"   # use 53 for standard DNS port (requires elevated privileges)
  tsig_keys:
    - key_name: "opnsense.example.com"     # TSIG key name in DNS messages
      algorithm: "hmac-sha256"             # only supported algorithm
      secret_file: "/run/secrets/tsig_opnsense"  # base64 HMAC-SHA256 secret
      client: "opnsense"                   # must match a providers.dynamic.clients key
```

### TSIG key generation

```bash
# Generate a key for OPNsense
tsig-keygen -a hmac-sha256 opnsense.example.com

# Extract the base64 secret
tsig-keygen -a hmac-sha256 opnsense.example.com | awk '/secret/ {gsub(/[";]/, "", $2); print $2}' \
  > /run/secrets/tsig_opnsense
```

### OPNsense configuration (RFC 2136 plugin)

In OPNsense: **Services > Dynamic DNS > RFC 2136 > Add**

| Field       | Value                                         |
|-------------|-----------------------------------------------|
| Server      | `herald.example.com`                          |
| Port        | `5353` (or your configured port)              |
| Key name    | `opnsense.example.com` (must match `key_name`)|
| Key         | base64 HMAC-SHA256 secret (from `secret_file`)|
| Algorithm   | HMAC-SHA256                                   |
| Zone        | `example.com`                                 |
| Record      | `wan.example.com`                             |

### nsupdate usage

```bash
# Create/update an A record
nsupdate -y hmac-sha256:opnsense.example.com:<base64-secret> <<EOF
server herald.example.com 5353
update add wan.example.com 60 A 198.51.100.1
send
EOF

# Delete a record
nsupdate -y hmac-sha256:opnsense.example.com:<base64-secret> <<EOF
server herald.example.com 5353
update delete wan.example.com A
send
EOF
```

### Firewall requirements

Open the DNS UPDATE port (UDP and TCP) to clients that need to send updates. Restrict to known client IPs where possible — TSIG provides cryptographic authentication, but defence in depth is valuable.

### Permission model

Incoming DNS UPDATE records are subject to the same permission scoping as the HTTP API:
- The TSIG key's `client` must have `allowed_domains` matching the record name
- The derived zone must be in `allowed_zones`
- Only records in configured backend zones can be managed

### Prerequisite evaluation

The DNS UPDATE receiver evaluates all five RFC 2136 §3.2 prerequisite forms against actual backend state. Prerequisites are checked using targeted per-name queries — for the RFC 2136 backend, this queries the authoritative server directly rather than local state.

### Limitations

- Responses are not TSIG-signed

## Multi-Zone Setup

Herald supports managing DNS records across multiple Cloudflare zones. This is useful for organizations managing multiple domains or environments.

### Configuration

```yaml
backends:
  cloudflare:
    zones:
      - "example.com"
      - "internal.example.org"
      - "staging.example.com"
    token_file: "/run/secrets/herald_cloudflare_token"
```

The Cloudflare API token must have `Zone:DNS:Edit` permission scoped to all target zones.

### Provider Integration

Each provider (static, mirror, ACME, dynamic) specifies which zone to target for its records:

```yaml
providers:
  static:
    records:
      - name: "www.example.com"
        zone: "example.com"
        type: A
        value: "203.0.113.1"
      - name: "api.internal.example.org"
        zone: "internal.example.org"
        type: A
        value: "198.51.100.1"

  acme:
    zone: "example.com"  # ACME challenges go to this zone
    domain: "acme.example.com"

  mirror:
    rules:
      - match:
          type: AAAA
        transform:
          suffix: "example.com"
          zone: "example.com"  # Mirror targets this zone
      - match:
          type: A
        transform:
          suffix: "internal.example.org"
          zone: "internal.example.org"  # Different mirror rule, different zone
```

### Reconciliation

The reconciler treats records across different zones as independent. Two records with the same name and type can coexist if they're in different zones:

- `[example.com] www.example.com A 203.0.113.1`
- `[internal.example.org] www.example.com A 198.51.100.1`

These are separate records with no conflict.

## Troubleshooting

### Token File Not Found

**Error**: `reading Cloudflare token file: /run/secrets/herald_cloudflare_token: No such file or directory`

**Solution**:
- Verify the file exists: `ls -l /run/secrets/herald_cloudflare_token`
- Check file permissions (herald user must be able to read)
- For NixOS with sops-nix, ensure `config.sops.secrets.herald_cloudflare_token.path` matches the config

### Zone Not Found

**Error**: `zone example.com not found`

**Solution**:
- Verify the zone name is listed in `backends.cloudflare.zones`
- Verify the zone name exactly matches what's in Cloudflare
- Check that the API token has access to the zone
- Test the token manually:
  ```bash
  TOKEN=$(cat /run/secrets/herald_cloudflare_token)
  curl -H "Authorization: Bearer $TOKEN" \
    https://api.cloudflare.com/client/v4/zones?name=example.com
  ```

### Dynamic DNS Permission Denied

**Error**: `client opnsense is not allowed to manage challenges for other.example.org` or `not allowed to target zone example.org`

**Solution**:
- Verify the client's `allowed_domains` includes the target domain (supports wildcards like `*.example.com`)
- Verify the client's `allowed_zones` includes the target zone
- Remember that both checks must pass: domain pattern AND zone must be allowed
- Check that the client name in the request matches the token owner

### DNS Propagation Delays

**Symptom**: ACME challenges fail with "DNS record not found"

**Solution**:
- Herald sets TXT records with `ttl: 60`, but propagation takes time
- Increase sleep in ACME hooks from 10s to 20-30s
- Check that the record appears in Cloudflare's dashboard
- Verify with `dig`:
  ```bash
  dig +short _acme-challenge.service1.example.org TXT @1.1.1.1
  ```

### Dry-Run Mode Enabled

**Symptom**: Herald logs changes but they never appear at Cloudflare

**Solution**:
- Check config: `reconciler.dry_run: false`
- Check CLI flag: not running with `--dry-run`
- Look for log line: `dry-run: changes not applied`

### ACME Permission Denied

**Error**: `client service1 is not allowed to manage challenges for other-domain.example.org`

**Solution**:
- Verify the client's `allowed_domains` in config includes the target domain
- Wildcards (`*.example.org`) match subdomains, not the apex
- Check client name in tokens file matches the name in config

### Unmanaged Record Conflict

**Symptom**: Herald logs `desired record conflicts with unmanaged record; skipping`

**Solution**:
- A manually-created record exists at Cloudflare without the `managed-by: herald` comment
- Either:
  - Delete the manual record and let Herald recreate it (will be tagged)
  - Remove the record from Herald's desired state if you want to keep it manual
- Herald will never modify or delete records without the managed tag

### RFC 2136 Prerequisite Failure

**Error**: `DNS UPDATE prerequisite failed ... NXRRSet (state drift)` or `... YXRRSet (state drift)`

**Explanation**: Herald's local SQLite state doesn't match the authoritative DNS server. This happens when records are modified or deleted outside of Herald (manual `nsupdate`, another tool, zone reload).

**What Herald does automatically**:
- Queries the authoritative server to discover actual state
- Updates its SQLite ledger to match
- The next reconciliation cycle will generate the correct change

**If it persists**:
- Check whether another system is managing the same records (conflicting automation)
- Inspect the SQLite database: `sqlite3 {state_dir}/rfc2136-{name}.db "SELECT * FROM managed_records;"`
- Compare with actual DNS: `dig @ns1.example.com host.example.com A`
- As a last resort, delete the SQLite database — Herald will treat all its records as new CREATEs on the next cycle (existing records will fail the "does not exist" prerequisite and be resynced)

### High API Error Rate

**Symptom**: `herald.backend.api_calls{status="error"}` metric is high

**Solution**:
- Check Cloudflare API status: https://www.cloudflarestatus.com/
- Verify token hasn't expired or been revoked
- Look at Herald logs for specific error messages
- Check rate limits (Herald respects Cloudflare's limits, but external tools may share the quota)

### Reconciliation Taking Too Long

**Symptom**: `herald.reconciliation.duration` P95 > 30 seconds

**Solution**:
- Check number of records being managed (Cloudflare API pagination)
- Verify network latency to Cloudflare API
- Look for provider errors causing retries
- Consider reducing `reconciler.interval` if load is acceptable

## Logs

Herald uses structured JSON logging. Key fields:

- `level`: `info`, `warn`, `error`
- `timestamp`: ISO 8601
- `target`: Rust module path (e.g., `herald::reconciler`)
- `fields`: Structured context (e.g., `provider`, `fqdn`, `error`)

Example log filtering:

```bash
# View only errors
journalctl -u herald | jq 'select(.level == "error")'

# View ACME operations
journalctl -u herald | jq 'select(.fields.fqdn != null)'

# View reconciliation changes
journalctl -u herald | jq 'select(.fields.change != null)'
```

### Log Levels

Control via `RUST_LOG` environment variable:

```bash
# Default: info level for herald, warn for dependencies
RUST_LOG=herald=info

# Debug mode (very verbose)
RUST_LOG=herald=debug

# Trace everything (including dependencies)
RUST_LOG=trace
```

## Upgrading

Herald aims for backward-compatible config changes. When upgrading:

1. Review the changelog for breaking changes
2. Test in dry-run mode first: `herald --config config.yaml --once --dry-run`
3. Verify no unexpected changes would be applied
4. Restart the service

For NixOS, update the flake input and rebuild:

```bash
nix flake lock --update-input herald
nixos-rebuild switch
```

## Performance

Herald is designed for small to medium deployments (hundreds of DNS records). Performance characteristics:

- **Reconciliation time**: ~1-3 seconds for 100 records (dominated by Cloudflare API pagination)
- **Memory usage**: ~10-20 MB RSS
- **API response time**: <10ms for ACME challenge set/clear
- **Mirror polling**: ~100-500ms for Technitium zones with 50 records

Herald does not currently batch changes or parallelize API calls, so reconciliation time scales linearly with record count.
