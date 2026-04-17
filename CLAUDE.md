# CLAUDE.md — Herald DNS Control Plane

This file provides guidance to Claude Code when working on the Herald codebase.

## Build Commands

```bash
# Enter dev shell (provides Rust toolchain, cargo-watch, alejandra)
nix develop

# Build
cargo build

# Run tests
cargo test

# Run with file watching
cargo watch -x run

# Check / lint (pedantic enabled via Cargo.toml [lints.clippy])
cargo clippy --all-targets -- -D warnings

# Format check
cargo fmt -- --check

# Build static musl binary (for deployment)
nix build .#heraldStatic

# Build with nix
nix build
```

The Nix formatter is **alejandra**.

## Project Overview

Herald is a DNS control plane service that manages DNS records across multiple DNS backends (Cloudflare, Technitium DNS Server) with fine-grained control. It is a Rust service deployed as a single static binary on NixOS.

### Four use cases

1. **ACME challenge proxy** — per-service scoped tokens for DNS-01 certificate validation. Services call Herald's API to set/clear `_acme-challenge` TXT records. Each service has its own token and can only manage challenges for its allowed domains.

2. **Declarative static records** — infrastructure-as-code DNS records defined in Herald's config file and reconciled to Cloudflare.

3. **Dynamic DNS mirroring** — poll internal Technitium DNS zones (e.g., AAAA records from DHCPv6/RA in `internal.example.com`), mirror selected records to Cloudflare under different names (e.g., `host.example.org`). Internal zone structure is never exposed publicly.

4. **Dynamic DNS records** — API-driven DNS record management for systems like OPNsense. Authenticated clients can create, update, and delete arbitrary DNS records with fine-grained domain and zone permission scoping.

## Architecture

```
herald
├── Providers (sources of desired records)
│   ├── static    — records from config file
│   ├── mirror    — poll a DNS source, transform names, filter types
│   ├── acme      — ephemeral TXT records from API, per-client scoped
│   ├── dynamic   — API-driven records, per-client domain/zone scoped
│   └── (future)  — webhook, Kubernetes, etc.
│
├── Backends (where records are published)
│   ├── cloudflare  — Cloudflare API, multi-zone support
│   ├── technitium  — Technitium DNS Server HTTP API, multi-zone support
│   ├── rfc2136     — RFC 2136 DNS UPDATE to any authoritative server (BIND, Knot, etc.)
│   └── (future)    — Route53, PowerDNS, etc.
│
├── Reconciler
│   └── Periodically diffs desired state vs actual → creates/updates/deletes
│
├── DNS UPDATE server (optional)
│   └── Receives nsupdate-compatible DNS UPDATE messages, feeds into dynamic provider
│
└── API server (axum)
    └── Authenticated endpoints for ACME challenges, DNS records, and management
    └── Per-client tokens with scoped permissions (HMAC-SHA256 based)
```

### Key design properties

- **Provider pattern**: Each provider implements the `Provider` trait and contributes `Vec<DnsRecord>` to a unified desired-state set. Providers are independent and composable.
- **Reconciliation, not imperative**: The reconciler diffs desired vs actual and converges. Safe to re-run. Supports dry-run mode.
- **ACME is just a provider**: Challenge TXT records are ephemeral entries in the desired state, added/removed via API. They participate in the same reconciliation loop as all other records.
- **DNS mirroring**: The mirror provider polls a DNS source, applies transformation rules (rename, filter by type/name), and contributes to desired state. Runs on a configurable schedule.
- **Zone-agnostic providers**: Providers declare records by FQDN only. The reconciler derives the zone from the FQDN using backend zone declarations via longest suffix matching. This decouples providers from backend topology.
- **Multi-backend support**: Multiple backends can be configured, each managing a distinct set of zones. Zones cannot overlap between backends.

### Zone Derivation

Herald uses **longest suffix matching** to derive the zone for a given FQDN from the configured backends:

1. **Backends declare zones**: Each backend specifies which DNS zones it manages (e.g., `["example.com", "sub.example.com"]`)
2. **Providers emit FQDNs**: Providers create `DnsRecord` entries with just the fully-qualified domain name (e.g., `www.sub.example.com`)
3. **Reconciler derives zones**: For each record, the reconciler finds the longest matching zone suffix
4. **Records route to backends**: The derived zone determines which backend handles the record

**Examples:**
- FQDN: `www.example.com`, zones: `["example.com"]` → zone: `example.com`
- FQDN: `host.sub.example.com`, zones: `["example.com", "sub.example.com"]` → zone: `sub.example.com` (longest match)
- FQDN: `example.com`, zones: `["example.com"]` → zone: `example.com` (exact match)

This design allows:
- **Provider simplicity**: Providers don't need to know about zones or backend topology
- **Multi-backend support**: Mix Cloudflare (public DNS) and Technitium (internal DNS) in the same Herald instance
- **Multi-account support**: Different API tokens can manage different zones (e.g., separate Cloudflare accounts, multiple Technitium servers)
- **Flexible deployment**: Adding/removing zones only requires updating backend config

### Source layout

```
src/
├── main.rs           — CLI parsing, config loading, service startup
├── config.rs         — Configuration types and loading (figment)
├── api/mod.rs        — axum API server (health, ACME, dynamic DNS endpoints)
├── provider/
│   ├── mod.rs        — Provider trait, DnsRecord type, shared utilities
│   ├── static.rs     — Static records from config
│   ├── mirror.rs     — DNS mirroring with name transformation
│   ├── acme.rs       — Ephemeral ACME challenge records
│   └── dynamic.rs    — API-driven DNS records with permission scoping
├── backend/
│   ├── mod.rs         — Backend trait + Change type
│   ├── cloudflare.rs  — Cloudflare API implementation (multi-zone support)
│   ├── technitium.rs  — Technitium DNS Server API implementation (multi-zone support)
│   └── rfc2136.rs     — RFC 2136 DNS UPDATE backend (SQLite managed-record tracking)
├── reconciler/
│   └── mod.rs         — Desired vs actual diff + change application
├── dns_server.rs      — RFC 2136 DNS UPDATE receiver (nsupdate-compatible server)
├── rfc2136_util.rs    — Herald ↔ hickory-dns adapter (RecordValue ↔ RData conversions, TSIG key loading)
└── technitium_util.rs — Shared Technitium API types and utilities
```

## Config File Schema

Herald reads a YAML config file (default: `/etc/herald/config.yaml`). Environment variables with prefix `HERALD_` override config values.

```yaml
# API server listen address
listen: "[::]:8443"

# TLS certificate and key (required)
tls:
  cert_file: "/run/secrets/herald_tls_cert"   # PEM cert chain (leaf + intermediates)
  key_file: "/run/secrets/herald_tls_key"     # PEM private key

# Client tokens (shared by ACME and dynamic DNS)
# JSON file: {"client_name": "token_value", ...}
tokens_file: "/run/secrets/herald_tokens"

# Backends — where records are published
backends:
  cloudflare:
    - name: "personal"  # optional name for logging
      zones:
        - "example.org"
        - "example.com"
      token_file: "/run/secrets/herald_cloudflare_personal"
    - name: "work"
      zones:
        - "corp.example"
      token_file: "/run/secrets/herald_cloudflare_work"

  technitium:
    - name: "internal"  # optional name for logging
      zones:
        - "internal.example.org"
        - "internal.local"
      url: "http://ns01.internal.example.com:5380"
      token_file: "/run/secrets/herald_technitium_token"

  rfc2136:
    - name: "bind-internal"  # optional name for logging
      zones:
        - "internal.example.com"
      primary_nameserver: "ns1.internal.example.com:53"  # :53 default if port omitted
      tsig_key_file: "/run/secrets/herald_tsig_key"      # base64 HMAC-SHA256 secret
      tsig_key_name: "herald.internal.example.com"       # key name in DNS messages

# Providers — sources of desired records
providers:
  # Static records from config
  static:
    records:
      - name: "www.example.org"
        type: CNAME
        value: "example.org"
        ttl: 300
      - name: "example.org"
        type: A
        value: "203.0.113.1"
        ttl: 300

  # Mirror records from internal DNS
  mirror:
    source:
      # Option 1: Technitium API (requires API access)
      type: technitium
      url: "http://ns01.internal.example.com:5380"
      zone: "internal.example.com"
      token_file: "/run/secrets/herald_technitium_token"

      # Option 2: Direct DNS queries (works with any DNS server)
      # type: dns
      # zone: "internal.example.com"
      # subdomains:  # optional: explicit list of subdomains to query
      #   - "host1"
      #   - "host2"

      # Option 3: AXFR zone transfer (RFC 2136-compatible authoritative server)
      # type: rfc2136
      # zone: "internal.example.com"
      # nameserver: "ns1.internal.example.com:53"
      # tsig_key_file: "/run/secrets/tsig_key"  # optional TSIG for AXFR auth
      # tsig_key_name: "axfr.internal.example.com"
    rules:
      - match:
          type: AAAA             # only AAAA records
        transform:
          suffix: "example.org"  # replace source zone suffix
      - match:
          type: A
          name: "*.internal.example.com"
        transform:
          suffix: "example.org"
    interval: "5m"

  # ACME DNS-01 challenge proxy
  acme:
    clients:
      proxy:
        allowed_domains:
          - "proxy.example.com"
          - "*.example.com"
      webapp:
        allowed_domains:
          - "app.example.com"

  # Dynamic DNS records — API-driven record management
  dynamic:
    clients:
      opnsense:
        allowed_domains:
          - "*.example.com"
        allowed_zones:
          - "example.com"
      other:
        allowed_domains:
          - "other.example.org"
        allowed_zones:
          - "example.org"

# Reconciler settings
reconciler:
  interval: "1m"
  dry_run: false

# DNS UPDATE server (optional) — receives nsupdate/OPNsense DNS UPDATE messages
dns_server:
  listen: "[::]:5353"  # default port; use 53 if running as root/with CAP_NET_BIND_SERVICE
  tsig_keys:
    - key_name: "opnsense.example.com"  # TSIG key name as it appears in DNS messages
      algorithm: "hmac-sha256"          # only supported algorithm
      secret_file: "/run/secrets/tsig_opnsense"  # file containing base64 HMAC secret
      client: "opnsense"               # must match a key in providers.dynamic.clients
```

## API Design

### Authentication

All API endpoints (except `/health`) require a `Authorization: Bearer <token>` header. Tokens are mapped to client names using HMAC-SHA256 hashing for O(1) lookup with timing-attack resistance.

### Error Responses

All API endpoints (except `/health` and `/nic/update`) return errors as structured JSON:

```json
{"error": {"code": "UNAUTHORIZED", "message": "missing or invalid authorization"}}
```

Error codes: `UNAUTHORIZED` (401), `FORBIDDEN` (403), `BAD_REQUEST` (400), `NOT_CONFIGURED` (501), `INTERNAL_ERROR` (500).

Success responses return `200 OK`. Mutation endpoints return an empty body. `GET /api/v1/records` returns data directly.

### Endpoints

#### `GET /health`
No auth required. Returns `200 ok`.

#### `POST /api/v1/acme/challenge`
Set an ACME DNS-01 challenge TXT record.

Request:
```json
{
  "domain": "proxy.example.com",
  "value": "abc123-acme-challenge-digest"
}
```

This creates a TXT record at `_acme-challenge.proxy.example.com` with the given value. The client must have permission for this domain.

Response: `200 OK` (empty body). Triggers immediate reconciliation.

Error (domain not allowed):
```json
{"error": {"code": "FORBIDDEN", "message": "client proxy is not allowed to manage challenges for other.example.com"}}
```

#### `POST /api/v1/acme/challenge/clear`
Clear an ACME DNS-01 challenge.

Request:
```json
{
  "domain": "proxy.example.com"
}
```

Response: `200 OK` (empty body). Triggers immediate reconciliation.

#### `POST /api/v1/dns/record`
Create or update a DNS record (requires dynamic provider configured).

Request:
```json
{
  "zone": "example.com",  // optional - will be derived from name if omitted
  "name": "wan.example.com",
  "type": "A",
  "value": "198.51.100.1",
  "ttl": 60
}
```

The client must have permission for both the domain name and the zone. If `zone` is omitted, Herald will derive it from the `name` using the configured backend zones (longest suffix match).

Response: `200 OK` (empty body). Triggers immediate reconciliation.

Error (domain not allowed):
```json
{"error": {"code": "FORBIDDEN", "message": "client opnsense is not allowed to manage records for other.example.org"}}
```

#### `POST /api/v1/dns/record/delete`
Delete a DNS record (requires dynamic provider configured).

Request:
```json
{
  "zone": "example.com",  // optional - will be derived from name if omitted
  "name": "wan.example.com",
  "type": "A"
}
```

Only the client that created the record can delete it. Deleting a nonexistent record is a no-op (idempotent). If `zone` is omitted, Herald will derive it from the `name`.

Response: `200 OK` (empty body). Triggers immediate reconciliation.

#### `GET /nic/update` (DynDNS Protocol)
Update a DNS record using the classic DynDNS protocol (requires dynamic provider configured).

This endpoint provides compatibility with OPNsense and other clients that support the DynDNS/dyndns2 protocol.

**Authentication:** HTTP Basic Auth with `username=clientname` and `password=token`

**Query Parameters:**
- `hostname` (required) - FQDN to update (e.g., `wan.example.com`)
- `myip` (optional) - IPv4 address (creates/updates A record)
- `myipv6` (optional) - IPv6 address (creates/updates AAAA record)

**Example Request:**
```
GET /nic/update?hostname=wan.example.com&myip=198.51.100.1
Authorization: Basic <base64(clientname:token)>
```

**Responses (plain text):**
- `good <IP>` - Update successful
- `nochg <IP>` - IP unchanged (not currently implemented, always returns `good`)
- `badauth` - Authentication failed
- `nohost` - Hostname not allowed for client or zone not found
- `notfqdn` - Invalid hostname format
- `911` - Server error (dynamic provider not configured)

**OPNsense Configuration:**
1. **Services > Dynamic DNS > Settings**
2. **Add** new entry:
   - **Service:** DynDNS
   - **Protocol:** dyndns2
   - **Server:** `herald.example.com:8443`
   - **Username:** `opnsense` (your Herald client name)
   - **Password:** `your-herald-token`
   - **Hostname:** `wan.example.com`
   - **Check IP method:** Interface
   - **Interface to monitor:** WAN

OPNsense will automatically update the DNS record whenever the WAN IP changes.

#### `GET /api/v1/records`
List all desired records from all providers.

Response:
```json
{
  "records": [
    {
      "provider": "static",
      "name": "www.example.com",
      "record_type": "A",
      "value": "203.0.113.1",
      "ttl": 300
    }
  ]
}
```

When a provider fails, its records are omitted and a `warnings` array is included:

```json
{
  "records": [...],
  "warnings": ["provider 'mirror' failed: connection refused"]
}
```

The `warnings` field is omitted when empty.

#### `POST /api/v1/reconcile`
Trigger an immediate reconciliation pass.

Response: `200 OK` (empty body).

## Integration Points

### NixOS Module (in the nixos repo)

The NixOS module (`services.herald`) in the sibling nixos repo:
- Runs herald as a systemd service
- Serializes `settings` attrset to `/etc/herald/config.yaml`
- Manages sops secrets and passes paths via config
- Opens firewall on Tailscale interface only

### ACME Hook Script (lego exec provider)

For NixOS hosts using `security.acme` with DNS-01 validation, the nixos repo provides a module (`services.herald-acme`) that configures lego's `exec` DNS provider. The hook script:

```bash
#!/usr/bin/env bash
# Called by lego with: EXEC_MODE=present/cleanup CERTBOT_DOMAIN=... CERTBOT_VALIDATION=...
set -euo pipefail

HERALD_URL="${HERALD_URL:-https://herald.example.com:8443}"
TOKEN=$(cat /run/secrets/acme_service_token)

case "${EXEC_MODE}" in
  present)
    curl -sf -X POST "${HERALD_URL}/api/v1/acme/challenge" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"domain\": \"${CERTBOT_DOMAIN}\", \"value\": \"${CERTBOT_VALIDATION}\"}"
    # Wait for DNS propagation
    sleep 10
    ;;
  cleanup)
    curl -sf -X POST "${HERALD_URL}/api/v1/acme/challenge/clear" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"domain\": \"${CERTBOT_DOMAIN}\"}"
    ;;
esac
```

Lego calls this script with environment variables:
- `EXEC_MODE` — `present` (set challenge) or `cleanup` (clear challenge)
- `CERTBOT_DOMAIN` — the domain being validated (note: lego uses CERTBOT_ prefix for exec compatibility)
- `CERTBOT_VALIDATION` — the challenge token value

### acme.sh Hook (non-NixOS systems)

For Proxmox, OPNsense, or other non-NixOS systems, a ~20 line acme.sh DNS hook script:

```bash
#!/usr/bin/env bash
# acme.sh DNS hook for Herald
# Usage: acme.sh --dns dns_herald ...

HERALD_URL="${HERALD_URL:-https://herald.example.com:8443}"
HERALD_TOKEN="${HERALD_TOKEN:-$(cat /etc/herald/token)}"

dns_herald_add() {
  local fqdn="$1" value="$2"
  # fqdn is like _acme-challenge.example.com, extract the domain
  local domain="${fqdn#_acme-challenge.}"
  curl -sf -X POST "${HERALD_URL}/api/v1/acme/challenge" \
    -H "Authorization: Bearer ${HERALD_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"${domain}\", \"value\": \"${value}\"}"
}

dns_herald_rm() {
  local fqdn="$1"
  local domain="${fqdn#_acme-challenge.}"
  curl -sf -X POST "${HERALD_URL}/api/v1/acme/challenge/clear" \
    -H "Authorization: Bearer ${HERALD_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"${domain}\"}"
}
```

## DNS UPDATE Server

Herald can receive DNS UPDATE messages (RFC 2136) on a configurable address, providing an alternative to the HTTP API for clients like OPNsense (via its "RFC 2136 Dynamic DNS" plugin) or `nsupdate`.

### Authentication

All incoming DNS UPDATE messages must be signed with TSIG (RFC 2845/8945). HMAC-SHA256 is the default; hickory-dns supports the full RFC 8945 algorithm set. Each configured TSIG key maps to a dynamic provider client name; that client's `allowed_domains` and `allowed_zones` govern what records the key may manage.

### TSIG key file format

The `secret_file` for each TSIG key should contain a single base64-encoded HMAC-SHA256 secret (the raw key bytes encoded as base64, with or without trailing newline). This is the same format as `tsig-keygen` output with the secret extracted:

```bash
# Generate a key with tsig-keygen (BIND)
tsig-keygen -a hmac-sha256 opnsense.example.com

# Extract the secret for Herald's secret_file
tsig-keygen -a hmac-sha256 opnsense.example.com | grep secret | awk -F'"' '{print $2}' > /run/secrets/tsig_opnsense
```

### RCODE semantics

| Condition                          | RCODE          |
|------------------------------------|----------------|
| Success                            | 0 (NOERROR)    |
| Unknown TSIG key / bad MAC         | 9 (NOTAUTH)    |
| Domain or zone not permitted       | 5 (REFUSED)    |
| Zone not found for FQDN            | 5 (REFUSED)    |
| Malformed request                  | 1 (FORMERR)    |
| Non-UPDATE opcode                  | 5 (REFUSED)    |

### OPNsense configuration (RFC 2136 plugin)

OPNsense's "Services > Dynamic DNS > RFC 2136" plugin can send DNS UPDATE messages directly to Herald:
1. **Server**: `herald.example.com` (Herald's hostname)
2. **Port**: `5353` (or whatever `dns_server.listen` specifies)
3. **Key name**: must match `key_name` in Herald's `dns_server.tsig_keys`
4. **Key**: base64 HMAC-SHA256 secret (same value as `secret_file`)
5. **Algorithm**: `hmac-sha256`

### nsupdate usage

```bash
nsupdate -k /path/to/tsig.key <<EOF
server herald.example.com 5353
update add wan.example.com 60 A 198.51.100.1
send
EOF
```

### Limitations

- Prerequisite section (RFC 2136 §3.2) is parsed by hickory but not evaluated — updates always proceed if TSIG authentication succeeds
- `TYPE=ANY` delete-all is parsed but not yet dispatched to the dynamic provider
- Responses are not TSIG-signed (future work)
- Zone section validation (ZOCOUNT=1, QTYPE=SOA, QCLASS=IN) is now enforced

## Cloudflare API Reference

Herald targets the Cloudflare v4 API. Base URL: `https://api.cloudflare.com/client/v4`

### Authentication
`Authorization: Bearer <token>` header. The token needs `Zone:DNS:Edit` permission scoped to the target zone.

### Key endpoints

- `GET /zones?name=example.org` — look up zone ID
- `GET /zones/{zone_id}/dns_records?page=N&per_page=100` — list records (paginated)
- `POST /zones/{zone_id}/dns_records` — create record
- `PUT /zones/{zone_id}/dns_records/{record_id}` — update record
- `DELETE /zones/{zone_id}/dns_records/{record_id}` — delete record

### Record create/update body
```json
{
  "type": "A",
  "name": "www.example.org",
  "content": "203.0.113.1",
  "ttl": 300,
  "proxied": false,
  "comment": "managed-by: herald"
}
```

Note: Herald manages DNS records only (proxied: false). Proxied records require additional Cloudflare features and are not supported.

### Response format
```json
{
  "success": true,
  "errors": [],
  "result": { ... },
  "result_info": { "page": 1, "per_page": 100, "total_pages": 1, "count": 5, "total_count": 5 }
}
```

## Technitium API Reference

Herald's mirror provider and Technitium backend use the Technitium DNS Server HTTP API.

### Authentication
Pass `token=<api_token>` as a query parameter on every request.

### Key endpoints

- `GET /api/zones/records/get?token=TOKEN&domain=ZONE&zone=ZONE` — list all records in a zone
- `POST /api/zones/records/add` — create a new DNS record (form-encoded parameters)
- `POST /api/zones/records/delete` — delete an existing DNS record (form-encoded parameters)

### Response format
```json
{
  "status": "ok",
  "response": {
    "records": [
      {
        "name": "host.internal.example.com",
        "type": "AAAA",
        "rData": {
          "ipAddress": "2001:db8::1"
        },
        "ttl": 300
      }
    ]
  }
}
```

The `rData` structure varies by record type:
- A: `{"ipAddress": "..."}`
- AAAA: `{"ipAddress": "..."}`
- CNAME: `{"cname": "..."}`
- TXT: `{"text": "..."}`
- MX: `{"preference": N, "exchange": "..."}`

### Backend-Specific Endpoints

When using Technitium as a backend (not just a mirror source), Herald creates, updates, and deletes records:

**Create/Update parameters** (POST `/api/zones/records/add`):
- `token` — API token
- `domain` — FQDN (e.g., `host.example.org`)
- `zone` — Zone name (e.g., `example.org`)
- `type` — Record type (A, AAAA, CNAME, TXT, MX)
- `ttl` — TTL in seconds
- `comments` — **Always set to `managed-by: herald`** (enables managed record tracking)
- `overwrite` — Set to `false` to avoid replacing existing records
- Type-specific: `ipAddress`, `cname`, `text`, or `preference`+`exchange`

**Delete parameters** (POST `/api/zones/records/delete`):
- Same as create, but identifies the exact record to delete

**Managed Record Tracking**: Like Cloudflare, Technitium supports a `comments` field. Herald tags all created records with `"managed-by: herald"` and only modifies/deletes records with this tag. This prevents Herald from touching manually-created records.

**MX Record Format**: Herald stores MX records internally as `"preference:exchange"` (e.g., `"10:mail.example.com"`). When creating/deleting via Technitium API, this is split into separate `preference` and `exchange` parameters.

## AAAA Mirroring Flow (Example)

### Technitium API Source

1. Mirror provider queries Technitium: `GET /api/zones/records/get?token=T&domain=internal.example.com&zone=internal.example.com`
2. Response includes: `myhost.internal.example.com AAAA 2001:db8::1`
3. Rule matches: type=AAAA, transform suffix=example.org
4. Provider contributes: `myhost.example.org AAAA 2001:db8::1` to desired state
5. Reconciler compares with Cloudflare actual state
6. If record doesn't exist or value differs → CREATE or UPDATE at Cloudflare
7. External clients: `dig myhost.example.org AAAA` → `2001:db8::1`
8. Internal hostnames (`internal.example.com`) never appear in public DNS

### DNS Lookup Source

1. Mirror provider queries DNS: A, AAAA, CNAME, TXT, MX lookups for `internal.example.com` and configured subdomains
2. Example response: `myhost.internal.example.com AAAA 2001:db8::1`
3. Rule matches: type=AAAA, transform suffix=example.org
4. Provider contributes: `myhost.example.org AAAA 2001:db8::1` to desired state
5. Same reconciliation flow as above

**DNS Lookup Limitations:**
- Cannot enumerate all records in a zone (no AXFR/zone transfer support)
- Only queries zone apex and explicitly configured subdomains
- Use `subdomains: ["host1", "host2"]` in config to query specific hosts
- Works with any DNS server (authoritative or recursive) without API access

## Managed Record Tracking

Herald needs to distinguish records it manages from records created manually at backends. Strategy:

- Use the backend's `comment` (or `comments`) field to tag managed records with `"managed-by: herald"`
- Only update/delete records that have this tag
- When creating records, always set the comment
- This prevents Herald from deleting manually-created records

**Cloudflare**: Herald creates records with `"proxied": false` and the comment tag:
```json
{
  "type": "A",
  "name": "www.example.org",
  "content": "203.0.113.1",
  "ttl": 300,
  "proxied": false,
  "comment": "managed-by: herald"
}
```

## Testing Strategy

### Unit tests
- `provider::mirror::tests` — name transformation, glob matching, rule application
- `provider::acme` — permission checking, challenge set/clear logic
- `provider::static` — config parsing to DnsRecord conversion
- `reconciler` — diff logic (create/update/delete detection) with mock backends
- `config` — config file parsing, defaults, env override

### Integration tests
- `api` — use `axum-test` to test HTTP endpoints, auth, request/response formats
- `backend::cloudflare` — use `wiremock` to mock Cloudflare API responses

### End-to-end (manual or CI)
- Start Herald with a test config pointing to a test Cloudflare zone
- Verify static records appear
- Set/clear ACME challenges via API
- Verify permission scoping works (rejected requests)

## Implementation Status

**Completed:**
1. ✅ **Config loading + main startup loop** — binary runs as systemd service
2. ✅ **Static provider + Cloudflare backend + Reconciler** — end-to-end for static records
3. ✅ **ACME provider + API server** — challenge set/clear flow
4. ✅ **Mirror provider (Technitium + DNS)** — DNS mirroring from internal zones
5. ✅ **Dynamic DNS provider** — API-driven record management (OPNsense integration)
6. ✅ **Managed record tracking** — comment-based tagging for both Cloudflare and Technitium
7. ✅ **Scheduling** — periodic reconciliation and mirror polling
8. ✅ **Technitium backend** — Technitium DNS Server as a backend target (in addition to Cloudflare)
9. ✅ **Persistence** — SQLite storage for dynamic DNS and ACME challenges
10. ✅ **RFC 2136 backend** — DNS UPDATE to BIND/Knot/etc., SQLite managed-record tracking
11. ✅ **RFC 2136 mirror source** — AXFR zone transfer as a mirror source type (`type: rfc2136`)
12. ✅ **DNS UPDATE receiver** — nsupdate-compatible server, feeds into dynamic provider

**Future:**
- Metrics / observability — OpenTelemetry metrics are partially implemented, could expand
- Additional backends — Route53, PowerDNS, etc.
- Batch operations — Optimize API calls with batch creates/deletes
- TSIG-signed responses in the DNS UPDATE receiver
- RFC 2136 prerequisite section evaluation

## Code Style

- Use `anyhow::Result` for application errors, `thiserror` for library-style errors in the provider/backend traits
- Structured logging with `tracing` — include relevant context fields
- Keep functions small and focused
- Prefer explicit error handling over `.unwrap()`
- Use `async_trait` for async trait methods
- Config types use `serde::Deserialize` with `#[serde(default)]` for optional fields

### Clippy — pedantic by default

`clippy::pedantic` is enabled project-wide via `[lints.clippy]` in `Cargo.toml`. All code must pass `cargo clippy --all-targets -- -D warnings` cleanly.

- **Maintain pedantic compliance** — fix warnings rather than suppressing them
- **Targeted `#[allow(...)]` only when justified** — add a comment explaining why (e.g., `#[allow(clippy::unused_async)] // Will await once implemented`)
- **Never blanket-allow pedantic** — do not add `#![allow(clippy::pedantic)]` to any module
- **New lint exceptions** require a code comment explaining the rationale
- The Nix flake CI enforces this via `cargoClippyExtraArgs = "--all-targets -- --deny warnings"`
