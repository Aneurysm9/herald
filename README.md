# Herald

[![CI](https://github.com/Aneurysm9/herald/actions/workflows/ci.yml/badge.svg)](https://github.com/Aneurysm9/herald/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Aneurysm9/herald)](https://github.com/Aneurysm9/herald/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-orange.svg)](Cargo.toml)

**DNS control plane for multi-provider record management**

Managing DNS records across multiple providers and zones is tedious and error-prone. Records drift, manual changes get lost, and coordinating updates across Cloudflare, internal DNS servers, and ACME challenges means juggling multiple APIs and credentials. Herald solves this by providing a single reconciliation loop that takes a declared desired state and converges it across any number of backends — safely, repeatedly, and automatically.

## Features

- **Declarative static records** — define DNS records in a config file; Herald reconciles them to your backends
- **ACME challenge proxy** — per-service scoped tokens for DNS-01 certificate validation, compatible with lego and acme.sh
- **DNS mirroring** — poll internal DNS zones (Technitium API, direct DNS queries, or AXFR zone transfer) and mirror selected records to public DNS under different names
- **Dynamic DNS** — API-driven record management with fine-grained domain and zone permission scoping (DynDNS protocol compatible)
- **RFC 2136 backend** — send DNS UPDATE messages to any authoritative server (BIND, Knot, PowerDNS) with TSIG authentication, prerequisite-based consistency checks, and self-healing state resync
- **DNS UPDATE receiver** — accept nsupdate-compatible DNS UPDATE messages as an alternative to the HTTP API (OPNsense compatible)
- **Multi-backend support** — Cloudflare, Technitium DNS Server, and RFC 2136; trait-based design for adding more
- **Safe reconciliation** — diffs desired vs actual state, tags managed records, never touches manually-created records

## Architecture

```
Providers (sources of desired records)
  ├── static    — records from config file
  ├── mirror    — poll a DNS source (Technitium/DNS/AXFR), transform names, filter types
  ├── acme      — ephemeral TXT records from API, per-client scoped
  └── dynamic   — API-driven records, per-client domain/zone scoped
          ▲
          │  DNS UPDATE server (optional)
          │  nsupdate/OPNsense → dynamic provider
          │
          ▼
     Reconciler
  diffs desired vs actual → creates/updates/deletes
          │
          ▼
     Backends (where records are published)
  ├── cloudflare  — Cloudflare API, multi-zone support
  ├── technitium  — Technitium DNS Server HTTP API, multi-zone support
  └── rfc2136     — DNS UPDATE to BIND/Knot/PowerDNS, atomic CAS with prerequisites, SQLite tracking
```

Each provider implements the `Provider` trait and contributes `Vec<DnsRecord>` to a unified desired-state set. The reconciler diffs this against actual state from the backends and converges. The process is safe to re-run and supports dry-run mode.

Herald uses each backend's comment field to tag managed records with `managed-by: herald`, ensuring it never modifies or deletes manually-created records.

## Quick Start

```bash
# Enter the development shell (provides Rust toolchain)
nix develop

# Build and run with a config file
cargo run -- --config config.yaml

# Or run a single reconciliation pass and exit
cargo run -- --config config.yaml --once

# Dry-run mode: compute changes without applying them
cargo run -- --config config.yaml --once --dry-run
```

## Configuration

Herald reads a YAML config file (default: `/etc/herald/config.yaml`). Environment variables with prefix `HERALD_` override config values.

Minimal example:

```yaml
listen: "[::]:8443"

tls:
  cert_file: "/run/secrets/herald_tls_cert"
  key_file: "/run/secrets/herald_tls_key"

tokens_file: "/run/secrets/herald_tokens"

backends:
  cloudflare:
    - zones: ["example.com"]
      token_file: "/run/secrets/herald_cloudflare_token"

providers:
  static:
    records:
      - name: "www.example.com"
        type: CNAME
        value: "example.com"
        ttl: 300

reconciler:
  interval: "1m"
  dry_run: false
```

For the full configuration reference, backend setup, multi-zone configuration, and secret management, see the [Operations Guide](docs/operations.md).

## API Reference

All endpoints except `/health` require a `Authorization: Bearer <token>` header. Tokens are mapped to client names and compared using constant-time equality.

### Health Check

```bash
curl -k https://localhost:8443/health
# 200 ok
```

### Set ACME Challenge

Creates a TXT record at `_acme-challenge.<domain>` with the given value. The client must have permission for the specified domain.

```bash
curl -k -X POST https://localhost:8443/api/v1/acme/challenge \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "service1.example.org", "value": "abc123-acme-challenge-digest"}'
```

### Clear ACME Challenge

Removes a previously set challenge TXT record. Only the client that created the challenge can clear it.

```bash
curl -k -X POST https://localhost:8443/api/v1/acme/challenge/clear \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "service1.example.org"}'
```

### Set DNS Record

Create or update a DNS record (requires dynamic provider configured). The client must have permission for both the domain name and the zone.

```bash
curl -k -X POST https://localhost:8443/api/v1/dns/record \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "zone": "example.com",
    "name": "wan.example.com",
    "type": "A",
    "value": "198.51.100.1",
    "ttl": 60
  }'
```

### Delete DNS Record

Remove a DNS record (requires dynamic provider configured). Only the client that created the record can delete it.

```bash
curl -k -X POST https://localhost:8443/api/v1/dns/record/delete \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "zone": "example.com",
    "name": "wan.example.com",
    "type": "A"
  }'
```

### List Records

Returns all desired records from all providers.

```bash
curl -k https://localhost:8443/api/v1/records \
  -H "Authorization: Bearer $TOKEN"
```

### Trigger Reconciliation

Runs an immediate reconciliation pass.

```bash
curl -k -X POST https://localhost:8443/api/v1/reconcile \
  -H "Authorization: Bearer $TOKEN"
```

## Building

```bash
# Development build
cargo build

# Release build
cargo build --release

# Static musl binary (for deployment)
nix build .#heraldStatic

# Build with nix (default package)
nix build
```

## Testing

```bash
# Run all tests
cargo test

# Lint (clippy pedantic is enforced project-wide)
cargo clippy --all-targets -- -D warnings

# Format check
cargo fmt -- --check
```

## Deployment

Herald is designed to run as a single static binary. For deployment instructions, NixOS module configuration, systemd setup, TLS, monitoring, and troubleshooting, see the [Operations Guide](docs/operations.md).

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, testing practices, and the contribution workflow.

## Security

To report a security vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
