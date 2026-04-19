use anyhow::Result;
use figment::{
    Figment,
    providers::{Env, Format, Yaml},
};
use serde::Deserialize;
use std::collections::HashMap;

use crate::telemetry::TelemetryConfig;

/// TLS configuration for the API server.
///
/// Both fields are required — Herald will fail to start if TLS is not configured.
/// Certificate and key files are PEM-encoded. The cert file should contain the
/// full chain (leaf + intermediates).
#[derive(Debug, Deserialize)]
pub(crate) struct TlsConfig {
    /// Path to PEM-encoded certificate chain file
    pub cert_file: String,

    /// Path to PEM-encoded private key file
    pub key_file: String,
}

/// Top-level configuration for Herald.
///
/// Loaded from a YAML file with environment variable overrides (`HERALD_*` prefix).
/// Use [`load`] to read configuration from disk.
#[derive(Debug, Deserialize)]
pub(crate) struct Config {
    /// Listen address for the API server
    #[serde(default = "default_listen")]
    pub listen: String,

    /// TLS certificate and key for HTTPS
    pub tls: TlsConfig,

    /// Backend configurations
    #[serde(default)]
    pub backends: BackendsConfig,

    /// Provider configurations
    #[serde(default)]
    pub providers: ProvidersConfig,

    /// Reconciler settings
    #[serde(default)]
    pub reconciler: ReconcilerConfig,

    /// Telemetry / OpenTelemetry settings
    #[serde(default)]
    pub telemetry: TelemetryConfig,

    /// Path to JSON file mapping client names to bearer tokens.
    /// Shared by all providers that need authentication (ACME, dynamic).
    #[serde(default)]
    pub tokens_file: Option<String>,

    /// Directory for persistent state (`SQLite` databases for dynamic DNS and ACME challenges)
    #[serde(default = "default_state_dir")]
    pub state_dir: String,

    /// Global rate limiting configuration.
    ///
    /// Sets a default per-client rate limit applied to all authenticated
    /// endpoints (API, `DynDNS`, DNS UPDATE). Per-client overrides in provider
    /// configs take precedence. If omitted, no rate limiting is applied.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,

    /// DNS UPDATE server configuration (RFC 2136 receiver).
    ///
    /// When set, Herald starts a DNS UPDATE server on the specified address.
    /// Requires `providers.dynamic` to be configured.
    #[serde(default)]
    pub dns_server: Option<DnsServerConfig>,
}

fn default_listen() -> String {
    "[::]:8443".to_string()
}

fn default_state_dir() -> String {
    "/var/lib/herald".to_string()
}

/// Backend configuration.
///
/// Backends are where DNS records are published. Supports Cloudflare, Technitium, and RFC 2136.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct BackendsConfig {
    /// Multiple Cloudflare backend instances. Each manages a distinct set of zones.
    #[serde(default)]
    pub cloudflare: Vec<CloudflareConfig>,

    /// Multiple Technitium backend instances. Each manages a distinct set of zones.
    #[serde(default)]
    pub technitium: Vec<TechnitiumConfig>,

    /// Multiple RFC 2136 backend instances. Each manages a distinct set of zones.
    #[serde(default)]
    pub rfc2136: Vec<Rfc2136BackendConfig>,
}

/// Cloudflare backend configuration.
///
/// Requires one or more zone names and an API token with `Zone:DNS:Edit` permission
/// scoped to all listed zones.
#[derive(Debug, Deserialize)]
pub(crate) struct CloudflareConfig {
    /// Optional name for logging (defaults to "cloudflare-{index}")
    #[serde(default)]
    pub name: Option<String>,

    /// List of Cloudflare zone names to manage (e.g., `["example.com", "example.org"]`)
    pub zones: Vec<String>,

    /// Path to file containing the Cloudflare API token
    pub token_file: String,
}

/// Technitium backend configuration.
///
/// Requires one or more zone names, the Technitium API base URL, and an API token
/// with permissions to manage DNS records in the specified zones.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TechnitiumConfig {
    /// Optional name for logging (defaults to "technitium-{index}")
    #[serde(default)]
    pub name: Option<String>,

    /// List of Technitium zone names to manage (e.g., `["internal.example.org", "home.local"]`)
    pub zones: Vec<String>,

    /// Technitium DNS Server API base URL (e.g., `"http://ns01.internal.example.com:5380"`)
    pub url: String,

    /// Path to file containing the Technitium API token
    pub token_file: String,
}

/// RFC 2136 backend configuration.
///
/// Uses the DNS UPDATE protocol (RFC 2136) to manage records on any compatible
/// authoritative DNS server (BIND, Knot, `PowerDNS`, etc.).
///
/// Managed records are tracked via a local `SQLite` database rather than a comment
/// field (which RFC 2136 does not provide). Herald only manages records it
/// created; pre-existing records in the zone are invisible to the reconciler.
#[derive(Debug, Deserialize)]
pub(crate) struct Rfc2136BackendConfig {
    /// Optional name for logging (defaults to "rfc2136-{index}")
    #[serde(default)]
    pub name: Option<String>,

    /// List of zone names this backend manages (e.g., `["internal.example.com"]`)
    pub zones: Vec<String>,

    /// Address of the primary (master) nameserver to send DNS UPDATE messages to.
    ///
    /// Format: `"host:port"` (e.g., `"ns1.internal.example.com:53"`).
    pub primary_nameserver: String,

    /// Path to file containing the base64-encoded TSIG secret.
    ///
    /// If omitted, UPDATE messages are sent unsigned. Only use unsigned updates
    /// when the server is configured to allow updates from trusted IP ranges.
    #[serde(default)]
    pub tsig_key_file: Option<String>,

    /// TSIG key name, as configured on the DNS server (e.g., `"herald.example.com."`).
    ///
    /// Required when `tsig_key_file` is set.
    #[serde(default)]
    pub tsig_key_name: Option<String>,
}

/// Provider configuration.
///
/// Providers are sources of desired DNS records. All configured providers
/// contribute records to a unified desired-state set.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ProvidersConfig {
    #[serde(default)]
    pub r#static: Option<StaticProviderConfig>,

    /// Multiple mirror provider instances. Each polls its own source with its
    /// own rules and interval.
    #[serde(default)]
    pub mirror: Vec<MirrorProviderConfig>,

    #[serde(default)]
    pub acme: Option<AcmeProviderConfig>,

    #[serde(default)]
    pub dynamic: Option<DynamicProviderConfig>,
}

/// Configuration for the static provider.
///
/// Static records are defined in the config file and never change at runtime.
#[derive(Debug, Deserialize)]
pub(crate) struct StaticProviderConfig {
    pub records: Vec<StaticRecord>,
}

/// A static DNS record definition.
///
/// The zone is derived from the FQDN by the reconciler using backend zone declarations.
#[derive(Debug, Deserialize)]
pub(crate) struct StaticRecord {
    pub name: String,
    pub r#type: String,
    pub value: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

fn default_ttl() -> u32 {
    300
}

/// Configuration for a single mirror provider instance.
///
/// The mirror provider polls a DNS source (Technitium or raw DNS queries),
/// applies transformation rules, and contributes the mirrored records to the
/// desired state. Multiple mirror instances can be configured, each with its
/// own source, rule set, and polling interval.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MirrorProviderConfig {
    /// Optional name for logging and metrics (defaults to `"mirror[{index}]"`).
    #[serde(default)]
    pub name: Option<String>,
    pub source: MirrorSource,
    pub rules: Vec<MirrorRule>,
    #[serde(default = "default_interval")]
    pub interval: String,
}

fn default_interval() -> String {
    "5m".to_string()
}

/// Mirror source configuration.
///
/// Specifies where to poll records from. Supports:
/// - `technitium`: Technitium DNS Server HTTP API (requires `url` and `token_file`)
/// - `dns`: Direct DNS queries via resolver (optionally specify `subdomains` to query)
/// - `rfc2136`: AXFR zone transfer from any RFC 2136-capable server (requires `nameserver`)
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MirrorSource {
    pub r#type: String,
    /// API URL (required for technitium, unused for dns and rfc2136)
    #[serde(default)]
    pub url: Option<String>,
    /// Zone to query records from
    pub zone: String,
    /// Path to API token file (required for technitium; optional TSIG secret for rfc2136)
    #[serde(default)]
    pub token_file: Option<String>,
    /// Explicit subdomain list to query (optional, for dns type only)
    ///
    /// If empty, only queries the zone apex. If specified, queries each
    /// subdomain in addition to the apex. Example: `["host1", "host2"]`
    /// will query `host1.zone` and `host2.zone`.
    #[serde(default)]
    pub subdomains: Vec<String>,
    /// Nameserver address for AXFR (required for rfc2136, unused for other types).
    ///
    /// Format: `"host:port"` (e.g., `"ns1.internal.example.com:53"`).
    #[serde(default)]
    pub nameserver: Option<String>,
    /// TSIG key name for AXFR authentication (optional, for rfc2136 type only).
    #[serde(default)]
    pub tsig_key_name: Option<String>,
}

/// A mirror transformation rule.
///
/// Rules are applied in order. Each rule matches source records and applies
/// a transformation. Matched records are included in the mirrored set.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MirrorRule {
    pub r#match: MirrorMatch,
    pub transform: MirrorTransform,
}

/// Match criteria for mirror rules.
///
/// All specified fields must match for the rule to apply.
/// If a field is `None`, it matches all records.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MirrorMatch {
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Transformation kind applied to matched records.
///
/// Exactly one variant must be specified via the `type` field in YAML. The
/// chosen variant determines how the source record's name is rewritten before
/// it is contributed to the desired state.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(crate) enum MirrorTransformKind {
    /// Replace the source zone suffix with the given suffix.
    ///
    /// Example: `host.internal.example.org` with source zone
    /// `internal.example.org` and suffix `example.com` becomes
    /// `host.example.com`.
    Suffix { suffix: String },

    /// Replace the full FQDN with the given literal value.
    ///
    /// Useful for one-off mappings that don't fit a suffix rewrite, e.g.
    /// `db-primary.corp.internal → db.example.org`.
    Rename { to: String },

    /// Apply a regex replacement to the source FQDN.
    ///
    /// `pattern` is matched against the full name; `replacement` may
    /// reference capture groups with `$1`, `$2`, etc. The pattern is compiled
    /// once at startup — invalid patterns fail config validation.
    Regex {
        pattern: String,
        replacement: String,
    },
}

/// Transformation to apply to matched records.
///
/// Specifies how to modify the record's name before contributing it to the
/// desired state, and optionally overrides the TTL. The zone is derived from
/// the transformed name by the reconciler using backend zone declarations.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MirrorTransform {
    /// Name-transformation kind. Flattened so `type: suffix, suffix: ...`
    /// lives at the same YAML level as `ttl`.
    #[serde(flatten)]
    pub kind: MirrorTransformKind,

    /// Optional TTL override for the contributed record. If omitted, the
    /// mirror provider falls back to a default TTL of 300 seconds.
    #[serde(default)]
    pub ttl: Option<u32>,
}

/// Configuration for the ACME DNS-01 challenge provider.
///
/// Manages ephemeral TXT records for ACME DNS-01 challenges. Each client
/// has a token and a list of allowed domains.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AcmeProviderConfig {
    /// Per-client token configuration
    #[serde(default)]
    pub clients: HashMap<String, AcmeClientConfig>,
}

/// Per-client ACME configuration.
///
/// Defines which domains a client can manage challenges for. Supports
/// wildcard patterns (`*.example.org` matches all subdomains).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AcmeClientConfig {
    /// Domains this client is allowed to create challenges for
    ///
    /// Supports wildcards: `*.example.org` matches `host.example.org`,
    /// `deep.sub.example.org`, etc.
    pub allowed_domains: Vec<String>,

    /// Per-client rate limit override.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

/// Configuration for the dynamic DNS update provider.
///
/// Allows authenticated clients to create, update, and delete arbitrary DNS
/// records via the API. Each client has scoped permissions by domain and zone.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DynamicProviderConfig {
    /// Per-client configuration
    #[serde(default)]
    pub clients: HashMap<String, DynamicClientConfig>,
}

/// Per-client dynamic DNS configuration.
///
/// Defines which domains and zones a client can manage.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DynamicClientConfig {
    /// Domain patterns this client is allowed to manage (supports `*.example.com`)
    pub allowed_domains: Vec<String>,
    /// Zones this client is allowed to target
    pub allowed_zones: Vec<String>,

    /// Per-client rate limit override.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

/// Configuration for the DNS UPDATE receiver (RFC 2136 server).
///
/// When configured, Herald listens for DNS UPDATE messages on UDP and TCP,
/// validates TSIG authentication, and stores incoming records in the dynamic
/// DNS provider. Requires `providers.dynamic` to be configured.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DnsServerConfig {
    /// Listen address for the DNS UPDATE server (UDP and TCP).
    ///
    /// Defaults to `"[::]:5353"`. Use port 53 only if Herald runs as root or
    /// has `CAP_NET_BIND_SERVICE`.
    #[serde(default = "default_dns_listen")]
    pub listen: String,

    /// TSIG keys accepted by the DNS UPDATE server.
    ///
    /// Each key maps to a dynamic provider client name, inheriting that
    /// client's `allowed_domains` and `allowed_zones` permissions.
    #[serde(default)]
    pub tsig_keys: Vec<TsigKeyConfig>,
}

fn default_dns_listen() -> String {
    "[::]:5353".to_string()
}

/// A TSIG key accepted by the DNS UPDATE receiver.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TsigKeyConfig {
    /// TSIG key name, as used in DNS UPDATE messages (e.g., `"opnsense.example.com."`).
    pub key_name: String,

    /// TSIG algorithm. Currently only `"hmac-sha256"` is supported.
    #[serde(default = "default_tsig_algorithm")]
    pub algorithm: String,

    /// Path to file containing the base64-encoded TSIG secret.
    pub secret_file: String,

    /// Dynamic provider client name this key maps to.
    ///
    /// Must match a key in `providers.dynamic.clients`. The client's
    /// `allowed_domains` and `allowed_zones` control which records this
    /// key is permitted to manage.
    pub client: String,
}

fn default_tsig_algorithm() -> String {
    "hmac-sha256".to_string()
}

/// Per-client or global rate limiting configuration.
///
/// Configures a token-bucket rate limiter. Can be set globally on `Config`
/// (default for all clients) and overridden per-client in `AcmeClientConfig`
/// or `DynamicClientConfig`.
#[derive(Debug, Clone, Copy, Deserialize)]
pub(crate) struct RateLimitConfig {
    /// Maximum sustained requests per second.
    pub requests_per_second: u32,
    /// Maximum burst capacity (requests allowed in a single burst).
    pub burst: u32,
}

/// Reconciler configuration.
///
/// Controls the reconciliation loop behavior: how often it runs and whether
/// to apply changes or just log them (dry-run mode).
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ReconcilerConfig {
    /// Reconciliation interval
    #[serde(default = "default_reconciler_interval")]
    pub interval: String,

    /// If true, log changes but don't apply them
    #[serde(default)]
    pub dry_run: bool,
}

fn default_reconciler_interval() -> String {
    "1m".to_string()
}

// ── Validation ───────────────────────────────────────────────────────────────
//
// Each config type validates its own invariants. `Config::validate()` composes
// them, threading context (e.g., known backend zones) where cross-cutting
// checks are needed.

impl Config {
    /// Validate the configuration for internal consistency.
    ///
    /// Called at startup before initializing any backends or providers.
    /// Delegates to per-type validation methods and checks cross-cutting
    /// constraints (e.g., provider zones must reference backend zones).
    ///
    /// # Errors
    ///
    /// Returns an error describing the first invalid configuration found.
    pub(crate) fn validate(&self) -> Result<()> {
        let backend_zones = self.backends.validate()?;
        self.providers.validate(&backend_zones)?;
        if let Some(ref dns) = self.dns_server {
            dns.validate(&self.providers)?;
        }
        Ok(())
    }
}

impl CloudflareConfig {
    fn validate(&self, index: usize) -> Result<Vec<String>> {
        let desc = self
            .name
            .clone()
            .unwrap_or_else(|| format!("cloudflare[{index}]"));
        if self.zones.is_empty() {
            anyhow::bail!("backend {desc} has no zones configured");
        }
        Ok(self.zones.clone())
    }
}

impl TechnitiumConfig {
    fn validate(&self, index: usize) -> Result<Vec<String>> {
        let desc = self
            .name
            .clone()
            .unwrap_or_else(|| format!("technitium[{index}]"));
        if self.zones.is_empty() {
            anyhow::bail!("backend {desc} has no zones configured");
        }
        Ok(self.zones.clone())
    }
}

impl Rfc2136BackendConfig {
    fn validate(&self, index: usize) -> Result<Vec<String>> {
        let desc = self
            .name
            .clone()
            .unwrap_or_else(|| format!("rfc2136[{index}]"));
        if self.zones.is_empty() {
            anyhow::bail!("backend {desc} has no zones configured");
        }
        if self.tsig_key_file.is_some() != self.tsig_key_name.is_some() {
            anyhow::bail!(
                "backend {desc}: tsig_key_file and tsig_key_name must both be set or both omitted"
            );
        }
        Ok(self.zones.clone())
    }
}

impl BackendsConfig {
    /// Validate all backends and return the set of all configured zone names.
    ///
    /// Checks that each backend has at least one zone and that no zone appears
    /// in more than one backend.
    fn validate(&self) -> Result<std::collections::HashSet<String>> {
        let mut seen: HashMap<String, String> = HashMap::new(); // zone → backend desc

        for (i, cf) in self.cloudflare.iter().enumerate() {
            let desc = cf
                .name
                .clone()
                .unwrap_or_else(|| format!("cloudflare[{i}]"));
            for zone in cf.validate(i)? {
                if let Some(first) = seen.get(&zone) {
                    anyhow::bail!("zone '{zone}' appears in both {first} and {desc}");
                }
                seen.insert(zone, desc.clone());
            }
        }
        for (i, tech) in self.technitium.iter().enumerate() {
            let desc = tech
                .name
                .clone()
                .unwrap_or_else(|| format!("technitium[{i}]"));
            for zone in tech.validate(i)? {
                if let Some(first) = seen.get(&zone) {
                    anyhow::bail!("zone '{zone}' appears in both {first} and {desc}");
                }
                seen.insert(zone, desc.clone());
            }
        }
        for (i, rfc) in self.rfc2136.iter().enumerate() {
            let desc = rfc.name.clone().unwrap_or_else(|| format!("rfc2136[{i}]"));
            for zone in rfc.validate(i)? {
                if let Some(first) = seen.get(&zone) {
                    anyhow::bail!("zone '{zone}' appears in both {first} and {desc}");
                }
                seen.insert(zone, desc.clone());
            }
        }

        Ok(seen.into_keys().collect())
    }
}

impl DynamicProviderConfig {
    /// Validate that all client `allowed_zones` reference zones in some backend.
    fn validate(&self, backend_zones: &std::collections::HashSet<String>) -> Result<()> {
        for (client_name, client_config) in &self.clients {
            for zone in &client_config.allowed_zones {
                if !backend_zones.contains(zone) {
                    anyhow::bail!(
                        "dynamic client '{client_name}' references zone '{zone}' \
                         which is not configured in any backend"
                    );
                }
            }
        }
        Ok(())
    }
}

impl MirrorProviderConfig {
    /// Return the display name for this mirror instance, falling back to an
    /// index-based name when `name` is unset. Keep this in sync with the
    /// convention used by backend configs (`cloudflare[0]`, `technitium[1]`).
    pub(crate) fn display_name(&self, index: usize) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("mirror[{index}]"))
    }

    /// Validate this mirror against startup-time invariants. Returns the
    /// display name so the caller can check for duplicates across instances.
    ///
    /// Checks (in order):
    /// - `source.type` is a known value.
    /// - At least one rule is configured.
    /// - Each rule's TTL (if set) is within a practical operational range
    ///   (1 second to 1 week). Typos like `ttl: 0` or a stray extra zero are
    ///   rejected here rather than producing confusing backend errors later.
    /// - A `rename` transform has a specific (non-wildcard) `match.name`.
    ///   Rename is unconditional per-record, so without a specific name
    ///   filter it would collapse every source record into the same FQDN.
    ///
    /// Regex patterns and `interval` are NOT parsed here — `MirrorProvider::new`
    /// is the single parse site for both. Any parse error still surfaces at
    /// startup (inside `init_providers`, milliseconds after `config.validate()`).
    fn validate(&self, index: usize) -> Result<String> {
        let desc = self.display_name(index);

        match self.source.r#type.as_str() {
            "technitium" | "dns" | "rfc2136" => {}
            other => anyhow::bail!(
                "mirror {desc}: unknown source type {other:?}; expected one of technitium, dns, rfc2136"
            ),
        }

        if self.rules.is_empty() {
            anyhow::bail!("mirror {desc} has no rules configured");
        }

        for (rule_idx, rule) in self.rules.iter().enumerate() {
            if let Some(ttl) = rule.transform.ttl {
                // 1-week cap: higher than any reasonable record TTL, low
                // enough to catch unit-of-measure typos (e.g. ms-as-seconds).
                if ttl == 0 || ttl > MAX_MIRROR_TTL {
                    anyhow::bail!(
                        "mirror {desc} rule[{rule_idx}]: ttl {ttl} is out of range \
                         (must be 1..={MAX_MIRROR_TTL})"
                    );
                }
            }

            if matches!(rule.transform.kind, MirrorTransformKind::Rename { .. }) {
                match &rule.r#match.name {
                    None => anyhow::bail!(
                        "mirror {desc} rule[{rule_idx}]: rename transform requires \
                         match.name — without a specific name, every source record \
                         would collapse into the same FQDN"
                    ),
                    Some(name) if name.contains('*') => anyhow::bail!(
                        "mirror {desc} rule[{rule_idx}]: rename transform requires \
                         a specific match.name; glob pattern {name:?} still collapses \
                         every matching record into the same FQDN"
                    ),
                    Some(_) => {}
                }
            }
        }

        Ok(desc)
    }
}

/// Maximum TTL (in seconds) accepted on a mirror rule — 1 week.
///
/// RFC 2181 §8 permits up to 2^31-1 seconds (~68 years). That's far beyond
/// any operationally sensible DNS TTL and makes unit-of-measure typos
/// invisible. A 1-week ceiling rejects obvious mistakes without restricting
/// realistic deployments.
pub(crate) const MAX_MIRROR_TTL: u32 = 604_800;

impl ProvidersConfig {
    /// Validate providers against the set of known backend zones.
    fn validate(&self, backend_zones: &std::collections::HashSet<String>) -> Result<()> {
        if let Some(ref dynamic) = self.dynamic {
            dynamic.validate(backend_zones)?;
        }

        // Validate each mirror and reject duplicate display names. The check
        // runs over resolved display names (explicit or `mirror[{idx}]`
        // fallback) so an operator can't collide an explicit name against an
        // anonymous mirror's fallback — e.g., naming one entry `mirror[0]`
        // while leaving another unnamed.
        let mut seen_mirror_names: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for (idx, mirror) in self.mirror.iter().enumerate() {
            let desc = mirror.validate(idx)?;
            if !seen_mirror_names.insert(desc.clone()) {
                anyhow::bail!("duplicate mirror name {desc}");
            }
        }

        Ok(())
    }
}

impl DnsServerConfig {
    /// Validate DNS server config against the providers config.
    ///
    /// Requires the dynamic provider to be configured, and all TSIG key
    /// `client` fields must reference existing dynamic provider clients.
    fn validate(&self, providers: &ProvidersConfig) -> Result<()> {
        let Some(ref dynamic) = providers.dynamic else {
            anyhow::bail!(
                "dns_server is configured but providers.dynamic is not — \
                 the DNS UPDATE receiver requires the dynamic provider"
            );
        };

        for key in &self.tsig_keys {
            if !dynamic.clients.contains_key(&key.client) {
                anyhow::bail!(
                    "dns_server TSIG key '{}' maps to client '{}' \
                     which is not defined in providers.dynamic.clients",
                    key.key_name,
                    key.client
                );
            }
        }
        Ok(())
    }
}

/// Load configuration from a YAML file with environment variable overrides.
///
/// Configuration is loaded in layers (later layers override earlier ones):
/// 1. YAML file at `path`
/// 2. Environment variables with `HERALD_` prefix (e.g., `HERALD_LISTEN`)
///
/// Returns an error if the file cannot be read or parsed, or if required
/// fields are missing.
///
/// # Example
///
/// ```no_run
/// # use herald::config::load;
/// let config = load("/etc/herald/config.yaml")?;
/// println!("Listening on {}", config.listen);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub(crate) fn load(path: &str) -> Result<Config> {
    let config: Config = Figment::new()
        .merge(Yaml::file(path))
        .merge(Env::prefixed("HERALD_").split("_"))
        .extract()?;

    tracing::info!("configuration loaded from {path}");
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::Figment;
    use figment::providers::Yaml;

    /// Build a minimal valid Config for testing. Each test overrides
    /// the specific field it wants to invalidate.
    fn valid_config() -> Config {
        Config {
            listen: "[::]:8443".to_string(),
            tls: TlsConfig {
                cert_file: "/tmp/cert.pem".to_string(),
                key_file: "/tmp/key.pem".to_string(),
            },
            backends: BackendsConfig {
                cloudflare: vec![CloudflareConfig {
                    name: Some("cf-test".to_string()),
                    zones: vec!["example.com".to_string()],
                    token_file: "/tmp/token".to_string(),
                }],
                technitium: vec![],
                rfc2136: vec![],
            },
            providers: ProvidersConfig::default(),
            reconciler: ReconcilerConfig::default(),
            telemetry: TelemetryConfig::default(),
            tokens_file: None,
            state_dir: "/tmp/herald".to_string(),
            rate_limit: None,
            dns_server: None,
        }
    }

    // ── Default value tests ───────────────────────────────────────────────────

    #[test]
    fn test_default_listen_is_dual_stack() {
        assert_eq!(default_listen(), "[::]:8443");
    }

    #[test]
    fn test_default_state_dir() {
        assert_eq!(default_state_dir(), "/var/lib/herald");
    }

    #[test]
    fn test_default_reconciler_interval() {
        assert_eq!(default_reconciler_interval(), "1m");
    }

    #[test]
    fn test_default_ttl_is_300() {
        assert_eq!(default_ttl(), 300);
    }

    #[test]
    fn test_default_dns_listen() {
        assert_eq!(default_dns_listen(), "[::]:5353");
    }

    #[test]
    fn test_default_mirror_interval() {
        assert_eq!(default_interval(), "5m");
    }

    #[test]
    fn test_default_tsig_algorithm() {
        assert_eq!(default_tsig_algorithm(), "hmac-sha256");
    }

    // ── YAML parsing tests ────────────────────────────────────────────────────

    fn parse_yaml(yaml: &'static str) -> Config {
        Figment::new()
            .merge(Yaml::string(yaml))
            .extract()
            .expect("valid YAML config")
    }

    #[test]
    fn test_parse_minimal_yaml_applies_defaults() {
        let config = parse_yaml("tls:\n  cert_file: /tmp/cert.pem\n  key_file: /tmp/key.pem\n");
        assert_eq!(config.listen, "[::]:8443");
        assert_eq!(config.state_dir, "/var/lib/herald");
        // reconciler.dry_run defaults to false when reconciler section is absent
        assert!(!config.reconciler.dry_run);
        assert!(config.backends.cloudflare.is_empty());
        assert!(config.providers.dynamic.is_none());
    }

    #[test]
    fn test_parse_custom_listen_address() {
        let config =
            parse_yaml("listen: \"0.0.0.0:9443\"\ntls:\n  cert_file: /c\n  key_file: /k\n");
        assert_eq!(config.listen, "0.0.0.0:9443");
    }

    #[test]
    fn test_parse_static_record_inherits_default_ttl() {
        let config = parse_yaml(
            "tls:\n  cert_file: /c\n  key_file: /k\n\
             providers:\n  static:\n    records:\n\
             \x20\x20\x20\x20\x20\x20- name: www.example.com\n\
             \x20\x20\x20\x20\x20\x20\x20\x20type: A\n\
             \x20\x20\x20\x20\x20\x20\x20\x20value: 1.2.3.4\n",
        );
        let records = &config.providers.r#static.unwrap().records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ttl, 300);
        assert_eq!(records[0].name, "www.example.com");
    }

    #[test]
    fn test_parse_static_record_explicit_ttl() {
        let config = parse_yaml(
            "tls:\n  cert_file: /c\n  key_file: /k\n\
             providers:\n  static:\n    records:\n\
             \x20\x20\x20\x20\x20\x20- name: apex.example.com\n\
             \x20\x20\x20\x20\x20\x20\x20\x20type: A\n\
             \x20\x20\x20\x20\x20\x20\x20\x20value: 1.2.3.4\n\
             \x20\x20\x20\x20\x20\x20\x20\x20ttl: 60\n",
        );
        let records = &config.providers.r#static.unwrap().records;
        assert_eq!(records[0].ttl, 60);
    }

    #[test]
    fn test_parse_reconciler_dry_run() {
        let config = parse_yaml(
            "tls:\n  cert_file: /c\n  key_file: /k\n\
             reconciler:\n  dry_run: true\n  interval: \"30s\"\n",
        );
        assert!(config.reconciler.dry_run);
        assert_eq!(config.reconciler.interval, "30s");
    }

    #[test]
    fn test_parse_rate_limit_config() {
        let config = parse_yaml(
            "tls:\n  cert_file: /c\n  key_file: /k\n\
             rate_limit:\n  requests_per_second: 10\n  burst: 20\n",
        );
        let rl = config.rate_limit.unwrap();
        assert_eq!(rl.requests_per_second, 10);
        assert_eq!(rl.burst, 20);
    }

    #[test]
    fn test_parse_missing_tls_fails() {
        let result: Result<Config, _> = Figment::new()
            .merge(Yaml::string("listen: \"[::]:8443\"\n"))
            .extract();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_tokens_file() {
        let config = parse_yaml(
            "tls:\n  cert_file: /c\n  key_file: /k\n\
             tokens_file: /run/secrets/tokens\n",
        );
        assert_eq!(config.tokens_file.as_deref(), Some("/run/secrets/tokens"));
    }

    // ── Validation tests ──────────────────────────────────────────────────────

    #[test]
    fn test_validate_valid_config_passes() {
        let config = valid_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_zones_rejected() {
        let mut config = valid_config();
        config.backends.cloudflare[0].zones.clear();
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("no zones configured"),
            "expected 'no zones configured', got: {err}"
        );
    }

    #[test]
    fn test_validate_duplicate_zones_rejected() {
        let mut config = valid_config();
        config.backends.technitium.push(TechnitiumConfig {
            name: Some("tech-test".to_string()),
            zones: vec!["example.com".to_string()], // same zone as cloudflare
            url: "http://localhost:5380".to_string(),
            token_file: "/tmp/token".to_string(),
        });
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("example.com"),
            "expected zone name in error, got: {err}"
        );
    }

    #[test]
    fn test_validate_dynamic_allowed_zone_must_exist() {
        let mut config = valid_config();
        config.providers.dynamic = Some(DynamicProviderConfig {
            clients: HashMap::from([(
                "test-client".to_string(),
                DynamicClientConfig {
                    allowed_domains: vec!["*.example.com".to_string()],
                    allowed_zones: vec!["nonexistent.org".to_string()],
                    rate_limit: None,
                },
            )]),
        });
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("nonexistent.org"),
            "expected zone name in error, got: {err}"
        );
    }

    #[test]
    fn test_validate_dns_server_requires_dynamic() {
        let mut config = valid_config();
        config.dns_server = Some(DnsServerConfig {
            listen: "[::]:5353".to_string(),
            tsig_keys: vec![],
        });
        // No dynamic provider
        config.providers.dynamic = None;
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("dynamic"),
            "expected mention of dynamic provider, got: {err}"
        );
    }

    #[test]
    fn test_validate_tsig_key_client_must_exist() {
        let mut config = valid_config();
        config.providers.dynamic = Some(DynamicProviderConfig {
            clients: HashMap::from([(
                "real-client".to_string(),
                DynamicClientConfig {
                    allowed_domains: vec!["*.example.com".to_string()],
                    allowed_zones: vec!["example.com".to_string()],
                    rate_limit: None,
                },
            )]),
        });
        config.dns_server = Some(DnsServerConfig {
            listen: "[::]:5353".to_string(),
            tsig_keys: vec![TsigKeyConfig {
                key_name: "test.example.com".to_string(),
                algorithm: "hmac-sha256".to_string(),
                secret_file: "/tmp/secret".to_string(),
                client: "ghost-client".to_string(), // not in dynamic.clients
            }],
        });
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("ghost-client"),
            "expected client name in error, got: {err}"
        );
    }

    #[test]
    fn test_validate_rfc2136_tsig_partial_rejected() {
        let mut config = valid_config();
        config.backends.cloudflare.clear();
        config.backends.rfc2136.push(Rfc2136BackendConfig {
            name: Some("bind".to_string()),
            zones: vec!["example.com".to_string()],
            primary_nameserver: "ns1.example.com:53".to_string(),
            tsig_key_file: Some("/tmp/key".to_string()),
            tsig_key_name: None, // missing key_name
        });
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("tsig_key_file") && err.contains("tsig_key_name"),
            "expected both tsig fields mentioned, got: {err}"
        );
    }

    // ── Mirror schema (multi-instance, tagged transforms, validation) ────────

    /// Build a minimal valid mirror config used across multi-mirror tests.
    fn mirror_config(name: Option<&str>, rules: Vec<MirrorRule>) -> MirrorProviderConfig {
        MirrorProviderConfig {
            name: name.map(str::to_string),
            source: MirrorSource {
                r#type: "dns".to_string(),
                url: None,
                zone: "internal.example.com".to_string(),
                token_file: None,
                subdomains: vec![],
                nameserver: None,
                tsig_key_name: None,
            },
            rules,
            interval: "5m".to_string(),
        }
    }

    fn suffix_rule(suffix: &str) -> MirrorRule {
        MirrorRule {
            r#match: MirrorMatch {
                r#type: None,
                name: None,
            },
            transform: MirrorTransform {
                kind: MirrorTransformKind::Suffix {
                    suffix: suffix.to_string(),
                },
                ttl: None,
            },
        }
    }

    #[test]
    fn test_parse_mirror_list_form() {
        let yaml = r"
tls:
  cert_file: /tmp/cert.pem
  key_file: /tmp/key.pem
backends:
  cloudflare:
    - name: cf
      zones: [example.com]
      token_file: /tmp/token
providers:
  mirror:
    - name: first
      source:
        type: dns
        zone: internal.example.com
      rules:
        - match: { type: AAAA }
          transform: { type: suffix, suffix: example.com, ttl: 600 }
    - name: second
      source:
        type: dns
        zone: corp.internal
      rules:
        - match: { type: A, name: 'db-primary.corp.internal' }
          transform: { type: rename, to: db.example.org }
        - match: {}
          transform:
            type: regex
            pattern: '^(.+)\.legacy\.corp$'
            replacement: '$1.public.org'
";
        let config: Config = Figment::new().merge(Yaml::string(yaml)).extract().unwrap();

        assert_eq!(config.providers.mirror.len(), 2);
        assert_eq!(config.providers.mirror[0].name.as_deref(), Some("first"));
        assert_eq!(config.providers.mirror[1].name.as_deref(), Some("second"));

        // Mirror 0: suffix transform with explicit TTL override.
        match &config.providers.mirror[0].rules[0].transform.kind {
            MirrorTransformKind::Suffix { suffix } => assert_eq!(suffix, "example.com"),
            other => panic!("expected Suffix variant, got {other:?}"),
        }
        assert_eq!(config.providers.mirror[0].rules[0].transform.ttl, Some(600));

        // Mirror 1: rename and regex transforms parsed into the right variants.
        match &config.providers.mirror[1].rules[0].transform.kind {
            MirrorTransformKind::Rename { to } => assert_eq!(to, "db.example.org"),
            other => panic!("expected Rename variant, got {other:?}"),
        }
        match &config.providers.mirror[1].rules[1].transform.kind {
            MirrorTransformKind::Regex {
                pattern,
                replacement,
            } => {
                assert_eq!(pattern, r"^(.+)\.legacy\.corp$");
                assert_eq!(replacement, "$1.public.org");
            }
            other => panic!("expected Regex variant, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_mirror_old_singular_form_rejected() {
        // Pre-refactor, `mirror:` accepted a single map. Post-refactor, the list
        // form is required — a singular map must fail to parse cleanly so
        // operators see the breaking-change error at startup.
        let yaml = r"
tls:
  cert_file: /tmp/cert.pem
  key_file: /tmp/key.pem
backends:
  cloudflare:
    - name: cf
      zones: [example.com]
      token_file: /tmp/token
providers:
  mirror:
    source:
      type: dns
      zone: internal.example.com
    rules:
      - match: { type: AAAA }
        transform: { type: suffix, suffix: example.com }
";
        let result = Figment::new().merge(Yaml::string(yaml)).extract::<Config>();
        assert!(
            result.is_err(),
            "expected singular mirror map to fail parsing, got: {result:?}"
        );
    }

    #[test]
    fn test_parse_mirror_absent_is_empty_vec() {
        let yaml = r"
tls:
  cert_file: /tmp/cert.pem
  key_file: /tmp/key.pem
backends:
  cloudflare:
    - name: cf
      zones: [example.com]
      token_file: /tmp/token
";
        let config: Config = Figment::new().merge(Yaml::string(yaml)).extract().unwrap();
        assert!(config.providers.mirror.is_empty());
    }

    #[test]
    fn test_validate_mirror_empty_rules_rejected() {
        let mut config = valid_config();
        config.providers.mirror = vec![mirror_config(Some("empty"), vec![])];
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("no rules configured"),
            "expected 'no rules configured' error, got: {err}"
        );
    }

    #[test]
    fn test_validate_mirror_duplicate_names_rejected() {
        let mut config = valid_config();
        config.providers.mirror = vec![
            mirror_config(Some("dup"), vec![suffix_rule("example.com")]),
            mirror_config(Some("dup"), vec![suffix_rule("example.org")]),
        ];
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("duplicate mirror name"),
            "expected duplicate-name error, got: {err}"
        );
    }

    #[test]
    fn test_validate_mirror_anonymous_duplicates_allowed() {
        // Two unnamed mirrors get index-based fallback names (mirror[0],
        // mirror[1]) which are inherently unique, so the duplicate check must
        // not trigger on them.
        let mut config = valid_config();
        config.providers.mirror = vec![
            mirror_config(None, vec![suffix_rule("example.com")]),
            mirror_config(None, vec![suffix_rule("example.org")]),
        ];
        assert!(config.validate().is_ok());
    }

    // Note: interval parsing is no longer validated by `config.validate()`;
    // `MirrorProvider::new` is the single parse site. Syntax errors still
    // surface at startup inside `init_providers`, tested at the provider level.

    #[test]
    fn test_validate_mirror_unknown_source_type_rejected() {
        let mut config = valid_config();
        let mut mc = mirror_config(Some("typo"), vec![suffix_rule("example.com")]);
        mc.source.r#type = "technicium".to_string();
        config.providers.mirror = vec![mc];
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("unknown source type"),
            "expected unknown-source-type error, got: {err}"
        );
    }

    #[test]
    fn test_validate_mirror_ttl_zero_rejected() {
        let mut config = valid_config();
        let rule = MirrorRule {
            r#match: MirrorMatch {
                r#type: Some("A".to_string()),
                name: None,
            },
            transform: MirrorTransform {
                kind: MirrorTransformKind::Suffix {
                    suffix: "example.com".to_string(),
                },
                ttl: Some(0),
            },
        };
        config.providers.mirror = vec![mirror_config(Some("ttl0"), vec![rule])];
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("ttl 0 is out of range"),
            "expected ttl=0 rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_mirror_ttl_above_week_rejected() {
        // Operational cap is 1 week (604800s). Anything higher is almost
        // certainly a typo (e.g., ms-as-seconds) rather than a real ask.
        let mut config = valid_config();
        let rule = MirrorRule {
            r#match: MirrorMatch {
                r#type: Some("A".to_string()),
                name: None,
            },
            transform: MirrorTransform {
                kind: MirrorTransformKind::Suffix {
                    suffix: "example.com".to_string(),
                },
                ttl: Some(MAX_MIRROR_TTL + 1),
            },
        };
        config.providers.mirror = vec![mirror_config(Some("ttl-huge"), vec![rule])];
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("out of range"),
            "expected ttl-too-large rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_mirror_ttl_at_week_accepted() {
        // Exactly one week is still legal — the cap is inclusive.
        let mut config = valid_config();
        let rule = MirrorRule {
            r#match: MirrorMatch {
                r#type: Some("A".to_string()),
                name: None,
            },
            transform: MirrorTransform {
                kind: MirrorTransformKind::Suffix {
                    suffix: "example.com".to_string(),
                },
                ttl: Some(MAX_MIRROR_TTL),
            },
        };
        config.providers.mirror = vec![mirror_config(Some("ttl-week"), vec![rule])];
        assert!(config.validate().is_ok());
    }

    /// Build a rename rule with the given optional match shape, for tests
    /// exercising the rename-match-required invariant.
    fn rename_rule(match_type: Option<&str>, match_name: Option<&str>) -> MirrorRule {
        MirrorRule {
            r#match: MirrorMatch {
                r#type: match_type.map(str::to_string),
                name: match_name.map(str::to_string),
            },
            transform: MirrorTransform {
                kind: MirrorTransformKind::Rename {
                    to: "db.example.com".to_string(),
                },
                ttl: None,
            },
        }
    }

    #[test]
    fn test_validate_mirror_rename_without_match_rejected() {
        // No match fields set at all — unconditional rename would collapse
        // every source record into the same FQDN.
        let mut config = valid_config();
        config.providers.mirror = vec![mirror_config(Some("bare"), vec![rename_rule(None, None)])];
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("rename transform requires match.name"),
            "expected rename-requires-match.name error, got: {err}"
        );
    }

    #[test]
    fn test_validate_mirror_rename_with_type_only_rejected() {
        // `match.type = A` without a specific name still collapses every
        // matching A record in the source zone into the same FQDN. The
        // guardrail must catch this, not just the no-match case.
        let mut config = valid_config();
        config.providers.mirror = vec![mirror_config(
            Some("type-only"),
            vec![rename_rule(Some("A"), None)],
        )];
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("rename transform requires match.name"),
            "expected rename-requires-match.name error, got: {err}"
        );
    }

    #[test]
    fn test_validate_mirror_rename_with_glob_name_rejected() {
        // A glob like `*.internal.corp` also matches multiple records, which
        // the unconditional rename would collapse — just more insidiously,
        // because `match.name` *is* set.
        let mut config = valid_config();
        config.providers.mirror = vec![mirror_config(
            Some("glob"),
            vec![rename_rule(Some("A"), Some("*.internal.corp"))],
        )];
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("glob pattern"),
            "expected glob-pattern-rejection error, got: {err}"
        );
    }

    #[test]
    fn test_validate_mirror_rename_with_specific_name_accepted() {
        // Specific name match is the intended shape — one source record in,
        // one output record out.
        let mut config = valid_config();
        config.providers.mirror = vec![mirror_config(
            Some("specific"),
            vec![rename_rule(Some("A"), Some("db-primary.internal.corp"))],
        )];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_mirror_explicit_name_collides_with_fallback() {
        // An explicit `mirror[0]` on the second entry collides with the
        // first entry's anonymous fallback name.
        let mut config = valid_config();
        config.providers.mirror = vec![
            mirror_config(None, vec![suffix_rule("example.com")]),
            mirror_config(Some("mirror[0]"), vec![suffix_rule("example.org")]),
        ];
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("duplicate mirror name"),
            "expected duplicate-name error for explicit/fallback collision, got: {err}"
        );
    }

    #[test]
    fn test_validate_mirror_three_way_fallback_collision() {
        // Three anonymous mirrors plus an explicit name that collides with
        // the middle entry's fallback. The canonicalized duplicate check
        // must catch it regardless of where in the list the collision sits.
        let mut config = valid_config();
        config.providers.mirror = vec![
            mirror_config(None, vec![suffix_rule("example.com")]), // mirror[0]
            mirror_config(None, vec![suffix_rule("example.org")]), // mirror[1]
            mirror_config(None, vec![suffix_rule("example.net")]), // mirror[2]
            mirror_config(Some("mirror[1]"), vec![suffix_rule("example.test")]),
        ];
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("duplicate mirror name mirror[1]"),
            "expected mirror[1] collision detected, got: {err}"
        );
    }

    #[test]
    fn test_validate_mirror_three_anonymous_mirrors_ok() {
        // Three anonymous mirrors must all validate cleanly — their
        // auto-generated fallback names are distinct by construction.
        let mut config = valid_config();
        config.providers.mirror = vec![
            mirror_config(None, vec![suffix_rule("example.com")]),
            mirror_config(None, vec![suffix_rule("example.org")]),
            mirror_config(None, vec![suffix_rule("example.net")]),
        ];
        assert!(config.validate().is_ok());
    }
}
