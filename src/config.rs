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

/// Configuration for the ACME DNS-01 challenge provider.
///
/// Manages ephemeral TXT records for ACME DNS-01 challenges. Each client
/// has a token and a list of allowed domains.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AcmeProviderConfig {
    /// Per-client token configuration
    #[serde(default)]
    pub clients: HashMap<String, AcmeClientConfig>,

    /// How long a challenge may live before it is expired and cleaned up.
    ///
    /// Guards against ACME clients that crash mid-renewal and never clear
    /// their challenge. Humantime format (e.g., "48h", "30m").
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl: String,
}

fn default_challenge_ttl() -> String {
    "48h".to_string()
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

/// One specific configuration validation failure.
///
/// Each variant corresponds to one rule in the validators below. The phrasing
/// is preserved verbatim from the previous `anyhow::bail!` calls so that
/// existing tests' substring assertions continue to pass.
#[derive(thiserror::Error, Debug)]
pub(crate) enum ConfigError {
    #[error("backend {desc} has no zones configured")]
    EmptyZones { desc: String },

    #[error("backend {desc}: tsig_key_file and tsig_key_name must both be set or both omitted")]
    Rfc2136TsigPartial { desc: String },

    #[error("zone '{zone}' appears in both {first} and {second}")]
    DuplicateZone {
        zone: String,
        first: String,
        second: String,
    },

    #[error(
        "dynamic client '{client}' references zone '{zone}' \
         which is not configured in any backend"
    )]
    DynamicZoneNotConfigured { client: String, zone: String },

    #[error(
        "dns_server is configured but providers.dynamic is not — \
         the DNS UPDATE receiver requires the dynamic provider"
    )]
    DnsServerWithoutDynamic,

    #[error(
        "dns_server TSIG key '{key_name}' maps to client '{client}' \
         which is not defined in providers.dynamic.clients"
    )]
    TsigClientUnknown { key_name: String, client: String },
}

/// A collection of configuration validation errors, reported together at
/// startup. Implements `std::error::Error` so it can be propagated through
/// `?` into `anyhow::Result` at the call site in `main`.
#[derive(Debug, Default)]
pub(crate) struct ConfigErrors(Vec<ConfigError>);

impl ConfigErrors {
    fn push(&mut self, err: ConfigError) {
        self.0.push(err);
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    /// Consume this accumulator: return `Ok(())` if no errors were pushed,
    /// otherwise `Err(self)`.
    fn into_result(self) -> Result<(), ConfigErrors> {
        if self.is_empty() { Ok(()) } else { Err(self) }
    }
}

impl std::fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.len();
        let plural = if n == 1 { "error" } else { "errors" };
        writeln!(f, "configuration validation failed ({n} {plural}):")?;
        for err in &self.0 {
            writeln!(f, "  - {err}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // The contained errors are independent peers, not a causation chain.
        // Returning None avoids misrepresenting the relationship to formatters
        // like anyhow's `{:#}` that walk the source chain.
        None
    }
}

impl Config {
    /// Validate the configuration for internal consistency.
    ///
    /// Called at startup before initializing any backends or providers.
    /// Accumulates every validation issue across all layers (backends,
    /// providers, `dns_server`) into a single `ConfigErrors` report. Returns
    /// `Ok(())` if the configuration is valid, otherwise an error describing
    /// every issue found in one message.
    ///
    /// # Errors
    ///
    /// Returns a `ConfigErrors` listing every invalid setting. The single
    /// caller (`main.rs`) propagates this via `?` into `anyhow::Result`,
    /// which renders the multi-line `Display` to the operator's logs.
    pub(crate) fn validate(&self) -> Result<(), ConfigErrors> {
        let mut errors = ConfigErrors::default();
        let backend_zones = self.backends.validate(&mut errors);
        self.providers.validate(&backend_zones, &mut errors);
        if let Some(ref dns) = self.dns_server {
            dns.validate(&self.providers, &mut errors);
        }
        errors.into_result()
    }
}

impl CloudflareConfig {
    fn validate(&self, index: usize, errors: &mut ConfigErrors) -> Vec<String> {
        let desc = self
            .name
            .clone()
            .unwrap_or_else(|| format!("cloudflare[{index}]"));
        if self.zones.is_empty() {
            errors.push(ConfigError::EmptyZones { desc });
        }
        self.zones.clone()
    }
}

impl TechnitiumConfig {
    fn validate(&self, index: usize, errors: &mut ConfigErrors) -> Vec<String> {
        let desc = self
            .name
            .clone()
            .unwrap_or_else(|| format!("technitium[{index}]"));
        if self.zones.is_empty() {
            errors.push(ConfigError::EmptyZones { desc });
        }
        self.zones.clone()
    }
}

impl Rfc2136BackendConfig {
    fn validate(&self, index: usize, errors: &mut ConfigErrors) -> Vec<String> {
        let desc = self
            .name
            .clone()
            .unwrap_or_else(|| format!("rfc2136[{index}]"));
        if self.zones.is_empty() {
            errors.push(ConfigError::EmptyZones { desc: desc.clone() });
        }
        if self.tsig_key_file.is_some() != self.tsig_key_name.is_some() {
            errors.push(ConfigError::Rfc2136TsigPartial { desc });
        }
        self.zones.clone()
    }
}

impl BackendsConfig {
    /// Validate all backends and return the set of all configured zone names.
    ///
    /// Pushes errors into `errors` for any per-backend issues (empty zones,
    /// rfc2136 tsig partial) and any cross-backend duplicates. Always returns
    /// the partial set of zones successfully declared so that downstream
    /// provider validation can run against it without phantom "zone not
    /// configured" cascades caused by an unrelated upstream failure.
    fn validate(&self, errors: &mut ConfigErrors) -> std::collections::HashSet<String> {
        let mut seen: HashMap<String, String> = HashMap::new(); // zone → first backend desc
        let mut all_zones: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (i, cf) in self.cloudflare.iter().enumerate() {
            let desc = cf
                .name
                .clone()
                .unwrap_or_else(|| format!("cloudflare[{i}]"));
            for zone in cf.validate(i, errors) {
                if let Some(first) = seen.get(&zone) {
                    errors.push(ConfigError::DuplicateZone {
                        zone: zone.clone(),
                        first: first.clone(),
                        second: desc.clone(),
                    });
                } else {
                    seen.insert(zone.clone(), desc.clone());
                    all_zones.insert(zone);
                }
            }
        }
        for (i, tech) in self.technitium.iter().enumerate() {
            let desc = tech
                .name
                .clone()
                .unwrap_or_else(|| format!("technitium[{i}]"));
            for zone in tech.validate(i, errors) {
                if let Some(first) = seen.get(&zone) {
                    errors.push(ConfigError::DuplicateZone {
                        zone: zone.clone(),
                        first: first.clone(),
                        second: desc.clone(),
                    });
                } else {
                    seen.insert(zone.clone(), desc.clone());
                    all_zones.insert(zone);
                }
            }
        }
        for (i, rfc) in self.rfc2136.iter().enumerate() {
            let desc = rfc.name.clone().unwrap_or_else(|| format!("rfc2136[{i}]"));
            for zone in rfc.validate(i, errors) {
                if let Some(first) = seen.get(&zone) {
                    errors.push(ConfigError::DuplicateZone {
                        zone: zone.clone(),
                        first: first.clone(),
                        second: desc.clone(),
                    });
                } else {
                    seen.insert(zone.clone(), desc.clone());
                    all_zones.insert(zone);
                }
            }
        }

        all_zones
    }
}

impl DynamicProviderConfig {
    /// Validate that all client `allowed_zones` reference zones in some backend.
    fn validate(
        &self,
        backend_zones: &std::collections::HashSet<String>,
        errors: &mut ConfigErrors,
    ) {
        for (client_name, client_config) in &self.clients {
            for zone in &client_config.allowed_zones {
                if !backend_zones.contains(zone) {
                    errors.push(ConfigError::DynamicZoneNotConfigured {
                        client: client_name.clone(),
                        zone: zone.clone(),
                    });
                }
            }
        }
    }
}

impl ProvidersConfig {
    /// Validate providers against the set of known backend zones.
    fn validate(
        &self,
        backend_zones: &std::collections::HashSet<String>,
        errors: &mut ConfigErrors,
    ) {
        if let Some(ref dynamic) = self.dynamic {
            dynamic.validate(backend_zones, errors);
        }
    }
}

impl DnsServerConfig {
    /// Validate DNS server config against the providers config.
    ///
    /// Requires the dynamic provider to be configured, and all TSIG key
    /// `client` fields must reference existing dynamic provider clients.
    /// If `providers.dynamic` is not configured, the per-key check is
    /// skipped to avoid cascading "client not in dynamic.clients" errors
    /// that would otherwise be reported once per configured TSIG key.
    fn validate(&self, providers: &ProvidersConfig, errors: &mut ConfigErrors) {
        let Some(ref dynamic) = providers.dynamic else {
            errors.push(ConfigError::DnsServerWithoutDynamic);
            return;
        };

        for key in &self.tsig_keys {
            if !dynamic.clients.contains_key(&key.client) {
                errors.push(ConfigError::TsigClientUnknown {
                    key_name: key.key_name.clone(),
                    client: key.client.clone(),
                });
            }
        }
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
    fn test_default_challenge_ttl_is_48h() {
        assert_eq!(default_challenge_ttl(), "48h");
    }

    #[test]
    fn test_acme_challenge_ttl_from_yaml() {
        let config = parse_yaml(
            "tls:\n  cert_file: /c\n  key_file: /k\n\
             providers:\n  acme:\n    challenge_ttl: \"30m\"\n    clients:\n\
             \x20\x20\x20\x20\x20\x20web:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20allowed_domains: [\"example.com\"]\n",
        );
        let acme = config.providers.acme.unwrap();
        assert_eq!(acme.challenge_ttl, "30m");
    }

    #[test]
    fn test_acme_challenge_ttl_defaults_when_omitted() {
        let config = parse_yaml(
            "tls:\n  cert_file: /c\n  key_file: /k\n\
             providers:\n  acme:\n    clients:\n\
             \x20\x20\x20\x20\x20\x20web:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20allowed_domains: [\"example.com\"]\n",
        );
        let acme = config.providers.acme.unwrap();
        assert_eq!(acme.challenge_ttl, "48h");
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

    #[test]
    fn test_validate_duplicate_zones_reports_all() {
        // Three backends all claim 'example.com'. The first claim wins
        // (cloudflare[0] is the original valid_config() backend). The
        // technitium and rfc2136 entries each produce a DuplicateZone
        // error pointing at cloudflare[0] as the first occurrence.
        let mut config = valid_config();
        config.backends.technitium.push(TechnitiumConfig {
            name: Some("tech-a".to_string()),
            zones: vec!["example.com".to_string()],
            url: "http://localhost:5380".to_string(),
            token_file: "/tmp/t".to_string(),
        });
        config.backends.rfc2136.push(Rfc2136BackendConfig {
            name: Some("bind-a".to_string()),
            zones: vec!["example.com".to_string()],
            primary_nameserver: "ns1.example.com:53".to_string(),
            tsig_key_file: None,
            tsig_key_name: None,
        });

        let errors = config.validate().unwrap_err();
        assert_eq!(
            errors.len(),
            2,
            "expected 2 duplicate-zone errors (technitium and rfc2136 each \
             collide with cloudflare[0]), got {} errors: {errors}",
            errors.len()
        );

        let msg = errors.to_string();
        assert!(
            msg.contains("(2 errors)"),
            "expected '(2 errors)' header, got: {msg}"
        );
        assert!(
            msg.contains("'example.com' appears in both"),
            "expected duplicate-zone error wording, got: {msg}"
        );
        assert!(
            msg.contains("tech-a"),
            "expected mention of technitium backend, got: {msg}"
        );
        assert!(
            msg.contains("bind-a"),
            "expected mention of rfc2136 backend, got: {msg}"
        );
    }

    #[test]
    fn test_validate_dynamic_reports_all_unknown_zones_per_client() {
        // A single dynamic client references three zones, none of which
        // exist in any backend. Today's bail-on-first behavior would
        // report only one; the accumulator reports all three.
        let mut config = valid_config();
        config.providers.dynamic = Some(DynamicProviderConfig {
            clients: HashMap::from([(
                "noisy".to_string(),
                DynamicClientConfig {
                    allowed_domains: vec!["*.example.com".to_string()],
                    allowed_zones: vec![
                        "absent1.example.org".to_string(),
                        "absent2.example.org".to_string(),
                        "absent3.example.org".to_string(),
                    ],
                    rate_limit: None,
                },
            )]),
        });

        let errors = config.validate().unwrap_err();
        assert_eq!(
            errors.len(),
            3,
            "expected 3 unknown-zone errors, got {}: {errors}",
            errors.len()
        );

        let msg = errors.to_string();
        assert!(
            msg.contains("(3 errors)"),
            "expected '(3 errors)' header, got: {msg}"
        );
        for missing in [
            "absent1.example.org",
            "absent2.example.org",
            "absent3.example.org",
        ] {
            assert!(
                msg.contains(missing),
                "expected report to mention {missing}, got: {msg}"
            );
        }
    }

    #[test]
    fn test_validate_dns_server_missing_dynamic_does_not_cascade_tsig_errors() {
        // Setup:
        //   - dns_server has TWO TSIG keys
        //   - providers.dynamic is absent
        //
        // Without the cascade guard, every TSIG key would fail with
        // "client X not in dynamic.clients" because there are no
        // dynamic clients to compare against. The correct behavior is
        // exactly ONE error: DnsServerWithoutDynamic.
        let mut config = valid_config();
        config.providers.dynamic = None;
        config.dns_server = Some(DnsServerConfig {
            listen: "[::]:5353".to_string(),
            tsig_keys: vec![
                TsigKeyConfig {
                    key_name: "k1.example.com".to_string(),
                    algorithm: "hmac-sha256".to_string(),
                    secret_file: "/tmp/s1".to_string(),
                    client: "would-be-client-1".to_string(),
                },
                TsigKeyConfig {
                    key_name: "k2.example.com".to_string(),
                    algorithm: "hmac-sha256".to_string(),
                    secret_file: "/tmp/s2".to_string(),
                    client: "would-be-client-2".to_string(),
                },
            ],
        });

        let errors = config.validate().unwrap_err();
        assert_eq!(
            errors.len(),
            1,
            "expected exactly 1 error (DnsServerWithoutDynamic, no per-key \
             cascade), got {} errors: {errors}",
            errors.len()
        );

        let msg = errors.to_string();
        assert!(
            msg.contains("dns_server is configured but providers.dynamic is not"),
            "expected DnsServerWithoutDynamic message, got: {msg}"
        );
        assert!(
            !msg.contains("would-be-client-1") && !msg.contains("would-be-client-2"),
            "should NOT mention any TSIG client (no cascade), got: {msg}"
        );
    }

    #[test]
    fn test_validate_partial_zone_set_prevents_cascade() {
        // Setup:
        //   - cloudflare[0]: empty zones (will fail with EmptyZones)
        //   - cloudflare[1]: zones = ["example.com"] (passes)
        //   - dynamic provider client references "example.com"
        //
        // Without partial-zone-set semantics, BackendsConfig would either
        // bail on cloudflare[0] (and the dynamic check wouldn't run at all)
        // or yield an empty zone set (and the dynamic check would phantom-
        // fail with "zone example.com not configured"). The correct
        // accumulator behavior is: exactly ONE error, and it is the
        // EmptyZones error from cloudflare[0].
        let mut config = valid_config();
        config.backends.cloudflare[0].zones.clear(); // becomes failing backend
        config.backends.cloudflare.push(CloudflareConfig {
            name: Some("cf-second".to_string()),
            zones: vec!["example.com".to_string()],
            token_file: "/tmp/t".to_string(),
        });
        config.providers.dynamic = Some(DynamicProviderConfig {
            clients: HashMap::from([(
                "test-client".to_string(),
                DynamicClientConfig {
                    allowed_domains: vec!["*.example.com".to_string()],
                    allowed_zones: vec!["example.com".to_string()],
                    rate_limit: None,
                },
            )]),
        });

        let errors = config.validate().unwrap_err();
        assert_eq!(
            errors.len(),
            1,
            "expected exactly 1 error (no cascade from upstream EmptyZones), \
             got {} errors: {errors}",
            errors.len()
        );

        let msg = errors.to_string();
        assert!(
            msg.contains("no zones configured"),
            "expected the EmptyZones error, got: {msg}"
        );
        assert!(
            !msg.contains("references zone 'example.com'"),
            "should NOT contain phantom 'zone example.com not configured' \
             cascade error, but found it in: {msg}"
        );
    }

    #[test]
    fn test_validate_rfc2136_reports_both_empty_zones_and_partial_tsig() {
        // A single rfc2136 backend with TWO violations — empty zones AND
        // partial tsig config. Today's pre-refactor code bailed on the first;
        // the accumulator must report both.
        let mut config = valid_config();
        config.backends.cloudflare.clear();
        config.backends.rfc2136.push(Rfc2136BackendConfig {
            name: Some("bind".to_string()),
            zones: vec![], // first violation: empty zones
            primary_nameserver: "ns1.example.com:53".to_string(),
            tsig_key_file: Some("/tmp/key".to_string()),
            tsig_key_name: None, // second violation: tsig partial
        });

        let errors = config.validate().unwrap_err();
        assert_eq!(
            errors.len(),
            2,
            "expected 2 errors from one rfc2136 backend with two issues, got: {errors}",
        );

        let msg = errors.to_string();
        assert!(
            msg.contains("(2 errors)"),
            "expected '(2 errors)' header, got: {msg}"
        );
        assert!(
            msg.contains("backend bind has no zones configured"),
            "expected empty-zones bullet, got: {msg}"
        );
        assert!(
            msg.contains("tsig_key_file") && msg.contains("tsig_key_name"),
            "expected tsig partial bullet mentioning both fields, got: {msg}"
        );
    }

    #[test]
    fn test_validate_accumulates_multiple_errors() {
        // Two distinct violations: cloudflare[0] has empty zones AND a duplicate
        // zone 'example.com' is declared by cloudflare[1] and a technitium backend.
        let mut config = valid_config();
        config.backends.cloudflare[0].zones.clear(); // first violation
        config.backends.cloudflare.push(CloudflareConfig {
            name: Some("cf-second".to_string()),
            zones: vec!["example.com".to_string()],
            token_file: "/tmp/t".to_string(),
        });
        config.backends.technitium.push(TechnitiumConfig {
            name: Some("tech-dup".to_string()),
            zones: vec!["example.com".to_string()], // duplicates cf-second
            url: "http://localhost:5380".to_string(),
            token_file: "/tmp/t".to_string(),
        });

        let errors = config.validate().unwrap_err();
        assert_eq!(
            errors.len(),
            2,
            "expected 2 accumulated errors, got {}: {errors}",
            errors.len()
        );

        let msg = errors.to_string();
        assert!(
            msg.contains("(2 errors)"),
            "expected '(2 errors)' header, got: {msg}"
        );
        assert!(
            msg.contains("cf-test") || msg.contains("cloudflare[0]"),
            "expected mention of empty-zones backend, got: {msg}"
        );
        assert!(
            msg.contains("'example.com' appears in both"),
            "expected duplicate-zone message, got: {msg}"
        );
    }

    // ── ConfigErrors Display tests ───────────────────────────────────────────

    #[test]
    fn test_config_errors_display_singular() {
        let mut errors = ConfigErrors::default();
        errors.push(ConfigError::EmptyZones {
            desc: "cloudflare[0]".to_string(),
        });
        let s = errors.to_string();
        assert!(
            s.contains("(1 error)"),
            "expected singular header '(1 error)', got: {s}"
        );
        assert!(
            s.contains("backend cloudflare[0] has no zones configured"),
            "expected error body, got: {s}"
        );
        assert!(
            s.starts_with("configuration validation failed"),
            "expected header line, got: {s}"
        );
    }

    #[test]
    fn test_config_errors_display_plural_with_indented_bullets() {
        let mut errors = ConfigErrors::default();
        errors.push(ConfigError::EmptyZones {
            desc: "cloudflare[0]".to_string(),
        });
        errors.push(ConfigError::DuplicateZone {
            zone: "example.com".to_string(),
            first: "cf-a".to_string(),
            second: "cf-b".to_string(),
        });
        let s = errors.to_string();
        assert!(
            s.contains("(2 errors)"),
            "expected plural header '(2 errors)', got: {s}"
        );
        assert!(
            s.contains("\n  - backend cloudflare[0] has no zones configured"),
            "expected indented bullet for first error, got: {s}"
        );
        assert!(
            s.contains("\n  - zone 'example.com' appears in both cf-a and cf-b"),
            "expected indented bullet for second error, got: {s}"
        );
    }

    #[test]
    fn test_config_errors_into_result_empty_is_ok() {
        let errors = ConfigErrors::default();
        assert!(errors.into_result().is_ok());
    }

    #[test]
    fn test_config_errors_into_result_nonempty_is_err() {
        let mut errors = ConfigErrors::default();
        errors.push(ConfigError::DnsServerWithoutDynamic);
        let result = errors.into_result();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    #[test]
    fn test_config_error_all_variants_render() {
        // Smoke test: every variant must have a non-empty Display rendering.
        // Also serves to construct each variant at least once so subsequent
        // tasks adding pushers don't change the dead_code surface.
        let cases: Vec<ConfigError> = vec![
            ConfigError::EmptyZones {
                desc: "cloudflare[0]".to_string(),
            },
            ConfigError::Rfc2136TsigPartial {
                desc: "rfc2136[0]".to_string(),
            },
            ConfigError::DuplicateZone {
                zone: "example.com".to_string(),
                first: "a".to_string(),
                second: "b".to_string(),
            },
            ConfigError::DynamicZoneNotConfigured {
                client: "client".to_string(),
                zone: "example.com".to_string(),
            },
            ConfigError::DnsServerWithoutDynamic,
            ConfigError::TsigClientUnknown {
                key_name: "k".to_string(),
                client: "c".to_string(),
            },
        ];
        for case in cases {
            assert!(
                !case.to_string().is_empty(),
                "variant {case:?} rendered empty"
            );
        }
    }
}
