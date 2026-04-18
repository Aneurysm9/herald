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
    pub mirror: Option<MirrorProviderConfig>,

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

/// Configuration for the mirror provider.
///
/// The mirror provider polls a DNS source (Technitium or raw DNS queries),
/// applies transformation rules, and contributes the mirrored records to the
/// desired state.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MirrorProviderConfig {
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

/// Transformation to apply to matched records.
///
/// Specifies how to modify the record's name before contributing it to
/// the desired state. The zone is derived from the transformed name by the
/// reconciler using backend zone declarations.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MirrorTransform {
    /// Replace the source zone suffix with this suffix
    ///
    /// Example: `host.internal.example.org` with source zone `internal.example.org`
    /// and suffix `example.com` becomes `host.example.com`
    pub suffix: String,
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

impl ProvidersConfig {
    /// Validate providers against the set of known backend zones.
    fn validate(&self, backend_zones: &std::collections::HashSet<String>) -> Result<()> {
        if let Some(ref dynamic) = self.dynamic {
            dynamic.validate(backend_zones)?;
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
            dns_server: None,
        }
    }

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
}
