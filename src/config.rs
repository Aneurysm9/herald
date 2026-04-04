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
}

fn default_listen() -> String {
    "[::]:8443".to_string()
}

fn default_state_dir() -> String {
    "/var/lib/herald".to_string()
}

/// Backend configuration.
///
/// Backends are where DNS records are published. Supports Cloudflare and Technitium.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct BackendsConfig {
    /// Multiple Cloudflare backend instances. Each manages a distinct set of zones.
    #[serde(default)]
    pub cloudflare: Vec<CloudflareConfig>,

    /// Multiple Technitium backend instances. Each manages a distinct set of zones.
    #[serde(default)]
    pub technitium: Vec<TechnitiumConfig>,
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
/// Specifies where to poll records from. Currently supports:
/// - `technitium`: Technitium DNS Server HTTP API (requires `url` and `token_file`)
/// - `dns`: Direct DNS queries via resolver (optionally specify `subdomains` to query)
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MirrorSource {
    pub r#type: String,
    /// API URL (required for technitium, unused for dns)
    #[serde(default)]
    pub url: Option<String>,
    /// Zone to query records from
    pub zone: String,
    /// Path to API token file (required for technitium, unused for dns)
    #[serde(default)]
    pub token_file: Option<String>,
    /// Explicit subdomain list to query (optional, for dns type only)
    ///
    /// If empty, only queries the zone apex. If specified, queries each
    /// subdomain in addition to the apex. Example: `["host1", "host2"]`
    /// will query `host1.zone` and `host2.zone`.
    #[serde(default)]
    pub subdomains: Vec<String>,
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
