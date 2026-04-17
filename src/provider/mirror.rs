use super::{DesiredRecord, Named, Provider, RecordValue};
use crate::backend::technitium_util::{
    TechnitiumResponse, extract_rdata as extract_technitium_rdata,
};
use crate::config::MirrorProviderConfig;
use crate::telemetry::Metrics;
use crate::tsig::{self, TSIG_FUDGE};
use anyhow::{Context, Result};
use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::xfer::DnsMultiplexer;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::{Name, RecordType, TSigner};
use hickory_resolver::TokioResolver;
use opentelemetry::KeyValue;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Provider that polls a DNS source and mirrors selected records
/// with name transformations.
pub(crate) struct MirrorProvider {
    config: MirrorProviderConfig,
    /// Cached records from the last poll
    cached_records: Arc<RwLock<Vec<DesiredRecord>>>,
    /// Reusable HTTP client for Technitium API requests
    client: reqwest::Client,
    /// Pre-loaded API token for Technitium authentication
    technitium_token: Option<String>,
    /// TSIG signer for RFC 2136 (AXFR) authentication
    tsig_signer: Option<TSigner>,
    /// Parsed nameserver address for RFC 2136 AXFR
    rfc2136_nameserver: Option<SocketAddr>,
    /// DNS resolver for direct DNS queries
    resolver: TokioResolver,
    metrics: Metrics,
}

impl MirrorProvider {
    pub(crate) async fn new(config: MirrorProviderConfig, metrics: Metrics) -> Result<Self> {
        // Validate configuration based on source type and prepare type-specific state.
        let mut technitium_token: Option<String> = None;
        let mut tsig_signer: Option<TSigner> = None;
        let mut rfc2136_nameserver: Option<SocketAddr> = None;

        match config.source.r#type.as_str() {
            "technitium" => {
                if config.source.url.is_none() {
                    anyhow::bail!("mirror source type 'technitium' requires 'url' field");
                }
                if config.source.token_file.is_none() {
                    anyhow::bail!("mirror source type 'technitium' requires 'token_file' field");
                }
                if let Some(ref path) = config.source.token_file {
                    let token = tokio::fs::read_to_string(path)
                        .await
                        .with_context(|| format!("reading mirror token file: {path}"))?;
                    technitium_token = Some(token.trim().to_string());
                }
            }
            "dns" => {
                // DNS type doesn't require url or token_file
                if config.source.url.is_some() || config.source.token_file.is_some() {
                    tracing::warn!(
                        "mirror source type 'dns' does not use 'url' or 'token_file' fields"
                    );
                }
            }
            "rfc2136" => {
                let ns_str = config
                    .source
                    .nameserver
                    .as_deref()
                    .context("mirror source type 'rfc2136' requires 'nameserver' field")?;

                // Add default port 53 if omitted.
                let addr_str = if ns_str.contains(':') {
                    ns_str.to_string()
                } else {
                    format!("{ns_str}:53")
                };
                rfc2136_nameserver =
                    Some(addr_str.parse().with_context(|| {
                        format!("parsing rfc2136 nameserver address: {addr_str}")
                    })?);

                if let (Some(path), Some(key_name)) =
                    (&config.source.token_file, &config.source.tsig_key_name)
                {
                    let signer = tsig::load_tsigner_from_file(
                        key_name,
                        path,
                        TsigAlgorithm::HmacSha256,
                        TSIG_FUDGE,
                    )
                    .await?;
                    tracing::info!(key_name = %key_name, "mirror TSIG key loaded");
                    tsig_signer = Some(signer);
                } else if config.source.token_file.is_some()
                    || config.source.tsig_key_name.is_some()
                {
                    anyhow::bail!(
                        "mirror rfc2136 source: both 'token_file' and 'tsig_key_name' are required for TSIG authentication"
                    );
                }
            }
            other => {
                anyhow::bail!("unknown mirror source type: {other}");
            }
        }

        let client = reqwest::Client::new();

        // Initialize DNS resolver from system configuration
        let resolver = TokioResolver::builder_tokio()
            .context("initializing DNS resolver from system configuration")?
            .build()?;

        Ok(Self {
            config,
            cached_records: Arc::new(RwLock::new(Vec::new())),
            client,
            technitium_token,
            tsig_signer,
            rfc2136_nameserver,
            resolver,
            metrics,
        })
    }

    /// Poll the source DNS server and update cached records.
    ///
    /// This method:
    /// 1. Fetches all records from the configured source (Technitium or DNS)
    /// 2. Applies transformation rules (match + transform)
    /// 3. Updates the internal cache with the resulting records
    ///
    /// Records mirror polling metrics (`mirror_polls`, `mirror_poll_duration`,
    /// `mirror_records`).
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the response cannot be parsed,
    /// or the source type is unknown.
    pub(crate) async fn poll(&self) -> Result<()> {
        let start = Instant::now();

        let result = self.poll_inner().await;

        let elapsed = start.elapsed().as_secs_f64();
        let status = if result.is_ok() { "success" } else { "error" };
        self.metrics
            .mirror_polls
            .add(1, &[KeyValue::new("status", status)]);
        self.metrics.mirror_poll_duration.record(elapsed, &[]);

        result
    }

    async fn poll_inner(&self) -> Result<()> {
        let source_records = match self.config.source.r#type.as_str() {
            "technitium" => self.poll_technitium().await?,
            "dns" => self.poll_dns().await?,
            "rfc2136" => self.poll_rfc2136().await?,
            other => anyhow::bail!("unknown mirror source type: {other}"),
        };

        let source_count = source_records.len();
        let transformed = self.apply_rules(source_records);

        tracing::info!(
            source_type = %self.config.source.r#type,
            source_zone = %self.config.source.zone,
            source_count,
            transformed_count = transformed.len(),
            "mirror poll complete"
        );

        self.metrics
            .mirror_records
            .record(transformed.len() as u64, &[]);

        let mut cache = self.cached_records.write().await;
        *cache = transformed;

        Ok(())
    }

    /// Poll records from a Technitium DNS Server.
    ///
    /// Calls the Technitium HTTP API `/api/zones/records/get` endpoint with
    /// the configured token. Parses the JSON response and extracts record
    /// data from the polymorphic `rData` field.
    ///
    /// Records with unsupported types or missing fields are skipped with
    /// a debug log message.
    async fn poll_technitium(&self) -> Result<Vec<SourceRecord>> {
        let token = self
            .technitium_token
            .as_deref()
            .context("technitium source requires a token_file")?;

        let zone = &self.config.source.zone;
        let url = self
            .config
            .source
            .url
            .as_ref()
            .context("technitium source requires url")?;
        let url = format!("{url}/api/zones/records/get");

        tracing::debug!(url = %url, zone = %zone, "querying technitium API");

        let resp = self
            .client
            .get(&url)
            .query(&[("token", token), ("domain", zone), ("zone", zone)])
            .send()
            .await
            .context("technitium API request failed")?;

        let status_code = resp.status();
        tracing::debug!(status = %status_code, "received technitium response");

        let resp = resp
            .error_for_status()
            .context("technitium API returned error status")?;

        // Parse as generic JSON first to handle error responses gracefully
        let body: serde_json::Value = resp
            .json()
            .await
            .context("parsing technitium API response as JSON")?;

        // Check status field
        let status = body
            .get("status")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("technitium response missing 'status' field"))?;

        if status != "ok" {
            let error_msg = body
                .get("errorMessage")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown error");
            anyhow::bail!("technitium API error: {error_msg}");
        }

        // Parse the full response structure
        let body: TechnitiumResponse =
            serde_json::from_value(body).context("parsing technitium API success response")?;

        let mut records = Vec::new();
        for rec in body.response.records {
            if let Some(value) = extract_technitium_rdata(&rec.r#type, &rec.r_data) {
                records.push(SourceRecord {
                    name: rec.name,
                    record_type: rec.r#type,
                    value,
                });
            } else {
                tracing::debug!(
                    name = %rec.name,
                    record_type = %rec.r#type,
                    "skipping record with unsupported type or missing rData"
                );
            }
        }

        tracing::debug!(count = records.len(), zone = %zone, "fetched records from technitium");
        Ok(records)
    }

    /// Poll records via DNS queries.
    ///
    /// Queries standard record types (A, AAAA, CNAME, TXT, MX) for the
    /// configured zone and any specified subdomains. Returns records that
    /// can be filtered by transformation rules.
    ///
    /// This approach works with any DNS server (authoritative or recursive)
    /// without requiring zone transfer permissions or API access.
    ///
    /// # Limitations
    ///
    /// - Cannot discover all records in a zone automatically
    /// - Only queries the zone apex and explicitly configured subdomains
    /// - Use `subdomains` config field to specify additional names to query
    async fn poll_dns(&self) -> Result<Vec<SourceRecord>> {
        use hickory_resolver::proto::rr::RecordType;

        let zone = &self.config.source.zone;
        let mut records = Vec::new();

        // Query standard record types that Herald supports
        let query_types = [
            RecordType::A,
            RecordType::AAAA,
            RecordType::CNAME,
            RecordType::TXT,
            RecordType::MX,
        ];

        // Query zone apex for all record types
        for record_type in query_types {
            match self.resolver.lookup(zone.as_str(), record_type).await {
                Ok(lookup) => {
                    for record in lookup.answers() {
                        if let Some(value) = extract_dns_rdata(record) {
                            records.push(SourceRecord {
                                name: record.name.to_utf8(),
                                record_type: record.record_type().to_string(),
                                value,
                            });
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        zone = %zone,
                        record_type = ?record_type,
                        error = %e,
                        "DNS query returned no records or failed"
                    );
                    // Continue with other types - not all types may exist
                }
            }
        }

        // Query configured subdomains
        for subdomain in &self.config.source.subdomains {
            let fqdn = format!("{subdomain}.{zone}");
            tracing::debug!(fqdn = %fqdn, "querying subdomain");

            for record_type in query_types {
                match self.resolver.lookup(fqdn.as_str(), record_type).await {
                    Ok(lookup) => {
                        for record in lookup.answers() {
                            if let Some(value) = extract_dns_rdata(record) {
                                records.push(SourceRecord {
                                    name: record.name.to_utf8(),
                                    record_type: record.record_type().to_string(),
                                    value,
                                });
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            fqdn = %fqdn,
                            record_type = ?record_type,
                            error = %e,
                            "DNS query returned no records or failed"
                        );
                        // Continue with other types
                    }
                }
            }
        }

        tracing::debug!(count = records.len(), zone = %zone, "fetched records via DNS");
        Ok(records)
    }

    /// Poll records via AXFR zone transfer from an RFC 2136-compatible authoritative server.
    ///
    /// Connects over TCP, sends an AXFR query (optionally signed with TSIG), and reads
    /// response messages until the second SOA record marks end-of-transfer.
    /// SOA records are excluded from the returned set.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails, the zone transfer is rejected,
    /// or the response is malformed.
    async fn poll_rfc2136(&self) -> Result<Vec<SourceRecord>> {
        use futures_util::StreamExt;

        let nameserver = self
            .rfc2136_nameserver
            .context("rfc2136 nameserver not initialized")?;
        let zone = &self.config.source.zone;
        let zone_name = Name::from_ascii(zone)
            .with_context(|| format!("invalid zone name for AXFR: {zone}"))?;

        let provider = TokioRuntimeProvider::default();
        let (connect_future, handle) = TcpClientStream::new(
            nameserver,
            None,
            Some(std::time::Duration::from_secs(30)),
            provider,
        );
        let stream = connect_future
            .await
            .with_context(|| format!("connecting to nameserver {nameserver} for AXFR"))?;

        let multiplexer =
            DnsMultiplexer::new(stream, handle).with_timeout(std::time::Duration::from_secs(30));

        let multiplexer = if let Some(ref signer) = self.tsig_signer {
            multiplexer.with_signer(signer.clone())
        } else {
            multiplexer
        };

        let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(multiplexer);
        tokio::spawn(bg);

        let mut xfr = client.zone_transfer(zone_name, None);

        let mut records: Vec<SourceRecord> = Vec::new();
        let mut soa_count = 0usize;

        while let Some(response) = xfr.next().await {
            let response = response.with_context(|| format!("AXFR response for {zone}"))?;

            for record in &response.answers {
                if record.record_type() == RecordType::SOA {
                    soa_count += 1;
                    if soa_count >= 2 {
                        break;
                    }
                    continue;
                }

                let type_name = record.record_type().to_string();
                match RecordValue::try_from(&record.data) {
                    Ok(value) => {
                        records.push(SourceRecord {
                            name: record.name.to_utf8().trim_end_matches('.').to_string(),
                            record_type: type_name,
                            value: value.value_str().clone(),
                        });
                    }
                    Err(_) => {
                        tracing::debug!(
                            name = %record.name,
                            rtype = %record.record_type(),
                            "skipping AXFR record with unsupported RDATA"
                        );
                    }
                }
            }

            if soa_count >= 2 {
                break;
            }
        }

        tracing::debug!(count = records.len(), zone = %zone, "fetched records via AXFR");
        Ok(records)
    }

    /// Apply transformation rules to source records.
    ///
    /// For each source record, checks if it matches any rule's criteria (type,
    /// name pattern). If it matches, applies the transformation (e.g., suffix
    /// replacement) and adds the result to the output.
    ///
    /// A single source record can match multiple rules and produce multiple
    /// output records.
    fn apply_rules(&self, source_records: Vec<SourceRecord>) -> Vec<DesiredRecord> {
        let mut result = Vec::new();

        for record in source_records {
            for rule in &self.config.rules {
                // Check type match
                if let Some(ref type_match) = rule.r#match.r#type
                    && record.record_type != *type_match
                {
                    continue;
                }

                // Check name match (glob-style)
                if let Some(ref name_match) = rule.r#match.name
                    && !glob_match(name_match, &record.name)
                {
                    continue;
                }

                // Apply transformation
                if let Some(transformed) = transform_name(
                    &record.name,
                    &self.config.source.zone,
                    &rule.transform.suffix,
                ) {
                    match RecordValue::parse(&record.record_type, &record.value) {
                        Ok(value) => {
                            result.push(DesiredRecord {
                                name: transformed,
                                value,
                                ttl: 300,
                            });
                        }
                        Err(e) => {
                            tracing::debug!(
                                name = %record.name,
                                record_type = %record.record_type,
                                error = %e,
                                "skipping record with unparseable value"
                            );
                        }
                    }
                }
            }
        }

        result
    }
}

impl Named for MirrorProvider {
    fn name(&self) -> &str {
        "mirror"
    }
}

impl Provider for MirrorProvider {
    fn records(&self) -> Pin<Box<dyn Future<Output = Result<Vec<DesiredRecord>>> + Send + '_>> {
        Box::pin(async move {
            let cache = self.cached_records.read().await;
            Ok(cache.clone())
        })
    }
}

/// Internal representation of a DNS record from the mirror source.
///
/// Simplified intermediate format before transformation rules are applied.
#[derive(Debug)]
struct SourceRecord {
    name: String,
    record_type: String,
    value: String,
}

/// Transform a DNS name by replacing its source suffix with a new suffix.
///
/// # Examples
///
/// ```text
/// transform_name("host.internal.example.org", "internal.example.org", "example.com")
/// => Some("host.example.com")
///
/// transform_name("internal.example.org", "internal.example.org", "example.com")
/// => Some("example.com")
///
/// transform_name("other.example.org", "internal.example.org", "example.com")
/// => None (doesn't match suffix)
/// ```
fn transform_name(name: &str, source_suffix: &str, new_suffix: &str) -> Option<String> {
    let stripped = name.strip_suffix(source_suffix)?;
    let stripped = stripped.strip_suffix('.').unwrap_or(stripped);
    if stripped.is_empty() {
        Some(new_suffix.to_string())
    } else {
        Some(format!("{stripped}.{new_suffix}"))
    }
}

/// Extract value from `hickory_resolver` DNS record.
///
/// Converts the DNS record data (`RData`) into a string value that Herald
/// can use in DNS record definitions. Returns `None` for unsupported record
/// types.
fn extract_dns_rdata(record: &hickory_resolver::proto::rr::Record) -> Option<String> {
    use hickory_resolver::proto::rr::RData;

    match &record.data {
        RData::A(addr) => Some(addr.to_string()),
        RData::AAAA(addr) => Some(addr.to_string()),
        RData::CNAME(cname) => Some(cname.to_utf8()),
        RData::TXT(txt) => Some(
            txt.txt_data
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .collect::<String>(),
        ),
        RData::MX(mx) => Some(mx.exchange.to_utf8()),
        _ => None,
    }
}

/// Simple glob pattern matching.
///
/// Supports limited glob syntax:
/// - `*.example.org` matches `host.example.org`, `deep.sub.example.org`, etc.
/// - Exact string match otherwise
///
/// Does NOT match the apex: `*.example.org` does not match `example.org`.
fn glob_match(pattern: &str, name: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        name.ends_with(suffix) && name.len() > suffix.len() + 1
    } else {
        pattern == name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_name() {
        assert_eq!(
            transform_name(
                "host.internal.example.com",
                "internal.example.com",
                "example.org"
            ),
            Some("host.example.org".to_string())
        );
        assert_eq!(
            transform_name(
                "a.b.internal.example.com",
                "internal.example.com",
                "example.org"
            ),
            Some("a.b.example.org".to_string())
        );
        assert_eq!(
            transform_name(
                "internal.example.com",
                "internal.example.com",
                "example.org"
            ),
            Some("example.org".to_string())
        );
        assert_eq!(
            transform_name("other.example.com", "internal.example.com", "example.org"),
            None
        );
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match(
            "*.internal.example.com",
            "host.internal.example.com"
        ));
        assert!(glob_match(
            "*.internal.example.com",
            "a.b.internal.example.com"
        ));
        assert!(!glob_match(
            "*.internal.example.com",
            "internal.example.com"
        ));
        assert!(glob_match("host.example.com", "host.example.com"));
        assert!(!glob_match("host.example.com", "other.example.com"));
    }
}
