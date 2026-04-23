use super::technitium_util::{TechnitiumRecord, TechnitiumResponse, extract_rdata};
use super::{Backend, Change, ExistingRecord};
use crate::config::TechnitiumConfig;
use crate::provider::{EnrichedRecord, Named, RecordValue};
use crate::telemetry::Metrics;
use anyhow::{Context, Result};
use opentelemetry::KeyValue;
use reqwest::Client;
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

const MANAGED_COMMENT: &str = "managed-by: herald";

/// Technitium DNS Server backend implementation.
///
/// Manages DNS records at a Technitium DNS Server via the HTTP API. All records
/// created or updated by Herald are tagged with the comment `managed-by: herald`
/// to distinguish them from manually-created records.
///
/// The backend never modifies or deletes records without this tag, ensuring
/// safe coexistence with manual changes.
///
/// # Technitium API Differences
///
/// Unlike Cloudflare, Technitium:
/// - Does not have unique record IDs — records are identified by (name, type, value)
/// - Does not have a dedicated update endpoint — updates use delete + create
/// - Requires explicit record data fields based on type (ipAddress, cname, text, etc.)
pub(crate) struct TechnitiumBackend {
    name: String,
    client: Client,
    api_base: String,
    zones: Vec<String>,
    token: String,
    metrics: Metrics,
}

impl TechnitiumBackend {
    /// Creates a new Technitium backend.
    ///
    /// Loads the API token from the file specified in `config.token_file`.
    /// The zones list is stored for routing decisions by the reconciler.
    ///
    /// # Errors
    ///
    /// Returns an error if the token file cannot be read.
    pub async fn new(config: TechnitiumConfig, index: usize, metrics: Metrics) -> Result<Self> {
        let token = tokio::fs::read_to_string(&config.token_file)
            .await
            .with_context(|| format!("reading technitium token file: {}", config.token_file))?
            .trim()
            .to_string();

        let name = config.name.unwrap_or_else(|| format!("technitium-{index}"));

        tracing::info!(
            name = %name,
            zones = ?config.zones,
            url = %config.url,
            "Technitium backend initialized"
        );

        Ok(Self {
            name,
            client: Client::new(),
            api_base: config.url,
            zones: config.zones,
            token,
            metrics,
        })
    }

    #[cfg(test)]
    fn with_base_url(name: String, api_base: String, zones: Vec<String>, token: String) -> Self {
        Self {
            name,
            client: Client::new(),
            api_base,
            zones,
            token,
            metrics: Metrics::noop(),
        }
    }

    /// Apply a change to the Technitium API.
    ///
    /// Dispatches to the appropriate method (POST for create/delete).
    /// All created records are tagged with the `managed-by: herald` comment.
    async fn apply_change_inner(&self, change: &Change) -> Result<()> {
        match change {
            Change::Create(record) => self.create_record(record).await,
            Change::Update { old, new, .. } => self.update_record(old, new).await,
            Change::Delete(existing) => self.delete_record(existing).await,
        }
    }

    /// Create a new DNS record via the Technitium API.
    ///
    /// Makes a POST request to `/api/zones/records/add` with form-encoded parameters.
    /// Always includes `comments=managed-by: herald` to mark the record as Herald-managed.
    async fn create_record(&self, record: &EnrichedRecord) -> Result<()> {
        let url = format!("{}/api/zones/records/add", self.api_base);

        // Build form parameters
        let ttl_string = record.ttl.to_string();
        let type_str = record.value.type_str();
        let mut params = vec![
            ("token", self.token.as_str()),
            ("domain", record.name.as_str()),
            ("zone", record.zone.as_str()),
            ("type", type_str),
            ("ttl", ttl_string.as_str()),
            ("comments", MANAGED_COMMENT),
            ("overwrite", "false"),
        ];

        // Add type-specific parameters via pattern matching on RecordValue
        let value_string;
        let priority_string;
        match &record.value {
            RecordValue::A(addr) => {
                value_string = addr.to_string();
                params.push(("ipAddress", &value_string));
            }
            RecordValue::AAAA(addr) => {
                value_string = addr.to_string();
                params.push(("ipAddress", &value_string));
            }
            RecordValue::CNAME(name) => {
                params.push(("cname", name));
            }
            RecordValue::TXT(text) => {
                params.push(("text", text));
            }
            RecordValue::MX { priority, exchange } => {
                priority_string = priority.to_string();
                params.push(("preference", &priority_string));
                params.push(("exchange", exchange));
            }
            RecordValue::NS(name) => {
                params.push(("nsDomainName", name));
            }
            other => anyhow::bail!(
                "unsupported record type for Technitium: {}",
                other.type_str()
            ),
        }

        let resp = self
            .client
            .post(&url)
            .form(&params)
            .send()
            .await
            .context("technitium API request failed")?;

        let body: serde_json::Value = resp.json().await.context("parsing technitium response")?;
        let status = body
            .get("status")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("technitium response missing 'status' field"))?;

        if status != "ok" {
            let error_msg = body
                .get("errorMessage")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown error");
            anyhow::bail!("technitium create failed: {error_msg}");
        }

        tracing::info!(
            backend = %self.name,
            name = %record.name,
            record_type = %record.value.type_str(),
            "created DNS record"
        );

        Ok(())
    }

    /// Update a DNS record (implemented as delete + create).
    ///
    /// Technitium does not have a dedicated update endpoint, so we delete
    /// the old record and create a new one. This is safe because we only
    /// update managed records.
    async fn update_record(&self, old: &EnrichedRecord, new: &EnrichedRecord) -> Result<()> {
        let existing = ExistingRecord {
            id: String::new(),
            record: old.clone(),
            managed: true,
        };

        self.delete_record(&existing).await?;
        self.create_record(new).await?;

        tracing::info!(
            backend = %self.name,
            name = %new.name,
            record_type = %new.value.type_str(),
            "updated DNS record (delete + create)"
        );

        Ok(())
    }

    /// Delete a DNS record via the Technitium API.
    ///
    /// Makes a POST request to `/api/zones/records/delete` with parameters
    /// identifying the exact record to delete.
    async fn delete_record(&self, existing: &ExistingRecord) -> Result<()> {
        let url = format!("{}/api/zones/records/delete", self.api_base);

        let type_str = existing.record.value.type_str();
        let mut params = vec![
            ("token", self.token.as_str()),
            ("domain", existing.record.name.as_str()),
            ("zone", existing.record.zone.as_str()),
            ("type", type_str),
        ];

        // Add type-specific parameters to identify the exact record
        let value_string;
        let priority_string;
        match &existing.record.value {
            RecordValue::A(addr) => {
                value_string = addr.to_string();
                params.push(("ipAddress", &value_string));
            }
            RecordValue::AAAA(addr) => {
                value_string = addr.to_string();
                params.push(("ipAddress", &value_string));
            }
            RecordValue::CNAME(name) => {
                params.push(("cname", name));
            }
            RecordValue::TXT(text) => {
                params.push(("text", text));
            }
            RecordValue::MX { priority, exchange } => {
                priority_string = priority.to_string();
                params.push(("preference", &priority_string));
                params.push(("exchange", exchange));
            }
            RecordValue::NS(name) => {
                params.push(("nsDomainName", name));
            }
            _ => {
                // For other types, try to delete by name and type only
            }
        }

        let resp = self
            .client
            .post(&url)
            .form(&params)
            .send()
            .await
            .context("technitium API request failed")?;

        let body: serde_json::Value = resp.json().await.context("parsing technitium response")?;
        let status = body
            .get("status")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("technitium response missing 'status' field"))?;

        if status != "ok" {
            let error_msg = body
                .get("errorMessage")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown error");
            anyhow::bail!("technitium delete failed: {error_msg}");
        }

        tracing::info!(
            backend = %self.name,
            name = %existing.record.name,
            record_type = %existing.record.value.type_str(),
            "deleted DNS record"
        );

        Ok(())
    }
}

impl Named for TechnitiumBackend {
    fn name(&self) -> &str {
        &self.name
    }
}

impl Backend for TechnitiumBackend {
    fn zones(&self) -> Vec<String> {
        self.zones.clone()
    }

    fn get_records(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ExistingRecord>>> + Send + '_>> {
        Box::pin(self.get_records_inner())
    }

    fn apply_change<'a>(
        &'a self,
        change: &'a Change,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.apply_change_with_metrics(change))
    }
}

impl TechnitiumRecord {
    /// Convert this wire-format Technitium record into an [`ExistingRecord`]
    /// scoped to `zone`. Returns `None` (with a debug log) for unsupported
    /// types or unparseable values — these are intentional skips rather
    /// than errors, so the reconciler quietly drops them and moves on.
    fn into_existing(self, zone: &str) -> Option<ExistingRecord> {
        let managed = self
            .comments
            .as_ref()
            .is_some_and(|c| c.contains(MANAGED_COMMENT));

        let Some(raw_value) = extract_rdata(&self.r#type, &self.r_data) else {
            tracing::debug!(
                name = %self.name,
                record_type = %self.r#type,
                "skipping record with unsupported type or missing rData"
            );
            return None;
        };

        match RecordValue::parse(&self.r#type, &raw_value) {
            Ok(value) => {
                let id = format!("{}.{}.{raw_value}", self.name, self.r#type);
                Some(ExistingRecord {
                    id,
                    record: EnrichedRecord {
                        zone: zone.to_string(),
                        name: self.name,
                        value,
                        ttl: self.ttl,
                    },
                    managed,
                })
            }
            Err(e) => {
                tracing::debug!(
                    name = %self.name,
                    record_type = %self.r#type,
                    error = %e,
                    "skipping Technitium record with unparseable value"
                );
                None
            }
        }
    }
}

impl TechnitiumBackend {
    async fn get_records_inner(&self) -> Result<Vec<ExistingRecord>> {
        let start = Instant::now();
        let mut all_records = Vec::new();

        let result: Result<()> = async {
            for zone in &self.zones {
                let url = format!("{}/api/zones/records/get", self.api_base);

                tracing::debug!(
                    backend = %self.name,
                    zone = %zone,
                    "fetching records from technitium"
                );

                let resp = self
                    .client
                    .get(&url)
                    .query(&[
                        ("token", self.token.as_str()),
                        ("domain", zone.as_str()),
                        ("zone", zone.as_str()),
                        ("listZone", "true"),
                    ])
                    .send()
                    .await
                    .context("technitium API request failed")?;

                let body: serde_json::Value = resp
                    .json()
                    .await
                    .context("parsing technitium API response")?;

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

                let body: TechnitiumResponse = serde_json::from_value(body)
                    .context("parsing technitium API success response")?;

                for rec in body.response.records {
                    if let Some(record) = rec.into_existing(zone) {
                        all_records.push(record);
                    }
                }
            }
            Ok(())
        }
        .await;

        let elapsed = start.elapsed().as_secs_f64();
        let status = if result.is_ok() { "success" } else { "error" };
        self.metrics.backend_api_calls.add(
            1,
            &[
                KeyValue::new("operation", "get_records"),
                KeyValue::new("status", status),
            ],
        );
        self.metrics
            .backend_api_duration
            .record(elapsed, &[KeyValue::new("operation", "get_records")]);

        result?;

        tracing::info!(
            backend = %self.name,
            count = all_records.len(),
            "fetched records from technitium"
        );

        Ok(all_records)
    }

    async fn apply_change_with_metrics(&self, change: &Change) -> Result<()> {
        let start = Instant::now();
        let operation = match change {
            Change::Create(_) => "create",
            Change::Update { .. } => "update",
            Change::Delete(_) => "delete",
        };

        let result = self.apply_change_inner(change).await;

        let elapsed = start.elapsed().as_secs_f64();
        let status = if result.is_ok() { "success" } else { "error" };
        self.metrics.backend_api_calls.add(
            1,
            &[
                KeyValue::new("operation", operation),
                KeyValue::new("status", status),
            ],
        );
        self.metrics
            .backend_api_duration
            .record(elapsed, &[KeyValue::new("operation", operation)]);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_backend(server: &MockServer) -> TechnitiumBackend {
        TechnitiumBackend::with_base_url(
            "test-technitium".to_string(),
            server.uri(),
            vec!["test.local".to_string()],
            "test-token".to_string(),
        )
    }

    fn technitium_records_response(records: &serde_json::Value) -> serde_json::Value {
        json!({
            "status": "ok",
            "response": {
                "records": records
            }
        })
    }

    fn technitium_success_response() -> serde_json::Value {
        json!({
            "status": "ok",
            "response": {}
        })
    }

    fn technitium_error_response(msg: &str) -> serde_json::Value {
        json!({
            "status": "error",
            "errorMessage": msg
        })
    }

    #[tokio::test]
    async fn test_get_records_single_zone() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("GET"))
            .and(path("/api/zones/records/get"))
            .and(query_param("token", "test-token"))
            .and(query_param("zone", "test.local"))
            .and(query_param("listZone", "true"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(technitium_records_response(&json!([
                    {
                        "name": "host.test.local",
                        "type": "A",
                        "ttl": 300,
                        "rData": {"ipAddress": "10.0.0.1"},
                        "comments": "managed-by: herald"
                    }
                ]))),
            )
            .expect(1)
            .mount(&server)
            .await;

        let records = backend.get_records().await.unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record.name, "host.test.local");
        assert_eq!(
            records[0].record.value,
            RecordValue::A("10.0.0.1".parse().unwrap())
        );
        assert_eq!(records[0].record.ttl, 300);
        assert!(records[0].managed);
    }

    #[tokio::test]
    async fn test_get_records_unmanaged() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("GET"))
            .and(path("/api/zones/records/get"))
            .and(query_param("listZone", "true"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(technitium_records_response(&json!([
                    {
                        "name": "manual.test.local",
                        "type": "CNAME",
                        "ttl": 600,
                        "rData": {"cname": "target.test.local"},
                        "comments": null
                    }
                ]))),
            )
            .mount(&server)
            .await;

        let records = backend.get_records().await.unwrap();

        assert_eq!(records.len(), 1);
        assert!(!records[0].managed);
    }

    #[tokio::test]
    async fn test_get_records_returns_subdomain_records() {
        // Regression: Technitium returns records at deeper subdomain depths
        // only when listZone=true is passed. Without it, the reconciler sees
        // an empty actual state for subdomain records and plans spurious CREATEs
        // that fail with "record already exists".
        let server = MockServer::start().await;
        let backend = TechnitiumBackend::with_base_url(
            "test-technitium".to_string(),
            server.uri(),
            vec!["internal.example.com".to_string()],
            "test-token".to_string(),
        );

        Mock::given(method("GET"))
            .and(path("/api/zones/records/get"))
            .and(query_param("domain", "internal.example.com"))
            .and(query_param("zone", "internal.example.com"))
            .and(query_param("listZone", "true"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(technitium_records_response(&json!([
                    {
                        "name": "host1.subnet1.internal.example.com",
                        "type": "A",
                        "ttl": 300,
                        "rData": {"ipAddress": "192.0.2.10"},
                        "comments": "managed-by: herald"
                    },
                    {
                        "name": "host2.subnet2.internal.example.com",
                        "type": "AAAA",
                        "ttl": 300,
                        "rData": {"ipAddress": "2001:db8::1"},
                        "comments": "managed-by: herald"
                    }
                ]))),
            )
            .expect(1)
            .mount(&server)
            .await;

        let records = backend.get_records().await.unwrap();

        assert_eq!(records.len(), 2);

        let host1 = records
            .iter()
            .find(|r| r.record.name == "host1.subnet1.internal.example.com")
            .expect("subnet1-depth subdomain record should be returned");
        assert_eq!(host1.record.zone, "internal.example.com");
        assert_eq!(
            host1.record.value,
            RecordValue::A("192.0.2.10".parse().unwrap())
        );
        assert!(host1.managed);

        let host2 = records
            .iter()
            .find(|r| r.record.name == "host2.subnet2.internal.example.com")
            .expect("subnet2-depth subdomain record should be returned");
        assert_eq!(host2.record.zone, "internal.example.com");
        assert!(host2.managed);
    }

    #[tokio::test]
    async fn test_get_records_api_error() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("GET"))
            .and(path("/api/zones/records/get"))
            .and(query_param("listZone", "true"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(technitium_error_response("Access denied")),
            )
            .mount(&server)
            .await;

        let result = backend.get_records().await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Access denied"),
            "expected error message, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_apply_create_a_record() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("POST"))
            .and(path("/api/zones/records/add"))
            .and(body_string_contains("token=test-token"))
            .and(body_string_contains("domain=new.test.local"))
            .and(body_string_contains("zone=test.local"))
            .and(body_string_contains("type=A"))
            .and(body_string_contains("ipAddress=192.0.2.1"))
            .and(body_string_contains("comments=managed-by%3A+herald"))
            .respond_with(ResponseTemplate::new(200).set_body_json(technitium_success_response()))
            .expect(1)
            .mount(&server)
            .await;

        let change = Change::Create(EnrichedRecord {
            zone: "test.local".to_string(),
            name: "new.test.local".to_string(),
            value: RecordValue::A("192.0.2.1".parse().unwrap()),
            ttl: 300,
        });

        backend.apply_change(&change).await.unwrap();
    }

    #[tokio::test]
    async fn test_apply_create_mx_record() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("POST"))
            .and(path("/api/zones/records/add"))
            .and(body_string_contains("type=MX"))
            .and(body_string_contains("preference=10"))
            .and(body_string_contains("exchange=mail.test.local"))
            .respond_with(ResponseTemplate::new(200).set_body_json(technitium_success_response()))
            .expect(1)
            .mount(&server)
            .await;

        let change = Change::Create(EnrichedRecord {
            zone: "test.local".to_string(),
            name: "test.local".to_string(),
            value: RecordValue::MX {
                priority: 10,
                exchange: "mail.test.local".to_string(),
            },
            ttl: 300,
        });

        backend.apply_change(&change).await.unwrap();
    }

    #[tokio::test]
    async fn test_apply_delete() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("POST"))
            .and(path("/api/zones/records/delete"))
            .and(body_string_contains("token=test-token"))
            .and(body_string_contains("domain=old.test.local"))
            .and(body_string_contains("type=A"))
            .and(body_string_contains("ipAddress=10.0.0.1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(technitium_success_response()))
            .expect(1)
            .mount(&server)
            .await;

        let change = Change::Delete(ExistingRecord {
            id: "old.test.local.A.10.0.0.1".to_string(),
            record: EnrichedRecord {
                zone: "test.local".to_string(),
                name: "old.test.local".to_string(),
                value: RecordValue::A("10.0.0.1".parse().unwrap()),
                ttl: 300,
            },
            managed: true,
        });

        backend.apply_change(&change).await.unwrap();
    }

    #[tokio::test]
    async fn test_apply_update() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        // Update is delete + create, so we need to mock both
        Mock::given(method("POST"))
            .and(path("/api/zones/records/delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(technitium_success_response()))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/zones/records/add"))
            .respond_with(ResponseTemplate::new(200).set_body_json(technitium_success_response()))
            .expect(1)
            .mount(&server)
            .await;

        let change = Change::Update {
            id: "host.test.local.A.10.0.0.1".to_string(),
            old: EnrichedRecord {
                zone: "test.local".to_string(),
                name: "host.test.local".to_string(),
                value: RecordValue::A("10.0.0.1".parse().unwrap()),
                ttl: 300,
            },
            new: EnrichedRecord {
                zone: "test.local".to_string(),
                name: "host.test.local".to_string(),
                value: RecordValue::A("10.0.0.2".parse().unwrap()),
                ttl: 300,
            },
        };

        backend.apply_change(&change).await.unwrap();
    }

    #[tokio::test]
    async fn test_apply_create_api_error() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("POST"))
            .and(path("/api/zones/records/add"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(technitium_error_response("Invalid IP address")),
            )
            .mount(&server)
            .await;

        let change = Change::Create(EnrichedRecord {
            zone: "test.local".to_string(),
            name: "bad.test.local".to_string(),
            value: RecordValue::A("192.0.2.1".parse().unwrap()),
            ttl: 300,
        });

        let result = backend.apply_change(&change).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid IP address"),
            "expected error message, got: {err_msg}"
        );
    }
}
