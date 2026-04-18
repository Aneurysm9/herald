use super::{Backend, Change, ExistingRecord};
use crate::config::CloudflareConfig;
use crate::provider::{EnrichedRecord, Named, RecordValue};
use crate::telemetry::Metrics;
use anyhow::{Context, Result};
use opentelemetry::KeyValue;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const MANAGED_COMMENT: &str = "managed-by: herald";

/// Cloudflare backend implementation.
///
/// Manages DNS records at Cloudflare via the v4 HTTP API. All records created
/// or updated by Herald are tagged with the comment `managed-by: herald` to
/// distinguish them from manually-created records.
///
/// Supports multiple zones — each zone is resolved to its Cloudflare zone ID
/// at startup.
///
/// The backend never modifies or deletes records without this tag, ensuring
/// safe coexistence with manual changes.
pub(crate) struct CloudflareBackend {
    name: String,
    client: Client,
    api_base: String,
    /// Maps zone name → Cloudflare zone ID
    zone_ids: HashMap<String, String>,
    token: String,
    metrics: Metrics,
}

impl CloudflareBackend {
    /// Creates a new Cloudflare backend.
    ///
    /// Loads the API token from the file specified in `config.token_file`,
    /// then looks up the zone ID for each zone in `config.zones`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The token file cannot be read
    /// - Any zone lookup fails (zone not found, API error, network error)
    /// - The API token lacks permission to access any zone
    pub async fn new(config: &CloudflareConfig, index: usize, metrics: Metrics) -> Result<Self> {
        let token = tokio::fs::read_to_string(&config.token_file)
            .await
            .context("reading Cloudflare token file")?
            .trim()
            .to_string();

        let name = config
            .name
            .clone()
            .unwrap_or_else(|| format!("cloudflare-{index}"));

        let client = Client::new();
        let api_base = CF_API_BASE.to_string();

        // Look up zone IDs for all configured zones
        let mut zone_ids = HashMap::new();
        for zone_name in &config.zones {
            let zone_id = Self::lookup_zone_id(&client, &token, &api_base, zone_name).await?;
            tracing::info!(zone = %zone_name, zone_id = %zone_id, "resolved Cloudflare zone");
            zone_ids.insert(zone_name.clone(), zone_id);
        }

        tracing::info!(
            name = %name,
            zones = config.zones.len(),
            "Cloudflare backend initialized"
        );

        Ok(Self {
            name,
            client,
            api_base,
            zone_ids,
            token,
            metrics,
        })
    }

    #[cfg(test)]
    fn with_base_url(api_base: String, zone_ids: HashMap<String, String>, token: String) -> Self {
        Self {
            name: "cloudflare-test".to_string(),
            client: Client::new(),
            api_base,
            zone_ids,
            token,
            metrics: Metrics::noop(),
        }
    }

    /// Look up the zone ID for a given zone name.
    ///
    /// Queries the Cloudflare `/zones` endpoint with a name filter. Returns
    /// the ID of the first matching zone.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the zone is not found, or
    /// the API returns an error response.
    async fn lookup_zone_id(
        client: &Client,
        token: &str,
        api_base: &str,
        zone_name: &str,
    ) -> Result<String> {
        let resp: CfListResponse<CfZone> = client
            .get(format!("{api_base}/zones"))
            .bearer_auth(token)
            .query(&[("name", zone_name)])
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            anyhow::bail!("Cloudflare API error looking up zone: {:?}", resp.errors);
        }

        resp.result
            .first()
            .map(|z| z.id.clone())
            .ok_or_else(|| anyhow::anyhow!("zone {zone_name} not found"))
    }

    /// Constructs the DNS records API URL for a specific zone.
    ///
    /// Returns `{api_base}/zones/{zone_id}/dns_records`.
    ///
    /// # Errors
    ///
    /// Returns an error if the zone name is not in the configured zone set.
    fn records_url_for_zone(&self, zone_name: &str) -> Result<String> {
        let zone_id = self
            .zone_ids
            .get(zone_name)
            .ok_or_else(|| anyhow::anyhow!("zone {zone_name} is not configured"))?;
        Ok(format!("{}/zones/{zone_id}/dns_records", self.api_base))
    }

    /// Fetch all existing records from Cloudflare.
    ///
    /// Paginates through all records in all configured zones. Records with
    /// unparseable types/values are skipped with a debug log.
    async fn get_records_inner(&self) -> Result<Vec<ExistingRecord>> {
        let start = Instant::now();
        let mut all_records = Vec::new();

        let result: Result<()> = async {
            for (zone_name, zone_id) in &self.zone_ids {
                let base_url = format!("{}/zones/{zone_id}/dns_records", self.api_base);
                let mut page = 1u32;

                loop {
                    let resp: CfListResponse<CfDnsRecord> = self
                        .client
                        .get(&base_url)
                        .bearer_auth(&self.token)
                        .query(&[("page", page.to_string()), ("per_page", "100".to_string())])
                        .send()
                        .await?
                        .json()
                        .await?;

                    if !resp.success {
                        anyhow::bail!(
                            "Cloudflare API error for zone {zone_name}: {:?}",
                            resp.errors
                        );
                    }

                    if resp.result.is_empty() {
                        break;
                    }

                    for cf_rec in &resp.result {
                        match RecordValue::parse(&cf_rec.r#type, &cf_rec.content) {
                            Ok(value) => {
                                all_records.push(ExistingRecord {
                                    id: cf_rec.id.clone(),
                                    record: EnrichedRecord {
                                        zone: zone_name.clone(),
                                        name: cf_rec.name.clone(),
                                        value,
                                        ttl: cf_rec.ttl,
                                    },
                                    managed: cf_rec
                                        .comment
                                        .as_deref()
                                        .is_some_and(|c| c.contains(MANAGED_COMMENT)),
                                });
                            }
                            Err(e) => {
                                tracing::debug!(
                                    name = %cf_rec.name,
                                    record_type = %cf_rec.r#type,
                                    error = %e,
                                    "skipping Cloudflare record with unparseable type/value"
                                );
                            }
                        }
                    }

                    if let Some(info) = &resp.result_info {
                        if page >= info.total_pages {
                            break;
                        }
                    } else {
                        break;
                    }

                    page += 1;
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
        Ok(all_records)
    }

    /// Fetch records for a specific name from the Cloudflare API.
    ///
    /// Uses the `name` query parameter to filter server-side, avoiding a full
    /// zone fetch. A single name typically has only a handful of records.
    async fn get_records_by_name_inner(
        &self,
        name: &str,
        zone: &str,
    ) -> Result<Vec<ExistingRecord>> {
        let url = self.records_url_for_zone(zone)?;

        let resp: CfListResponse<CfDnsRecord> = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .query(&[("name", name)])
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            anyhow::bail!(
                "Cloudflare API error querying {name} in zone {zone}: {:?}",
                resp.errors
            );
        }

        let mut records = Vec::new();
        for cf_rec in &resp.result {
            match RecordValue::parse(&cf_rec.r#type, &cf_rec.content) {
                Ok(value) => {
                    records.push(ExistingRecord {
                        id: cf_rec.id.clone(),
                        record: EnrichedRecord {
                            zone: zone.to_string(),
                            name: cf_rec.name.clone(),
                            value,
                            ttl: cf_rec.ttl,
                        },
                        managed: cf_rec
                            .comment
                            .as_deref()
                            .is_some_and(|c| c.contains(MANAGED_COMMENT)),
                    });
                }
                Err(e) => {
                    tracing::debug!(
                        name = %cf_rec.name,
                        record_type = %cf_rec.r#type,
                        error = %e,
                        "skipping Cloudflare record with unparseable type/value"
                    );
                }
            }
        }
        Ok(records)
    }

    /// Apply a change to the Cloudflare API.
    ///
    /// Dispatches to the appropriate HTTP method (POST for create, PUT for
    /// update, DELETE for delete). All created/updated records are tagged
    /// with the `managed-by: herald` comment.
    async fn apply_change_inner(&self, change: &Change) -> Result<()> {
        match change {
            Change::Create(record) => {
                let url = self.records_url_for_zone(&record.zone)?;
                let content = record.value.value_str();
                let body = CfCreateRecord {
                    r#type: record.value.type_str(),
                    name: &record.name,
                    content: &content,
                    ttl: record.ttl,
                    proxied: false,
                    comment: MANAGED_COMMENT,
                };

                let resp: CfSingleResponse = self
                    .client
                    .post(url)
                    .bearer_auth(&self.token)
                    .json(&body)
                    .send()
                    .await?
                    .json()
                    .await?;

                if !resp.success {
                    anyhow::bail!("failed to create record: {:?}", resp.errors);
                }

                tracing::info!(%record, "created DNS record");
            }
            Change::Update { id, new, .. } => {
                let url = self.records_url_for_zone(&new.zone)?;
                let content = new.value.value_str();
                let body = CfCreateRecord {
                    r#type: new.value.type_str(),
                    name: &new.name,
                    content: &content,
                    ttl: new.ttl,
                    proxied: false,
                    comment: MANAGED_COMMENT,
                };

                let resp: CfSingleResponse = self
                    .client
                    .put(format!("{url}/{id}"))
                    .bearer_auth(&self.token)
                    .json(&body)
                    .send()
                    .await?
                    .json()
                    .await?;

                if !resp.success {
                    anyhow::bail!("failed to update record: {:?}", resp.errors);
                }

                tracing::info!(record = %new, "updated DNS record");
            }
            Change::Delete(existing) => {
                let url = self.records_url_for_zone(&existing.record.zone)?;
                let resp: CfSingleResponse = self
                    .client
                    .delete(format!("{url}/{}", existing.id))
                    .bearer_auth(&self.token)
                    .send()
                    .await?
                    .json()
                    .await?;

                if !resp.success {
                    anyhow::bail!("failed to delete record: {:?}", resp.errors);
                }

                tracing::info!(record = %existing.record, "deleted DNS record");
            }
        }
        Ok(())
    }

    /// Apply a change with metrics tracking.
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

impl Named for CloudflareBackend {
    fn name(&self) -> &str {
        &self.name
    }
}

impl Backend for CloudflareBackend {
    fn zones(&self) -> Vec<String> {
        self.zone_ids.keys().cloned().collect()
    }

    fn get_records(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ExistingRecord>>> + Send + '_>> {
        Box::pin(self.get_records_inner())
    }

    fn get_records_by_name<'a>(
        &'a self,
        name: &'a str,
        zone: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ExistingRecord>>> + Send + 'a>> {
        Box::pin(self.get_records_by_name_inner(name, zone))
    }

    fn apply_change<'a>(
        &'a self,
        change: &'a Change,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.apply_change_with_metrics(change))
    }
}

// Cloudflare API types

#[derive(Deserialize)]
struct CfListResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    result: Vec<T>,
    result_info: Option<CfResultInfo>,
}

#[derive(Deserialize)]
struct CfSingleResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields accessed via Debug formatting in error messages
struct CfError {
    code: u32,
    message: String,
}

#[derive(Deserialize)]
struct CfResultInfo {
    total_pages: u32,
}

#[derive(Deserialize)]
struct CfZone {
    id: String,
}

#[derive(Deserialize)]
struct CfDnsRecord {
    id: String,
    r#type: String,
    name: String,
    content: String,
    ttl: u32,
    comment: Option<String>,
}

#[derive(Serialize)]
struct CfCreateRecord<'a> {
    r#type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
    proxied: bool,
    comment: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{bearer_token, body_partial_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_backend(server: &MockServer) -> CloudflareBackend {
        let mut zone_ids = HashMap::new();
        zone_ids.insert("example.com".to_string(), "zone-123".to_string());
        CloudflareBackend::with_base_url(server.uri(), zone_ids, "test-token".to_string())
    }

    fn cf_records_response(records: &serde_json::Value, total_pages: u32) -> serde_json::Value {
        json!({
            "success": true,
            "errors": [],
            "result": records,
            "result_info": {
                "total_pages": total_pages
            }
        })
    }

    fn cf_success_response() -> serde_json::Value {
        json!({
            "success": true,
            "errors": [],
            "result": {}
        })
    }

    fn cf_error_response() -> serde_json::Value {
        json!({
            "success": false,
            "errors": [{"code": 1000, "message": "something went wrong"}],
            "result": []
        })
    }

    #[tokio::test]
    async fn test_get_records_single_page() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("GET"))
            .and(path("/zones/zone-123/dns_records"))
            .and(bearer_token("test-token"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(cf_records_response(
                    &json!([{
                        "id": "rec-001",
                        "type": "A",
                        "name": "www.example.com",
                        "content": "203.0.113.1",
                        "ttl": 300,
                        "proxied": false,
                        "comment": "managed-by: herald"
                    }]),
                    1,
                )),
            )
            .expect(1)
            .mount(&server)
            .await;

        let records = backend.get_records_inner().await.unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, "rec-001");
        assert_eq!(records[0].record.name, "www.example.com");
        assert_eq!(
            records[0].record.value,
            RecordValue::A("203.0.113.1".parse().unwrap())
        );
        assert_eq!(records[0].record.ttl, 300);
        assert!(records[0].managed);
    }

    #[tokio::test]
    async fn test_get_records_pagination() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("GET"))
            .and(path("/zones/zone-123/dns_records"))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(cf_records_response(
                    &json!([{
                        "id": "rec-001",
                        "type": "A",
                        "name": "a.example.com",
                        "content": "1.2.3.4",
                        "ttl": 300,
                        "proxied": false,
                        "comment": "managed-by: herald"
                    }]),
                    2,
                )),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/zones/zone-123/dns_records"))
            .and(query_param("page", "2"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(cf_records_response(
                    &json!([{
                        "id": "rec-002",
                        "type": "AAAA",
                        "name": "b.example.com",
                        "content": "2001:db8::1",
                        "ttl": 600,
                        "proxied": true,
                        "comment": "managed-by: herald"
                    }]),
                    2,
                )),
            )
            .expect(1)
            .mount(&server)
            .await;

        let records = backend.get_records_inner().await.unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, "rec-001");
        assert_eq!(records[0].record.name, "a.example.com");
        assert_eq!(records[1].id, "rec-002");
        assert_eq!(records[1].record.name, "b.example.com");
    }

    #[tokio::test]
    async fn test_get_records_unmanaged() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("GET"))
            .and(path("/zones/zone-123/dns_records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(cf_records_response(
                    &json!([{
                        "id": "rec-ext",
                        "type": "CNAME",
                        "name": "example.com",
                        "content": "target.example.com",
                        "ttl": 3600,
                        "proxied": false,
                        "comment": null
                    }]),
                    1,
                )),
            )
            .mount(&server)
            .await;

        let records = backend.get_records_inner().await.unwrap();

        assert_eq!(records.len(), 1);
        assert!(!records[0].managed);
    }

    #[tokio::test]
    async fn test_get_records_api_error() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("GET"))
            .and(path("/zones/zone-123/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(cf_error_response()))
            .mount(&server)
            .await;

        let result = backend.get_records_inner().await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("something went wrong"),
            "expected error message, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_get_records_skips_unparseable() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("GET"))
            .and(path("/zones/zone-123/dns_records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(cf_records_response(
                    &json!([
                        {
                            "id": "rec-001",
                            "type": "A",
                            "name": "good.example.com",
                            "content": "203.0.113.1",
                            "ttl": 300,
                            "proxied": false,
                            "comment": "managed-by: herald"
                        },
                        {
                            "id": "rec-002",
                            "type": "UNKNOWNTYPE",
                            "name": "unknown.example.com",
                            "content": "some-value",
                            "ttl": 300,
                            "proxied": false,
                            "comment": null
                        }
                    ]),
                    1,
                )),
            )
            .mount(&server)
            .await;

        let records = backend.get_records_inner().await.unwrap();

        // Only the parseable A record should be returned
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record.name, "good.example.com");
    }

    #[tokio::test]
    async fn test_apply_create() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("POST"))
            .and(path("/zones/zone-123/dns_records"))
            .and(bearer_token("test-token"))
            .and(body_partial_json(json!({
                "type": "A",
                "name": "new.example.com",
                "content": "10.0.0.1",
                "ttl": 300,
                "proxied": false,
                "comment": "managed-by: herald"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(cf_success_response()))
            .expect(1)
            .mount(&server)
            .await;

        let change = Change::Create(EnrichedRecord {
            zone: "example.com".to_string(),
            name: "new.example.com".to_string(),
            value: RecordValue::A("10.0.0.1".parse().unwrap()),
            ttl: 300,
        });

        backend.apply_change_with_metrics(&change).await.unwrap();
    }

    #[tokio::test]
    async fn test_apply_update() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("PUT"))
            .and(path("/zones/zone-123/dns_records/rec-456"))
            .and(bearer_token("test-token"))
            .and(body_partial_json(json!({
                "type": "A",
                "name": "updated.example.com",
                "content": "10.0.0.2",
                "comment": "managed-by: herald"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(cf_success_response()))
            .expect(1)
            .mount(&server)
            .await;

        let change = Change::Update {
            id: "rec-456".to_string(),
            old: EnrichedRecord {
                zone: "example.com".to_string(),
                name: "updated.example.com".to_string(),
                value: RecordValue::A("10.0.0.1".parse().unwrap()),
                ttl: 300,
            },
            new: EnrichedRecord {
                zone: "example.com".to_string(),
                name: "updated.example.com".to_string(),
                value: RecordValue::A("10.0.0.2".parse().unwrap()),
                ttl: 300,
            },
        };

        backend.apply_change_with_metrics(&change).await.unwrap();
    }

    #[tokio::test]
    async fn test_apply_delete() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("DELETE"))
            .and(path("/zones/zone-123/dns_records/rec-789"))
            .and(bearer_token("test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(cf_success_response()))
            .expect(1)
            .mount(&server)
            .await;

        let change = Change::Delete(ExistingRecord {
            id: "rec-789".to_string(),
            record: EnrichedRecord {
                zone: "example.com".to_string(),
                name: "old.example.com".to_string(),
                value: RecordValue::CNAME("target.example.com".to_string()),
                ttl: 300,
            },
            managed: true,
        });

        backend.apply_change_with_metrics(&change).await.unwrap();
    }

    #[tokio::test]
    async fn test_apply_create_api_error() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("POST"))
            .and(path("/zones/zone-123/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": false,
                "errors": [{"code": 1004, "message": "DNS Validation Error"}],
                "result": null
            })))
            .mount(&server)
            .await;

        let change = Change::Create(EnrichedRecord {
            zone: "example.com".to_string(),
            name: "bad.example.com".to_string(),
            value: RecordValue::A("10.0.0.1".parse().unwrap()),
            ttl: 300,
        });

        let result = backend.apply_change_with_metrics(&change).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("DNS Validation Error"),
            "expected error message, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_get_records_by_name() {
        let server = MockServer::start().await;
        let backend = test_backend(&server);

        Mock::given(method("GET"))
            .and(path("/zones/zone-123/dns_records"))
            .and(bearer_token("test-token"))
            .and(query_param("name", "www.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "errors": [],
                "result": [{
                    "id": "rec-001",
                    "type": "A",
                    "name": "www.example.com",
                    "content": "203.0.113.1",
                    "ttl": 300,
                    "comment": "managed-by: herald"
                }, {
                    "id": "rec-002",
                    "type": "AAAA",
                    "name": "www.example.com",
                    "content": "2001:db8::1",
                    "ttl": 300,
                    "comment": null
                }],
                "result_info": null
            })))
            .expect(1)
            .mount(&server)
            .await;

        let records = backend
            .get_records_by_name_inner("www.example.com", "example.com")
            .await
            .unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].record.name, "www.example.com");
        assert_eq!(
            records[0].record.value,
            RecordValue::A("203.0.113.1".parse().unwrap())
        );
        assert!(records[0].managed);
        assert_eq!(
            records[1].record.value,
            RecordValue::AAAA("2001:db8::1".parse().unwrap())
        );
        assert!(!records[1].managed);
    }
}
