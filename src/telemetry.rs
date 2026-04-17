use anyhow::Result;
use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter, UpDownCounter};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct TelemetryConfig {
    /// Whether OpenTelemetry metrics export is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// OTLP endpoint (e.g., `http://localhost:4318`).
    /// Falls back to `OTEL_EXPORTER_OTLP_ENDPOINT` env var if unset.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
}

/// Holds all OpenTelemetry metric instruments for Herald.
///
/// All OpenTelemetry instrument types are internally `Arc`-based, so cloning is cheap.
/// When no `MeterProvider` has been configured globally, every instrument
/// silently discards recorded values (noop behavior).
#[derive(Clone)]
pub(crate) struct Metrics {
    // Reconciliation
    pub reconciliation_runs: Counter<u64>,
    pub reconciliation_duration: Histogram<f64>,
    pub reconciliation_changes: Counter<u64>,

    // Provider
    pub provider_records: Gauge<u64>,
    pub provider_errors: Counter<u64>,

    // ACME
    pub acme_challenges_active: UpDownCounter<i64>,
    pub acme_operations: Counter<u64>,

    // Mirror
    pub mirror_polls: Counter<u64>,
    pub mirror_poll_duration: Histogram<f64>,
    pub mirror_records: Gauge<u64>,

    // Dynamic DNS
    pub dynamic_operations: Counter<u64>,
    pub dynamic_records_active: Gauge<u64>,

    // Backend
    pub backend_api_calls: Counter<u64>,
    pub backend_api_duration: Histogram<f64>,

    // DNS UPDATE receiver
    pub dns_server_requests: Counter<u64>,
    pub dns_server_duration: Histogram<f64>,

    // HTTP API
    pub http_requests: Counter<u64>,
    pub http_duration: Histogram<f64>,

    // Reconciliation drift
    pub reconciliation_drift: Gauge<u64>,
}

/// Initialize the OTLP meter provider and set it as the global provider.
///
/// Returns the `SdkMeterProvider` handle — the caller must hold it and call
/// `shutdown()` on graceful exit to flush buffered metrics.
pub(crate) fn init_meter_provider(config: &TelemetryConfig) -> Result<SdkMeterProvider> {
    let mut builder = opentelemetry_otlp::MetricExporter::builder().with_http();

    if let Some(ref endpoint) = config.otlp_endpoint {
        builder = builder.with_endpoint(endpoint);
    }

    let exporter = builder.build()?;

    let provider = SdkMeterProvider::builder()
        .with_periodic_exporter(exporter)
        .build();

    opentelemetry::global::set_meter_provider(provider.clone());
    Ok(provider)
}

impl Metrics {
    /// Create metrics instruments from the current global meter.
    ///
    /// If `init_meter_provider` was called beforehand, instruments will
    /// export real data. Otherwise they behave as noops.
    pub(crate) fn new() -> Self {
        let meter = opentelemetry::global::meter("herald");
        Self::from_meter(&meter)
    }

    /// Create noop metrics instruments (for tests and disabled telemetry).
    ///
    /// Equivalent to `new()` when no provider has been set, but the distinct
    /// name makes intent clear at call sites.
    #[cfg(test)]
    pub(crate) fn noop() -> Self {
        let meter = opentelemetry::global::meter("herald");
        Self::from_meter(&meter)
    }

    fn from_meter(meter: &Meter) -> Self {
        Self {
            reconciliation_runs: meter
                .u64_counter("herald.reconciliation.runs")
                .with_description("Number of reconciliation passes")
                .build(),
            reconciliation_duration: meter
                .f64_histogram("herald.reconciliation.duration")
                .with_description("Duration of reconciliation passes")
                .with_unit("s")
                .build(),
            reconciliation_changes: meter
                .u64_counter("herald.reconciliation.changes")
                .with_description("Number of changes produced by reconciliation")
                .build(),
            provider_records: meter
                .u64_gauge("herald.provider.records")
                .with_description("Number of records from each provider")
                .build(),
            provider_errors: meter
                .u64_counter("herald.provider.errors")
                .with_description("Number of provider errors")
                .build(),
            acme_challenges_active: meter
                .i64_up_down_counter("herald.acme.challenges.active")
                .with_description("Number of active ACME challenges")
                .build(),
            acme_operations: meter
                .u64_counter("herald.acme.operations")
                .with_description("Number of ACME operations")
                .build(),
            mirror_polls: meter
                .u64_counter("herald.mirror.polls")
                .with_description("Number of mirror poll operations")
                .build(),
            mirror_poll_duration: meter
                .f64_histogram("herald.mirror.poll_duration")
                .with_description("Duration of mirror polls")
                .with_unit("s")
                .build(),
            mirror_records: meter
                .u64_gauge("herald.mirror.records")
                .with_description("Number of mirrored records")
                .build(),
            dynamic_operations: meter
                .u64_counter("herald.dynamic.operations")
                .with_description("Number of dynamic DNS operations")
                .build(),
            dynamic_records_active: meter
                .u64_gauge("herald.dynamic.records.active")
                .with_description("Number of active dynamic DNS records")
                .build(),
            backend_api_calls: meter
                .u64_counter("herald.backend.api_calls")
                .with_description("Number of backend API calls")
                .build(),
            backend_api_duration: meter
                .f64_histogram("herald.backend.api_duration")
                .with_description("Duration of backend API calls")
                .with_unit("s")
                .build(),
            dns_server_requests: meter
                .u64_counter("herald.dns_server.requests")
                .with_description("DNS UPDATE messages received")
                .build(),
            dns_server_duration: meter
                .f64_histogram("herald.dns_server.duration")
                .with_description("Duration of DNS UPDATE message handling")
                .with_unit("s")
                .build(),
            http_requests: meter
                .u64_counter("herald.http.requests")
                .with_description("HTTP API requests")
                .build(),
            http_duration: meter
                .f64_histogram("herald.http.duration")
                .with_description("HTTP API request duration")
                .with_unit("s")
                .build(),
            reconciliation_drift: meter
                .u64_gauge("herald.reconciliation.drift")
                .with_description("Number of changes needed to converge (0 = converged)")
                .build(),
        }
    }
}
