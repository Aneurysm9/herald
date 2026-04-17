//! Herald is a DNS control plane service that manages DNS records at Cloudflare
//! with fine-grained control.
//!
//! # Overview
//!
//! Herald provides three primary use cases:
//!
//! 1. **ACME challenge proxy** — per-service scoped tokens for DNS-01 certificate
//!    validation. Services call Herald's API to set/clear `_acme-challenge` TXT records.
//! 2. **Declarative static records** — infrastructure-as-code DNS records defined
//!    in Herald's config file and reconciled to Cloudflare.
//! 3. **Dynamic DNS mirroring** — poll internal DNS zones (e.g., AAAA records from
//!    DHCPv6/RA), mirror selected records to Cloudflare under different names.
//!
//! # Architecture
//!
//! Providers contribute DNS records to a unified desired-state set. The reconciler
//! diffs this against actual state from the backend and produces changes (create,
//! update, delete). Changes are applied to the backend (currently Cloudflare).
//!
//! Herald uses Cloudflare's record `comment` field to tag managed records with
//! `managed-by: herald`, ensuring it never modifies or deletes manually-created records.
//!
//! # Usage
//!
//! ```bash
//! # Run with a config file
//! herald --config /etc/herald/config.yaml
//!
//! # Single reconciliation pass and exit
//! herald --config config.yaml --once
//!
//! # Dry-run mode (log changes without applying)
//! herald --config config.yaml --once --dry-run
//! ```

mod api;
mod backend;
mod config;
mod dns_server;
mod provider;
mod reconciler;
mod storage;
mod telemetry;
#[cfg(test)]
mod testing;
mod tls;
mod tsig;
mod zone_util;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use hyper_util::rt::TokioIo;
use tokio::signal;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tracing_subscriber::EnvFilter;

use crate::api::{AppState, TokenIndex};
use crate::backend::Backend;
use crate::backend::cloudflare::CloudflareBackend;
use crate::backend::rfc2136::Rfc2136Backend;
use crate::backend::technitium::TechnitiumBackend;
use crate::config::Config;
use crate::dns_server::DnsServer;
use crate::provider::Provider;
use crate::provider::acme::AcmeProvider;
use crate::provider::dynamic::DynamicProvider;
use crate::provider::mirror::MirrorProvider;
use crate::provider::r#static::StaticProvider;
use crate::reconciler::Reconciler;
use crate::telemetry::Metrics;

#[derive(Parser, Debug)]
#[command(name = "herald", about = "DNS control plane service")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/herald/config.yaml")]
    config: String,

    /// Run a single reconciliation pass and exit
    #[arg(long)]
    once: bool,

    /// Dry-run mode: compute changes but don't apply them
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("herald=info".parse()?))
        .json()
        .init();

    let cli = Cli::parse();

    tracing::info!(config = %cli.config, "starting herald");

    let config = config::load(&cli.config)?;

    // Initialize telemetry
    let meter_provider = if config.telemetry.enabled {
        let provider = telemetry::init_meter_provider(&config.telemetry)?;
        tracing::info!("OpenTelemetry metrics enabled");
        Some(provider)
    } else {
        None
    };
    let metrics = Metrics::new();

    // CLI --dry-run overrides config
    let dry_run = cli.dry_run || config.reconciler.dry_run;
    if dry_run {
        tracing::info!("dry-run mode enabled");
    }

    // Initialize backends
    let backends = init_backends(&config, metrics.clone()).await?;

    // Initialize providers
    let initialized_providers = init_providers(&config, metrics.clone()).await?;
    let providers = initialized_providers.all;
    let acme_provider = initialized_providers.acme;
    let mirror_provider = initialized_providers.mirror;
    let dynamic_provider = initialized_providers.dynamic;

    let reconciler = Arc::new(Reconciler::new(dry_run, metrics.clone()));

    // --once mode: single reconciliation pass then exit
    if cli.once {
        tracing::info!("running single reconciliation pass (--once)");

        if let Some(ref mirror) = mirror_provider
            && let Err(e) = mirror.poll().await
        {
            tracing::error!(error = %e, "mirror poll failed");
        }

        reconciler.reconcile(&providers, &backends).await?;

        if let Some(provider) = meter_provider
            && let Err(e) = provider.shutdown()
        {
            tracing::error!(error = %e, "meter provider shutdown failed");
        }

        tracing::info!("herald stopped (single pass complete)");
        return Ok(());
    }

    // Long-running service mode
    run_service(
        &config,
        providers,
        backends,
        reconciler,
        acme_provider,
        dynamic_provider,
        mirror_provider,
        metrics,
    )
    .await?;

    if let Some(provider) = meter_provider
        && let Err(e) = provider.shutdown()
    {
        tracing::error!(error = %e, "meter provider shutdown failed");
    }

    tracing::info!("herald stopped");
    Ok(())
}

/// Holds all initialized providers.
struct InitializedProviders {
    all: Vec<Arc<dyn Provider>>,
    acme: Option<Arc<AcmeProvider>>,
    mirror: Option<Arc<MirrorProvider>>,
    dynamic: Option<Arc<DynamicProvider>>,
}

/// Initialize all configured providers.
async fn init_providers(config: &Config, metrics: Metrics) -> Result<InitializedProviders> {
    let mut all: Vec<Arc<dyn Provider>> = Vec::new();

    if let Some(ref static_config) = config.providers.r#static {
        let p = Arc::new(StaticProvider::new(static_config));
        tracing::info!(
            records = static_config.records.len(),
            "static provider loaded"
        );
        all.push(p);
    }

    let acme = if let Some(ref acme_config) = config.providers.acme {
        let storage_path = Some(std::path::PathBuf::from(&config.state_dir).join("acme.db"));

        let p = Arc::new(
            AcmeProvider::new(acme_config.clone(), storage_path, metrics.clone())
                .context("initializing ACME provider")?,
        );
        tracing::info!("acme provider loaded");
        all.push(Arc::clone(&p) as Arc<dyn Provider>);
        Some(p)
    } else {
        None
    };

    let mirror = if let Some(ref mirror_config) = config.providers.mirror {
        let p = Arc::new(MirrorProvider::new(mirror_config.clone(), metrics.clone()).await?);
        tracing::info!("mirror provider loaded");
        all.push(Arc::clone(&p) as Arc<dyn Provider>);
        Some(p)
    } else {
        None
    };

    let dynamic = if let Some(ref dynamic_config) = config.providers.dynamic {
        let storage_path = Some(std::path::PathBuf::from(&config.state_dir).join("dynamic.db"));

        let p = Arc::new(
            DynamicProvider::new(dynamic_config.clone(), storage_path, metrics.clone())
                .context("initializing dynamic DNS provider")?,
        );
        tracing::info!("dynamic provider loaded");
        all.push(Arc::clone(&p) as Arc<dyn Provider>);
        Some(p)
    } else {
        None
    };

    if all.is_empty() {
        tracing::warn!("no providers configured — reconciliation will produce no records");
    }

    Ok(InitializedProviders {
        all,
        acme,
        mirror,
        dynamic,
    })
}

/// Initialize all configured backends and validate zone ownership.
async fn init_backends(config: &Config, metrics: Metrics) -> Result<Vec<Arc<dyn Backend>>> {
    let mut backends: Vec<Arc<dyn Backend>> = Vec::new();

    // Initialize Cloudflare backends
    for (i, cf_config) in config.backends.cloudflare.iter().enumerate() {
        let backend = Arc::new(CloudflareBackend::new(cf_config, i, metrics.clone()).await?)
            as Arc<dyn Backend>;

        tracing::info!(
            backend = %backend.name(),
            zones = ?backend.zones(),
            "cloudflare backend initialized"
        );

        backends.push(backend);
    }

    // Initialize Technitium backends
    for (idx, tech_config) in config.backends.technitium.iter().enumerate() {
        let backend =
            Arc::new(TechnitiumBackend::new(tech_config.clone(), idx, metrics.clone()).await?)
                as Arc<dyn Backend>;

        tracing::info!(
            backend = %backend.name(),
            zones = ?backend.zones(),
            "technitium backend initialized"
        );

        backends.push(backend);
    }

    // Initialize RFC 2136 backends
    for (idx, rfc_config) in config.backends.rfc2136.iter().enumerate() {
        let backend = Arc::new(
            Rfc2136Backend::new(rfc_config, idx, &config.state_dir, metrics.clone()).await?,
        ) as Arc<dyn Backend>;

        tracing::info!(
            backend = %backend.name(),
            zones = ?backend.zones(),
            "rfc2136 backend initialized"
        );

        backends.push(backend);
    }

    // Require at least one backend
    if backends.is_empty() {
        anyhow::bail!(
            "no backends configured — at least one backend (cloudflare, technitium, or rfc2136) is required"
        );
    }

    // Validate: no zone overlap between backends
    let mut all_zones = std::collections::HashSet::new();
    for backend in &backends {
        for zone in backend.zones() {
            if !all_zones.insert(zone.clone()) {
                anyhow::bail!("zone {zone} managed by multiple backends");
            }
        }
    }

    Ok(backends)
}

/// Run the long-running service: API server, mirror polling, and reconciliation loop.
#[allow(clippy::too_many_arguments)] // Service entrypoint wiring all components together
async fn run_service(
    config: &Config,
    providers: Vec<Arc<dyn Provider>>,
    backends: Vec<Arc<dyn Backend>>,
    reconciler: Arc<Reconciler>,
    acme_provider: Option<Arc<AcmeProvider>>,
    dynamic_provider: Option<Arc<DynamicProvider>>,
    mirror_provider: Option<Arc<MirrorProvider>>,
    metrics: Metrics,
) -> Result<()> {
    // Load client tokens from top-level tokens_file
    let raw_tokens = load_client_tokens(config).await?;
    let token_index = TokenIndex::new(raw_tokens);

    let reconcile_notify = Arc::new(Notify::new());

    // Clone what we need before dynamic_provider is consumed by AppState.
    let dynamic_for_dns = dynamic_provider.as_ref().map(Arc::clone);

    let state = Arc::new(AppState {
        acme_provider,
        dynamic_provider,
        token_index,
        providers: providers.clone(),
        reconciler: Arc::clone(&reconciler),
        backends: backends.clone(),
        reconcile_notify: Arc::clone(&reconcile_notify),
        metrics,
    });

    let app = api::router(state);
    let tls_acceptor = tls::load_tls_acceptor(&config.tls).context("loading TLS configuration")?;
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("binding to {}", config.listen))?;

    tracing::info!(listen = %config.listen, "HTTPS server starting");
    tokio::spawn(serve_tls(listener, tls_acceptor, app));

    // Spawn DNS UPDATE receiver if configured.
    if let Some(ref dns_config) = config.dns_server {
        let Some(dyn_provider) = dynamic_for_dns else {
            anyhow::bail!("dns_server requires providers.dynamic to be configured");
        };
        let dns_server = DnsServer::new(
            dns_config,
            &dns_config.tsig_keys,
            dyn_provider,
            backends.clone(),
            Arc::clone(&reconcile_notify),
        )
        .await?;
        tokio::spawn(dns_server.run());
        tracing::info!("DNS UPDATE receiver started");
    }

    // Parse intervals
    let reconciler_interval =
        parse_duration(&config.reconciler.interval).context("invalid reconciler interval")?;

    // Spawn mirror polling loop
    let mirror_task = if let Some(ref mirror) = mirror_provider {
        let interval = parse_duration(
            &config
                .providers
                .mirror
                .as_ref()
                .context("mirror config missing despite mirror provider being initialized")?
                .interval,
        )
        .context("invalid mirror interval")?;

        // Initial poll before entering the loop
        if let Err(e) = mirror.poll().await {
            tracing::error!(error = %e, "initial mirror poll failed");
        }

        let mirror = Arc::clone(mirror);
        let notify = Arc::clone(&reconcile_notify);
        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // consume the immediate first tick
            loop {
                ticker.tick().await;
                match mirror.poll().await {
                    Ok(()) => notify.notify_one(),
                    Err(e) => tracing::error!(error = %e, "mirror poll failed"),
                }
            }
        }))
    } else {
        None
    };

    // Main reconciliation loop
    let mut ticker = tokio::time::interval(reconciler_interval);
    tracing::info!("entering reconciliation loop");

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = reconciler.reconcile(&providers, &backends).await {
                    tracing::error!(error = %e, "reconciliation failed");
                }
            }
            () = reconcile_notify.notified() => {
                tracing::debug!("provider mutation detected, reconciling");
                if let Err(e) = reconciler.reconcile(&providers, &backends).await {
                    tracing::error!(error = %e, "reconciliation failed");
                }
            }
            () = shutdown_signal() => {
                tracing::info!("shutdown signal received");
                break;
            }
        }
    }

    if let Some(task) = mirror_task {
        task.abort();
    }

    Ok(())
}

/// Parse a human-readable duration string (e.g., "1m", "5m30s") into a `Duration`.
fn parse_duration(s: &str) -> Result<Duration> {
    humantime::parse_duration(s).with_context(|| format!("invalid duration: {s}"))
}

/// Load client tokens from the top-level tokens file.
///
/// The file is expected to be JSON: `{"client_name": "token_value", ...}`.
/// If no `tokens_file` is configured, returns an empty map.
async fn load_client_tokens(config: &Config) -> Result<HashMap<String, String>> {
    let Some(ref tokens_file) = config.tokens_file else {
        return Ok(HashMap::new());
    };

    let content = tokio::fs::read_to_string(tokens_file)
        .await
        .with_context(|| format!("reading tokens file: {tokens_file}"))?;

    let tokens: HashMap<String, String> =
        serde_json::from_str(&content).context("parsing tokens file as JSON")?;

    // Warn about clients in config that have no token
    if let Some(ref acme_config) = config.providers.acme {
        for client_name in acme_config.clients.keys() {
            if !tokens.contains_key(client_name) {
                tracing::warn!(client = %client_name, "ACME client has no token entry — will be unreachable");
            }
        }
    }
    if let Some(ref dynamic_config) = config.providers.dynamic {
        for client_name in dynamic_config.clients.keys() {
            if !tokens.contains_key(client_name) {
                tracing::warn!(client = %client_name, "dynamic client has no token entry — will be unreachable");
            }
        }
    }

    tracing::info!(clients = tokens.len(), "client tokens loaded");
    Ok(tokens)
}

/// Accept TLS connections and serve each one via hyper.
///
/// This is the standard pattern for TLS with axum 0.8: accept TCP, perform the
/// TLS handshake, then serve each connection individually using `hyper_util`.
/// The router is cloned per-connection (axum `Router` is cheaply cloneable via `Arc`).
async fn serve_tls(
    listener: tokio::net::TcpListener,
    tls_acceptor: TlsAcceptor,
    app: axum::Router,
) {
    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "TCP accept failed");
                continue;
            }
        };

        let tls_acceptor = tls_acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, remote_addr = %remote_addr, "TLS handshake failed");
                    return;
                }
            };

            let hyper_service =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let mut svc = app.clone();
                    async move { svc.call(req).await }
                });

            if let Err(e) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls_stream), hyper_service)
                    .await
            {
                tracing::debug!(error = %e, remote_addr = %remote_addr, "connection error");
            }
        });
    }
}

/// Wait for a shutdown signal (SIGINT or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
