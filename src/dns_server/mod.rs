//! DNS UPDATE receiver (RFC 2136 server).
//!
//! Herald can act as a DNS UPDATE target, accepting `nsupdate`-compatible messages
//! over UDP and TCP on a configurable address. Incoming records are stored in the
//! dynamic DNS provider and a reconciliation pass is triggered automatically.
//!
//! # Authentication
//!
//! All DNS UPDATE messages must be signed with TSIG (RFC 2845/8945).
//! Each TSIG key is mapped to a dynamic provider client name; that client's
//! `allowed_domains` and `allowed_zones` govern which records the key may manage.
//!
//! # RCODE semantics
//!
//! | Condition                             | RCODE          | Response TSIG                 |
//! |---------------------------------------|----------------|-------------------------------|
//! | Success                               | 0 (NOERROR)    | Signed (RFC 8945 §5.4)        |
//! | Prereq / permission / zone failure    | (varied)       | Signed                        |
//! | Unknown TSIG key                      | 9 (NOTAUTH)    | Unsigned BADKEY stub          |
//! | Bad MAC                               | 9 (NOTAUTH)    | Unsigned BADSIG stub          |
//! | Time outside fudge window             | 9 (NOTAUTH)    | Signed BADTIME (RFC 8945 §5.2.3) |
//! | No TSIG / non-UPDATE / malformed      | (varied)       | Plain (no TSIG)               |
//! | Domain or zone not permitted          | 5 (REFUSED)    | Signed                        |
//! | Zone not found for FQDN               | 5 (REFUSED)    | Signed                        |
//! | Malformed request                     | 1 (FORMERR)    | Plain or signed (see above)   |
//! | Non-UPDATE opcode                     | 5 (REFUSED)    | Plain                         |

mod error;
mod prereqs;
#[cfg(test)]
mod tests;
mod update;
mod wire;

use error::DnsError;
use wire::build_response;

use crate::backend::Backend;
use crate::config::{DnsServerConfig, TsigKeyConfig};
use crate::provider::dynamic::DynamicProvider;
use crate::telemetry::Metrics;
use crate::tsig::{self, TSIG_FUDGE};
use anyhow::{Context, Result};
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::tsig::{TsigAlgorithm, TsigError};
use hickory_proto::rr::{DNSClass, Name, RecordType, TSigResponseContext, TSigner};
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Notify;

/// Normalize a TSIG key name by stripping a single trailing dot.
///
/// `tsig-keygen` output and BIND/nsupdate examples use canonical FQDNs
/// (with trailing dot); the wire form likewise places the trailing dot
/// in the TSIG record name. Lookup uses the dot-stripped form, so insert
/// must match — otherwise dotted config keys silently mismatch.
fn normalize_key_name(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

/// Outcome of TSIG processing for an inbound UPDATE.
///
/// Drives both whether the update is dispatched (only `Verified` proceeds)
/// and how the response is signed per RFC 8945 §5.4.
enum AuthOutcome {
    /// Request carried no TSIG record. Response is plain unsigned.
    NoTsig,
    /// TSIG present but the key name is not configured. Response carries
    /// an unsigned BADKEY stub TSIG (RFC 8945 §5.3.2).
    UnknownKey { key_name: Name },
    /// Key found but MAC verification failed. Response carries an
    /// unsigned BADSIG stub TSIG (RFC 8945 §5.3.2).
    BadMac { signer: TSigner },
    /// MAC verified but signing time outside the fudge window. Response
    /// is signed with TSIG ERROR 18 (BADTIME) (RFC 8945 §5.2.3).
    BadTime {
        signer: TSigner,
        request_mac: Vec<u8>,
    },
    /// Fully authenticated. Update can be dispatched; response is signed.
    Verified {
        signer: TSigner,
        client_name: String,
        request_mac: Vec<u8>,
    },
}

impl AuthOutcome {
    /// Build a `TSigResponseContext` for the response, if signing applies.
    /// Returns `None` for `NoTsig` — those responses are plain.
    fn into_response_context(self, request_id: u16, now: u64) -> Option<TSigResponseContext> {
        match self {
            Self::NoTsig => None,
            Self::UnknownKey { key_name } => {
                Some(TSigResponseContext::unknown_key(request_id, now, key_name))
            }
            Self::BadMac { signer } => {
                Some(TSigResponseContext::bad_signature(request_id, now, signer))
            }
            Self::BadTime {
                signer,
                request_mac,
            } => Some(TSigResponseContext::new(
                request_id,
                now,
                signer,
                request_mac,
                Some(TsigError::BadTime),
            )),
            Self::Verified {
                signer,
                request_mac,
                ..
            } => Some(TSigResponseContext::new(
                request_id,
                now,
                signer,
                request_mac,
                None,
            )),
        }
    }
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// DNS UPDATE receiver that feeds incoming records into the dynamic provider.
pub(crate) struct DnsServer {
    /// Map from TSIG key name to `(signer, client_name)`.
    tsig_signers: HashMap<String, (TSigner, String)>,
    dynamic_provider: Arc<DynamicProvider>,
    backends: Vec<Arc<dyn Backend>>,
    reconcile_notify: Arc<Notify>,
    listen: SocketAddr,
    metrics: Metrics,
    rate_limiter: Option<Arc<crate::rate_limit::RateLimiterRegistry>>,
}

impl DnsServer {
    /// Create a new DNS server, loading all TSIG keys from their configured files.
    ///
    /// # Errors
    ///
    /// Returns an error if the listen address is invalid or a TSIG key file cannot be read.
    pub(crate) async fn new(
        config: &DnsServerConfig,
        key_configs: &[TsigKeyConfig],
        dynamic_provider: Arc<DynamicProvider>,
        backends: Vec<Arc<dyn Backend>>,
        reconcile_notify: Arc<Notify>,
        metrics: Metrics,
        rate_limiter: Option<Arc<crate::rate_limit::RateLimiterRegistry>>,
    ) -> Result<Self> {
        let listen: SocketAddr = config
            .listen
            .parse()
            .with_context(|| format!("parsing dns_server listen address: {}", config.listen))?;

        let mut tsig_signers = HashMap::new();
        for key_config in key_configs {
            let algorithm = match key_config.algorithm.as_str() {
                "hmac-sha256" => TsigAlgorithm::HmacSha256,
                other => {
                    anyhow::bail!(
                        "dns_server: TSIG key '{}': unsupported algorithm '{other}'",
                        key_config.key_name
                    );
                }
            };
            let signer = tsig::load_tsigner_from_file(
                &key_config.key_name,
                &key_config.secret_file,
                algorithm,
                TSIG_FUDGE,
            )
            .await?;
            tracing::info!(
                key_name = %key_config.key_name,
                client = %key_config.client,
                "DNS server TSIG key loaded"
            );
            tsig_signers.insert(
                normalize_key_name(&key_config.key_name).to_string(),
                (signer, key_config.client.clone()),
            );
        }

        Ok(Self {
            tsig_signers,
            dynamic_provider,
            backends,
            reconcile_notify,
            listen,
            metrics,
            rate_limiter,
        })
    }

    /// Test-only constructor that bypasses TSIG-key file I/O.
    #[cfg(test)]
    pub(crate) fn from_tsig_signers_for_test(
        config: &DnsServerConfig,
        signers: Vec<(String, TSigner, String)>,
        dynamic_provider: Arc<DynamicProvider>,
        backends: Vec<Arc<dyn Backend>>,
        reconcile_notify: Arc<Notify>,
    ) -> Result<Self> {
        let listen: SocketAddr = config
            .listen
            .parse()
            .with_context(|| format!("parsing dns_server listen address: {}", config.listen))?;

        let mut tsig_signers = HashMap::new();
        for (name, signer, client) in signers {
            tsig_signers.insert(normalize_key_name(&name).to_string(), (signer, client));
        }

        Ok(Self {
            tsig_signers,
            dynamic_provider,
            backends,
            reconcile_notify,
            listen,
            metrics: Metrics::noop(),
            rate_limiter: None,
        })
    }

    /// Run the DNS server, binding UDP and TCP listeners.
    ///
    /// This future runs forever; cancel by aborting the spawned task.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound.
    pub(crate) async fn run(self) -> Result<()> {
        let udp = UdpSocket::bind(self.listen)
            .await
            .with_context(|| format!("binding UDP socket on {}", self.listen))?;
        let tcp = TcpListener::bind(self.listen)
            .await
            .with_context(|| format!("binding TCP listener on {}", self.listen))?;

        tracing::info!(listen = %self.listen, "DNS UPDATE server started");

        let server = Arc::new(self);

        let udp_server = Arc::clone(&server);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (len, src) = match udp_server.udp_recv_from(&udp, &mut buf).await {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::error!(error = %e, "UDP recv failed");
                        continue;
                    }
                };
                let msg = buf[..len].to_vec();
                let response = udp_server.handle_message(&msg).await;
                if let Err(e) = udp.send_to(&response, src).await {
                    tracing::warn!(error = %e, src = %src, "failed to send UDP DNS response");
                }
            }
        });

        loop {
            let (stream, src) = tcp.accept().await.context("TCP accept failed")?;
            let conn_server = Arc::clone(&server);
            tokio::spawn(async move {
                let mut stream = stream;
                loop {
                    let Ok(msg) = wire::tcp_recv(&mut stream).await else {
                        break;
                    };
                    let response = conn_server.handle_message(&msg).await;
                    if let Err(e) = wire::tcp_send(&mut stream, &response).await {
                        tracing::warn!(error = %e, src = %src, "failed to send TCP DNS response");
                        break;
                    }
                }
            });
        }
    }

    async fn udp_recv_from(
        &self,
        socket: &UdpSocket,
        buf: &mut [u8],
    ) -> Result<(usize, SocketAddr)> {
        socket.recv_from(buf).await.context("UDP recv_from")
    }

    /// Process one raw DNS message and return the wire-format response.
    #[tracing::instrument(skip(self, msg), fields(msg_len = msg.len()))]
    pub(crate) async fn handle_message(&self, msg: &[u8]) -> Vec<u8> {
        let start = Instant::now();

        // Pre-parse short-circuit cases. These responses cannot be TSIG-signed
        // because we never reached TSIG processing.
        if msg.len() < 12 {
            let response = build_response(0, OpCode::Update, ResponseCode::FormErr, None);
            self.record_dns_metrics("FORMERR", start);
            return response;
        }

        let id = u16::from_be_bytes([msg[0], msg[1]]);

        let Ok(parsed) = Message::from_vec(msg) else {
            let response = build_response(id, OpCode::Update, ResponseCode::FormErr, None);
            self.record_dns_metrics("FORMERR", start);
            return response;
        };

        if parsed.metadata.op_code != OpCode::Update {
            tracing::debug!(opcode = ?parsed.metadata.op_code, "ignoring non-UPDATE DNS message");
            let response = build_response(id, parsed.metadata.op_code, ResponseCode::Refused, None);
            self.record_dns_metrics("REFUSED", start);
            return response;
        }

        // Classify the auth state. The same outcome both gates dispatch
        // (only `Verified` proceeds to update logic) and drives response
        // signing per RFC 8945 §5.4.
        let now = current_unix_time();
        let auth = self.classify_auth(msg, &parsed, now);

        let result = match &auth {
            AuthOutcome::Verified { client_name, .. } => {
                self.handle_update(&parsed, client_name).await
            }
            AuthOutcome::NoTsig
            | AuthOutcome::UnknownKey { .. }
            | AuthOutcome::BadMac { .. }
            | AuthOutcome::BadTime { .. } => Err(DnsError::NotAuth),
        };

        let (rcode, label) = match &result {
            Ok(()) => (ResponseCode::NoError, "NOERROR".to_string()),
            Err(DnsError::NotAuth) => (ResponseCode::NotAuth, "NOTAUTH".to_string()),
            Err(DnsError::Refused(reason)) => {
                tracing::debug!(reason = %reason, "DNS UPDATE refused");
                (ResponseCode::Refused, "REFUSED".to_string())
            }
            Err(DnsError::PrereqFailed(rc)) => {
                tracing::debug!(rcode = ?rc, "DNS UPDATE prerequisite failed");
                (*rc, format!("{rc}"))
            }
            Err(DnsError::FormErr(reason)) => {
                tracing::debug!(reason = %reason, "DNS UPDATE malformed");
                (ResponseCode::FormErr, "FORMERR".to_string())
            }
            Err(DnsError::NotZone(reason)) => {
                tracing::debug!(reason = %reason, "DNS UPDATE: name not in zone");
                (ResponseCode::NotZone, "NOTZONE".to_string())
            }
        };

        self.record_dns_metrics(&label, start);
        let sign_ctx = auth.into_response_context(id, now);
        build_response(id, OpCode::Update, rcode, sign_ctx)
    }

    /// Inspect the request's TSIG record (if any) and resolve it to one of
    /// the five auth outcomes. Only `Verified` permits the update to be
    /// dispatched; the others all map to NOTAUTH but each carries a
    /// distinct response-signing strategy.
    fn classify_auth(&self, raw_msg: &[u8], parsed: &Message, now: u64) -> AuthOutcome {
        let Some(sig_record) = parsed.signature.as_ref() else {
            return AuthOutcome::NoTsig;
        };

        let utf8 = sig_record.name.to_utf8();
        let key_name = normalize_key_name(&utf8);

        let Some((signer, client_name)) = self.tsig_signers.get(key_name) else {
            tracing::debug!(
                attempted = %key_name,
                configured = ?self.tsig_signers.keys().collect::<Vec<_>>(),
                "TSIG key lookup miss"
            );
            return AuthOutcome::UnknownKey {
                key_name: sig_record.name.clone(),
            };
        };

        match signer.verify_message_byte(raw_msg, None, true) {
            Err(_) => AuthOutcome::BadMac {
                signer: signer.clone(),
            },
            Ok((request_mac, _time, valid_range)) => {
                if valid_range.contains(&now) {
                    AuthOutcome::Verified {
                        signer: signer.clone(),
                        client_name: client_name.clone(),
                        request_mac,
                    }
                } else {
                    AuthOutcome::BadTime {
                        signer: signer.clone(),
                        request_mac,
                    }
                }
            }
        }
    }

    /// Record DNS server metrics for a processed message.
    fn record_dns_metrics(&self, rcode: &str, start: Instant) {
        let elapsed = start.elapsed().as_secs_f64();
        self.metrics
            .dns_server_requests
            .add(1, &[KeyValue::new("rcode", rcode.to_string())]);
        self.metrics.dns_server_duration.record(elapsed, &[]);
    }

    /// Apply a TSIG-authenticated UPDATE: rate-limit, validate the zone
    /// section, evaluate prerequisites, and apply the update RRs.
    ///
    /// Auth (TSIG key lookup, MAC, time-fudge) is performed upstream in
    /// `classify_auth`; this method is only entered for the `Verified`
    /// auth outcome.
    #[tracing::instrument(skip(self, parsed, client_name), fields(client = %client_name))]
    async fn handle_update(&self, parsed: &Message, client_name: &str) -> Result<(), DnsError> {
        // Check rate limit after successful TSIG authentication.
        if let Some(ref limiter) = self.rate_limiter
            && limiter.check(client_name).is_err()
        {
            self.metrics
                .rate_limit_rejected
                .add(1, &[KeyValue::new("client", client_name.to_string())]);
            return Err(DnsError::Refused(format!(
                "rate limit exceeded for client {client_name}"
            )));
        }

        // Zone section validation (RFC 2136 §2.3): ZOCOUNT must be 1,
        // QTYPE must be SOA, QCLASS must be IN.
        if parsed.queries.len() != 1 {
            return Err(DnsError::FormErr(format!(
                "ZOCOUNT must be 1, got {}",
                parsed.queries.len()
            )));
        }
        let zone_query = &parsed.queries[0];
        if zone_query.query_type() != RecordType::SOA {
            return Err(DnsError::FormErr(format!(
                "zone QTYPE must be SOA, got {:?}",
                zone_query.query_type()
            )));
        }
        if zone_query.query_class() != DNSClass::IN {
            return Err(DnsError::FormErr(format!(
                "zone QCLASS must be IN, got {:?}",
                zone_query.query_class()
            )));
        }

        // Evaluate prerequisites (RFC 2136 §3.2) against the current zone
        // contents. Only incurs a backend query when prereqs are present.
        if !parsed.answers.is_empty() {
            prereqs::evaluate_prereqs(&self.backends, &parsed.answers, zone_query).await?;
        }

        // RFC 2136 §3.4: validate ALL update RRs before applying ANY.
        // If any RR fails validation, no mutations occur (atomic).
        let mut actions = Vec::with_capacity(parsed.authorities.len());
        for record in &parsed.authorities {
            actions.push(update::validate_update_record(
                client_name,
                record,
                &self.backends,
                &self.dynamic_provider,
            )?);
        }

        for action in actions {
            update::apply_validated_update(action, &self.dynamic_provider).await?;
        }

        self.reconcile_notify.notify_one();
        tracing::info!(client = %client_name, "DNS UPDATE applied successfully");
        Ok(())
    }
}
