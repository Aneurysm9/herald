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
//! | Condition                             | RCODE          |
//! |---------------------------------------|----------------|
//! | Success                               | 0 (NOERROR)    |
//! | Unknown TSIG key / bad MAC            | 9 (NOTAUTH)    |
//! | Domain or zone not permitted          | 5 (REFUSED)    |
//! | Zone not found for FQDN              | 5 (REFUSED)    |
//! | Malformed request                     | 1 (FORMERR)    |
//! | Non-UPDATE opcode                     | 5 (REFUSED)    |

use crate::backend::{Backend, ExistingRecord};
use crate::config::{DnsServerConfig, TsigKeyConfig};
use crate::provider::RecordValue;
use crate::provider::dynamic::DynamicProvider;
use crate::telemetry::Metrics;
use crate::tsig::{self, TSIG_FUDGE};
use crate::zone_util::derive_zone;
use anyhow::{Context, Result};
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::{DNSClass, RData, RecordType, TSigner};
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Notify;

/// DNS UPDATE receiver that feeds incoming records into the dynamic provider.
pub(crate) struct DnsServer {
    /// Map from TSIG key name to `(signer, client_name)`.
    tsig_signers: HashMap<String, (TSigner, String)>,
    dynamic_provider: Arc<DynamicProvider>,
    backends: Vec<Arc<dyn Backend>>,
    reconcile_notify: Arc<Notify>,
    listen: SocketAddr,
    metrics: Metrics,
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
                key_config.key_name.clone(),
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
            tsig_signers.insert(name, (signer, client));
        }

        Ok(Self {
            tsig_signers,
            dynamic_provider,
            backends,
            reconcile_notify,
            listen,
            metrics: Metrics::noop(),
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
                    let Ok(msg) = tcp_recv(&mut stream).await else {
                        break;
                    };
                    let response = conn_server.handle_message(&msg).await;
                    if let Err(e) = tcp_send(&mut stream, &response).await {
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

        if msg.len() < 12 {
            let response = build_response(0, OpCode::Update, ResponseCode::FormErr);
            self.record_dns_metrics("FORMERR", start);
            return response;
        }

        let id = u16::from_be_bytes([msg[0], msg[1]]);

        let Ok(parsed) = Message::from_vec(msg) else {
            let response = build_response(id, OpCode::Update, ResponseCode::FormErr);
            self.record_dns_metrics("FORMERR", start);
            return response;
        };

        if parsed.metadata.op_code != OpCode::Update {
            tracing::debug!(opcode = ?parsed.metadata.op_code, "ignoring non-UPDATE DNS message");
            let response = build_response(id, parsed.metadata.op_code, ResponseCode::Refused);
            self.record_dns_metrics("REFUSED", start);
            return response;
        }

        match self.handle_update(msg, &parsed).await {
            Ok(()) => {
                let r = build_response(id, OpCode::Update, ResponseCode::NoError);
                self.record_dns_metrics("NOERROR", start);
                r
            }
            Err(DnsError::NotAuth) => {
                let r = build_response(id, OpCode::Update, ResponseCode::NotAuth);
                self.record_dns_metrics("NOTAUTH", start);
                r
            }
            Err(DnsError::Refused(reason)) => {
                tracing::debug!(reason = %reason, "DNS UPDATE refused");
                let r = build_response(id, OpCode::Update, ResponseCode::Refused);
                self.record_dns_metrics("REFUSED", start);
                r
            }
            Err(DnsError::PrereqFailed(rcode)) => {
                tracing::debug!(rcode = ?rcode, "DNS UPDATE prerequisite failed");
                let r = build_response(id, OpCode::Update, rcode);
                self.record_dns_metrics(&format!("{rcode}"), start);
                r
            }
            Err(DnsError::FormErr(reason)) => {
                tracing::debug!(reason = %reason, "DNS UPDATE malformed");
                let r = build_response(id, OpCode::Update, ResponseCode::FormErr);
                self.record_dns_metrics("FORMERR", start);
                r
            }
            Err(DnsError::NotZone(reason)) => {
                tracing::debug!(reason = %reason, "DNS UPDATE: name not in zone");
                let r = build_response(id, OpCode::Update, ResponseCode::NotZone);
                self.record_dns_metrics("NOTZONE", start);
                r
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

    /// Validate TSIG, parse zone + update sections, and apply each update RR.
    #[tracing::instrument(skip(self, raw_msg, parsed))]
    async fn handle_update(&self, raw_msg: &[u8], parsed: &Message) -> Result<(), DnsError> {
        // Extract TSIG key name — hickory places the TSIG record in
        // `Message.signature` (not `additionals`) during parsing.
        // `Name::to_utf8()` includes a trailing dot for FQDNs; strip it
        // for consistent HashMap lookup.
        let key_name = parsed
            .signature
            .as_ref()
            .map(|r| {
                let s = r.name.to_utf8();
                s.strip_suffix('.').unwrap_or(&s).to_string()
            })
            .ok_or(DnsError::NotAuth)?;

        let (signer, client_name) = self
            .tsig_signers
            .get(key_name.as_str())
            .ok_or(DnsError::NotAuth)?;

        // Verify the TSIG MAC against the raw bytes.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let verify_result = signer.verify_message_byte(raw_msg, None, true);
        match verify_result {
            Ok((_hash, _time, valid_range)) => {
                if !valid_range.contains(&now) {
                    return Err(DnsError::NotAuth);
                }
            }
            Err(_) => return Err(DnsError::NotAuth),
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
            self.evaluate_prereqs(&parsed.answers, zone_query).await?;
        }

        // RFC 2136 §3.4: validate ALL update RRs before applying ANY.
        // If any RR fails validation, no mutations occur (atomic).
        let mut actions = Vec::with_capacity(parsed.authorities.len());
        for record in &parsed.authorities {
            actions.push(self.validate_update_record(client_name, record)?);
        }

        for action in actions {
            self.apply_validated_update(action).await?;
        }

        self.reconcile_notify.notify_one();
        tracing::info!(client = %client_name, "DNS UPDATE applied successfully");
        Ok(())
    }

    /// Evaluate RFC 2136 §3.2 prerequisites against actual backend state.
    ///
    /// Queries the backend for each unique name referenced in the prerequisite
    /// section, then checks each prerequisite RR against the results. This
    /// uses targeted per-name queries (`get_records_by_name`) instead of
    /// fetching the entire zone, which is both more efficient and ensures the
    /// RFC 2136 backend checks the authoritative server (not local `SQLite`).
    async fn evaluate_prereqs(
        &self,
        prereqs: &[hickory_proto::rr::Record],
        zone_query: &hickory_proto::op::Query,
    ) -> Result<(), DnsError> {
        use hickory_proto::rr::RecordType;

        let zone_name = zone_query.name().to_utf8();
        let zone_name_trimmed = zone_name.trim_end_matches('.');

        let (zone, backend_idx) = derive_zone(zone_name_trimmed, &self.backends)
            .map_err(|_| DnsError::NotZone(format!("no backend for zone {zone_name}")))?;
        let backend = &self.backends[backend_idx];

        // Collect unique prerequisite names and fetch records per name.
        let mut unique_names: Vec<String> = prereqs
            .iter()
            .map(|p| p.name.to_utf8().trim_end_matches('.').to_string())
            .collect();
        unique_names.sort_unstable();
        unique_names.dedup();

        let mut records_by_name: HashMap<String, Vec<ExistingRecord>> = HashMap::new();
        for name in &unique_names {
            let records = backend
                .get_records_by_name(name, &zone)
                .await
                .map_err(|e| {
                    DnsError::Refused(format!("failed to query records for {name}: {e}"))
                })?;
            records_by_name.insert(name.clone(), records);
        }

        for prereq in prereqs {
            // §3.2: prereq TTL MUST be zero.
            if prereq.ttl != 0 {
                return Err(DnsError::FormErr(format!(
                    "prerequisite TTL must be 0, got {}",
                    prereq.ttl
                )));
            }

            let prereq_name = prereq.name.to_utf8();
            let prereq_name = prereq_name.trim_end_matches('.');
            let prereq_class = prereq.dns_class;
            let prereq_type = prereq.record_type();
            let has_rdata = !matches!(&prereq.data, RData::Update0(..));

            let empty: Vec<ExistingRecord> = Vec::new();
            let name_records = records_by_name.get(prereq_name).unwrap_or(&empty);

            match (prereq_class, prereq_type, has_rdata) {
                // §2.4.1 RRset exists (value-independent): CLASS=ANY, specific TYPE, no RDATA
                (DNSClass::ANY, rtype, false) if rtype != RecordType::ANY => {
                    let type_str = rtype.to_string();
                    let found = name_records
                        .iter()
                        .any(|r| r.record.value.type_str() == type_str);
                    if !found {
                        return Err(DnsError::PrereqFailed(ResponseCode::NXRRSet));
                    }
                }

                // §2.4.2 RRset exists (value-dependent): CLASS=IN, specific TYPE, RDATA present
                (DNSClass::IN, rtype, true) if rtype != RecordType::ANY => {
                    let type_str = rtype.to_string();
                    let prereq_value = RecordValue::try_from(&prereq.data)
                        .map_err(|e| DnsError::FormErr(format!("bad prereq RDATA: {e}")))?;
                    let found = name_records.iter().any(|r| {
                        r.record.value.type_str() == type_str && r.record.value == prereq_value
                    });
                    if !found {
                        return Err(DnsError::PrereqFailed(ResponseCode::NXRRSet));
                    }
                }

                // §2.4.3 RRset does not exist: CLASS=NONE, specific TYPE, no RDATA
                (DNSClass::NONE, rtype, false) if rtype != RecordType::ANY => {
                    let type_str = rtype.to_string();
                    let found = name_records
                        .iter()
                        .any(|r| r.record.value.type_str() == type_str);
                    if found {
                        return Err(DnsError::PrereqFailed(ResponseCode::YXRRSet));
                    }
                }

                // §2.4.4 Name is in use: CLASS=ANY, TYPE=ANY, no RDATA
                (DNSClass::ANY, RecordType::ANY, false) => {
                    if name_records.is_empty() {
                        return Err(DnsError::PrereqFailed(ResponseCode::NXDomain));
                    }
                }

                // §2.4.5 Name is not in use: CLASS=NONE, TYPE=ANY, no RDATA
                (DNSClass::NONE, RecordType::ANY, false) => {
                    if !name_records.is_empty() {
                        return Err(DnsError::PrereqFailed(ResponseCode::YXDomain));
                    }
                }

                _ => {
                    return Err(DnsError::FormErr(format!(
                        "unrecognized prerequisite form: class={prereq_class:?} type={prereq_type:?} has_rdata={has_rdata}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validate a single update RR without mutating state. Returns a
    /// `ValidatedUpdate` that can be applied later, ensuring atomicity
    /// per RFC 2136 §3.4: if any RR fails validation, no updates are applied.
    fn validate_update_record(
        &self,
        client: &str,
        record: &hickory_proto::rr::Record,
    ) -> Result<ValidatedUpdate, DnsError> {
        let name = record.name.to_utf8();
        let name = name.trim_end_matches('.').to_string();
        let rtype = record.record_type();
        let dns_class = record.dns_class;

        let (zone, _) = derive_zone(&name, &self.backends)
            .map_err(|_| DnsError::NotZone(format!("no zone found for {name}")))?;

        self.dynamic_provider
            .check_permission(client, &zone, &name)
            .map_err(|e| DnsError::Refused(e.to_string()))?;

        let has_rdata = !matches!(&record.data, RData::Update0(..));
        let ttl = record.ttl;

        if dns_class == DNSClass::ANY && !has_rdata && rtype == RecordType::ANY {
            return Ok(ValidatedUpdate::DeleteAll {
                client: client.to_string(),
                zone,
                name,
            });
        }

        let type_name = match rtype {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::TXT => "TXT",
            RecordType::MX => "MX",
            RecordType::NS => "NS",
            _ => return Ok(ValidatedUpdate::Skip),
        };

        match dns_class {
            DNSClass::IN if has_rdata => {
                let value = RecordValue::try_from(&record.data).map_err(|e| {
                    DnsError::FormErr(format!("undecodable RDATA for {name} {type_name}: {e}"))
                })?;
                Ok(ValidatedUpdate::Set {
                    client: client.to_string(),
                    zone,
                    name,
                    type_name: type_name.to_string(),
                    value: value.value_str().clone(),
                    ttl,
                })
            }
            DNSClass::NONE if has_rdata => Ok(ValidatedUpdate::Delete {
                client: client.to_string(),
                zone,
                name,
                type_name: type_name.to_string(),
            }),
            DNSClass::ANY if !has_rdata => Ok(ValidatedUpdate::DeleteType {
                client: client.to_string(),
                zone,
                name,
                type_name: type_name.to_string(),
            }),
            _ => Ok(ValidatedUpdate::Skip),
        }
    }

    /// Apply a previously validated update action to the dynamic provider.
    async fn apply_validated_update(&self, action: ValidatedUpdate) -> Result<(), DnsError> {
        match action {
            ValidatedUpdate::Set {
                client,
                zone,
                name,
                type_name,
                value,
                ttl,
            } => {
                self.dynamic_provider
                    .set_record(&client, &zone, &name, &type_name, &value, ttl)
                    .await
                    .map_err(|e| DnsError::Refused(e.to_string()))?;
                tracing::debug!(
                    client,
                    name,
                    record_type = type_name,
                    zone,
                    "DNS UPDATE: record added"
                );
            }
            ValidatedUpdate::Delete {
                client,
                zone,
                name,
                type_name,
            } => {
                self.dynamic_provider
                    .delete_record(&client, &zone, &name, &type_name)
                    .await
                    .map_err(|e| DnsError::Refused(e.to_string()))?;
                tracing::debug!(
                    client,
                    name,
                    record_type = type_name,
                    zone,
                    "DNS UPDATE: record deleted"
                );
            }
            ValidatedUpdate::DeleteType {
                client,
                zone,
                name,
                type_name,
            } => {
                self.dynamic_provider
                    .delete_record(&client, &zone, &name, &type_name)
                    .await
                    .map_err(|e| DnsError::Refused(e.to_string()))?;
                tracing::debug!(
                    client,
                    name,
                    record_type = type_name,
                    zone,
                    "DNS UPDATE: RRset deleted"
                );
            }
            ValidatedUpdate::DeleteAll { client, zone, name } => {
                self.dynamic_provider
                    .delete_all_for_name(&client, &zone, &name)
                    .await
                    .map_err(|e| DnsError::Refused(e.to_string()))?;
                tracing::debug!(
                    client,
                    name,
                    zone,
                    "DNS UPDATE: all records for name deleted"
                );
            }
            ValidatedUpdate::Skip => {}
        }
        Ok(())
    }
}

/// A validated but not-yet-applied update action. Separating validation from
/// mutation ensures atomicity per RFC 2136 §3.4: all RRs are validated first,
/// and mutations only happen if every RR passes.
enum ValidatedUpdate {
    Set {
        client: String,
        zone: String,
        name: String,
        type_name: String,
        value: String,
        ttl: u32,
    },
    Delete {
        client: String,
        zone: String,
        name: String,
        type_name: String,
    },
    DeleteType {
        client: String,
        zone: String,
        name: String,
        type_name: String,
    },
    DeleteAll {
        client: String,
        zone: String,
        name: String,
    },
    Skip,
}

/// Errors that can occur during DNS UPDATE processing.
enum DnsError {
    NotAuth,
    Refused(String),
    FormErr(String),
    NotZone(String),
    /// Prerequisite check failed with a specific RFC 2136 RCODE.
    PrereqFailed(ResponseCode),
}

// ── Wire helpers ─────────────────────────────────────────────────────────────

/// Build a minimal DNS response (header only, all counts zero).
fn build_response(id: u16, opcode: OpCode, rcode: ResponseCode) -> Vec<u8> {
    let msg = Message::error_msg(id, opcode, rcode);
    msg.to_vec().unwrap_or_else(|_| {
        // Fallback: hand-rolled 12-byte header if serialization fails.
        let op_val = u8::from(opcode);
        let rcode_val = rcode.low();
        let flags: u16 = 0x8000 | (u16::from(op_val) << 11) | u16::from(rcode_val);
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        buf
    })
}

/// Receive one DNS message from a TCP connection (2-byte length prefix).
async fn tcp_recv(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let len = stream
        .read_u16()
        .await
        .context("reading DNS message length")? as usize;
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .context("reading DNS message body")?;
    Ok(buf)
}

/// Send a DNS message over a TCP connection (2-byte length prefix).
async fn tcp_send(stream: &mut TcpStream, msg: &[u8]) -> Result<()> {
    let len = u16::try_from(msg.len())
        .context("DNS message too large for TCP transport (> 65535 bytes)")?;
    stream
        .write_u16(len)
        .await
        .context("writing DNS message length")?;
    stream
        .write_all(msg)
        .await
        .context("writing DNS message body")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::doc_markdown)]
mod tests {
    use crate::testing as helpers;
    use crate::testing::{
        DnsServerFixture, FIXTURE_CLIENT, FIXTURE_KEY_NAME, FIXTURE_ZONE, Prereq, TEST_TSIG_SECRET,
        UpdateMessageBuilder, extract_rcode, make_test_tsig_key,
    };

    fn rdata_a_sample() -> Vec<u8> {
        helpers::rdata_a_bytes(std::net::Ipv4Addr::new(192, 0, 2, 1))
    }

    /// RCODEs defined by RFC 1035 / RFC 2136 / RFC 2845.
    mod rfc_rcodes {
        pub(super) const NXDOMAIN: u8 = 3;
        pub(super) const YXDOMAIN: u8 = 6;
        pub(super) const YXRRSET: u8 = 7;
        pub(super) const NXRRSET: u8 = 8;
        pub(super) const NOTZONE: u8 = 10;
    }

    // ─�� 5a. Authentication (RFC 2845) ─────────────────────────────────────────

    #[tokio::test]
    async fn test_unsigned_update_returns_notauth() {
        let fx = DnsServerFixture::default_fixture().await;
        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .add(
                format!("host.{FIXTURE_ZONE}"),
                helpers::RTYPE_A,
                60,
                rdata_a_sample(),
            )
            .build(0x0001);

        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 9); // NOTAUTH
        assert!(fx.current_records().await.is_empty());
    }

    #[tokio::test]
    async fn test_unknown_tsig_key_returns_notauth() {
        let fx = DnsServerFixture::default_fixture().await;
        let wrong_key = make_test_tsig_key("other.example.com", TEST_TSIG_SECRET);
        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .add(
                format!("host.{FIXTURE_ZONE}"),
                helpers::RTYPE_A,
                60,
                rdata_a_sample(),
            )
            .build_signed(0x0001, &wrong_key);

        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 9);
        assert!(fx.current_records().await.is_empty());
    }

    #[tokio::test]
    async fn test_bad_mac_returns_notauth() {
        let fx = DnsServerFixture::default_fixture().await;
        let mut msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .add(
                format!("host.{FIXTURE_ZONE}"),
                helpers::RTYPE_A,
                60,
                rdata_a_sample(),
            )
            .build_signed(0x0001, &fx.key);
        let flip = msg.len() - 10;
        msg[flip] ^= 0x80;

        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 9);
        assert!(fx.current_records().await.is_empty());
    }

    #[tokio::test]
    async fn test_time_skew_past_fudge_returns_notauth() {
        let fx = DnsServerFixture::default_fixture().await;
        let ancient = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(600);
        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .add(
                format!("host.{FIXTURE_ZONE}"),
                helpers::RTYPE_A,
                60,
                rdata_a_sample(),
            )
            .build_signed_with_time(0x0001, &fx.key, ancient);

        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 9);
        assert!(fx.current_records().await.is_empty());
    }

    // ── 5b. Opcode dispatch ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_non_update_opcode_returns_refused() {
        let fx = DnsServerFixture::default_fixture().await;
        // Standard query (opcode 0)
        let msg = helpers::build_raw_query(0x0001, "example.com");
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 5); // REFUSED
    }

    #[tokio::test]
    async fn test_truncated_header_returns_formerr() {
        let fx = DnsServerFixture::default_fixture().await;
        let msg = [0u8; 6];
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 1); // FORMERR
    }

    // ── 5c. Zone section validation ────────────────────────────────────���──────

    #[tokio::test]
    async fn test_zocount_zero_returns_formerr() {
        let fx = DnsServerFixture::default_fixture().await;
        let msg = UpdateMessageBuilder::empty()
            .zocount_override(0)
            .add(
                format!("host.{FIXTURE_ZONE}"),
                helpers::RTYPE_A,
                60,
                rdata_a_sample(),
            )
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 1);
    }

    #[tokio::test]
    async fn test_zocount_two_returns_formerr() {
        let fx = DnsServerFixture::default_fixture().await;
        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .extra_zone(format!("other.{FIXTURE_ZONE}"), helpers::RTYPE_SOA, 1)
            .add(
                format!("host.{FIXTURE_ZONE}"),
                helpers::RTYPE_A,
                60,
                rdata_a_sample(),
            )
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 1);
    }

    #[tokio::test]
    async fn test_zone_qtype_not_soa_returns_formerr() {
        let fx = DnsServerFixture::default_fixture().await;
        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .zone_qtype(helpers::RTYPE_A)
            .add(
                format!("host.{FIXTURE_ZONE}"),
                helpers::RTYPE_A,
                60,
                rdata_a_sample(),
            )
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 1);
    }

    #[tokio::test]
    async fn test_update_rr_outside_zone_returns_notzone() {
        let fx = DnsServerFixture::default_fixture().await;
        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .add("foo.other.org", helpers::RTYPE_A, 60, rdata_a_sample())
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), rfc_rcodes::NOTZONE);
    }

    // ── 5d. Prerequisite evaluation ────────────────────────────────────────��──

    #[tokio::test]
    async fn test_prereq_rrset_exists_match_proceeds() {
        let fx = DnsServerFixture::default_fixture().await;
        fx.seed_record(FIXTURE_ZONE, "host.example.com", "A", "192.0.2.1", 60)
            .await;

        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .prereq_rrset_exists("host.example.com", helpers::RTYPE_A)
            .add("new.example.com", helpers::RTYPE_A, 60, rdata_a_sample())
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 0);
    }

    #[tokio::test]
    async fn test_prereq_rrset_exists_no_match_returns_nxrrset() {
        let fx = DnsServerFixture::default_fixture().await;
        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .prereq_rrset_exists("missing.example.com", helpers::RTYPE_A)
            .add("new.example.com", helpers::RTYPE_A, 60, rdata_a_sample())
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), rfc_rcodes::NXRRSET);
        assert!(fx.current_records().await.is_empty());
    }

    #[tokio::test]
    async fn test_prereq_rrset_does_not_exist_conflict_returns_yxrrset() {
        let fx = DnsServerFixture::default_fixture().await;
        fx.seed_record(FIXTURE_ZONE, "host.example.com", "A", "192.0.2.1", 60)
            .await;

        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .prereq_rrset_does_not_exist("host.example.com", helpers::RTYPE_A)
            .add("new.example.com", helpers::RTYPE_A, 60, rdata_a_sample())
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), rfc_rcodes::YXRRSET);
    }

    #[tokio::test]
    async fn test_prereq_name_in_use_no_match_returns_nxdomain() {
        let fx = DnsServerFixture::default_fixture().await;
        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .prereq_name_in_use("missing.example.com")
            .add("new.example.com", helpers::RTYPE_A, 60, rdata_a_sample())
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), rfc_rcodes::NXDOMAIN);
    }

    #[tokio::test]
    async fn test_prereq_name_not_in_use_conflict_returns_yxdomain() {
        let fx = DnsServerFixture::default_fixture().await;
        fx.seed_record(FIXTURE_ZONE, "host.example.com", "A", "192.0.2.1", 60)
            .await;

        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .prereq_name_not_in_use("host.example.com")
            .add("new.example.com", helpers::RTYPE_A, 60, rdata_a_sample())
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), rfc_rcodes::YXDOMAIN);
    }

    #[tokio::test]
    async fn test_prereq_value_dependent_wrong_value_returns_nxrrset() {
        let fx = DnsServerFixture::default_fixture().await;
        fx.seed_record(FIXTURE_ZONE, "host.example.com", "A", "192.0.2.1", 60)
            .await;

        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .prereq_rrset_exists_value(
                "host.example.com",
                helpers::RTYPE_A,
                helpers::rdata_a_bytes(std::net::Ipv4Addr::new(192, 0, 2, 99)),
            )
            .add("new.example.com", helpers::RTYPE_A, 60, rdata_a_sample())
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), rfc_rcodes::NXRRSET);
    }

    #[tokio::test]
    async fn test_prereq_nonzero_ttl_returns_formerr() {
        let fx = DnsServerFixture::default_fixture().await;
        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .prereq_raw(Prereq::Raw {
                name: "host.example.com".to_string(),
                rtype: helpers::RTYPE_A,
                class: 255, // ANY
                ttl: 60,
                rdata: Vec::new(),
            })
            .add("new.example.com", helpers::RTYPE_A, 60, rdata_a_sample())
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 1);
    }

    // ── 5e. Update semantics ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_add_new_rr_succeeds() {
        let fx = DnsServerFixture::default_fixture().await;
        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .add(
                "new.example.com",
                helpers::RTYPE_A,
                60,
                helpers::rdata_a_bytes(std::net::Ipv4Addr::new(203, 0, 113, 1)),
            )
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;

        assert_eq!(extract_rcode(&response), 0);
        let records = fx.current_records().await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "new.example.com");
        assert_eq!(records[0].1, "A");
        assert_eq!(records[0].2, "203.0.113.1");
    }

    #[tokio::test]
    async fn test_delete_specific_rr_succeeds() {
        let fx = DnsServerFixture::default_fixture().await;
        fx.seed_record(FIXTURE_ZONE, "host.example.com", "A", "192.0.2.1", 60)
            .await;

        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .delete_rr(
                "host.example.com",
                helpers::RTYPE_A,
                helpers::rdata_a_bytes(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            )
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;

        assert_eq!(extract_rcode(&response), 0);
        assert!(fx.current_records().await.is_empty());
    }

    #[tokio::test]
    async fn test_delete_rrset_succeeds() {
        let fx = DnsServerFixture::default_fixture().await;
        fx.seed_record(FIXTURE_ZONE, "host.example.com", "A", "192.0.2.1", 60)
            .await;

        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .delete_rrset("host.example.com", helpers::RTYPE_A)
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;

        assert_eq!(extract_rcode(&response), 0);
        assert!(fx.current_records().await.is_empty());
    }

    #[tokio::test]
    async fn test_delete_all_rrsets_succeeds() {
        let fx = DnsServerFixture::default_fixture().await;
        fx.seed_record(FIXTURE_ZONE, "host.example.com", "A", "192.0.2.1", 60)
            .await;
        fx.seed_record(FIXTURE_ZONE, "host.example.com", "AAAA", "2001:db8::1", 60)
            .await;

        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .delete_all_rrsets("host.example.com")
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;

        assert_eq!(extract_rcode(&response), 0);
        assert!(fx.current_records().await.is_empty());
    }

    #[tokio::test]
    async fn test_permission_denied_domain_returns_refused() {
        let fx =
            DnsServerFixture::build(vec![FIXTURE_ZONE.to_string(), "other.org".to_string()]).await;

        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .add(
                "evil.other.org",
                helpers::RTYPE_A,
                60,
                helpers::rdata_a_bytes(std::net::Ipv4Addr::new(203, 0, 113, 1)),
            )
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 5);
        assert!(fx.current_records().await.is_empty());
    }

    // ── 5f. Atomicity ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_atomic_update_rolls_back_on_failure() {
        let fx =
            DnsServerFixture::build(vec![FIXTURE_ZONE.to_string(), "other.org".to_string()]).await;

        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .add(
                "ok.example.com",
                helpers::RTYPE_A,
                60,
                helpers::rdata_a_bytes(std::net::Ipv4Addr::new(203, 0, 113, 1)),
            )
            .add(
                "evil.other.org",
                helpers::RTYPE_A,
                60,
                helpers::rdata_a_bytes(std::net::Ipv4Addr::new(203, 0, 113, 2)),
            )
            .build_signed(0x0001, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(extract_rcode(&response), 5);

        let records = fx.current_records().await;
        assert!(
            records.is_empty(),
            "first RR must not be applied when the second fails; got {records:?}"
        );
    }

    // ── Guards ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_response_preserves_message_id() {
        let fx = DnsServerFixture::default_fixture().await;
        let id = 0x55AA;
        let msg = UpdateMessageBuilder::new(FIXTURE_ZONE)
            .add("host.example.com", helpers::RTYPE_A, 60, rdata_a_sample())
            .build_signed(id, &fx.key);
        let response = fx.server.handle_message(&msg).await;
        assert_eq!(u16::from_be_bytes([response[0], response[1]]), id);
    }

    #[test]
    fn test_fixture_constants_are_coherent() {
        assert_eq!(FIXTURE_KEY_NAME, "client.example.com");
        assert_eq!(FIXTURE_CLIENT, "test-client");
        assert_eq!(FIXTURE_ZONE, "example.com");
    }
}
