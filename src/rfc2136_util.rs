//! Herald ↔ hickory-dns adapter.
//!
//! Provides type conversions between Herald's internal `RecordValue` enum and
//! hickory-proto's `RData` type, plus TSIG key loading.
//!
//! # hickory-dns 0.26 API notes (verified against source, 2026-04-16)
//!
//! - **TSIG signer attachment**: `DnsMultiplexer::with_signer(tsigner)` on the
//!   stream before constructing `Client::from_sender(multiplexer)`. The
//!   multiplexer auto-signs messages matching `TSigner::should_sign_message`
//!   (UPDATE, NOTIFY, AXFR/IXFR queries).
//! - **UPDATE message sections**: `Message` has public fields `queries` (zone),
//!   `answers` (prereqs), `authorities` (update RRs), `additionals`.
//! - **AXFR TSIG verification**: `DnsMultiplexer` holds a `TSigVerifier` that
//!   auto-verifies each response in the multi-message AXFR chain.

use crate::provider::RecordValue;
use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::rdata::{self, A, AAAA, CNAME, MX, NS, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordSet, TSigner};

// ── RecordValue ↔ RData conversions ──────────────────────────────────────────

impl TryFrom<&RecordValue> for RData {
    type Error = anyhow::Error;

    fn try_from(value: &RecordValue) -> Result<Self> {
        match value {
            RecordValue::A(ip) => Ok(RData::A(A(*ip))),
            RecordValue::AAAA(ip) => Ok(RData::AAAA(AAAA(*ip))),
            RecordValue::CNAME(name) => {
                let n = Name::from_ascii(name)
                    .with_context(|| format!("invalid CNAME target: {name}"))?;
                Ok(RData::CNAME(CNAME(n)))
            }
            RecordValue::TXT(text) => Ok(RData::TXT(TXT::new(vec![text.clone()]))),
            RecordValue::MX { priority, exchange } => {
                let ex = Name::from_ascii(exchange)
                    .with_context(|| format!("invalid MX exchange: {exchange}"))?;
                Ok(RData::MX(MX::new(*priority, ex)))
            }
            RecordValue::NS(name) => {
                let n =
                    Name::from_ascii(name).with_context(|| format!("invalid NS target: {name}"))?;
                Ok(RData::NS(NS(n)))
            }
            RecordValue::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                let t = Name::from_ascii(target)
                    .with_context(|| format!("invalid SRV target: {target}"))?;
                Ok(RData::SRV(rdata::SRV::new(*priority, *weight, *port, t)))
            }
            RecordValue::CAA {
                flags, value: val, ..
            } => Ok(RData::CAA(rdata::CAA::new_issue(
                *flags != 0,
                Some(Name::from_ascii(val).unwrap_or_else(|_| Name::root())),
                vec![],
            ))),
        }
    }
}

impl TryFrom<&RData> for RecordValue {
    type Error = anyhow::Error;

    #[allow(clippy::similar_names)] // txt/text are the standard TXT record data vs. decoded text
    fn try_from(rdata: &RData) -> Result<Self> {
        match rdata {
            RData::A(a) => Ok(RecordValue::A(a.0)),
            RData::AAAA(aaaa) => Ok(RecordValue::AAAA(aaaa.0)),
            RData::CNAME(cname) => Ok(RecordValue::CNAME(cname.0.to_utf8())),
            RData::TXT(txt) => {
                let text = txt
                    .txt_data
                    .iter()
                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                    .collect::<String>();
                Ok(RecordValue::TXT(text))
            }
            RData::MX(mx) => Ok(RecordValue::MX {
                priority: mx.preference,
                exchange: mx.exchange.to_utf8(),
            }),
            RData::NS(ns) => Ok(RecordValue::NS(ns.0.to_utf8())),
            RData::SRV(srv) => Ok(RecordValue::SRV {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                target: srv.target.to_utf8(),
            }),
            _ => anyhow::bail!("unsupported RData type for Herald: {rdata:?}"),
        }
    }
}

// ── Helper: build a RecordSet from Herald types ──────────────────────────────

/// Build a single-record `RecordSet` from Herald's enriched record fields.
pub(crate) fn build_record_set(name: &str, value: &RecordValue, ttl: u32) -> Result<RecordSet> {
    let dns_name =
        Name::from_ascii(name).with_context(|| format!("invalid record name: {name}"))?;
    let rdata = RData::try_from(value)?;
    let rtype = rdata.record_type();
    let record = Record::from_rdata(dns_name.clone(), ttl, rdata);
    let mut rrset = RecordSet::new(dns_name, rtype, 0);
    rrset.insert(record, 0);
    Ok(rrset)
}

// ── TSIG key loading ─────────────────────────────────────────────────────────

/// Load a `TSigner` from a base64-encoded secret file.
///
/// The file is expected to contain a single base64-encoded HMAC secret
/// (with or without trailing newline), as generated by `tsig-keygen`.
pub(crate) async fn load_tsigner_from_file(
    key_name: &str,
    path: &str,
    algorithm: TsigAlgorithm,
    fudge: u16,
) -> Result<TSigner> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("reading TSIG key file: {path}"))?;
    let secret = BASE64
        .decode(content.trim())
        .context("decoding TSIG secret from base64")?;
    let name =
        Name::from_ascii(key_name).with_context(|| format!("invalid TSIG key name: {key_name}"))?;
    TSigner::new(secret, algorithm, name, fudge)
        .map_err(|e| anyhow::anyhow!("creating TSigner: {e}"))
}

/// Default TSIG fudge: permitted clock skew in seconds.
pub(crate) const TSIG_FUDGE: u16 = 300;
