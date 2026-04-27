use anyhow::{Context, Result};
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::TSigResponseContext;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Build a DNS response, optionally signing it with TSIG per RFC 8945 §5.4.
///
/// When `sign_context` is `Some`, the response carries the TSIG record
/// dictated by the supplied context (signed success, signed BADTIME,
/// unsigned BADSIG stub, or unsigned BADKEY stub). When `None`, the
/// response is plain (used for messages that arrived without TSIG, for
/// pre-parse FORMERR, and for non-UPDATE opcodes).
pub(super) fn build_response(
    id: u16,
    opcode: OpCode,
    rcode: ResponseCode,
    sign_context: Option<TSigResponseContext>,
) -> Vec<u8> {
    let mut msg = Message::error_msg(id, opcode, rcode);

    if let Some(ctx) = sign_context {
        // hickory's encode_response_tbs hashes the request MAC, the
        // unsigned response wire-bytes, and the stub TSIG together.
        // Serialize once unsigned, sign, attach, then serialize again so
        // hickory writes the TSIG into the additional section and bumps
        // ARCOUNT.
        match msg.to_vec() {
            Ok(unsigned_bytes) => match ctx.sign(&unsigned_bytes) {
                Ok(tsig_record) => {
                    msg.signature = Some(tsig_record);
                }
                Err(e) => {
                    tracing::warn!(
                        error = ?e,
                        "failed to sign DNS UPDATE response; sending unsigned"
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "failed to serialize DNS UPDATE response for signing"
                );
            }
        }
    }

    msg.to_vec().unwrap_or_else(|_| {
        // Fallback: hand-rolled 12-byte header if hickory serialization fails.
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
pub(super) async fn tcp_recv(stream: &mut TcpStream) -> Result<Vec<u8>> {
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
pub(super) async fn tcp_send(stream: &mut TcpStream, msg: &[u8]) -> Result<()> {
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
