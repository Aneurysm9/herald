use anyhow::{Context, Result};
use hickory_proto::op::{Message, OpCode, ResponseCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Build a minimal DNS response (header only, all counts zero).
pub(super) fn build_response(id: u16, opcode: OpCode, rcode: ResponseCode) -> Vec<u8> {
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
