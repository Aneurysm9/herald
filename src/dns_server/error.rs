use hickory_proto::op::ResponseCode;

/// Errors that can occur during DNS UPDATE processing.
pub(super) enum DnsError {
    NotAuth,
    Refused(String),
    FormErr(String),
    NotZone(String),
    /// Prerequisite check failed with a specific RFC 2136 RCODE.
    PrereqFailed(ResponseCode),
}
