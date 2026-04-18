#![allow(clippy::doc_markdown)]

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

// ── 5a. Authentication (RFC 2845) ─────────────────────────────────────────

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

// ── 5c. Zone section validation ──────────────────────────────────────────

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

// ── 5d. Prerequisite evaluation ──────────────────────────────────────────

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
    let fx = DnsServerFixture::build(vec![FIXTURE_ZONE.to_string(), "other.org".to_string()]).await;

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
    let fx = DnsServerFixture::build(vec![FIXTURE_ZONE.to_string(), "other.org".to_string()]).await;

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
