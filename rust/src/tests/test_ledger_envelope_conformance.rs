//! Conformance check of our off-chain envelope against `LedgerHQ/app-solana`.
//!
//! Why this exists. [`crate::ledger::ledger_offchain_envelope`] hand-builds an
//! 85-byte header because the obvious choice, `solana_offchain_message`'s
//! serializer, emits a *different* 20-byte layout that the device rejects
//! outright. That divergence is invisible from inside this repo: our unit tests
//! assert our bytes against our own constant, so if the app changed its header
//! we would keep producing a well-formed envelope that no device would sign, and
//! nothing would go red until someone plugged in hardware.
//!
//! So this asserts our layout against the app's own source, and it is
//! `#[ignore]`d because it reaches the network. Run it with:
//!
//! ```bash
//! just rust-test-ledger-conformance
//! ```
//!
//! ## Why a commit SHA and not a tag
//!
//! Off-chain message signing is not in any released tag: `v1.0.2`, the newest,
//! returns 404 for the file, and it exists only on `develop`, which is the
//! repository's default branch. Pinning `develop` would mean this test's meaning
//! changes under us without a commit here, which is the same supply-chain
//! failure mode as following a moving branch in someone else's repository. So it
//! pins a SHA. When it fails because upstream moved, read the diff, decide
//! whether our layout must change, and bump the pin deliberately.

#![cfg(feature = "ledger")]

/// `libsol/include/sol/offchain_message_signing.h` and
/// `libsol/offchain_message_signing.c`, at the commit the source-level audit
/// reviewed.
const APP_SOLANA_PIN: &str = "c855c1a0ea12e76406efbfd17203ecf419952e27";

fn raw_url(path: &str) -> String {
    format!("https://raw.githubusercontent.com/LedgerHQ/app-solana/{APP_SOLANA_PIN}/{path}")
}

fn fetch(path: &str) -> String {
    let url = raw_url(path);
    let out = std::process::Command::new("curl")
        .args(["-sS", "--fail", "--max-time", "30", &url])
        .output()
        .unwrap_or_else(|e| panic!("could not run curl for {url}: {e}"));
    assert!(
        out.status.success(),
        "fetch failed for {url}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("app-solana source is UTF-8")
}

/// Read a `#define NAME <integer>` out of a C header.
fn define_usize(src: &str, name: &str) -> usize {
    let line = src
        .lines()
        .find(|l| l.trim_start().starts_with(&format!("#define {name} ")))
        .unwrap_or_else(|| panic!("upstream no longer defines {name}"));
    line.split_whitespace()
        .nth(2)
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("could not parse a number out of: {line}"))
}

#[test]
#[ignore = "reaches the network; run via `just rust-test-ledger-conformance`"]
fn our_header_length_matches_the_app_solana_definition() {
    let header = fetch("libsol/include/sol/offchain_message_signing.h");
    let signing_domain_len = define_usize(&header, "OFFCHAIN_MESSAGE_SIGNING_DOMAIN_LENGTH");
    let application_domain_len =
        define_usize(&header, "OFFCHAIN_MESSAGE_APPLICATION_DOMAIN_LENGTH");

    // The app computes the header length itself, in
    // `get_offchain_message_header_length`. Rather than restate its arithmetic,
    // assert the source still says what we built against: for version 0 the
    // common part is signing_domain + version(1) + signer_count(1) +
    // PUBKEY_SIZE * signers, and v0 adds application_domain + format(1) +
    // message_length(2).
    let impl_src = fetch("libsol/offchain_message_signing.c");
    for expected in [
        "OFFCHAIN_MESSAGE_SIGNING_DOMAIN_LENGTH + 1 + 1 +",
        "(PUBKEY_SIZE * header->signers_length)",
        "base_length += OFFCHAIN_MESSAGE_APPLICATION_DOMAIN_LENGTH + 1 + 2;",
    ] {
        assert!(
            impl_src.contains(expected),
            "app-solana's header-length arithmetic changed; expected to find `{expected}`. \
             Re-read get_offchain_message_header_length and update our envelope."
        );
    }

    const PUBKEY_SIZE: usize = 32;
    let upstream_v0_one_signer =
        signing_domain_len + 1 + 1 + PUBKEY_SIZE + application_domain_len + 1 + 2;

    // The value our envelope is built from. Derived here rather than imported so
    // this test fails loudly if either side moves.
    let ours =
        crate::ledger::ledger_offchain_envelope(&crate::sdk_adapter::Pubkey::from([0u8; 32]), b"x")
            .expect("envelope builds")
            .len()
            - 1; // minus the one-byte payload

    assert_eq!(
        ours, upstream_v0_one_signer,
        "our off-chain header is {ours} bytes but app-solana's v0 single-signer header is \
         {upstream_v0_one_signer}. A device will reject our envelope."
    );
    assert_eq!(
        upstream_v0_one_signer, 85,
        "the layout we verified on hardware"
    );
}

#[test]
#[ignore = "reaches the network; run via `just rust-test-ledger-conformance`"]
fn our_field_order_matches_the_documented_v0_layout() {
    // The header documents V0 field-by-field. Length agreement alone would not
    // catch a reordering, and a reordered envelope of the right size is exactly
    // the failure that reaches a device instead of a test.
    let header = fetch("libsol/include/sol/offchain_message_signing.h");
    let v0 = header
        .split("V0 layout:")
        .nth(1)
        .and_then(|s| s.split("V1 layout").next())
        .expect("upstream still documents the V0 layout");

    for (n, field) in [
        (1, "Signing domain (16 bytes)"),
        (2, "Header version (1 byte) = 0x00"),
        (3, "Application domain (32 bytes)"),
        (4, "Message format (1 byte)"),
        (5, "Signer count (1 byte)"),
        (6, "Signers (signer_count * 32 bytes)"),
        (7, "Message length (2 bytes, LE)"),
    ] {
        let marker = format!("{n}. {field}");
        assert!(
            v0.contains(&marker),
            "app-solana's documented V0 layout no longer has `{marker}`. Our envelope encodes \
             exactly this order, so re-read the header before changing anything."
        );
    }

    // And our bytes really are in that order.
    let signer = crate::sdk_adapter::Pubkey::from([9u8; 32]);
    let envelope = crate::ledger::ledger_offchain_envelope(&signer, b"hi").expect("builds");
    assert_eq!(
        &envelope[0..16],
        b"\xffsolana offchain",
        "1. signing domain"
    );
    assert_eq!(envelope[16], 0x00, "2. header version");
    assert_eq!(&envelope[17..49], &[0u8; 32], "3. application domain");
    assert_eq!(envelope[49], 0, "4. message format");
    assert_eq!(envelope[50], 1, "5. signer count");
    assert_eq!(&envelope[51..83], &[9u8; 32], "6. signers");
    assert_eq!(
        &envelope[83..85],
        &2u16.to_le_bytes(),
        "7. message length, LE"
    );
    assert_eq!(&envelope[85..], b"hi", "8. message body");
}

#[test]
#[ignore = "reaches the network; run via `just rust-test-ledger-conformance`"]
fn we_are_aware_of_the_v1_layout_the_app_also_accepts() {
    // Not a conformance failure: we deliberately emit V0, which the app still
    // parses. This exists so the V1 layout (sRFC 38) cannot appear, or change,
    // without someone here noticing. V1 drops the application domain and the
    // length prefix and requires sorted unique signers, so adopting it is a
    // real envelope change and not a version bump.
    let header = fetch("libsol/include/sol/offchain_message_signing.h");
    assert!(
        header.contains("V1 layout (sRFC 38)"),
        "app-solana's V1 layout section moved or was renamed; re-check whether V0 is still \
         accepted before shipping"
    );
    assert!(
        header.contains("Header version (1 byte) = 0x01"),
        "V1's version byte changed"
    );
}
