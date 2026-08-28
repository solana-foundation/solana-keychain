use super::*;
use crate::sdk_adapter::{keypair_pubkey, keypair_sign_message, Keypair};
use crate::test_util::create_test_transaction;
use base64::{engine::general_purpose::STANDARD, Engine};
use wiremock::{
    matchers::{header_exists, method, path_regex},
    Mock, MockServer, ResponseTemplate,
};

const TEST_PUBKEY: &str = "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV";
const TEST_ACCOUNT_ID: &str = "acc_e0b84653-1741-4a3d-9e91-2b0fd2942f60";

/// Minimal valid P-256 PKCS#8 DER, base64-encoded.
/// Scalar is `[0x01; 32]`, which is in the valid range `[1, n-1]`.
fn test_wallet_secret_b64() -> String {
    #[rustfmt::skip]
        const P256_PKCS8_DER: &[u8] = &[
            0x30, 0x41,
            0x02, 0x01, 0x00,
            0x30, 0x13,
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x04, 0x27,
            0x30, 0x25,
            0x02, 0x01, 0x01,
            0x04, 0x20,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];
    STANDARD.encode(P256_PKCS8_DER)
}

/// Same key wrapped in PEM headers — used to exercise the PEM-input path.
fn test_wallet_secret_pem() -> String {
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        test_wallet_secret_b64()
    )
}

/// Bare base64 form, the shape the Openfort dashboard and env vars deliver.
fn test_wallet_secret() -> String {
    test_wallet_secret_b64()
}

/// Build a signer pointing at the mock server, with `public_key` pre-set
/// so individual tests can skip exercising `init()`.
fn create_test_signer(base_url: &str) -> OpenfortSigner {
    let api_host =
        wallet_jwt::extract_host(base_url, "Openfort").expect("failed to parse test base URL");
    OpenfortSigner {
        secret_key: "sk_test_secret".to_string(),
        account_id: TEST_ACCOUNT_ID.to_string(),
        wallet_secret: test_wallet_secret(),
        public_key: Some(Pubkey::from_str(TEST_PUBKEY).unwrap()),
        api_base_url: base_url.to_string(),
        api_host,
        client: reqwest::Client::new(),
    }
}

#[test]
fn test_new_valid() {
    let signer = OpenfortSigner::new(
        "sk_test_secret".to_string(),
        TEST_ACCOUNT_ID.to_string(),
        test_wallet_secret(),
    );
    assert!(signer.is_ok());
    assert!(signer.unwrap().public_key.is_none());
}

#[test]
fn test_new_rejects_empty_fields() {
    let cases = [
        ("", TEST_ACCOUNT_ID, test_wallet_secret()),
        ("sk_test_secret", "", test_wallet_secret()),
        ("sk_test_secret", TEST_ACCOUNT_ID, String::new()),
    ];

    for (sk, account, secret) in cases {
        let result = OpenfortSigner::new(sk.to_string(), account.to_string(), secret);
        assert!(
            result.is_err(),
            "expected ConfigError for inputs with an empty field"
        );
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }
}

#[test]
fn test_debug_does_not_leak_secrets() {
    let signer = create_test_signer("http://localhost");
    let debug_str = format!("{signer:?}");
    assert!(!debug_str.contains("sk_test_secret"));
    assert!(!debug_str.contains(&test_wallet_secret()));
    assert!(debug_str.contains("OpenfortSigner"));
}

/// Build an uninitialized signer pointing at the wiremock server with a
/// plain HTTP client (the production builder forces https_only).
fn create_uninitialized_test_signer(base_url: &str) -> OpenfortSigner {
    let api_host =
        wallet_jwt::extract_host(base_url, "Openfort").expect("failed to parse test base URL");
    OpenfortSigner {
        secret_key: "sk_test_secret".to_string(),
        account_id: TEST_ACCOUNT_ID.to_string(),
        wallet_secret: test_wallet_secret(),
        public_key: None,
        api_base_url: base_url.to_string(),
        api_host,
        client: reqwest::Client::new(),
    }
}

#[tokio::test]
async fn test_init_fetches_address() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/v2/accounts/{TEST_ACCOUNT_ID}$")))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "address": TEST_PUBKEY,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_uninitialized_test_signer(&mock_server.uri());
    signer.init().await.unwrap();
    assert_eq!(signer.pubkey().to_string(), TEST_PUBKEY);
}

#[tokio::test]
async fn test_init_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/v2/accounts/{TEST_ACCOUNT_ID}$")))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_uninitialized_test_signer(&mock_server.uri());
    let err = signer.init().await.unwrap_err();
    assert!(matches!(err, SignerError::RemoteApiError { .. }));
}

#[tokio::test]
async fn test_init_rejects_non_solana_address() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/v2/accounts/{TEST_ACCOUNT_ID}$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_uninitialized_test_signer(&mock_server.uri());
    let err = signer.init().await.unwrap_err();
    assert!(matches!(err, SignerError::InvalidPublicKey(_)));
}

#[tokio::test]
async fn test_is_available_uninitialized_returns_false() {
    // Uninitialized signers must short-circuit without issuing a request.
    let signer = create_uninitialized_test_signer("http://localhost");
    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_is_available_returns_true_when_address_matches() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/v2/accounts/{TEST_ACCOUNT_ID}$")))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "address": TEST_PUBKEY,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let signer = create_test_signer(&mock_server.uri());
    assert!(signer.is_available().await);
}

#[tokio::test]
async fn test_is_available_returns_false_when_address_changed() {
    let mock_server = MockServer::start().await;
    let other_pubkey = keypair_pubkey(&Keypair::new()).to_string();

    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/v2/accounts/{TEST_ACCOUNT_ID}$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "address": other_pubkey,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let signer = create_test_signer(&mock_server.uri());
    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_is_available_returns_false_on_remote_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/v2/accounts/{TEST_ACCOUNT_ID}$")))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&mock_server)
        .await;

    let signer = create_test_signer(&mock_server.uri());
    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_sign_message_requires_init() {
    let signer = OpenfortSigner::new(
        "sk_test_secret".to_string(),
        TEST_ACCOUNT_ID.to_string(),
        test_wallet_secret(),
    )
    .unwrap();

    let err = signer.sign_message(b"test").await.unwrap_err();
    assert!(matches!(err, SignerError::ConfigError(_)));
}

#[tokio::test]
async fn test_sign_message_invalid_wallet_secret() {
    let mut signer = create_test_signer("http://localhost");
    signer.wallet_secret = "not-a-pem-key".to_string();

    let result = signer.sign_message(b"test").await;
    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPrivateKey(_)
    ));
}

#[tokio::test]
async fn test_sign_message_success() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();
    let pubkey = keypair_pubkey(&keypair);

    let test_message = b"test message";
    let signature = keypair_sign_message(&keypair, test_message);
    let sig_hex = format!("0x{}", hex::encode(signature.as_ref()));

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = Some(pubkey);

    Mock::given(method("POST"))
        .and(path_regex(format!(
            r"^/v2/accounts/backend/{TEST_ACCOUNT_ID}/sign$"
        )))
        .and(header_exists("authorization"))
        .and(header_exists("x-wallet-auth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "signature",
            "account": TEST_ACCOUNT_ID,
            "signature": sig_hex,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(test_message).await;
    assert!(result.is_ok(), "sign_message failed: {:?}", result.err());
    assert_eq!(result.unwrap().as_ref(), signature.as_ref());
}

#[tokio::test]
async fn test_sign_message_signature_verification_failure() {
    let mock_server = MockServer::start().await;
    let signing_keypair = Keypair::new();
    let other_keypair = Keypair::new();
    let test_message = b"test message";
    let signature = keypair_sign_message(&signing_keypair, test_message);
    let sig_hex = format!("0x{}", hex::encode(signature.as_ref()));

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = Some(keypair_pubkey(&other_keypair));

    Mock::given(method("POST"))
        .and(path_regex(r".*/sign$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "signature",
            "account": TEST_ACCOUNT_ID,
            "signature": sig_hex,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(test_message).await;
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_sign_message_invalid_signature_length() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    Mock::given(method("POST"))
        .and(path_regex(r".*/sign$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "signature",
            "account": TEST_ACCOUNT_ID,
            "signature": "0x1234",
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_sign_message_invalid_hex_signature() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    Mock::given(method("POST"))
        .and(path_regex(r".*/sign$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "signature",
            "account": TEST_ACCOUNT_ID,
            "signature": "0xZZZZ",
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(matches!(
        result.unwrap_err(),
        SignerError::SerializationError(_)
    ));
}

#[tokio::test]
async fn test_sign_unauthorized() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    Mock::given(method("POST"))
        .and(path_regex(r".*/sign$"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError { .. }
    ));
}

#[tokio::test]
async fn test_sign_transaction_success() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();
    let pubkey = keypair_pubkey(&keypair);

    let mut tx = create_test_transaction(&pubkey);
    let signature = keypair_sign_message(&keypair, &tx.message.serialize());
    let sig_hex = format!("0x{}", hex::encode(signature.as_ref()));

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = Some(pubkey);

    Mock::given(method("POST"))
        .and(path_regex(r".*/sign$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "signature",
            "account": TEST_ACCOUNT_ID,
            "signature": sig_hex,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_transaction(&mut tx).await;
    assert!(
        result.is_ok(),
        "sign_transaction failed: {:?}",
        result.err()
    );

    let (returned_base64, returned_sig) = result.unwrap().into_signed_transaction();
    assert!(!returned_base64.is_empty());
    assert_eq!(returned_sig.as_ref(), signature.as_ref());
}

#[tokio::test]
async fn test_clone() {
    let signer = create_test_signer("http://localhost");
    let clone = signer.clone();
    assert_eq!(signer.pubkey(), clone.pubkey());
}

#[test]
fn test_wallet_secret_to_pem_passthrough_for_pem_input() {
    let pem = test_wallet_secret_pem();
    assert_eq!(wallet_secret_to_pem(&pem), pem);
}

#[test]
fn test_wallet_secret_to_pem_wraps_bare_base64() {
    let bare = test_wallet_secret_b64();
    let pem = wallet_secret_to_pem(&bare);
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(pem.contains(&bare));
    assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
    // The wrapped form must still be parseable by jsonwebtoken — exercise it.
    EncodingKey::from_ec_pem(pem.as_bytes()).expect("wrapped PEM should parse");
}

#[test]
fn test_wallet_secret_to_pem_strips_whitespace_in_bare_input() {
    let bare = test_wallet_secret_b64();
    let with_whitespace = format!(" {}\n  {}  ", &bare[..20], &bare[20..]);
    let pem = wallet_secret_to_pem(&with_whitespace);
    EncodingKey::from_ec_pem(pem.as_bytes()).expect("whitespaced base64 should still parse");
}

#[test]
fn test_from_config_trims_trailing_slashes() {
    let signer = OpenfortSigner::from_config(OpenfortSignerConfig {
        secret_key: "sk_test_secret".to_string(),
        account_id: TEST_ACCOUNT_ID.to_string(),
        wallet_secret: test_wallet_secret(),
        api_base_url: Some("https://api.openfort.io///".to_string()),
        http_client_config: None,
    })
    .unwrap();
    assert_eq!(signer.api_base_url, "https://api.openfort.io");
}

#[test]
fn test_from_config_rejects_non_https_base_url() {
    let result = OpenfortSigner::from_config(OpenfortSignerConfig {
        secret_key: "sk_test_secret".to_string(),
        account_id: TEST_ACCOUNT_ID.to_string(),
        wallet_secret: test_wallet_secret(),
        api_base_url: Some("http://api.openfort.io".to_string()),
        http_client_config: None,
    });
    match result {
        Err(SignerError::ConfigError(msg)) => {
            assert!(msg.contains("HTTPS"), "unexpected error message: {msg}");
        }
        other => panic!("expected ConfigError for non-HTTPS base URL, got {other:?}"),
    }
}

/// A dot-segment account id must become one percent-encoded path segment, so
/// the URL cannot be retargeted and the JWT `uris` claim keeps matching it.
#[test]
fn test_paths_escape_the_account_id_as_one_segment() {
    let mut signer = create_uninitialized_test_signer("https://api.openfort.xyz");
    signer.account_id = "acc_a/../acc_b".to_string();

    assert_eq!(signer.account_path(), "/v2/accounts/acc_a%2F..%2Facc_b");
    assert_eq!(
        signer.sign_path(),
        "/v2/accounts/backend/acc_a%2F..%2Facc_b/sign"
    );
}
