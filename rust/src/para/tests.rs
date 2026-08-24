use super::*;
use crate::sdk_adapter::{keypair_pubkey, Keypair, Signer};
use crate::test_util::create_test_transaction;
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

fn create_test_keypair() -> Keypair {
    Keypair::new()
}

/// Helper to create a ParaSigner for tests, bypassing `sk_` and UUID validation.
fn create_test_signer(api_key: &str, wallet_id: &str, base_url: Option<String>) -> ParaSigner {
    ParaSigner {
        api_key: api_key.to_string(),
        wallet_id: wallet_id.to_string(),
        api_base_url: base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
        client: reqwest::Client::builder()
            .timeout(CLIENT_TIMEOUT)
            .build()
            .unwrap(),
        public_key: Pubkey::default(),
    }
}

// --- Validation tests ---

#[test]
fn test_para_new_validates_api_key_prefix() {
    let result = ParaSigner::new(
        "bad-key".to_string(),
        "12345678-1234-1234-1234-123456789abc".to_string(),
        None,
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, SignerError::ConfigError(_)));
    assert_eq!(err.to_string(), "Configuration error");
}

#[test]
fn test_para_new_validates_wallet_id_uuid() {
    let result = ParaSigner::new("sk_test-key".to_string(), "not-a-uuid".to_string(), None);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, SignerError::ConfigError(_)));
    assert_eq!(err.to_string(), "Configuration error");
}

#[test]
fn test_para_new_validates_empty_fields() {
    let result = ParaSigner::new(
        "".to_string(),
        "12345678-1234-1234-1234-123456789abc".to_string(),
        None,
    );
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_para_new_valid() {
    let result = ParaSigner::new(
        "sk_test-key".to_string(),
        "12345678-1234-1234-1234-123456789abc".to_string(),
        None,
    );
    assert!(result.is_ok());
    let signer = result.unwrap();
    assert_eq!(signer.api_base_url, "https://api.getpara.com");
    assert_eq!(signer.public_key, Pubkey::default());
}

#[test]
fn test_para_new_custom_url_strips_trailing_slash() {
    let signer = ParaSigner::new(
        "sk_test-key".to_string(),
        "12345678-1234-1234-1234-123456789abc".to_string(),
        Some("https://custom.api.com/".to_string()),
    )
    .unwrap();
    assert_eq!(signer.api_base_url, "https://custom.api.com");
}

#[test]
fn test_uuid_validation() {
    assert!(ParaSigner::is_valid_uuid(
        "12345678-1234-1234-1234-123456789abc"
    ));
    assert!(ParaSigner::is_valid_uuid(
        "ABCDEF01-2345-6789-ABCD-EF0123456789"
    ));
    assert!(!ParaSigner::is_valid_uuid("not-a-uuid"));
    assert!(!ParaSigner::is_valid_uuid(""));
    assert!(!ParaSigner::is_valid_uuid(
        "12345678123412341234123456789abc"
    )); // no dashes
    assert!(!ParaSigner::is_valid_uuid(
        "1234567g-1234-1234-1234-123456789abc"
    )); // 'g' is not hex
}

// --- Sign before init ---

#[tokio::test]
async fn test_para_sign_before_init() {
    let signer = create_test_signer("test-api-key", "test-wallet-id", None);

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

// --- Init tests ---

#[tokio::test]
async fn test_para_init_success() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey_str = keypair_pubkey(&keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .and(header("X-API-Key", "test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": pubkey_str,
            "type": "SOLANA",
            "status": "ACTIVE"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

    let result = signer.init().await;
    assert!(result.is_ok());
    assert_eq!(signer.pubkey(), keypair_pubkey(&keypair));
}

#[tokio::test]
async fn test_para_init_case_insensitive_type() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey_str = keypair_pubkey(&keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": pubkey_str,
            "type": "Solana",
            "status": "active"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

    assert!(signer.init().await.is_ok());
}

#[tokio::test]
async fn test_para_init_non_solana_wallet() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": "0xabc123",
            "type": "EVM",
            "status": "ACTIVE"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

    let result = signer.init().await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[tokio::test]
async fn test_para_init_no_address() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "type": "SOLANA",
            "status": "ACTIVE"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

    let result = signer.init().await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[tokio::test]
async fn test_para_init_invalid_pubkey() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": "not-a-valid-pubkey",
            "type": "SOLANA",
            "status": "ACTIVE"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

    let result = signer.init().await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPublicKey(_)
    ));
}

#[tokio::test]
async fn test_para_init_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "message": "Invalid API key"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("bad-api-key", "test-wallet-id", Some(mock_server.uri()));

    let result = signer.init().await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, SignerError::RemoteApiError(_)));
    assert_eq!(err.to_string(), "Remote API error");
}

// --- Sign tests ---

#[tokio::test]
async fn test_para_sign_message() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    let tx = create_test_transaction(&keypair_pubkey(&keypair));
    let signature = keypair.sign_message(&tx.message.serialize());
    let sig_hex = hex::encode(signature);

    Mock::given(method("POST"))
        .and(path("/v1/wallets/test-wallet-id/sign-raw"))
        .and(header("X-API-Key", "test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature": sig_hex
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    let result = signer.sign_message(&tx.message.serialize()).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), signature);
}

#[tokio::test]
async fn test_para_sign_message_0x_prefix() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    let tx = create_test_transaction(&keypair_pubkey(&keypair));
    let signature = keypair.sign_message(&tx.message.serialize());
    let sig_hex = format!("0x{}", hex::encode(signature));

    Mock::given(method("POST"))
        .and(path("/v1/wallets/test-wallet-id/sign-raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature": sig_hex
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    let result = signer.sign_message(&tx.message.serialize()).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), signature);
}

#[tokio::test]
async fn test_para_sign_transaction() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    let mut tx = create_test_transaction(&keypair_pubkey(&keypair));
    let signature = keypair.sign_message(&tx.message.serialize());
    let sig_hex = hex::encode(signature);

    Mock::given(method("POST"))
        .and(path("/v1/wallets/test-wallet-id/sign-raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature": sig_hex
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_ok());
    let (serialized_tx, returned_sig) = result.unwrap().into_signed_transaction();
    assert_eq!(returned_sig, signature);
    assert!(!serialized_tx.is_empty());
}

#[tokio::test]
async fn test_para_sign_unauthorized() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    Mock::given(method("POST"))
        .and(path("/v1/wallets/test-wallet-id/sign-raw"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "message": "Unauthorized"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("bad-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
}

#[tokio::test]
async fn test_para_sign_missing_signature() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    Mock::given(method("POST"))
        .and(path("/v1/wallets/test-wallet-id/sign-raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_para_sign_invalid_hex_length() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    Mock::given(method("POST"))
        .and(path("/v1/wallets/test-wallet-id/sign-raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature": "aabbccdd"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

// --- is_available tests ---

#[tokio::test]
async fn test_para_is_available_ready() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey_str = keypair_pubkey(&keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": pubkey_str,
            "type": "SOLANA",
            "status": "READY"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    assert!(signer.is_available().await);
}

#[tokio::test]
async fn test_para_is_available_active() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey_str = keypair_pubkey(&keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": pubkey_str,
            "type": "SOLANA",
            "status": "ACTIVE"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    assert!(signer.is_available().await);
}

#[tokio::test]
async fn test_para_is_available_creating() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey_str = keypair_pubkey(&keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": pubkey_str,
            "type": "SOLANA",
            "status": "CREATING"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_para_is_available_non_solana() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": "0xabc123",
            "type": "EVM",
            "status": "ACTIVE"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_para_is_available_api_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&mock_server)
        .await;

    let signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_para_sign_invalid_hex_chars() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    // 128 chars but contains invalid hex characters ('z', 'q')
    let bad_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";

    Mock::given(method("POST"))
        .and(path("/v1/wallets/test-wallet-id/sign-raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature": bad_hex
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::SerializationError(_)
    ));
}

#[tokio::test]
async fn test_para_init_malformed_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

    let result = signer.init().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_para_sign_malformed_json() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    Mock::given(method("POST"))
        .and(path("/v1/wallets/test-wallet-id/sign-raw"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_para_init_creating_status_with_address() {
    // init() does not check status (matches TS behavior) — only is_available() does
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey_str = keypair_pubkey(&keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": pubkey_str,
            "type": "SOLANA",
            "status": "CREATING"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

    assert!(signer.init().await.is_ok());
    assert_eq!(signer.pubkey(), keypair_pubkey(&keypair));
}

#[tokio::test]
async fn test_para_init_missing_type_field() {
    let mock_server = MockServer::start().await;

    // Missing "type" field — serde deserialization should fail early
    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": "11111111111111111111111111111111",
            "status": "ACTIVE"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

    let result = signer.init().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_para_is_available_timeout() {
    let mock_server = MockServer::start().await;

    // Respond with a 10-second delay — exceeds the 5s timeout
    Mock::given(method("GET"))
        .and(path("/v1/wallets/test-wallet-id"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "id": "test-wallet-id",
                    "address": "11111111111111111111111111111111",
                    "type": "SOLANA",
                    "status": "ACTIVE"
                }))
                .set_delay(std::time::Duration::from_secs(10)),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_para_debug_hides_secrets() {
    let signer = create_test_signer("secret-api-key", "secret-wallet-id", None);

    let debug_str = format!("{:?}", signer);
    assert!(!debug_str.contains("secret-api-key"));
    assert!(!debug_str.contains("secret-wallet-id"));
    assert!(debug_str.contains("ParaSigner"));
}

#[tokio::test]
async fn test_para_error_status_code_only() {
    // Display output should stay generic and never include API response text.
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    Mock::given(method("POST"))
        .and(path("/v1/wallets/test-wallet-id/sign-raw"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "message": "Wallet is locked"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.to_string(), "Remote API error");
    assert!(!err.to_string().contains("Wallet is locked"));
}

#[test]
fn test_para_new_rejects_http_url() {
    let result = ParaSigner::new(
        "sk_test-key".to_string(),
        "12345678-1234-1234-1234-123456789abc".to_string(),
        Some("http://insecure.example.com".to_string()),
    );
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[tokio::test]
async fn test_para_sign_verification_failure() {
    // If API returns a bad signature that doesn't verify, we should get an error
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    // Return a valid-format but wrong signature (64 zero bytes)
    let bad_sig_hex = "00".repeat(64);

    Mock::given(method("POST"))
        .and(path("/v1/wallets/test-wallet-id/sign-raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature": bad_sig_hex
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
    signer.public_key = keypair_pubkey(&keypair);

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}
