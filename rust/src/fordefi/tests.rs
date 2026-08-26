use super::*;
use crate::sdk_adapter::{keypair_pubkey, Keypair, Signer as SdkSigner};
use crate::test_util::{add_required_signer, create_test_transaction};
use p256::ecdsa::SigningKey;
use wiremock::{
    matchers::{header, method, path, path_regex},
    Mock, MockServer, ResponseTemplate,
};

fn create_test_keypair() -> Keypair {
    Keypair::new()
}

/// Generate a test PEM key string (SEC1-encoded ECDSA P-256).
fn test_pem_key() -> String {
    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let secret_key: p256::SecretKey = signing_key.into();
    secret_key
        .to_sec1_pem(p256::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string()
}

fn test_request_signer() -> Arc<dyn FordefiRequestSigner> {
    Arc::new(PemRequestSigner::from_pem(&test_pem_key()).unwrap())
}

/// Exercise the synchronous local-validation/build phase directly, without
/// going through the async public constructor.
fn build_test_signer_from_config(
    config: FordefiSignerConfig,
) -> Result<FordefiSigner, SignerError> {
    FordefiSigner::build(config)
}

fn base_test_config() -> FordefiSignerConfig {
    FordefiSignerConfig {
        access_token: "test-token".to_string(),
        vault_id: "test-vault-id".to_string(),
        private_key_pem: Some(test_pem_key()),
        request_signer: None,
        public_key: "11111111111111111111111111111111".to_string(),
        api_base_url: None,
        poll_interval_ms: None,
        max_poll_attempts: None,
        http_client_config: None,
        chain: None,
        fee: None,
    }
}

fn test_config(base_url: &str, public_key: Pubkey) -> FordefiSignerConfig {
    FordefiSignerConfig {
        public_key: public_key.to_string(),
        api_base_url: Some(base_url.to_string()),
        poll_interval_ms: Some(10),
        max_poll_attempts: Some(3),
        ..base_test_config()
    }
}

/// Build a FordefiSigner for tests with the given request signer and chain.
fn create_test_signer_with(
    base_url: &str,
    pubkey: Pubkey,
    request_signer: Arc<dyn FordefiRequestSigner>,
    chain: Option<SolanaChainUniqueId>,
) -> FordefiSigner {
    FordefiSigner {
        access_token: "test-token".to_string(),
        vault_id: "test-vault-id".to_string(),
        request_signer,
        api_base_url: base_url.to_string(),
        client: reqwest::Client::builder().build().unwrap(),
        public_key: pubkey,
        poll_interval_ms: 10,
        max_poll_attempts: 3,
        chain,
        fee: None,
    }
}

/// Helper to build a black-box FordefiSigner for tests with a mock server URL.
fn create_test_signer(base_url: &str, pubkey: Pubkey) -> FordefiSigner {
    create_test_signer_with(base_url, pubkey, test_request_signer(), None)
}

/// Helper to build a native-Solana FordefiSigner for tests.
fn create_native_test_signer(base_url: &str, pubkey: Pubkey) -> FordefiSigner {
    create_test_signer_with(
        base_url,
        pubkey,
        test_request_signer(),
        Some(SolanaChainUniqueId::SolanaMainnet),
    )
}

#[test]
fn test_broadcasts_transactions_by_mode() {
    let pubkey = Pubkey::new_unique();
    assert!(!create_test_signer("https://example.com", pubkey).broadcasts_transactions());
    assert!(create_native_test_signer("https://example.com", pubkey).broadcasts_transactions());
}

/// Build a mock wire transaction: [1 byte sig_count][64-byte signature][message bytes]
fn build_mock_wire_transaction(keypair: &Keypair, message_bytes: &[u8]) -> Vec<u8> {
    let signature = keypair.sign_message(message_bytes);
    let sig_bytes = signature.as_ref();
    let mut wire = Vec::with_capacity(1 + 64 + message_bytes.len());
    wire.push(1u8); // sig_count = 1
    wire.extend_from_slice(sig_bytes);
    wire.extend_from_slice(message_bytes);
    wire
}

// --- Config validation tests ---

#[test]
fn test_fordefi_config_empty_access_token() {
    let result = build_test_signer_from_config(FordefiSignerConfig {
        access_token: String::new(),
        ..base_test_config()
    });
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_fordefi_config_empty_vault_id() {
    let result = build_test_signer_from_config(FordefiSignerConfig {
        vault_id: String::new(),
        ..base_test_config()
    });
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_fordefi_config_invalid_pem() {
    let result = build_test_signer_from_config(FordefiSignerConfig {
        private_key_pem: Some("not-a-valid-pem".to_string()),
        ..base_test_config()
    });
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPrivateKey(_)
    ));
}

#[test]
fn test_fordefi_config_invalid_pubkey() {
    let result = build_test_signer_from_config(FordefiSignerConfig {
        public_key: "not-a-pubkey".to_string(),
        ..base_test_config()
    });
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPublicKey(_)
    ));
}

#[test]
fn test_fordefi_config_rejects_http_url() {
    let result = build_test_signer_from_config(FordefiSignerConfig {
        api_base_url: Some("http://insecure.example.com".to_string()),
        ..base_test_config()
    });
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_fordefi_config_rejects_malformed_https_url() {
    let result = build_test_signer_from_config(FordefiSignerConfig {
        api_base_url: Some("https://".to_string()),
        ..base_test_config()
    });

    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_fordefi_config_fee_without_chain_rejected() {
    let result = build_test_signer_from_config(FordefiSignerConfig {
        fee: Some(FordefiSolanaFee::Priority {
            priority_level: FordefiPriorityLevel::High,
        }),
        ..base_test_config()
    });
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_fordefi_config_zero_poll_interval_rejected() {
    let result = build_test_signer_from_config(FordefiSignerConfig {
        poll_interval_ms: Some(0),
        ..base_test_config()
    });
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_fordefi_config_zero_max_poll_attempts_rejected() {
    let result = build_test_signer_from_config(FordefiSignerConfig {
        max_poll_attempts: Some(0),
        ..base_test_config()
    });
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_fordefi_config_with_chain_valid() {
    let result = build_test_signer_from_config(FordefiSignerConfig {
        chain: Some(SolanaChainUniqueId::SolanaDevnet),
        ..base_test_config()
    });
    assert!(result.is_ok());
}

#[test]
fn test_fordefi_config_valid() {
    let keypair = create_test_keypair();
    let pubkey_str = keypair_pubkey(&keypair).to_string();

    let result = build_test_signer_from_config(FordefiSignerConfig {
        public_key: pubkey_str,
        ..base_test_config()
    });
    assert!(result.is_ok());
    let signer = result.unwrap();
    assert_eq!(signer.api_base_url, "https://api.fordefi.com");
    assert_eq!(signer.public_key, keypair_pubkey(&keypair));
}

#[test]
fn test_fordefi_config_strips_trailing_slash() {
    let result = build_test_signer_from_config(FordefiSignerConfig {
        api_base_url: Some("https://custom.api.com/".to_string()),
        ..base_test_config()
    });
    assert!(result.is_ok());
    assert_eq!(result.unwrap().api_base_url, "https://custom.api.com");
}

// --- Construction trust-model tests ---

#[tokio::test]
async fn test_fordefi_from_config_trusts_configured_public_key() {
    // No server exists at this base URL: construction must not touch the network.
    let public_key = keypair_pubkey(&create_test_keypair());

    let signer =
        FordefiSigner::from_config(test_config("https://api.test.fordefi.com", public_key))
            .await
            .unwrap();

    assert_eq!(signer.pubkey(), public_key);
}

// --- sign_message tests ---

#[tokio::test]
async fn test_fordefi_sign_message_success() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    let message = b"hello fordefi message signing";
    let real_signature = keypair.sign_message(message);
    let sig_b64 = STANDARD.encode(real_signature.as_ref());

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .and(header("Authorization", "Bearer test-token"))
        .and(wiremock::matchers::body_partial_json(serde_json::json!({
            "type": "black_box_signature",
            "details": { "format": "hash_binary" }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "msg-1"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/msg-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "completed",
            "signatures": [{ "data": sig_b64 }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(message).await;
    assert!(result.is_ok(), "sign_message failed: {:?}", result.err());
    assert_eq!(result.unwrap(), real_signature);
}

#[tokio::test]
async fn test_fordefi_sign_message_verification_failure() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    // Mock returns a signature for a *different* message than the one we sign
    let bogus_signature = keypair.sign_message(b"different message");
    let sig_b64 = STANDARD.encode(bogus_signature.as_ref());

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "msg-bad"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/msg-bad"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "completed",
            "signatures": [{ "data": sig_b64 }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"actual message").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_fordefi_sign_message_missing_signatures() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "msg-empty"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/msg-empty"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "completed"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_fordefi_sign_message_failed_state() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "msg-fail"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/msg-fail"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "aborted"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

// --- Sign transaction tests ---

#[tokio::test]
async fn test_fordefi_sign_transaction_success() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    let tx = create_test_transaction(&pubkey);
    let message_data = tx.message.serialize();
    let real_signature = keypair.sign_message(&message_data);
    let sig_b64 = STANDARD.encode(real_signature.as_ref());

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .and(header("Authorization", "Bearer test-token"))
        .and(wiremock::matchers::body_partial_json(serde_json::json!({
            "type": "black_box_signature",
            "details": { "format": "hash_binary" }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-123"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/tx-123"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "completed",
            "signatures": [{ "data": sig_b64 }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut tx = tx;
    let result = signer.sign_transaction(&mut tx).await;
    assert!(
        result.is_ok(),
        "sign_transaction failed: {:?}",
        result.err()
    );
    let (serialized_tx, _sig) = result.unwrap().into_signed_transaction();
    assert!(!serialized_tx.is_empty());
}

#[tokio::test]
async fn test_fordefi_sign_transaction_failed_state() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-fail"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/tx-fail"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "aborted"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_fordefi_sign_transaction_poll_timeout() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-pending"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Always return pending state
    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/tx-pending"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "pending_signature"
        })))
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
}

#[tokio::test]
async fn test_fordefi_submit_unauthorized() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "message": "Invalid token"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, SignerError::RemoteApiError(_)));
    assert_eq!(err.to_string(), "Remote API error");
}

#[tokio::test]
async fn test_fordefi_sign_transaction_missing_signatures() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-no-sig"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/tx-no-sig"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "completed"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

// --- is_available tests ---

#[tokio::test]
async fn test_fordefi_is_available_success() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("GET"))
        .and(path_regex("/api/v1/vaults/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-vault-id"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(signer.is_available().await);
}

#[tokio::test]
async fn test_fordefi_is_available_checks_request_signer() {
    let mock_server = MockServer::start().await;
    let public_key = keypair_pubkey(&create_test_keypair());
    let signer = create_test_signer_with(
        &mock_server.uri(),
        public_key,
        Arc::new(FailingSigner),
        None,
    );

    Mock::given(method("GET"))
        .and(path_regex("/api/v1/vaults/.*"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id": "test-vault-id" })),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_fordefi_is_available_api_error() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("GET"))
        .and(path_regex("/api/v1/vaults/.*"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_fordefi_is_available_timeout() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("GET"))
        .and(path_regex("/api/v1/vaults/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "id": "vault" }))
                .set_delay(std::time::Duration::from_secs(10)),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(!signer.is_available().await);
}

// --- Debug ---

#[test]
fn test_fordefi_debug_hides_secrets() {
    let keypair = create_test_keypair();
    let signer = create_test_signer("https://test.com", keypair_pubkey(&keypair));

    let debug_str = format!("{:?}", signer);
    assert!(!debug_str.contains("test-token"));
    assert!(!debug_str.contains("test-vault-id"));
    assert!(debug_str.contains("FordefiSigner"));
}

#[tokio::test]
async fn test_fordefi_error_status_code_only() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "message": "Vault is locked"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.to_string(), "Remote API error");
    assert!(!err.to_string().contains("Vault is locked"));
}

// --- Native Solana signing tests ---

#[test]
fn test_fordefi_native_extracts_vault_signature_from_non_first_slot() {
    let fee_payer = create_test_keypair();
    let fordefi_keypair = create_test_keypair();
    let fordefi_pubkey = keypair_pubkey(&fordefi_keypair);
    let signer = create_native_test_signer("https://test.com", fordefi_pubkey);

    let mut returned_tx = create_test_transaction(&keypair_pubkey(&fee_payer));
    add_required_signer(&mut returned_tx, fordefi_pubkey);
    let returned_message = returned_tx.message.serialize();
    let fee_payer_signature = fee_payer.sign_message(&returned_message);
    let fordefi_signature = fordefi_keypair.sign_message(&returned_message);
    returned_tx.signatures = vec![fee_payer_signature, fordefi_signature];

    let extracted = signer.extract_vault_signature(&returned_tx).unwrap();
    assert_eq!(extracted, fordefi_signature);
    assert!(extracted.verify(&fordefi_pubkey.to_bytes(), &returned_message));
}

#[test]
fn test_fordefi_native_rejects_multiple_required_signers_before_submit() {
    let fee_payer = create_test_keypair();
    let fordefi_keypair = create_test_keypair();
    let fordefi_pubkey = keypair_pubkey(&fordefi_keypair);
    let signer = create_native_test_signer("https://test.com", fordefi_pubkey);

    let mut tx = create_test_transaction(&keypair_pubkey(&fee_payer));
    add_required_signer(&mut tx, fordefi_pubkey);

    let result = signer.validate_native_auto_transaction(&tx);
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_fordefi_native_sign_transaction_success() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_test_signer(&mock_server.uri(), pubkey);

    let tx = create_test_transaction(&pubkey);
    let message_data = tx.message.serialize();

    let wire_bytes = build_mock_wire_transaction(&keypair, &message_data);
    let wire_b64 = STANDARD.encode(&wire_bytes);

    let expected_idempotence_id = idempotency_key_from_message(&message_data);
    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .and(header("Authorization", "Bearer test-token"))
        .and(header("x-idempotence-id", expected_idempotence_id.as_str()))
        .and(wiremock::matchers::body_partial_json(serde_json::json!({
            "type": "solana_transaction",
            "details": {
                "type": "solana_serialized_transaction_message",
                "push_mode": "auto"
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "native-tx-1"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/native-tx-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "completed",
            "raw_transaction": wire_b64
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut tx = tx;
    let result = signer.sign_and_send_transaction(&mut tx).await;
    assert!(
        result.is_ok(),
        "native sign_and_send_transaction failed: {:?}",
        result.err()
    );
    let sig = result.unwrap();
    assert!(sig.verify(&pubkey.to_bytes(), &message_data));
    assert!(
        tx.signatures.iter().all(|s| *s == Signature::default()),
        "the caller's transaction must be left untouched by provider-chosen bytes"
    );
}

#[tokio::test]
async fn test_fordefi_native_sign_transaction_missing_raw_transaction() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "native-tx-no-raw"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/native-tx-no-raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "completed"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    let result = signer.sign_and_send_transaction(&mut tx).await;
    match result.unwrap_err() {
        SignerError::BroadcastUnconfirmed { provider_tx_id, .. } => {
            assert_eq!(provider_tx_id.as_deref(), Some("native-tx-no-raw"));
        }
        other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_native_submit_server_error_is_unconfirmed_without_a_transaction_id() {
    let mock_server = MockServer::start().await;
    let pubkey = keypair_pubkey(&create_test_keypair());
    let signer = create_native_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    match signer.sign_and_send_transaction(&mut tx).await.unwrap_err() {
        SignerError::BroadcastUnconfirmed {
            provider_tx_id,
            provider_status,
            ..
        } => {
            assert_eq!(provider_tx_id, None);
            assert_eq!(provider_status, Some(502));
        }
        other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_native_submit_accepted_without_an_id_is_unconfirmed() {
    let mock_server = MockServer::start().await;
    let pubkey = keypair_pubkey(&create_test_keypair());
    let signer = create_native_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "state": "pending" })),
        )
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    match signer.sign_and_send_transaction(&mut tx).await.unwrap_err() {
        SignerError::BroadcastUnconfirmed { provider_tx_id, .. } => {
            assert_eq!(provider_tx_id, None);
        }
        other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_native_submit_rejected_by_fordefi_stays_a_plain_failure() {
    let mock_server = MockServer::start().await;
    let pubkey = keypair_pubkey(&create_test_keypair());
    let signer = create_native_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    match signer.sign_and_send_transaction(&mut tx).await.unwrap_err() {
        SignerError::RemoteApiError(_) => {}
        other => panic!("Expected RemoteApiError, got: {other:?}"),
    }
}

/// Black-box mode only signs, so a failed submit has no on-chain outcome to be unconfirmed about.
#[tokio::test]
async fn test_black_box_submit_server_error_is_not_reported_as_unconfirmed() {
    let mock_server = MockServer::start().await;
    let pubkey = keypair_pubkey(&create_test_keypair());
    let signer = create_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    match signer.sign_transaction(&mut tx).await.unwrap_err() {
        SignerError::RemoteApiError(_) => {}
        other => panic!("Expected RemoteApiError, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_fordefi_native_sign_transaction_failed_state() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "native-tx-fail"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/native-tx-fail"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "aborted"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    let result = signer.sign_and_send_transaction(&mut tx).await;
    match result.unwrap_err() {
        SignerError::BroadcastUnconfirmed {
            provider_tx_id,
            detail,
            ..
        } => {
            assert_eq!(provider_tx_id.as_deref(), Some("native-tx-fail"));
            assert!(
                detail.contains("aborted"),
                "detail must carry the state, got: {detail}"
            );
        }
        other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_fordefi_native_sign_message_success() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_test_signer(&mock_server.uri(), pubkey);

    let message = b"hello native solana message signing";
    let real_signature = keypair.sign_message(message);
    let sig_b64 = STANDARD.encode(real_signature.as_ref());

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .and(wiremock::matchers::body_partial_json(serde_json::json!({
            "type": "solana_message",
            "details": { "type": "personal_message_type" }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "native-msg-1"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/native-msg-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "signed",
            "signatures": [{ "data": sig_b64 }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(message).await;
    assert!(
        result.is_ok(),
        "native sign_message failed: {:?}",
        result.err()
    );
    assert_eq!(result.unwrap(), real_signature);
}

#[tokio::test]
async fn test_fordefi_native_sign_message_aborted() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "native-msg-abort"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/native-msg-abort"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "aborted"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_fordefi_native_sign_transaction_poll_timeout_is_broadcast_unconfirmed() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_test_signer(&mock_server.uri(), pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "native-tx-pending"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/native-tx-pending"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "pending_signature"
        })))
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    let result = signer.sign_and_send_transaction(&mut tx).await;
    match result.unwrap_err() {
        SignerError::BroadcastUnconfirmed {
            provider_tx_id,
            detail,
            ..
        } => {
            assert_eq!(provider_tx_id.as_deref(), Some("native-tx-pending"));
            assert!(
                detail.contains("timeout"),
                "detail must carry the cause, got: {detail}"
            );
        }
        other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
    }
}

// --- Wire transaction parsing tests ---

#[tokio::test]
async fn test_fordefi_native_sign_transaction_malformed_raw_transaction() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_test_signer(&mock_server.uri(), pubkey);

    // A blob that is not a valid bincode-encoded Solana transaction.
    let bad_wire_b64 = STANDARD.encode([1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "native-tx-malformed"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/native-tx-malformed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "completed",
            "raw_transaction": bad_wire_b64
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&pubkey);
    let result = signer.sign_and_send_transaction(&mut tx).await;
    match result.unwrap_err() {
        SignerError::BroadcastUnconfirmed { provider_tx_id, .. } => {
            assert_eq!(provider_tx_id.as_deref(), Some("native-tx-malformed"));
        }
        other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
    }
}

// --- Custom request-signer (FordefiRequestSigner) tests ---

/// A custom request signer that returns a fixed `x-signature` value.
struct CannedSigner(&'static str);

#[async_trait::async_trait]
impl FordefiRequestSigner for CannedSigner {
    async fn sign_request(&self, _payload: &[u8]) -> Result<String, SignerError> {
        Ok(self.0.to_string())
    }
}

/// A custom request signer that always fails (e.g. KMS unavailable).
struct FailingSigner;

#[async_trait::async_trait]
impl FordefiRequestSigner for FailingSigner {
    async fn sign_request(&self, _payload: &[u8]) -> Result<String, SignerError> {
        Err(SignerError::SigningFailed("kms unavailable".to_string()))
    }
}

#[tokio::test]
async fn test_fordefi_custom_request_signer_sets_signature_header() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer_with(
        &mock_server.uri(),
        pubkey,
        Arc::new(CannedSigner("canned-sig-value")),
        None,
    );

    let message = b"custom signer message";
    let real_signature = keypair.sign_message(message);
    let sig_b64 = STANDARD.encode(real_signature.as_ref());

    // The POST must carry the exact x-signature produced by the custom signer.
    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .and(header("x-signature", "canned-sig-value"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "cs-1"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/cs-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "completed",
            "signatures": [{ "data": sig_b64 }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(message).await;
    assert!(
        result.is_ok(),
        "sign_message with custom signer failed: {:?}",
        result.err()
    );
    assert_eq!(result.unwrap(), real_signature);
}

#[tokio::test]
async fn test_fordefi_custom_request_signer_error_propagates() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_test_signer_with(&mock_server.uri(), pubkey, Arc::new(FailingSigner), None);

    // Signing fails before any HTTP request is made, so no mock is needed.
    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_fordefi_config_uses_custom_request_signer() {
    let public_key = keypair_pubkey(&create_test_keypair());

    let mut config = test_config("https://api.test.fordefi.com", public_key);
    config.private_key_pem = None;
    config.request_signer = Some(Arc::new(CannedSigner("x")));

    let signer = FordefiSigner::from_config(config).await.unwrap();
    assert_eq!(
        signer
            .sign_request("/api/v1/vaults", 123, "")
            .await
            .unwrap(),
        "x"
    );
}

#[test]
fn test_fordefi_config_rejects_both_request_signing_mechanisms() {
    let public_key = keypair_pubkey(&create_test_keypair());
    let mut config = test_config("https://api.test.fordefi.com", public_key);
    config.request_signer = Some(Arc::new(CannedSigner("x")));

    let result = FordefiSigner::build(config);

    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_fordefi_config_rejects_missing_request_signing_mechanism() {
    let public_key = keypair_pubkey(&create_test_keypair());
    let mut config = test_config("https://api.test.fordefi.com", public_key);
    config.private_key_pem = None;

    let result = FordefiSigner::build(config);

    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_fordefi_custom_request_signer_still_validates_config() {
    let result = FordefiSigner::build(FordefiSignerConfig {
        access_token: String::new(),
        private_key_pem: None,
        request_signer: Some(Arc::new(CannedSigner("x"))),
        ..base_test_config()
    });

    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}
