use super::*;
use crate::sdk_adapter::{keypair_pubkey, Hash, Keypair, Signer as SdkSigner, VersionedMessage};
#[cfg(feature = "sdk-v4")]
use crate::test_util::create_test_v1_transaction;
use crate::test_util::{add_required_signer, create_test_transaction, create_test_v0_transaction};
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

/// Exercise the synchronous local-validation/build phase without the public
/// constructor's authoritative Fordefi vault round-trip.
fn build_test_signer_from_config(
    config: FordefiSignerConfig,
) -> Result<FordefiSigner, SignerError> {
    FordefiSigner::build(config)
}

/// `from_config` against a plain-HTTP wiremock server: the production
/// client is HTTPS-only, so the vault round-trip needs a test client
/// (which keeps the no-redirect policy).
async fn from_config_with_test_client(
    config: FordefiSignerConfig,
) -> Result<FordefiSigner, SignerError> {
    let mut signer = FordefiSigner::build(config)?;
    signer.client = reqwest::Client::builder()
        .redirect(crate::http_client_config::no_redirect_policy())
        .build()
        .expect("Failed to build test HTTP client");
    signer.verify_vault_address_with_timeout().await?;
    Ok(signer)
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
        push_mode: None,
        max_priority_fee_lamports: None,
    }
}

fn verified_test_config(base_url: &str, public_key: Pubkey) -> FordefiSignerConfig {
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
    create_test_signer_with_mode(
        base_url,
        pubkey,
        request_signer,
        chain,
        FordefiPushMode::Auto,
    )
}

fn create_test_signer_with_mode(
    base_url: &str,
    pubkey: Pubkey,
    request_signer: Arc<dyn FordefiRequestSigner>,
    chain: Option<SolanaChainUniqueId>,
    push_mode: FordefiPushMode,
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
        push_mode,
        max_priority_fee_lamports: None,
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

fn create_native_manual_test_signer(base_url: &str, pubkey: Pubkey) -> FordefiSigner {
    create_test_signer_with_mode(
        base_url,
        pubkey,
        test_request_signer(),
        Some(SolanaChainUniqueId::SolanaMainnet),
        FordefiPushMode::Manual,
    )
}

#[test]
fn test_broadcasts_transactions_by_mode() {
    let pubkey = Pubkey::new_unique();
    assert!(!create_test_signer("https://example.com", pubkey).broadcasts_transactions());
    assert!(create_native_test_signer("https://example.com", pubkey).broadcasts_transactions());
    assert!(
        !create_native_manual_test_signer("https://example.com", pubkey).broadcasts_transactions()
    );
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

fn signed_wire_transaction(
    transaction: &mut VersionedTransaction,
    keypair: &Keypair,
) -> (Vec<u8>, Signature) {
    let message_bytes = transaction.message.serialize();
    let signature = keypair.sign_message(&message_bytes);
    let required_signatures = transaction.message.header().num_required_signatures as usize;
    transaction
        .signatures
        .resize(required_signatures, Signature::default());
    transaction.signatures[0] = signature;
    (
        serialize_wire_transaction(transaction).expect("serialize signed transaction"),
        signature,
    )
}

fn prepend_manual_compute_budget_instruction(
    transaction: &mut VersionedTransaction,
    data: Vec<u8>,
    accounts: Vec<u8>,
) {
    let compute_budget_id = COMPUTE_BUDGET_PROGRAM_ID;
    let (header, account_keys, instructions) = match &mut transaction.message {
        VersionedMessage::Legacy(message) => (
            &mut message.header,
            &mut message.account_keys,
            &mut message.instructions,
        ),
        VersionedMessage::V0(message) => (
            &mut message.header,
            &mut message.account_keys,
            &mut message.instructions,
        ),
        #[cfg(feature = "sdk-v4")]
        VersionedMessage::V1(_) => panic!("fee helper does not support v1"),
    };
    let program_id_index = account_keys
        .iter()
        .position(|key| key == &compute_budget_id)
        .unwrap_or_else(|| {
            let index = account_keys.len();
            account_keys.push(compute_budget_id);
            header.num_readonly_unsigned_accounts += 1;
            index
        });
    instructions.insert(
        0,
        CompiledInstruction {
            program_id_index: u8::try_from(program_id_index).unwrap(),
            accounts,
            data,
        },
    );
}

fn compute_limit_data(limit: u32) -> Vec<u8> {
    let mut data = vec![SET_COMPUTE_UNIT_LIMIT];
    data.extend_from_slice(&limit.to_le_bytes());
    data
}

fn compute_price_data(price: u64) -> Vec<u8> {
    let mut data = vec![SET_COMPUTE_UNIT_PRICE];
    data.extend_from_slice(&price.to_le_bytes());
    data
}

async fn assert_native_manual_round_trip(
    mut transaction: VersionedTransaction,
    keypair: &Keypair,
    terminal_state: &str,
) {
    let mock_server = MockServer::start().await;
    let pubkey = keypair_pubkey(keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let original_message = transaction.message.serialize();

    let mut returned_tx = transaction.clone();
    returned_tx.message.set_recent_blockhash(Hash::new_unique());
    let returned_message = returned_tx.message.serialize();
    let (wire_bytes, expected_signature) = signed_wire_transaction(&mut returned_tx, keypair);
    let wire_b64 = STANDARD.encode(wire_bytes);

    let mut idempotency_input = b"fordefi:solana:manual:solana_mainnet:test-vault-id:".to_vec();
    idempotency_input.extend_from_slice(&original_message);
    let expected_idempotence_id = idempotency_key_from_message(&idempotency_input);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .and(header("x-idempotence-id", expected_idempotence_id.as_str()))
        .and(wiremock::matchers::body_partial_json(serde_json::json!({
            "type": "solana_transaction",
            "details": {
                "type": "solana_serialized_transaction_message",
                "push_mode": "manual"
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "native-manual-tx"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/native-manual-tx"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": terminal_state,
            "raw_transaction": wire_b64
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer
        .sign_transaction(&mut transaction)
        .await
        .expect("manual transaction should sign");
    assert!(matches!(result, SignTransactionResult::Complete(_)));
    let (serialized_transaction, signature) = result.into_signed_transaction();
    assert!(!serialized_transaction.is_empty());
    assert_eq!(signature, expected_signature);
    assert!(signature.verify(&pubkey.to_bytes(), &returned_message));
    assert_ne!(original_message, returned_message);
    assert_eq!(transaction.message.serialize(), returned_message);
    assert_eq!(transaction.signatures, returned_tx.signatures);

    let decoded = deserialize_wire_transaction(
        &STANDARD
            .decode(serialized_transaction)
            .expect("decode returned base64 transaction"),
    )
    .expect("decode returned wire transaction");
    assert_eq!(decoded.message.serialize(), transaction.message.serialize());
    assert_eq!(decoded.signatures, transaction.signatures);
}

async fn mount_native_manual_result(
    mock_server: &MockServer,
    tx_id: &str,
    state: &str,
    raw_transaction: Option<String>,
) {
    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": tx_id
        })))
        .expect(1)
        .mount(mock_server)
        .await;

    let mut poll_body = serde_json::json!({ "state": state });
    if let Some(raw_transaction) = raw_transaction {
        poll_body["raw_transaction"] = serde_json::Value::String(raw_transaction);
    }
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/transactions/{tx_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(poll_body))
        .expect(1)
        .mount(mock_server)
        .await;
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
fn test_fordefi_manual_config_requires_chain() {
    let result = FordefiSigner::build(FordefiSignerConfig {
        push_mode: Some(FordefiPushMode::Manual),
        ..base_test_config()
    });
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_fordefi_manual_config_with_chain_valid() {
    let result = FordefiSigner::build(FordefiSignerConfig {
        chain: Some(SolanaChainUniqueId::SolanaDevnet),
        push_mode: Some(FordefiPushMode::Manual),
        ..base_test_config()
    });
    assert_eq!(result.unwrap().push_mode, FordefiPushMode::Manual);
}

#[test]
fn test_fordefi_config_defaults_to_auto_push_mode() {
    let signer = FordefiSigner::build(FordefiSignerConfig {
        chain: Some(SolanaChainUniqueId::SolanaDevnet),
        ..base_test_config()
    })
    .expect("config is valid");
    assert_eq!(signer.push_mode, FordefiPushMode::Auto);
    assert!(signer.broadcasts_transactions());
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

// --- Authoritative vault verification tests ---

#[tokio::test]
async fn test_fordefi_constructor_verifies_chain_specific_vault_address() {
    let mock_server = MockServer::start().await;
    let public_key = keypair_pubkey(&create_test_keypair());

    Mock::given(method("GET"))
        .and(path("/api/v1/vaults/test-vault-id"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "address": public_key.to_string(),
            "id": "test-vault-id",
            "type": "solana"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let signer = from_config_with_test_client(verified_test_config(&mock_server.uri(), public_key))
        .await
        .unwrap();

    assert_eq!(signer.pubkey(), public_key);
}

#[tokio::test]
async fn test_fordefi_constructor_derives_black_box_vault_address() {
    let mock_server = MockServer::start().await;
    let public_key = keypair_pubkey(&create_test_keypair());
    let public_key_compressed = STANDARD.encode(public_key.to_bytes());

    Mock::given(method("GET"))
        .and(path("/api/v1/vaults/test-vault-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-vault-id",
            "public_key_compressed": public_key_compressed,
            "type": "black_box"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let signer = from_config_with_test_client(verified_test_config(&mock_server.uri(), public_key))
        .await
        .unwrap();

    assert_eq!(signer.pubkey(), public_key);
}

#[tokio::test]
async fn test_fordefi_constructor_rejects_vault_address_mismatch() {
    let mock_server = MockServer::start().await;
    let configured_public_key = keypair_pubkey(&create_test_keypair());
    let remote_public_key = keypair_pubkey(&create_test_keypair());

    Mock::given(method("GET"))
        .and(path("/api/v1/vaults/test-vault-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "address": remote_public_key.to_string(),
            "id": "test-vault-id"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = from_config_with_test_client(verified_test_config(
        &mock_server.uri(),
        configured_public_key,
    ))
    .await;

    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[tokio::test]
async fn test_fordefi_constructor_rejects_vault_without_public_key() {
    let mock_server = MockServer::start().await;
    let public_key = keypair_pubkey(&create_test_keypair());

    Mock::given(method("GET"))
        .and(path("/api/v1/vaults/test-vault-id"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id": "test-vault-id" })),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let result =
        from_config_with_test_client(verified_test_config(&mock_server.uri(), public_key)).await;

    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[tokio::test]
async fn test_fordefi_constructor_rejects_invalid_black_box_public_key() {
    let mock_server = MockServer::start().await;
    let public_key = keypair_pubkey(&create_test_keypair());

    Mock::given(method("GET"))
        .and(path("/api/v1/vaults/test-vault-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-vault-id",
            "public_key_compressed": STANDARD.encode([1_u8; 31]),
            "type": "black_box"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result =
        from_config_with_test_client(verified_test_config(&mock_server.uri(), public_key)).await;

    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPublicKey(_)
    ));
}

#[tokio::test]
async fn test_fordefi_constructor_rejects_invalid_black_box_base64() {
    let mock_server = MockServer::start().await;
    let public_key = keypair_pubkey(&create_test_keypair());

    Mock::given(method("GET"))
        .and(path("/api/v1/vaults/test-vault-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-vault-id",
            "public_key_compressed": "not-base64",
            "type": "black_box"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result =
        from_config_with_test_client(verified_test_config(&mock_server.uri(), public_key)).await;

    assert!(matches!(
        result.unwrap_err(),
        SignerError::SerializationError(_)
    ));
}

#[tokio::test]
async fn test_fordefi_constructor_propagates_vault_api_error() {
    let mock_server = MockServer::start().await;
    let public_key = keypair_pubkey(&create_test_keypair());

    Mock::given(method("GET"))
        .and(path("/api/v1/vaults/test-vault-id"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result =
        from_config_with_test_client(verified_test_config(&mock_server.uri(), public_key)).await;

    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
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
async fn test_fordefi_native_manual_replaces_legacy_transaction() {
    let keypair = create_test_keypair();
    let transaction = create_test_transaction(&keypair_pubkey(&keypair));
    assert_native_manual_round_trip(transaction, &keypair, "signed").await;
}

#[tokio::test]
async fn test_fordefi_native_manual_replaces_v0_transaction() {
    let keypair = create_test_keypair();
    let transaction = create_test_v0_transaction(&keypair_pubkey(&keypair));
    assert_native_manual_round_trip(transaction, &keypair, "completed").await;
}

/// Largest compute-unit price that still lands on the default ceiling when
/// Fordefi also sets the maximum compute-unit limit.
const CEILING_PRICE: u64 = (DEFAULT_MAX_PRIORITY_FEE_LAMPORTS as u128 * MICRO_LAMPORTS_PER_LAMPORT
    / MAX_COMPUTE_UNIT_LIMIT as u128) as u64;

fn manual_signer_with_fee_policy(
    pubkey: Pubkey,
    fee: Option<FordefiSolanaFee>,
    max_priority_fee_lamports: Option<u64>,
) -> FordefiSigner {
    let mut signer = create_native_manual_test_signer("https://example.com", pubkey);
    signer.fee = fee;
    signer.max_priority_fee_lamports = max_priority_fee_lamports;
    signer
}

/// Builds a Fordefi-mutated transaction carrying the given fee instructions.
fn returned_with_fee(
    base: &VersionedTransaction,
    price: u64,
    limit: Option<u32>,
) -> VersionedTransaction {
    let mut returned = base.clone();
    if let Some(limit) = limit {
        prepend_manual_compute_budget_instruction(&mut returned, compute_limit_data(limit), vec![]);
    }
    prepend_manual_compute_budget_instruction(&mut returned, compute_price_data(price), vec![]);
    returned
}

#[test]
fn test_fordefi_native_manual_default_fee_ceiling_rejects_drain_sized_fees() {
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let base = create_test_v0_transaction(&pubkey);
    let returned = returned_with_fee(&base, u64::MAX, Some(MAX_COMPUTE_UNIT_LIMIT));

    for fee in [
        None,
        Some(FordefiSolanaFee::Priority {
            priority_level: FordefiPriorityLevel::High,
        }),
        Some(FordefiSolanaFee::Custom {
            unit_price: None,
            priority_fee: None,
        }),
    ] {
        let signer = manual_signer_with_fee_policy(pubkey, fee, None);
        assert!(
            signer
                .validate_manual_message_mutation(&base, &returned)
                .is_err(),
            "an uncapped fee mode must reject a drain-sized priority fee"
        );
    }
}

#[test]
fn test_fordefi_native_manual_default_fee_ceiling_allows_realistic_fees() {
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let base = create_test_v0_transaction(&pubkey);
    let signer = manual_signer_with_fee_policy(pubkey, None, None);

    for (label, price, limit) in [
        ("ordinary", 1_000_000, 200_000),
        ("congestion", 10_000_000, MAX_COMPUTE_UNIT_LIMIT),
        (
            "exactly at the ceiling",
            CEILING_PRICE,
            MAX_COMPUTE_UNIT_LIMIT,
        ),
    ] {
        signer
            .validate_manual_message_mutation(&base, &returned_with_fee(&base, price, Some(limit)))
            .unwrap_or_else(|error| panic!("{label} fee should be accepted: {error}"));
    }

    assert!(
        signer
            .validate_manual_message_mutation(
                &base,
                &returned_with_fee(&base, CEILING_PRICE + 1, Some(MAX_COMPUTE_UNIT_LIMIT)),
            )
            .is_err(),
        "one micro-lamport past the ceiling must be rejected"
    );

    // With no explicit limit the fee is charged at the runtime maximum.
    assert!(
        signer
            .validate_manual_message_mutation(
                &base,
                &returned_with_fee(&base, CEILING_PRICE + 1, None),
            )
            .is_err(),
        "a price-only fee must be charged at the maximum compute-unit limit"
    );
}

#[test]
fn test_fordefi_native_manual_fee_ceiling_precedence() {
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let base = create_test_v0_transaction(&pubkey);

    // An explicit ceiling overrides the default in both directions.
    manual_signer_with_fee_policy(pubkey, None, Some(10_000_000_000))
        .validate_manual_message_mutation(
            &base,
            &returned_with_fee(&base, 1_000_000_000, Some(MAX_COMPUTE_UNIT_LIMIT)),
        )
        .expect("a raised ceiling should permit 1.4 SOL");
    assert!(
        manual_signer_with_fee_policy(pubkey, None, Some(1_000))
            .validate_manual_message_mutation(
                &base,
                &returned_with_fee(&base, 1_000_000, Some(200_000)),
            )
            .is_err(),
        "a lowered ceiling should reject an otherwise ordinary fee"
    );

    // A caller-stated custom priority_fee governs instead of the default.
    let custom = Some(FordefiSolanaFee::Custom {
        unit_price: None,
        priority_fee: Some("500000000".to_string()),
    });
    manual_signer_with_fee_policy(pubkey, custom.clone(), None)
        .validate_manual_message_mutation(
            &base,
            &returned_with_fee(&base, 300_000_000, Some(MAX_COMPUTE_UNIT_LIMIT)),
        )
        .expect("the caller-stated bound should govern");
    assert!(
        manual_signer_with_fee_policy(pubkey, custom.clone(), None)
            .validate_manual_message_mutation(
                &base,
                &returned_with_fee(&base, 400_000_000, Some(MAX_COMPUTE_UNIT_LIMIT)),
            )
            .is_err(),
        "a fee above the caller-stated bound must be rejected"
    );

    // An explicit ceiling is never widened by a custom priority_fee.
    assert!(
        manual_signer_with_fee_policy(pubkey, custom, Some(1_000))
            .validate_manual_message_mutation(
                &base,
                &returned_with_fee(&base, 300_000_000, Some(MAX_COMPUTE_UNIT_LIMIT)),
            )
            .is_err(),
        "an explicit ceiling must still apply alongside a custom priority_fee"
    );
}

#[test]
fn test_fordefi_native_manual_fee_ceiling_spares_caller_authored_prices() {
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = manual_signer_with_fee_policy(pubkey, None, None);

    // The caller set the price themselves, so the message is compared
    // byte-for-byte and Fordefi has no discretion left to bound.
    let mut original = create_test_v0_transaction(&pubkey);
    prepend_manual_compute_budget_instruction(
        &mut original,
        compute_limit_data(MAX_COMPUTE_UNIT_LIMIT),
        vec![],
    );
    prepend_manual_compute_budget_instruction(&mut original, compute_price_data(u64::MAX), vec![]);
    let mut returned = original.clone();
    returned.message.set_recent_blockhash(Hash::new_unique());
    signer
        .validate_manual_message_mutation(&original, &returned)
        .expect("a caller-authored price must not be subject to the ceiling");
}

#[test]
fn test_fordefi_native_manual_message_mutation_fee_policy() {
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let base = create_test_v0_transaction(&pubkey);
    let signer = create_native_manual_test_signer("https://example.com", pubkey);

    let mut returned = base.clone();
    returned.message.set_recent_blockhash(Hash::new_unique());
    prepend_manual_compute_budget_instruction(&mut returned, compute_limit_data(300_000), vec![]);
    prepend_manual_compute_budget_instruction(&mut returned, compute_price_data(7), vec![]);
    signer
        .validate_manual_message_mutation(&base, &returned)
        .unwrap();

    let mut original_limit = base.clone();
    prepend_manual_compute_budget_instruction(
        &mut original_limit,
        compute_limit_data(200_000),
        vec![],
    );
    let mut adjusted_limit = base.clone();
    prepend_manual_compute_budget_instruction(
        &mut adjusted_limit,
        compute_limit_data(400_000),
        vec![],
    );
    signer
        .validate_manual_message_mutation(&original_limit, &adjusted_limit)
        .unwrap();
    signer
        .validate_manual_message_mutation(&original_limit, &base)
        .unwrap();

    let mut heap = base.clone();
    prepend_manual_compute_budget_instruction(&mut heap, vec![1, 0, 128, 0, 0], vec![]);
    let mut heap_with_price = heap.clone();
    prepend_manual_compute_budget_instruction(&mut heap_with_price, compute_price_data(5), vec![]);
    signer
        .validate_manual_message_mutation(&heap, &heap_with_price)
        .unwrap();
    if let VersionedMessage::V0(message) = &mut heap_with_price.message {
        message.instructions[1].data[1] ^= 1;
    }
    assert!(signer
        .validate_manual_message_mutation(&heap, &heap_with_price)
        .is_err());
}

#[test]
fn test_fordefi_native_manual_rejects_invalid_fee_mutations() {
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let base = create_test_transaction(&pubkey);
    let signer = create_native_manual_test_signer("https://example.com", pubkey);

    let mut original_price = base.clone();
    prepend_manual_compute_budget_instruction(&mut original_price, compute_price_data(5), vec![]);
    signer
        .validate_manual_message_mutation(&original_price, &original_price)
        .unwrap();
    let mut changed_price = base.clone();
    prepend_manual_compute_budget_instruction(&mut changed_price, compute_price_data(6), vec![]);
    assert!(signer
        .validate_manual_message_mutation(&original_price, &changed_price)
        .is_err());

    let mut malformed = base.clone();
    prepend_manual_compute_budget_instruction(
        &mut malformed,
        vec![SET_COMPUTE_UNIT_LIMIT, 1],
        vec![],
    );
    let mut duplicate = base.clone();
    prepend_manual_compute_budget_instruction(&mut duplicate, compute_price_data(1), vec![]);
    prepend_manual_compute_budget_instruction(&mut duplicate, compute_price_data(2), vec![]);
    let mut account_bearing = base.clone();
    prepend_manual_compute_budget_instruction(&mut account_bearing, compute_price_data(1), vec![0]);
    let mut out_of_range = base.clone();
    prepend_manual_compute_budget_instruction(
        &mut out_of_range,
        compute_limit_data(MAX_COMPUTE_UNIT_LIMIT + 1),
        vec![],
    );
    let mut unknown = base.clone();
    prepend_manual_compute_budget_instruction(&mut unknown, vec![9], vec![]);
    for invalid in [malformed, duplicate, account_bearing, out_of_range, unknown] {
        assert!(signer
            .validate_manual_message_mutation(&base, &invalid)
            .is_err());
    }
}

#[test]
fn test_fordefi_native_manual_enforces_custom_fee_constraints() {
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let base = create_test_v0_transaction(&pubkey);
    let mut returned = base.clone();
    prepend_manual_compute_budget_instruction(&mut returned, compute_limit_data(200_000), vec![]);
    prepend_manual_compute_budget_instruction(&mut returned, compute_price_data(10), vec![]);

    let mut exact = create_native_manual_test_signer("https://example.com", pubkey);
    exact.fee = Some(FordefiSolanaFee::Custom {
        unit_price: Some("10".to_string()),
        priority_fee: Some("2".to_string()),
    });
    exact
        .validate_manual_message_mutation(&base, &returned)
        .unwrap();
    assert!(exact
        .validate_manual_message_mutation(&base, &base)
        .is_err());

    let mut capped = create_native_manual_test_signer("https://example.com", pubkey);
    capped.fee = Some(FordefiSolanaFee::Custom {
        unit_price: None,
        priority_fee: Some("1".to_string()),
    });
    assert!(capped
        .validate_manual_message_mutation(&base, &returned)
        .is_err());

    let mut original_price = base.clone();
    prepend_manual_compute_budget_instruction(&mut original_price, compute_price_data(10), vec![]);
    let mut conflicting = create_native_manual_test_signer("https://example.com", pubkey);
    conflicting.fee = Some(FordefiSolanaFee::Custom {
        unit_price: Some("11".to_string()),
        priority_fee: None,
    });
    assert!(conflicting
        .validate_manual_message_mutation(&original_price, &original_price)
        .is_err());
}

#[test]
fn test_fordefi_native_manual_restricts_durable_nonce_lifetime() {
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer("https://example.com", pubkey);
    let mut nonce = create_test_transaction(&pubkey);
    if let VersionedMessage::Legacy(message) = &mut nonce.message {
        message.instructions[0].data = vec![4, 0, 0, 0];
    }
    assert!(nonce.uses_durable_nonce());
    let mut changed = nonce.clone();
    changed.message.set_recent_blockhash(Hash::new_unique());
    assert!(signer
        .validate_manual_message_mutation(&nonce, &changed)
        .is_err());
}

#[cfg(feature = "sdk-v4")]
#[test]
fn test_fordefi_native_manual_restricts_v1_inline_config() {
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer("https://example.com", pubkey);
    let original = create_test_v1_transaction(&pubkey);
    let mut blockhash_changed = original.clone();
    blockhash_changed
        .message
        .set_recent_blockhash(Hash::new_unique());
    signer
        .validate_manual_message_mutation(&original, &blockhash_changed)
        .unwrap();

    let mut config_changed = blockhash_changed;
    if let VersionedMessage::V1(message) = &mut config_changed.message {
        message.config.priority_fee = Some(99);
    }
    assert!(signer
        .validate_manual_message_mutation(&original, &config_changed)
        .is_err());
}

#[cfg(feature = "sdk-v4")]
#[tokio::test]
async fn test_fordefi_native_manual_replaces_v1_transaction() {
    let keypair = create_test_keypair();
    let transaction = create_test_v1_transaction(&keypair_pubkey(&keypair));
    assert_native_manual_round_trip(transaction, &keypair, "signed").await;
}

#[tokio::test]
async fn test_fordefi_native_manual_returns_partial_multisigner_transaction() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let cosigner = keypair_pubkey(&create_test_keypair());
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);

    let mut transaction = create_test_transaction(&pubkey);
    add_required_signer(&mut transaction, cosigner);
    transaction.signatures = vec![Signature::default(); 2];

    let mut returned_tx = transaction.clone();
    returned_tx.message.set_recent_blockhash(Hash::new_unique());
    let (wire_bytes, expected_signature) = signed_wire_transaction(&mut returned_tx, &keypair);
    mount_native_manual_result(
        &mock_server,
        "manual-multisigner",
        "signed",
        Some(STANDARD.encode(wire_bytes)),
    )
    .await;

    let result = signer.sign_transaction(&mut transaction).await.unwrap();
    assert!(matches!(result, SignTransactionResult::Partial(_)));
    let (serialized_transaction, signature) = result.into_signed_transaction();
    assert_eq!(signature, expected_signature);
    assert!(!serialized_transaction.is_empty());
    assert_eq!(transaction.signatures[0], expected_signature);
    assert_eq!(transaction.signatures[1], Signature::default());
    assert_eq!(
        transaction.message.serialize(),
        returned_tx.message.serialize()
    );
}

#[tokio::test]
async fn test_fordefi_native_manual_forwards_fee_configuration() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let mut signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    signer.fee = Some(FordefiSolanaFee::Custom {
        unit_price: None,
        priority_fee: Some("1000".to_string()),
    });

    let mut transaction = create_test_transaction(&pubkey);
    let mut returned_tx = transaction.clone();
    returned_tx.message.set_recent_blockhash(Hash::new_unique());
    let (wire_bytes, _) = signed_wire_transaction(&mut returned_tx, &keypair);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .and(wiremock::matchers::body_partial_json(serde_json::json!({
            "details": {
                "push_mode": "manual",
                "fee": { "type": "custom", "priority_fee": "1000" }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "manual-fee"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/manual-fee"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "signed",
            "raw_transaction": STANDARD.encode(wire_bytes)
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    signer.sign_transaction(&mut transaction).await.unwrap();
}

#[tokio::test]
async fn test_fordefi_native_manual_rejects_presigned_input_before_submit() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let mut transaction = create_test_transaction(&pubkey);
    transaction.signatures[0] = keypair.sign_message(&transaction.message.serialize());

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_server)
        .await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::SigningFailed(_)
    ));
}

#[tokio::test]
async fn test_fordefi_native_manual_rejects_non_vault_fee_payer_before_submit() {
    let mock_server = MockServer::start().await;
    let vault_keypair = create_test_keypair();
    let signer =
        create_native_manual_test_signer(&mock_server.uri(), keypair_pubkey(&vault_keypair));
    let mut transaction = create_test_transaction(&keypair_pubkey(&create_test_keypair()));

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_server)
        .await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::SigningFailed(_)
    ));
}

#[tokio::test]
async fn test_fordefi_native_manual_rejects_missing_raw_transaction() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let mut transaction = create_test_transaction(&pubkey);
    let original_message = transaction.message.serialize();
    mount_native_manual_result(&mock_server, "manual-no-raw", "signed", None).await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::SigningFailed(_)
    ));
    assert_eq!(transaction.message.serialize(), original_message);
}

#[tokio::test]
async fn test_fordefi_native_manual_rejects_malformed_raw_transaction() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let mut transaction = create_test_transaction(&pubkey);
    mount_native_manual_result(
        &mock_server,
        "manual-malformed",
        "signed",
        Some(STANDARD.encode([1u8, 2, 3])),
    )
    .await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::SerializationError(_)
    ));
}

#[tokio::test]
async fn test_fordefi_native_manual_rejects_oversized_raw_transaction() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let mut transaction = create_test_transaction(&pubkey);
    mount_native_manual_result(
        &mock_server,
        "manual-oversized",
        "signed",
        Some(STANDARD.encode(vec![0u8; SOLANA_PACKET_DATA_SIZE + 1])),
    )
    .await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::SigningFailed(_)
    ));
}

#[tokio::test]
async fn test_fordefi_native_manual_rejects_missing_vault_signature() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let mut transaction = create_test_transaction(&pubkey);
    let returned_tx = transaction.clone();
    let wire_bytes = serialize_wire_transaction(&returned_tx).unwrap();
    mount_native_manual_result(
        &mock_server,
        "manual-no-signature",
        "signed",
        Some(STANDARD.encode(wire_bytes)),
    )
    .await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::SigningFailed(_)
    ));
}

#[tokio::test]
async fn test_fordefi_native_manual_rejects_invalid_vault_signature() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let mut transaction = create_test_transaction(&pubkey);
    let mut returned_tx = transaction.clone();
    returned_tx.signatures[0] = Signature::from([0xabu8; 64]);
    let wire_bytes = serialize_wire_transaction(&returned_tx).unwrap();
    mount_native_manual_result(
        &mock_server,
        "manual-invalid-signature",
        "signed",
        Some(STANDARD.encode(wire_bytes)),
    )
    .await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::SigningFailed(_)
    ));
}

#[tokio::test]
async fn test_fordefi_native_manual_rejects_changed_signer_set() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let mut transaction = create_test_transaction(&pubkey);
    let mut returned_tx = transaction.clone();
    add_required_signer(&mut returned_tx, keypair_pubkey(&create_test_keypair()));
    returned_tx.signatures = vec![Signature::default(); 2];
    let (wire_bytes, _) = signed_wire_transaction(&mut returned_tx, &keypair);
    mount_native_manual_result(
        &mock_server,
        "manual-changed-signers",
        "signed",
        Some(STANDARD.encode(wire_bytes)),
    )
    .await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::SigningFailed(_)
    ));
}

#[tokio::test]
async fn test_fordefi_native_manual_rejects_changed_instruction_content() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let mut transaction = create_test_transaction(&pubkey);
    let mut returned_tx = transaction.clone();
    match &mut returned_tx.message {
        VersionedMessage::Legacy(message) => message.instructions[0].data[0] ^= 0x01,
        _ => panic!("expected legacy test transaction"),
    }
    let (wire_bytes, _) = signed_wire_transaction(&mut returned_tx, &keypair);
    mount_native_manual_result(
        &mock_server,
        "manual-changed-content",
        "signed",
        Some(STANDARD.encode(wire_bytes)),
    )
    .await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::SigningFailed(_)
    ));
}

#[tokio::test]
async fn test_fordefi_native_manual_rejects_populated_downstream_signature() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let cosigner_keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let mut transaction = create_test_transaction(&pubkey);
    add_required_signer(&mut transaction, keypair_pubkey(&cosigner_keypair));
    transaction.signatures = vec![Signature::default(); 2];

    let mut returned_tx = transaction.clone();
    let returned_message = returned_tx.message.serialize();
    returned_tx.signatures = vec![
        keypair.sign_message(&returned_message),
        cosigner_keypair.sign_message(&returned_message),
    ];
    let wire_bytes = serialize_wire_transaction(&returned_tx).unwrap();
    mount_native_manual_result(
        &mock_server,
        "manual-downstream-signature",
        "signed",
        Some(STANDARD.encode(wire_bytes)),
    )
    .await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::SigningFailed(_)
    ));
}

#[tokio::test]
async fn test_fordefi_native_manual_failure_state_is_not_broadcast_unconfirmed() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let mut transaction = create_test_transaction(&pubkey);
    mount_native_manual_result(&mock_server, "manual-failed", "error_signing", None).await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::SigningFailed(_)
    ));
}

#[tokio::test]
async fn test_fordefi_native_manual_poll_timeout_is_not_broadcast_unconfirmed() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let mut transaction = create_test_transaction(&pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "manual-pending"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/transactions/manual-pending"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "state": "pending_signature"
        })))
        .expect(3)
        .mount(&mock_server)
        .await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
}

#[tokio::test]
async fn test_fordefi_native_manual_submit_error_is_not_broadcast_unconfirmed() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey = keypair_pubkey(&keypair);
    let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
    let mut transaction = create_test_transaction(&pubkey);

    Mock::given(method("POST"))
        .and(path("/api/v1/transactions"))
        .respond_with(ResponseTemplate::new(502))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(matches!(
        signer.sign_transaction(&mut transaction).await.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
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
    let mock_server = MockServer::start().await;
    let public_key = keypair_pubkey(&create_test_keypair());

    let mut config = verified_test_config(&mock_server.uri(), public_key);
    config.private_key_pem = None;
    config.request_signer = Some(Arc::new(CannedSigner("x")));

    Mock::given(method("GET"))
        .and(path("/api/v1/vaults/test-vault-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "address": public_key.to_string(),
            "id": "test-vault-id"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let signer = from_config_with_test_client(config).await.unwrap();
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
    let mut config = verified_test_config("https://api.test.fordefi.com", public_key);
    config.request_signer = Some(Arc::new(CannedSigner("x")));

    let result = FordefiSigner::build(config);

    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_fordefi_config_rejects_missing_request_signing_mechanism() {
    let public_key = keypair_pubkey(&create_test_keypair());
    let mut config = verified_test_config("https://api.test.fordefi.com", public_key);
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
