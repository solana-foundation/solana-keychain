
use super::*;
use crate::sdk_adapter::{keypair_pubkey, Keypair, Signer};
use crate::test_util::create_test_transaction;
use wiremock::{
    matchers::{body_partial_json, header, method, path, path_regex},
    Mock, MockServer, ResponseTemplate,
};

// Test RSA key for unit tests only (PKCS#8 format required by jsonwebtoken)
const TEST_RSA_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDKKw7fHhfK3/Ts
rAqsNCrDsjmyBTHx/AUCOTM+tZph2ZOyDSH9nZO4JkzLrW6Vfk7EZvlP3QjLiXEG
m9qQgAh9sXgp07GicWU5omSILTMdd18yR6aIXVw/YzgjD7EVLRQU6YHc3BYgR8P8
PBbJcxzYrrUDSGEXX2b44cZO72RxIPM+yeY3ZXiztgFQSpfEIKX488/k/PgUHMHK
/04VoL/jiQa5dOs44CmHHT6MbBT1Sb/VR0G1hHtfMSIQCtdvzt+VBZhg7sxm50h/
cT+n0UVOBwEp2IY2x4lzlwOdptZl7P3D1+A2rAbalXg5WO+LVEjx5ym++XbCGyvU
rlH+ILOPAgMBAAECggEAXio3F5J/N4YgITqzD+mOf69cc0A7NsCRnqsA5PUWbvw2
cIjwa55BZ1UjkPz7lJML4iwqdNn51j/yzsa6Q3L3QYBvfV/2jbiuku1CUTFobRGk
XBmGhl6h8H5o79/HthrUjzcCP1qdzbRPo4Vjgbpl1cFuW5STcJ0Fq+gRg8O6b3w7
A2843mcF9EA9ZFjXpn+VtpzLe4nHVRZFYXvXSlfdYc6WQbThnLLiLQYsVMqhYQAU
I4c9hfgasfgZ6iCV5hMK2ZPX45+/OVQzjh4+I8zlvNWp2cKNoEhMHU2G/In11yBF
wHGRuvbwx9Wc4Okqq+GvfTO0jCAinAQQu8C+eIcNcQKBgQDo9dzw2cNsJmaUvaL5
I7gEtbPdr+CTgVjGoVUIlGeI0OBHt1DJEwczS2tycScE9SUDLdmegYA8ubHsAs/6
PFEJ+779h9/IDzL3Fe9Zp1fiQgWOKF1uCS7+b8QwFMhh2u0OLWmI1rdFmqX2KCPf
AfD/Pvp6bgapXTN1EoB3LQ/4PwKBgQDeKZeJMk9CZzWFe+m5x2yzJBK62ZvKzyjZ
Y3IeK75V0xG+Y7ZAb0zTXPkgBpBiQOqdFRgt6bp/S/6Tq/OXfeV9xVURSz4zRtCR
lRoONL8ZSl0h4VptEjXrYfBnH2j4gtjhnTATJZBp0rYrExbz0jVbQtRzPLs+k3+p
TuZA8+XwsQKBgCocn8buJpR7UJncugQ9f7tiOVR+waMIg8rMSTnW0ex6jcCJE9J1
XRzZql+ysrIDuqAbfrZXhJ31l4Mpcv0yQBgE6R6dnEdm7/iYf37+cDWXZ7et9k24
3UTjYVyrtRlzYNzqOqSg49pyPUQFN47NpAoQEWlmUE/3aCDmqlBg1f0zAoGAamv+
HUiuUx7hspnTMp1nYsEq/7ryOErYRJqwtec6fB5p54wYZ/FpGe71n/PFAmwadzj9
pjDKl+QthUvfmnhCkOcQgwJKP4Hys2p7WsbFrDXFO0+aY5lPnvwBj0SqojD798e2
mdVqwmafwS6Z1h6iVJ9E6hbzk1xQ0SfsgLzVL2ECgYBN6fJ99og4fkp4iA5C31TB
UKlH64yqwxFu4vuVMqBOpGPkdsLNGhE/vpdP7yYxC/MP+v8ow/sCa40Ely20Yqqa
znT9Ik5JV4eRXyRG9iwllKvcrmczFDIuxFmXPff4G9nmyB9fLQfSM0gD+yDR05Hx
p6B5CCtpBPgD01Vm+bT/JQ==
-----END PRIVATE KEY-----"#;

const TEST_PUBKEY: &str = "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV";
const OTHER_TEST_PUBKEY: &str = "6dNUL7bY6oNCM4vXfB6HrCa3Wa2QhTVowsPYqzTGMTfd";

fn test_signing_key() -> Arc<jsonwebtoken::EncodingKey> {
    Arc::new(jwt::parse_encoding_key(TEST_RSA_KEY).expect("failed to parse test RSA key"))
}

fn create_test_signer_uninit(base_url: &str) -> FireblocksSigner {
    FireblocksSigner {
        api_key: "test-api-key".to_string(),
        signing_key: Some(test_signing_key()),
        vault_account_id: "test-vault-id".to_string(),
        asset_id: "SOL".to_string(),
        public_key: None,
        api_base_url: base_url.to_string(),
        client: reqwest::Client::new(),
        poll_interval_ms: 10,
        max_poll_attempts: 3,
        use_program_call: false, // Use RAW (default) for message signing tests
    }
}

fn create_test_signer(base_url: &str) -> FireblocksSigner {
    FireblocksSigner {
        api_key: "test-api-key".to_string(),
        signing_key: Some(test_signing_key()),
        vault_account_id: "test-vault-id".to_string(),
        asset_id: "SOL".to_string(),
        public_key: Some(Pubkey::from_str(TEST_PUBKEY).unwrap()),
        api_base_url: base_url.to_string(),
        client: reqwest::Client::new(),
        poll_interval_ms: 10,
        max_poll_attempts: 3,
        use_program_call: false, // Use RAW (default) for message signing tests
    }
}

fn create_test_signer_program_call(base_url: &str, public_key: Pubkey) -> FireblocksSigner {
    FireblocksSigner {
        api_key: "test-api-key".to_string(),
        signing_key: Some(test_signing_key()),
        vault_account_id: "test-vault-id".to_string(),
        asset_id: "SOL".to_string(),
        public_key: Some(public_key),
        api_base_url: base_url.to_string(),
        client: reqwest::Client::new(),
        poll_interval_ms: 10,
        max_poll_attempts: 3,
        use_program_call: true,
    }
}

async fn mount_program_call_create(mock_server: &MockServer, program_call_data: &str) {
    Mock::given(method("POST"))
        .and(path("/v1/transactions"))
        .and(header("X-API-Key", "test-api-key"))
        .and(body_partial_json(serde_json::json!({
            "operation": "PROGRAM_CALL",
            "extraParameters": {
                "programCallData": program_call_data,
                "signOnly": true,
                "useDurableNonce": false
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-789",
            "status": "SUBMITTED"
        })))
        .expect(1)
        .mount(mock_server)
        .await;
}

async fn mount_program_call_poll(mock_server: &MockServer, body: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/v1/transactions/tx-789"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(mock_server)
        .await;
}

#[test]
fn test_new_valid() {
    let signer = FireblocksSigner::new(FireblocksSignerConfig {
        api_key: "test-key".to_string(),
        private_key_pem: TEST_RSA_KEY.to_string(),
        vault_account_id: "test-vault".to_string(),
        asset_id: None,
        api_base_url: None,
        poll_interval_ms: None,
        max_poll_attempts: None,
        use_program_call: None,
        http_client_config: None,
    });
    assert_eq!(signer.asset_id, "SOL");
    assert_eq!(signer.public_key, None);
    assert!(!signer.use_program_call); // Default is RAW (matching other signers)
}

#[tokio::test]
async fn test_init_success() {
    let mock_server = MockServer::start().await;
    let mut signer = create_test_signer_uninit(&mock_server.uri());

    Mock::given(method("GET"))
        .and(path(
            "/v1/vault/accounts/test-vault-id/SOL/addresses_paginated",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "addresses": [{ "address": TEST_PUBKEY }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.init().await;
    assert!(result.is_ok());
    assert_eq!(signer.pubkey().to_string(), TEST_PUBKEY);
}

/// Serve `entries` from addresses_paginated and run `init()`.
async fn init_with_addresses(
    mock_server: &MockServer,
    entries: serde_json::Value,
) -> Result<FireblocksSigner, SignerError> {
    init_with_asset_addresses(mock_server, "SOL", entries).await
}

/// Serve `entries` for a signer configured with `asset_id` and run `init()`.
async fn init_with_asset_addresses(
    mock_server: &MockServer,
    asset_id: &str,
    entries: serde_json::Value,
) -> Result<FireblocksSigner, SignerError> {
    let mut signer = create_test_signer_uninit(&mock_server.uri());
    signer.asset_id = asset_id.to_string();
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/vault/accounts/test-vault-id/{asset_id}/addresses_paginated"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "addresses": entries })),
        )
        .expect(1)
        .mount(mock_server)
        .await;
    signer.init().await?;
    Ok(signer)
}

#[tokio::test]
async fn test_init_selects_address_for_configured_asset() {
    let mock_server = MockServer::start().await;
    let signer = init_with_addresses(
        &mock_server,
        serde_json::json!([
            { "address": OTHER_TEST_PUBKEY, "assetId": "SOL_TEST" },
            { "address": TEST_PUBKEY, "assetId": "SOL" },
        ]),
    )
    .await
    .expect("init should select the SOL address");
    assert_eq!(signer.pubkey().to_string(), TEST_PUBKEY);
}

#[tokio::test]
async fn test_init_selects_address_for_custom_asset_id() {
    let mock_server = MockServer::start().await;
    let signer = init_with_asset_addresses(
        &mock_server,
        "SOL_TEST",
        serde_json::json!([
            { "address": OTHER_TEST_PUBKEY, "assetId": "SOL" },
            { "address": TEST_PUBKEY, "assetId": "SOL_TEST" },
        ]),
    )
    .await
    .expect("init should select the configured asset's address");
    assert_eq!(signer.pubkey().to_string(), TEST_PUBKEY);
}

#[tokio::test]
async fn test_init_rejects_ambiguous_addresses() {
    let mock_server = MockServer::start().await;
    let result = init_with_addresses(
        &mock_server,
        serde_json::json!([
            { "address": TEST_PUBKEY, "assetId": "SOL" },
            { "address": OTHER_TEST_PUBKEY, "assetId": "SOL" },
        ]),
    )
    .await;
    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPublicKey(_)
    ));
}

#[tokio::test]
async fn test_init_rejects_no_address_for_configured_asset() {
    let mock_server = MockServer::start().await;
    let result = init_with_addresses(
        &mock_server,
        serde_json::json!([{ "address": TEST_PUBKEY, "assetId": "SOL_TEST" }]),
    )
    .await;
    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPublicKey(_)
    ));
}

/// Duplicate entries for the same address are not ambiguous.
#[tokio::test]
async fn test_init_accepts_duplicate_address_entries() {
    let mock_server = MockServer::start().await;
    let signer = init_with_addresses(
        &mock_server,
        serde_json::json!([
            { "address": TEST_PUBKEY, "assetId": "SOL" },
            { "address": TEST_PUBKEY, "assetId": "SOL" },
        ]),
    )
    .await
    .expect("duplicate entries for one address must be accepted");
    assert_eq!(signer.pubkey().to_string(), TEST_PUBKEY);
}

#[test]
#[should_panic(expected = "FireblocksSigner not initialized")]
fn test_pubkey_requires_init() {
    let signer = create_test_signer_uninit("http://localhost");
    let _ = signer.pubkey();
}

#[tokio::test]
async fn test_init_api_error() {
    let mock_server = MockServer::start().await;
    let mut signer = create_test_signer_uninit(&mock_server.uri());

    Mock::given(method("GET"))
        .and(path(
            "/v1/vault/accounts/test-vault-id/SOL/addresses_paginated",
        ))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.init().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_sign_message_success() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();
    let message = b"test message";
    let signature = keypair.sign_message(message);
    let sig_hex = hex::encode(signature.as_ref());

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = Some(keypair_pubkey(&keypair));

    // Mock create transaction
    Mock::given(method("POST"))
        .and(path("/v1/transactions"))
        .and(header("X-API-Key", "test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "SUBMITTED"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Mock get transaction (polling)
    Mock::given(method("GET"))
        .and(path("/v1/transactions/tx-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "COMPLETED",
            "signedMessages": [{
                "signature": {
                    "fullSig": sig_hex
                }
            }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(message).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), signature);
}

#[tokio::test]
async fn test_sign_message_signature_verification_failure() {
    let mock_server = MockServer::start().await;
    let signing_keypair = Keypair::new();
    let different_keypair = Keypair::new();
    let message = b"test message";
    let signature = signing_keypair.sign_message(message);
    let sig_hex = hex::encode(signature.as_ref());

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = Some(keypair_pubkey(&different_keypair));

    Mock::given(method("POST"))
        .and(path("/v1/transactions"))
        .and(header("X-API-Key", "test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "SUBMITTED"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/transactions/tx-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "COMPLETED",
            "signedMessages": [{
                "signature": {
                    "fullSig": sig_hex
                }
            }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(message).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_sign_message_api_error() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/v1/transactions"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_sign_message_requires_init() {
    let signer = create_test_signer_uninit("http://localhost");
    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[tokio::test]
async fn test_sign_message_transaction_failed() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/v1/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "SUBMITTED"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/transactions/tx-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "FAILED",
            "signedMessages": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_is_available_success() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    Mock::given(method("GET"))
        .and(path_regex(r"/v1/vault/accounts/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-vault-id",
            "name": "Test Vault"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(signer.is_available().await);
}

#[tokio::test]
async fn test_is_available_failure() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    Mock::given(method("GET"))
        .and(path_regex(r"/v1/vault/accounts/.*"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_is_available_uninitialized_false() {
    let signer = create_test_signer_uninit("http://localhost");
    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_program_call_signs_only_and_takes_the_signature_from_signed_messages() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();
    let mut transaction = create_test_transaction(&keypair_pubkey(&keypair));
    let message_bytes = transaction.message.serialize();
    let signature = keypair.sign_message(&message_bytes);

    let signer = create_test_signer_program_call(&mock_server.uri(), keypair_pubkey(&keypair));

    mount_program_call_create(
        &mock_server,
        &TransactionUtil::serialize_transaction(&transaction).unwrap(),
    )
    .await;
    mount_program_call_poll(
        &mock_server,
        serde_json::json!({
            "id": "tx-789",
            "status": "SIGNED",
            "signedMessages": [{ "signature": { "fullSig": hex::encode(signature.as_ref()) } }]
        }),
    )
    .await;

    signer.sign_transaction(&mut transaction).await.unwrap();

    assert_eq!(transaction.signatures[0], signature);
}

#[tokio::test]
async fn test_program_call_accepts_the_signature_carried_as_tx_hash() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();
    let mut transaction = create_test_transaction(&keypair_pubkey(&keypair));
    let message_bytes = transaction.message.serialize();
    let signature = keypair.sign_message(&message_bytes);

    let signer = create_test_signer_program_call(&mock_server.uri(), keypair_pubkey(&keypair));

    mount_program_call_create(
        &mock_server,
        &TransactionUtil::serialize_transaction(&transaction).unwrap(),
    )
    .await;
    mount_program_call_poll(
        &mock_server,
        serde_json::json!({
            "id": "tx-789",
            "status": "SIGNED",
            "txHash": bs58::encode(signature.as_ref()).into_string()
        }),
    )
    .await;

    signer.sign_transaction(&mut transaction).await.unwrap();

    assert_eq!(transaction.signatures[0], signature);
}

#[tokio::test]
async fn test_program_call_rejects_a_tx_hash_that_is_not_the_vault_signature() {
    let mock_server = MockServer::start().await;
    let vault = Keypair::new();
    let other_signer = Keypair::new();
    let mut transaction = create_test_transaction(&keypair_pubkey(&vault));
    let foreign_signature = other_signer.sign_message(&transaction.message.serialize());

    let signer = create_test_signer_program_call(&mock_server.uri(), keypair_pubkey(&vault));

    mount_program_call_create(
        &mock_server,
        &TransactionUtil::serialize_transaction(&transaction).unwrap(),
    )
    .await;
    mount_program_call_poll(
        &mock_server,
        serde_json::json!({
            "id": "tx-789",
            "status": "SIGNED",
            "txHash": bs58::encode(foreign_signature.as_ref()).into_string()
        }),
    )
    .await;

    let result = signer.sign_transaction(&mut transaction).await;

    assert!(matches!(result, Err(SignerError::SigningFailed(_))));
    assert_eq!(
        transaction.signatures[0],
        Signature::default(),
        "an unverified signature must not reach the transaction"
    );
}

#[tokio::test]
async fn test_program_call_broadcast_despite_sign_only_is_reported_as_unconfirmed() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();
    let mut transaction = create_test_transaction(&keypair_pubkey(&keypair));
    let signature = keypair.sign_message(&transaction.message.serialize());

    let signer = create_test_signer_program_call(&mock_server.uri(), keypair_pubkey(&keypair));

    mount_program_call_create(
        &mock_server,
        &TransactionUtil::serialize_transaction(&transaction).unwrap(),
    )
    .await;
    mount_program_call_poll(
        &mock_server,
        serde_json::json!({
            "id": "tx-789",
            "status": "BROADCASTING",
            "txHash": bs58::encode(signature.as_ref()).into_string()
        }),
    )
    .await;

    let result = signer.sign_transaction(&mut transaction).await;

    match result {
        Err(SignerError::BroadcastUnconfirmed { provider_tx_id, .. }) => {
            assert_eq!(provider_tx_id.as_deref(), Some("tx-789"));
        }
        other => unreachable!("expected BroadcastUnconfirmed, got {other:?}"),
    }
}

#[cfg(feature = "sdk-v4")]
#[tokio::test]
async fn test_program_call_rejects_a_v1_message_before_any_network_call() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();
    let mut transaction = crate::test_util::create_test_v1_transaction(&keypair_pubkey(&keypair));

    let signer = create_test_signer_program_call(&mock_server.uri(), keypair_pubkey(&keypair));

    let result = signer.sign_transaction(&mut transaction).await;

    assert!(matches!(result, Err(SignerError::SigningFailed(_))));
    assert!(
        mock_server.received_requests().await.unwrap().is_empty(),
        "a v1 message must be rejected before the PROGRAM_CALL is created"
    );
}

#[tokio::test]
async fn test_sign_transaction_requires_init() {
    let signer = create_test_signer_uninit("http://localhost");
    let mut transaction = create_test_transaction(&Pubkey::new_unique());

    let result = signer.sign_transaction(&mut transaction).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_use_program_call_config_carried_but_constructor_is_infallible() {
    // Construction never fails; the unsupported PROGRAM_CALL flag is carried
    // through and rejected later at init() (see the init rejection test).
    let signer_program_call = FireblocksSigner::new(FireblocksSignerConfig {
        api_key: "test-key".to_string(),
        private_key_pem: TEST_RSA_KEY.to_string(),
        vault_account_id: "test-vault".to_string(),
        asset_id: None,
        api_base_url: None,
        poll_interval_ms: None,
        max_poll_attempts: None,
        use_program_call: Some(true),
        http_client_config: None,
    });
    assert!(signer_program_call.use_program_call);

    // Explicit RAW mode (the only supported mode).
    let signer_raw = FireblocksSigner::new(FireblocksSignerConfig {
        api_key: "test-key".to_string(),
        private_key_pem: TEST_RSA_KEY.to_string(),
        vault_account_id: "test-vault".to_string(),
        asset_id: None,
        api_base_url: None,
        poll_interval_ms: None,
        max_poll_attempts: None,
        use_program_call: Some(false),
        http_client_config: None,
    });
    assert!(!signer_raw.use_program_call);
}
