use super::*;
use crate::sdk_adapter::{keypair_pubkey, Keypair, Signer};
use crate::test_util::create_test_transaction;
use std::panic::{self, AssertUnwindSafe};
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

fn create_test_keypair() -> Keypair {
    Keypair::new()
}

#[tokio::test]
async fn test_privy_new() {
    let signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();

    assert_eq!(signer.app_id, "test-app-id");
    assert_eq!(signer.wallet_id, "test-wallet-id");
    assert_eq!(signer.public_key, None);
}

#[tokio::test]
async fn test_privy_fetch_public_key() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let pubkey_str = keypair.pubkey().to_string();

    // Mock the wallet GET endpoint
    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .and(header(
            "Authorization",
            "Basic dGVzdC1hcHAtaWQ6dGVzdC1hcHAtc2VjcmV0",
        )) // base64("test-app-id:test-app-secret")
        .and(header("privy-app-id", "test-app-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": pubkey_str,
            "chain_type": "solana"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.init().await;
    assert!(result.is_ok());
    assert_eq!(signer.pubkey(), keypair.pubkey());
}

#[tokio::test]
async fn test_privy_sign_message_rejects_oversized_response_body() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    // A body just past the 1 MiB cap: the bounded body reader in post_rpc
    // must refuse it before any parsing happens.
    let oversized_body = vec![b'a'; crate::remote_util::MAX_RESPONSE_BYTES + 1];
    Mock::given(method("POST"))
        .and(path("/wallets/test-wallet-id/rpc"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();
    signer.public_key = Some(keypair.pubkey());

    let error = signer.sign_message(&[1, 2, 3, 4]).await.unwrap_err();
    assert!(matches!(error, SignerError::SerializationError(_)));
}

#[tokio::test]
async fn test_privy_sign_message() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    // Create a signed transaction
    let tx = create_test_transaction(&keypair_pubkey(&keypair));
    let signature = keypair.sign_message(&tx.message.serialize());

    let mut signed_tx = tx.clone();
    signed_tx.signatures = vec![signature];

    // Mock the RPC signing endpoint
    Mock::given(method("POST"))
        .and(path("/wallets/test-wallet-id/rpc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "method": "signMessage",
            "data": {
                "signature": STANDARD.encode(signature),
                "encoding": "base64"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();
    signer.public_key = Some(keypair.pubkey());

    let result = signer.sign_message(&tx.message.serialize()).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), signature);
}

#[tokio::test]
async fn test_privy_sign_message_authorization_context_headers() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let message = [1, 2, 3, 4];
    let signature = keypair.sign_message(&message);

    Mock::given(method("POST"))
        .and(path("/wallets/test-wallet-id/rpc"))
        .and(header(
            "privy-authorization-signature",
            "authorization-signature",
        ))
        .and(body_json(serde_json::json!({
            "method": "signMessage",
            "chain_type": "solana",
            "params": {
                "message": "AQIDBA==",
                "encoding": "base64"
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "method": "signMessage",
            "data": {
                "signature": STANDARD.encode(signature),
                "encoding": "base64"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::from_config(PrivySignerConfig {
        app_id: "test-app-id".to_string(),
        app_secret: "test-app-secret".to_string(),
        wallet_id: "test-wallet-id".to_string(),
        api_base_url: Some(mock_server.uri()),
        http_client_config: None,
        authorization_context: Some(PrivyAuthorizationConfig::from(PrivyAuthorizationContext {
            signatures: vec!["authorization-signature".to_string()],
            ..Default::default()
        })),
        authorization_request_expiry: PrivyAuthorizationRequestExpiry::Omit,
    })
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.public_key = Some(keypair.pubkey());

    let result = signer.sign_message(&message).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), signature);
}

#[tokio::test]
async fn test_privy_sign_message_signature_verification_failure() {
    let mock_server = MockServer::start().await;
    let signing_keypair = create_test_keypair();
    let different_keypair = create_test_keypair();
    let message = b"test message";
    let signature = signing_keypair.sign_message(message);

    Mock::given(method("POST"))
        .and(path("/wallets/test-wallet-id/rpc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "method": "signMessage",
            "data": {
                "signature": STANDARD.encode(signature),
                "encoding": "base64"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();
    signer.public_key = Some(different_keypair.pubkey());

    let result = signer.sign_message(message).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_privy_sign_message_invalid_base64_signature() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    let tx = create_test_transaction(&keypair_pubkey(&keypair));

    Mock::given(method("POST"))
        .and(path("/wallets/test-wallet-id/rpc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "method": "signMessage",
            "data": {
                "signature": "not-base64###",
                "encoding": "base64"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();
    signer.public_key = Some(keypair.pubkey());

    let result = signer.sign_message(&tx.message.serialize()).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::SerializationError(_)
    ));
}

#[tokio::test]
async fn test_privy_sign_message_requires_init() {
    let signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[tokio::test]
async fn test_privy_sign_transaction() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    let mut tx = create_test_transaction(&keypair_pubkey(&keypair));

    // The signature that Privy API will return (signing the message_data)
    let signature = keypair.sign_message(&tx.message.serialize());

    // Create a signed transaction to return from the mock
    let mut signed_tx = tx.clone();
    signed_tx.signatures = vec![signature];

    // Mock the RPC signing endpoint - it returns the signed transaction
    Mock::given(method("POST"))
        .and(path("/wallets/test-wallet-id/rpc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "method": "signTransaction",
            "data": {
                "signed_transaction": STANDARD.encode(bincode::serialize(&signed_tx).unwrap()),
                "encoding": "base64"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();
    signer.public_key = Some(keypair.pubkey());

    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_ok());
    let (serialized_tx, returned_sig) = result.unwrap().into_signed_transaction();

    // Verify the signature matches
    assert_eq!(returned_sig, signature);

    // Verify the transaction is properly serialized
    assert!(!serialized_tx.is_empty());
    assert_eq!(tx.signatures, vec![signature]);
}

#[tokio::test]
async fn test_privy_sign_transaction_rejects_signature_over_different_bytes() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    let mut tx = create_test_transaction(&keypair_pubkey(&keypair));
    let mut other_tx = create_test_transaction(&keypair_pubkey(&keypair));
    other_tx.signatures = vec![keypair.sign_message(&other_tx.message.serialize())];

    Mock::given(method("POST"))
        .and(path("/wallets/test-wallet-id/rpc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "method": "signTransaction",
            "data": {
                "signed_transaction": STANDARD.encode(bincode::serialize(&other_tx).unwrap()),
                "encoding": "base64"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();
    signer.public_key = Some(keypair.pubkey());

    let result = signer.sign_transaction(&mut tx).await;
    match result.unwrap_err() {
        SignerError::SigningFailed(message) => {
            assert!(
                message.contains("verification failed"),
                "expected a verification failure, got: {message}"
            );
        }
        other => panic!("Expected SigningFailed, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_privy_sign_transaction_requires_init() {
    let keypair = create_test_keypair();
    let mut tx = create_test_transaction(&keypair_pubkey(&keypair));

    let signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();

    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[tokio::test]
async fn test_privy_pubkey_requires_init() {
    let signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();

    let result = panic::catch_unwind(AssertUnwindSafe(|| signer.pubkey()));
    assert!(result.is_err());
}

#[tokio::test]
async fn test_privy_pubkey() {
    let keypair = create_test_keypair();
    let mut signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.public_key = Some(keypair.pubkey());

    assert_eq!(signer.pubkey(), keypair.pubkey());
}

#[tokio::test]
async fn test_privy_fetch_public_key_unauthorized() {
    let mock_server = MockServer::start().await;

    // Mock 401 Unauthorized response
    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "Unauthorized"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::new(
        "bad-app-id".to_string(),
        "bad-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.init().await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
}

#[tokio::test]
async fn test_privy_fetch_public_key_invalid() {
    let mock_server = MockServer::start().await;

    // Mock response with invalid public key
    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": "not-a-valid-pubkey",
            "chain_type": "solana"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.init().await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPublicKey(_)
    ));
}

#[tokio::test]
async fn test_privy_sign_unauthorized() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    // Mock 401 Unauthorized response
    Mock::given(method("POST"))
        .and(path("/wallets/test-wallet-id/rpc"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "Unauthorized"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::new(
        "bad-app-id".to_string(),
        "bad-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();
    signer.public_key = Some(keypair.pubkey());

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
}

#[tokio::test]
async fn test_privy_is_available() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    // Not initialized
    let signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    assert!(!signer.is_available().await);

    // Initialized and remote API is reachable.
    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .and(header(
            "Authorization",
            "Basic dGVzdC1hcHAtaWQ6dGVzdC1hcHAtc2VjcmV0",
        ))
        .and(header("privy-app-id", "test-app-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "address": keypair.pubkey().to_string(),
            "chain_type": "solana"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();
    signer.public_key = Some(keypair.pubkey());
    assert!(signer.is_available().await);
}

#[tokio::test]
async fn test_privy_is_available_remote_failure() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "Unauthorized"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = PrivySigner::new(
        "test-app-id".to_string(),
        "test-app-secret".to_string(),
        "test-wallet-id".to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();
    signer.public_key = Some(keypair.pubkey());

    assert!(!signer.is_available().await);
}
