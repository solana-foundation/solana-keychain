use super::*;
use crate::sdk_adapter::{Keypair, Signer};
use crate::test_util::create_test_transaction;
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

const TEST_VAULT_ADDR: &str = "http://127.0.0.1:8200";
const TEST_VAULT_TOKEN: &str = "test-token";
const TEST_KEY_NAME: &str = "test-key";
const TEST_PUBKEY: &str = "2vfDxWYbhRt7GXiRYKf1Dr5Z8y7zVQCSERbDTKyBaAqQ";

fn create_test_http_client() -> Arc<Client> {
    Arc::new(Client::new())
}

fn create_test_signer() -> VaultSigner {
    let mut signer = VaultSigner::new(
        TEST_VAULT_ADDR.to_string(),
        TEST_VAULT_TOKEN.to_string(),
        TEST_KEY_NAME.to_string(),
        TEST_PUBKEY.to_string(),
    )
    .expect("Failed to create test signer");
    signer.client = create_test_http_client();
    signer
}

fn create_test_signer_with_pubkey(vault_addr: &str, pubkey: String) -> VaultSigner {
    let mut signer = VaultSigner::new(
        vault_addr.to_string(),
        TEST_VAULT_TOKEN.to_string(),
        TEST_KEY_NAME.to_string(),
        pubkey,
    )
    .expect("Failed to create test signer");
    signer.client = create_test_http_client();
    signer
}

#[test]
fn test_create_vault_signer() {
    let signer = VaultSigner::new(
        TEST_VAULT_ADDR.to_string(),
        TEST_VAULT_TOKEN.to_string(),
        TEST_KEY_NAME.to_string(),
        TEST_PUBKEY.to_string(),
    );
    assert!(signer.is_ok());
}

#[tokio::test]
async fn test_with_client_builder_uses_supplied_builder() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();
    let message = b"with-client-message";
    let signature = keypair.sign_message(message);
    let signature_b64 = STANDARD.encode(signature.as_ref());

    Mock::given(method("POST"))
        .and(path("/v1/transit/sign/test-key"))
        .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
        .and(body_json(serde_json::json!({
            "input": STANDARD.encode(message),
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "signature": format!("vault:v1:{signature_b64}") }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Plain-http builder: `with_client_builder` leaves TLS policy to the caller.
    let signer = VaultSigner::with_client_builder(
        Client::builder(),
        mock_server.uri(),
        TEST_VAULT_TOKEN.to_string(),
        TEST_KEY_NAME.to_string(),
        keypair.pubkey().to_string(),
    )
    .expect("with_client_builder should accept a caller-configured builder");

    let result = signer.sign_message(message).await;
    assert!(result.is_ok(), "sign_message failed: {:?}", result.err());
    assert_eq!(result.unwrap(), signature);
}

#[tokio::test]
async fn test_with_client_builder_enforces_no_redirect_policy() {
    // The redirect must fail rather than replay X-Vault-Token to the target.
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/collect"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&target)
        .await;

    let origin = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/sign/test-key"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", format!("{}/collect", target.uri()).as_str()),
        )
        .expect(1)
        .mount(&origin)
        .await;

    let signer = VaultSigner::with_client_builder(
        Client::builder().redirect(reqwest::redirect::Policy::limited(10)),
        origin.uri(),
        TEST_VAULT_TOKEN.to_string(),
        TEST_KEY_NAME.to_string(),
        TEST_PUBKEY.to_string(),
    )
    .unwrap();

    let result = signer.sign_message(b"redirect-message").await;
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
}

#[test]
fn test_invalid_pubkey() {
    let signer = VaultSigner::new(
        TEST_VAULT_ADDR.to_string(),
        TEST_VAULT_TOKEN.to_string(),
        TEST_KEY_NAME.to_string(),
        "invalid-pubkey".to_string(),
    );
    assert!(signer.is_err());
}

#[test]
fn test_pubkey() {
    let signer = create_test_signer();
    let pubkey = signer.pubkey();
    assert_eq!(pubkey.to_string(), TEST_PUBKEY);
}

#[test]
fn test_debug_impl() {
    let signer = create_test_signer();
    let debug_str = format!("{:?}", signer);
    assert!(debug_str.contains("VaultSigner"));
    assert!(debug_str.contains("public_key"));
}

#[test]
fn test_strip_vault_signature_prefix_v1() {
    assert_eq!(
        VaultSigner::strip_vault_signature_prefix("vault:v1:abc123"),
        "abc123"
    );
}

#[test]
fn test_strip_vault_signature_prefix_higher_version() {
    assert_eq!(
        VaultSigner::strip_vault_signature_prefix("vault:v27:abc123"),
        "abc123"
    );
}

#[test]
fn test_strip_vault_signature_prefix_no_prefix() {
    assert_eq!(
        VaultSigner::strip_vault_signature_prefix("abc123"),
        "abc123"
    );
}

#[test]
fn test_strip_vault_signature_prefix_invalid_version_segment() {
    assert_eq!(
        VaultSigner::strip_vault_signature_prefix("vault:vx:abc123"),
        "vault:vx:abc123"
    );
    assert_eq!(
        VaultSigner::strip_vault_signature_prefix("vault:v:abc123"),
        "vault:v:abc123"
    );
}

#[tokio::test]
async fn test_sign_message_success() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();
    let message = b"vault-message";
    let signature = keypair.sign_message(message);
    let signature_b64 = STANDARD.encode(signature.as_ref());

    Mock::given(method("POST"))
        .and(path("/v1/transit/sign/test-key"))
        .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
        .and(body_json(serde_json::json!({
            "input": STANDARD.encode(message),
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "signature": format!("vault:v1:{signature_b64}")
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let signer = create_test_signer_with_pubkey(&mock_server.uri(), keypair.pubkey().to_string());
    let result = signer.sign_message(message).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), signature);
}

#[tokio::test]
async fn test_sign_message_signature_verification_failure() {
    let mock_server = MockServer::start().await;
    let signing_keypair = Keypair::new();
    let different_keypair = Keypair::new();
    let message = b"vault-message";
    let signature = signing_keypair.sign_message(message);
    let signature_b64 = STANDARD.encode(signature.as_ref());

    Mock::given(method("POST"))
        .and(path("/v1/transit/sign/test-key"))
        .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
        .and(body_json(serde_json::json!({
            "input": STANDARD.encode(message),
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "signature": format!("vault:v1:{signature_b64}")
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let signer =
        create_test_signer_with_pubkey(&mock_server.uri(), different_keypair.pubkey().to_string());
    let result = signer.sign_message(message).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_sign_message_api_error() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer_with_pubkey(&mock_server.uri(), TEST_PUBKEY.to_string());

    Mock::given(method("POST"))
        .and(path("/v1/transit/sign/test-key"))
        .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "errors": ["unauthorized"]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"hello").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
}

#[tokio::test]
async fn test_sign_message_refuses_redirects() {
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&target)
        .await;

    let origin = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/sign/test-key"))
        .respond_with(ResponseTemplate::new(307).insert_header(
            "Location",
            format!("{}/v1/transit/sign/test-key", target.uri()).as_str(),
        ))
        .expect(1)
        .mount(&origin)
        .await;

    let mut signer = create_test_signer_with_pubkey(&origin.uri(), TEST_PUBKEY.to_string());
    signer.client = Arc::new(
        Client::builder()
            .redirect(crate::http_client_config::no_redirect_policy())
            .build()
            .unwrap(),
    );

    let result = signer.sign_message(b"hello").await;
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
}

#[tokio::test]
async fn test_sign_transaction_success() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();
    let signer = create_test_signer_with_pubkey(&mock_server.uri(), keypair.pubkey().to_string());
    let mut tx = create_test_transaction(&keypair.pubkey());
    let signature = keypair.sign_message(&tx.message.serialize());
    let signature_b64 = STANDARD.encode(signature.as_ref());

    Mock::given(method("POST"))
        .and(path("/v1/transit/sign/test-key"))
        .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "signature": format!("vault:v2:{signature_b64}")
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_ok());
    let (serialized_tx, returned_sig) = result.unwrap().into_signed_transaction();

    assert_eq!(returned_sig, signature);
    assert!(!serialized_tx.is_empty());
    assert_eq!(tx.signatures.len(), 1);
    assert_eq!(tx.signatures[0], signature);
}

#[tokio::test]
async fn test_is_available_success() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer_with_pubkey(&mock_server.uri(), TEST_PUBKEY.to_string());

    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/test-key"))
        .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "name": "test-key",
                "supports_signing": true,
                "type": "ed25519"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(signer.is_available().await);
}

#[tokio::test]
async fn test_is_available_false_for_unsupported_key_type() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer_with_pubkey(&mock_server.uri(), TEST_PUBKEY.to_string());

    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/test-key"))
        .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "name": "test-key",
                "supports_signing": true,
                "type": "rsa-2048"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_is_available_false_when_key_does_not_support_signing() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer_with_pubkey(&mock_server.uri(), TEST_PUBKEY.to_string());

    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/test-key"))
        .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "name": "test-key",
                "supports_signing": false,
                "type": "ed25519"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_is_available_failure() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer_with_pubkey(&mock_server.uri(), TEST_PUBKEY.to_string());

    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/test-key"))
        .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errors": ["forbidden"]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(!signer.is_available().await);
}
