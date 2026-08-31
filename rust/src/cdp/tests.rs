use super::jwt;
use super::*;
use crate::sdk_adapter::{
    keypair_from_seed, keypair_pubkey, keypair_sign_message, Keypair, Pubkey,
};
use crate::test_util::{create_test_transaction, create_test_transaction_with_recipient};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use wiremock::{
    matchers::{method, path_regex},
    Mock, MockServer, ResponseTemplate,
};

const TEST_PUBKEY: &str = "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV";

/// Real keypair required to pass JWT validation.
fn test_ed25519_key() -> String {
    let seed = [0x42u8; 32];
    let keypair = keypair_from_seed(&seed).expect("failed to derive test keypair");
    let pubkey = keypair_pubkey(&keypair).to_bytes();

    let mut key_bytes = [0u8; 64];
    key_bytes[..32].copy_from_slice(&seed);
    key_bytes[32..].copy_from_slice(pubkey.as_ref());
    STANDARD.encode(key_bytes)
}

/// Return a valid wallet secret for tests: base64 of a minimal P-256 PKCS#8 DER.
///
/// Structure (67 bytes):
///   SEQUENCE { INTEGER 0, SEQUENCE { OID ecPublicKey, OID prime256v1 },
///     OCTET STRING { SEQUENCE { INTEGER 1, OCTET STRING [32-byte scalar] } } }
fn test_wallet_secret() -> String {
    #[rustfmt::skip]
        const P256_PKCS8_DER: &[u8] = &[
            // outer SEQUENCE (65 bytes)
            0x30, 0x41,
            // version INTEGER 0
            0x02, 0x01, 0x00,
            // AlgorithmIdentifier SEQUENCE (19 bytes)
            0x30, 0x13,
            // OID ecPublicKey (1.2.840.10045.2.1)
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            // OID prime256v1 (1.2.840.10045.3.1.7)
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            // privateKey OCTET STRING (39 bytes)
            0x04, 0x27,
            // ECPrivateKey SEQUENCE (37 bytes)
            0x30, 0x25,
            // version INTEGER 1
            0x02, 0x01, 0x01,
            // privateKey OCTET STRING (32 bytes) — scalar in [1, n-1]
            0x04, 0x20,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];
    STANDARD.encode(P256_PKCS8_DER)
}

fn create_test_signer(base_url: &str) -> CdpSigner {
    let api_host = extract_host(base_url, "CDP").expect("failed to parse test base URL");
    CdpSigner {
        api_key_id: "test-api-key".to_string(),
        api_key_secret: test_ed25519_key(),
        wallet_secret: test_wallet_secret(),
        public_key: Pubkey::from_str(TEST_PUBKEY).unwrap(),
        api_base_url: base_url.to_string(),
        api_host,
        client: reqwest::Client::new(),
    }
}

#[test]
fn test_new_valid() {
    let signer = CdpSigner::new(
        "test-key".to_string(),
        test_ed25519_key(),
        test_wallet_secret(),
        TEST_PUBKEY.to_string(),
    );

    assert!(signer.is_ok());
    let signer = signer.unwrap();
    assert_eq!(signer.public_key.to_string(), TEST_PUBKEY);
}

#[test]
fn test_new_empty_api_key_id() {
    let result = CdpSigner::new(
        "".to_string(),
        "private".to_string(),
        "secret".to_string(),
        TEST_PUBKEY.to_string(),
    );
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_new_empty_api_key_secret() {
    let result = CdpSigner::new(
        "key".to_string(),
        "".to_string(),
        "secret".to_string(),
        TEST_PUBKEY.to_string(),
    );
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_new_empty_wallet_secret() {
    let result = CdpSigner::new(
        "key".to_string(),
        "private".to_string(),
        "".to_string(),
        TEST_PUBKEY.to_string(),
    );
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_new_empty_address() {
    let result = CdpSigner::new(
        "key".to_string(),
        "private".to_string(),
        "secret".to_string(),
        "".to_string(),
    );
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
}

#[test]
fn test_new_invalid_address() {
    let result = CdpSigner::new(
        "key".to_string(),
        "private".to_string(),
        "secret".to_string(),
        "not-a-valid-pubkey".to_string(),
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPublicKey(_)
    ));
}

#[test]
fn test_pubkey() {
    let signer = create_test_signer("http://localhost");
    assert_eq!(signer.pubkey().to_string(), TEST_PUBKEY);
}

#[test]
fn test_debug_does_not_leak_secrets() {
    let signer = create_test_signer("http://localhost");
    let debug_str = format!("{signer:?}");
    assert!(!debug_str.contains(&test_ed25519_key()));
    assert!(!debug_str.contains(&test_wallet_secret()));
    assert!(debug_str.contains("CdpSigner"));
}

#[tokio::test]
async fn test_sign_message_invalid_api_key_secret() {
    let mut signer = create_test_signer("http://localhost");
    signer.api_key_secret = "not-base64".to_string();

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPrivateKey(_)
    ));
}

#[tokio::test]
async fn test_sign_message_invalid_wallet_secret() {
    let mut signer = create_test_signer("http://localhost");
    signer.wallet_secret = "not-base64".to_string();

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
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

    // Create a valid 64-byte signature
    let test_message = b"test message";
    let signature = keypair_sign_message(&keypair, test_message);
    let sig_base58 = bs58::encode(signature.as_ref()).into_string();

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = pubkey;

    Mock::given(method("POST"))
        .and(path_regex(r".*/sign/message$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature": sig_base58
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
    let different_keypair = Keypair::new();
    let test_message = b"test message";
    let signature = keypair_sign_message(&signing_keypair, test_message);
    let sig_base58 = bs58::encode(signature.as_ref()).into_string();

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = keypair_pubkey(&different_keypair);

    Mock::given(method("POST"))
        .and(path_regex(r".*/sign/message$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature": sig_base58
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(test_message).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_sign_message_api_error() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    Mock::given(method("POST"))
        .and(path_regex(r".*/sign/message$"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError { .. }
    ));
}

#[tokio::test]
async fn test_sign_message_invalid_signature_length() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    // Return a base58-encoded value that decodes to != 64 bytes
    let short_sig = bs58::encode(&[0u8; 10]).into_string();

    Mock::given(method("POST"))
        .and(path_regex(r".*/sign/message$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature": short_sig
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_sign_transaction_success() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();
    let pubkey = keypair_pubkey(&keypair);

    let mut tx = create_test_transaction(&pubkey);
    let signature = keypair_sign_message(&keypair, &tx.message.serialize());

    let mut signed_tx = tx.clone();
    signed_tx.signatures = vec![signature];

    // Serialize the signed transaction to get the base64 wire format
    let serialized = bincode::serialize(&signed_tx).unwrap();
    let base64_signed_tx = STANDARD.encode(&serialized);

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = pubkey;

    Mock::given(method("POST"))
        .and(path_regex(r".*/sign/transaction$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signedTransaction": base64_signed_tx
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
    assert_eq!(
        returned_base64,
        TransactionUtil::serialize_transaction(&tx).unwrap()
    );
}

#[tokio::test]
async fn test_sign_transaction_rejects_tampered_remote_transaction() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();
    let pubkey = keypair_pubkey(&keypair);

    let mut tx = create_test_transaction(&pubkey);
    let original_message = tx.message.clone();

    // Simulate a compromised API returning a signature over a different transaction.
    let tampered_recipient = Pubkey::new_unique();
    let mut tampered_tx = create_test_transaction_with_recipient(&pubkey, &tampered_recipient);
    let tampered_signature = keypair_sign_message(&keypair, &tampered_tx.message.serialize());
    tampered_tx.signatures = vec![tampered_signature];

    let serialized = bincode::serialize(&tampered_tx).unwrap();
    let base64_signed_tx = STANDARD.encode(&serialized);

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = pubkey;

    Mock::given(method("POST"))
        .and(path_regex(r".*/sign/transaction$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signedTransaction": base64_signed_tx
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    assert_eq!(tx.message, original_message);
}

#[tokio::test]
async fn test_sign_transaction_api_error() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    Mock::given(method("POST"))
        .and(path_regex(r".*/sign/transaction$"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut tx = create_test_transaction(&Pubkey::from_str(TEST_PUBKEY).unwrap());
    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError { .. }
    ));
}

#[tokio::test]
async fn test_is_available_success() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    Mock::given(method("GET"))
        .and(path_regex(r".*/accounts/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "address": TEST_PUBKEY
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
        .and(path_regex(r".*/accounts/.*"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_clone() {
    let signer = create_test_signer("http://localhost");
    let clone = signer.clone();
    assert_eq!(signer.pubkey(), clone.pubkey());
}

#[test]
fn test_der_to_pkcs8_pem() {
    let der = vec![0x30u8, 0x2e, 0x01]; // minimal fake DER
    let pem = jwt::der_to_pkcs8_pem(&der);
    assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(pem.contains("-----END PRIVATE KEY-----"));
}

#[test]
fn test_auth_jwt_lifetime() {
    let token = jwt::create_auth_jwt(
        "test-api-key",
        &test_ed25519_key(),
        "api.cdp.coinbase.com",
        "GET",
        "/platform/v2/solana/accounts/abc",
    )
    .expect("failed to create auth JWT");

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(
            token
                .split('.')
                .nth(1)
                .expect("JWT payload should be present"),
        )
        .expect("failed to decode JWT payload");
    let payload: Value =
        serde_json::from_slice(&payload_bytes).expect("failed to parse JWT payload");

    let iat = payload["iat"].as_i64().expect("iat missing from auth JWT");
    let exp = payload["exp"].as_i64().expect("exp missing from auth JWT");
    assert_eq!(exp - iat, 120);
}

#[test]
fn test_wallet_jwt_includes_req_hash() {
    let request_body = serde_json::json!({
        "b": 2,
        "a": {
            "d": 4,
            "c": 3
        }
    });

    let expected_hash = crate::wallet_jwt::compute_req_hash(Some(&request_body))
        .expect("failed to compute reqHash");

    let token = create_wallet_jwt(
        &test_wallet_secret(),
        "api.cdp.coinbase.com",
        "POST",
        "/platform/v2/solana/accounts/abc/sign/message",
        Some(&request_body),
    )
    .expect("failed to create wallet JWT");

    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("failed to decode JWT payload");
    let payload: Value =
        serde_json::from_slice(&payload_bytes).expect("failed to parse JWT payload");

    let iat = payload["iat"]
        .as_i64()
        .expect("iat missing from wallet JWT");
    let exp = payload["exp"]
        .as_i64()
        .expect("exp missing from wallet JWT");
    assert_eq!(exp - iat, 60);

    let req_hash = payload
        .get("reqHash")
        .and_then(|value| value.as_str())
        .expect("reqHash missing in wallet JWT payload");

    assert_eq!(Some(req_hash.to_string()), expected_hash);
}
