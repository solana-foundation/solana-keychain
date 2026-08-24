use super::*;
use crate::dfns::auth::tests::TEST_ED25519_PEM;
use crate::sdk_adapter::{keypair_pubkey, Keypair, Signer};
use crate::test_util::create_test_transaction;
use std::str::FromStr;
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

const TEST_KEY_ID: &str = "test-key-id";
const TEST_PUBKEY_HEX: &str = "5da30b28c87836b0ee76ae7b07e3a2e3be1a4c12e48fce3aee18de0a13040b9a";
// This is the base58 encoding of the above hex bytes
const TEST_PUBKEY: &str = "7JX7XMJ9TpfkKmz5u85DowRFyQabHsUgWajTmhToUfgM";

fn create_test_signer_uninit(base_url: &str) -> DfnsSigner {
    DfnsSigner {
        auth_token: "test-auth-token".to_string(),
        cred_id: "test-cred-id".to_string(),
        private_key_pem: TEST_ED25519_PEM.to_string(),
        wallet_id: "test-wallet-id".to_string(),
        key_id: String::new(),
        public_key: None,
        api_base_url: base_url.to_string(),
        client: reqwest::Client::new(),
    }
}

fn create_test_signer(base_url: &str) -> DfnsSigner {
    DfnsSigner {
        auth_token: "test-auth-token".to_string(),
        cred_id: "test-cred-id".to_string(),
        private_key_pem: TEST_ED25519_PEM.to_string(),
        wallet_id: "test-wallet-id".to_string(),
        key_id: TEST_KEY_ID.to_string(),
        public_key: Some(Pubkey::from_str(TEST_PUBKEY).unwrap()),
        api_base_url: base_url.to_string(),
        client: reqwest::Client::new(),
    }
}

fn wallet_response_json() -> serde_json::Value {
    serde_json::json!({
        "id": "test-wallet-id",
        "status": "Active",
        "network": "Solana",
        "signingKey": {
            "id": TEST_KEY_ID,
            "scheme": "EdDSA",
            "curve": "ed25519",
            "publicKey": TEST_PUBKEY_HEX
        }
    })
}

#[test]
fn test_new_valid() {
    let signer = DfnsSigner::new(DfnsSignerConfig {
        auth_token: "token".to_string(),
        cred_id: "cred".to_string(),
        private_key_pem: TEST_ED25519_PEM.to_string(),
        wallet_id: "wallet".to_string(),
        api_base_url: None,
        http_client_config: None,
    })
    .unwrap();
    assert_eq!(signer.api_base_url, "https://api.dfns.io");
    assert!(signer.public_key.is_none());
}

#[tokio::test]
async fn test_init_success() {
    let mock_server = MockServer::start().await;
    let mut signer = create_test_signer_uninit(&mock_server.uri());

    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(wallet_response_json()))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.init().await;
    assert!(result.is_ok());
    assert_eq!(signer.pubkey().to_string(), TEST_PUBKEY);
    assert_eq!(signer.key_id, TEST_KEY_ID);
}

#[tokio::test]
async fn test_init_api_error() {
    let mock_server = MockServer::start().await;
    let mut signer = create_test_signer_uninit(&mock_server.uri());

    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.init().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_init_invalid_scheme() {
    let mock_server = MockServer::start().await;
    let mut signer = create_test_signer_uninit(&mock_server.uri());

    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "test-wallet-id",
            "status": "Active",
            "network": "Ethereum",
            "signingKey": {
                "id": "key-id",
                "scheme": "ECDSA",
                "curve": "secp256k1",
                "publicKey": "abcd"
            }
        })))
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
    let sig_bytes = signature.as_ref();
    let r_hex = hex::encode(&sig_bytes[0..32]);
    let s_hex = hex::encode(&sig_bytes[32..64]);

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = Some(keypair_pubkey(&keypair));

    // Mock user action init
    Mock::given(method("POST"))
        .and(path("/auth/action/init"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "challenge": "test-challenge",
            "challengeIdentifier": "test-challenge-id",
            "allowCredentials": {
                "key": [{ "id": "test-cred-id" }]
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Mock user action sign
    Mock::given(method("POST"))
        .and(path("/auth/action"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "userAction": "test-user-action-token"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Mock generate signature via Keys API
    Mock::given(method("POST"))
        .and(path(format!("/keys/{}/signatures", TEST_KEY_ID)))
        .and(header("x-dfns-useraction", "test-user-action-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "sig-123",
            "status": "Signed",
            "signature": {
                "r": r_hex,
                "s": s_hex
            }
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
    let sig_bytes = signature.as_ref();
    let r_hex = hex::encode(&sig_bytes[0..32]);
    let s_hex = hex::encode(&sig_bytes[32..64]);

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = Some(keypair_pubkey(&different_keypair));

    Mock::given(method("POST"))
        .and(path("/auth/action/init"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "challenge": "test-challenge",
            "challengeIdentifier": "test-challenge-id",
            "allowCredentials": {
                "key": [{ "id": "test-cred-id" }]
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/auth/action"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "userAction": "test-user-action-token"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/keys/{}/signatures", TEST_KEY_ID)))
        .and(header("x-dfns-useraction", "test-user-action-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "sig-123",
            "status": "Signed",
            "signature": {
                "r": r_hex,
                "s": s_hex
            }
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

    // Mock user action init
    Mock::given(method("POST"))
        .and(path("/auth/action/init"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "challenge": "test-challenge",
            "challengeIdentifier": "test-challenge-id",
            "allowCredentials": { "key": [{ "id": "test-cred-id" }] }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/auth/action"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "userAction": "token"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Signing endpoint fails
    Mock::given(method("POST"))
        .and(path(format!("/keys/{}/signatures", TEST_KEY_ID)))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_sign_transaction_success() {
    let mock_server = MockServer::start().await;
    let keypair = Keypair::new();

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = Some(keypair_pubkey(&keypair));

    let mut transaction = create_test_transaction(&signer.pubkey());
    let signature = keypair.sign_message(&transaction.message.serialize());
    let sig_bytes = signature.as_ref();
    let r_hex = hex::encode(&sig_bytes[0..32]);
    let s_hex = hex::encode(&sig_bytes[32..64]);

    // Mock user action flow
    Mock::given(method("POST"))
        .and(path("/auth/action/init"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "challenge": "test-challenge",
            "challengeIdentifier": "test-challenge-id",
            "allowCredentials": { "key": [{ "id": "test-cred-id" }] }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/auth/action"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "userAction": "test-user-action-token"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/keys/{}/signatures", TEST_KEY_ID)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "sig-456",
            "status": "Signed",
            "signature": {
                "r": r_hex,
                "s": s_hex
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_transaction(&mut transaction).await;
    assert!(result.is_ok());
    let (_, returned_sig) = result.unwrap().into_signed_transaction();
    assert_eq!(returned_sig, signature);
}

#[tokio::test]
async fn test_sign_transaction_signature_verification_failure() {
    let mock_server = MockServer::start().await;
    let signing_keypair = Keypair::new();
    let different_keypair = Keypair::new();

    let mut signer = create_test_signer(&mock_server.uri());
    signer.public_key = Some(keypair_pubkey(&different_keypair));

    let mut transaction = create_test_transaction(&signer.pubkey());
    let signature = signing_keypair.sign_message(&transaction.message.serialize());
    let sig_bytes = signature.as_ref();
    let r_hex = hex::encode(&sig_bytes[0..32]);
    let s_hex = hex::encode(&sig_bytes[32..64]);

    Mock::given(method("POST"))
        .and(path("/auth/action/init"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "challenge": "test-challenge",
            "challengeIdentifier": "test-challenge-id",
            "allowCredentials": { "key": [{ "id": "test-cred-id" }] }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/auth/action"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "userAction": "test-user-action-token"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/keys/{}/signatures", TEST_KEY_ID)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "sig-456",
            "status": "Signed",
            "signature": {
                "r": r_hex,
                "s": s_hex
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_transaction(&mut transaction).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_is_available_success() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(wallet_response_json()))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(signer.is_available().await);
}

#[tokio::test]
async fn test_is_available_archived_wallet() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    let mut body = wallet_response_json();
    body["status"] = serde_json::json!("Archived");

    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_is_available_wrong_scheme() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    let mut body = wallet_response_json();
    body["signingKey"]["scheme"] = serde_json::json!("ECDSA");

    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_is_available_wrong_curve() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    let mut body = wallet_response_json();
    body["signingKey"]["curve"] = serde_json::json!("secp256k1");

    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_is_available_api_error() {
    let mock_server = MockServer::start().await;
    let signer = create_test_signer(&mock_server.uri());

    Mock::given(method("GET"))
        .and(path("/wallets/test-wallet-id"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(!signer.is_available().await);
}
