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

fn create_test_api_keys() -> (String, String) {
    let signing_key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let private_key_hex = hex::encode(signing_key.to_bytes());
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.to_encoded_point(false).as_bytes());
    (public_key_hex, private_key_hex)
}

#[tokio::test]
async fn test_turnkey_new() {
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    let signer = TurnkeySigner::new(
        api_public_key.clone(),
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    );

    assert!(signer.is_ok());
    let signer = signer.unwrap();
    assert_eq!(signer.organization_id, "test-org-id");
    assert_eq!(signer.private_key_id, "test-key-id");
    assert_eq!(signer.public_key, keypair.pubkey());
}

#[tokio::test]
async fn test_turnkey_new_invalid_pubkey() {
    let (api_public_key, api_private_key) = create_test_api_keys();

    let result = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        "not-a-valid-pubkey".to_string(),
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPublicKey(_)
    ));
}

#[tokio::test]
async fn test_turnkey_pubkey() {
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    let signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();

    assert_eq!(signer.pubkey(), keypair.pubkey());
}

#[tokio::test]
async fn test_turnkey_sign_message() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    let message = b"test message";
    let signature = keypair.sign_message(message);
    let sig_bytes = signature.as_ref();

    let r_hex = hex::encode(&sig_bytes[0..32]);
    let s_hex = hex::encode(&sig_bytes[32..64]);

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {
                "status": "ACTIVITY_STATUS_COMPLETED",
                "result": {
                    "signRawPayloadResult": {
                        "r": r_hex,
                        "s": s_hex
                    }
                }
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.sign_message(message).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), signature);
}

#[tokio::test]
async fn test_turnkey_sign_message_signature_verification_failure() {
    let mock_server = MockServer::start().await;
    let signing_keypair = create_test_keypair();
    let different_keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();
    let message = b"test message";
    let signature = signing_keypair.sign_message(message);
    let sig_bytes = signature.as_ref();

    let r_hex = hex::encode(&sig_bytes[0..32]);
    let s_hex = hex::encode(&sig_bytes[32..64]);

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {
                "status": "ACTIVITY_STATUS_COMPLETED",
                "result": {
                    "signRawPayloadResult": {
                        "r": r_hex,
                        "s": s_hex
                    }
                }
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        different_keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.sign_message(message).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_turnkey_sign_transaction() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    let mut tx = create_test_transaction(&keypair_pubkey(&keypair));

    let signature = keypair.sign_message(&tx.message.serialize());
    let mut signed_tx = tx.clone();
    signed_tx.signatures = vec![signature];
    let signed_hex = hex::encode(bincode::serialize(&signed_tx).unwrap());

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_transaction"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {
                "status": "ACTIVITY_STATUS_COMPLETED",
                "result": {
                    "signTransactionResult": {
                        "signedTransaction": signed_hex
                    }
                }
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.sign_transaction(&mut tx).await;
    assert!(result.is_ok());
    let (serialized_tx, returned_sig) = result.unwrap().into_signed_transaction();

    assert_eq!(returned_sig, signature);
    assert!(!serialized_tx.is_empty());
    assert_eq!(tx.signatures, vec![signature]);
}

#[tokio::test]
async fn test_turnkey_sign_transaction_rejects_signature_over_different_bytes() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    let mut tx = create_test_transaction(&keypair_pubkey(&keypair));
    let mut other_tx = create_test_transaction(&keypair_pubkey(&keypair));
    other_tx.signatures = vec![keypair.sign_message(&other_tx.message.serialize())];
    let signed_hex = hex::encode(bincode::serialize(&other_tx).unwrap());

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_transaction"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {
                "status": "ACTIVITY_STATUS_COMPLETED",
                "result": {
                    "signTransactionResult": {
                        "signedTransaction": signed_hex
                    }
                }
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

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
async fn test_turnkey_sign_transaction_rejects_non_completed_activity() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    let mut tx = create_test_transaction(&keypair_pubkey(&keypair));

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_transaction"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": { "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED" }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.sign_transaction(&mut tx).await;
    match result.unwrap_err() {
        SignerError::SigningFailed(message) => {
            assert!(message.contains("ACTIVITY_STATUS_CONSENSUS_NEEDED"));
        }
        other => panic!("Expected SigningFailed, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_turnkey_sign_unauthorized() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "message": "Unauthorized"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
}

#[tokio::test]
async fn test_turnkey_sign_invalid_response() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": { "status": "ACTIVITY_STATUS_COMPLETED" }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_turnkey_sign_rejects_non_completed_activity() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": { "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED" }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.sign_message(b"test").await;
    match result.unwrap_err() {
        SignerError::SigningFailed(message) => {
            assert!(
                message.contains("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
                "error must name the received status, got: {message}"
            );
        }
        other => panic!("Expected SigningFailed, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_turnkey_sign_rejects_missing_activity_status() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {}
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.sign_message(b"test").await;
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
async fn test_turnkey_sign_invalid_hex() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {
                "status": "ACTIVITY_STATUS_COMPLETED",
                "result": {
                    "signRawPayloadResult": {
                        "r": "not-valid-hex!!!",
                        "s": "also-not-valid-hex!!!"
                    }
                }
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::SerializationError(_)
    ));
}

#[tokio::test]
async fn test_turnkey_is_available() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    Mock::given(method("POST"))
        .and(path("/public/v1/query/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "organizationId": "test-org-id",
            "organizationName": "Test Org",
            "userId": "test-user-id",
            "username": "test@example.com"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    assert!(signer.is_available().await);
}

#[tokio::test]
async fn test_turnkey_is_not_available() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    Mock::given(method("POST"))
        .and(path("/public/v1/query/whoami"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    assert!(!signer.is_available().await);
}

#[tokio::test]
async fn test_turnkey_create_stamp() {
    let (api_public_key, api_private_key) = create_test_api_keys();
    let keypair = create_test_keypair();

    let signer = TurnkeySigner::new(
        api_public_key.clone(),
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();

    let message = "test message";
    let stamp = signer.create_stamp(message);

    assert!(stamp.is_ok());
    let stamp_str = stamp.unwrap();

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&stamp_str);
    assert!(decoded.is_ok());

    let json: serde_json::Value = serde_json::from_slice(&decoded.unwrap()).unwrap();
    assert!(json.get("public_key").is_some());
    assert!(json.get("signature").is_some());
    assert_eq!(json.get("scheme").unwrap(), "SIGNATURE_SCHEME_TK_API_P256");
}

#[tokio::test]
async fn test_turnkey_sign_oversized_component() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();
    let (api_public_key, api_private_key) = create_test_api_keys();

    let r_hex = hex::encode(vec![0xFF; 33]);
    let s_hex = hex::encode(vec![0x01; 32]);

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {
                "status": "ACTIVITY_STATUS_COMPLETED",
                "result": {
                    "signRawPayloadResult": {
                        "r": r_hex,
                        "s": s_hex
                    }
                }
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut signer = TurnkeySigner::new(
        api_public_key,
        api_private_key,
        "test-org-id".to_string(),
        "test-key-id".to_string(),
        keypair.pubkey().to_string(),
    )
    .unwrap();
    signer.client = reqwest::Client::new();
    signer.api_base_url = mock_server.uri();

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}
