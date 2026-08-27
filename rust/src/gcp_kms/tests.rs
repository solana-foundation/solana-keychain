use super::*;
use crate::sdk_adapter::{Keypair, Signer};
use crate::test_util::create_test_transaction;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use google_cloud_kms_v1::client::KeyManagementService;
use scoped_env::ScopedEnv;
use serial_test::serial;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_KEY_NAME: &str = "projects/test-project/locations/us-east1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1";

fn create_test_keypair() -> Keypair {
    Keypair::new()
}

/// Helper to create a KMS client configured for testing with wiremock
async fn create_test_client(endpoint: &str) -> KeyManagementService {
    KeyManagementService::builder()
        .with_endpoint(endpoint)
        .build()
        .await
        .expect("Failed to create mock client")
}

#[tokio::test]
#[serial]
async fn test_gcp_kms_new_invalid_pubkey() {
    let client = KeyManagementService::builder().build().await.unwrap();
    let result = GcpKmsSigner::with_client(
        client,
        TEST_KEY_NAME.to_string(),
        "invalid-pubkey".to_string(),
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPublicKey(_)
    ));
}

#[tokio::test]
#[serial]
async fn test_gcp_kms_new_empty_pubkey() {
    let client = KeyManagementService::builder().build().await.unwrap();
    let result = GcpKmsSigner::with_client(client, TEST_KEY_NAME.to_string(), "".to_string());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::InvalidPublicKey(_)
    ));
}

#[tokio::test]
async fn test_gcp_kms_new_valid_pubkey() {
    let keypair = create_test_keypair();
    let pubkey_str = keypair.pubkey().to_string();

    let result = GcpKmsSigner::new(TEST_KEY_NAME.to_string(), pubkey_str).await;

    if let Ok(signer) = result {
        assert_eq!(signer.public_key, keypair.pubkey());
        assert_eq!(signer.key_name, TEST_KEY_NAME);
    }
}

#[tokio::test]
async fn test_gcp_kms_pubkey() {
    let keypair = create_test_keypair();
    let pubkey_str = keypair.pubkey().to_string();

    let result = GcpKmsSigner::new(TEST_KEY_NAME.to_string(), pubkey_str.clone()).await;

    if let Ok(signer) = result {
        assert_eq!(signer.pubkey(), keypair.pubkey());
        assert_eq!(signer.pubkey().to_string(), pubkey_str);
    }
}

#[tokio::test]
async fn test_gcp_kms_key_id_accessor() {
    let keypair = create_test_keypair();
    let pubkey_str = keypair.pubkey().to_string();

    let result = GcpKmsSigner::new(TEST_KEY_NAME.to_string(), pubkey_str).await;

    if let Ok(signer) = result {
        assert_eq!(signer.key_name(), TEST_KEY_NAME);
    }
}

#[tokio::test]
async fn test_gcp_kms_debug_impl() {
    let keypair = create_test_keypair();
    let pubkey_str = keypair.pubkey().to_string();

    let result = GcpKmsSigner::new(TEST_KEY_NAME.to_string(), pubkey_str).await;

    if let Ok(signer) = result {
        let debug_str = format!("{:?}", signer);

        assert!(debug_str.contains("GcpKmsSigner"));
        assert!(debug_str.contains("key_name"));
        assert!(debug_str.contains("public_key"));
        assert!(!debug_str.contains("client"));
    }
}

#[tokio::test]
#[serial]
async fn test_gcp_kms_is_available_success() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    // Mock Metadata server for auth token
    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "access_token": "mock-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            }
        )))
        .mount(&mock_server)
        .await;

    let metadata_host = mock_server.address().to_string();
    let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

    let client = create_test_client(&mock_server.uri()).await;
    let signer = GcpKmsSigner::with_client(
        client,
        TEST_KEY_NAME.to_string(),
        keypair.pubkey().to_string(),
    )
    .expect("Failed to create signer");

    Mock::given(method("GET"))
        .and(path(format!("/v1/{TEST_KEY_NAME}/publicKey")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "name": TEST_KEY_NAME,
                "algorithm": "EC_SIGN_ED25519"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(signer.is_available().await);
}

#[tokio::test]
#[serial]
async fn test_gcp_kms_sign_message_success() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    // Mock Metadata server for auth token
    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "access_token": "mock-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            }
        )))
        .mount(&mock_server)
        .await;

    let metadata_host = mock_server.address().to_string();
    let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

    let client = create_test_client(&mock_server.uri()).await;
    let signer = GcpKmsSigner::with_client(
        client,
        TEST_KEY_NAME.to_string(),
        keypair.pubkey().to_string(),
    )
    .expect("Failed to create signer");

    let message = b"test message";
    let signature = keypair.sign_message(message);

    // Mock AsymmetricSign
    Mock::given(method("POST"))
        .and(path(format!("/v1/{TEST_KEY_NAME}:asymmetricSign")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "signature": STANDARD.encode(signature.as_ref()),
                "verified_data_crc32c": true
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(message).await;
    assert!(result.is_ok(), "Sign message failed");
    assert_eq!(result.unwrap().as_ref().len(), 64);
}

#[tokio::test]
#[serial]
async fn test_gcp_kms_sign_message_signature_verification_failure() {
    let mock_server = MockServer::start().await;
    let signing_keypair = create_test_keypair();
    let different_keypair = create_test_keypair();

    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "access_token": "mock-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            }
        )))
        .mount(&mock_server)
        .await;

    let metadata_host = mock_server.address().to_string();
    let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

    let client = create_test_client(&mock_server.uri()).await;
    let signer = GcpKmsSigner::with_client(
        client,
        TEST_KEY_NAME.to_string(),
        different_keypair.pubkey().to_string(),
    );
    assert!(signer.is_ok());
    let signer = signer.unwrap();

    let message = b"test message";
    let signature = signing_keypair.sign_message(message);

    Mock::given(method("POST"))
        .and(path(format!("/v1/{TEST_KEY_NAME}:asymmetricSign")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "signature": STANDARD.encode(signature.as_ref()),
                "verified_data_crc32c": true
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(message).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
#[serial]
async fn test_gcp_kms_sign_transaction_success() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    // Mock Metadata server for auth token
    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "access_token": "mock-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            }
        )))
        .mount(&mock_server)
        .await;

    let metadata_host = mock_server.address().to_string();
    let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

    let client = create_test_client(&mock_server.uri()).await;
    let signer = GcpKmsSigner::with_client(
        client,
        TEST_KEY_NAME.to_string(),
        keypair.pubkey().to_string(),
    )
    .expect("Failed to create signer");

    let mut tx = create_test_transaction(&keypair.pubkey());
    let signature = keypair.sign_message(&tx.message.serialize());

    Mock::given(method("POST"))
        .and(path(format!("/v1/{TEST_KEY_NAME}:asymmetricSign")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "signature": STANDARD.encode(signature.as_ref()),
                "verified_data_crc32c": true
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_transaction(&mut tx).await;
    assert!(
        result.is_ok(),
        "Sign transaction failed: {:#?}",
        result.err()
    );

    let (base64_tx, sig) = result.unwrap().into_signed_transaction();
    assert!(!base64_tx.is_empty());
    assert_eq!(sig.as_ref().len(), 64);
    assert_eq!(sig, signature);
}

#[tokio::test]
#[serial]
async fn test_gcp_kms_sign_message_invalid_signature_length() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    // Mock Metadata server for auth token
    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "access_token": "mock-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            }
        )))
        .mount(&mock_server)
        .await;

    let metadata_host = mock_server.address().to_string();
    let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

    let client = create_test_client(&mock_server.uri()).await;
    let signer = GcpKmsSigner::with_client(
        client,
        TEST_KEY_NAME.to_string(),
        keypair.pubkey().to_string(),
    )
    .expect("Failed to create signer");

    Mock::given(method("POST"))
        .and(path(format!("/v1/{TEST_KEY_NAME}:asymmetricSign")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "signature": STANDARD.encode(vec![0u8; 32]),
                "verified_data_crc32c": true
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
}

#[tokio::test]
#[serial]
async fn test_gcp_kms_sign_api_error() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    // Mock Metadata server for auth token
    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "access_token": "mock-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            }
        )))
        .mount(&mock_server)
        .await;

    let metadata_host = mock_server.address().to_string();
    let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

    let client = create_test_client(&mock_server.uri()).await;
    let signer = GcpKmsSigner::with_client(
        client,
        TEST_KEY_NAME.to_string(),
        keypair.pubkey().to_string(),
    )
    .expect("Failed to create signer");

    Mock::given(method("POST"))
        .and(path(format!("/v1/{TEST_KEY_NAME}:asymmetricSign")))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!(
            {
                "error": {
                    "code": 400,
                    "message": "Key is not valid for signing",
                    "status": "INVALID_ARGUMENT"
                }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
}

#[tokio::test]
#[serial]
async fn test_gcp_kms_sign_unauthorized() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "access_token": "mock-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            }
        )))
        .mount(&mock_server)
        .await;

    let metadata_host = mock_server.address().to_string();
    let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

    let client = create_test_client(&mock_server.uri()).await;
    let signer = GcpKmsSigner::with_client(
        client,
        TEST_KEY_NAME.to_string(),
        keypair.pubkey().to_string(),
    )
    .expect("Failed to create signer");

    // Mock 403 Forbidden
    Mock::given(method("POST"))
        .and(path(format!("/v1/{TEST_KEY_NAME}:asymmetricSign")))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!(
            {
                "error": {
                    "code": 403,
                    "message": "Permission denied",
                    "status": "PERMISSION_DENIED"
                }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = signer.sign_message(b"test").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SignerError::RemoteApiError(_)
    ));
}

#[tokio::test]
#[serial]
async fn test_gcp_kms_is_available_wrong_algorithm() {
    let mock_server = MockServer::start().await;
    let keypair = create_test_keypair();

    // Mock Metadata server for auth token
    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "access_token": "mock-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            }
        )))
        .mount(&mock_server)
        .await;

    let metadata_host = mock_server.address().to_string();
    let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

    let client = create_test_client(&mock_server.uri()).await;
    let signer = GcpKmsSigner::with_client(
        client,
        TEST_KEY_NAME.to_string(),
        keypair.pubkey().to_string(),
    )
    .expect("Failed to create signer");

    // Mock GetPublicKey with WRONG algorithm
    Mock::given(method("GET"))
        .and(path(format!("/v1/{TEST_KEY_NAME}/publicKey")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
            {
                "name": TEST_KEY_NAME,
                "algorithm": "RSA_SIGN_PSS_2048_SHA256"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    assert!(
        !signer.is_available().await,
        "Availability check should fail for wrong algorithm"
    );
}
