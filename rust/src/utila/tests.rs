use super::*;
use crate::sdk_adapter::{keypair_pubkey, keypair_sign_message, Keypair};
use crate::test_util::create_test_transaction;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use wiremock::{
    matchers::{body_json, method, path},
    Mock, MockServer, ResponseTemplate,
};

const TEST_EMAIL: &str = "service-account@vault.utilaserviceaccount.io";
const TEST_VAULT_ID: &str = "vault-test";
const TEST_WALLET_ID: &str = "wallet-test";
const TEST_NETWORK: &str = "networks/solana-devnet";
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

fn config() -> UtilaSignerConfig {
    UtilaSignerConfig {
        service_account_email: TEST_EMAIL.to_string(),
        service_account_private_key_pem: TEST_RSA_KEY.to_string(),
        vault_id: TEST_VAULT_ID.to_string(),
        wallet_id: TEST_WALLET_ID.to_string(),
        network: TEST_NETWORK.to_string(),
        api_base_url: None,
        poll_interval_ms: Some(1),
        max_poll_attempts: Some(2),
        designated_signers: None,
        http_client_config: None,
    }
}

fn create_test_signer(base_url: &str, public_key: Option<Pubkey>) -> UtilaSigner {
    UtilaSigner {
        service_account_email: TEST_EMAIL.to_string(),
        signing_key: Arc::new(EncodingKey::from_rsa_pem(TEST_RSA_KEY.as_bytes()).unwrap()),
        vault_id: TEST_VAULT_ID.to_string(),
        wallet_id: TEST_WALLET_ID.to_string(),
        network: TEST_NETWORK.to_string(),
        api_base_url: base_url.trim_end_matches('/').to_string(),
        client: reqwest::Client::builder().build().unwrap(),
        public_key,
        poll_interval_ms: 1,
        max_poll_attempts: 2,
        designated_signers: vec![format!("users/{TEST_EMAIL}")],
    }
}

fn wallet_response(address: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "wallet": {
            "solanaDetails": {
                "address": address
            }
        }
    }))
}

fn signed_transaction_payload() -> (Keypair, VersionedTransaction, String, String, Signature) {
    let keypair = Keypair::new();
    let public_key = keypair_pubkey(&keypair);
    let unsigned = create_test_transaction(&public_key);
    let unsigned_raw = STANDARD.encode(bincode::serialize(&unsigned).unwrap());

    let mut signed = unsigned.clone();
    let signature = keypair_sign_message(&keypair, &signed.message.serialize());
    TransactionUtil::add_signature_to_transaction(&mut signed, &public_key, signature).unwrap();
    let signed_raw = STANDARD.encode(bincode::serialize(&signed).unwrap());

    (keypair, unsigned, unsigned_raw, signed_raw, signature)
}

fn decode_jwt_payload(jwt: &str) -> Value {
    let parts: Vec<&str> = jwt.split('.').collect();
    let payload_b64 = parts.get(1).expect("jwt payload should exist");
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("payload should be base64url");
    serde_json::from_slice::<Value>(&payload_bytes).expect("payload should be valid json")
}

#[test]
fn test_new_rejects_missing_config() {
    let mut config = config();
    config.service_account_email = String::new();
    assert!(matches!(
        UtilaSigner::new(config),
        Err(SignerError::ConfigError(_))
    ));
}

#[test]
fn test_new_rejects_insecure_api_base_url() {
    let mut config = config();
    config.api_base_url = Some("http://api.utila.test".to_string());
    assert!(matches!(
        UtilaSigner::new(config),
        Err(SignerError::ConfigError(_))
    ));
}

#[test]
fn test_create_access_token_claims() {
    let signer = UtilaSigner::new(config()).expect("signer should be created");
    let token = signer
        .create_access_token()
        .expect("access token should be created");
    let payload = decode_jwt_payload(&token);

    assert_eq!(payload["sub"], TEST_EMAIL);
    assert_eq!(payload["aud"], UTILA_API_AUDIENCE);
    assert!(payload["exp"].as_i64().is_some());
}

#[test]
fn test_new_accepts_escaped_newline_pem() {
    let mut config = config();
    config.service_account_private_key_pem = TEST_RSA_KEY.replace('\n', "\\n");
    assert!(UtilaSigner::new(config).is_ok());
}

#[tokio::test]
async fn test_init_fetches_solana_address() {
    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let public_key = keypair_pubkey(&keypair);

    Mock::given(method("GET"))
        .and(path("/v2/vaults/vault-test/wallets/wallet-test"))
        .respond_with(wallet_response(&public_key.to_string()))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), None);
    signer.init().await.expect("init should fetch address");
    assert_eq!(signer.pubkey(), public_key);
}

#[tokio::test]
async fn test_fetch_wallet_encodes_resource_ids() {
    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let public_key = keypair_pubkey(&keypair);

    Mock::given(method("GET"))
        .and(path(
            "/v2/vaults/vault%2Fwith%20space/wallets/wallet%2Fwith%20space",
        ))
        .respond_with(wallet_response(&public_key.to_string()))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), None);
    signer.vault_id = "vault/with space".to_string();
    signer.wallet_id = "wallet/with space".to_string();

    signer.init().await.expect("init should fetch address");
    assert_eq!(signer.pubkey(), public_key);
}

#[tokio::test]
async fn test_initiate_transaction_encodes_vault_id() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/v2/vaults/vault%2Fwith%20space/transactions:initiate",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transaction": {
                "name": "vaults/vault/with space/transactions/tx-1",
                "state": "AWAITING_SIGNATURE"
            }
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), None);
    signer.vault_id = "vault/with space".to_string();

    let transaction = signer
        .initiate_transaction("raw-transaction".to_string())
        .await
        .expect("transaction should be initiated");

    assert_eq!(
        transaction.name,
        "vaults/vault/with space/transactions/tx-1"
    );
}

#[tokio::test]
async fn test_sign_message_not_supported() {
    let keypair = Keypair::new();
    let signer = create_test_signer(&server_url(), Some(keypair_pubkey(&keypair)));
    let result = signer.sign_message(b"hello").await;
    assert!(matches!(result, Err(SignerError::SigningFailed(_))));
}

#[tokio::test]
async fn test_sign_transaction_posts_payload_and_polls_signed_response() {
    let server = MockServer::start().await;
    let (keypair, mut transaction, unsigned_raw, signed_raw, expected_signature) =
        signed_transaction_payload();
    let public_key = keypair_pubkey(&keypair);

    Mock::given(method("POST"))
        .and(path("/v2/vaults/vault-test/transactions:initiate"))
        .and(body_json(serde_json::json!({
            "details": {
                "solanaSerializedTransaction": {
                    "network": TEST_NETWORK,
                    "rawTransaction": unsigned_raw,
                    "publish": false,
                    "replaceBlockhash": false,
                    "tryReplaceBlockhash": false
                }
            },
            "designatedSigners": [format!("users/{TEST_EMAIL}")]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transaction": {
                "name": "vaults/vault-test/transactions/tx-1",
                "state": "AWAITING_SIGNATURE"
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/vaults/vault-test/transactions/tx-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transaction": {
                "name": "vaults/vault-test/transactions/tx-1",
                "state": "SIGNED",
                "solanaTransaction": {
                    "rawTransaction": signed_raw
                }
            }
        })))
        .mount(&server)
        .await;

    let signer = create_test_signer(&server.uri(), Some(public_key));
    let result = signer
        .sign_transaction(&mut transaction)
        .await
        .expect("transaction should sign");
    let (_, signature) = result.into_signed_transaction();

    assert_eq!(signature, expected_signature);
    assert_eq!(transaction.signatures[0], expected_signature);
}

#[tokio::test]
async fn test_sign_transaction_terminal_failure() {
    let server = MockServer::start().await;
    let (keypair, mut transaction, unsigned_raw, _, _) = signed_transaction_payload();

    Mock::given(method("POST"))
        .and(path("/v2/vaults/vault-test/transactions:initiate"))
        .and(body_json(serde_json::json!({
            "details": {
                "solanaSerializedTransaction": {
                    "network": TEST_NETWORK,
                    "rawTransaction": unsigned_raw,
                    "publish": false,
                    "replaceBlockhash": false,
                    "tryReplaceBlockhash": false
                }
            },
            "designatedSigners": [format!("users/{TEST_EMAIL}")]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transaction": {
                "name": "vaults/vault-test/transactions/tx-1",
                "state": "FAILED"
            }
        })))
        .mount(&server)
        .await;

    let signer = create_test_signer(&server.uri(), Some(keypair_pubkey(&keypair)));
    let result = signer.sign_transaction(&mut transaction).await;
    assert!(matches!(result, Err(SignerError::SigningFailed(_))));
}

#[tokio::test]
async fn test_sign_transaction_timeout() {
    let server = MockServer::start().await;
    let (keypair, mut transaction, unsigned_raw, _, _) = signed_transaction_payload();

    Mock::given(method("POST"))
        .and(path("/v2/vaults/vault-test/transactions:initiate"))
        .and(body_json(serde_json::json!({
            "details": {
                "solanaSerializedTransaction": {
                    "network": TEST_NETWORK,
                    "rawTransaction": unsigned_raw,
                    "publish": false,
                    "replaceBlockhash": false,
                    "tryReplaceBlockhash": false
                }
            },
            "designatedSigners": [format!("users/{TEST_EMAIL}")]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transaction": {
                "name": "vaults/vault-test/transactions/tx-1",
                "state": "AWAITING_SIGNATURE"
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/vaults/vault-test/transactions/tx-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transaction": {
                "name": "vaults/vault-test/transactions/tx-1",
                "state": "AWAITING_SIGNATURE"
            }
        })))
        .mount(&server)
        .await;

    let signer = create_test_signer(&server.uri(), Some(keypair_pubkey(&keypair)));
    let result = signer.sign_transaction(&mut transaction).await;
    assert!(matches!(result, Err(SignerError::RemoteApiError(_))));
}

#[tokio::test]
async fn test_sign_transaction_rejects_mismatched_returned_transaction() {
    let server = MockServer::start().await;
    let (keypair, mut transaction, unsigned_raw, _, _) = signed_transaction_payload();
    let other_keypair = Keypair::new();
    let (_, _, _, mismatched_raw, _) = signed_transaction_payload_for_keypair(&other_keypair);

    Mock::given(method("POST"))
        .and(path("/v2/vaults/vault-test/transactions:initiate"))
        .and(body_json(serde_json::json!({
            "details": {
                "solanaSerializedTransaction": {
                    "network": TEST_NETWORK,
                    "rawTransaction": unsigned_raw,
                    "publish": false,
                    "replaceBlockhash": false,
                    "tryReplaceBlockhash": false
                }
            },
            "designatedSigners": [format!("users/{TEST_EMAIL}")]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transaction": {
                "name": "vaults/vault-test/transactions/tx-1",
                "state": "SIGNED",
                "solanaTransaction": {
                    "rawTransaction": mismatched_raw
                }
            }
        })))
        .mount(&server)
        .await;

    let signer = create_test_signer(&server.uri(), Some(keypair_pubkey(&keypair)));
    let result = signer.sign_transaction(&mut transaction).await;
    assert!(matches!(result, Err(SignerError::SigningFailed(_))));
}

#[tokio::test]
async fn test_is_available() {
    let server = MockServer::start().await;
    let keypair = Keypair::new();

    Mock::given(method("GET"))
        .and(path("/v2/vaults/vault-test/wallets/wallet-test"))
        .respond_with(wallet_response(&keypair_pubkey(&keypair).to_string()))
        .mount(&server)
        .await;

    let signer = create_test_signer(&server.uri(), None);
    assert!(signer.is_available().await);

    let unavailable = create_test_signer("http://127.0.0.1:1", None);
    assert!(!unavailable.is_available().await);
}

fn signed_transaction_payload_for_keypair(
    keypair: &Keypair,
) -> (
    VersionedTransaction,
    VersionedTransaction,
    String,
    String,
    Signature,
) {
    let public_key = keypair_pubkey(keypair);
    let unsigned = create_test_transaction(&public_key);
    let unsigned_raw = STANDARD.encode(bincode::serialize(&unsigned).unwrap());

    let mut signed = unsigned.clone();
    let signature = keypair_sign_message(keypair, &signed.message.serialize());
    TransactionUtil::add_signature_to_transaction(&mut signed, &public_key, signature).unwrap();
    let signed_raw = STANDARD.encode(bincode::serialize(&signed).unwrap());

    (
        unsigned.clone(),
        signed,
        unsigned_raw,
        signed_raw,
        signature,
    )
}

fn server_url() -> String {
    "http://127.0.0.1:1".to_string()
}
