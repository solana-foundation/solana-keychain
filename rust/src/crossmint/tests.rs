use super::*;
use crate::sdk_adapter::{keypair_pubkey, keypair_sign_message, Keypair};
use crate::test_util::{create_test_transaction, create_test_transaction_with_recipient};
use crate::transaction_util::TransactionUtil;
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

fn assert_caller_transaction_untouched(tx: &VersionedTransaction) {
    assert!(
        tx.signatures.iter().all(|s| *s == Signature::default()),
        "Crossmint broadcasts server-side, so the caller's transaction must stay unsigned"
    );
}

/// The key the signer must derive: the message namespaced by the signer locator,
/// so two signers on one wallet cannot deduplicate onto each other.
fn expected_idempotency_key(locator: &str, message_bytes: &[u8]) -> String {
    let mut input = format!("crossmint:solana:{}:{}:", locator.len(), locator).into_bytes();
    input.extend_from_slice(message_bytes);
    idempotency_key_from_message(&input)
}

fn wallet_response(address: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "chainType": "solana",
        "type": "smart",
        "address": address
    }))
}

/// Helper to create a signer for tests that point to local wiremock HTTP URLs.
/// Production URL validation stays enforced in `CrossmintSigner::new`.
fn create_test_signer(
    base_url: &str,
    poll_interval_ms: u64,
    max_poll_attempts: u32,
) -> CrossmintSigner {
    CrossmintSigner {
        api_key: "test-api-key".to_string(),
        wallet_locator: "test-wallet".to_string(),
        signer: None,
        api_base_url: base_url.trim_end_matches('/').to_string(),
        client: reqwest::Client::builder()
            .timeout(CLIENT_TIMEOUT)
            .build()
            .unwrap(),
        public_key: None,
        poll_interval_ms,
        max_poll_attempts,
        signing_key: None,
        pending_transaction_id: None,
    }
}

fn create_url_builder_test_signer(wallet_locator: &str) -> CrossmintSigner {
    let mut signer = create_test_signer(
        "https://example.com/api",
        DEFAULT_POLL_INTERVAL_MS,
        DEFAULT_MAX_POLL_ATTEMPTS,
    );
    signer.wallet_locator = wallet_locator.to_string();
    signer
}

fn build_url_and_path(wallet_locator: &str, segments: &[&str]) -> (String, String) {
    let signer = create_url_builder_test_signer(wallet_locator);
    let built_url = signer.build_wallets_api_url(segments).unwrap();
    let path = reqwest::Url::parse(&built_url).unwrap().path().to_string();
    (built_url, path)
}

#[test]
fn test_build_wallets_api_url_encodes_raw_slashes_in_wallet_locator() {
    let (built_url, path) = build_url_and_path("userId:test-user/child:solana:smart", &[]);

    assert_eq!(
        built_url,
        "https://example.com/api/2025-06-09/wallets/userId%3Atest-user%2Fchild%3Asolana%3Asmart"
    );
    assert_eq!(
        path,
        "/api/2025-06-09/wallets/userId%3Atest-user%2Fchild%3Asolana%3Asmart"
    );
    assert!(
        !path.contains("/child"),
        "wallet locator slash must stay inside a single encoded path segment: {path}"
    );
}

#[test]
fn test_build_wallets_api_url_prevents_dot_segment_retargeting() {
    let (built_url, path) =
        build_url_and_path("userId:attacker/../victim:solana:smart", &["transactions"]);

    assert_eq!(
            built_url,
            "https://example.com/api/2025-06-09/wallets/userId%3Aattacker%2F..%2Fvictim%3Asolana%3Asmart/transactions"
        );
    assert_eq!(
        path,
        "/api/2025-06-09/wallets/userId%3Aattacker%2F..%2Fvictim%3Asolana%3Asmart/transactions"
    );
    assert_ne!(
        path, "/api/2025-06-09/wallets/victim%3Asolana%3Asmart/transactions",
        "wallet locator must not normalize into a different wallet path"
    );
}

#[test]
fn test_build_wallets_api_url_double_encodes_encoded_traversal_sequences() {
    for (wallet_locator, expected_fragment) in [
        (
            "userId:attacker%2Fvictim:solana:smart",
            "userId%3Aattacker%252Fvictim%3Asolana%3Asmart",
        ),
        (
            "userId:attacker%2e%2e%2Fvictim:solana:smart",
            "userId%3Aattacker%252e%252e%252Fvictim%3Asolana%3Asmart",
        ),
    ] {
        let (built_url, path) = build_url_and_path(wallet_locator, &[]);

        assert!(
            built_url.contains(expected_fragment),
            "expected encoded traversal fragment {expected_fragment} in URL {built_url}"
        );
        assert!(
            path.contains(expected_fragment),
            "expected encoded traversal fragment {expected_fragment} in path {path}"
        );
    }
}

#[test]
fn test_build_wallets_api_url_encodes_query_and_fragment_metacharacters() {
    let (built_url, path) = build_url_and_path("userId:test?wallet#fragment:solana:smart", &[]);

    assert_eq!(
            built_url,
            "https://example.com/api/2025-06-09/wallets/userId%3Atest%3Fwallet%23fragment%3Asolana%3Asmart"
        );
    assert_eq!(
        path,
        "/api/2025-06-09/wallets/userId%3Atest%3Fwallet%23fragment%3Asolana%3Asmart"
    );
}

#[test]
fn test_build_wallets_api_url_matches_typescript_encodeuricomponent_behavior() {
    let (built_url, path) = build_url_and_path(
        "userId:alice/../wallet?draft#frag:solana:smart",
        &["transactions", "tx-123", "approvals"],
    );

    assert_eq!(
            built_url,
            "https://example.com/api/2025-06-09/wallets/userId%3Aalice%2F..%2Fwallet%3Fdraft%23frag%3Asolana%3Asmart/transactions/tx-123/approvals"
        );
    assert_eq!(
            path,
            "/api/2025-06-09/wallets/userId%3Aalice%2F..%2Fwallet%3Fdraft%23frag%3Asolana%3Asmart/transactions/tx-123/approvals"
        );
}

#[test]
fn test_new_rejects_insecure_api_base_url() {
    let result = CrossmintSigner::new(CrossmintSignerConfig {
        api_key: "test-api-key".to_string(),
        wallet_locator: "test-wallet".to_string(),
        signer_secret: None,
        signer: None,
        api_base_url: Some("http://insecure.example.com".to_string()),
        poll_interval_ms: None,
        max_poll_attempts: None,
    });

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, SignerError::ConfigError(_)));
}

/// Pins the exact bytes hashed into the idempotency key. Every language must
/// derive the same key from the same locator and message.
#[test]
fn test_the_idempotency_key_input_is_namespaced_by_the_signer_locator() {
    let mut signer = create_test_signer("https://api.crossmint.com", 1, 1);

    assert_eq!(
        signer.namespaced_key_input(b"MSG"),
        b"crossmint:solana:0::MSG".to_vec()
    );

    signer.signer = Some("server:abc".to_string());
    assert_eq!(
        signer.namespaced_key_input(b"MSG"),
        b"crossmint:solana:10:server:abc:MSG".to_vec()
    );
}

#[tokio::test]
async fn test_init_success() {
    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let address = keypair_pubkey(&keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(wallet_response(&address))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(
        &server.uri(),
        DEFAULT_POLL_INTERVAL_MS,
        DEFAULT_MAX_POLL_ATTEMPTS,
    );

    signer.init().await.unwrap();
    assert_eq!(signer.pubkey(), keypair_pubkey(&keypair));
}

#[tokio::test]
async fn test_init_rejects_oversized_response_body() {
    let server = MockServer::start().await;

    let padding = "a".repeat(crate::remote_util::MAX_RESPONSE_BYTES);
    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chainType": "solana",
            "type": "smart",
            "address": "11111111111111111111111111111111",
            "padding": padding
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(
        &server.uri(),
        DEFAULT_POLL_INTERVAL_MS,
        DEFAULT_MAX_POLL_ATTEMPTS,
    );

    let error = signer.init().await.unwrap_err();
    assert!(matches!(error, SignerError::SerializationError(_)));
}

#[tokio::test]
async fn test_init_url_encodes_wallet_locator() {
    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let address = keypair_pubkey(&keypair).to_string();
    let locator = "userId:test-user:solana:smart";

    Mock::given(method("GET"))
        .and(path(
            "/2025-06-09/wallets/userId%3Atest-user%3Asolana%3Asmart",
        ))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(wallet_response(&address))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(
        &server.uri(),
        DEFAULT_POLL_INTERVAL_MS,
        DEFAULT_MAX_POLL_ATTEMPTS,
    );
    signer.wallet_locator = locator.to_string();

    signer.init().await.unwrap();
    assert_eq!(signer.pubkey(), keypair_pubkey(&keypair));
}

#[tokio::test]
async fn test_sign_message_not_supported() {
    let signer = CrossmintSigner::new(CrossmintSignerConfig {
        api_key: "test-api-key".to_string(),
        wallet_locator: "test-wallet".to_string(),
        signer_secret: None,
        signer: None,
        api_base_url: None,
        poll_interval_ms: None,
        max_poll_attempts: None,
    })
    .unwrap();

    let result = signer.sign_message(b"hello").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        SignerError::SigningFailed(msg) => {
            assert!(
                msg.contains("not supported"),
                "Unexpected error message: {msg}"
            );
        }
        other => panic!("Expected SigningFailed error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_sign_and_send_transaction_success() {
    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let signer_pubkey = keypair_pubkey(&keypair);
    let signer_address = signer_pubkey.to_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(wallet_response(&signer_address))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 2);
    signer.init().await.unwrap();

    let local_tx = create_test_transaction(&signer_pubkey);
    let mut signed_remote_tx = local_tx.clone();
    let expected_signature = keypair_sign_message(&keypair, &signed_remote_tx.message.serialize());
    TransactionUtil::add_signature_to_transaction(
        &mut signed_remote_tx,
        &signer_pubkey,
        expected_signature,
    )
    .unwrap();

    let on_chain_transaction =
        bs58::encode(bincode::serialize(&signed_remote_tx).unwrap()).into_string();

    let expected_idempotency_key = expected_idempotency_key("", &local_tx.message.serialize());
    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .and(header("x-api-key", "test-api-key"))
        .and(header(
            "x-idempotency-key",
            expected_idempotency_key.as_str(),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "success",
            "chainType": "solana",
            "walletType": "smart",
            "onChain": {
                "transaction": on_chain_transaction
            }
        })))
        .mount(&server)
        .await;

    let signature = signer.sign_and_send_transaction(&local_tx).await.unwrap();

    assert_eq!(signature, expected_signature);
    assert_caller_transaction_untouched(&local_tx);
}

/// Dropping the signing future after the create was accepted runs no further
/// code, so the registered slot is the only carrier for the id the caller must
/// reconcile.
#[tokio::test]
async fn test_a_cancelled_send_leaves_the_transaction_id_in_the_pending_slot() {
    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let signer_pubkey = keypair_pubkey(&keypair);

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(wallet_response(&signer_pubkey.to_string()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-accepted",
            "status": "pending",
            "chainType": "solana",
            "walletType": "smart"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/2025-06-09/wallets/test-wallet/transactions/tx-accepted",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_secs(30))
                .set_body_json(serde_json::json!({ "id": "tx-accepted", "status": "pending" })),
        )
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 100);
    signer.init().await.unwrap();
    let pending = PendingTransactionId::new();
    let signer = signer.with_pending_transaction_id(pending.clone());

    let local_tx = create_test_transaction(&signer_pubkey);
    let cancelled = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        signer.sign_and_send_transaction(&local_tx),
    )
    .await;

    assert!(cancelled.is_err(), "the poll should still be in flight");
    assert_eq!(pending.get(), Some("tx-accepted".to_string()));
}

/// A call that returns normally clears the slot: its id is already in the
/// result or the error.
#[tokio::test]
async fn test_a_completed_send_clears_the_pending_slot() {
    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let signer_pubkey = keypair_pubkey(&keypair);

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(wallet_response(&signer_pubkey.to_string()))
        .mount(&server)
        .await;

    let local_tx = create_test_transaction(&signer_pubkey);
    let mut signed_remote_tx = local_tx.clone();
    let expected_signature = keypair_sign_message(&keypair, &signed_remote_tx.message.serialize());
    TransactionUtil::add_signature_to_transaction(
        &mut signed_remote_tx,
        &signer_pubkey,
        expected_signature,
    )
    .unwrap();
    let on_chain_transaction =
        bs58::encode(bincode::serialize(&signed_remote_tx).unwrap()).into_string();

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "success",
            "chainType": "solana",
            "walletType": "smart",
            "onChain": { "transaction": on_chain_transaction }
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 2);
    signer.init().await.unwrap();
    let pending = PendingTransactionId::new();
    let signer = signer.with_pending_transaction_id(pending.clone());

    signer.sign_and_send_transaction(&local_tx).await.unwrap();

    assert_eq!(pending.get(), None);
}

/// A smart wallet is signed by its delegated signer, not by the wallet address
/// the API reports, so the delegated key's returned signature is accepted.
#[tokio::test]
async fn test_sign_and_send_transaction_locates_delegated_signer_signature() {
    let server = MockServer::start().await;
    let wallet_keypair = Keypair::new();
    let wallet_pubkey = keypair_pubkey(&wallet_keypair);
    let delegated_keypair = Keypair::new();
    let delegated_pubkey = keypair_pubkey(&delegated_keypair);

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(wallet_response(&wallet_pubkey.to_string()))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 2);
    signer.init().await.unwrap();

    let local_tx = create_test_transaction(&wallet_pubkey);
    let mut rewritten_tx = create_test_transaction(&delegated_pubkey);
    let expected_signature =
        keypair_sign_message(&delegated_keypair, &rewritten_tx.message.serialize());
    TransactionUtil::add_signature_to_transaction(
        &mut rewritten_tx,
        &delegated_pubkey,
        expected_signature,
    )
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-delegated",
            "status": "success",
            "onChain": {
                "transaction": bs58::encode(bincode::serialize(&rewritten_tx).unwrap())
                    .into_string()
            }
        })))
        .mount(&server)
        .await;

    let signature = signer.sign_and_send_transaction(&local_tx).await.unwrap();

    assert_eq!(signature, expected_signature);
    assert_caller_transaction_untouched(&local_tx);
    // The wallet address remains the signer's public identity.
    assert_eq!(signer.pubkey(), wallet_pubkey);
}

/// Crossmint's returned transaction is trusted as the provider's broadcast result.
#[tokio::test]
async fn test_sign_and_send_transaction_accepts_unrelated_signer_key() {
    let server = MockServer::start().await;
    let wallet_keypair = Keypair::new();
    let wallet_pubkey = keypair_pubkey(&wallet_keypair);
    let stranger = Keypair::new();
    let stranger_pubkey = keypair_pubkey(&stranger);

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(wallet_response(&wallet_pubkey.to_string()))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 2);
    signer.init().await.unwrap();

    let local_tx = create_test_transaction(&wallet_pubkey);
    let mut rewritten_tx = create_test_transaction(&stranger_pubkey);
    let signature = keypair_sign_message(&stranger, &rewritten_tx.message.serialize());
    TransactionUtil::add_signature_to_transaction(&mut rewritten_tx, &stranger_pubkey, signature)
        .unwrap();

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-stranger",
            "status": "success",
            "onChain": {
                "transaction": bs58::encode(bincode::serialize(&rewritten_tx).unwrap())
                    .into_string()
            }
        })))
        .mount(&server)
        .await;

    let result = signer.sign_and_send_transaction(&local_tx).await.unwrap();
    assert_eq!(result, signature);
    assert_caller_transaction_untouched(&local_tx);
}

/// A signature that does not cover the envelope it arrived in identifies no
/// landed transaction, so returning it would send the caller to look up a
/// transaction that does not exist and conclude nothing landed.
#[tokio::test]
async fn test_sign_and_send_transaction_rejects_a_signature_not_covering_the_returned_message() {
    let server = MockServer::start().await;
    let wallet_keypair = Keypair::new();
    let wallet_pubkey = keypair_pubkey(&wallet_keypair);

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(wallet_response(&wallet_pubkey.to_string()))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 2);
    signer.init().await.unwrap();

    let local_tx = create_test_transaction(&wallet_pubkey);
    let mut returned_tx = create_test_transaction(&wallet_pubkey);
    let signature = keypair_sign_message(&wallet_keypair, b"unrelated bytes");
    returned_tx.signatures[0] = signature;

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-unverifiable",
            "status": "success",
            "onChain": {
                "transaction": bs58::encode(bincode::serialize(&returned_tx).unwrap())
                    .into_string()
            }
        })))
        .mount(&server)
        .await;

    match signer
        .sign_and_send_transaction(&local_tx)
        .await
        .unwrap_err()
    {
        SignerError::BroadcastUnconfirmed { provider_tx_id, .. } => {
            assert_eq!(provider_tx_id.as_deref(), Some("tx-unverifiable"));
        }
        other => panic!("Expected BroadcastUnconfirmed error, got: {:?}", other),
    }
}

/// Crossmint sponsors gas, so it is the fee payer and the message it signs
/// differs from the caller's. Its signature must never be placed in the
/// caller's transaction, which could not verify with it.
#[tokio::test]
async fn test_sign_and_send_transaction_rewritten_is_reported_as_a_broadcast_result() {
    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let signer_pubkey = keypair_pubkey(&keypair);

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(wallet_response(&signer_pubkey.to_string()))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 2);
    signer.init().await.unwrap();

    let local_tx = create_test_transaction(&signer_pubkey);
    let mut rewritten_tx = create_test_transaction(&signer_pubkey);
    assert_ne!(
        rewritten_tx.message.serialize(),
        local_tx.message.serialize()
    );
    let expected_signature = keypair_sign_message(&keypair, &rewritten_tx.message.serialize());
    TransactionUtil::add_signature_to_transaction(
        &mut rewritten_tx,
        &signer_pubkey,
        expected_signature,
    )
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "success",
            "chainType": "solana",
            "walletType": "smart",
            "onChain": {
                "transaction": bs58::encode(bincode::serialize(&rewritten_tx).unwrap())
                    .into_string()
            }
        })))
        .mount(&server)
        .await;

    let signature = signer.sign_and_send_transaction(&local_tx).await.unwrap();

    assert_eq!(signature, expected_signature);
    assert_caller_transaction_untouched(&local_tx);
}

/// Under sponsorship the returned signature must be the sponsor fee-payer's
/// slot-0 signature, not the wallet's approval, so RPC lookups resolve.
#[tokio::test]
async fn test_sign_and_send_transaction_sponsored_returns_fee_payer_transaction_id() {
    let server = MockServer::start().await;
    let wallet_keypair = Keypair::new();
    let wallet_pubkey = keypair_pubkey(&wallet_keypair);
    let sponsor_keypair = Keypair::new();
    let sponsor_pubkey = keypair_pubkey(&sponsor_keypair);

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(wallet_response(&wallet_pubkey.to_string()))
        .mount(&server)
        .await;

    let mut executed_tx = create_test_transaction(&sponsor_pubkey);
    let sponsor_signature =
        keypair_sign_message(&sponsor_keypair, &executed_tx.message.serialize());
    TransactionUtil::add_signature_to_transaction(
        &mut executed_tx,
        &sponsor_pubkey,
        sponsor_signature,
    )
    .unwrap();
    let approval_signature =
        keypair_sign_message(&wallet_keypair, &executed_tx.message.serialize());

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-sponsored",
            "status": "success",
            "approvals": {
                "submitted": [{
                    "signature": bs58::encode(approval_signature.as_ref()).into_string(),
                    "signer": { "address": wallet_pubkey.to_string() }
                }]
            },
            "onChain": {
                "transaction": bs58::encode(bincode::serialize(&executed_tx).unwrap())
                    .into_string()
            }
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 1);
    signer.init().await.unwrap();

    let local_tx = create_test_transaction(&wallet_pubkey);
    let signature = signer.sign_and_send_transaction(&local_tx).await.unwrap();

    assert_eq!(signature, sponsor_signature);
    assert_ne!(signature, approval_signature);
    assert_caller_transaction_untouched(&local_tx);
}

/// A quorum entry carrying neither a top-level address nor signature must not
/// end the scan: the wallet's approval can follow it.
#[tokio::test]
async fn test_sign_and_send_transaction_skips_submitted_approvals_without_an_address() {
    let server = MockServer::start().await;
    let wallet_keypair = Keypair::new();
    let wallet_pubkey = keypair_pubkey(&wallet_keypair);
    let sponsor_keypair = Keypair::new();
    let sponsor_pubkey = keypair_pubkey(&sponsor_keypair);

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(wallet_response(&wallet_pubkey.to_string()))
        .mount(&server)
        .await;

    let mut executed_tx = create_test_transaction(&sponsor_pubkey);
    let sponsor_signature =
        keypair_sign_message(&sponsor_keypair, &executed_tx.message.serialize());
    TransactionUtil::add_signature_to_transaction(
        &mut executed_tx,
        &sponsor_pubkey,
        sponsor_signature,
    )
    .unwrap();
    let approval_signature =
        keypair_sign_message(&wallet_keypair, &executed_tx.message.serialize());

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-quorum-first",
            "status": "success",
            "approvals": {
                "submitted": [
                    { "signer": { "locator": format!("server:{wallet_pubkey}") } },
                    {
                        "signature": bs58::encode(approval_signature.as_ref()).into_string(),
                        "signer": { "address": wallet_pubkey.to_string() }
                    }
                ]
            },
            "onChain": {
                "transaction": bs58::encode(bincode::serialize(&executed_tx).unwrap())
                    .into_string()
            }
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 1);
    signer.init().await.unwrap();

    let local_tx = create_test_transaction(&wallet_pubkey);
    let signature = signer.sign_and_send_transaction(&local_tx).await.unwrap();

    assert_eq!(signature, sponsor_signature);
    assert_caller_transaction_untouched(&local_tx);
}

#[tokio::test]
async fn test_sign_and_send_transaction_rejects_approval_signatures_for_local_transaction_bytes() {
    let server = MockServer::start().await;
    let wallet_keypair = Keypair::new();
    let signer_address = keypair_pubkey(&wallet_keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(wallet_response(&signer_address))
        .mount(&server)
        .await;

    let approval_signer = Keypair::new();
    let approval_signature = keypair_sign_message(&approval_signer, b"crossmint-approval-payload");
    let approval_signature_b58 = bs58::encode(approval_signature.as_ref()).into_string();

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-approval",
            "status": "success",
            "approvals": {
                "submitted": [
                    { "signature": approval_signature_b58 }
                ]
            }
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 1);
    signer.init().await.unwrap();

    let tx = create_test_transaction(&signer.pubkey());
    let result = signer.sign_and_send_transaction(&tx).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        SignerError::BroadcastUnconfirmed {
            provider_tx_id,
            detail,
            ..
        } => {
            assert_eq!(provider_tx_id.as_deref(), Some("tx-approval"));
            assert!(
                detail.contains("Unable to extract signature"),
                "Unexpected error detail: {detail}"
            );
        }
        other => panic!("Expected BroadcastUnconfirmed error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_create_server_error_is_unconfirmed_without_a_transaction_id() {
    let server = MockServer::start().await;
    let wallet_keypair = Keypair::new();
    let signer_address = keypair_pubkey(&wallet_keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(wallet_response(&signer_address))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
            "error": "service unavailable"
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 1);
    signer.init().await.unwrap();
    let tx = create_test_transaction(&signer.pubkey());

    match signer.sign_and_send_transaction(&tx).await.unwrap_err() {
        SignerError::BroadcastUnconfirmed {
            provider_tx_id,
            provider_status,
            ..
        } => {
            assert_eq!(provider_tx_id, None);
            assert_eq!(provider_status, Some(503));
        }
        other => panic!("Expected BroadcastUnconfirmed error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_create_accepted_without_an_id_is_unconfirmed() {
    let server = MockServer::start().await;
    let wallet_keypair = Keypair::new();
    let signer_address = keypair_pubkey(&wallet_keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(wallet_response(&signer_address))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(serde_json::json!({ "status": "pending" })),
        )
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 1);
    signer.init().await.unwrap();
    let tx = create_test_transaction(&signer.pubkey());

    match signer.sign_and_send_transaction(&tx).await.unwrap_err() {
        SignerError::BroadcastUnconfirmed {
            provider_tx_id,
            provider_status,
            ..
        } => {
            assert_eq!(provider_tx_id, None);
            assert_eq!(provider_status, None);
        }
        other => panic!("Expected BroadcastUnconfirmed error, got: {:?}", other),
    }
}

/// A blank create id is no handle at all: taken at face value it would be
/// spliced into the poll and approval URLs and reported as a recovery handle.
#[tokio::test]
async fn test_create_accepted_with_a_blank_id_is_unconfirmed_without_one() {
    let server = MockServer::start().await;
    let wallet_keypair = Keypair::new();
    let signer_address = keypair_pubkey(&wallet_keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(wallet_response(&signer_address))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(serde_json::json!({ "id": "   ", "status": "pending" })),
        )
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 1);
    signer.init().await.unwrap();
    let tx = create_test_transaction(&signer.pubkey());

    match signer.sign_and_send_transaction(&tx).await.unwrap_err() {
        SignerError::BroadcastUnconfirmed { provider_tx_id, .. } => {
            assert_eq!(provider_tx_id, None);
        }
        other => panic!("Expected BroadcastUnconfirmed error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_create_accepted_with_an_unusable_body_keeps_the_transaction_id() {
    let server = MockServer::start().await;
    let wallet_keypair = Keypair::new();
    let signer_address = keypair_pubkey(&wallet_keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(wallet_response(&signer_address))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(serde_json::json!({ "id": "tx-accepted" })),
        )
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 1);
    signer.init().await.unwrap();
    let tx = create_test_transaction(&signer.pubkey());

    match signer.sign_and_send_transaction(&tx).await.unwrap_err() {
        SignerError::BroadcastUnconfirmed {
            provider_tx_id,
            provider_status,
            ..
        } => {
            assert_eq!(provider_tx_id.as_deref(), Some("tx-accepted"));
            assert_eq!(provider_status, None);
        }
        other => panic!("Expected BroadcastUnconfirmed error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_create_rejected_by_crossmint_stays_a_plain_failure() {
    let server = MockServer::start().await;
    let wallet_keypair = Keypair::new();
    let signer_address = keypair_pubkey(&wallet_keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .respond_with(wallet_response(&signer_address))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "message": "invalid transaction"
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 1);
    signer.init().await.unwrap();
    let tx = create_test_transaction(&signer.pubkey());

    match signer.sign_and_send_transaction(&tx).await.unwrap_err() {
        SignerError::RemoteApiError { .. } => {}
        other => panic!("Expected RemoteApiError, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_sign_and_send_transaction_accepts_signature_from_on_chain_transaction_bytes() {
    let server = MockServer::start().await;
    let wallet_keypair = Keypair::new();
    let signer_pubkey = keypair_pubkey(&wallet_keypair);
    let signer_address = signer_pubkey.to_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(wallet_response(&signer_address))
        .mount(&server)
        .await;

    let recipient = Pubkey::new_unique();
    let mut remote_tx = create_test_transaction_with_recipient(&signer_pubkey, &recipient);
    let remote_signature = keypair_sign_message(&wallet_keypair, &remote_tx.message.serialize());
    TransactionUtil::add_signature_to_transaction(&mut remote_tx, &signer_pubkey, remote_signature)
        .unwrap();
    let remote_on_chain_transaction =
        bs58::encode(bincode::serialize(&remote_tx).unwrap()).into_string();

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-mismatch",
            "status": "success",
            "onChain": {
                "transaction": remote_on_chain_transaction
            }
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 1);
    signer.init().await.unwrap();

    let local_tx = create_test_transaction(&signer_pubkey);
    let signature = signer.sign_and_send_transaction(&local_tx).await.unwrap();
    assert_eq!(signature, remote_signature);
}

#[tokio::test]
async fn test_sign_and_send_transaction_prefers_on_chain_transaction_signature_over_txid_fallback()
{
    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let signer_pubkey = keypair_pubkey(&keypair);
    let signer_address = signer_pubkey.to_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(wallet_response(&signer_address))
        .mount(&server)
        .await;

    // onChain.transaction with different message bytes (different recipient)
    let recipient = Pubkey::new_unique();
    let mut remote_tx = create_test_transaction_with_recipient(&signer_pubkey, &recipient);
    let remote_sig = keypair_sign_message(&keypair, &remote_tx.message.serialize());
    TransactionUtil::add_signature_to_transaction(&mut remote_tx, &signer_pubkey, remote_sig)
        .unwrap();
    let remote_on_chain_transaction =
        bs58::encode(bincode::serialize(&remote_tx).unwrap()).into_string();

    // onChain.txId is only valid for the remote transaction bytes, not the local ones.
    let tx_id = bs58::encode(remote_sig.as_ref()).into_string();

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-fallthrough",
            "status": "success",
            "onChain": {
                "transaction": remote_on_chain_transaction,
                "txId": tx_id
            }
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 1);
    signer.init().await.unwrap();

    let local_tx = create_test_transaction(&signer_pubkey);
    let signature = signer.sign_and_send_transaction(&local_tx).await.unwrap();
    assert_eq!(signature, remote_sig);
}

#[tokio::test]
async fn test_sign_and_send_transaction_awaiting_approval() {
    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let signer_address = keypair_pubkey(&keypair).to_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(wallet_response(&signer_address))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "awaiting-approval",
            "chainType": "solana",
            "walletType": "smart"
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 2);
    signer.init().await.unwrap();

    let tx = create_test_transaction(&signer.pubkey());
    let result = signer.sign_and_send_transaction(&tx).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        SignerError::BroadcastUnconfirmed { detail, .. } => {
            assert!(
                detail.contains("awaiting approval"),
                "Unexpected error detail: {detail}"
            );
        }
        other => panic!("Expected BroadcastUnconfirmed error, got: {:?}", other),
    }
}

fn attach_approval_signer(
    signer: &mut CrossmintSigner,
    locator: &str,
) -> ed25519_dalek::SigningKey {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    signer.signing_key = Some(key.clone());
    signer.signer = Some(locator.to_string());
    key
}

#[tokio::test]
async fn test_sign_and_send_transaction_submits_approval_once_and_polls_after_async_registration() {
    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let signer_pubkey = keypair_pubkey(&keypair);
    let locator = "server:test-approver";
    let approval_message = bs58::encode(b"approval-challenge").into_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(wallet_response(&signer_pubkey.to_string()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "awaiting-approval",
            "approvals": {
                "pending": [
                    { "signer": { "locator": locator }, "message": approval_message }
                ]
            }
        })))
        .mount(&server)
        .await;

    // Approval is acknowledged but Crossmint has not registered it yet:
    // the transaction still reports awaiting-approval with nothing pending.
    Mock::given(method("POST"))
        .and(path(
            "/2025-06-09/wallets/test-wallet/transactions/tx-123/approvals",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "awaiting-approval",
            "approvals": { "pending": [] }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 5);
    attach_approval_signer(&mut signer, locator);
    signer.init().await.unwrap();

    let tx = create_test_transaction(&signer_pubkey);
    let expected_signature = keypair_sign_message(&keypair, &tx.message.serialize());
    let tx_id = bs58::encode(expected_signature.as_ref()).into_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions/tx-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "success",
            "onChain": { "txId": tx_id }
        })))
        .mount(&server)
        .await;

    let signature = signer.sign_and_send_transaction(&tx).await.unwrap();
    assert_eq!(signature, expected_signature);
}

#[tokio::test]
async fn test_sign_and_send_transaction_selects_pending_approval_matching_signer_locator() {
    use ed25519_dalek::Signer as _;
    use wiremock::matchers::body_string_contains;

    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let signer_pubkey = keypair_pubkey(&keypair);
    let locator = "server:test-approver";

    let our_message_bytes = b"our-approval-challenge";
    let our_message = bs58::encode(our_message_bytes).into_string();
    let other_message = bs58::encode(b"someone-elses-challenge").into_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(wallet_response(&signer_pubkey.to_string()))
        .mount(&server)
        .await;

    // pending[0] belongs to another approver; ours is second.
    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-multi",
            "status": "awaiting-approval",
            "approvals": {
                "pending": [
                    { "signer": { "locator": "server:other-approver" }, "message": other_message },
                    { "signer": { "locator": locator }, "message": our_message }
                ]
            }
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 5);
    let signing_key = attach_approval_signer(&mut signer, locator);
    signer.init().await.unwrap();

    let tx = create_test_transaction(&signer_pubkey);
    let expected_tx_signature = keypair_sign_message(&keypair, &tx.message.serialize());
    let tx_id = bs58::encode(expected_tx_signature.as_ref()).into_string();

    // Only an approval whose signature covers OUR challenge bytes (and
    // carries our locator) is answered; signing pending[0] would miss this
    // mock and fail the test.
    let expected_approval_signature =
        bs58::encode(signing_key.sign(our_message_bytes).to_bytes()).into_string();
    Mock::given(method("POST"))
        .and(path(
            "/2025-06-09/wallets/test-wallet/transactions/tx-multi/approvals",
        ))
        .and(body_string_contains(&expected_approval_signature))
        .and(body_string_contains(locator))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-multi",
            "status": "success",
            "onChain": { "txId": tx_id }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signature = signer.sign_and_send_transaction(&tx).await.unwrap();
    assert_eq!(signature, expected_tx_signature);
}

#[tokio::test]
async fn test_sign_and_send_transaction_success_on_last_polled_response() {
    let server = MockServer::start().await;
    let keypair = Keypair::new();
    let signer_pubkey = keypair_pubkey(&keypair);
    let signer_address = signer_pubkey.to_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(wallet_response(&signer_address))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "pending",
            "chainType": "solana",
            "walletType": "smart"
        })))
        .mount(&server)
        .await;

    let tx = create_test_transaction(&signer_pubkey);
    let expected_signature = keypair_sign_message(&keypair, &tx.message.serialize());
    let tx_id = bs58::encode(expected_signature.as_ref()).into_string();

    Mock::given(method("GET"))
        .and(path("/2025-06-09/wallets/test-wallet/transactions/tx-123"))
        .and(header("x-api-key", "test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "tx-123",
            "status": "success",
            "chainType": "solana",
            "walletType": "smart",
            "onChain": {
                "txId": tx_id
            }
        })))
        .mount(&server)
        .await;

    let mut signer = create_test_signer(&server.uri(), 1, 1);
    signer.init().await.unwrap();

    let signature = signer.sign_and_send_transaction(&tx).await.unwrap();
    assert_eq!(signature, expected_signature);
}
