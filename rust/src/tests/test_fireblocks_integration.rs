pub const FIREBLOCKS_API_KEY: &str = "FIREBLOCKS_API_KEY";
pub const FIREBLOCKS_PRIVATE_KEY_PEM: &str = "FIREBLOCKS_PRIVATE_KEY_PEM";
pub const FIREBLOCKS_VAULT_ACCOUNT_ID: &str = "FIREBLOCKS_VAULT_ACCOUNT_ID";
pub const SOLANA_RPC_URL: &str = "SOLANA_RPC_URL";

#[cfg(feature = "fireblocks")]
#[cfg(test)]
mod tests {
    use dotenvy::dotenv;

    use super::*;
    use crate::fireblocks::{FireblocksSigner, FireblocksSignerConfig};
    use crate::test_util::{create_test_transaction, create_test_transaction_with_recipient};
    use crate::tests::rpc_util::get_rpc_blockhash;
    use crate::traits::SolanaSigner;
    use std::env;

    async fn get_signer() -> FireblocksSigner {
        dotenv().ok();

        let api_key = env::var(FIREBLOCKS_API_KEY)
            .expect("FIREBLOCKS_API_KEY must be set for integration tests");
        let private_key_pem = env::var(FIREBLOCKS_PRIVATE_KEY_PEM)
            .expect("FIREBLOCKS_PRIVATE_KEY_PEM must be set for integration tests");
        let vault_account_id = env::var(FIREBLOCKS_VAULT_ACCOUNT_ID)
            .expect("FIREBLOCKS_VAULT_ACCOUNT_ID must be set for integration tests");

        let config = FireblocksSignerConfig {
            api_key,
            private_key_pem,
            vault_account_id,
            asset_id: Some("SOL_TEST".to_string()),
            api_base_url: Some("https://api.fireblocks.io".to_string()),
            poll_interval_ms: None,
            max_poll_attempts: None,
            use_program_call: Some(true),
        };

        let mut signer = FireblocksSigner::new(config);
        signer
            .init()
            .await
            .expect("Failed to initialize FireblocksSigner");
        signer
    }

    #[tokio::test]
    #[ignore] // Ignored because sign raw isn't available in testnet
    #[cfg(feature = "integration-tests")]
    async fn test_fireblocks_sign_message() {
        let signer = get_signer().await;

        let transaction = create_test_transaction(&signer.pubkey());
        let message = transaction.message_data();

        let signature = signer
            .sign_message(&message)
            .await
            .expect("Failed to sign message with Fireblocks");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(signature.verify(&signer.pubkey().to_bytes(), &message));
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_fireblocks_sign_transaction() {
        let signer = get_signer().await;
        let pubkey = signer.pubkey();

        // Self-transfer: from vault to same vault address
        let mut transaction = create_test_transaction_with_recipient(&pubkey, &pubkey);

        // PROGRAM_CALL needs real devnet blockhash
        let rpc_url = env::var(SOLANA_RPC_URL)
            .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());

        transaction.message.recent_blockhash = get_rpc_blockhash(&rpc_url)
            .await
            .expect("Failed to get blockhash from RPC");

        let (base64_txn, signature) = signer
            .sign_transaction(&mut transaction)
            .await
            .expect("Failed to sign transaction with Fireblocks");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(
            !base64_txn.is_empty(),
            "Serialized transaction should not be empty"
        );
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_fireblocks_availability() {
        let signer = get_signer().await;

        let is_available = signer.is_available().await;
        assert!(is_available, "Fireblocks signer should be available");
    }
}
