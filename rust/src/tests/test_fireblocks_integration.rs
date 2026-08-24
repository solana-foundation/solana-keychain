pub const FIREBLOCKS_API_KEY: &str = "FIREBLOCKS_API_KEY";
pub const FIREBLOCKS_PRIVATE_KEY_PEM: &str = "FIREBLOCKS_PRIVATE_KEY_PEM";
pub const FIREBLOCKS_VAULT_ACCOUNT_ID: &str = "FIREBLOCKS_VAULT_ACCOUNT_ID";
pub const FIREBLOCKS_API_BASE_URL: &str = "FIREBLOCKS_API_BASE_URL";
pub const FIREBLOCKS_ASSET_ID: &str = "FIREBLOCKS_ASSET_ID";

#[cfg(feature = "fireblocks")]
#[cfg(test)]
mod tests {
    use dotenvy::dotenv;
    use serial_test::serial;

    use super::*;
    use crate::fireblocks::{FireblocksSigner, FireblocksSignerConfig};
    use crate::test_util::create_test_transaction;
    use crate::traits::SolanaSigner;
    use std::env;

    fn required_env(name: &str) -> String {
        match env::var(name) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => panic!("{name} must be non-empty for integration tests"),
            Err(_) => panic!("{name} must be set for integration tests"),
        }
    }

    async fn get_signer() -> FireblocksSigner {
        get_signer_with_program_call(false).await
    }

    async fn get_signer_with_program_call(use_program_call: bool) -> FireblocksSigner {
        dotenv().ok();

        let api_key = required_env(FIREBLOCKS_API_KEY);
        let private_key_pem = required_env(FIREBLOCKS_PRIVATE_KEY_PEM);
        let vault_account_id = required_env(FIREBLOCKS_VAULT_ACCOUNT_ID);

        let config = FireblocksSignerConfig {
            api_key,
            private_key_pem,
            vault_account_id,
            asset_id: Some(
                env::var(FIREBLOCKS_ASSET_ID).unwrap_or_else(|_| "SOL_TEST".to_string()),
            ),
            api_base_url: Some(
                env::var(FIREBLOCKS_API_BASE_URL)
                    .unwrap_or_else(|_| "https://api.fireblocks.io".to_string()),
            ),
            poll_interval_ms: None,
            max_poll_attempts: None,
            use_program_call: Some(use_program_call),
            http_client_config: None,
        };

        let mut signer =
            FireblocksSigner::new(config).expect("Failed to construct FireblocksSigner");
        signer
            .init()
            .await
            .expect("Failed to initialize Fireblocks signer");
        signer
    }

    #[tokio::test]
    #[ignore] // Ignored because sign raw isn't available in testnet
    #[cfg(feature = "integration-tests")]
    #[serial]
    async fn test_fireblocks_sign_message() {
        let signer = get_signer().await;

        let transaction = create_test_transaction(&signer.pubkey());
        let message = transaction.message.serialize();

        let signature = signer
            .sign_message(&message)
            .await
            .expect("Failed to sign message with Fireblocks");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(signature.verify(&signer.pubkey().to_bytes(), &message));
    }

    #[tokio::test]
    #[ignore] // Ignored because PROGRAM_CALL must be enabled for the workspace by Fireblocks
    #[cfg(feature = "integration-tests")]
    #[serial]
    async fn test_fireblocks_program_call_signs_without_broadcasting() {
        let signer = get_signer_with_program_call(true).await;

        let mut transaction = create_test_transaction(&signer.pubkey());
        let message = transaction.message.serialize();

        signer
            .sign_transaction(&mut transaction)
            .await
            .expect("Failed to sign transaction with a Fireblocks PROGRAM_CALL");

        assert!(transaction.signatures[0].verify(&signer.pubkey().to_bytes(), &message));
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    #[serial]
    async fn test_fireblocks_availability() {
        let signer = get_signer().await;

        let is_available = signer.is_available().await;
        assert!(is_available, "Fireblocks signer should be available");
    }
}
