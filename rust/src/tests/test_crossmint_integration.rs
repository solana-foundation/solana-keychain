pub const CROSSMINT_API_KEY: &str = "CROSSMINT_API_KEY";
pub const CROSSMINT_WALLET_LOCATOR: &str = "CROSSMINT_WALLET_LOCATOR";
pub const CROSSMINT_API_BASE_URL: &str = "CROSSMINT_API_BASE_URL";
pub const CROSSMINT_SIGNER: &str = "CROSSMINT_SIGNER";

#[cfg(feature = "crossmint")]
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use dotenvy::dotenv;
    use std::env;

    use super::*;
    use crate::crossmint::{CrossmintSigner, CrossmintSignerConfig};
    use crate::test_util::create_test_transaction;
    use crate::tests::rpc_util::get_rpc_blockhash;
    use crate::traits::SolanaSigner;

    async fn get_signer() -> CrossmintSigner {
        dotenv().ok();

        let api_key = env::var(CROSSMINT_API_KEY)
            .expect("CROSSMINT_API_KEY must be set for integration tests");
        let wallet_locator = env::var(CROSSMINT_WALLET_LOCATOR)
            .expect("CROSSMINT_WALLET_LOCATOR must be set for integration tests");
        let api_base_url = env::var(CROSSMINT_API_BASE_URL).ok();
        let signer = env::var(CROSSMINT_SIGNER).ok();

        let mut signer = CrossmintSigner::new(CrossmintSignerConfig {
            api_key,
            wallet_locator,
            signer,
            api_base_url,
            poll_interval_ms: None,
            max_poll_attempts: None,
        })
        .expect("Failed to create CrossmintSigner");

        signer
            .init()
            .await
            .expect("Failed to initialize CrossmintSigner");

        signer
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_crossmint_sign_message_not_supported() {
        let signer = get_signer().await;
        let result = signer.sign_message(b"crossmint-test").await;
        assert!(result.is_err(), "sign_message should be unsupported");

        let err_text = format!("{}", result.unwrap_err());
        assert!(
            err_text.contains("not supported"),
            "Expected not supported error, got: {err_text}"
        );
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_crossmint_sign_transaction() {
        let signer = get_signer().await;

        let rpc_url = env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
        let latest_blockhash = get_rpc_blockhash(&rpc_url)
            .await
            .expect("Failed to fetch latest RPC blockhash");

        let mut transaction = create_test_transaction(&signer.pubkey());
        transaction.message.recent_blockhash = latest_blockhash;

        let (base64_txn, signature) = signer
            .sign_transaction(&mut transaction)
            .await
            .expect("Failed to sign transaction with Crossmint");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");

        let decoded_bytes = STANDARD
            .decode(&base64_txn)
            .expect("Failed to decode base64 transaction");

        let _: crate::sdk_adapter::Transaction =
            bincode::deserialize(&decoded_bytes).expect("Failed to deserialize transaction");
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_crossmint_is_available() {
        let signer = get_signer().await;
        assert!(signer.is_available().await);
    }
}
