pub const UTILA_SERVICE_ACCOUNT_EMAIL: &str = "UTILA_SERVICE_ACCOUNT_EMAIL";
pub const UTILA_SERVICE_ACCOUNT_PRIVATE_KEY: &str = "UTILA_SERVICE_ACCOUNT_PRIVATE_KEY";
pub const UTILA_VAULT_ID: &str = "UTILA_VAULT_ID";
pub const UTILA_WALLET_ID: &str = "UTILA_WALLET_ID";
pub const UTILA_NETWORK: &str = "UTILA_NETWORK";
pub const UTILA_API_BASE_URL: &str = "UTILA_API_BASE_URL";
pub const UTILA_POLL_INTERVAL_MS: &str = "UTILA_POLL_INTERVAL_MS";
pub const UTILA_MAX_POLL_ATTEMPTS: &str = "UTILA_MAX_POLL_ATTEMPTS";

#[cfg(feature = "utila")]
#[cfg(test)]
mod tests {
    use dotenvy::dotenv;
    use std::env;

    use super::*;
    use crate::sdk_adapter::{Message, Transaction, VersionedTransaction};
    use crate::tests::rpc_util::get_rpc_blockhash;
    use crate::traits::SolanaSigner;
    use crate::utila::{UtilaSigner, UtilaSignerConfig};

    fn required_env(name: &str) -> String {
        match env::var(name) {
            Ok(value) if !value.trim().is_empty() => value,
            Ok(_) => panic!("{name} must be non-empty for integration tests"),
            Err(_) => panic!("{name} must be set for integration tests"),
        }
    }

    async fn get_signer() -> UtilaSigner {
        dotenv().ok();

        let mut signer = UtilaSigner::new(UtilaSignerConfig {
            service_account_email: required_env(UTILA_SERVICE_ACCOUNT_EMAIL),
            service_account_private_key_pem: required_env(UTILA_SERVICE_ACCOUNT_PRIVATE_KEY),
            vault_id: required_env(UTILA_VAULT_ID),
            wallet_id: required_env(UTILA_WALLET_ID),
            network: required_env(UTILA_NETWORK),
            api_base_url: env::var(UTILA_API_BASE_URL).ok(),
            poll_interval_ms: env::var(UTILA_POLL_INTERVAL_MS)
                .ok()
                .and_then(|value| value.parse().ok()),
            max_poll_attempts: env::var(UTILA_MAX_POLL_ATTEMPTS)
                .ok()
                .and_then(|value| value.parse().ok()),
            designated_signers: None,
            http_client_config: None,
        })
        .expect("Failed to create UtilaSigner");

        signer
            .init()
            .await
            .expect("Failed to initialize UtilaSigner");
        signer
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_utila_sign_message_not_supported() {
        let signer = get_signer().await;
        let result = signer.sign_message(b"utila-test").await;
        assert!(result.is_err(), "sign_message should be unsupported");
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_utila_sign_transaction() {
        let signer = get_signer().await;

        let rpc_url = env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
        let latest_blockhash = get_rpc_blockhash(&rpc_url)
            .await
            .expect("Failed to fetch latest RPC blockhash");

        let mut message = Message::new(&[], Some(&signer.pubkey()));
        message.recent_blockhash = latest_blockhash;
        let mut transaction: VersionedTransaction = Transaction::new_unsigned(message).into();

        let (_base64_txn, signature) = signer
            .sign_transaction(&mut transaction)
            .await
            .expect("Failed to sign transaction with Utila")
            .into_signed_transaction();

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_utila_is_available() {
        let signer = get_signer().await;
        assert!(signer.is_available().await);
    }
}
