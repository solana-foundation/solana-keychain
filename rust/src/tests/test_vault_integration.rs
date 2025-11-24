pub const VAULT_ADDR: &str = "VAULT_ADDR";
pub const VAULT_TOKEN: &str = "VAULT_TOKEN";
pub const VAULT_KEY_NAME: &str = "VAULT_KEY_NAME";
pub const VAULT_SIGNER_PUBKEY: &str = "VAULT_SIGNER_PUBKEY";

#[cfg(feature = "vault")]
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use dotenvy::dotenv;

    use super::*;
    use crate::test_util::create_test_transaction;
    use crate::traits::SolanaSigner;
    use crate::vault::VaultSigner;
    use std::env;

    async fn get_signer() -> VaultSigner {
        dotenv().ok();

        let vault_addr =
            env::var(VAULT_ADDR).expect("VAULT_ADDR must be set for integration tests");
        let vault_token =
            env::var(VAULT_TOKEN).expect("VAULT_TOKEN must be set for integration tests");
        let key_name =
            env::var(VAULT_KEY_NAME).expect("VAULT_KEY_NAME must be set for integration tests");
        let signer_pubkey_str = env::var(VAULT_SIGNER_PUBKEY)
            .expect("VAULT_SIGNER_PUBKEY must be set for integration tests");

        VaultSigner::new(vault_addr, vault_token, key_name, signer_pubkey_str)
            .expect("Failed to create VaultSigner")
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_vault_sign_message() {
        let signer = get_signer().await;

        let transaction = create_test_transaction(&signer.pubkey());
        let message = transaction.message_data();

        let signature = signer
            .sign_message(&message)
            .await
            .expect("Failed to sign message with Vault");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(signature.verify(&signer.pubkey().to_bytes(), &message));
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_vault_sign_transaction() {
        use crate::tests::litesvm_util::{
            get_latest_blockhash, simulate_transaction, start_litesvm,
        };

        let signer = get_signer().await;

        let lite_svm = start_litesvm(&signer.pubkey())
            .await
            .expect("Failed to start LiteSVM");

        let mut transaction = create_test_transaction(&signer.pubkey());
        transaction.message.recent_blockhash = get_latest_blockhash(&lite_svm)
            .await
            .expect("Failed to get latest blockhash");

        let original_message = transaction.message_data();

        let (base64_txn, signature) = signer
            .sign_transaction(&mut transaction)
            .await
            .expect("Failed to sign transaction with Vault");

        // Validate the signature
        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(
            signature.verify(&signer.pubkey().to_bytes(), &transaction.message_data()),
            "Signature should be valid"
        );

        // Validate the transaction
        let decoded_bytes = STANDARD
            .decode(&base64_txn)
            .expect("Failed to decode base64 transaction");

        let decoded_transaction: crate::sdk_adapter::Transaction =
            bincode::deserialize(&decoded_bytes).expect("Failed to deserialize transaction");

        assert_eq!(
            decoded_transaction.message_data(),
            original_message,
            "Decoded transaction should have the same message"
        );

        simulate_transaction(&lite_svm, &decoded_transaction)
            .await
            .expect("Failed to simulate transaction");
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_vault_availability() {
        let signer = get_signer().await;

        let is_available = signer.is_available().await;
        assert!(is_available, "Vault signer should be available");
    }
}
