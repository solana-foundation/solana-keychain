pub const DFNS_AUTH_TOKEN: &str = "DFNS_AUTH_TOKEN";
pub const DFNS_CRED_ID: &str = "DFNS_CRED_ID";
pub const DFNS_PRIVATE_KEY_PEM: &str = "DFNS_PRIVATE_KEY_PEM";
pub const DFNS_WALLET_ID: &str = "DFNS_WALLET_ID";
pub const DFNS_API_BASE_URL: &str = "DFNS_API_BASE_URL";

#[cfg(feature = "dfns")]
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use dotenvy::dotenv;

    use super::*;
    use crate::dfns::{DfnsSigner, DfnsSignerConfig};
    use crate::test_util::create_test_transaction;
    use crate::traits::SolanaSigner;
    use std::env;

    async fn get_signer() -> DfnsSigner {
        dotenv().ok();

        let auth_token =
            env::var(DFNS_AUTH_TOKEN).expect("DFNS_AUTH_TOKEN must be set for integration tests");
        let cred_id =
            env::var(DFNS_CRED_ID).expect("DFNS_CRED_ID must be set for integration tests");
        let private_key_pem = env::var(DFNS_PRIVATE_KEY_PEM)
            .expect("DFNS_PRIVATE_KEY_PEM must be set for integration tests");
        let wallet_id =
            env::var(DFNS_WALLET_ID).expect("DFNS_WALLET_ID must be set for integration tests");
        let api_base_url = env::var(DFNS_API_BASE_URL).ok();

        let mut signer = DfnsSigner::new(DfnsSignerConfig {
            auth_token,
            cred_id,
            private_key_pem,
            wallet_id,
            api_base_url,
            http_client_config: None,
        });

        signer.init().await.expect("Failed to init DfnsSigner");
        signer
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_dfns_sign_message() {
        let signer = get_signer().await;

        let transaction = create_test_transaction(&signer.pubkey());
        let message = transaction.message_data();

        let signature = signer
            .sign_message(&message)
            .await
            .expect("Failed to sign message with Dfns");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(signature.verify(&signer.pubkey().to_bytes(), &message));
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_dfns_sign_transaction() {
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
            .expect("Failed to sign transaction with Dfns")
            .into_signed_transaction();

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(
            signature.verify(&signer.pubkey().to_bytes(), &transaction.message_data()),
            "Signature should be valid"
        );

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
    async fn test_dfns_availability() {
        let signer = get_signer().await;

        let is_available = signer.is_available().await;
        assert!(is_available, "Dfns signer should be available");
    }
}
