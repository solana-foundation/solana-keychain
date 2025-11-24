pub const PRIVY_APP_ID: &str = "PRIVY_APP_ID";
pub const PRIVY_APP_SECRET: &str = "PRIVY_APP_SECRET";
pub const PRIVY_WALLET_ID: &str = "PRIVY_WALLET_ID";

#[cfg(feature = "privy")]
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use dotenvy::dotenv;

    use super::*;
    use crate::privy::PrivySigner;
    use crate::test_util::create_test_transaction;
    use crate::traits::SolanaSigner;
    use std::env;

    async fn get_signer() -> PrivySigner {
        dotenv().ok();

        let app_id =
            env::var(PRIVY_APP_ID).expect("PRIVY_APP_ID must be set for integration tests");
        let app_secret =
            env::var(PRIVY_APP_SECRET).expect("PRIVY_APP_SECRET must be set for integration tests");
        let wallet_id =
            env::var(PRIVY_WALLET_ID).expect("PRIVY_WALLET_ID must be set for integration tests");

        let mut signer = PrivySigner::new(app_id, app_secret, wallet_id);

        signer
            .init()
            .await
            .expect("Failed to initialize Privy signer");

        signer
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_privy_sign_message() {
        let signer = get_signer().await;

        let transaction = create_test_transaction(&signer.pubkey());
        let message = transaction.message_data();

        let signature = signer
            .sign_message(&message)
            .await
            .expect("Failed to sign message with Privy");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(signature.verify(&signer.pubkey().to_bytes(), &message));
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_privy_sign_transaction() {
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
            .expect("Failed to sign transaction with Privy");

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
    async fn test_privy_is_available() {
        let signer = get_signer().await;
        assert!(signer.is_available().await);
    }
}
