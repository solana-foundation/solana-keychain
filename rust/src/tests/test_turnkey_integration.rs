pub const TURNKEY_API_PUBLIC_KEY: &str = "TURNKEY_API_PUBLIC_KEY";
pub const TURNKEY_API_PRIVATE_KEY: &str = "TURNKEY_API_PRIVATE_KEY";
pub const TURNKEY_ORGANIZATION_ID: &str = "TURNKEY_ORGANIZATION_ID";
pub const TURNKEY_PRIVATE_KEY_ID: &str = "TURNKEY_PRIVATE_KEY_ID";
pub const TURNKEY_PUBLIC_KEY: &str = "TURNKEY_PUBLIC_KEY";

#[cfg(feature = "turnkey")]
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use dotenvy::dotenv;

    use super::*;
    use crate::sdk_adapter::Pubkey;
    use crate::test_util::create_test_transaction;
    use crate::traits::SolanaSigner;
    use crate::turnkey::TurnkeySigner;
    use std::env;

    async fn get_signer() -> TurnkeySigner {
        dotenv().ok();

        let api_key = env::var(TURNKEY_API_PUBLIC_KEY)
            .expect("TURNKEY_API_PUBLIC_KEY must be set for integration tests");
        let api_private_key = env::var(TURNKEY_API_PRIVATE_KEY)
            .expect("TURNKEY_API_PRIVATE_KEY must be set for integration tests");
        let organization_id = env::var(TURNKEY_ORGANIZATION_ID)
            .expect("TURNKEY_ORGANIZATION_ID must be set for integration tests");
        let private_key_id = env::var(TURNKEY_PRIVATE_KEY_ID)
            .expect("TURNKEY_PRIVATE_KEY_ID must be set for integration tests");
        let signer_pubkey_str = env::var(TURNKEY_PUBLIC_KEY)
            .expect("TURNKEY_PUBLIC_KEY must be set for integration tests");

        let signer_pubkey = signer_pubkey_str
            .parse::<Pubkey>()
            .expect("Invalid TURNKEY_PUBLIC_KEY format");

        TurnkeySigner::new(
            api_key,
            api_private_key,
            organization_id,
            private_key_id,
            signer_pubkey.to_string(),
        )
        .expect("Failed to create TurnkeySigner")
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_turnkey_sign_message() {
        let signer = get_signer().await;

        let transaction = create_test_transaction(&signer.pubkey());
        let message = transaction.message_data();

        let signature = signer
            .sign_message(&message)
            .await
            .expect("Failed to sign message with Turnkey");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(signature.verify(&signer.pubkey().to_bytes(), &message));
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_turnkey_sign_transaction() {
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
            .expect("Failed to sign transaction with Turnkey");

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
    async fn test_turnkey_availability() {
        let signer = get_signer().await;

        let is_available = signer.is_available().await;
        assert!(is_available, "Turnkey signer should be available");
    }
}
