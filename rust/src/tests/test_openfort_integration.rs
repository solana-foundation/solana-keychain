pub const OPENFORT_SECRET_KEY: &str = "OPENFORT_SECRET_KEY";
pub const OPENFORT_ACCOUNT_ID: &str = "OPENFORT_ACCOUNT_ID";
pub const OPENFORT_WALLET_SECRET: &str = "OPENFORT_WALLET_SECRET";
pub const OPENFORT_BASE_URL: &str = "OPENFORT_BASE_URL";

#[cfg(feature = "openfort")]
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use dotenvy::dotenv;

    use super::*;
    use crate::openfort::{OpenfortSigner, OpenfortSignerConfig};
    use crate::test_util::create_test_transaction;
    use crate::traits::{SolanaSigner, TransactionSigner};
    use crate::transaction_util::deserialize_wire_transaction;
    use std::env;

    async fn get_signer() -> OpenfortSigner {
        dotenv().ok();

        let secret_key = env::var(OPENFORT_SECRET_KEY)
            .expect("OPENFORT_SECRET_KEY must be set for integration tests");
        let account_id = env::var(OPENFORT_ACCOUNT_ID)
            .expect("OPENFORT_ACCOUNT_ID must be set for integration tests");
        let wallet_secret = env::var(OPENFORT_WALLET_SECRET)
            .expect("OPENFORT_WALLET_SECRET must be set for integration tests");
        let api_base_url = env::var(OPENFORT_BASE_URL).ok();

        let mut signer = OpenfortSigner::from_config(OpenfortSignerConfig {
            secret_key,
            account_id,
            wallet_secret,
            api_base_url,
            http_client_config: None,
        })
        .expect("Failed to create OpenfortSigner");

        signer
            .init()
            .await
            .expect("Failed to initialize OpenfortSigner");

        signer
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_openfort_sign_message() {
        let signer = get_signer().await;

        let transaction = create_test_transaction(&signer.pubkey());
        let message = transaction.message.serialize();

        let signature = signer
            .sign_message(&message)
            .await
            .expect("Failed to sign message with Openfort");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(signature.verify(&signer.pubkey().to_bytes(), &message));
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_openfort_sign_transaction() {
        use crate::tests::litesvm_util::{
            get_latest_blockhash, simulate_transaction, start_litesvm,
        };

        let signer = get_signer().await;

        let lite_svm = start_litesvm(&signer.pubkey())
            .await
            .expect("Failed to start LiteSVM");

        let mut transaction = create_test_transaction(&signer.pubkey());
        transaction.message.set_recent_blockhash(
            get_latest_blockhash(&lite_svm)
                .await
                .expect("Failed to get latest blockhash"),
        );

        let original_message = transaction.message.serialize();

        let (base64_txn, signature) = signer
            .sign_transaction(&mut transaction)
            .await
            .expect("Failed to sign transaction with Openfort")
            .into_signed_transaction();

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(
            signature.verify(
                &signer.pubkey().to_bytes(),
                &transaction.message.serialize()
            ),
            "Signature should be valid"
        );

        let decoded_bytes = STANDARD
            .decode(&base64_txn)
            .expect("Failed to decode base64 transaction");

        let decoded_transaction = deserialize_wire_transaction(&decoded_bytes)
            .expect("Failed to deserialize transaction");

        assert_eq!(
            decoded_transaction.message.serialize(),
            original_message,
            "Decoded transaction should have the same message"
        );

        simulate_transaction(&lite_svm, &decoded_transaction)
            .await
            .expect("Failed to simulate transaction");
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_openfort_is_available() {
        let signer = get_signer().await;
        assert!(signer.is_available().await);
    }
}
