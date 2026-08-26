// GCP KMS integration tests require real GCP credentials and an Ed25519 KMS key.
// To run these tests:
// 1. Create an Ed25519 KMS key in GCP Console:
//    gcloud kms keys create my-key \
//      --keyring=my-keyring \
//      --location=us-east1 \
//      --purpose=asymmetric-signing \
//      --default-algorithm=ec-sign-ed25519
// 2. Set environment variables in .env or shell:
//    - GCP_KMS_KEY_NAME: Full resource name of the crypto key version
//    - GCP_KMS_SIGNER_PUBKEY: Base58-encoded Solana public key
// 3. Authenticate via ADC:
//    gcloud auth application-default login

pub const GCP_KMS_KEY_NAME: &str = "GCP_KMS_KEY_NAME";
pub const GCP_KMS_SIGNER_PUBKEY: &str = "GCP_KMS_SIGNER_PUBKEY";

#[cfg(feature = "gcp_kms")]
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use dotenvy::dotenv;

    use super::*;
    use crate::gcp_kms::GcpKmsSigner;
    use crate::test_util::create_test_transaction;
    use crate::tests::litesvm_util::{get_latest_blockhash, simulate_transaction, start_litesvm};
    use crate::traits::{SolanaSigner, TransactionSigner};
    use crate::transaction_util::deserialize_wire_transaction;
    use std::env;

    async fn get_signer() -> GcpKmsSigner {
        dotenv().ok();

        let key_name =
            env::var(GCP_KMS_KEY_NAME).expect("GCP_KMS_KEY_NAME must be set for integration tests");
        let signer_pubkey = env::var(GCP_KMS_SIGNER_PUBKEY)
            .expect("GCP_KMS_SIGNER_PUBKEY must be set for integration tests");

        GcpKmsSigner::new(key_name, signer_pubkey)
            .await
            .expect("Failed to create GcpKmsSigner")
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_gcp_kms_sign_message() {
        let signer = get_signer().await;

        let transaction = create_test_transaction(&signer.pubkey());
        let message = transaction.message.serialize();

        let signature = signer
            .sign_message(&message)
            .await
            .expect("Failed to sign message with GCP KMS");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(signature.verify(&signer.pubkey().to_bytes(), &message));
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_gcp_kms_sign_transaction() {
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
            .expect("Failed to sign transaction with GCP KMS")
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
    async fn test_gcp_kms_availability() {
        let signer = get_signer().await;

        let is_available = signer.is_available().await;
        assert!(is_available, "GCP KMS signer should be available");
    }
}
