// TODO: KMS integration tests require real AWS credentials and an Ed25519 KMS key.
// No lightweight local mock supports Ed25519 yet (AWS added ECC_NIST_EDWARDS25519 in Nov 2025).
// To run these tests:
// 1. Create an Ed25519 KMS key in AWS Console (KeySpec: ECC_NIST_EDWARDS25519)
// 2. Set environment variables in .env or shell:
//    - AWS_KMS_KEY_ID: KMS key ARN or alias
//    - AWS_KMS_SIGNER_PUBKEY: Base58-encoded public key
//    - AWS_KMS_REGION: AWS region (optional)
//    - AWS credentials via standard AWS env vars or profile

pub const AWS_KMS_KEY_ID: &str = "AWS_KMS_KEY_ID";
pub const AWS_KMS_SIGNER_PUBKEY: &str = "AWS_KMS_SIGNER_PUBKEY";
pub const AWS_KMS_REGION: &str = "AWS_KMS_REGION";

#[cfg(feature = "aws_kms")]
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use dotenvy::dotenv;

    use super::*;
    use crate::aws_kms::KmsSigner;
    use crate::test_util::create_test_transaction;
    use crate::traits::SolanaSigner;
    use std::env;

    async fn get_signer() -> KmsSigner {
        dotenv().ok();

        let key_id =
            env::var(AWS_KMS_KEY_ID).expect("AWS_KMS_KEY_ID must be set for integration tests");
        let signer_pubkey = env::var(AWS_KMS_SIGNER_PUBKEY)
            .expect("AWS_KMS_SIGNER_PUBKEY must be set for integration tests");
        let region = env::var(AWS_KMS_REGION).ok();

        KmsSigner::new(key_id, signer_pubkey, region)
            .await
            .expect("Failed to create KmsSigner")
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_kms_sign_message() {
        let signer = get_signer().await;

        let transaction = create_test_transaction(&signer.pubkey());
        let message = transaction.message_data();

        let signature = signer
            .sign_message(&message)
            .await
            .expect("Failed to sign message with KMS");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(signature.verify(&signer.pubkey().to_bytes(), &message));
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_kms_sign_transaction() {
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
            .expect("Failed to sign transaction with KMS");

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
    async fn test_kms_availability() {
        let signer = get_signer().await;

        let is_available = signer.is_available().await;
        assert!(is_available, "KMS signer should be available");
    }
}
