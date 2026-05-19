// CDP integration tests require real CDP credentials and a Solana account.
// To run these tests:
// 1. Create a CDP API key at https://portal.cdp.coinbase.com
// 2. Create a Solana account via the CDP API
// 3. Set environment variables in .env or shell:
//    - CDP_API_KEY_ID: CDP API key name / ID
//    - CDP_API_KEY_SECRET: CDP private key (base64 Ed25519)
//    - CDP_WALLET_SECRET: CDP wallet secret (base64 PKCS#8 DER)
//    - CDP_SOLANA_ADDRESS: Solana account address managed by CDP

pub const CDP_API_KEY_ID: &str = "CDP_API_KEY_ID";
pub const CDP_API_KEY_SECRET: &str = "CDP_API_KEY_SECRET";
pub const CDP_WALLET_SECRET: &str = "CDP_WALLET_SECRET";
pub const CDP_SOLANA_ADDRESS: &str = "CDP_SOLANA_ADDRESS";

#[cfg(feature = "cdp")]
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use dotenvy::dotenv;
    use std::env;

    use super::*;
    use crate::cdp::CdpSigner;
    use crate::test_util::create_test_transaction;
    use crate::traits::SolanaSigner;

    async fn get_signer() -> CdpSigner {
        dotenv().ok();

        let api_key_id =
            env::var(CDP_API_KEY_ID).expect("CDP_API_KEY_ID must be set for integration tests");
        let api_key_secret = env::var(CDP_API_KEY_SECRET)
            .expect("CDP_API_KEY_SECRET must be set for integration tests");
        let wallet_secret = env::var(CDP_WALLET_SECRET)
            .expect("CDP_WALLET_SECRET must be set for integration tests");
        let address = env::var(CDP_SOLANA_ADDRESS)
            .expect("CDP_SOLANA_ADDRESS must be set for integration tests");

        CdpSigner::new(api_key_id, api_key_secret, wallet_secret, address)
            .expect("Failed to create CdpSigner")
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_cdp_sign_message() {
        let signer = get_signer().await;

        let message = b"CDP keychain test";

        let signature = signer
            .sign_message(message)
            .await
            .expect("Failed to sign message with CDP");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_cdp_sign_transaction() {
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
            .expect("Failed to sign transaction with CDP")
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
    async fn test_cdp_availability() {
        let signer = get_signer().await;

        let is_available = signer.is_available().await;
        assert!(is_available, "CDP signer should be available");
    }
}
