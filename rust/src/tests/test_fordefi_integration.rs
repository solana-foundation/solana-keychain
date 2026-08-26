pub const FORDEFI_ACCESS_TOKEN: &str = "FORDEFI_ACCESS_TOKEN";
pub const FORDEFI_VAULT_ID: &str = "FORDEFI_VAULT_ID";
pub const FORDEFI_PRIVATE_KEY_PEM: &str = "FORDEFI_PRIVATE_KEY_PEM";
pub const FORDEFI_PUBLIC_KEY: &str = "FORDEFI_PUBLIC_KEY";
pub const FORDEFI_CHAIN: &str = "FORDEFI_CHAIN";
pub const FORDEFI_API_BASE_URL: &str = "FORDEFI_API_BASE_URL";
// Black box vault credentials — a black box vault signs raw bytes and is distinct
// from the Solana (native-mode) vault above. Mirrors the TypeScript integration tests.
pub const FORDEFI_BB_VAULT_ID: &str = "FORDEFI_BB_VAULT_ID";
pub const FORDEFI_BB_PUBLIC_KEY: &str = "FORDEFI_BB_PUBLIC_KEY";

#[cfg(feature = "fordefi")]
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use dotenvy::dotenv;

    use super::*;
    use crate::fordefi::{
        FordefiBlackBoxSigner, FordefiNativeAutoSigner, FordefiSignerConfig, SolanaChainUniqueId,
    };
    #[cfg(feature = "integration-tests")]
    use crate::sdk_adapter::{AccountMeta, Instruction, Message, VersionedTransaction};
    use crate::sdk_adapter::{Pubkey, Transaction};
    use crate::test_util::create_test_transaction;
    #[cfg(feature = "integration-tests")]
    use crate::tests::litesvm_util::{get_latest_blockhash, simulate_transaction, start_litesvm};
    #[cfg(feature = "integration-tests")]
    use crate::tests::rpc_util::{confirm_transaction, get_rpc_blockhash, send_raw_transaction};
    use crate::traits::{SendingSigner, SolanaSigner, TransactionSigner};
    use crate::transaction_util::deserialize_wire_transaction;
    use std::env;
    use std::str::FromStr;

    /// Build the config for the given vault, sharing the access token and
    /// request-signing key from the environment. `chain` selects black box mode
    /// (`None`) vs native Solana mode (`Some`).
    fn load_config(
        vault_id: String,
        public_key: String,
        chain: Option<SolanaChainUniqueId>,
    ) -> FordefiSignerConfig {
        let access_token = env::var(FORDEFI_ACCESS_TOKEN)
            .expect("FORDEFI_ACCESS_TOKEN must be set for integration tests");
        let private_key_pem = env::var(FORDEFI_PRIVATE_KEY_PEM)
            .expect("FORDEFI_PRIVATE_KEY_PEM must be set for integration tests");

        FordefiSignerConfig {
            access_token,
            vault_id,
            private_key_pem: Some(private_key_pem),
            request_signer: None,
            public_key,
            api_base_url: env::var(FORDEFI_API_BASE_URL).ok(),
            poll_interval_ms: None,
            max_poll_attempts: None,
            http_client_config: None,
            chain,
            fee: None,
        }
    }

    /// Black box signer — uses the dedicated black box vault (`FORDEFI_BB_*`),
    /// which is distinct from the Solana vault used by native mode.
    async fn get_signer() -> FordefiBlackBoxSigner {
        dotenv().ok();
        let vault_id = env::var(FORDEFI_BB_VAULT_ID)
            .expect("FORDEFI_BB_VAULT_ID must be set for integration tests");
        let public_key = env::var(FORDEFI_BB_PUBLIC_KEY)
            .expect("FORDEFI_BB_PUBLIC_KEY must be set for integration tests");
        FordefiBlackBoxSigner::from_config(load_config(vault_id, public_key, None))
            .await
            .expect("Failed to create Fordefi black box signer")
    }

    /// Native Solana signer — uses the Solana vault (`FORDEFI_VAULT_ID`) and the
    /// chain from `FORDEFI_CHAIN`.
    async fn get_native_signer() -> FordefiNativeAutoSigner {
        dotenv().ok();
        let vault_id =
            env::var(FORDEFI_VAULT_ID).expect("FORDEFI_VAULT_ID must be set for integration tests");
        let public_key = env::var(FORDEFI_PUBLIC_KEY)
            .expect("FORDEFI_PUBLIC_KEY must be set for integration tests");
        let chain = env::var(FORDEFI_CHAIN).ok().map(|c| match c.as_str() {
            "solana_devnet" => SolanaChainUniqueId::SolanaDevnet,
            "solana_mainnet" => SolanaChainUniqueId::SolanaMainnet,
            other => panic!("Invalid FORDEFI_CHAIN value: {other}"),
        });
        FordefiNativeAutoSigner::from_config(load_config(vault_id, public_key, chain))
            .await
            .expect("Failed to create Fordefi native signer")
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_fordefi_sign_message() {
        let signer = get_signer().await;

        let message = b"solana-keychain fordefi message signing test";
        let signature = signer
            .sign_message(message)
            .await
            .expect("Failed to sign message with Fordefi");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(
            signature.verify(&signer.pubkey().to_bytes(), message),
            "Signature should verify against the vault pubkey"
        );
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_fordefi_sign_transaction() {
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
            .expect("Failed to sign transaction with Fordefi")
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
    async fn test_fordefi_is_available() {
        let signer = get_signer().await;
        assert!(signer.is_available().await);
    }

    /// Transfer 0.1 SOL on devnet via Fordefi black box signing and broadcast.
    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_fordefi_devnet_transfer() {
        let signer = get_signer().await;
        let from = signer.pubkey();

        let rpc_url = env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());

        // Recipient: explicit env var, else self-transfer so the vault only pays fees
        let to = env::var("DEVNET_RECIPIENT")
            .ok()
            .and_then(|s| Pubkey::from_str(&s).ok())
            .unwrap_or(from);

        let lamports: u64 = 100_000_000; // 0.1 SOL

        // Build a system transfer instruction (program index 2, little-endian u64)
        let transfer_ix = Instruction {
            program_id: Pubkey::from_str("11111111111111111111111111111111").unwrap(),
            accounts: vec![AccountMeta::new(from, true), AccountMeta::new(to, false)],
            data: {
                let mut data = vec![2, 0, 0, 0];
                data.extend_from_slice(&lamports.to_le_bytes());
                data
            },
        };

        let blockhash = get_rpc_blockhash(&rpc_url)
            .await
            .expect("Failed to get devnet blockhash");

        let mut message = Message::new(&[transfer_ix], Some(&from));
        message.recent_blockhash = blockhash;
        let mut transaction: VersionedTransaction = Transaction::new_unsigned(message).into();

        let (base64_tx, signature) = signer
            .sign_transaction(&mut transaction)
            .await
            .expect("Failed to sign transaction with Fordefi")
            .into_signed_transaction();

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(
            signature.verify(&from.to_bytes(), &transaction.message.serialize()),
            "Signature should verify locally"
        );

        // Broadcast to devnet
        let tx_sig = send_raw_transaction(&rpc_url, &base64_tx)
            .await
            .expect("Failed to send transaction to devnet");

        println!("Devnet transaction sent: {tx_sig}");

        // Wait for confirmation (up to 60s)
        confirm_transaction(&rpc_url, &tx_sig, 60)
            .await
            .expect("Transaction was not confirmed on devnet");

        println!("Devnet transaction confirmed: {tx_sig}");
    }

    // --- Native Solana mode integration tests ---

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_fordefi_native_sign_message() {
        let signer = get_native_signer().await;

        let message = b"solana-keychain fordefi native message signing test";
        let signature = signer
            .sign_message(message)
            .await
            .expect("Failed to sign message with Fordefi native mode");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(
            signature.verify(&signer.pubkey().to_bytes(), message),
            "Signature should verify against the vault pubkey"
        );
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_fordefi_native_sign_and_send_transaction() {
        let signer = get_native_signer().await;
        let from = signer.pubkey();

        let rpc_url = env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());

        let to = env::var("DEVNET_RECIPIENT")
            .ok()
            .and_then(|s| Pubkey::from_str(&s).ok())
            .unwrap_or(from);

        let lamports: u64 = 100_000_000; // 0.1 SOL

        let transfer_ix = Instruction {
            program_id: Pubkey::from_str("11111111111111111111111111111111").unwrap(),
            accounts: vec![AccountMeta::new(from, true), AccountMeta::new(to, false)],
            data: {
                let mut data = vec![2, 0, 0, 0];
                data.extend_from_slice(&lamports.to_le_bytes());
                data
            },
        };

        let blockhash = get_rpc_blockhash(&rpc_url)
            .await
            .expect("Failed to get devnet blockhash");

        let mut message = Message::new(&[transfer_ix], Some(&from));
        message.recent_blockhash = blockhash;
        let transaction: VersionedTransaction = Transaction::new_unsigned(message).into();

        let signature = signer
            .sign_and_send_transaction(&transaction)
            .await
            .expect("Failed to sign and send transaction with Fordefi native mode");

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");

        // Fordefi already pushed the transaction; its signature is the Solana txid.
        // Confirm that on-chain rather than re-broadcasting.
        let tx_sig = signature.to_string();
        println!("Devnet native transaction pushed by Fordefi: {tx_sig}");

        confirm_transaction(&rpc_url, &tx_sig, 60)
            .await
            .expect("Native transaction was not confirmed on devnet");

        println!("Devnet native transaction confirmed: {tx_sig}");
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_fordefi_native_is_available() {
        let signer = get_native_signer().await;
        assert!(signer.is_available().await);
    }
}
