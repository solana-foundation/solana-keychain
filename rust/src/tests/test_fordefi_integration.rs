pub const FORDEFI_ACCESS_TOKEN: &str = "FORDEFI_ACCESS_TOKEN";
pub const FORDEFI_VAULT_ID: &str = "FORDEFI_VAULT_ID";
pub const FORDEFI_PRIVATE_KEY_PEM_PATH: &str = "FORDEFI_PRIVATE_KEY_PEM_PATH";
pub const FORDEFI_PUBLIC_KEY: &str = "FORDEFI_PUBLIC_KEY";
pub const FORDEFI_CHAIN: &str = "FORDEFI_CHAIN";
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
    use crate::fordefi::{FordefiSigner, FordefiSignerConfig, SolanaChainUniqueId};
    use crate::test_util::create_test_transaction;
    #[cfg(feature = "integration-tests")]
    use crate::tests::litesvm_util::{get_latest_blockhash, simulate_transaction, start_litesvm};
    use crate::traits::SolanaSigner;
    use std::env;
    use std::path::{Path, PathBuf};

    fn resolve_pem_path(raw: &str) -> PathBuf {
        let p = Path::new(raw);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("CARGO_MANIFEST_DIR has no parent")
                .join(p)
        }
    }

    /// Build a `FordefiSigner` for the given vault, sharing the access token and
    /// request-signing key from the environment. `chain` selects black box mode
    /// (`None`) vs native Solana mode (`Some`).
    async fn load_signer(
        vault_id: String,
        public_key: String,
        chain: Option<SolanaChainUniqueId>,
    ) -> FordefiSigner {
        let access_token = env::var(FORDEFI_ACCESS_TOKEN)
            .expect("FORDEFI_ACCESS_TOKEN must be set for integration tests");
        let pem_path = env::var(FORDEFI_PRIVATE_KEY_PEM_PATH)
            .expect("FORDEFI_PRIVATE_KEY_PEM_PATH must be set for integration tests");
        let private_key_pem =
            std::fs::read_to_string(resolve_pem_path(&pem_path)).expect("Failed to read PEM file");

        FordefiSigner::from_config(FordefiSignerConfig {
            access_token,
            vault_id,
            private_key_pem,
            public_key,
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
            http_client_config: None,
            chain,
            fee: None,
        })
        .await
        .expect("Failed to create Fordefi signer")
    }

    /// Black box signer — uses the dedicated black box vault (`FORDEFI_BB_*`),
    /// which is distinct from the Solana vault used by native mode.
    async fn get_signer() -> FordefiSigner {
        dotenv().ok();
        let vault_id = env::var(FORDEFI_BB_VAULT_ID)
            .expect("FORDEFI_BB_VAULT_ID must be set for integration tests");
        let public_key = env::var(FORDEFI_BB_PUBLIC_KEY)
            .expect("FORDEFI_BB_PUBLIC_KEY must be set for integration tests");
        load_signer(vault_id, public_key, None).await
    }

    /// Native Solana signer — uses the Solana vault (`FORDEFI_VAULT_ID`) and the
    /// chain from `FORDEFI_CHAIN`.
    async fn get_native_signer() -> FordefiSigner {
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
        load_signer(vault_id, public_key, chain).await
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
        transaction.message.recent_blockhash = get_latest_blockhash(&lite_svm)
            .await
            .expect("Failed to get latest blockhash");

        let original_message = transaction.message_data();

        let (base64_txn, signature) = signer
            .sign_transaction(&mut transaction)
            .await
            .expect("Failed to sign transaction with Fordefi")
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
    async fn test_fordefi_is_available() {
        let signer = get_signer().await;
        assert!(signer.is_available().await);
    }

    /// Transfer 0.1 SOL on devnet via Fordefi black box signing and broadcast.
    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_fordefi_devnet_transfer() {
        use crate::sdk_adapter::{AccountMeta, Instruction, Message, Pubkey, Transaction};
        use crate::tests::rpc_util::{
            confirm_transaction, get_rpc_blockhash, send_raw_transaction,
        };
        use std::str::FromStr;

        let signer = get_signer().await;
        let from = signer.pubkey();

        let rpc_url = env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());

        // Recipient: use env var or a throwaway address
        let to = env::var("DEVNET_RECIPIENT")
            .ok()
            .and_then(|s| Pubkey::from_str(&s).ok())
            .unwrap_or_else(Pubkey::new_unique);

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

        let message = Message::new(&[transfer_ix], Some(&from));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.message.recent_blockhash = blockhash;

        let (base64_tx, signature) = signer
            .sign_transaction(&mut transaction)
            .await
            .expect("Failed to sign transaction with Fordefi")
            .into_signed_transaction();

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        assert!(
            signature.verify(&from.to_bytes(), &transaction.message_data()),
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
    async fn test_fordefi_native_sign_transaction() {
        use crate::sdk_adapter::{AccountMeta, Instruction, Message, Pubkey, Transaction};
        use crate::tests::rpc_util::{confirm_transaction, get_rpc_blockhash};
        use std::str::FromStr;

        let signer = get_native_signer().await;
        let from = signer.pubkey();

        let rpc_url = env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());

        let to = env::var("DEVNET_RECIPIENT")
            .ok()
            .and_then(|s| Pubkey::from_str(&s).ok())
            .unwrap_or_else(Pubkey::new_unique);

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

        let message = Message::new(&[transfer_ix], Some(&from));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.message.recent_blockhash = blockhash;

        let (serialized_tx, signature) = signer
            .sign_transaction(&mut transaction)
            .await
            .expect("Failed to sign transaction with Fordefi native mode")
            .into_signed_transaction();

        assert_eq!(signature.as_ref().len(), 64, "Signature should be 64 bytes");
        // Native mode auto-broadcasts via Fordefi, so no re-sendable wire tx is returned.
        assert!(
            serialized_tx.is_empty(),
            "native mode should return an empty serialized transaction"
        );

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
