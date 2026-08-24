mod auth;
mod types;

use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::traits::SignTransactionResult;
pub use crate::traits::SignedTransaction;
use crate::transaction_util::{serialize_wire_transaction, TransactionUtil};
use crate::{
    error::SignerError, http_client_config::HttpClientConfig,
    signature_util::EXPECTED_SIGNATURE_LENGTH, traits::SolanaSigner,
};
use types::{GenerateSignatureRequest, GenerateSignatureResponse, GetWalletResponse};

/// Dfns-based signer using Dfns Keys API
#[derive(Clone)]
pub struct DfnsSigner {
    auth_token: String,
    cred_id: String,
    private_key_pem: String,
    wallet_id: String,
    key_id: String,
    public_key: Pubkey,
    api_base_url: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for DfnsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DfnsSigner")
            .field("public_key", &self.public_key)
            .field("wallet_id", &self.wallet_id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Configuration for creating a DfnsSigner
#[derive(Clone)]
pub struct DfnsSignerConfig {
    /// Service account token or personal access token
    pub auth_token: String,
    /// Credential ID for user action signing
    pub cred_id: String,
    /// Private key in PEM format for signing user action challenges (Ed25519, P256, or RSA)
    pub private_key_pem: String,
    /// Dfns wallet ID
    pub wallet_id: String,
    /// API base URL (default: "https://api.dfns.io")
    pub api_base_url: Option<String>,
    /// Optional HTTP client timeout config.
    pub http_client_config: Option<HttpClientConfig>,
}

impl DfnsSigner {
    /// Create a new DfnsSigner.
    ///
    /// You must call `init()` after construction to fetch the public key from Dfns.
    pub fn new(config: DfnsSignerConfig) -> Self {
        Self::from_config(config)
    }

    /// Create a new DfnsSigner from a configuration object.
    pub fn from_config(config: DfnsSignerConfig) -> Self {
        let http_client_config = config.http_client_config.unwrap_or_default();
        let client = http_client_config
            .client_builder()
            .user_agent("solana-keychain")
            .build()
            .expect("Failed to build HTTP client");

        Self {
            auth_token: config.auth_token,
            cred_id: config.cred_id,
            private_key_pem: config.private_key_pem,
            wallet_id: config.wallet_id,
            key_id: String::new(),
            public_key: Pubkey::default(),
            api_base_url: config
                .api_base_url
                .unwrap_or_else(|| "https://api.dfns.io".to_string()),
            client,
        }
    }

    /// Initialize the signer by fetching the wallet and extracting key details from Dfns
    pub async fn init(&mut self) -> Result<(), SignerError> {
        let wallet = self.get_wallet().await?;

        if wallet.status != "Active" {
            return Err(SignerError::ConfigError(format!(
                "Wallet is not active: {}",
                wallet.status
            )));
        }

        if wallet.signing_key.scheme != "EdDSA" {
            return Err(SignerError::ConfigError(format!(
                "Unsupported key scheme: {} (expected EdDSA)",
                wallet.signing_key.scheme
            )));
        }

        if wallet.signing_key.curve != "ed25519" {
            return Err(SignerError::ConfigError(format!(
                "Unsupported key curve: {} (expected ed25519)",
                wallet.signing_key.curve
            )));
        }

        let pubkey_bytes = hex::decode(&wallet.signing_key.public_key).map_err(|e| {
            SignerError::InvalidPublicKey(format!("Failed to decode hex public key: {e}"))
        })?;

        self.public_key = Pubkey::try_from(pubkey_bytes.as_slice()).map_err(|_| {
            SignerError::InvalidPublicKey(
                "Invalid public key length (expected 32 bytes)".to_string(),
            )
        })?;

        self.key_id = wallet.signing_key.id;

        Ok(())
    }

    /// Fetch wallet details from Dfns
    async fn get_wallet(&self) -> Result<GetWalletResponse, SignerError> {
        let url = format!("{}/wallets/{}", self.api_base_url, self.wallet_id);
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();

            #[cfg(feature = "unsafe-debug")]
            {
                let _error_text = response.text().await.unwrap_or_default();
                log::error!("Dfns get_wallet error - status: {status}, response: {_error_text}");
            }

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Dfns get_wallet error - status: {status}");

            return Err(SignerError::RemoteApiError(format!("API error {status}")));
        }

        response.json().await.map_err(|e| {
            SignerError::SerializationError(format!("Failed to parse wallet response: {e}"))
        })
    }

    /// Send a signature request to the Dfns Keys API
    async fn send_signature_request(
        &self,
        request_body: GenerateSignatureRequest,
    ) -> Result<Signature, SignerError> {
        let http_path = format!("/keys/{}/signatures", self.key_id);
        let body_json = serde_json::to_string(&request_body)?;

        let user_action = auth::sign_user_action(
            &self.client,
            &self.api_base_url,
            &self.auth_token,
            &self.cred_id,
            &self.private_key_pem,
            "POST",
            &http_path,
            &body_json,
        )
        .await?;

        let url = format!("{}{}", self.api_base_url, http_path);
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .header("Content-Type", "application/json")
            .header("x-dfns-useraction", &user_action)
            .body(body_json)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();

            #[cfg(feature = "unsafe-debug")]
            {
                let _error_text = response.text().await.unwrap_or_default();
                log::error!(
                    "Dfns generate_signature error - status: {status}, response: {_error_text}"
                );
            }

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Dfns generate_signature error - status: {status}");

            return Err(SignerError::RemoteApiError(format!("API error {status}")));
        }

        let sig_response: GenerateSignatureResponse = response.json().await.map_err(|e| {
            SignerError::SerializationError(format!("Failed to parse signature response: {e}"))
        })?;

        if sig_response.status == "Failed" {
            return Err(SignerError::SigningFailed(
                "Dfns signing failed".to_string(),
            ));
        }

        if sig_response.status != "Signed" {
            return Err(SignerError::SigningFailed(format!(
                "Unexpected signature status: {} (may require policy approval)",
                sig_response.status
            )));
        }

        let components = sig_response.signature.ok_or_else(|| {
            SignerError::SigningFailed("Signature components missing from response".to_string())
        })?;

        self.combine_signature(&components.r, &components.s)
    }

    async fn sign_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let request = GenerateSignatureRequest::Message {
            message: format!("0x{}", hex::encode(message)),
        };
        let sig = self.send_signature_request(request).await?;

        if !sig.verify(&self.public_key.to_bytes(), message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed — the returned signature does not match the public key".to_string(),
            ));
        }

        Ok(sig)
    }

    async fn sign_transaction_bytes(
        &self,
        transaction: &VersionedTransaction,
    ) -> Result<Signature, SignerError> {
        let tx_bytes = serialize_wire_transaction(transaction)?;
        let request = GenerateSignatureRequest::Transaction {
            transaction: format!("0x{}", hex::encode(&tx_bytes)),
            blockchain_kind: "Solana".to_string(),
        };
        let sig = self.send_signature_request(request).await?;

        if !sig.verify(
            &self.public_key.to_bytes(),
            &transaction.message.serialize(),
        ) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed — the returned signature does not match the public key".to_string(),
            ));
        }

        Ok(sig)
    }

    fn combine_signature(&self, r: &str, s: &str) -> Result<Signature, SignerError> {
        let r_bytes = hex::decode(r.strip_prefix("0x").unwrap_or(r)).map_err(|e| {
            SignerError::SerializationError(format!("Failed to decode signature r: {e}"))
        })?;
        let s_bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| {
            SignerError::SerializationError(format!("Failed to decode signature s: {e}"))
        })?;

        let mut sig_bytes = Vec::with_capacity(EXPECTED_SIGNATURE_LENGTH);
        sig_bytes.extend_from_slice(&r_bytes);
        sig_bytes.extend_from_slice(&s_bytes);

        let sig_array: [u8; EXPECTED_SIGNATURE_LENGTH] = sig_bytes.try_into().map_err(|_| {
            SignerError::SigningFailed(format!(
                "Invalid signature length (expected {} bytes)",
                EXPECTED_SIGNATURE_LENGTH
            ))
        })?;

        Ok(Signature::from(sig_array))
    }

    /// Sign and serialize a transaction
    async fn sign_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        let signature = self.sign_transaction_bytes(transaction).await?;

        TransactionUtil::add_signature_to_transaction(transaction, &self.public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    /// Check if the Dfns wallet is available and healthy: reachable, active,
    /// and backed by an EdDSA/ed25519 signing key
    async fn check_availability(&self) -> bool {
        match self.get_wallet().await {
            Ok(wallet) => {
                wallet.status == "Active"
                    && wallet.signing_key.scheme == "EdDSA"
                    && wallet.signing_key.curve == "ed25519"
            }
            Err(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl SolanaSigner for DfnsSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key
    }

    async fn sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError> {
        let signed_transaction = self.sign_and_serialize(tx).await?;
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            signed_transaction,
        ))
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.sign_bytes(message).await
    }

    async fn is_available(&self) -> bool {
        self.check_availability().await
    }
}

#[cfg(test)]
mod tests;
