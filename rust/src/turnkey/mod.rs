//! Turnkey API signer integration

mod types;

use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::traits::SignTransactionResult;
pub use crate::traits::SignedTransaction;
use crate::transaction_util::{
    deserialize_wire_transaction, serialize_wire_transaction, TransactionUtil,
};
use crate::{error::SignerError, http_client_config::HttpClientConfig, traits::SolanaSigner};
use base64::Engine;
use p256::ecdsa::signature::Signer as P256Signer;
use std::str::FromStr;
use types::{
    ActivityResponse, SignParameters, SignRequest, SignTransactionParameters,
    SignTransactionRequest, WhoAmIRequest,
};

/// Turnkey-based signer using Turnkey's API
#[derive(Clone)]
pub struct TurnkeySigner {
    organization_id: String,
    private_key_id: String,
    api_public_key: String,
    api_private_key: String,
    public_key: Pubkey,
    api_base_url: String,
    client: reqwest::Client,
}

/// Configuration for creating a TurnkeySigner.
#[derive(Clone)]
pub struct TurnkeySignerConfig {
    pub api_public_key: String,
    pub api_private_key: String,
    pub organization_id: String,
    pub private_key_id: String,
    pub public_key: String,
    pub api_base_url: Option<String>,
    pub http_client_config: Option<HttpClientConfig>,
}

impl std::fmt::Debug for TurnkeySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnkeySigner")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl TurnkeySigner {
    /// Create a new TurnkeySigner
    ///
    /// # Arguments
    ///
    /// * `api_public_key` - Turnkey API public key
    /// * `api_private_key` - Turnkey API private key (hex-encoded)
    /// * `organization_id` - Turnkey organization ID
    /// * `private_key_id` - Turnkey private key ID
    /// * `public_key` - Solana public key (base58-encoded)
    pub fn new(
        api_public_key: String,
        api_private_key: String,
        organization_id: String,
        private_key_id: String,
        public_key: String,
    ) -> Result<Self, SignerError> {
        Self::from_config(TurnkeySignerConfig {
            api_public_key,
            api_private_key,
            organization_id,
            private_key_id,
            public_key,
            api_base_url: None,
            http_client_config: None,
        })
    }

    /// Create a new TurnkeySigner from a configuration object.
    pub fn from_config(config: TurnkeySignerConfig) -> Result<Self, SignerError> {
        let http_client_config = config.http_client_config.unwrap_or_default();
        let pubkey = Pubkey::from_str(&config.public_key)
            .map_err(|e| SignerError::InvalidPublicKey(format!("Invalid public key: {e}")))?;
        let client = http_client_config.build_client()?;

        Ok(Self {
            api_public_key: config.api_public_key,
            api_private_key: config.api_private_key,
            organization_id: config.organization_id,
            private_key_id: config.private_key_id,
            public_key: pubkey,
            api_base_url: config
                .api_base_url
                .unwrap_or_else(|| "https://api.turnkey.com".to_string()),
            client,
        })
    }

    /// POST a stamped activity request and return the parsed response.
    /// Turnkey populates `result` only under ACTIVITY_STATUS_COMPLETED;
    /// anything else (e.g. CONSENSUS_NEEDED) carries no signature.
    async fn post_activity(
        &self,
        path: &str,
        body: String,
    ) -> Result<ActivityResponse, SignerError> {
        let stamp = self.create_stamp(&body)?;

        let url = format!("{}{}", self.api_base_url, path);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Stamp", stamp)
            .body(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let _error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            #[cfg(feature = "unsafe-debug")]
            log::error!("Turnkey API error - status: {status}, response: {_error_text}");

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Turnkey API error - status: {status}");

            return Err(SignerError::RemoteApiError(format!("API error {status}")));
        }

        let response_text = response.text().await?;
        let response: ActivityResponse = serde_json::from_str(&response_text)?;

        let status = response.activity.status.as_deref().unwrap_or("<missing>");
        if status != "ACTIVITY_STATUS_COMPLETED" {
            return Err(SignerError::SigningFailed(format!(
                "Turnkey activity is not completed (status: {status})"
            )));
        }

        Ok(response)
    }

    /// Sign message bytes using Turnkey API and return just the signature
    async fn sign_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let hex_message = hex::encode(message);

        let request = SignRequest {
            activity_type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2".to_string(),
            timestamp_ms: chrono::Utc::now().timestamp_millis().to_string(),
            organization_id: self.organization_id.clone(),
            parameters: SignParameters {
                sign_with: self.private_key_id.clone(),
                payload: hex_message,
                encoding: "PAYLOAD_ENCODING_HEXADECIMAL".to_string(),
                hash_function: "HASH_FUNCTION_NOT_APPLICABLE".to_string(),
            },
        };
        let body = serde_json::to_string(&request)?;
        let response = self
            .post_activity("/public/v1/submit/sign_raw_payload", body)
            .await?;

        if let Some(result) = response.activity.result {
            if let Some(sign_result) = result.sign_raw_payload_result {
                // Decode r and s components
                let r_bytes = hex::decode(&sign_result.r).map_err(|e| {
                    SignerError::SerializationError(format!("Failed to decode r: {e}"))
                })?;
                let s_bytes = hex::decode(&sign_result.s).map_err(|e| {
                    SignerError::SerializationError(format!("Failed to decode s: {e}"))
                })?;

                // Ensure each component is exactly 32 bytes
                if r_bytes.len() > 32 || s_bytes.len() > 32 {
                    return Err(SignerError::SigningFailed(
                        "Invalid signature component length".to_string(),
                    ));
                }

                // Create properly padded 32-byte arrays
                let mut final_r = [0u8; 32];
                let mut final_s = [0u8; 32];

                // Copy bytes with proper padding (right-aligned)
                final_r[32 - r_bytes.len()..].copy_from_slice(&r_bytes);
                final_s[32 - s_bytes.len()..].copy_from_slice(&s_bytes);

                // Combine r and s into final 64-byte signature
                let mut signature = Vec::with_capacity(64);
                signature.extend_from_slice(&final_r);
                signature.extend_from_slice(&final_s);

                let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| {
                    SignerError::SigningFailed("Invalid signature length".to_string())
                })?;

                let sig = Signature::from(sig_bytes);

                if !sig.verify(&self.public_key.to_bytes(), message) {
                    return Err(SignerError::SigningFailed(
                        "Signature verification failed — the returned signature does not match the public key".to_string(),
                    ));
                }

                return Ok(sig);
            }
        }

        Err(SignerError::SigningFailed(
            "Invalid response from Turnkey API".to_string(),
        ))
    }

    /// Sign via the `sign_transaction` activity, submitting the full wire
    /// transaction so Turnkey's policy engine can evaluate `solana.tx`
    /// conditions. Policies must allow `ACTIVITY_TYPE_SIGN_TRANSACTION_V2`.
    async fn sign_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        let unsigned_wire = serialize_wire_transaction(transaction)?;

        let request = SignTransactionRequest {
            activity_type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2".to_string(),
            timestamp_ms: chrono::Utc::now().timestamp_millis().to_string(),
            organization_id: self.organization_id.clone(),
            parameters: SignTransactionParameters {
                sign_with: self.private_key_id.clone(),
                transaction_type: "TRANSACTION_TYPE_SOLANA".to_string(),
                unsigned_transaction: hex::encode(&unsigned_wire),
            },
        };
        let body = serde_json::to_string(&request)?;
        let response = self
            .post_activity("/public/v1/submit/sign_transaction", body)
            .await?;

        let signed_hex = response
            .activity
            .result
            .and_then(|result| result.sign_transaction_result)
            .map(|result| result.signed_transaction)
            .ok_or_else(|| {
                SignerError::SigningFailed("Invalid response from Turnkey API".to_string())
            })?;

        let signed_wire = hex::decode(&signed_hex).map_err(|e| {
            SignerError::SerializationError(format!(
                "Failed to decode signed transaction returned by Turnkey: {e}"
            ))
        })?;
        let returned: VersionedTransaction =
            deserialize_wire_transaction(&signed_wire).map_err(|e| {
                SignerError::SerializationError(format!(
                    "Failed to deserialize signed transaction returned by Turnkey: {e}"
                ))
            })?;

        let position = TransactionUtil::get_signing_keypair_position(&returned, &self.public_key)?;
        let signature = returned.signatures.get(position).copied().ok_or_else(|| {
            SignerError::SigningFailed(
                "Turnkey signature slot missing from returned transaction".to_string(),
            )
        })?;

        if !signature.verify(
            &self.public_key.to_bytes(),
            &transaction.message.serialize(),
        ) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed — the returned signature does not match the public key".to_string(),
            ));
        }

        TransactionUtil::add_signature_to_transaction(transaction, &self.public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    /// Create X-Stamp header for Turnkey API authentication
    fn create_stamp(&self, message: &str) -> Result<String, SignerError> {
        let private_key_bytes = hex::decode(&self.api_private_key).map_err(|e| {
            SignerError::InvalidPrivateKey(format!("Failed to decode private key: {e}"))
        })?;

        let private_key_array: [u8; 32] = private_key_bytes.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey("Invalid private key length".to_string())
        })?;

        let signing_key = p256::ecdsa::SigningKey::from_slice(&private_key_array)
            .map_err(|e| SignerError::InvalidPrivateKey(format!("Invalid signing key: {e}")))?;

        let signature: p256::ecdsa::Signature = signing_key.sign(message.as_bytes());
        let signature_der = signature.to_der().to_bytes();
        let signature_hex = hex::encode(signature_der);

        let stamp = serde_json::json!({
            "public_key": self.api_public_key,
            "signature": signature_hex,
            "scheme": "SIGNATURE_SCHEME_TK_API_P256"
        });

        let json_stamp = serde_json::to_string(&stamp)?;

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json_stamp.as_bytes()))
    }

    /// Check if Turnkey API is available and credentials are valid
    async fn check_availability(&self) -> bool {
        let request = WhoAmIRequest {
            organization_id: self.organization_id.clone(),
        };

        let body = match serde_json::to_string(&request) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let stamp = match self.create_stamp(&body) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let url = format!("{}/public/v1/query/whoami", self.api_base_url);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Stamp", stamp)
            .body(body)
            .send()
            .await;

        match response {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl SolanaSigner for TurnkeySigner {
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
        // Verify Turnkey API is reachable and credentials are valid
        self.check_availability().await
    }
}

#[cfg(test)]
mod tests;
