//! Fireblocks API signer integration

mod jwt;
mod types;

use crate::sdk_adapter::{Pubkey, Signature, Transaction};
pub use crate::traits::SignedTransaction;
use crate::{error::SignerError, traits::SolanaSigner, transaction_util::TransactionUtil};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::str::FromStr;
use types::{
    CreateTransactionRequest, CreateTransactionResponse, ExtraParameters,
    ProgramCallExtraParameters, RawExtraParameters, RawMessage, RawMessageData,
    TransactionResponse, TransactionSource, VaultAddressesResponse,
};

/// Fireblocks-based signer using Fireblocks' API
#[derive(Clone)]
pub struct FireblocksSigner {
    api_key: String,
    private_key_pem: String,
    vault_account_id: String,
    asset_id: String,
    public_key: Pubkey,
    api_base_url: String,
    client: reqwest::Client,
    poll_interval_ms: u64,
    max_poll_attempts: u32,
    use_program_call: bool,
}

impl std::fmt::Debug for FireblocksSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FireblocksSigner")
            .field("public_key", &self.public_key)
            .field("vault_account_id", &self.vault_account_id)
            .field("asset_id", &self.asset_id)
            .field("use_program_call", &self.use_program_call)
            .finish_non_exhaustive()
    }
}

/// Configuration for creating a FireblocksSigner
#[derive(Clone)]
pub struct FireblocksSignerConfig {
    pub api_key: String,
    pub private_key_pem: String,
    pub vault_account_id: String,
    /// Asset ID (default: "SOL", use "SOL_TEST" for devnet)
    pub asset_id: Option<String>,
    pub api_base_url: Option<String>,
    pub poll_interval_ms: Option<u64>,
    pub max_poll_attempts: Option<u32>,
    /// Use PROGRAM_CALL operation for transaction signing (auto-broadcasts to Solana).
    /// Default: false (uses RAW signing)
    pub use_program_call: Option<bool>,
}

impl FireblocksSigner {
    /// Create a new FireblocksSigner
    ///
    /// Note: You must call `init()` after construction to fetch the public key.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the signer
    pub fn new(config: FireblocksSignerConfig) -> Self {
        Self {
            api_key: config.api_key,
            private_key_pem: config.private_key_pem,
            vault_account_id: config.vault_account_id,
            asset_id: config.asset_id.unwrap_or_else(|| "SOL".to_string()),
            public_key: Pubkey::default(),
            api_base_url: config
                .api_base_url
                .unwrap_or_else(|| "https://api.fireblocks.io".to_string()),
            client: reqwest::Client::new(),
            poll_interval_ms: config.poll_interval_ms.unwrap_or(1000),
            max_poll_attempts: config.max_poll_attempts.unwrap_or(300),
            use_program_call: config.use_program_call.unwrap_or(false),
        }
    }

    /// Initialize the signer by fetching the public key from Fireblocks
    pub async fn init(&mut self) -> Result<(), SignerError> {
        let pubkey = self.fetch_public_key().await?;
        self.public_key = pubkey;
        Ok(())
    }

    /// Fetch the public key from Fireblocks vault account addresses
    async fn fetch_public_key(&self) -> Result<Pubkey, SignerError> {
        let uri = format!(
            "/v1/vault/accounts/{}/{}/addresses_paginated",
            self.vault_account_id, self.asset_id
        );
        let token = jwt::create_jwt(&self.api_key, &self.private_key_pem, &uri, "")?;

        let url = format!("{}{}", self.api_base_url, uri);
        let response = self
            .client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let _error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            #[cfg(feature = "unsafe-debug")]
            log::error!(
                "Fireblocks API fetch_public_key error - status: {status}, response: {_error_text}"
            );

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Fireblocks API fetch_public_key error - status: {status}");

            return Err(SignerError::RemoteApiError(format!("API error {status}")));
        }

        let response_text = response.text().await?;

        let addresses_response: VaultAddressesResponse = serde_json::from_str(&response_text)
            .map_err(|_e| {
                #[cfg(feature = "unsafe-debug")]
                log::error!("Failed to parse Fireblocks response: {_e}");

                #[cfg(not(feature = "unsafe-debug"))]
                log::error!("Failed to parse Fireblocks response");

                SignerError::SerializationError("Failed to parse Fireblocks response".to_string())
            })?;

        let address = addresses_response.addresses.first().ok_or_else(|| {
            SignerError::InvalidPublicKey("Invalid public key from Fireblocks".to_string())
        })?;

        Pubkey::from_str(&address.address).map_err(|_| {
            SignerError::InvalidPublicKey("Invalid public key from Fireblocks".to_string())
        })
    }

    /// Sign raw bytes using RAW operation
    async fn sign_raw_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let hex_message = hex::encode(message);

        let request = CreateTransactionRequest {
            asset_id: self.asset_id.clone(),
            operation: "RAW".to_string(),
            source: TransactionSource {
                source_type: "VAULT_ACCOUNT".to_string(),
                id: self.vault_account_id.clone(),
            },
            extra_parameters: Some(ExtraParameters::Raw(RawExtraParameters {
                raw_message_data: RawMessageData {
                    messages: vec![RawMessage {
                        content: hex_message,
                    }],
                },
            })),
        };

        self.request_and_poll_signature(request).await
    }

    /// Sign a transaction using PROGRAM_CALL operation
    async fn sign_with_program_call(
        &self,
        transaction: &Transaction,
    ) -> Result<Signature, SignerError> {
        let serialized = bincode::serialize(transaction).map_err(|e| {
            SignerError::SerializationError(format!("Failed to serialize transaction: {e}"))
        })?;
        let base64_content = STANDARD.encode(&serialized);

        let request = CreateTransactionRequest {
            asset_id: self.asset_id.clone(),
            operation: "PROGRAM_CALL".to_string(),
            source: TransactionSource {
                source_type: "VAULT_ACCOUNT".to_string(),
                id: self.vault_account_id.clone(),
            },
            extra_parameters: Some(ExtraParameters::ProgramCall(ProgramCallExtraParameters {
                program_call_data: base64_content,
            })),
        };

        self.request_and_poll_signature(request).await
    }

    /// Request a signature from Fireblocks and poll until complete
    async fn request_and_poll_signature(
        &self,
        request: CreateTransactionRequest,
    ) -> Result<Signature, SignerError> {
        let create_response = self.create_transaction(request).await?;
        let tx_response = self.poll_for_signature(&create_response.id).await?;

        self.extract_signature(&tx_response)
    }

    /// Create a transaction (signing request) in Fireblocks
    async fn create_transaction(
        &self,
        request: CreateTransactionRequest,
    ) -> Result<CreateTransactionResponse, SignerError> {
        let uri = "/v1/transactions";
        let body = serde_json::to_string(&request)?;
        let token = jwt::create_jwt(&self.api_key, &self.private_key_pem, uri, &body)?;

        let url = format!("{}{}", self.api_base_url, uri);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-API-Key", &self.api_key)
            .header("Authorization", format!("Bearer {}", token))
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
            log::error!(
                "Fireblocks API create_transaction error - status: {status}, response: {_error_text}"
            );

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Fireblocks API create_transaction error - status: {status}");

            return Err(SignerError::RemoteApiError(format!("API error {status}")));
        }

        let response_text = response.text().await?;

        serde_json::from_str(&response_text).map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Failed to parse create_transaction response: {_e}, body: {response_text}");

            SignerError::SerializationError("Failed to parse response".to_string())
        })
    }

    /// Poll for transaction completion
    async fn poll_for_signature(&self, tx_id: &str) -> Result<TransactionResponse, SignerError> {
        for _attempt in 0..self.max_poll_attempts {
            let response = self.get_transaction(tx_id).await?;

            match response.status.as_str() {
                "COMPLETED" => return Ok(response),
                "FAILED" | "CANCELLED" | "REJECTED" | "BLOCKED" => {
                    #[cfg(feature = "unsafe-debug")]
                    log::error!("Transaction failed: {:?}", response);

                    return Err(SignerError::SigningFailed(format!(
                        "Transaction {}: {}",
                        response.status, tx_id
                    )));
                }
                _ => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(self.poll_interval_ms))
                        .await;
                }
            }
        }

        Err(SignerError::RemoteApiError(format!(
            "Transaction polling timeout after {} attempts - signing request may still complete",
            self.max_poll_attempts
        )))
    }

    /// Get transaction status
    async fn get_transaction(&self, tx_id: &str) -> Result<TransactionResponse, SignerError> {
        let uri = format!("/v1/transactions/{}", tx_id);
        let token = jwt::create_jwt(&self.api_key, &self.private_key_pem, &uri, "")?;

        let url = format!("{}{}", self.api_base_url, uri);
        let response = self
            .client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let _error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            #[cfg(feature = "unsafe-debug")]
            log::error!(
                "Fireblocks API get_transaction error - status: {status}, response: {_error_text}"
            );

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Fireblocks API get_transaction error - status: {status}");

            return Err(SignerError::RemoteApiError(format!(
                "Fireblocks API error {status}"
            )));
        }

        let response_text = response.text().await?;

        serde_json::from_str(&response_text).map_err(|e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!(
                "Failed to parse get_transaction response: {}, body: {}",
                e,
                response_text
            );
            SignerError::SerializationError(format!("Failed to parse response: {e}"))
        })
    }

    /// Extract signature from transaction response
    /// - RAW operations: signature in signed_messages[0].signature.full_sig (hex encoded)
    /// - PROGRAM_CALL: signature in tx_hash (base58 encoded, already broadcast)
    fn extract_signature(&self, response: &TransactionResponse) -> Result<Signature, SignerError> {
        // Try signed_messages first (RAW operations)
        if let Some(signed_message) = response.signed_messages.first() {
            let sig_hex = &signed_message.signature.full_sig;
            let sig_bytes = hex::decode(sig_hex).map_err(|_e| {
                #[cfg(feature = "unsafe-debug")]
                log::error!("Failed to decode hex signature: {_e}");

                #[cfg(not(feature = "unsafe-debug"))]
                log::error!("Failed to decode hex signature");

                SignerError::SerializationError("Failed to decode hex signature".to_string())
            })?;

            let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
                SignerError::SigningFailed(
                    "Invalid signature length (expected 64 bytes)".to_string(),
                )
            })?;

            return Ok(Signature::from(sig_array));
        }

        // Try tx_hash (PROGRAM_CALL - base58 encoded signature, already broadcast)
        if let Some(tx_hash) = &response.tx_hash {
            let sig_bytes = bs58::decode(tx_hash).into_vec().map_err(|_e| {
                #[cfg(feature = "unsafe-debug")]
                log::error!("Failed to decode base58 tx_hash: {_e}");

                #[cfg(not(feature = "unsafe-debug"))]
                log::error!("Failed to decode base58 tx_hash");

                SignerError::SerializationError("Failed to decode base58 tx_hash".to_string())
            })?;

            let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
                SignerError::SigningFailed("Invalid tx_hash length (expected 64 bytes)".to_string())
            })?;

            return Ok(Signature::from(sig_array));
        }

        Err(SignerError::SigningFailed(
            "No signature found in response (no signed_messages or tx_hash)".to_string(),
        ))
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        let signature = if self.use_program_call {
            // PROGRAM_CALL: signs and auto-broadcasts to Solana
            self.sign_with_program_call(transaction).await?
        } else {
            // RAW (default): sign the message bytes, caller broadcasts
            let message_bytes = transaction.message_data();
            self.sign_raw_bytes(&message_bytes).await?
        };

        TransactionUtil::add_signature_to_transaction(transaction, &self.public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    /// Check if Fireblocks API is available
    async fn check_availability(&self) -> bool {
        let uri = format!("/v1/vault/accounts/{}", self.vault_account_id);
        let token = match jwt::create_jwt(&self.api_key, &self.private_key_pem, &uri, "") {
            Ok(t) => t,
            Err(_) => return false,
        };

        let url = format!("{}{}", self.api_base_url, uri);
        let response = self
            .client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await;

        match response {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl SolanaSigner for FireblocksSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key
    }

    async fn sign_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        self.sign_and_serialize(tx).await
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.sign_raw_bytes(message).await
    }

    async fn sign_partial_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        self.sign_and_serialize(tx).await
    }

    async fn is_available(&self) -> bool {
        self.check_availability().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{header, method, path, path_regex},
        Mock, MockServer, ResponseTemplate,
    };

    // Test RSA key for unit tests only (PKCS#8 format required by jsonwebtoken)
    const TEST_RSA_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDKKw7fHhfK3/Ts
rAqsNCrDsjmyBTHx/AUCOTM+tZph2ZOyDSH9nZO4JkzLrW6Vfk7EZvlP3QjLiXEG
m9qQgAh9sXgp07GicWU5omSILTMdd18yR6aIXVw/YzgjD7EVLRQU6YHc3BYgR8P8
PBbJcxzYrrUDSGEXX2b44cZO72RxIPM+yeY3ZXiztgFQSpfEIKX488/k/PgUHMHK
/04VoL/jiQa5dOs44CmHHT6MbBT1Sb/VR0G1hHtfMSIQCtdvzt+VBZhg7sxm50h/
cT+n0UVOBwEp2IY2x4lzlwOdptZl7P3D1+A2rAbalXg5WO+LVEjx5ym++XbCGyvU
rlH+ILOPAgMBAAECggEAXio3F5J/N4YgITqzD+mOf69cc0A7NsCRnqsA5PUWbvw2
cIjwa55BZ1UjkPz7lJML4iwqdNn51j/yzsa6Q3L3QYBvfV/2jbiuku1CUTFobRGk
XBmGhl6h8H5o79/HthrUjzcCP1qdzbRPo4Vjgbpl1cFuW5STcJ0Fq+gRg8O6b3w7
A2843mcF9EA9ZFjXpn+VtpzLe4nHVRZFYXvXSlfdYc6WQbThnLLiLQYsVMqhYQAU
I4c9hfgasfgZ6iCV5hMK2ZPX45+/OVQzjh4+I8zlvNWp2cKNoEhMHU2G/In11yBF
wHGRuvbwx9Wc4Okqq+GvfTO0jCAinAQQu8C+eIcNcQKBgQDo9dzw2cNsJmaUvaL5
I7gEtbPdr+CTgVjGoVUIlGeI0OBHt1DJEwczS2tycScE9SUDLdmegYA8ubHsAs/6
PFEJ+779h9/IDzL3Fe9Zp1fiQgWOKF1uCS7+b8QwFMhh2u0OLWmI1rdFmqX2KCPf
AfD/Pvp6bgapXTN1EoB3LQ/4PwKBgQDeKZeJMk9CZzWFe+m5x2yzJBK62ZvKzyjZ
Y3IeK75V0xG+Y7ZAb0zTXPkgBpBiQOqdFRgt6bp/S/6Tq/OXfeV9xVURSz4zRtCR
lRoONL8ZSl0h4VptEjXrYfBnH2j4gtjhnTATJZBp0rYrExbz0jVbQtRzPLs+k3+p
TuZA8+XwsQKBgCocn8buJpR7UJncugQ9f7tiOVR+waMIg8rMSTnW0ex6jcCJE9J1
XRzZql+ysrIDuqAbfrZXhJ31l4Mpcv0yQBgE6R6dnEdm7/iYf37+cDWXZ7et9k24
3UTjYVyrtRlzYNzqOqSg49pyPUQFN47NpAoQEWlmUE/3aCDmqlBg1f0zAoGAamv+
HUiuUx7hspnTMp1nYsEq/7ryOErYRJqwtec6fB5p54wYZ/FpGe71n/PFAmwadzj9
pjDKl+QthUvfmnhCkOcQgwJKP4Hys2p7WsbFrDXFO0+aY5lPnvwBj0SqojD798e2
mdVqwmafwS6Z1h6iVJ9E6hbzk1xQ0SfsgLzVL2ECgYBN6fJ99og4fkp4iA5C31TB
UKlH64yqwxFu4vuVMqBOpGPkdsLNGhE/vpdP7yYxC/MP+v8ow/sCa40Ely20Yqqa
znT9Ik5JV4eRXyRG9iwllKvcrmczFDIuxFmXPff4G9nmyB9fLQfSM0gD+yDR05Hx
p6B5CCtpBPgD01Vm+bT/JQ==
-----END PRIVATE KEY-----"#;

    const TEST_PUBKEY: &str = "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV";

    fn create_test_signer_uninit(base_url: &str) -> FireblocksSigner {
        FireblocksSigner {
            api_key: "test-api-key".to_string(),
            private_key_pem: TEST_RSA_KEY.to_string(),
            vault_account_id: "test-vault-id".to_string(),
            asset_id: "SOL".to_string(),
            public_key: Pubkey::default(),
            api_base_url: base_url.to_string(),
            client: reqwest::Client::new(),
            poll_interval_ms: 10,
            max_poll_attempts: 3,
            use_program_call: false, // Use RAW (default) for message signing tests
        }
    }

    fn create_test_signer(base_url: &str) -> FireblocksSigner {
        FireblocksSigner {
            api_key: "test-api-key".to_string(),
            private_key_pem: TEST_RSA_KEY.to_string(),
            vault_account_id: "test-vault-id".to_string(),
            asset_id: "SOL".to_string(),
            public_key: Pubkey::from_str(TEST_PUBKEY).unwrap(),
            api_base_url: base_url.to_string(),
            client: reqwest::Client::new(),
            poll_interval_ms: 10,
            max_poll_attempts: 3,
            use_program_call: false, // Use RAW (default) for message signing tests
        }
    }

    fn create_test_signer_program_call(base_url: &str) -> FireblocksSigner {
        FireblocksSigner {
            api_key: "test-api-key".to_string(),
            private_key_pem: TEST_RSA_KEY.to_string(),
            vault_account_id: "test-vault-id".to_string(),
            asset_id: "SOL".to_string(),
            public_key: Pubkey::from_str(TEST_PUBKEY).unwrap(),
            api_base_url: base_url.to_string(),
            client: reqwest::Client::new(),
            poll_interval_ms: 10,
            max_poll_attempts: 3,
            use_program_call: true, // Use PROGRAM_CALL for transaction tests
        }
    }

    #[test]
    fn test_new_valid() {
        let signer = FireblocksSigner::new(FireblocksSignerConfig {
            api_key: "test-key".to_string(),
            private_key_pem: TEST_RSA_KEY.to_string(),
            vault_account_id: "test-vault".to_string(),
            asset_id: None,
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
            use_program_call: None,
        });
        assert_eq!(signer.asset_id, "SOL");
        assert_eq!(signer.public_key, Pubkey::default());
        assert!(!signer.use_program_call); // Default is RAW (matching other signers)
    }

    #[tokio::test]
    async fn test_init_success() {
        let mock_server = MockServer::start().await;
        let mut signer = create_test_signer_uninit(&mock_server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/v1/vault/accounts/test-vault-id/SOL/addresses_paginated",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "addresses": [{ "address": TEST_PUBKEY }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.init().await;
        assert!(result.is_ok());
        assert_eq!(signer.pubkey().to_string(), TEST_PUBKEY);
    }

    #[tokio::test]
    async fn test_init_api_error() {
        let mock_server = MockServer::start().await;
        let mut signer = create_test_signer_uninit(&mock_server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/v1/vault/accounts/test-vault-id/SOL/addresses_paginated",
            ))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.init().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sign_message_success() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        // Create a valid 64-byte signature
        let sig_bytes = [0x42u8; 64];
        let sig_hex = hex::encode(sig_bytes);

        // Mock create transaction
        Mock::given(method("POST"))
            .and(path("/v1/transactions"))
            .and(header("X-API-Key", "test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-123",
                "status": "SUBMITTED"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Mock get transaction (polling)
        Mock::given(method("GET"))
            .and(path("/v1/transactions/tx-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-123",
                "status": "COMPLETED",
                "signedMessages": [{
                    "signature": {
                        "fullSig": sig_hex
                    }
                }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test message").await;
        assert!(result.is_ok());
        let signature = result.unwrap();
        assert_eq!(signature.as_ref(), &sig_bytes);
    }

    #[tokio::test]
    async fn test_sign_message_api_error() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        Mock::given(method("POST"))
            .and(path("/v1/transactions"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sign_message_transaction_failed() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        Mock::given(method("POST"))
            .and(path("/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-123",
                "status": "SUBMITTED"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/v1/transactions/tx-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-123",
                "status": "FAILED",
                "signedMessages": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_available_success() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        Mock::given(method("GET"))
            .and(path_regex(r"/v1/vault/accounts/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-vault-id",
                "name": "Test Vault"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(signer.is_available().await);
    }

    #[tokio::test]
    async fn test_is_available_failure() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        Mock::given(method("GET"))
            .and(path_regex(r"/v1/vault/accounts/.*"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_sign_transaction_program_call() {
        use crate::test_util::create_test_transaction;

        let mock_server = MockServer::start().await;
        let signer = create_test_signer_program_call(&mock_server.uri());

        // Create a valid 64-byte signature
        let sig_bytes = [0x42u8; 64];
        let sig_hex = hex::encode(sig_bytes);

        // Mock create transaction for PROGRAM_CALL
        Mock::given(method("POST"))
            .and(path("/v1/transactions"))
            .and(header("X-API-Key", "test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-456",
                "status": "SUBMITTED"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Mock get transaction (polling)
        Mock::given(method("GET"))
            .and(path("/v1/transactions/tx-456"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-456",
                "status": "COMPLETED",
                "signedMessages": [{
                    "signature": {
                        "fullSig": sig_hex
                    }
                }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut transaction = create_test_transaction(&signer.pubkey());
        let result = signer.sign_transaction(&mut transaction).await;
        assert!(result.is_ok());
        let (_, signature) = result.unwrap();
        assert_eq!(signature.as_ref(), &sig_bytes);
    }

    #[test]
    fn test_use_program_call_config() {
        // Test with use_program_call = true (PROGRAM_CALL mode)
        let signer_program_call = FireblocksSigner::new(FireblocksSignerConfig {
            api_key: "test-key".to_string(),
            private_key_pem: TEST_RSA_KEY.to_string(),
            vault_account_id: "test-vault".to_string(),
            asset_id: None,
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
            use_program_call: Some(true),
        });
        assert!(signer_program_call.use_program_call);

        // Test with use_program_call = false (explicit RAW mode)
        let signer_raw = FireblocksSigner::new(FireblocksSignerConfig {
            api_key: "test-key".to_string(),
            private_key_pem: TEST_RSA_KEY.to_string(),
            vault_account_id: "test-vault".to_string(),
            asset_id: None,
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
            use_program_call: Some(false),
        });
        assert!(!signer_raw.use_program_call);
    }
}
