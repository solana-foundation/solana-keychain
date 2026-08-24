//! Utila API signer integration

mod types;

use crate::remote_util::parse_json_response;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::traits::{SignTransactionResult, SignedTransaction};
use crate::transaction_util::{
    deserialize_wire_transaction, serialize_wire_transaction, TransactionUtil,
};
use crate::{error::SignerError, http_client_config::HttpClientConfig, traits::SolanaSigner};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use std::{str::FromStr, sync::Arc};
use types::{
    InitiateTransactionDetails, InitiateTransactionRequest, SolanaSerializedTransaction,
    TransactionEnvelope, TransactionState, UtilaTransaction, WalletResponse,
};

const DEFAULT_API_BASE_URL: &str = "https://api.utila.io";
const UTILA_API_AUDIENCE: &str = "https://api.utila.io/";
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const DEFAULT_MAX_POLL_ATTEMPTS: u32 = 60;
const TOKEN_TTL_MINUTES: i64 = 55;
const AVAILABILITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Configuration for creating a UtilaSigner.
#[derive(Clone)]
pub struct UtilaSignerConfig {
    pub service_account_email: String,
    pub service_account_private_key_pem: String,
    pub vault_id: String,
    pub wallet_id: String,
    /// Utila network resource name, e.g. `networks/solana-devnet`.
    pub network: String,
    pub api_base_url: Option<String>,
    pub poll_interval_ms: Option<u64>,
    pub max_poll_attempts: Option<u32>,
    /// Utila signer resource names. Defaults to `users/{service_account_email}`.
    pub designated_signers: Option<Vec<String>>,
    pub http_client_config: Option<HttpClientConfig>,
}

/// Utila-backed signer using an existing Solana wallet.
#[derive(Clone)]
pub struct UtilaSigner {
    service_account_email: String,
    signing_key: Arc<EncodingKey>,
    vault_id: String,
    wallet_id: String,
    network: String,
    api_base_url: String,
    client: reqwest::Client,
    public_key: Option<Pubkey>,
    poll_interval_ms: u64,
    max_poll_attempts: u32,
    designated_signers: Vec<String>,
}

impl std::fmt::Debug for UtilaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UtilaSigner")
            .field("public_key", &self.public_key)
            .field("vault_id", &self.vault_id)
            .field("wallet_id", &self.wallet_id)
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct UtilaAccessTokenClaims<'a> {
    sub: &'a str,
    aud: &'a str,
    exp: i64,
}

impl UtilaSigner {
    /// Create a new Utila signer.
    ///
    /// You must call `init()` after construction to fetch the wallet address.
    pub fn new(config: UtilaSignerConfig) -> Result<Self, SignerError> {
        validate_required("service_account_email", &config.service_account_email)?;
        validate_required(
            "service_account_private_key_pem",
            &config.service_account_private_key_pem,
        )?;
        validate_required("vault_id", &config.vault_id)?;
        validate_required("wallet_id", &config.wallet_id)?;
        validate_required("network", &config.network)?;

        let api_base_url = normalize_api_base_url(config.api_base_url.as_deref())?;
        let poll_interval_ms = config.poll_interval_ms.unwrap_or(DEFAULT_POLL_INTERVAL_MS);
        if poll_interval_ms == 0 {
            return Err(SignerError::ConfigError(
                "poll_interval_ms must be greater than 0".to_string(),
            ));
        }

        let max_poll_attempts = config
            .max_poll_attempts
            .unwrap_or(DEFAULT_MAX_POLL_ATTEMPTS);
        if max_poll_attempts == 0 {
            return Err(SignerError::ConfigError(
                "max_poll_attempts must be greater than 0".to_string(),
            ));
        }

        let pem = config
            .service_account_private_key_pem
            .replace("\\n", "\n")
            .replace('\r', "");
        let signing_key = EncodingKey::from_rsa_pem(pem.trim().as_bytes()).map_err(|_| {
            SignerError::InvalidPrivateKey(
                "Failed to parse Utila service account RSA private key".to_string(),
            )
        })?;

        let http_client_config = config.http_client_config.unwrap_or_default();
        let client = http_client_config.build_client()?;

        let designated_signers = config
            .designated_signers
            .unwrap_or_else(|| vec![format!("users/{}", config.service_account_email)]);

        Ok(Self {
            service_account_email: config.service_account_email,
            signing_key: Arc::new(signing_key),
            vault_id: trim_resource_prefix(&config.vault_id, "vaults/").to_string(),
            wallet_id: trim_wallet_id(&config.wallet_id).to_string(),
            network: config.network,
            api_base_url,
            client,
            public_key: None,
            poll_interval_ms,
            max_poll_attempts,
            designated_signers,
        })
    }

    /// Initialize signer by fetching the Solana wallet address from Utila.
    pub async fn init(&mut self) -> Result<(), SignerError> {
        let wallet = self.fetch_wallet().await?;
        let address = wallet
            .wallet
            .solana_details
            .ok_or_else(|| {
                SignerError::InvalidPublicKey(
                    "Utila wallet response did not include solanaDetails".to_string(),
                )
            })?
            .address;

        let pubkey = Pubkey::from_str(&address).map_err(|_| {
            SignerError::InvalidPublicKey(
                "Invalid Solana address returned by Utila wallet".to_string(),
            )
        })?;

        self.public_key = Some(pubkey);
        Ok(())
    }

    fn initialized_pubkey(&self) -> Result<Pubkey, SignerError> {
        self.public_key.ok_or_else(|| {
            SignerError::ConfigError(
                "UtilaSigner is not initialized; call init() before signing".to_string(),
            )
        })
    }

    fn create_access_token(&self) -> Result<String, SignerError> {
        let claims = UtilaAccessTokenClaims {
            sub: &self.service_account_email,
            aud: UTILA_API_AUDIENCE,
            exp: (Utc::now() + Duration::minutes(TOKEN_TTL_MINUTES)).timestamp(),
        };

        encode(&Header::new(Algorithm::RS256), &claims, &self.signing_key).map_err(|_| {
            SignerError::SigningFailed("Failed to create Utila access token".to_string())
        })
    }

    async fn fetch_wallet(&self) -> Result<WalletResponse, SignerError> {
        let path = format!(
            "/v2/vaults/{}/wallets/{}",
            encode_uri_component(&self.vault_id),
            encode_uri_component(&self.wallet_id)
        );
        self.get_json(&path, "fetch_wallet").await
    }

    async fn initiate_transaction(
        &self,
        raw_transaction: String,
    ) -> Result<UtilaTransaction, SignerError> {
        let path = format!(
            "/v2/vaults/{}/transactions:initiate",
            encode_uri_component(&self.vault_id)
        );
        let request = InitiateTransactionRequest {
            details: InitiateTransactionDetails {
                solana_serialized_transaction: SolanaSerializedTransaction {
                    network: self.network.clone(),
                    raw_transaction,
                    publish: false,
                    replace_blockhash: false,
                    try_replace_blockhash: false,
                },
            },
            designated_signers: self.designated_signers.clone(),
        };

        let envelope: TransactionEnvelope = self
            .post_json(&path, &request, "initiate_transaction")
            .await?;
        Ok(envelope.transaction)
    }

    async fn get_transaction(&self, transaction_id: &str) -> Result<UtilaTransaction, SignerError> {
        let path = format!(
            "/v2/vaults/{}/transactions/{}?view=FULL",
            encode_uri_component(&self.vault_id),
            encode_uri_component(transaction_id)
        );
        let envelope: TransactionEnvelope = self.get_json(&path, "get_transaction").await?;
        Ok(envelope.transaction)
    }

    async fn get_json<T>(&self, path: &str, context: &str) -> Result<T, SignerError>
    where
        T: serde::de::DeserializeOwned,
    {
        let token = self.create_access_token()?;
        let response = self
            .client
            .get(self.build_url(path))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await?;

        parse_json_response(response, &format!("Utila API {context}")).await
    }

    async fn post_json<T, B>(&self, path: &str, body: &B, context: &str) -> Result<T, SignerError>
    where
        T: serde::de::DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let token = self.create_access_token()?;
        let response = self
            .client
            .post(self.build_url(path))
            .header("Authorization", format!("Bearer {token}"))
            .json(body)
            .send()
            .await?;

        parse_json_response(response, &format!("Utila API {context}")).await
    }

    fn build_url(&self, path: &str) -> String {
        format!("{}{}", self.api_base_url, path)
    }

    async fn poll_signed_transaction(
        &self,
        mut transaction: UtilaTransaction,
    ) -> Result<UtilaTransaction, SignerError> {
        let transaction_id = extract_transaction_id(&transaction.name)?;
        for attempt in 0..=self.max_poll_attempts {
            if attempt > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(self.poll_interval_ms)).await;
                transaction = self.get_transaction(&transaction_id).await?;
            }
            match transaction.state {
                TransactionState::Signed => return Ok(transaction),
                state if state.is_terminal_failure() => {
                    return Err(SignerError::SigningFailed(format!(
                        "Utila transaction reached terminal state {state:?}"
                    )));
                }
                _ => {}
            }
        }

        Err(SignerError::RemoteApiError(format!(
            "Utila transaction polling timed out after {} attempts",
            self.max_poll_attempts
        )))
    }

    fn extract_signature_from_raw_transaction(
        &self,
        raw_transaction: &str,
        expected_message: &[u8],
    ) -> Result<Signature, SignerError> {
        let public_key = self.initialized_pubkey()?;
        let bytes = STANDARD.decode(raw_transaction).map_err(|_| {
            SignerError::SerializationError(
                "Failed to decode Utila rawTransaction as base64".to_string(),
            )
        })?;

        let transaction: VersionedTransaction =
            deserialize_wire_transaction(&bytes).map_err(|_e| {
                SignerError::SerializationError(
                    "Failed to deserialize Utila rawTransaction".to_string(),
                )
            })?;

        let remote_message = transaction.message.serialize();
        if remote_message != expected_message {
            return Err(SignerError::SigningFailed(
                "Utila returned a signed transaction with different message bytes".to_string(),
            ));
        }

        let position = TransactionUtil::get_signing_keypair_position(&transaction, &public_key)?;
        let signature = transaction
            .signatures
            .get(position)
            .copied()
            .filter(|sig| *sig != Signature::default())
            .ok_or_else(|| {
                SignerError::SigningFailed(
                    "Utila rawTransaction did not contain a signer signature".to_string(),
                )
            })?;

        if !signature.verify(&public_key.to_bytes(), expected_message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed for Utila rawTransaction".to_string(),
            ));
        }

        Ok(signature)
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        let public_key = self.initialized_pubkey()?;
        let expected_message = transaction.message.serialize();
        let raw_transaction = STANDARD.encode(serialize_wire_transaction(transaction)?);

        let initiated = self.initiate_transaction(raw_transaction).await?;
        let signed = self.poll_signed_transaction(initiated).await?;
        let raw_signed_transaction = signed
            .solana_transaction
            .and_then(|solana| solana.raw_transaction)
            .ok_or_else(|| {
                SignerError::SigningFailed(
                    "Utila signed transaction response missing solanaTransaction.rawTransaction"
                        .to_string(),
                )
            })?;
        let signature = self
            .extract_signature_from_raw_transaction(&raw_signed_transaction, &expected_message)?;

        TransactionUtil::add_signature_to_transaction(transaction, &public_key, signature)?;
        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    async fn check_availability(&self) -> bool {
        let result = tokio::time::timeout(AVAILABILITY_TIMEOUT, self.fetch_wallet()).await;
        matches!(result, Ok(Ok(_)))
    }
}

#[async_trait::async_trait]
impl SolanaSigner for UtilaSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key.expect("UtilaSigner not initialized")
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

    async fn sign_message(&self, _message: &[u8]) -> Result<Signature, SignerError> {
        Err(SignerError::SigningFailed(
            "Utila sign_message is not supported for Solana wallets in this signer".to_string(),
        ))
    }

    async fn is_available(&self) -> bool {
        self.check_availability().await
    }
}

fn validate_required(field: &str, value: &str) -> Result<(), SignerError> {
    if value.trim().is_empty() {
        return Err(SignerError::ConfigError(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn normalize_api_base_url(value: Option<&str>) -> Result<String, SignerError> {
    let api_base_url = value
        .unwrap_or(DEFAULT_API_BASE_URL)
        .trim_end_matches('/')
        .to_string();

    let parsed = reqwest::Url::parse(&api_base_url)
        .map_err(|e| SignerError::ConfigError(format!("Invalid api_base_url: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(SignerError::ConfigError(
            "api_base_url must use HTTPS".to_string(),
        ));
    }

    Ok(api_base_url)
}

fn extract_transaction_id(name: &str) -> Result<String, SignerError> {
    name.rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| {
            SignerError::SerializationError(
                "Utila transaction response missing transaction id".to_string(),
            )
        })
}

fn trim_resource_prefix<'a>(value: &'a str, prefix: &str) -> &'a str {
    value.strip_prefix(prefix).unwrap_or(value)
}

fn trim_wallet_id(value: &str) -> &str {
    if let Some((_, wallet_id)) = value.rsplit_once("/wallets/") {
        wallet_id
    } else {
        value
    }
}

fn encode_uri_component(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        if matches!(
            byte,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'-'
                | b'_'
                | b'.'
                | b'!'
                | b'~'
                | b'*'
                | b'\''
                | b'('
                | b')'
        ) {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests;
