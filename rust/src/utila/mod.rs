//! Utila API signer integration

mod types;

use crate::sdk_adapter::{Pubkey, Signature, Transaction, VersionedTransaction};
use crate::traits::{SignTransactionResult, SignedTransaction};
use crate::transaction_util::TransactionUtil;
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
            .get(self.build_url(path)?)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await?;

        parse_response(response, context).await
    }

    async fn post_json<T, B>(&self, path: &str, body: &B, context: &str) -> Result<T, SignerError>
    where
        T: serde::de::DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let token = self.create_access_token()?;
        let response = self
            .client
            .post(self.build_url(path)?)
            .header("Authorization", format!("Bearer {token}"))
            .json(body)
            .send()
            .await?;

        parse_response(response, context).await
    }

    fn build_url(&self, path: &str) -> Result<String, SignerError> {
        let base = reqwest::Url::parse(&self.api_base_url)
            .map_err(|e| SignerError::ConfigError(format!("Invalid api_base_url: {e}")))?;
        if base.cannot_be_a_base() {
            return Err(SignerError::ConfigError(
                "api_base_url cannot be used as a base URL".to_string(),
            ));
        }

        Ok(format!(
            "{}{}",
            self.api_base_url.trim_end_matches('/'),
            path
        ))
    }

    async fn poll_signed_transaction(
        &self,
        mut transaction: UtilaTransaction,
    ) -> Result<UtilaTransaction, SignerError> {
        for _ in 0..self.max_poll_attempts {
            match transaction.state {
                TransactionState::Signed => return Ok(transaction),
                state if state.is_terminal_failure() => {
                    return Err(SignerError::SigningFailed(format!(
                        "Utila transaction reached terminal state {state:?}"
                    )));
                }
                _ => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(self.poll_interval_ms))
                        .await;
                    let transaction_id = extract_transaction_id(&transaction.name)?;
                    transaction = self.get_transaction(&transaction_id).await?;
                }
            }
        }

        if transaction.state == TransactionState::Signed {
            Ok(transaction)
        } else if transaction.state.is_terminal_failure() {
            Err(SignerError::SigningFailed(format!(
                "Utila transaction reached terminal state {:?}",
                transaction.state
            )))
        } else {
            Err(SignerError::RemoteApiError(format!(
                "Utila transaction polling timed out after {} attempts",
                self.max_poll_attempts
            )))
        }
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

        let signature = match bincode::deserialize::<VersionedTransaction>(&bytes) {
            Ok(transaction) => {
                let remote_message = transaction.message.serialize();
                if remote_message != expected_message {
                    return Err(SignerError::SigningFailed(
                        "Utila returned a signed transaction with different message bytes"
                            .to_string(),
                    ));
                }

                let required_signers =
                    usize::from(transaction.message.header().num_required_signatures);
                let signer_keys = transaction.message.static_account_keys();
                if signer_keys.len() < required_signers {
                    return Err(SignerError::SigningFailed(
                        "Invalid account index: not enough account keys".to_string(),
                    ));
                }

                let position = signer_keys
                    .iter()
                    .take(required_signers)
                    .position(|key| key == &public_key)
                    .ok_or_else(|| {
                        SignerError::SigningFailed(
                            "Failed to locate signer pubkey in Utila transaction".to_string(),
                        )
                    })?;

                transaction
                    .signatures
                    .get(position)
                    .copied()
                    .filter(|sig| *sig != Signature::default())
                    .ok_or_else(|| {
                        SignerError::SigningFailed(
                            "Utila rawTransaction did not contain a signer signature".to_string(),
                        )
                    })?
            }
            Err(_) => {
                let transaction: Transaction = bincode::deserialize(&bytes).map_err(|_| {
                    SignerError::SerializationError(
                        "Failed to deserialize Utila rawTransaction".to_string(),
                    )
                })?;

                let remote_message = transaction.message_data();
                if remote_message != expected_message {
                    return Err(SignerError::SigningFailed(
                        "Utila returned a signed transaction with different message bytes"
                            .to_string(),
                    ));
                }

                let position =
                    TransactionUtil::get_signing_keypair_position(&transaction, &public_key)?;
                transaction
                    .signatures
                    .get(position)
                    .copied()
                    .filter(|sig| *sig != Signature::default())
                    .ok_or_else(|| {
                        SignerError::SigningFailed(
                            "Utila rawTransaction did not contain a signer signature".to_string(),
                        )
                    })?
            }
        };

        if !signature.verify(&public_key.to_bytes(), expected_message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed for Utila rawTransaction".to_string(),
            ));
        }

        Ok(signature)
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        let public_key = self.initialized_pubkey()?;
        let expected_message = transaction.message_data();
        let raw_transaction = STANDARD.encode(bincode::serialize(transaction).map_err(|e| {
            SignerError::SerializationError(format!("Failed to serialize transaction: {e}"))
        })?);

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
        tx: &mut Transaction,
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

async fn parse_response<T>(response: reqwest::Response, context: &str) -> Result<T, SignerError>
where
    T: serde::de::DeserializeOwned,
{
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();

    if status >= 400 {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Utila API {context} error - status: {status}, response: {text}");

        #[cfg(not(feature = "unsafe-debug"))]
        log::error!("Utila API {context} error - status: {status}");

        return Err(SignerError::RemoteApiError(format!(
            "Utila API {context} error {status}"
        )));
    }

    serde_json::from_str(&text).map_err(|_| {
        SignerError::SerializationError(format!("Failed to parse Utila {context} response"))
    })
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
            encoded.push_str(&format!("%{:02X}", byte));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk_adapter::{keypair_pubkey, keypair_sign_message, Keypair};
    use crate::test_util::create_test_transaction;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value;
    use wiremock::{
        matchers::{body_json, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    const TEST_EMAIL: &str = "service-account@vault.utilaserviceaccount.io";
    const TEST_VAULT_ID: &str = "vault-test";
    const TEST_WALLET_ID: &str = "wallet-test";
    const TEST_NETWORK: &str = "networks/solana-devnet";
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

    fn config() -> UtilaSignerConfig {
        UtilaSignerConfig {
            service_account_email: TEST_EMAIL.to_string(),
            service_account_private_key_pem: TEST_RSA_KEY.to_string(),
            vault_id: TEST_VAULT_ID.to_string(),
            wallet_id: TEST_WALLET_ID.to_string(),
            network: TEST_NETWORK.to_string(),
            api_base_url: None,
            poll_interval_ms: Some(1),
            max_poll_attempts: Some(2),
            designated_signers: None,
            http_client_config: None,
        }
    }

    fn create_test_signer(base_url: &str, public_key: Option<Pubkey>) -> UtilaSigner {
        UtilaSigner {
            service_account_email: TEST_EMAIL.to_string(),
            signing_key: Arc::new(EncodingKey::from_rsa_pem(TEST_RSA_KEY.as_bytes()).unwrap()),
            vault_id: TEST_VAULT_ID.to_string(),
            wallet_id: TEST_WALLET_ID.to_string(),
            network: TEST_NETWORK.to_string(),
            api_base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder().build().unwrap(),
            public_key,
            poll_interval_ms: 1,
            max_poll_attempts: 2,
            designated_signers: vec![format!("users/{TEST_EMAIL}")],
        }
    }

    fn wallet_response(address: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallet": {
                "solanaDetails": {
                    "address": address
                }
            }
        }))
    }

    fn signed_transaction_payload() -> (Keypair, Transaction, String, String, Signature) {
        let keypair = Keypair::new();
        let public_key = keypair_pubkey(&keypair);
        let unsigned = create_test_transaction(&public_key);
        let unsigned_raw = STANDARD.encode(bincode::serialize(&unsigned).unwrap());

        let mut signed = unsigned.clone();
        let signature = keypair_sign_message(&keypair, &signed.message_data());
        TransactionUtil::add_signature_to_transaction(&mut signed, &public_key, signature).unwrap();
        let signed_raw = STANDARD.encode(bincode::serialize(&signed).unwrap());

        (keypair, unsigned, unsigned_raw, signed_raw, signature)
    }

    fn decode_jwt_payload(jwt: &str) -> Value {
        let parts: Vec<&str> = jwt.split('.').collect();
        let payload_b64 = parts.get(1).expect("jwt payload should exist");
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .expect("payload should be base64url");
        serde_json::from_slice::<Value>(&payload_bytes).expect("payload should be valid json")
    }

    #[test]
    fn test_new_rejects_missing_config() {
        let mut config = config();
        config.service_account_email = String::new();
        assert!(matches!(
            UtilaSigner::new(config),
            Err(SignerError::ConfigError(_))
        ));
    }

    #[test]
    fn test_new_rejects_insecure_api_base_url() {
        let mut config = config();
        config.api_base_url = Some("http://api.utila.test".to_string());
        assert!(matches!(
            UtilaSigner::new(config),
            Err(SignerError::ConfigError(_))
        ));
    }

    #[test]
    fn test_create_access_token_claims() {
        let signer = UtilaSigner::new(config()).expect("signer should be created");
        let token = signer
            .create_access_token()
            .expect("access token should be created");
        let payload = decode_jwt_payload(&token);

        assert_eq!(payload["sub"], TEST_EMAIL);
        assert_eq!(payload["aud"], UTILA_API_AUDIENCE);
        assert!(payload["exp"].as_i64().is_some());
    }

    #[test]
    fn test_new_accepts_escaped_newline_pem() {
        let mut config = config();
        config.service_account_private_key_pem = TEST_RSA_KEY.replace('\n', "\\n");
        assert!(UtilaSigner::new(config).is_ok());
    }

    #[tokio::test]
    async fn test_init_fetches_solana_address() {
        let server = MockServer::start().await;
        let keypair = Keypair::new();
        let public_key = keypair_pubkey(&keypair);

        Mock::given(method("GET"))
            .and(path("/v2/vaults/vault-test/wallets/wallet-test"))
            .respond_with(wallet_response(&public_key.to_string()))
            .mount(&server)
            .await;

        let mut signer = create_test_signer(&server.uri(), None);
        signer.init().await.expect("init should fetch address");
        assert_eq!(signer.pubkey(), public_key);
    }

    #[tokio::test]
    async fn test_fetch_wallet_encodes_resource_ids() {
        let server = MockServer::start().await;
        let keypair = Keypair::new();
        let public_key = keypair_pubkey(&keypair);

        Mock::given(method("GET"))
            .and(path(
                "/v2/vaults/vault%2Fwith%20space/wallets/wallet%2Fwith%20space",
            ))
            .respond_with(wallet_response(&public_key.to_string()))
            .mount(&server)
            .await;

        let mut signer = create_test_signer(&server.uri(), None);
        signer.vault_id = "vault/with space".to_string();
        signer.wallet_id = "wallet/with space".to_string();

        signer.init().await.expect("init should fetch address");
        assert_eq!(signer.pubkey(), public_key);
    }

    #[tokio::test]
    async fn test_initiate_transaction_encodes_vault_id() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(
                "/v2/vaults/vault%2Fwith%20space/transactions:initiate",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction": {
                    "name": "vaults/vault/with space/transactions/tx-1",
                    "state": "AWAITING_SIGNATURE"
                }
            })))
            .mount(&server)
            .await;

        let mut signer = create_test_signer(&server.uri(), None);
        signer.vault_id = "vault/with space".to_string();

        let transaction = signer
            .initiate_transaction("raw-transaction".to_string())
            .await
            .expect("transaction should be initiated");

        assert_eq!(
            transaction.name,
            "vaults/vault/with space/transactions/tx-1"
        );
    }

    #[tokio::test]
    async fn test_sign_message_not_supported() {
        let keypair = Keypair::new();
        let signer = create_test_signer(&server_url(), Some(keypair_pubkey(&keypair)));
        let result = signer.sign_message(b"hello").await;
        assert!(matches!(result, Err(SignerError::SigningFailed(_))));
    }

    #[tokio::test]
    async fn test_sign_transaction_posts_payload_and_polls_signed_response() {
        let server = MockServer::start().await;
        let (keypair, mut transaction, unsigned_raw, signed_raw, expected_signature) =
            signed_transaction_payload();
        let public_key = keypair_pubkey(&keypair);

        Mock::given(method("POST"))
            .and(path("/v2/vaults/vault-test/transactions:initiate"))
            .and(body_json(serde_json::json!({
                "details": {
                    "solanaSerializedTransaction": {
                        "network": TEST_NETWORK,
                        "rawTransaction": unsigned_raw,
                        "publish": false,
                        "replaceBlockhash": false,
                        "tryReplaceBlockhash": false
                    }
                },
                "designatedSigners": [format!("users/{TEST_EMAIL}")]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction": {
                    "name": "vaults/vault-test/transactions/tx-1",
                    "state": "AWAITING_SIGNATURE"
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/v2/vaults/vault-test/transactions/tx-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction": {
                    "name": "vaults/vault-test/transactions/tx-1",
                    "state": "SIGNED",
                    "solanaTransaction": {
                        "rawTransaction": signed_raw
                    }
                }
            })))
            .mount(&server)
            .await;

        let signer = create_test_signer(&server.uri(), Some(public_key));
        let result = signer
            .sign_transaction(&mut transaction)
            .await
            .expect("transaction should sign");
        let (_, signature) = result.into_signed_transaction();

        assert_eq!(signature, expected_signature);
        assert_eq!(transaction.signatures[0], expected_signature);
    }

    #[tokio::test]
    async fn test_sign_transaction_terminal_failure() {
        let server = MockServer::start().await;
        let (keypair, mut transaction, unsigned_raw, _, _) = signed_transaction_payload();

        Mock::given(method("POST"))
            .and(path("/v2/vaults/vault-test/transactions:initiate"))
            .and(body_json(serde_json::json!({
                "details": {
                    "solanaSerializedTransaction": {
                        "network": TEST_NETWORK,
                        "rawTransaction": unsigned_raw,
                        "publish": false,
                        "replaceBlockhash": false,
                        "tryReplaceBlockhash": false
                    }
                },
                "designatedSigners": [format!("users/{TEST_EMAIL}")]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction": {
                    "name": "vaults/vault-test/transactions/tx-1",
                    "state": "FAILED"
                }
            })))
            .mount(&server)
            .await;

        let signer = create_test_signer(&server.uri(), Some(keypair_pubkey(&keypair)));
        let result = signer.sign_transaction(&mut transaction).await;
        assert!(matches!(result, Err(SignerError::SigningFailed(_))));
    }

    #[tokio::test]
    async fn test_sign_transaction_timeout() {
        let server = MockServer::start().await;
        let (keypair, mut transaction, unsigned_raw, _, _) = signed_transaction_payload();

        Mock::given(method("POST"))
            .and(path("/v2/vaults/vault-test/transactions:initiate"))
            .and(body_json(serde_json::json!({
                "details": {
                    "solanaSerializedTransaction": {
                        "network": TEST_NETWORK,
                        "rawTransaction": unsigned_raw,
                        "publish": false,
                        "replaceBlockhash": false,
                        "tryReplaceBlockhash": false
                    }
                },
                "designatedSigners": [format!("users/{TEST_EMAIL}")]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction": {
                    "name": "vaults/vault-test/transactions/tx-1",
                    "state": "AWAITING_SIGNATURE"
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/v2/vaults/vault-test/transactions/tx-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction": {
                    "name": "vaults/vault-test/transactions/tx-1",
                    "state": "AWAITING_SIGNATURE"
                }
            })))
            .mount(&server)
            .await;

        let signer = create_test_signer(&server.uri(), Some(keypair_pubkey(&keypair)));
        let result = signer.sign_transaction(&mut transaction).await;
        assert!(matches!(result, Err(SignerError::RemoteApiError(_))));
    }

    #[tokio::test]
    async fn test_sign_transaction_rejects_mismatched_returned_transaction() {
        let server = MockServer::start().await;
        let (keypair, mut transaction, unsigned_raw, _, _) = signed_transaction_payload();
        let other_keypair = Keypair::new();
        let (_, _, _, mismatched_raw, _) = signed_transaction_payload_for_keypair(&other_keypair);

        Mock::given(method("POST"))
            .and(path("/v2/vaults/vault-test/transactions:initiate"))
            .and(body_json(serde_json::json!({
                "details": {
                    "solanaSerializedTransaction": {
                        "network": TEST_NETWORK,
                        "rawTransaction": unsigned_raw,
                        "publish": false,
                        "replaceBlockhash": false,
                        "tryReplaceBlockhash": false
                    }
                },
                "designatedSigners": [format!("users/{TEST_EMAIL}")]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transaction": {
                    "name": "vaults/vault-test/transactions/tx-1",
                    "state": "SIGNED",
                    "solanaTransaction": {
                        "rawTransaction": mismatched_raw
                    }
                }
            })))
            .mount(&server)
            .await;

        let signer = create_test_signer(&server.uri(), Some(keypair_pubkey(&keypair)));
        let result = signer.sign_transaction(&mut transaction).await;
        assert!(matches!(result, Err(SignerError::SigningFailed(_))));
    }

    #[tokio::test]
    async fn test_is_available() {
        let server = MockServer::start().await;
        let keypair = Keypair::new();

        Mock::given(method("GET"))
            .and(path("/v2/vaults/vault-test/wallets/wallet-test"))
            .respond_with(wallet_response(&keypair_pubkey(&keypair).to_string()))
            .mount(&server)
            .await;

        let signer = create_test_signer(&server.uri(), None);
        assert!(signer.is_available().await);

        let unavailable = create_test_signer("http://127.0.0.1:1", None);
        assert!(!unavailable.is_available().await);
    }

    fn signed_transaction_payload_for_keypair(
        keypair: &Keypair,
    ) -> (Transaction, Transaction, String, String, Signature) {
        let public_key = keypair_pubkey(keypair);
        let unsigned = create_test_transaction(&public_key);
        let unsigned_raw = STANDARD.encode(bincode::serialize(&unsigned).unwrap());

        let mut signed = unsigned.clone();
        let signature = keypair_sign_message(keypair, &signed.message_data());
        TransactionUtil::add_signature_to_transaction(&mut signed, &public_key, signature).unwrap();
        let signed_raw = STANDARD.encode(bincode::serialize(&signed).unwrap());

        (
            unsigned.clone(),
            signed,
            unsigned_raw,
            signed_raw,
            signature,
        )
    }

    fn server_url() -> String {
        "http://127.0.0.1:1".to_string()
    }
}
