//! Framework-agnostic Solana signing abstractions
//!
//! This crate provides a unified interface for signing Solana transactions
//! with multiple backend implementations (memory, Vault, Privy, Turnkey, AWS KMS,
//! Fireblocks, GCP KMS, Dfns, Crossmint, CDP, Para, Openfort, Utila, Fordefi).
//!
//! # Features
//!
//! ## Signer Backends
//! - `memory` (default): Local keypair signing
//! - `vault`: HashiCorp Vault integration
//! - `privy`: Privy API integration
//! - `turnkey`: Turnkey API integration
//! - `aws_kms`: AWS KMS integration with EdDSA (Ed25519) signing
//! - `fireblocks`: Fireblocks API integration
//! - `gcp_kms`: GCP KMS integration with EdDSA (Ed25519) signing
//! - `cdp`: Coinbase Developer Platform integration
//! - `para`: Para MPC wallet integration
//! - `dfns`: Dfns Wallet API integration
//! - `crossmint`: Crossmint wallet integration
//! - `openfort`: Openfort backend wallet integration
//! - `utila`: Utila MPC wallet integration
//! - `fordefi`: Fordefi MPC custody integration
//! - `all`: Enable all signer backends
//!
//! ## SDK Version Selection
//! - `sdk-v2` (default): Use Solana SDK v2.3.x
//! - `sdk-v3`: Use Solana SDK v3.x
//! - `sdk-v4`: Use Solana SDK v4.x
//!
//! **Note**: Only one SDK version can be enabled at a time.

pub mod error;
pub mod http_client_config;
#[cfg(feature = "_remote")]
mod remote_util;
mod sdk_adapter;
pub mod send;
pub mod signature_util;
#[cfg(test)]
pub mod test_util;
#[cfg(feature = "integration-tests")]
pub mod tests;
pub mod traits;
pub mod transaction_util;
#[cfg(any(feature = "cdp", feature = "openfort"))]
mod wallet_jwt;

#[cfg(feature = "memory")]
pub mod memory;

#[cfg(feature = "vault")]
pub mod vault;

#[cfg(feature = "privy")]
pub mod privy;

#[cfg(feature = "turnkey")]
pub mod turnkey;

#[cfg(feature = "aws_kms")]
pub mod aws_kms;

#[cfg(feature = "fireblocks")]
pub mod fireblocks;

#[cfg(feature = "gcp_kms")]
pub mod gcp_kms;

#[cfg(feature = "cdp")]
pub mod cdp;
#[cfg(feature = "crossmint")]
pub mod crossmint;
#[cfg(feature = "dfns")]
pub mod dfns;
#[cfg(feature = "fordefi")]
pub mod fordefi;
#[cfg(feature = "ledger")]
pub mod ledger;
#[cfg(feature = "openfort")]
pub mod openfort;
#[cfg(feature = "para")]
pub mod para;
#[cfg(feature = "utila")]
pub mod utila;

pub use error::SignerError;
pub use http_client_config::HttpClientConfig;
pub use send::sign_and_send;
pub use traits::{
    ModifyingSigner, SendingSigner, SignTransactionResult, SolanaSigner, TransactionSigner,
};

#[cfg(feature = "memory")]
pub use memory::{MemorySigner, MemorySignerConfig};

#[cfg(feature = "vault")]
pub use vault::{VaultSigner, VaultSignerConfig};

#[cfg(feature = "privy")]
pub use privy::{PrivyAuthorizationRequestExpiry, PrivySigner, PrivySignerConfig};

#[cfg(feature = "turnkey")]
pub use turnkey::{TurnkeySigner, TurnkeySignerConfig};

#[cfg(feature = "aws_kms")]
pub use aws_kms::{AwsKmsSigner, AwsKmsSignerConfig};

#[cfg(feature = "fireblocks")]
pub use fireblocks::{FireblocksSigner, FireblocksSignerConfig};

#[cfg(feature = "gcp_kms")]
pub use gcp_kms::{GcpKmsSigner, GcpKmsSignerConfig};

#[cfg(feature = "cdp")]
pub use cdp::{CdpSigner, CdpSignerConfig};
#[cfg(feature = "crossmint")]
pub use crossmint::{CrossmintSigner, CrossmintSignerConfig};
#[cfg(feature = "dfns")]
pub use dfns::{DfnsSigner, DfnsSignerConfig};
#[cfg(feature = "fordefi")]
pub use fordefi::{
    FordefiBlackBoxSigner, FordefiNativeAutoSigner, FordefiNativeManualSigner,
    FordefiPriorityLevel, FordefiPushMode, FordefiRequestSigner, FordefiSignerConfig,
    FordefiSolanaFee, PemRequestSigner, SolanaChainUniqueId,
};
#[cfg(feature = "ledger")]
pub use ledger::{
    LedgerConfig, LedgerSigner, DEFAULT_DERIVATION_PATH, DEFAULT_SIGN_TIMEOUT, OPS_TIMEOUT,
};
#[cfg(feature = "openfort")]
pub use openfort::{OpenfortSigner, OpenfortSignerConfig};
#[cfg(feature = "para")]
pub use para::{ParaSigner, ParaSignerConfig};
#[cfg(any(feature = "crossmint", feature = "fordefi"))]
pub use transaction_util::PendingTransactionId;
#[cfg(feature = "utila")]
pub use utila::{UtilaSigner, UtilaSignerConfig};

// Ensure at least one signer backend is enabled
#[cfg(not(any(
    feature = "memory",
    feature = "vault",
    feature = "privy",
    feature = "turnkey",
    feature = "aws_kms",
    feature = "fireblocks",
    feature = "gcp_kms",
    feature = "cdp",
    feature = "dfns",
    feature = "para",
    feature = "crossmint",
    feature = "openfort",
    feature = "utila",
    feature = "fordefi",
    feature = "ledger"
)))]
compile_error!(
    "At least one signer backend feature must be enabled: memory, vault, privy, turnkey, aws_kms, fireblocks, gcp_kms, cdp, para, dfns, crossmint, openfort, utila, fordefi, or ledger"
);

/// Unified signer enum supporting multiple backends
#[derive(Debug)]
pub enum Signer {
    #[cfg(feature = "memory")]
    Memory(MemorySigner),

    #[cfg(feature = "vault")]
    Vault(VaultSigner),

    #[cfg(feature = "privy")]
    Privy(PrivySigner),

    #[cfg(feature = "turnkey")]
    Turnkey(TurnkeySigner),

    #[cfg(feature = "aws_kms")]
    AwsKms(AwsKmsSigner),

    #[cfg(feature = "fireblocks")]
    Fireblocks(FireblocksSigner),

    #[cfg(feature = "gcp_kms")]
    GcpKms(GcpKmsSigner),

    #[cfg(feature = "cdp")]
    Cdp(CdpSigner),
    #[cfg(feature = "dfns")]
    Dfns(DfnsSigner),
    #[cfg(feature = "openfort")]
    Openfort(OpenfortSigner),
    #[cfg(feature = "para")]
    Para(ParaSigner),
    #[cfg(feature = "crossmint")]
    Crossmint(CrossmintSigner),
    #[cfg(feature = "utila")]
    Utila(UtilaSigner),
    #[cfg(feature = "fordefi")]
    FordefiBlackBox(FordefiBlackBoxSigner),
    #[cfg(feature = "fordefi")]
    FordefiNativeAuto(FordefiNativeAutoSigner),
    #[cfg(feature = "fordefi")]
    FordefiNativeManual(FordefiNativeManualSigner),
    #[cfg(feature = "ledger")]
    Ledger(LedgerSigner),
}

impl Signer {
    /// Create a memory signer from a private key string
    #[cfg(feature = "memory")]
    pub fn from_memory(private_key: &str) -> Result<Self, SignerError> {
        Ok(Self::Memory(MemorySigner::from_private_key_string(
            private_key,
        )?))
    }

    /// Create a memory signer from a JSON keypair file path
    #[cfg(feature = "memory")]
    pub fn from_memory_file(path: &str) -> Result<Self, SignerError> {
        Ok(Self::Memory(MemorySigner::from_private_key_file(path)?))
    }

    /// Create a Vault signer.
    ///
    /// Pass `None` for `http_client_config` to use default timeout settings.
    #[cfg(feature = "vault")]
    pub fn from_vault(
        vault_addr: String,
        vault_token: String,
        key_name: String,
        pubkey: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        Ok(Self::Vault(VaultSigner::from_config(VaultSignerConfig {
            api_base_url: vault_addr,
            token: vault_token,
            key_name,
            public_key: pubkey,
            http_client_config,
        })?))
    }

    /// Create a Privy signer (requires initialization).
    ///
    /// Pass `None` for `http_client_config` to use default timeout settings.
    #[cfg(feature = "privy")]
    pub async fn from_privy(
        app_id: String,
        app_secret: String,
        wallet_id: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        let mut signer = PrivySigner::from_config(PrivySignerConfig {
            app_id,
            app_secret,
            wallet_id,
            api_base_url: None,
            http_client_config,
            authorization_context: None,
            authorization_request_expiry: PrivyAuthorizationRequestExpiry::Default,
        })?;
        signer.init().await?;
        Ok(Self::Privy(signer))
    }

    /// Create a Turnkey signer.
    ///
    /// Pass `None` for `http_client_config` to use default timeout settings.
    #[cfg(feature = "turnkey")]
    pub fn from_turnkey(
        api_public_key: String,
        api_private_key: String,
        organization_id: String,
        private_key_id: String,
        public_key: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        Ok(Self::Turnkey(TurnkeySigner::from_config(
            TurnkeySignerConfig {
                api_public_key,
                api_private_key,
                organization_id,
                private_key_id,
                public_key,
                api_base_url: None,
                http_client_config,
            },
        )?))
    }

    /// Create an AWS KMS signer (requires initialization)
    #[cfg(feature = "aws_kms")]
    pub async fn from_aws_kms(
        key_id: String,
        public_key: String,
        region: Option<String>,
    ) -> Result<Self, SignerError> {
        Ok(Self::AwsKms(
            AwsKmsSigner::from_config(AwsKmsSignerConfig {
                key_id,
                public_key,
                region,
            })
            .await?,
        ))
    }

    /// Create a Fireblocks signer (requires initialization)
    #[cfg(feature = "fireblocks")]
    pub async fn from_fireblocks(config: FireblocksSignerConfig) -> Result<Self, SignerError> {
        let mut signer = FireblocksSigner::new(config)?;
        signer.init().await?;
        Ok(Self::Fireblocks(signer))
    }

    /// Create a GCP KMS signer (requires initialization)
    #[cfg(feature = "gcp_kms")]
    pub async fn from_gcp_kms(key_name: String, public_key: String) -> Result<Self, SignerError> {
        Ok(Self::GcpKms(
            GcpKmsSigner::from_config(GcpKmsSignerConfig {
                key_name,
                public_key,
            })
            .await?,
        ))
    }

    /// Create a Para signer (requires initialization)
    #[cfg(feature = "para")]
    pub async fn from_para(
        api_key: String,
        wallet_id: String,
        api_base_url: Option<String>,
    ) -> Result<Self, SignerError> {
        let mut signer = ParaSigner::from_config(ParaSignerConfig {
            api_key,
            wallet_id,
            api_base_url,
        })?;
        signer.init().await?;
        Ok(Self::Para(signer))
    }

    /// Create a CDP signer.
    ///
    /// Pass `None` for `http_client_config` to use default timeout settings.
    #[cfg(feature = "cdp")]
    pub fn from_cdp(
        api_key_id: String,
        api_key_secret: String,
        wallet_secret: String,
        address: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        Ok(Self::Cdp(CdpSigner::from_config(CdpSignerConfig {
            api_key_id,
            api_key_secret,
            wallet_secret,
            address,
            api_base_url: None,
            http_client_config,
        })?))
    }

    /// Create a Dfns signer (requires initialization)
    #[cfg(feature = "dfns")]
    pub async fn from_dfns(config: DfnsSignerConfig) -> Result<Self, SignerError> {
        let mut signer = DfnsSigner::new(config)?;
        signer.init().await?;
        Ok(Self::Dfns(signer))
    }

    /// Create a Crossmint signer (requires initialization)
    #[cfg(feature = "crossmint")]
    pub async fn from_crossmint(config: CrossmintSignerConfig) -> Result<Self, SignerError> {
        let mut signer = CrossmintSigner::new(config)?;
        signer.init().await?;
        Ok(Self::Crossmint(signer))
    }

    /// Create an Openfort backend wallet signer.
    ///
    /// Fetches the wallet's Solana address from `GET /v2/accounts/{account_id}`
    /// during initialization. Pass `None` for `http_client_config` to use
    /// default timeout settings.
    #[cfg(feature = "openfort")]
    pub async fn from_openfort(
        secret_key: String,
        account_id: String,
        wallet_secret: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        let mut signer = OpenfortSigner::from_config(OpenfortSignerConfig {
            secret_key,
            account_id,
            wallet_secret,
            api_base_url: None,
            http_client_config,
        })?;
        signer.init().await?;
        Ok(Self::Openfort(signer))
    }

    /// Create a Utila signer from an existing Solana wallet.
    ///
    /// Fetches the wallet's Solana address from Utila during initialization.
    #[cfg(feature = "utila")]
    pub async fn from_utila(config: UtilaSignerConfig) -> Result<Self, SignerError> {
        let mut signer = UtilaSigner::new(config)?;
        signer.init().await?;
        Ok(Self::Utila(signer))
    }

    /// Connect to a Ledger hardware wallet over USB-HID.
    ///
    /// `derivation_path` defaults to `m/44'/501'/0'` when `None` — Ledger Live's
    /// path, so the address matches the one the user sees and funds there. Set
    /// `confirm_pubkey_on_device` to display the derived address on-screen for
    /// the user to verify (use when registering an account, not when signing).
    /// `host_device_path` selects a specific device when several are attached;
    /// `None` requires exactly one.
    ///
    /// The device must be unlocked. If the Solana app is not open this will try
    /// to launch it for the user via the BOLOS dashboard.
    #[cfg(feature = "ledger")]
    pub async fn from_ledger(
        derivation_path: Option<&str>,
        confirm_pubkey_on_device: bool,
        host_device_path: Option<&str>,
    ) -> Result<Self, SignerError> {
        // `LedgerSigner::connect` blocks the calling thread on device I/O,
        // including waiting for a physical button press when
        // `confirm_pubkey_on_device` is set. Run it on the blocking pool so it
        // never stalls the async runtime.
        let derivation_path = derivation_path.map(str::to_string);
        let host_device_path = host_device_path.map(str::to_string);
        let signer = tokio::task::spawn_blocking(move || {
            LedgerSigner::connect(
                derivation_path.as_deref(),
                confirm_pubkey_on_device,
                host_device_path.as_deref(),
            )
        })
        .await
        .map_err(|e| SignerError::Other(format!("Ledger connect task failed: {e}")))??;
        Ok(Self::Ledger(signer))
    }

    /// Open a Ledger signer with an explicit [`LedgerConfig`].
    ///
    /// The knobs that matter for unattended use are
    /// [`LedgerConfig::signing_timeout`] and [`LedgerConfig::auto_open_app`];
    /// see that type for what each one costs.
    #[cfg(feature = "ledger")]
    pub async fn from_ledger_with(config: LedgerConfig) -> Result<Self, SignerError> {
        let signer = tokio::task::spawn_blocking(move || LedgerSigner::connect_with(config))
            .await
            .map_err(|e| SignerError::Other(format!("Ledger connect task failed: {e}")))??;
        Ok(Self::Ledger(signer))
    }

    /// Create a Fordefi signer.
    ///
    /// `config.public_key` is trusted as the vault's Solana address; construction
    /// performs no network calls. Set `config.chain` to use native Solana mode;
    /// leave it `None` for black-box mode (raw EdDSA signing, transaction
    /// assembled locally). Within native mode, `config.push_mode` selects whether
    /// Fordefi broadcasts the transaction ([`FordefiPushMode::Auto`], the default)
    /// or rewrites and signs it for the caller to send
    /// ([`FordefiPushMode::Manual`]).
    #[cfg(feature = "fordefi")]
    pub async fn from_fordefi(config: FordefiSignerConfig) -> Result<Self, SignerError> {
        Ok(match (config.chain.is_some(), config.push_mode) {
            (false, _) => Self::FordefiBlackBox(FordefiBlackBoxSigner::from_config(config).await?),
            (true, Some(FordefiPushMode::Manual)) => {
                Self::FordefiNativeManual(FordefiNativeManualSigner::from_config(config).await?)
            }
            (true, _) => {
                Self::FordefiNativeAuto(FordefiNativeAutoSigner::from_config(config).await?)
            }
        })
    }

    /// Sign `tx` and get it on chain with one call, whichever shape the signer has.
    ///
    /// A [`SendingSigner`] backend broadcasts through its provider, so its own
    /// signature identifies the transaction and `send` is never called; any
    /// other backend signs and `send` broadcasts the encoded wire transaction.
    /// A [`ModifyingSigner`] backend replaces `tx` with the transaction its
    /// signature covers, and `send` broadcasts that one. The crate has no RPC
    /// client, so the network hop is always caller-supplied.
    ///
    /// # Errors
    ///
    /// [`SignerError::SigningFailed`] when a broadcasting backend returns no
    /// signature, or when the transaction is still partially signed. Backend
    /// signing errors and anything `send` returns propagate unchanged.
    pub async fn sign_and_send<F, Fut>(
        &self,
        tx: &mut sdk_adapter::VersionedTransaction,
        send: F,
    ) -> Result<sdk_adapter::Signature, SignerError>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<sdk_adapter::Signature, SignerError>>,
    {
        match self.as_sending_signer() {
            Some(signer) => {
                send::require_broadcast_signature(signer.sign_and_send_transaction(tx).await?)
            }
            None => match self.as_transaction_signer() {
                Some(signer) => send::sign_and_send(signer, tx, send).await,
                None => match self.as_modifying_signer() {
                    Some(signer) => send::modify_and_send(signer, tx, send).await,
                    None => Err(SignerError::SigningFailed(
                        "This signer supports neither sign_transaction nor sign_and_send_transaction"
                            .to_string(),
                    )),
                },
            },
        }
    }

    /// The wrapped backend as a [`TransactionSigner`], or `None` when the
    /// provider broadcasts instead of returning signed bytes.
    pub fn as_transaction_signer(&self) -> Option<&dyn TransactionSigner> {
        match self {
            #[cfg(feature = "memory")]
            Signer::Memory(s) => Some(s),
            #[cfg(feature = "vault")]
            Signer::Vault(s) => Some(s),
            #[cfg(feature = "privy")]
            Signer::Privy(s) => Some(s),
            #[cfg(feature = "turnkey")]
            Signer::Turnkey(s) => Some(s),
            #[cfg(feature = "aws_kms")]
            Signer::AwsKms(s) => Some(s),
            #[cfg(feature = "fireblocks")]
            Signer::Fireblocks(s) => Some(s),
            #[cfg(feature = "gcp_kms")]
            Signer::GcpKms(s) => Some(s),
            #[cfg(feature = "cdp")]
            Signer::Cdp(s) => Some(s),
            #[cfg(feature = "dfns")]
            Signer::Dfns(s) => Some(s),
            #[cfg(feature = "openfort")]
            Signer::Openfort(s) => Some(s),
            #[cfg(feature = "para")]
            Signer::Para(s) => Some(s),
            #[cfg(feature = "utila")]
            Signer::Utila(s) => Some(s),
            #[cfg(feature = "fordefi")]
            Signer::FordefiBlackBox(s) => Some(s),
            #[cfg(feature = "ledger")]
            Signer::Ledger(s) => Some(s),
            #[cfg(feature = "crossmint")]
            Signer::Crossmint(_) => None,
            #[cfg(feature = "fordefi")]
            Signer::FordefiNativeAuto(_) => None,
            #[cfg(feature = "fordefi")]
            Signer::FordefiNativeManual(_) => None,
        }
    }

    /// The wrapped backend as a [`ModifyingSigner`], or `None` when the provider
    /// signs the bytes it was given.
    pub fn as_modifying_signer(&self) -> Option<&dyn ModifyingSigner> {
        match self {
            #[cfg(feature = "fordefi")]
            Signer::FordefiNativeManual(s) => Some(s),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// The wrapped backend as a [`SendingSigner`], or `None` when the caller
    /// broadcasts.
    pub fn as_sending_signer(&self) -> Option<&dyn SendingSigner> {
        match self {
            #[cfg(feature = "crossmint")]
            Signer::Crossmint(s) => Some(s),
            #[cfg(feature = "fordefi")]
            Signer::FordefiNativeAuto(s) => Some(s),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

macro_rules! dispatch_signer {
    ($self:ident, $signer:pat => $body:expr) => {
        match $self {
            #[cfg(feature = "memory")]
            Signer::Memory($signer) => $body,
            #[cfg(feature = "vault")]
            Signer::Vault($signer) => $body,
            #[cfg(feature = "privy")]
            Signer::Privy($signer) => $body,
            #[cfg(feature = "turnkey")]
            Signer::Turnkey($signer) => $body,
            #[cfg(feature = "aws_kms")]
            Signer::AwsKms($signer) => $body,
            #[cfg(feature = "fireblocks")]
            Signer::Fireblocks($signer) => $body,
            #[cfg(feature = "gcp_kms")]
            Signer::GcpKms($signer) => $body,
            #[cfg(feature = "cdp")]
            Signer::Cdp($signer) => $body,
            #[cfg(feature = "dfns")]
            Signer::Dfns($signer) => $body,
            #[cfg(feature = "openfort")]
            Signer::Openfort($signer) => $body,
            #[cfg(feature = "para")]
            Signer::Para($signer) => $body,
            #[cfg(feature = "crossmint")]
            Signer::Crossmint($signer) => $body,
            #[cfg(feature = "utila")]
            Signer::Utila($signer) => $body,
            #[cfg(feature = "fordefi")]
            Signer::FordefiBlackBox($signer) => $body,
            #[cfg(feature = "fordefi")]
            Signer::FordefiNativeAuto($signer) => $body,
            #[cfg(feature = "fordefi")]
            Signer::FordefiNativeManual($signer) => $body,
            #[cfg(feature = "ledger")]
            Signer::Ledger($signer) => $body,
        }
    };
}

#[async_trait::async_trait]
impl SolanaSigner for Signer {
    fn pubkey(&self) -> sdk_adapter::Pubkey {
        dispatch_signer!(self, s => s.pubkey())
    }

    async fn sign_message(&self, message: &[u8]) -> Result<sdk_adapter::Signature, SignerError> {
        dispatch_signer!(self, s => s.sign_message(message).await)
    }

    async fn is_available(&self) -> bool {
        dispatch_signer!(self, s => s.is_available().await)
    }
}

#[cfg(all(test, feature = "crossmint", feature = "memory"))]
mod signer_tests {
    use super::*;

    fn crossmint_signer() -> Signer {
        Signer::Crossmint(
            CrossmintSigner::new(CrossmintSignerConfig {
                api_key: "test-api-key".to_string(),
                wallet_locator: "test-wallet".to_string(),
                signer_secret: None,
                signer: None,
                api_base_url: Some("https://example.com".to_string()),
                poll_interval_ms: None,
                max_poll_attempts: None,
            })
            .unwrap(),
        )
    }

    fn memory_signer() -> Signer {
        const TEST_KEYPAIR_BYTES: &str = "[41,99,180,88,51,57,48,80,61,63,219,75,176,49,116,254,227,176,196,204,122,47,166,133,155,252,217,0,253,17,49,143,47,94,121,167,195,136,72,22,157,48,77,88,63,96,57,122,181,243,236,188,241,134,174,224,100,246,17,170,104,17,151,48]";
        Signer::Memory(
            MemorySigner::from_private_key_string(TEST_KEYPAIR_BYTES)
                .expect("test keypair must parse"),
        )
    }

    #[test]
    fn sending_backend_exposes_only_the_sending_capability() {
        let signer = crossmint_signer();
        assert!(signer.as_transaction_signer().is_none());
        assert!(signer.as_sending_signer().is_some());
    }

    #[test]
    fn transaction_backend_exposes_only_the_transaction_capability() {
        let signer = memory_signer();
        assert!(signer.as_transaction_signer().is_some());
        assert!(signer.as_sending_signer().is_none());
    }

    #[tokio::test]
    async fn unified_sign_and_send_routes_transaction_backend_through_the_caller_hop() {
        let signer = memory_signer();
        let mut tx = test_util::create_test_transaction(&signer.pubkey());
        let signature = signer
            .sign_and_send(&mut tx, |_encoded| async {
                Ok(sdk_adapter::Signature::from([7u8; 64]))
            })
            .await
            .unwrap();
        assert_eq!(signature, sdk_adapter::Signature::from([7u8; 64]));
    }
}
