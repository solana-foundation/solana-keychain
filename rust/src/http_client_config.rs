//! Shared HTTP timeout configuration for remote signers.

use std::time::Duration;

/// Optional timeout settings for signer HTTP clients.
///
/// Unset values fall back to:
/// - request timeout: 30 seconds
/// - connect timeout: 5 seconds
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HttpClientConfig {
    pub request_timeout: Option<Duration>,
    pub connect_timeout: Option<Duration>,
}

impl HttpClientConfig {
    pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    pub fn resolved_request_timeout(&self) -> Duration {
        self.request_timeout
            .unwrap_or(Self::DEFAULT_REQUEST_TIMEOUT)
    }

    pub fn resolved_connect_timeout(&self) -> Duration {
        self.connect_timeout
            .unwrap_or(Self::DEFAULT_CONNECT_TIMEOUT)
    }

    /// Shared `reqwest` builder for every remote-signer client: resolved
    /// timeouts, HTTPS-only, and a policy that refuses every redirect.
    ///
    /// Backends must start from this builder so no client silently regains
    /// reqwest's default redirect-following, which would replay
    /// provider-specific credential headers (X-Vault-Token, X-Stamp,
    /// X-API-KEY, ...) to the redirect target: reqwest only strips the four
    /// standard sensitive headers on a cross-host hop.
    #[cfg(any(
        feature = "vault",
        feature = "privy",
        feature = "turnkey",
        feature = "fireblocks",
        feature = "cdp",
        feature = "dfns",
        feature = "para",
        feature = "crossmint",
        feature = "openfort",
        feature = "utila",
        feature = "fordefi"
    ))]
    pub(crate) fn client_builder(&self) -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .timeout(self.resolved_request_timeout())
            .connect_timeout(self.resolved_connect_timeout())
            .https_only(true)
            .redirect(no_redirect_policy())
    }

    /// `client_builder()` finished into a client, with the error mapped to
    /// [`SignerError::ConfigError`].
    #[cfg(any(
        feature = "vault",
        feature = "privy",
        feature = "turnkey",
        feature = "fireblocks",
        feature = "cdp",
        feature = "dfns",
        feature = "para",
        feature = "crossmint",
        feature = "openfort",
        feature = "utila",
        feature = "fordefi"
    ))]
    pub(crate) fn build_client(&self) -> Result<reqwest::Client, crate::error::SignerError> {
        self.client_builder().build().map_err(|e| {
            crate::error::SignerError::ConfigError(format!("Failed to build HTTP client: {e}"))
        })
    }
}

/// A redirect policy that fails the request instead of following.
///
/// Deliberately an error rather than `Policy::none()`: with `none()` the 3xx
/// comes back as a normal response and status-code branches would try to parse
/// its body, reporting a misleading error.
#[cfg(any(
    feature = "vault",
    feature = "privy",
    feature = "turnkey",
    feature = "fireblocks",
    feature = "cdp",
    feature = "dfns",
    feature = "para",
    feature = "crossmint",
    feature = "openfort",
    feature = "utila",
    feature = "fordefi"
))]
pub(crate) fn no_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        attempt.error("redirects are not followed: a signer request carries provider credentials")
    })
}

#[cfg(test)]
mod tests;
