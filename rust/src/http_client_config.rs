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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_are_applied_when_unset() {
        let config = HttpClientConfig::default();
        assert_eq!(
            config.resolved_request_timeout(),
            HttpClientConfig::DEFAULT_REQUEST_TIMEOUT
        );
        assert_eq!(
            config.resolved_connect_timeout(),
            HttpClientConfig::DEFAULT_CONNECT_TIMEOUT
        );
    }

    #[test]
    fn test_custom_values_override_defaults() {
        let config = HttpClientConfig {
            request_timeout: Some(Duration::from_secs(42)),
            connect_timeout: Some(Duration::from_secs(7)),
        };
        assert_eq!(config.resolved_request_timeout(), Duration::from_secs(42));
        assert_eq!(config.resolved_connect_timeout(), Duration::from_secs(7));
    }
}
