//! Shared HTTP response handling for remote signer backends.

use crate::error::SignerError;

/// Reject an API base URL that is not valid HTTPS, parsing it rather than
/// string-matching so `HTTPS://`, whitespace, and malformed URLs are all
/// caught.
#[cfg(any(feature = "crossmint", feature = "para"))]
pub(crate) fn validate_https_url(url: &str) -> Result<(), SignerError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| SignerError::ConfigError("api_base_url is not a valid URL".to_string()))?;
    if parsed.scheme() != "https" {
        return Err(SignerError::ConfigError(
            "api_base_url must use HTTPS".to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(feature = "fireblocks", feature = "fordefi"))]
pub(crate) enum PollOutcome<T> {
    Done(T),
    Pending,
}

/// Run `attempt` up to `max_attempts` times, sleeping `interval_ms` between
/// tries (never after the last, so the timeout error is not delayed).
/// `attempt` classifies each response itself: `Done` returns, `Pending`
/// retries, and a terminal failure is any `Err`.
#[cfg(any(feature = "fireblocks", feature = "fordefi"))]
pub(crate) async fn poll_until<T, F, Fut>(
    max_attempts: u32,
    interval_ms: u64,
    timeout_error: impl FnOnce() -> SignerError,
    mut attempt: F,
) -> Result<T, SignerError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<PollOutcome<T>, SignerError>>,
{
    for i in 0..max_attempts {
        if i > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
        }
        match attempt().await? {
            PollOutcome::Done(value) => return Ok(value),
            PollOutcome::Pending => {}
        }
    }
    Err(timeout_error())
}

/// Consume a failed response into a [`SignerError::RemoteApiError`], logging
/// the status (and, under `unsafe-debug` only, the response body).
pub(crate) async fn extract_api_error(response: reqwest::Response, context: &str) -> SignerError {
    let status = response.status().as_u16();

    #[cfg(feature = "unsafe-debug")]
    {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error response".to_string());
        log::error!("{context} error - status: {status}, response: {error_text}");
    }

    #[cfg(not(feature = "unsafe-debug"))]
    {
        let _ = response;
        log::error!("{context} error - status: {status}");
    }

    SignerError::RemoteApiError(format!("{context} error {status}"))
}

/// Reject a non-success response via [`extract_api_error`], then parse the
/// body as JSON.
pub(crate) async fn parse_json_response<T>(
    response: reqwest::Response,
    context: &str,
) -> Result<T, SignerError>
where
    T: serde::de::DeserializeOwned,
{
    if !response.status().is_success() {
        return Err(extract_api_error(response, context).await);
    }

    let text = response.text().await.unwrap_or_default();
    serde_json::from_str(&text).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to parse {context} response: {_e}");
        SignerError::SerializationError(format!("Failed to parse {context} response"))
    })
}
