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

/// Percent-encode `input` so it can be interpolated into a URL as a single
/// path segment: every byte outside the unreserved set is escaped, including
/// `/`, `?`, `#` and `.`-only sequences that would otherwise let a configured
/// identifier retarget the request path.
#[cfg(any(
    feature = "crossmint",
    feature = "dfns",
    feature = "openfort",
    feature = "utila"
))]
pub(crate) fn encode_uri_component(input: &str) -> String {
    use std::fmt::Write;

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
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

/// Maximum number of response-body bytes read from a remote signer API
/// (1 MiB, matching Go's `core.MaxResponseBytes`).
pub(crate) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Read a response body in chunks, refusing anything larger than
/// [`MAX_RESPONSE_BYTES`] so a hostile or broken endpoint cannot exhaust
/// memory. Every remote-signer body read must go through this instead of
/// `Response::text()`/`bytes()`/`json()`.
pub(crate) async fn read_body_capped(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, SignerError> {
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(SignerError::SerializationError(
                "response exceeded maximum size".to_string(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Consume a failed response into a [`SignerError::RemoteApiError`], logging
/// the status (and, under `unsafe-debug` only, the response body).
pub(crate) async fn extract_api_error(response: reqwest::Response, context: &str) -> SignerError {
    let status = response.status().as_u16();

    #[cfg(feature = "unsafe-debug")]
    {
        let error_text = match read_body_capped(response).await {
            Ok(body) => String::from_utf8_lossy(&body).into_owned(),
            Err(_) => "Failed to read error response".to_string(),
        };
        log::error!("{context} error - status: {status}, response: {error_text}");
    }

    #[cfg(not(feature = "unsafe-debug"))]
    {
        let _ = response;
        log::error!("{context} error - status: {status}");
    }

    SignerError::remote_api(format!("{context} error {status}"))
}

/// The top-level `id` of a response body, when there is one. A provider that
/// has already accepted a transaction may still answer with a non-2xx status or
/// an otherwise unusable body, and that id is the caller's only handle for
/// reconciling it.
#[cfg(any(feature = "crossmint", feature = "fireblocks", feature = "fordefi"))]
pub(crate) fn transaction_id_in_body(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .map(str::to_string)
}

/// [`extract_api_error`] plus any transaction id the failed body named, for a
/// create whose acceptance the caller still has to reconcile.
#[cfg(feature = "fordefi")]
pub(crate) async fn extract_api_error_with_transaction_id(
    response: reqwest::Response,
    context: &str,
) -> (SignerError, Option<String>) {
    let status = response.status().as_u16();
    let body = read_body_capped(response).await.unwrap_or_default();

    #[cfg(feature = "unsafe-debug")]
    log::error!(
        "{context} error - status: {status}, response: {}",
        String::from_utf8_lossy(&body)
    );
    #[cfg(not(feature = "unsafe-debug"))]
    log::error!("{context} error - status: {status}");

    (
        SignerError::remote_api(format!("{context} error {status}")),
        transaction_id_in_body(&body),
    )
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

    let body = read_body_capped(response).await?;
    serde_json::from_slice(&body).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to parse {context} response: {_e}");
        SignerError::SerializationError(format!("Failed to parse {context} response"))
    })
}

#[cfg(test)]
mod tests;
