//! Shared HTTP response handling for remote signer backends.

use crate::error::SignerError;

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
