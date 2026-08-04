"""HTTPS-enforcing HTTP pipeline for remote signer backends."""

import os
import re
from typing import Any
from urllib.parse import urlsplit

import httpx

from solana_keychain.core.errors import SignerError, SignerErrorCode

DEFAULT_REQUEST_TIMEOUT_SECONDS = 60.0
DEFAULT_REMOTE_ERROR_RESPONSE_MAX_LENGTH = 256

_LOOPBACK_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "::1"})
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalize_base_url(base_url: str) -> str:
    """Trim surrounding whitespace and strip trailing slashes so paths can be
    appended with a single ``/``."""
    return base_url.strip().rstrip("/")


def assert_https_url(url: str, field: str, *, allow_http_loopback_in_tests: bool = False) -> None:
    """Validate that a configured endpoint is a well-formed HTTPS URL — the security
    control behind the library's "HTTPS enforced" guarantee; every remote backend must
    run its base URL through this check.

    ``allow_http_loopback_in_tests`` permits plain-HTTP loopback URLs
    (localhost / 127.0.0.1 / ::1) while running under pytest, for backends whose
    integration tests target a local dev server.
    """
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        # Accessing ``port`` forces urllib to validate the authority's port syntax
        # and range rather than deferring the failure to httpx.
        _ = parsed.port
    except ValueError:
        raise SignerError(SignerErrorCode.CONFIG_ERROR, f"{field} is not a valid URL") from None
    if not hostname:
        raise SignerError(SignerErrorCode.CONFIG_ERROR, f"{field} is not a valid URL")
    if parsed.scheme == "https":
        return
    if (
        allow_http_loopback_in_tests
        and parsed.scheme == "http"
        and hostname in _LOOPBACK_HOSTNAMES
        and "PYTEST_CURRENT_TEST" in os.environ
    ):
        return
    raise SignerError(SignerErrorCode.CONFIG_ERROR, f"{field} must use HTTPS")


def sanitize_remote_error_response(
    response_text: str, max_length: int = DEFAULT_REMOTE_ERROR_RESPONSE_MAX_LENGTH
) -> str:
    """Sanitize remote API error text before attaching it to error detail: strips
    control characters, collapses whitespace, truncates long payloads."""
    normalized = " ".join(_CONTROL_CHARS.sub(" ", response_text).split())
    if not normalized:
        return "[empty remote response]"
    if len(normalized) <= max_length:
        return normalized
    return f"{normalized[:max_length]} [truncated]"


async def fetch_signer_json(
    *,
    url: str,
    provider_name: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    json_body: Any | None = None,
    timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    client: httpx.AsyncClient | None = None,
) -> Any:
    """Perform a remote signer API request and parse the JSON response, mapping
    failures to the standard signer error pipeline (parity with the TS
    ``fetchSignerJson`` and the Go core HTTP client):

    - network failure or timeout → ``HTTP_ERROR``
    - any redirect → ``HTTP_ERROR`` (auth headers must never replay against a
      redirect target)
    - non-2xx status → ``REMOTE_API_ERROR`` with the sanitized response body in
      the (redacted) detail
    - invalid JSON body → ``PARSING_ERROR``

    When ``client`` is provided the caller owns its lifecycle and transport policy
    (custom TLS, proxies); otherwise a one-shot client is used.
    """
    if client is not None:
        return await _request_json(
            client,
            url=url,
            provider_name=provider_name,
            method=method,
            headers=headers,
            json_body=json_body,
            timeout_seconds=timeout_seconds,
        )
    async with httpx.AsyncClient() as own_client:
        return await _request_json(
            own_client,
            url=url,
            provider_name=provider_name,
            method=method,
            headers=headers,
            json_body=json_body,
            timeout_seconds=timeout_seconds,
        )


async def _request_json(
    client: httpx.AsyncClient,
    *,
    url: str,
    provider_name: str,
    method: str,
    headers: dict[str, str] | None,
    json_body: Any | None,
    timeout_seconds: float,
) -> Any:
    try:
        response = await client.request(
            method,
            url,
            headers=headers,
            json=json_body,
            timeout=timeout_seconds,
            follow_redirects=False,
        )
    except httpx.HTTPError as error:
        raise SignerError(
            SignerErrorCode.HTTP_ERROR, f"{provider_name} network request failed: {error}"
        ) from None
    if 300 <= response.status_code < 400:
        raise SignerError(SignerErrorCode.HTTP_ERROR, f"{provider_name} response was a redirect")
    if not response.is_success:
        raise SignerError(
            SignerErrorCode.REMOTE_API_ERROR,
            f"{provider_name} API error: {response.status_code}: "
            f"{sanitize_remote_error_response(response.text)}",
        )
    try:
        return response.json()
    except ValueError:
        raise SignerError(
            SignerErrorCode.PARSING_ERROR, f"Failed to parse {provider_name} response"
        ) from None
