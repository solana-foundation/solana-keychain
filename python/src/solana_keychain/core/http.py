"""HTTPS-enforcing HTTP pipeline for remote signer backends."""

import asyncio
import json
import os
import re
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from solana_keychain.core.errors import SignerError, SignerErrorCode

DEFAULT_REQUEST_TIMEOUT_SECONDS = 60.0
AVAILABILITY_TIMEOUT_SECONDS = 5.0
DEFAULT_REMOTE_ERROR_RESPONSE_MAX_LENGTH = 256
MAX_RESPONSE_BYTES = 1024 * 1024

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


async def probe_availability(probe: Callable[[], Awaitable[bool]]) -> bool:
    """Run a backend health probe under the shared availability timeout.

    Any failure means unavailable: a signer error, a timeout, or an exception from
    caller-supplied credential machinery all report ``False`` rather than raising,
    since the contract returns a bool. Cancellation still propagates.
    """
    try:
        return await asyncio.wait_for(probe(), AVAILABILITY_TIMEOUT_SECONDS)
    except Exception:
        return False


def provider_may_have_accepted(status_code: int | None) -> bool:
    """A 4xx other than 408 is the only create outcome that rules out a transaction;
    anything else (no response, timeout, 5xx, unusable success body) may already be
    executing. A 408 is a timeout reached while the request was being processed, so it
    does not rule the transaction out either.
    """
    return status_code is None or status_code == 408 or not 400 <= status_code < 500


async def fetch_signer_json(
    *,
    url: str,
    provider_name: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    json_body: Any | None = None,
    content: bytes | None = None,
    timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    client: httpx.AsyncClient | None = None,
) -> Any:
    """Perform a remote signer API request and parse the JSON response, mapping
    failures to the standard signer error pipeline:

    - network failure or timeout → ``HTTP_ERROR``
    - any redirect → ``HTTP_ERROR`` (auth headers must never replay against a
      redirect target)
    - non-2xx status → ``REMOTE_API_ERROR`` with the sanitized response body in
      the (redacted) detail
    - invalid JSON body → ``PARSING_ERROR``
    - body larger than ``MAX_RESPONSE_BYTES`` → ``PARSING_ERROR``

    ``json_body`` and ``content`` are mutually exclusive. Use ``content`` when the
    request bytes must match a signature computed over them exactly (request-stamping
    auth schemes) — re-serialization would change the bytes.

    When ``client`` is provided the caller owns its lifecycle and transport policy
    (custom TLS, proxies); otherwise a one-shot client is used.
    """
    if json_body is not None and content is not None:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR, "json_body and content are mutually exclusive"
        )
    if client is not None:
        return await _request_json(
            client,
            url=url,
            provider_name=provider_name,
            method=method,
            headers=headers,
            json_body=json_body,
            content=content,
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
            content=content,
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
    content: bytes | None,
    timeout_seconds: float,
) -> Any:
    request = client.build_request(
        method,
        url,
        headers=headers,
        json=json_body,
        content=content,
        timeout=timeout_seconds,
    )
    try:
        response = await client.send(request, stream=True, follow_redirects=False)
    except httpx.HTTPError as error:
        raise SignerError(
            SignerErrorCode.HTTP_ERROR, f"{provider_name} network request failed: {error}"
        ) from None
    try:
        if 300 <= response.status_code < 400:
            raise SignerError(
                SignerErrorCode.HTTP_ERROR, f"{provider_name} response was a redirect"
            )
        body = await _read_bounded_body(response, provider_name)
    finally:
        await response.aclose()
    if not response.is_success:
        error_text = body.decode(response.encoding or "utf-8", errors="replace")
        raise SignerError(
            SignerErrorCode.REMOTE_API_ERROR,
            f"{provider_name} API error: {response.status_code}: "
            f"{sanitize_remote_error_response(error_text)}",
            provider_transaction_id=_transaction_id_in_body(body),
            status_code=response.status_code,
        )
    try:
        return json.loads(body)
    except ValueError:
        raise SignerError(
            SignerErrorCode.PARSING_ERROR, f"Failed to parse {provider_name} response"
        ) from None


def _transaction_id_in_body(body: bytes) -> str | None:
    """The top-level ``id`` of a failed response body, when there is one.

    A provider that has already accepted a transaction may still answer with a
    non-2xx status, and that id is the caller's only handle for reconciling it.
    """
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    if isinstance(parsed, dict):
        transaction_id = parsed.get("id")
        if isinstance(transaction_id, str) and transaction_id.strip():
            return transaction_id
    return None


async def _read_bounded_body(response: httpx.Response, provider_name: str) -> bytes:
    """Stream the response body, never buffering more than ``MAX_RESPONSE_BYTES``.

    Applies to success and error bodies alike so a misbehaving remote cannot
    exhaust memory before the status/JSON handling sees the payload.
    """
    body = bytearray()
    try:
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise SignerError(
                    SignerErrorCode.PARSING_ERROR,
                    f"{provider_name} response exceeded maximum size",
                )
    except httpx.HTTPError as error:
        raise SignerError(
            SignerErrorCode.HTTP_ERROR, f"{provider_name} network request failed: {error}"
        ) from None
    return bytes(body)
