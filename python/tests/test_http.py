import asyncio

import httpx
import pytest
import respx

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.core import (
    assert_https_url,
    fetch_signer_json,
    normalize_base_url,
    sanitize_remote_error_response,
)
from solana_keychain.core.http import probe_availability


def test_normalize_base_url_strips_whitespace_and_trailing_slashes() -> None:
    assert normalize_base_url("  https://vault.example.com///  ") == "https://vault.example.com"


def test_assert_https_url_accepts_https() -> None:
    assert_https_url("https://vault.example.com", "vault_addr")


@pytest.mark.parametrize("url", ["not a url", "https://example.com:bad"])
def test_assert_https_url_rejects_malformed_urls(url: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        assert_https_url(url, "vault_addr")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@pytest.mark.parametrize("url", ["http://api.example.com", "ftp://x.example.com"])
def test_assert_https_url_rejects_non_https(url: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        assert_https_url(url, "vault_addr")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_assert_https_url_allows_http_loopback_under_pytest_when_opted_in() -> None:
    assert_https_url("http://127.0.0.1:8200", "vault_addr", allow_http_loopback_in_tests=True)


def test_assert_https_url_rejects_http_loopback_without_opt_in() -> None:
    with pytest.raises(SignerError):
        assert_https_url("http://127.0.0.1:8200", "vault_addr")


def test_sanitize_strips_control_chars_and_collapses_whitespace() -> None:
    assert sanitize_remote_error_response("a\x00b\n\n  c\td") == "a b c d"


def test_sanitize_empty_response() -> None:
    assert sanitize_remote_error_response("\x00 \n") == "[empty remote response]"


def test_sanitize_truncates_long_payloads() -> None:
    sanitized = sanitize_remote_error_response("x" * 500)
    assert sanitized == "x" * 256 + " [truncated]"


URL = "https://api.example.com/endpoint"


@respx.mock
async def test_fetch_signer_json_returns_parsed_body() -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    assert await fetch_signer_json(url=URL, provider_name="Test") == {"ok": True}


@respx.mock
async def test_network_failure_is_http_error() -> None:
    respx.get(URL).mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(SignerError) as excinfo:
        await fetch_signer_json(url=URL, provider_name="Test")
    assert excinfo.value.code == SignerErrorCode.HTTP_ERROR


@respx.mock
async def test_redirect_is_rejected_as_http_error() -> None:
    respx.get(URL).mock(
        return_value=httpx.Response(302, headers={"location": "https://evil.example.com"})
    )
    with pytest.raises(SignerError) as excinfo:
        await fetch_signer_json(url=URL, provider_name="Test")
    assert excinfo.value.code == SignerErrorCode.HTTP_ERROR


@respx.mock
async def test_non_2xx_is_remote_api_error() -> None:
    respx.get(URL).mock(return_value=httpx.Response(500, text="secret-backend-detail"))
    with pytest.raises(SignerError) as excinfo:
        await fetch_signer_json(url=URL, provider_name="Test")
    error = excinfo.value
    assert error.code == SignerErrorCode.REMOTE_API_ERROR
    assert "secret-backend-detail" not in str(error)
    assert "secret-backend-detail" not in repr(error)


@respx.mock
async def test_invalid_json_is_parsing_error() -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, text="not json"))
    with pytest.raises(SignerError) as excinfo:
        await fetch_signer_json(url=URL, provider_name="Test")
    assert excinfo.value.code == SignerErrorCode.PARSING_ERROR


@respx.mock
async def test_caller_supplied_client_is_used_and_not_closed() -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json={"ok": 1}))
    async with httpx.AsyncClient() as client:
        assert await fetch_signer_json(
            url=URL, provider_name="Test", method="POST", json_body={"a": 1}, client=client
        ) == {"ok": 1}
        assert not client.is_closed


async def test_probe_availability_returns_the_probe_result() -> None:
    async def healthy() -> bool:
        return True

    async def unhealthy() -> bool:
        return False

    assert await probe_availability(healthy)
    assert not await probe_availability(unhealthy)


async def test_probe_availability_reports_unavailable_on_any_failure() -> None:
    async def signer_error() -> bool:
        raise SignerError(SignerErrorCode.HTTP_ERROR, "unreachable")

    async def credential_error() -> bool:
        raise RuntimeError("kms unavailable")

    assert not await probe_availability(signer_error)
    assert not await probe_availability(credential_error)


async def test_probe_availability_bounds_a_slow_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("solana_keychain.core.http.AVAILABILITY_TIMEOUT_SECONDS", 0.01)

    async def slow() -> bool:
        await asyncio.sleep(5)
        return True

    assert not await probe_availability(slow)
