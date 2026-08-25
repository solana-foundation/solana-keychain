import pytest

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.core.wallet_jwt import compute_req_hash, extract_host


def test_extract_host_keeps_port_and_drops_path() -> None:
    assert extract_host("https://api.example.com", "Example") == "api.example.com"
    assert extract_host("https://api.example.com:8443/base", "Example") == "api.example.com:8443"


def test_extract_host_rejects_unparseable_url() -> None:
    with pytest.raises(SignerError) as excinfo:
        extract_host("not a url", "Example")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_compute_req_hash_is_none_for_absent_and_empty_bodies() -> None:
    assert compute_req_hash(None) is None
    assert compute_req_hash({}) is None


def test_compute_req_hash_is_key_order_independent() -> None:
    ordered = compute_req_hash({"a": 1, "b": {"c": 2, "d": 3}})
    assert ordered is not None
    assert ordered == compute_req_hash({"b": {"d": 3, "c": 2}, "a": 1})
