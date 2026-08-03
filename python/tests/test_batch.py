import logging

import pytest

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.core import sign_batch_staggered, validate_request_delay_ms


def test_negative_delay_is_config_error() -> None:
    with pytest.raises(SignerError) as excinfo:
        validate_request_delay_ms(-1)
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_zero_and_moderate_delays_are_accepted() -> None:
    validate_request_delay_ms(0)
    validate_request_delay_ms(3000)


def test_oversized_delay_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="solana_keychain"):
        validate_request_delay_ms(3001)
    assert any("blockhash" in record.message for record in caplog.records)


async def test_sign_batch_staggered_preserves_order() -> None:
    async def sign(item: str, index: int) -> str:
        return f"{item}:{index}"

    results = await sign_batch_staggered(["a", "b", "c"], sign, delay_ms=0)
    assert results == ["a:0", "b:1", "c:2"]


async def test_sign_batch_staggered_delays_later_items() -> None:
    started: list[int] = []

    async def sign(item: str, index: int) -> str:
        started.append(index)
        return item

    await sign_batch_staggered(["a", "b"], sign, delay_ms=10)
    assert started == [0, 1]


async def test_sign_batch_staggered_empty() -> None:
    async def sign(item: str, index: int) -> str:
        return item

    assert await sign_batch_staggered([], sign, delay_ms=0) == []
