from typing import Any
from unittest.mock import AsyncMock, patch

from solana_keychain.core.poll import poll_attempts


async def test_yields_every_attempt_and_sleeps_only_between_them() -> None:
    with patch("solana_keychain.core.poll.asyncio.sleep", new=AsyncMock()) as sleep:
        attempts = [attempt async for attempt in poll_attempts(3, 250)]
    assert attempts == [0, 1, 2]
    assert sleep.await_count == 2
    assert sleep.await_args_list[0].args == (0.25,)


async def test_caller_breaking_early_does_not_sleep_again() -> None:
    with patch("solana_keychain.core.poll.asyncio.sleep", new=AsyncMock()) as sleep:
        async for _ in poll_attempts(10, 1000):
            break
    assert sleep.await_count == 0


async def test_single_attempt_never_sleeps() -> None:
    calls: list[Any] = []
    with patch("solana_keychain.core.poll.asyncio.sleep", new=AsyncMock(side_effect=calls.append)):
        assert [attempt async for attempt in poll_attempts(1, 5000)] == [0]
    assert calls == []
