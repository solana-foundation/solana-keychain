"""Concurrent batch-signing helpers with per-request stagger."""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from typing import TypeVar

from solana_keychain.core.errors import SignerError, SignerErrorCode

MAX_RECOMMENDED_REQUEST_DELAY_MS = 3000

_logger = logging.getLogger("solana_keychain")

TItem = TypeVar("TItem")
TResult = TypeVar("TResult")


def validate_request_delay_ms(request_delay_ms: int) -> None:
    """Validate a backend's ``request_delay_ms`` config value.

    Raises ``CONFIG_ERROR`` when negative; warns when the delay is large enough to
    risk blockhash expiration across a staggered batch.
    """
    if request_delay_ms < 0:
        raise SignerError(SignerErrorCode.CONFIG_ERROR, "request_delay_ms must not be negative")
    if request_delay_ms > MAX_RECOMMENDED_REQUEST_DELAY_MS:
        _logger.warning(
            "request_delay_ms is greater than %dms, this may result in blockhash "
            "expiration errors for signing messages/transactions",
            MAX_RECOMMENDED_REQUEST_DELAY_MS,
        )


async def sign_batch_staggered(
    items: Sequence[TItem],
    fn: Callable[[TItem, int], Awaitable[TResult]],
    delay_ms: int,
) -> list[TResult]:
    """Run ``fn`` concurrently over ``items``, staggering the start of each item by
    ``index * delay_ms`` to avoid remote API rate limits. With ``delay_ms`` of 0 this
    is a plain gather. Results keep the input order."""

    async def run(item: TItem, index: int) -> TResult:
        if delay_ms > 0 and index > 0:
            await asyncio.sleep(index * delay_ms / 1000)
        return await fn(item, index)

    return list(await asyncio.gather(*(run(item, i) for i, item in enumerate(items))))
