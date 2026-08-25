"""Attempt pacing for backends that poll a provider until a transaction settles."""

import asyncio
from collections.abc import AsyncIterator


async def poll_attempts(max_attempts: int, interval_ms: int) -> AsyncIterator[int]:
    """Yield attempt indices ``0..max_attempts-1``, sleeping ``interval_ms`` before
    every attempt but the first, so a caller that exhausts the loop reports its
    timeout without waiting out one more interval."""
    for attempt in range(max_attempts):
        if attempt:
            await asyncio.sleep(interval_ms / 1000)
        yield attempt
