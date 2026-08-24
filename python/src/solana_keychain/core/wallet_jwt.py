"""ES256 wallet-auth JWT building for backends that stamp write requests with a
hash of the exact request body.

Requires ``pyjwt`` and ``cryptography``; import it from a backend module whose
extra provides them.
"""

import hashlib
import json
import time
import uuid
from typing import Any
from urllib.parse import urlsplit

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec

from solana_keychain.core.errors import SignerError, SignerErrorCode

WALLET_JWT_TTL_SECONDS = 120


def extract_host(base_url: str, provider_name: str) -> str:
    """Extract the request host (including port if present) from a base URL."""
    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR, f"Invalid {provider_name} base URL: {base_url}"
        ) from None
    if not hostname:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR, f"Missing host in {provider_name} base URL: {base_url}"
        )
    return f"{hostname}:{port}" if port is not None else hostname


def compute_req_hash(body: Any | None) -> str | None:
    """SHA-256 hex of the request body serialized with recursively sorted keys and
    compact separators; ``None`` for absent, null, or empty-object bodies."""
    if body is None or body == {}:
        return None
    serialized = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode()).hexdigest()


def create_es256_wallet_jwt(
    signing_key: ec.EllipticCurvePrivateKey,
    host: str,
    method: str,
    path: str,
    request_body: Any | None,
    provider_name: str,
) -> str:
    """Build an ES256 wallet-auth JWT scoped to a single request URI, carrying
    ``reqHash`` over the sorted request body when one is present."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "uris": [f"{method} {host}{path}"],
        "iat": now,
        "nbf": now,
        "exp": now + WALLET_JWT_TTL_SECONDS,
        "jti": str(uuid.uuid4()),
    }
    req_hash = compute_req_hash(request_body)
    if req_hash is not None:
        claims["reqHash"] = req_hash
    try:
        return pyjwt.encode(claims, signing_key, algorithm="ES256", headers={"typ": "JWT"})
    except Exception:
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED, f"Failed to create {provider_name} wallet JWT"
        ) from None
