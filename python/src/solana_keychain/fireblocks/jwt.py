"""Fireblocks JWT authentication helper."""

import hashlib
import time
import uuid
from typing import Any

try:
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.fireblocks requires the fireblocks extra: "
        "pip install 'solana-keychain[fireblocks]'"
    ) from error

from solana_keychain.core.errors import SignerError, SignerErrorCode

JWT_TTL_SECONDS = 120
JWT_SKEW_LEEWAY_SECONDS = 60


def parse_signing_key(private_key_pem: str) -> rsa.RSAPrivateKey:
    """Parse the Fireblocks RSA private key once for token reuse."""
    try:
        key = load_pem_private_key(private_key_pem.encode(), password=None)
    except Exception:
        raise SignerError(SignerErrorCode.INVALID_PRIVATE_KEY, "Failed to parse RSA key") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise SignerError(SignerErrorCode.INVALID_PRIVATE_KEY, "Failed to parse RSA key")
    return key


def create_jwt(api_key: str, signing_key: rsa.RSAPrivateKey, uri: str, body: str) -> str:
    """Create an RS256 request JWT: ``uri``, a fresh nonce, an issued-at backdated by
    the skew leeway, and ``bodyHash`` = SHA-256 hex of the exact request body (empty
    string for GET requests)."""
    now = int(time.time())
    issued_at = now - JWT_SKEW_LEEWAY_SECONDS
    claims: dict[str, Any] = {
        "uri": uri,
        "nonce": str(uuid.uuid4()),
        "iat": issued_at,
        "nbf": issued_at,
        "exp": now + JWT_TTL_SECONDS,
        "sub": api_key,
        "bodyHash": hashlib.sha256(body.encode()).hexdigest(),
    }
    try:
        return pyjwt.encode(claims, signing_key, algorithm="RS256")
    except Exception:
        raise SignerError(SignerErrorCode.SIGNING_FAILED, "Failed to create JWT") from None
