"""Openfort wallet-auth JWT: an ES256 token signed by the project's wallet secret,
carrying a hash of the exact request body."""

import hashlib
import json
import time
import uuid
from typing import Any
from urllib.parse import urlsplit

try:
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.openfort requires the openfort extra: "
        "pip install 'solana-keychain[openfort]'"
    ) from error

from solana_keychain.core.errors import SignerError, SignerErrorCode

JWT_LIFETIME_SECONDS = 120


def extract_host(base_url: str) -> str:
    """Extract the request host (including port if present) from a base URL."""
    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR, f"Invalid Openfort base URL: {base_url}"
        ) from None
    if not hostname:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR, f"Missing host in Openfort base URL: {base_url}"
        )
    return f"{hostname}:{port}" if port is not None else hostname


def compute_req_hash(body: Any) -> str:
    """SHA-256 hex of the request body serialized with recursively sorted keys and
    compact separators."""
    serialized = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode()).hexdigest()


def _wallet_secret_to_pem(wallet_secret: str) -> str:
    """Accept either a full PEM (passed through) or a bare base64 PKCS8 DER body
    (the env-var-friendly single-line form), which gets whitespace-stripped and
    wrapped in PEM headers."""
    if wallet_secret.lstrip().startswith("-----BEGIN"):
        return wallet_secret
    stripped = "".join(wallet_secret.split())
    return f"-----BEGIN PRIVATE KEY-----\n{stripped}\n-----END PRIVATE KEY-----\n"


def create_wallet_jwt(
    wallet_secret: str, host: str, method: str, path: str, request_body: Any
) -> str:
    """Build the ``x-wallet-auth`` JWT for an Openfort backend wallet request."""
    pem = _wallet_secret_to_pem(wallet_secret)
    try:
        signing_key = load_pem_private_key(pem.encode(), password=None)
    except Exception:
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY,
            "Failed to parse Openfort wallet secret as EC P-256 private key "
            "(expected base64 PKCS#8 DER or PEM)",
        ) from None
    if not isinstance(signing_key, ec.EllipticCurvePrivateKey):
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY,
            "Failed to parse Openfort wallet secret as EC P-256 private key "
            "(expected base64 PKCS#8 DER or PEM)",
        )

    now = int(time.time())
    claims = {
        "uris": [f"{method} {host}{path}"],
        "iat": now,
        "nbf": now,
        "exp": now + JWT_LIFETIME_SECONDS,
        "jti": str(uuid.uuid4()),
        "reqHash": compute_req_hash(request_body),
    }
    try:
        return pyjwt.encode(claims, signing_key, algorithm="ES256", headers={"typ": "JWT"})
    except Exception:
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED, "Failed to create Openfort wallet JWT"
        ) from None
