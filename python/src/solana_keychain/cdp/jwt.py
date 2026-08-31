"""CDP JWT authentication helpers: an EdDSA bearer token for every request and an
ES256 wallet token for write endpoints."""

import base64
import time
import uuid
from typing import Any

try:
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_der_private_key

    from solana_keychain.core.wallet_jwt import create_es256_wallet_jwt
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.cdp requires the cdp extra: pip install 'solana-keychain[cdp]'"
    ) from error

from solders.keypair import Keypair

from solana_keychain.core.errors import SignerError, SignerErrorCode

JWT_TTL_SECONDS = 120
WALLET_JWT_TTL_SECONDS = 60

ED25519_KEYPAIR_LENGTH = 64


def jwt_uri(host: str, method: str, path: str) -> str:
    return f"{method} {host}{path}"


def _parse_ed25519_signing_key(api_key_secret: str) -> Ed25519PrivateKey:
    if api_key_secret.startswith("-----BEGIN"):
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY,
            "PEM EC keys are not supported; use base64 Ed25519 key",
        )
    try:
        key_bytes = base64.b64decode(api_key_secret, validate=True)
    except Exception:
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY,
            "Failed to decode Ed25519 private key from base64",
        ) from None
    if len(key_bytes) != ED25519_KEYPAIR_LENGTH:
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY,
            f"Invalid Ed25519 key length: expected {ED25519_KEYPAIR_LENGTH} bytes, "
            f"got {len(key_bytes)}",
        )
    seed, provided_pubkey = key_bytes[:32], key_bytes[32:]
    try:
        derived_pubkey = bytes(Keypair.from_seed(seed).pubkey())
    except Exception:
        raise SignerError(SignerErrorCode.INVALID_PRIVATE_KEY, "Invalid Ed25519 seed") from None
    if derived_pubkey != provided_pubkey:
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY, "Ed25519 public key does not match seed"
        )
    return Ed25519PrivateKey.from_private_bytes(seed)


def create_auth_jwt(api_key_id: str, api_key_secret: str, host: str, method: str, path: str) -> str:
    """Create the main CDP API authentication JWT (EdDSA over the request URI), with
    ``kid`` and a fresh ``nonce`` in the protected header for replay prevention."""
    signing_key = _parse_ed25519_signing_key(api_key_secret)
    now = int(time.time())
    claims = {
        "sub": api_key_id,
        "iss": "cdp",
        "iat": now,
        "nbf": now,
        "exp": now + JWT_TTL_SECONDS,
        "uris": [jwt_uri(host, method, path)],
    }
    try:
        return pyjwt.encode(
            claims,
            signing_key,
            algorithm="EdDSA",
            headers={"kid": api_key_id, "nonce": uuid.uuid4().hex, "typ": "JWT"},
        )
    except Exception:
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED, "Failed to create CDP authentication JWT"
        ) from None


def create_wallet_jwt(
    wallet_secret: str, host: str, method: str, path: str, request_body: Any | None
) -> str:
    """Create the CDP wallet authentication JWT (``X-Wallet-Auth``, ES256), carrying
    ``reqHash`` over the sorted request body when one is present."""
    try:
        der_bytes = base64.b64decode(wallet_secret, validate=True)
    except Exception:
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY, "Failed to decode walletSecret from base64"
        ) from None
    try:
        signing_key = load_der_private_key(der_bytes, password=None)
    except Exception:
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY,
            "Failed to parse walletSecret as EC private key",
        ) from None
    if not isinstance(signing_key, ec.EllipticCurvePrivateKey):
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY,
            "Failed to parse walletSecret as EC private key",
        )
    return create_es256_wallet_jwt(
        signing_key, host, method, path, request_body, "CDP", WALLET_JWT_TTL_SECONDS
    )
