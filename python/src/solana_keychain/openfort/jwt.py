"""Openfort wallet-auth JWT: an ES256 token signed by the project's wallet secret,
carrying a hash of the exact request body."""

from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    from solana_keychain.core.wallet_jwt import create_es256_wallet_jwt
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.openfort requires the openfort extra: "
        "pip install 'solana-keychain[openfort]'"
    ) from error

from solana_keychain.core.errors import SignerError, SignerErrorCode


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
    return create_es256_wallet_jwt(signing_key, host, method, path, request_body, "Openfort")
