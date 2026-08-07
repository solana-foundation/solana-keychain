"""Pluggable API-request signer for Fordefi's ``x-signature`` header."""

import base64
from abc import ABC, abstractmethod

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.fordefi requires the fordefi extra: pip install 'solana-keychain[fordefi]'"
    ) from error

from solana_keychain.core.errors import SignerError, SignerErrorCode


class FordefiRequestSigner(ABC):
    """Signs Fordefi API-request payloads for the ``x-signature`` header.

    Implementations receive the fully-formatted payload
    (``{path}|{timestamp}|{body}``) and must return the exact base64 value
    Fordefi expects: base64 of the DER-encoded ECDSA P-256 signature over
    ``SHA-256(payload)``. Implement this interface to keep the request key in
    a KMS/HSM instead of handing over raw PEM material.
    """

    @abstractmethod
    async def sign_request(self, payload: bytes) -> str:
        """Sign ``payload`` and return the base64-encoded ``x-signature`` value."""


class PemRequestSigner(FordefiRequestSigner):
    """Built-in request signer backed by a PEM-encoded ECDSA P-256 private key.

    Supports both PKCS#8 and SEC1 (EC) PEM encodings.
    """

    def __init__(self, private_key_pem: str) -> None:
        try:
            key = load_pem_private_key(private_key_pem.encode(), password=None)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PRIVATE_KEY,
                "Failed to parse PEM as an ECDSA P-256 key",
            ) from None
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise SignerError(
                SignerErrorCode.INVALID_PRIVATE_KEY,
                "Failed to parse PEM as an ECDSA P-256 key",
            )
        self._key = key

    async def sign_request(self, payload: bytes) -> str:
        signature = self._key.sign(payload, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode("ascii")
