"""Privy wallet-authorization signatures."""

import base64
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        load_der_private_key,
        load_pem_private_key,
    )
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.privy requires the privy extra: pip install 'solana-keychain[privy]'"
    ) from error

from solana_keychain.core.errors import SignerError, SignerErrorCode

DEFAULT_AUTHORIZATION_REQUEST_EXPIRY_MS = 15 * 60 * 1000

PrivyAuthorizationSignFn = Callable[[bytes], str]


@dataclass
class PrivyAuthorizationContext:
    """Key material for Privy wallet-authorization signatures.

    ``authorization_private_keys`` are base64 PKCS8 P-256 private keys exported by
    Privy (``wallet-auth:`` and ``wallet-api:`` prefixes accepted, PEM supported).
    ``signatures`` are precomputed base64 authorization signatures for the exact
    request. ``sign_fns`` are external signers that receive the canonical payload
    bytes and return a base64 signature.
    """

    authorization_private_keys: list[str] = field(default_factory=list, repr=False)
    signatures: list[str] = field(default_factory=list, repr=False)
    sign_fns: list[PrivyAuthorizationSignFn] = field(default_factory=list, repr=False)


PrivyAuthorizationContextProvider = Callable[[dict[str, Any]], PrivyAuthorizationContext | None]
PrivyAuthorizationConfig = PrivyAuthorizationContext | PrivyAuthorizationContextProvider


def format_authorization_signature_payload(request: dict[str, Any]) -> bytes:
    """Serialize the authorization request to its canonical signed form: recursively
    sorted keys, compact separators, and an empty ``body`` object replaced by ``""``."""
    value = dict(request)
    body = value.get("body")
    if isinstance(body, dict) and not body:
        value["body"] = ""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _parse_p256_private_key(authorization_private_key: str) -> ec.EllipticCurvePrivateKey:
    normalized = authorization_private_key
    for prefix in ("wallet-auth:", "wallet-api:"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    normalized = normalized.strip()

    if "-----BEGIN" in normalized:
        pem = normalized.replace("\\n", "\n")
        try:
            key = load_pem_private_key(pem.encode(), password=None)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PRIVATE_KEY, "Invalid Privy authorization private key"
            ) from None
    else:
        compact = "".join(normalized.split())
        try:
            der = base64.b64decode(compact, validate=True)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PRIVATE_KEY,
                "Invalid Privy authorization private key encoding",
            ) from None
        try:
            key = load_der_private_key(der, password=None)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PRIVATE_KEY, "Invalid Privy authorization private key"
            ) from None

    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY, "Invalid Privy authorization private key"
        )
    return key


def generate_authorization_signatures(
    request: dict[str, Any], authorization_context: PrivyAuthorizationContext
) -> list[str]:
    """Produce base64 DER ECDSA signatures over the canonical payload, preserving
    the order: precomputed signatures, then private keys, then sign functions."""
    payload = format_authorization_signature_payload(request)
    signatures = list(authorization_context.signatures)
    for private_key in authorization_context.authorization_private_keys:
        signing_key = _parse_p256_private_key(private_key)
        der_signature = signing_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        signatures.append(base64.b64encode(der_signature).decode("ascii"))
    for sign_fn in authorization_context.sign_fns:
        signatures.append(sign_fn(payload))
    return signatures


def prepare_authorization_headers(
    *,
    app_id: str,
    authorization_config: PrivyAuthorizationConfig | None,
    method: str,
    url: str,
    body: dict[str, Any],
    request_expiry_ms: int | None,
) -> tuple[str | None, str | None]:
    """Build the (``privy-authorization-signature``, ``privy-request-expiry``) header
    values, or ``(None, None)`` when no authorization context is configured."""
    if authorization_config is None:
        return (None, None)

    request_expiry = (
        str(int(time.time() * 1000) + request_expiry_ms) if request_expiry_ms is not None else None
    )
    headers = {"privy-app-id": app_id}
    if request_expiry is not None:
        headers["privy-request-expiry"] = request_expiry

    request: dict[str, Any] = {
        "version": 1,
        "method": method,
        "url": url,
        "body": body,
        "headers": headers,
    }

    context = (
        authorization_config
        if isinstance(authorization_config, PrivyAuthorizationContext)
        else authorization_config(request)
    )
    if context is None:
        return (None, None)

    signatures = generate_authorization_signatures(request, context)
    if not signatures:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR,
            "authorization_context must include authorization_private_keys, signatures, "
            "or sign_fns",
        )
    return (",".join(signatures), request_expiry)
