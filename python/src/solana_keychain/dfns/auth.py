"""Dfns User Action Signing flow: mutating API requests require a challenge to be
signed with a registered credential key and exchanged for a one-time user-action
token."""

import base64
import json
from typing import Any

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.dfns requires the dfns extra: pip install 'solana-keychain[dfns]'"
    ) from error

import httpx

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.http import fetch_signer_json


def sign_challenge(private_key_pem: str, data: bytes) -> bytes:
    """Sign challenge data with an Ed25519, P-256, or RSA private key in PEM format
    (PKCS8 or SEC1). Ed25519 yields the raw 64-byte signature, P-256 a DER-encoded
    ECDSA-SHA256 signature, RSA a PKCS1v15-SHA256 signature."""
    invalid = SignerError(
        SignerErrorCode.INVALID_PRIVATE_KEY,
        "Unsupported PEM key type (expected Ed25519, P256, or RSA)",
    )
    try:
        key = load_pem_private_key(private_key_pem.encode(), password=None)
    except Exception:
        raise invalid from None
    if isinstance(key, Ed25519PrivateKey):
        return key.sign(data)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise invalid
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    raise invalid


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def format_client_data(challenge: str) -> bytes:
    """The exact bytes signed for a key credential assertion: a compact JSON object
    with ``challenge`` before ``type``. The byte layout is part of the assertion —
    the server verifies the signature over precisely these bytes."""
    return json.dumps({"challenge": challenge, "type": "key.get"}, separators=(",", ":")).encode()


async def sign_user_action(
    *,
    api_base_url: str,
    auth_token: str,
    cred_id: str,
    private_key_pem: str,
    http_method: str,
    http_path: str,
    body: str,
    client: httpx.AsyncClient | None,
) -> str:
    """Perform the User Action Signing flow and return the token for the
    ``x-dfns-useraction`` header."""
    headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}

    challenge_response = await fetch_signer_json(
        url=f"{api_base_url}/auth/action/init",
        provider_name="Dfns",
        method="POST",
        headers=headers,
        json_body={
            "userActionPayload": body,
            "userActionHttpMethod": http_method,
            "userActionHttpPath": http_path,
            "userActionServerKind": "Api",
        },
        client=client,
    )
    if not isinstance(challenge_response, dict):
        raise SignerError(
            SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse action init response"
        )
    challenge = challenge_response.get("challenge")
    challenge_identifier = challenge_response.get("challengeIdentifier")
    if not isinstance(challenge, str) or not isinstance(challenge_identifier, str):
        raise SignerError(
            SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse action init response"
        )

    allowed: list[Any] = []
    allow_credentials = challenge_response.get("allowCredentials")
    if isinstance(allow_credentials, dict) and isinstance(allow_credentials.get("key"), list):
        allowed = allow_credentials["key"]
    if not any(isinstance(c, dict) and c.get("id") == cred_id for c in allowed):
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR, f"Credential {cred_id} not in allowed credentials"
        )

    client_data = format_client_data(challenge)
    signature = sign_challenge(private_key_pem, client_data)

    action_response = await fetch_signer_json(
        url=f"{api_base_url}/auth/action",
        provider_name="Dfns",
        method="POST",
        headers=headers,
        json_body={
            "challengeIdentifier": challenge_identifier,
            "firstFactor": {
                "kind": "Key",
                "credentialAssertion": {
                    "credId": cred_id,
                    "clientData": _b64url_no_pad(client_data),
                    "signature": _b64url_no_pad(signature),
                },
            },
        },
        client=client,
    )
    user_action = action_response.get("userAction") if isinstance(action_response, dict) else None
    if not isinstance(user_action, str):
        raise SignerError(SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse action response")
    return user_action
