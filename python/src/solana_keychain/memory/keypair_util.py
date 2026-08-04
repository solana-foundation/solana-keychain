"""Utility functions for parsing private keys in multiple formats."""

import json
from pathlib import Path

from solders.keypair import Keypair

from solana_keychain.core.errors import SignerError, SignerErrorCode

PRIVATE_KEY_LENGTH = 64
SEED_LENGTH = 32


def keypair_from_bytes(private_key: bytes) -> Keypair:
    """Build a keypair from raw bytes: 64 bytes (seed ‖ pubkey, the Solana CLI layout,
    with the public half validated against the seed) or 32 bytes (seed only; the
    public key is derived)."""
    if len(private_key) == SEED_LENGTH:
        try:
            return Keypair.from_seed(private_key)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PRIVATE_KEY, "Invalid private key bytes"
            ) from None
    if len(private_key) != PRIVATE_KEY_LENGTH:
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY,
            f"Private key must be {SEED_LENGTH} (seed) or {PRIVATE_KEY_LENGTH} "
            f"(seed ‖ pubkey) bytes, got {len(private_key)}",
        )
    return _keypair_from_64_bytes(private_key)


def _keypair_from_64_bytes(private_key: bytes) -> Keypair:
    try:
        return Keypair.from_bytes(private_key)
    except Exception:
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY, "Invalid private key bytes"
        ) from None


def keypair_from_private_key_string(private_key: str) -> Keypair:
    """Parse a private key string, auto-detecting the format:

    - U8Array form: ``"[1, 2, ..., 64]"`` (Solana CLI keypair JSON, inline)
    - Otherwise: base58

    String forms must always decode to exactly 64 bytes.
    """
    trimmed = private_key.strip()
    if trimmed.startswith("[") and trimmed.endswith("]"):
        return keypair_from_u8_array_string(trimmed)
    return keypair_from_base58(trimmed)


def keypair_from_base58(private_key: str) -> Keypair:
    """Parse a base58-encoded 64-byte private key."""
    try:
        return Keypair.from_base58_string(private_key)
    except Exception:
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY, "Invalid private key format"
        ) from None


def keypair_from_u8_array_string(array_str: str) -> Keypair:
    """Parse a u8-array string of the form ``"[1, 2, ..., 64]"``."""
    trimmed = array_str.strip()
    if not (trimmed.startswith("[") and trimmed.endswith("]")):
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY,
            "U8Array string must start with '[' and end with ']'",
        )
    inner = trimmed[1:-1]
    if not inner.strip():
        raise SignerError(SignerErrorCode.INVALID_PRIVATE_KEY, "U8Array string cannot be empty")
    try:
        byte_values = bytes(int(part.strip()) for part in inner.split(","))
    except ValueError:
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY, "Invalid U8Array private key format"
        ) from None
    if len(byte_values) != PRIVATE_KEY_LENGTH:
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY,
            f"Private key must be exactly {PRIVATE_KEY_LENGTH} bytes, got {len(byte_values)}",
        )
    return _keypair_from_64_bytes(byte_values)


def keypair_from_json_keypair(json_content: str) -> Keypair:
    """Parse Solana CLI keypair JSON file content (a JSON array of 64 bytes)."""
    invalid = SignerError(
        SignerErrorCode.INVALID_PRIVATE_KEY,
        "Invalid JSON keypair format. Expected a JSON array of 64 bytes",
    )
    try:
        parsed = json.loads(json_content)
    except json.JSONDecodeError:
        raise invalid from None
    if not isinstance(parsed, list) or not all(
        isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255
        for value in parsed
    ):
        raise invalid
    if len(parsed) != PRIVATE_KEY_LENGTH:
        raise SignerError(
            SignerErrorCode.INVALID_PRIVATE_KEY,
            f"JSON keypair must be exactly {PRIVATE_KEY_LENGTH} bytes, got {len(parsed)}",
        )
    return _keypair_from_64_bytes(bytes(parsed))


def keypair_from_private_key_file(path: str) -> Keypair:
    """Read a Solana CLI keypair JSON file from disk."""
    try:
        content = Path(path).read_text()
    except (OSError, UnicodeDecodeError):
        # UnicodeDecodeError.args embeds the raw file bytes — never let it propagate.
        raise SignerError(SignerErrorCode.IO_ERROR, "Failed to read private key file") from None
    return keypair_from_json_keypair(content)
