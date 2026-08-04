"""Crossmint delegated-signer key derivation."""

try:
    import base58
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.crossmint requires the crossmint extra: "
        "pip install 'solana-keychain[crossmint]'"
    ) from error

from solders.keypair import Keypair

from solana_keychain.core.errors import SignerError, SignerErrorCode

SIGNER_SECRET_HEX_LENGTH = 64


def parse_api_key(api_key: str) -> tuple[str, str]:
    """Extract ``(project_id, environment)`` from a Crossmint API key of the form
    ``{ck|sk}_{environment}_{base58data}`` where the base58 data decodes to UTF-8
    ``projectId:nacl_signature``."""
    parts = api_key.split("_", 2)
    if len(parts) != 3:
        raise SignerError(SignerErrorCode.CONFIG_ERROR, "Invalid API key format")
    environment, base58_data = parts[1], parts[2]
    try:
        decoded = base58.b58decode(base58_data).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise SignerError(SignerErrorCode.CONFIG_ERROR, "Failed to decode API key data") from None
    project_id = decoded.split(":", 1)[0]
    if not project_id:
        raise SignerError(SignerErrorCode.CONFIG_ERROR, "Could not extract projectId from API key")
    return project_id, environment


def derive_signing_key(secret: str, api_key: str) -> Keypair:
    """Derive the server delegated-signer Ed25519 keypair from an ``xmsk1_``-prefixed
    64-hex-char secret via HKDF-SHA256 (salt ``crossmint``, info
    ``{projectId}:{environment}:solana-ed25519``)."""
    project_id, environment = parse_api_key(api_key)

    raw_secret = secret.removeprefix("xmsk1_")
    if len(raw_secret) != SIGNER_SECRET_HEX_LENGTH:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR,
            f"signer_secret must be a {SIGNER_SECRET_HEX_LENGTH}-char hex string "
            f"(got {len(raw_secret)})",
        )
    try:
        ikm = bytes.fromhex(raw_secret)
    except ValueError:
        raise SignerError(SignerErrorCode.CONFIG_ERROR, "signer_secret is not valid hex") from None

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"crossmint",
        info=f"{project_id}:{environment}:solana-ed25519".encode(),
    )
    return Keypair.from_seed(hkdf.derive(ikm))
