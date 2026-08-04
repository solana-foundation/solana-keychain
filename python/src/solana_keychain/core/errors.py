"""Error types for signer operations."""

from enum import Enum, unique


@unique
class SignerErrorCode(str, Enum):
    """Stable, machine-readable error codes for every signer failure mode."""

    CONFIG_ERROR = "SIGNER_CONFIG_ERROR"
    EXPECTED_SOLANA_SIGNER = "SIGNER_EXPECTED_SOLANA_SIGNER"
    HTTP_ERROR = "SIGNER_HTTP_ERROR"
    INVALID_PRIVATE_KEY = "SIGNER_INVALID_PRIVATE_KEY"
    INVALID_PUBLIC_KEY = "SIGNER_INVALID_PUBLIC_KEY"
    IO_ERROR = "SIGNER_IO_ERROR"
    NOT_AVAILABLE = "SIGNER_NOT_AVAILABLE"
    NOT_INITIALIZED = "SIGNER_NOT_INITIALIZED"
    OTHER = "SIGNER_ERROR"
    PARSING_ERROR = "SIGNER_PARSING_ERROR"
    REMOTE_API_ERROR = "SIGNER_REMOTE_API_ERROR"
    SERIALIZATION_ERROR = "SIGNER_SERIALIZATION_ERROR"
    SIGNING_FAILED = "SIGNER_SIGNING_FAILED"


_GENERIC_MESSAGES: dict[SignerErrorCode, str] = {
    SignerErrorCode.CONFIG_ERROR: "Configuration error",
    SignerErrorCode.EXPECTED_SOLANA_SIGNER: "Expected a Solana signer",
    SignerErrorCode.HTTP_ERROR: "HTTP request failed",
    SignerErrorCode.INVALID_PRIVATE_KEY: "Invalid private key format",
    SignerErrorCode.INVALID_PUBLIC_KEY: "Invalid public key",
    SignerErrorCode.IO_ERROR: "IO error",
    SignerErrorCode.NOT_AVAILABLE: "Signer not available",
    SignerErrorCode.NOT_INITIALIZED: "Signer not initialized",
    SignerErrorCode.OTHER: "Signer error",
    SignerErrorCode.PARSING_ERROR: "Parsing error",
    SignerErrorCode.REMOTE_API_ERROR: "Remote API error",
    SignerErrorCode.SERIALIZATION_ERROR: "Serialization error",
    SignerErrorCode.SIGNING_FAILED: "Signing failed",
}


class SignerError(Exception):
    """Unified error raised by every signer operation.

    Security: ``str()``, ``repr()``, and ``args`` only ever expose the fixed generic
    message for the code. The per-error ``detail`` is kept private so key material and
    raw remote-API responses cannot leak through formatted output or logs.
    """

    def __init__(self, code: SignerErrorCode, detail: str = "") -> None:
        super().__init__(_GENERIC_MESSAGES[code])
        self.code = code
        self._detail = detail

    def __repr__(self) -> str:
        return f"SignerError({self.code.value})"

    def __reduce__(self) -> tuple[type["SignerError"], tuple[SignerErrorCode]]:
        return (SignerError, (self.code,))
