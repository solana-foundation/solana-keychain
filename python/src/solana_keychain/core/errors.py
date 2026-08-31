"""Error types for signer operations."""

from enum import Enum, unique
from typing import Any, TypedDict, cast

from solders.signature import Signature


@unique
class SignerErrorCode(str, Enum):
    """Stable, machine-readable error codes for every signer failure mode."""

    BROADCAST_UNCONFIRMED = "SIGNER_BROADCAST_UNCONFIRMED"
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
    SignerErrorCode.BROADCAST_UNCONFIRMED: (
        "Broadcast unconfirmed; the provider may have executed the transaction"
    ),
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


class _SignerErrorPickleState(TypedDict):
    provider_transaction_id: str | None
    status_code: int | None
    idempotency_key: str | None
    transaction_signature: Signature | None


class SignerError(Exception):
    """Unified error raised by every signer operation.

    Security: ``str()``, ``repr()``, and ``args`` only ever expose the fixed generic
    message for the code. The per-error ``detail`` is kept private so key material and
    raw remote-API responses cannot leak through formatted output or logs.

    ``status_code`` is the remote HTTP status when the failure came from a response,
    and ``None`` otherwise.

    ``idempotency_key`` is the key an ambiguous create was submitted under, when the
    backend sends one. With no ``provider_transaction_id`` to check, resending the
    identical bytes under that key is the only recovery that cannot double-spend.

    ``transaction_signature`` identifies the completed transaction supplied to a
    caller-managed broadcast whose outcome could not be confirmed.
    """

    def __init__(
        self,
        code: SignerErrorCode,
        detail: str = "",
        *,
        provider_transaction_id: str | None = None,
        status_code: int | None = None,
        idempotency_key: str | None = None,
        transaction_signature: Signature | None = None,
    ) -> None:
        message = _GENERIC_MESSAGES[code]
        if provider_transaction_id is not None:
            message += f" (provider transaction id: {provider_transaction_id})"
        super().__init__(message)
        self.code = code
        self._detail = detail
        self.provider_transaction_id = provider_transaction_id
        self.status_code = status_code
        self.idempotency_key = idempotency_key
        self.transaction_signature = transaction_signature

    def __repr__(self) -> str:
        return f"SignerError({self.code.value})"

    def __reduce__(
        self,
    ) -> tuple[type["SignerError"], tuple[SignerErrorCode], _SignerErrorPickleState]:
        state = _SignerErrorPickleState(
            provider_transaction_id=self.provider_transaction_id,
            status_code=self.status_code,
            idempotency_key=self.idempotency_key,
            transaction_signature=self.transaction_signature,
        )
        return (SignerError, (self.code,), state)

    def __setstate__(self, state: dict[str, Any] | None) -> None:
        if state is None:
            return
        self.provider_transaction_id = cast(str | None, state["provider_transaction_id"])
        self.status_code = cast(int | None, state["status_code"])
        self.idempotency_key = cast(str | None, state["idempotency_key"])
        self.transaction_signature = cast(Signature | None, state["transaction_signature"])
