import pickle

import pytest
from solders.signature import Signature

from solana_keychain import SignerError, SignerErrorCode

SECRET = "sensitive-secret-material"

EXPECTED_GENERIC_MESSAGES = {
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


def test_detail_is_redacted_from_all_output_channels() -> None:
    # Redaction is code-independent; per-code messages are covered below.
    error = SignerError(SignerErrorCode.REMOTE_API_ERROR, SECRET)
    assert SECRET not in str(error)
    assert SECRET not in repr(error)
    assert all(SECRET not in str(arg) for arg in error.args)


@pytest.mark.parametrize("code", list(SignerErrorCode))
def test_generic_messages_are_stable(code: SignerErrorCode) -> None:
    assert str(SignerError(code, "x")) == EXPECTED_GENERIC_MESSAGES[code]


def test_pickle_round_trip_preserves_code_and_redacts_detail() -> None:
    error = SignerError(SignerErrorCode.CONFIG_ERROR, SECRET)

    payload = pickle.dumps(error)
    assert SECRET.encode() not in payload

    restored = pickle.loads(payload)
    assert isinstance(restored, SignerError)
    assert restored.code == SignerErrorCode.CONFIG_ERROR
    assert str(restored) == str(error)


def test_pickle_round_trip_preserves_recovery_metadata() -> None:
    transaction_signature = Signature.from_bytes(bytes([7] * 64))
    error = SignerError(
        SignerErrorCode.BROADCAST_UNCONFIRMED,
        SECRET,
        provider_transaction_id="provider-tx-123",
        status_code=503,
        idempotency_key="idempotency-key-123",
        transaction_signature=transaction_signature,
    )

    payload = pickle.dumps(error)
    assert SECRET.encode() not in payload

    restored = pickle.loads(payload)
    assert restored.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert restored.provider_transaction_id == "provider-tx-123"
    assert restored.status_code == 503
    assert restored.idempotency_key == "idempotency-key-123"
    assert restored.transaction_signature == transaction_signature
    assert restored._detail == ""


def test_code_values_are_frozen() -> None:
    assert {code.value for code in SignerErrorCode} == {
        "SIGNER_BROADCAST_UNCONFIRMED",
        "SIGNER_CONFIG_ERROR",
        "SIGNER_ERROR",
        "SIGNER_EXPECTED_SOLANA_SIGNER",
        "SIGNER_HTTP_ERROR",
        "SIGNER_INVALID_PRIVATE_KEY",
        "SIGNER_INVALID_PUBLIC_KEY",
        "SIGNER_IO_ERROR",
        "SIGNER_NOT_AVAILABLE",
        "SIGNER_NOT_INITIALIZED",
        "SIGNER_PARSING_ERROR",
        "SIGNER_REMOTE_API_ERROR",
        "SIGNER_SERIALIZATION_ERROR",
        "SIGNER_SIGNING_FAILED",
    }


def test_broadcast_unconfirmed_surfaces_tx_id_but_not_detail() -> None:
    error = SignerError(
        SignerErrorCode.BROADCAST_UNCONFIRMED,
        SECRET,
        provider_transaction_id="provider-tx-123",
    )
    assert error.provider_transaction_id == "provider-tx-123"
    assert "provider-tx-123" in str(error)
    assert SECRET not in str(error)
    assert SECRET not in repr(error)
