import pytest

from solana_keychain import SignerError, SignerErrorCode

SECRET = "sensitive-secret-material"

EXPECTED_GENERIC_MESSAGES = {
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


@pytest.mark.parametrize("code", list(SignerErrorCode))
def test_detail_is_redacted_from_all_output_channels(code: SignerErrorCode) -> None:
    error = SignerError(code, SECRET)
    assert SECRET not in str(error)
    assert SECRET not in repr(error)
    assert all(SECRET not in str(arg) for arg in error.args)


@pytest.mark.parametrize("code", list(SignerErrorCode))
def test_generic_messages_are_stable(code: SignerErrorCode) -> None:
    assert str(SignerError(code, "x")) == EXPECTED_GENERIC_MESSAGES[code]


def test_code_values_match_cross_language_contract() -> None:
    assert {code.value for code in SignerErrorCode} == {
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
