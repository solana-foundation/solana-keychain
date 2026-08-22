from types import SimpleNamespace
from typing import Any

import pytest
from google.api_core.exceptions import PermissionDenied
from google.cloud import kms_v1
from solders.keypair import Keypair

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.core import signed_message_bytes
from solana_keychain.gcp_kms import GcpKmsSigner, GcpKmsSignerConfig, create_gcp_kms_signer
from tests.util import create_test_transaction

TEST_KEY_NAME = (
    "projects/test-project/locations/us-east1/keyRings/test-ring/"
    "cryptoKeys/test-key/cryptoKeyVersions/1"
)
EC_SIGN_ED25519 = kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_ED25519
RSA_SIGN_PKCS1_2048_SHA256 = (
    kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256
)


class StubKmsClient:
    def __init__(
        self,
        signature: bytes | None = None,
        sign_error: Exception | None = None,
        algorithm: Any = EC_SIGN_ED25519,
        key_error: Exception | None = None,
    ) -> None:
        self.signature = signature
        self.sign_error = sign_error
        self.algorithm = algorithm
        self.key_error = key_error
        self.sign_requests: list[dict[str, Any]] = []
        self.key_requests: list[dict[str, Any]] = []

    async def asymmetric_sign(self, request: dict[str, Any]) -> Any:
        self.sign_requests.append(request)
        if self.sign_error is not None:
            raise self.sign_error
        return SimpleNamespace(signature=self.signature)

    async def get_public_key(self, request: dict[str, Any]) -> Any:
        self.key_requests.append(request)
        if self.key_error is not None:
            raise self.key_error
        return SimpleNamespace(algorithm=self.algorithm)


def make_signer(pubkey: str, client: StubKmsClient) -> GcpKmsSigner:
    return GcpKmsSigner(
        GcpKmsSignerConfig(key_name=TEST_KEY_NAME, public_key=pubkey, client=client)
    )


@pytest.mark.parametrize("invalid", ["not-a-valid-pubkey", ""])
def test_invalid_pubkey_rejected_before_any_gcp_call(invalid: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(invalid, StubKmsClient())
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


def test_repr_shows_key_name_and_pubkey() -> None:
    keypair = Keypair()
    signer = make_signer(str(keypair.pubkey()), StubKmsClient())
    assert repr(signer) == f"GcpKmsSigner(key_name={TEST_KEY_NAME}, pubkey={keypair.pubkey()})"


async def test_create_gcp_kms_signer_factory() -> None:
    keypair = Keypair()
    signer = await create_gcp_kms_signer(
        GcpKmsSignerConfig(
            key_name=TEST_KEY_NAME, public_key=str(keypair.pubkey()), client=StubKmsClient()
        )
    )
    assert signer.pubkey == keypair.pubkey()


async def test_sign_message_sends_raw_data() -> None:
    keypair = Keypair()
    message = b"gcp-kms-message"
    signature = keypair.sign_message(message)
    client = StubKmsClient(signature=bytes(signature))
    signer = make_signer(str(keypair.pubkey()), client)

    result = await signer.sign_message(message)

    assert result == signature
    assert client.sign_requests == [{"name": TEST_KEY_NAME, "data": message}]


async def test_sign_message_api_error() -> None:
    keypair = Keypair()
    client = StubKmsClient(sign_error=PermissionDenied("denied"))
    signer = make_signer(str(keypair.pubkey()), client)

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


async def test_sign_message_empty_signature() -> None:
    keypair = Keypair()
    client = StubKmsClient(signature=b"")
    signer = make_signer(str(keypair.pubkey()), client)

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


async def test_sign_message_wrong_signature_length() -> None:
    keypair = Keypair()
    client = StubKmsClient(signature=bytes(32))
    signer = make_signer(str(keypair.pubkey()), client)

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


async def test_sign_message_signature_verification_failure() -> None:
    signing_keypair = Keypair()
    other_keypair = Keypair()
    message = b"gcp-kms-message"
    client = StubKmsClient(signature=bytes(signing_keypair.sign_message(message)))
    signer = make_signer(str(other_keypair.pubkey()), client)

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(message)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


async def test_sign_transaction_success() -> None:
    keypair = Keypair()
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(signed_message_bytes(transaction.message))
    client = StubKmsClient(signature=bytes(signature))
    signer = make_signer(str(keypair.pubkey()), client)

    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == signature
    assert list(transaction.signatures) == [signature]


async def test_is_available_success() -> None:
    keypair = Keypair()
    client = StubKmsClient()
    signer = make_signer(str(keypair.pubkey()), client)

    assert await signer.is_available()
    assert client.key_requests == [{"name": TEST_KEY_NAME}]


async def test_is_available_false_for_non_ed25519_algorithm() -> None:
    keypair = Keypair()
    client = StubKmsClient(algorithm=RSA_SIGN_PKCS1_2048_SHA256)
    signer = make_signer(str(keypair.pubkey()), client)

    assert not await signer.is_available()


async def test_is_available_false_on_api_error() -> None:
    keypair = Keypair()
    client = StubKmsClient(key_error=PermissionDenied("denied"))
    signer = make_signer(str(keypair.pubkey()), client)

    assert not await signer.is_available()
