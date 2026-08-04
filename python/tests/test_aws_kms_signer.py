from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from solders.keypair import Keypair

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.aws_kms import AwsKmsSigner, AwsKmsSignerConfig, create_aws_kms_signer
from tests.util import create_test_transaction

TEST_KEY_ID = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
TEST_REGION = "us-east-1"


def make_stubbed_signer(pubkey: str) -> tuple[AwsKmsSigner, Stubber]:
    client = boto3.client(
        "kms",
        region_name=TEST_REGION,
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )
    stubber = Stubber(client)
    signer = AwsKmsSigner(AwsKmsSignerConfig(key_id=TEST_KEY_ID, public_key=pubkey, client=client))
    return signer, stubber


def expected_sign_params(message: bytes) -> dict[str, Any]:
    return {
        "KeyId": TEST_KEY_ID,
        "Message": message,
        "MessageType": "RAW",
        "SigningAlgorithm": "ED25519_SHA_512",
    }


def sign_response(signature: bytes) -> dict[str, Any]:
    return {"KeyId": TEST_KEY_ID, "Signature": signature, "SigningAlgorithm": "ED25519_SHA_512"}


def key_metadata_response(
    key_spec: str = "ECC_NIST_EDWARDS25519", enabled: bool = True, key_usage: str = "SIGN_VERIFY"
) -> dict[str, Any]:
    return {
        "KeyMetadata": {
            "KeyId": "12345678-1234-1234-1234-123456789012",
            "KeySpec": key_spec,
            "Enabled": enabled,
            "KeyUsage": key_usage,
        }
    }


@pytest.mark.parametrize("invalid", ["not-a-valid-pubkey", ""])
def test_invalid_pubkey_rejected_before_any_aws_call(invalid: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        AwsKmsSigner(AwsKmsSignerConfig(key_id=TEST_KEY_ID, public_key=invalid))
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


@pytest.mark.parametrize(
    "key_id",
    [
        TEST_KEY_ID,
        "12345678-1234-1234-1234-123456789012",
        "alias/my-key",
    ],
)
def test_key_id_variations_accepted(key_id: str) -> None:
    keypair = Keypair()
    signer = AwsKmsSigner(
        AwsKmsSignerConfig(key_id=key_id, public_key=str(keypair.pubkey()), region=TEST_REGION)
    )
    assert signer.key_id == key_id
    assert signer.pubkey == keypair.pubkey()


def test_repr_shows_key_id_pubkey_region_only() -> None:
    keypair = Keypair()
    signer, _ = make_stubbed_signer(str(keypair.pubkey()))
    assert (
        repr(signer)
        == f"AwsKmsSigner(key_id={TEST_KEY_ID}, pubkey={keypair.pubkey()}, region=None)"
    )


async def test_create_aws_kms_signer_factory() -> None:
    keypair = Keypair()
    signer = await create_aws_kms_signer(
        AwsKmsSignerConfig(key_id=TEST_KEY_ID, public_key=str(keypair.pubkey()), region=TEST_REGION)
    )
    assert signer.pubkey == keypair.pubkey()


async def test_sign_message_success() -> None:
    keypair = Keypair()
    message = b"aws-kms-message"
    signature = keypair.sign_message(message)
    signer, stubber = make_stubbed_signer(str(keypair.pubkey()))
    stubber.add_response("sign", sign_response(bytes(signature)), expected_sign_params(message))

    with stubber:
        result = await signer.sign_message(message)

    assert result == signature


async def test_sign_message_api_error() -> None:
    keypair = Keypair()
    signer, stubber = make_stubbed_signer(str(keypair.pubkey()))
    stubber.add_client_error("sign", service_error_code="AccessDeniedException")

    with stubber:
        with pytest.raises(SignerError) as excinfo:
            await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


async def test_sign_message_wrong_signature_length() -> None:
    keypair = Keypair()
    message = b"hello"
    signer, stubber = make_stubbed_signer(str(keypair.pubkey()))
    stubber.add_response("sign", sign_response(bytes(32)), expected_sign_params(message))

    with stubber:
        with pytest.raises(SignerError) as excinfo:
            await signer.sign_message(message)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


async def test_sign_message_signature_verification_failure() -> None:
    signing_keypair = Keypair()
    other_keypair = Keypair()
    message = b"aws-kms-message"
    signature = signing_keypair.sign_message(message)
    signer, stubber = make_stubbed_signer(str(other_keypair.pubkey()))
    stubber.add_response("sign", sign_response(bytes(signature)), expected_sign_params(message))

    with stubber:
        with pytest.raises(SignerError) as excinfo:
            await signer.sign_message(message)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


async def test_sign_transaction_success() -> None:
    keypair = Keypair()
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(transaction.message_data())
    signer, stubber = make_stubbed_signer(str(keypair.pubkey()))
    stubber.add_response(
        "sign",
        sign_response(bytes(signature)),
        expected_sign_params(transaction.message_data()),
    )

    with stubber:
        result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == signature
    assert list(transaction.signatures) == [signature]


async def test_is_available_success() -> None:
    keypair = Keypair()
    signer, stubber = make_stubbed_signer(str(keypair.pubkey()))
    stubber.add_response("describe_key", key_metadata_response(), {"KeyId": TEST_KEY_ID})

    with stubber:
        assert await signer.is_available()


@pytest.mark.parametrize(
    "metadata_kwargs",
    [
        {"key_spec": "RSA_2048"},
        {"enabled": False},
        {"key_usage": "ENCRYPT_DECRYPT"},
    ],
)
async def test_is_available_false_for_unusable_key(metadata_kwargs: dict[str, Any]) -> None:
    keypair = Keypair()
    signer, stubber = make_stubbed_signer(str(keypair.pubkey()))
    stubber.add_response(
        "describe_key", key_metadata_response(**metadata_kwargs), {"KeyId": TEST_KEY_ID}
    )

    with stubber:
        assert not await signer.is_available()


async def test_is_available_false_on_api_error() -> None:
    keypair = Keypair()
    signer, stubber = make_stubbed_signer(str(keypair.pubkey()))
    stubber.add_client_error("describe_key", service_error_code="NotFoundException")

    with stubber:
        assert not await signer.is_available()
