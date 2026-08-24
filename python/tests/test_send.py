import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core import (
    SignedTransaction,
    SignerError,
    SignerErrorCode,
    SolanaSigner,
    sign_and_send_transaction,
)
from tests.util import create_test_transaction

ENCODED = "encoded-transaction"
SIGNATURE = Signature.default()


class StubSigner(SolanaSigner):
    def __init__(self, *, broadcasts: bool, is_complete: bool) -> None:
        self._broadcasts = broadcasts
        self._is_complete = is_complete
        self._pubkey = Keypair().pubkey()

    @property
    def pubkey(self) -> Pubkey:
        return self._pubkey

    @property
    def broadcasts_transactions(self) -> bool:
        return self._broadcasts

    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        return SignedTransaction(
            encoded_transaction=ENCODED,
            signature=SIGNATURE,
            is_complete=self._is_complete,
        )

    async def sign_message(self, message: bytes) -> Signature:
        return SIGNATURE

    async def is_available(self) -> bool:
        return True


async def test_broadcasting_signer_skips_the_injected_sender() -> None:
    """A provider that broadcasts server-side has already put the transaction on
    chain, so its own signature identifies it."""
    signer = StubSigner(broadcasts=True, is_complete=True)

    async def send(encoded: str) -> Signature:
        raise AssertionError("send must not run for a signer that broadcasts")

    signature = await sign_and_send_transaction(
        signer, create_test_transaction(signer.pubkey), send
    )
    assert signature == SIGNATURE


async def test_sign_only_signer_broadcasts_the_encoded_transaction() -> None:
    signer = StubSigner(broadcasts=False, is_complete=True)
    sent: list[str] = []
    broadcast_signature = Signature.from_bytes(bytes([1] * 64))

    async def send(encoded: str) -> Signature:
        sent.append(encoded)
        return broadcast_signature

    signature = await sign_and_send_transaction(
        signer, create_test_transaction(signer.pubkey), send
    )
    assert sent == [ENCODED]
    assert signature == broadcast_signature


async def test_missing_sender_is_rejected_before_signing() -> None:
    """A signature the caller cannot broadcast is a wasted remote signing request."""
    signer = StubSigner(broadcasts=False, is_complete=True)

    with pytest.raises(SignerError) as excinfo:
        await sign_and_send_transaction(signer, create_test_transaction(signer.pubkey))
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


async def test_partial_signature_is_rejected_before_broadcast() -> None:
    """A partially signed transaction cannot land, so it must never be broadcast."""
    signer = StubSigner(broadcasts=False, is_complete=False)

    async def send(encoded: str) -> Signature:
        raise AssertionError("send must not run for a partially signed transaction")

    with pytest.raises(SignerError) as excinfo:
        await sign_and_send_transaction(signer, create_test_transaction(signer.pubkey), send)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
