import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core import (
    ModifyingSigner,
    SendingSigner,
    SignedTransaction,
    SignerError,
    SignerErrorCode,
    SolanaSigner,
    TransactionSigner,
    sign_and_send_transaction,
)
from tests.util import create_test_transaction

ENCODED = "encoded-transaction"
REWRITTEN_ENCODED = "rewritten-transaction"
SIGNATURE = Signature.from_bytes(bytes([7] * 64))


class _StubBase(SolanaSigner):
    def __init__(self, signature: Signature = SIGNATURE) -> None:
        self._signature = signature
        self._pubkey = Keypair().pubkey()

    @property
    def pubkey(self) -> Pubkey:
        return self._pubkey

    async def sign_message(self, message: bytes) -> Signature:
        return self._signature

    async def is_available(self) -> bool:
        return True


class StubTransactionSigner(_StubBase, TransactionSigner):
    def __init__(self, *, is_complete: bool, signature: Signature = SIGNATURE) -> None:
        super().__init__(signature)
        self._is_complete = is_complete

    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        if self._is_complete:
            transaction.signatures = [self._signature]
        return SignedTransaction(
            encoded_transaction=ENCODED,
            signature=self._signature,
            is_complete=self._is_complete,
            transaction=transaction,
        )


class StubModifyingSigner(_StubBase, ModifyingSigner):
    def __init__(
        self, *, is_complete: bool = True, transaction_signature: Signature = SIGNATURE
    ) -> None:
        super().__init__()
        self._is_complete = is_complete
        self._transaction_signature = transaction_signature

    async def modify_and_sign_transaction(
        self, transaction: VersionedTransaction
    ) -> SignedTransaction:
        rewritten = create_test_transaction(self.pubkey)
        if self._is_complete:
            rewritten.signatures = [self._transaction_signature]
        return SignedTransaction(
            encoded_transaction=REWRITTEN_ENCODED,
            signature=self._signature,
            is_complete=self._is_complete,
            transaction=rewritten,
        )


class StubSendingSigner(_StubBase, SendingSigner):
    async def sign_and_send_transaction(self, transaction: VersionedTransaction) -> Signature:
        return self._signature


class StubMessageOnlySigner(_StubBase):
    pass


async def test_broadcasting_signer_skips_the_injected_sender() -> None:
    """A provider that broadcasts server-side already put the transaction on chain."""
    signer = StubSendingSigner()

    async def send(encoded: str) -> Signature:
        raise AssertionError("send must not run for a signer that broadcasts")

    signature = await sign_and_send_transaction(
        signer, create_test_transaction(signer.pubkey), send
    )
    assert signature == SIGNATURE


async def test_sign_only_signer_broadcasts_the_encoded_transaction() -> None:
    signer = StubTransactionSigner(is_complete=True)
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


async def test_modifying_signer_broadcasts_the_rewritten_transaction() -> None:
    """The provider rewrote the message, so only its own bytes can be broadcast."""
    signer = StubModifyingSigner()
    sent: list[str] = []
    broadcast_signature = Signature.from_bytes(bytes([2] * 64))

    async def send(encoded: str) -> Signature:
        sent.append(encoded)
        return broadcast_signature

    signature = await sign_and_send_transaction(
        signer, create_test_transaction(signer.pubkey), send
    )
    assert sent == [REWRITTEN_ENCODED]
    assert signature == broadcast_signature


async def test_callback_failure_keeps_the_rewritten_transaction_signature() -> None:
    transaction_signature = Signature.from_bytes(bytes([3] * 64))
    signer = StubModifyingSigner(transaction_signature=transaction_signature)
    callback_error = RuntimeError("connection reset")

    async def send(encoded: str) -> Signature:
        assert encoded == REWRITTEN_ENCODED
        raise callback_error

    with pytest.raises(SignerError) as excinfo:
        await sign_and_send_transaction(signer, create_test_transaction(signer.pubkey), send)
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.transaction_signature == transaction_signature
    assert excinfo.value.__cause__ is callback_error


async def test_modifying_signer_without_a_sender_is_rejected() -> None:
    """A modifying signer does not broadcast either, so the hop is still required."""
    signer = StubModifyingSigner()

    with pytest.raises(SignerError) as excinfo:
        await sign_and_send_transaction(signer, create_test_transaction(signer.pubkey))
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


async def test_partially_signed_rewrite_is_rejected_before_broadcast() -> None:
    """A rewrite still awaiting downstream signers cannot land."""
    signer = StubModifyingSigner(is_complete=False)

    async def send(encoded: str) -> Signature:
        raise AssertionError("send must not run for a partially signed rewrite")

    with pytest.raises(SignerError) as excinfo:
        await sign_and_send_transaction(signer, create_test_transaction(signer.pubkey), send)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


async def test_missing_sender_is_rejected_before_signing() -> None:
    """A signature the caller cannot broadcast is a wasted remote signing request."""
    signer = StubTransactionSigner(is_complete=True)

    with pytest.raises(SignerError) as excinfo:
        await sign_and_send_transaction(signer, create_test_transaction(signer.pubkey))
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


async def test_broadcasting_signer_without_a_signature_is_rejected() -> None:
    """The signature a broadcasting provider returns is the only handle on the
    transaction it just put on chain, so an empty one cannot be passed off as one."""
    signer = StubSendingSigner(Signature.default())

    async def send(encoded: str) -> Signature:
        raise AssertionError("send must not run for a signer that broadcasts")

    with pytest.raises(SignerError) as excinfo:
        await sign_and_send_transaction(signer, create_test_transaction(signer.pubkey), send)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


async def test_partial_signature_is_rejected_before_broadcast() -> None:
    """A partially signed transaction cannot land, so it must never be broadcast."""
    signer = StubTransactionSigner(is_complete=False)

    async def send(encoded: str) -> Signature:
        raise AssertionError("send must not run for a partially signed transaction")

    with pytest.raises(SignerError) as excinfo:
        await sign_and_send_transaction(signer, create_test_transaction(signer.pubkey), send)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


async def test_signer_without_a_transaction_capability_is_rejected() -> None:
    """A signer that only signs messages has no transaction shape to route to."""
    signer = StubMessageOnlySigner()

    async def send(encoded: str) -> Signature:
        raise AssertionError("send must not run for a signer with no transaction capability")

    with pytest.raises(SignerError) as excinfo:
        await sign_and_send_transaction(signer, create_test_transaction(signer.pubkey), send)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
