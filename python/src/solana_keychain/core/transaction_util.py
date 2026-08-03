"""Transaction serialization and signature-placement utilities."""

import base64

from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.signer import SignedTransaction


def serialize_transaction(transaction: Transaction) -> str:
    """Encode a transaction to base64(bincode(tx))."""
    try:
        raw = bytes(transaction)
    except Exception as error:
        raise SignerError(
            SignerErrorCode.SERIALIZATION_ERROR, f"Failed to serialize transaction: {error}"
        ) from None
    return base64.b64encode(raw).decode("ascii")


def get_signing_keypair_position(transaction: Transaction, pubkey: Pubkey) -> int:
    """Index of ``pubkey`` within the transaction's required-signer slots."""
    num_required = transaction.message.header.num_required_signatures
    account_keys = transaction.message.account_keys
    if len(account_keys) < num_required:
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED, "Invalid account index: not enough account keys"
        )
    try:
        return account_keys[:num_required].index(pubkey)
    except ValueError:
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED, f"Pubkey {pubkey} not found in transaction signers"
        ) from None


def add_signature_to_transaction(
    transaction: Transaction, pubkey: Pubkey, signature: Signature
) -> None:
    """Place ``signature`` at ``pubkey``'s required-signer position, in place."""
    position = get_signing_keypair_position(transaction, pubkey)
    num_required = transaction.message.header.num_required_signatures
    signatures = list(transaction.signatures)
    while len(signatures) < num_required:
        signatures.append(Signature.default())
    signatures[position] = signature
    transaction.signatures = signatures


def has_all_required_signatures(transaction: Transaction) -> bool:
    """True when every required signature slot holds a non-default signature."""
    num_required = transaction.message.header.num_required_signatures
    signatures = transaction.signatures
    if len(signatures) < num_required:
        return False
    default = Signature.default()
    return all(sig != default for sig in signatures[:num_required])


def classify_signed_transaction(
    transaction: Transaction, encoded_transaction: str, signature: Signature
) -> SignedTransaction:
    """Build a SignedTransaction marked complete or partial."""
    return SignedTransaction(
        encoded_transaction=encoded_transaction,
        signature=signature,
        is_complete=has_all_required_signatures(transaction),
    )
