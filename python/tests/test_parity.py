"""Cross-language parity: this suite pins the golden vectors produced by the Rust signer
(rust/src/memory/mod.rs parity vectors, also pinned in go/core/parity_test.go). The Python
implementation must keep producing byte-identical serialized output."""

import base64

from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction

from solana_keychain import MemorySigner

# fmt: off
CANONICAL_KEYPAIR_BYTES = bytes([
    41, 99, 180, 88, 51, 57, 48, 80, 61, 63, 219, 75, 176, 49, 116, 254,
    227, 176, 196, 204, 122, 47, 166, 133, 155, 252, 217, 0, 253, 17, 49, 143,
    47, 94, 121, 167, 195, 136, 72, 22, 157, 48, 77, 88, 63, 96, 57, 122,
    181, 243, 236, 188, 241, 134, 174, 224, 100, 246, 17, 170, 104, 17, 151, 48,
])
# fmt: on

RUST_PARITY_PUBKEY = "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR"
RUST_PARITY_MESSAGE_B64 = (
    "AQABAy9eeafDiEgWnTBNWD9gOXq18+y88Yau4GT2EapoEZcwAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC"
    "AgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAQICAAEMAgAAAEBCDwAAAAAA"
)
RUST_PARITY_SIGNED_TX_B64 = (
    "AaynSvis6Ib7Ryu0FHtVWQEOaHwqjVtlBUmx5dS8lnDzYlucZlaLBuiwHh2yKYxh9BpT4SnIu2Lkp+dmBFf9Igc"
    "BAAEDL155p8OISBadME1YP2A5erXz7Lzxhq7gZPYRqmgRlzACAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAABAgIAAQwCAAAAQEIPAAAAAAA="
)


def build_parity_transaction() -> tuple[Keypair, Transaction]:
    """The EXACT transaction the Rust and Go parity tests build: a System transfer of
    1_000_000 lamports from the canonical signer to the all-0x02 recipient, zero recent
    blockhash, payer = signer."""
    keypair = Keypair.from_bytes(CANONICAL_KEYPAIR_BYTES)
    recipient = Pubkey.from_bytes(bytes([2] * 32))
    instruction = transfer(
        TransferParams(from_pubkey=keypair.pubkey(), to_pubkey=recipient, lamports=1_000_000)
    )
    message = Message.new_with_blockhash([instruction], keypair.pubkey(), Hash.default())
    return keypair, Transaction.new_unsigned(message)


def test_canonical_keypair_derives_shared_pubkey() -> None:
    keypair, _ = build_parity_transaction()
    assert str(keypair.pubkey()) == RUST_PARITY_PUBKEY


def test_message_bytes_match_rust() -> None:
    _, transaction = build_parity_transaction()
    encoded = base64.b64encode(transaction.message_data()).decode("ascii")
    assert encoded == RUST_PARITY_MESSAGE_B64


async def test_signed_transaction_matches_rust() -> None:
    keypair, transaction = build_parity_transaction()
    signer = MemorySigner(keypair)

    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.encoded_transaction == RUST_PARITY_SIGNED_TX_B64
    assert result.signature.verify(signer.pubkey, transaction.message_data())
