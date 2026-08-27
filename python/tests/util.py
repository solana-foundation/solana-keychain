from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.message import Message, MessageV0, MessageV1, TransactionConfig
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import ID as SYSTEM_PROGRAM_ID
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction, VersionedTransaction

TEST_KEYPAIR_BYTES = (
    "[41,99,180,88,51,57,48,80,61,63,219,75,176,49,116,254,227,176,196,204,122,47,166,133,"
    "155,252,217,0,253,17,49,143,47,94,121,167,195,136,72,22,157,48,77,88,63,96,57,122,181,"
    "243,236,188,241,134,174,224,100,246,17,170,104,17,151,48]"
)
TEST_KEYPAIR_BASE58 = (
    "pzjkwgQ5shhq3Awijz6CjDjZrXPX7YKKgkTipBK7JAq8XW5GbDynBFChESMBrz4SvFiZ8qJAtUB6sL3PpVCnbR1"
)
TEST_PUBKEY = "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR"


def _transfer_instruction(from_pubkey: Pubkey, to_pubkey: Pubkey | None) -> Instruction:
    if to_pubkey is None:
        to_pubkey = Pubkey.new_unique()
    return transfer(
        TransferParams(from_pubkey=from_pubkey, to_pubkey=to_pubkey, lamports=1_000_000)
    )


def create_test_transaction(
    from_pubkey: Pubkey, to_pubkey: Pubkey | None = None
) -> VersionedTransaction:
    instruction = _transfer_instruction(from_pubkey, to_pubkey)
    message = Message.new_with_blockhash([instruction], from_pubkey, Hash.default())
    return VersionedTransaction.from_legacy(Transaction.new_unsigned(message))


def create_test_v0_transaction(
    from_pubkey: Pubkey, to_pubkey: Pubkey | None = None
) -> VersionedTransaction:
    instruction = _transfer_instruction(from_pubkey, to_pubkey)
    message = MessageV0.try_compile(from_pubkey, [instruction], [], Hash.default())
    unsigned = [Signature.default()] * message.header.num_required_signatures
    return VersionedTransaction.populate(message, unsigned)


def create_test_v1_transaction(
    from_pubkey: Pubkey, to_pubkey: Pubkey | None = None
) -> VersionedTransaction:
    """A v1 transaction. v1 treats an unset resource limit as zero, not a default."""
    instruction = _transfer_instruction(from_pubkey, to_pubkey)
    message = MessageV1.try_compile(
        from_pubkey,
        [instruction],
        Hash.default(),
        TransactionConfig(compute_unit_limit=30_000, loaded_accounts_data_size_limit=65_536),
    )
    unsigned = [Signature.default()] * message.header.num_required_signatures
    return VersionedTransaction.populate(message, unsigned)


def create_two_signer_transaction(payer: Pubkey, cosigner: Pubkey) -> VersionedTransaction:
    instruction = Instruction(
        SYSTEM_PROGRAM_ID,
        bytes([2, 0, 0, 0]) + (1_000_000).to_bytes(8, "little"),
        [
            AccountMeta(payer, is_signer=True, is_writable=True),
            AccountMeta(cosigner, is_signer=True, is_writable=True),
        ],
    )
    message = Message.new_with_blockhash([instruction], payer, Hash.default())
    return VersionedTransaction.from_legacy(Transaction.new_unsigned(message))
