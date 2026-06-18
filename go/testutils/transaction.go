package testutils

import (
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
)

// testRecipient is a fixed transfer recipient for deterministic test transactions.
var testRecipient = deriveKey(0x42)

// testBlockhash is a fixed recent blockhash so test transactions serialize
// deterministically (these transactions are never submitted to a cluster).
var testBlockhash = func() solana.Hash {
	var h solana.Hash
	for i := range h {
		h[i] = 9
	}
	return h
}()

// TestTransferLamports is the lamport amount used by CreateTestTransaction.
const TestTransferLamports = 1_000_000

// CreateTestTransaction builds a minimal single-signer System transfer transaction
// (payer -> a fixed recipient) with a fixed blockhash — the Go analog of the Rust
// create_test_transaction helper. It is deterministic for a given payer.
func CreateTestTransaction(payer solana.PublicKey) (*solana.Transaction, error) {
	inst := system.NewTransferInstruction(TestTransferLamports, payer, testRecipient).Build()
	return solana.NewTransaction(
		[]solana.Instruction{inst},
		testBlockhash,
		solana.TransactionPayer(payer),
	)
}
