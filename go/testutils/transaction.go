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

// Resource limits used by CreateTestV1Transaction.
const (
	TestComputeUnitLimit            = 30_000
	TestLoadedAccountsDataSizeLimit = 65_536
)

// CreateTestTransaction builds a minimal single-signer System transfer transaction
// (payer -> a fixed recipient) with a fixed blockhash. It is deterministic for a
// given payer.
func CreateTestTransaction(payer solana.PublicKey) (*solana.Transaction, error) {
	inst := system.NewTransferInstruction(TestTransferLamports, payer, testRecipient).Build()
	return solana.NewTransaction(
		[]solana.Instruction{inst},
		testBlockhash,
		solana.TransactionPayer(payer),
	)
}

// CreateTestV1Transaction is CreateTestTransaction as a v1 message, with both
// resource limits set.
func CreateTestV1Transaction(payer solana.PublicKey) (*solana.Transaction, error) {
	tx, err := CreateTestTransaction(payer)
	if err != nil {
		return nil, err
	}
	tx.Message.TransactionConfig = solana.TransactionConfig{}.
		WithComputeUnitLimit(TestComputeUnitLimit).
		WithLoadedAccountsDataSizeLimit(TestLoadedAccountsDataSizeLimit)
	message, err := tx.Message.SetVersion(solana.MessageVersionV1)
	if err != nil {
		return nil, err
	}
	tx.Message = *message
	return tx, nil
}
