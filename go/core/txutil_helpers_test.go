package core

import (
	"crypto/ed25519"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
)

// This file inlines the one testutils helper core's tests need, so the core
// module carries no dependency on the testutils module: core must be taggable
// and publishable first, before testutils and the signer modules.

// testTransferLamports is the lamport amount used by createTestTransaction.
const testTransferLamports = 1_000_000

// testRecipient is a fixed transfer recipient for deterministic test
// transactions (seed bytes all 0x42, matching testutils.deriveKey(0x42)).
var testRecipient = func() solana.PublicKey {
	var seed [ed25519.SeedSize]byte
	for i := range seed {
		seed[i] = 0x42
	}
	priv := ed25519.NewKeyFromSeed(seed[:])
	var pub solana.PublicKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return pub
}()

// testBlockhash is a fixed recent blockhash so test transactions serialize
// deterministically (these transactions are never submitted to a cluster).
var testBlockhash = func() solana.Hash {
	var h solana.Hash
	for i := range h {
		h[i] = 9
	}
	return h
}()

// createTestTransaction builds a minimal single-signer System transfer
// transaction (payer -> a fixed recipient) with a fixed blockhash — the same
// deterministic shape as testutils.CreateTestTransaction, whose golden vectors
// the tests in this package pin.
func createTestTransaction(payer solana.PublicKey) (*solana.Transaction, error) {
	inst := system.NewTransferInstruction(testTransferLamports, payer, testRecipient).Build()
	return solana.NewTransaction(
		[]solana.Instruction{inst},
		testBlockhash,
		solana.TransactionPayer(payer),
	)
}

// testSeed is the fixed 32-byte Ed25519 seed shared with the testutils module,
// so the golden vectors stay pinned.
var testSeed = [ed25519.SeedSize]byte{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
}

// testPrivateKey returns the deterministic test private key.
func testPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(testSeed[:])
}

// testPublicKey returns the Solana public key for testPrivateKey.
func testPublicKey() solana.PublicKey {
	var pub solana.PublicKey
	copy(pub[:], testPrivateKey().Public().(ed25519.PublicKey))
	return pub
}

// createTestV1Transaction is createTestTransaction as a v1 message.
func createTestV1Transaction(payer solana.PublicKey) (*solana.Transaction, error) {
	tx, err := createTestTransaction(payer)
	if err != nil {
		return nil, err
	}
	tx.Message.TransactionConfig = solana.TransactionConfig{}.
		WithComputeUnitLimit(30_000).
		WithLoadedAccountsDataSizeLimit(65_536)
	message, err := tx.Message.SetVersion(solana.MessageVersionV1)
	if err != nil {
		return nil, err
	}
	tx.Message = *message
	return tx, nil
}
