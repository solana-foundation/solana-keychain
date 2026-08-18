package core

import (
	"context"

	"github.com/gagliardetto/solana-go"
)

// Completeness records whether a signed transaction now carries all of its
// required signatures. Go has no sum types, so this is a tagged field.
type Completeness int

// Partial means required signatures are still missing; Complete means every
// required signature is present.
const (
	Partial Completeness = iota
	Complete
)

// String renders the completeness for logging.
func (c Completeness) String() string {
	if c == Complete {
		return "Complete"
	}
	return "Partial"
}

// SignedTransaction is the result of SignTransaction: the base64-encoded wire
// transaction, the signature this signer contributed, and whether every required
// signature is now present.
type SignedTransaction struct {
	// EncodedTransaction is the transaction in canonical Solana wire format,
	// base64-encoded.
	EncodedTransaction string
	// Signature is the signature this signer added.
	Signature solana.Signature
	// Completeness reports whether the transaction is now fully signed.
	Completeness Completeness
}

// IsComplete reports whether every required signature is present.
func (s SignedTransaction) IsComplete() bool { return s.Completeness == Complete }

// Signer is the unified signing interface implemented by every backend.
//
// Methods take a context.Context and block. Batch signing is provided as the free
// helpers SignMessages / SignTransactions rather than on the interface.
type Signer interface {
	// Pubkey returns this signer's Solana public key.
	Pubkey() solana.PublicKey

	// SignTransaction signs tx in place: it places this signer's signature at the
	// correct position in tx.Signatures and returns the encoded transaction, the
	// signature, and whether the transaction is now fully signed.
	SignTransaction(ctx context.Context, tx *solana.Transaction) (SignedTransaction, error)

	// SignMessage signs arbitrary bytes and returns the 64-byte signature.
	SignMessage(ctx context.Context, message []byte) (solana.Signature, error)

	// IsAvailable reports whether the signer is reachable and healthy. Implementations
	// swallow internal errors and return false.
	IsAvailable(ctx context.Context) bool
}

// TransactionBroadcaster marks signers whose SignTransaction submits and
// broadcasts the transaction server-side (a managed send) rather than only
// signing. For such signers a failure does not mean nothing happened: the
// provider may have already executed the transaction, so callers must
// reconcile by provider transaction id before retrying. SignTransactions
// rejects signers reporting true.
type TransactionBroadcaster interface {
	// BroadcastsTransactions reports whether SignTransaction broadcasts
	// server-side in this signer's current configuration.
	BroadcastsTransactions() bool
}

// SignatureDictionary maps a signer address to its signature, a convenience for
// @solana/kit-style callers; it is NOT part of the Signer interface.
type SignatureDictionary map[solana.PublicKey]solana.Signature

// NewSignatureDictionary builds a single-entry SignatureDictionary.
func NewSignatureDictionary(address solana.PublicKey, sig solana.Signature) SignatureDictionary {
	return SignatureDictionary{address: sig}
}
