package core

import (
	"context"

	"github.com/gagliardetto/solana-go"
)

// Completeness records whether a signed transaction now carries all of its
// required signatures. It is the Go analog of the Rust SignTransactionResult
// Complete/Partial discriminant (Go has no sum types, so this is a tagged field).
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
// signature is now present. Mirrors the Rust (base64 String, Signature) tuple plus
// the Complete/Partial tag.
type SignedTransaction struct {
	// EncodedTransaction is base64(bincode(tx)) — the same bytes the Rust and TS
	// implementations produce, since solana-go targets the canonical wire format.
	EncodedTransaction string
	// Signature is the signature this signer added.
	Signature solana.Signature
	// Completeness reports whether the transaction is now fully signed.
	Completeness Completeness
}

// IsComplete reports whether every required signature is present.
func (s SignedTransaction) IsComplete() bool { return s.Completeness == Complete }

// Signer is the unified signing interface implemented by every backend — the Go
// analog of the Rust SolanaSigner trait and the TS SolanaSigner interface.
//
// Go has no async/await: methods take a context.Context and block. The array-shaped
// batch API that TypeScript exposes (a requirement of @solana/kit there) is provided
// here as the free helpers SignMessages / SignTransactions rather than on the interface.
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
	// swallow internal errors and return false (parity with the Rust bool return).
	IsAvailable(ctx context.Context) bool
}

// SignatureDictionary maps a signer address to its signature. It mirrors the TS
// SignatureDictionary used for @solana/kit interop; it is NOT part of the Signer
// interface and exists only as a convenience for kit-style callers.
type SignatureDictionary map[solana.PublicKey]solana.Signature

// NewSignatureDictionary builds a single-entry SignatureDictionary.
func NewSignatureDictionary(address solana.PublicKey, sig solana.Signature) SignatureDictionary {
	return SignatureDictionary{address: sig}
}
