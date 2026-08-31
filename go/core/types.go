package core

import (
	"context"

	"github.com/solana-foundation/solana-go/v2"
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

// SolanaSigner is the base contract every signer backend implements: identity,
// message signing and health.
//
// Methods take a context.Context and block. Batch signing is provided as the free
// helpers SignMessages / SignTransactions rather than on the interface.
//
// Transaction handling lives in the capability interfaces, and a backend
// implements exactly the one matching its provider's shape: TransactionSigner
// signs the caller's transaction as given, ModifyingSigner rewrites it before
// signing, SendingSigner has the provider sign and broadcast it.
type SolanaSigner interface {
	// Pubkey returns this signer's Solana public key.
	Pubkey() solana.PublicKey

	// SignMessage signs arbitrary bytes and returns the 64-byte signature.
	SignMessage(ctx context.Context, message []byte) (solana.Signature, error)

	// IsAvailable reports whether the signer is reachable and healthy. Implementations
	// swallow internal errors and return false.
	IsAvailable(ctx context.Context) bool
}

// TransactionSigner signs the caller's transaction exactly as given; the caller
// broadcasts the result.
type TransactionSigner interface {
	SolanaSigner

	// SignTransaction signs tx in place: it places this signer's signature at the
	// correct position in tx.Signatures and returns the encoded transaction, the
	// signature, and whether the transaction is now fully signed.
	SignTransaction(ctx context.Context, tx *solana.Transaction) (SignedTransaction, error)
}

// ModifyingSigner has its provider rewrite the transaction before signing it.
// The returned signature covers the rewritten message, not the bytes the caller
// supplied, so any signatures collected beforehand are invalidated; continue
// from the transaction it returns.
type ModifyingSigner interface {
	SolanaSigner

	// ModifyAndSignTransaction lets the provider rewrite tx, signs the rewritten
	// transaction and replaces tx with it.
	ModifyAndSignTransaction(ctx context.Context, tx *solana.Transaction) (SignedTransaction, error)
}

// SendingSigner has its provider sign and broadcast the transaction server-side,
// where a failure does not mean nothing happened: callers must reconcile by
// provider transaction id before retrying.
type SendingSigner interface {
	SolanaSigner

	// SignAndSendTransaction signs tx and broadcasts it through the provider.
	// The provider may rewrite tx, in which case tx is left untouched and the
	// returned signature identifies the transaction that actually landed.
	SignAndSendTransaction(ctx context.Context, tx *solana.Transaction) (solana.Signature, error)
}

// SignatureDictionary maps a signer address to its signature, a convenience for
// @solana/kit-style callers; it is NOT part of the SolanaSigner interface.
type SignatureDictionary map[solana.PublicKey]solana.Signature

// NewSignatureDictionary builds a single-entry SignatureDictionary.
func NewSignatureDictionary(address solana.PublicKey, sig solana.Signature) SignatureDictionary {
	return SignatureDictionary{address: sig}
}
