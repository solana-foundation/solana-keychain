package core

import (
	"context"

	"github.com/gagliardetto/solana-go"
)

// MessageBytes returns the serialized transaction message, the bytes a Solana
// signature covers.
func MessageBytes(tx *solana.Transaction) ([]byte, error) {
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, WrapSignerError(CodeSerializationError, "failed to serialize transaction message", err)
	}
	return msg, nil
}

// VerifySignature reports an error unless sig is pubkey's signature over message.
func VerifySignature(pubkey solana.PublicKey, message []byte, sig solana.Signature) error {
	if !VerifyEd25519(pubkey, message, sig) {
		return NewSignerError(CodeSigningFailed,
			"signature verification failed: the returned signature does not match the public key")
	}
	return nil
}

// AttachSignature places sig at pubkey's required-signer position and returns the
// encoded transaction tagged with its completeness.
func AttachSignature(tx *solana.Transaction, pubkey solana.PublicKey, sig solana.Signature) (SignedTransaction, error) {
	if err := AddSignature(tx, pubkey, sig); err != nil {
		return SignedTransaction{}, err
	}
	encoded, err := Serialize(tx)
	if err != nil {
		return SignedTransaction{}, err
	}
	return Classify(tx, encoded, sig), nil
}

// SignTransactionWith signs tx's message with signFn and attaches the resulting
// signature at pubkey's position. Backends whose remote API signs the message
// bytes directly implement SignTransaction through this helper.
func SignTransactionWith(
	ctx context.Context,
	tx *solana.Transaction,
	pubkey solana.PublicKey,
	signFn func(ctx context.Context, message []byte) (solana.Signature, error),
) (SignedTransaction, error) {
	msg, err := MessageBytes(tx)
	if err != nil {
		return SignedTransaction{}, err
	}
	sig, err := signFn(ctx, msg)
	if err != nil {
		return SignedTransaction{}, err
	}
	return AttachSignature(tx, pubkey, sig)
}
