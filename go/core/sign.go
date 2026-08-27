package core

import (
	"context"

	"github.com/solana-foundation/solana-go/v2"
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

// ExtractAndVerifyReturnedSignature deserializes a signed wire transaction
// returned by a remote provider, extracts the signature at pubkey's
// required-signer position, and verifies it against the original
// locally-computed message bytes — the guarantee that the provider signed
// exactly what was requested.
func ExtractAndVerifyReturnedSignature(
	returnedTxBytes []byte,
	pubkey solana.PublicKey,
	originalMessage []byte,
	provider string,
) (solana.Signature, error) {
	returned, err := solana.TransactionFromBytes(returnedTxBytes)
	if err != nil {
		return solana.Signature{}, WrapSignerError(CodeSerializationError,
			"failed to deserialize signed transaction returned by "+provider, err)
	}
	pos, err := SigningPosition(returned, pubkey)
	if err != nil {
		return solana.Signature{}, err
	}
	if pos >= len(returned.Signatures) || returned.Signatures[pos].IsZero() {
		return solana.Signature{}, NewSignerError(CodeSigningFailed,
			"signed transaction returned by "+provider+" is missing the signer's signature")
	}
	sig := returned.Signatures[pos]
	if err := VerifySignature(pubkey, originalMessage, sig); err != nil {
		return solana.Signature{}, err
	}
	return sig, nil
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

// SendTransactionFn broadcasts a base64-encoded wire transaction and returns its
// signature. Core has no RPC dependency, so the network hop is always caller-supplied.
type SendTransactionFn func(ctx context.Context, encodedTransaction string) (solana.Signature, error)

// SignAndSendTransaction gets tx on chain with one call. A SendingSigner
// broadcasts through its provider, so its own signature identifies the transaction
// and send is ignored; a TransactionSigner signs and send broadcasts the result.
//
// send is checked before signing so a missing one cannot waste a signature.
func SignAndSendTransaction(ctx context.Context, s SolanaSigner, tx *solana.Transaction, send SendTransactionFn) (solana.Signature, error) {
	if sender, ok := s.(SendingSigner); ok {
		sig, err := sender.SignAndSendTransaction(ctx, tx)
		if err != nil {
			return solana.Signature{}, err
		}
		if sig == (solana.Signature{}) {
			return solana.Signature{}, NewSignerError(CodeSigningFailed,
				"signer returned no signature for the transaction it broadcast")
		}
		return sig, nil
	}

	signer, ok := s.(TransactionSigner)
	if !ok {
		return solana.Signature{}, NewSignerError(CodeSigningFailed,
			"this signer supports neither SignTransaction nor SignAndSendTransaction")
	}

	if send == nil {
		return solana.Signature{}, NewSignerError(CodeConfigError,
			"this signer cannot broadcast transactions; supply a SendTransactionFn to broadcast the signed one")
	}

	signed, err := signer.SignTransaction(ctx, tx)
	if err != nil {
		return solana.Signature{}, err
	}
	if !signed.IsComplete() {
		return solana.Signature{}, NewSignerError(CodeSigningFailed,
			"transaction is still missing signatures after signing and cannot be broadcast")
	}
	return send(ctx, signed.EncodedTransaction)
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
