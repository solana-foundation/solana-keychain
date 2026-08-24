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

// SendTransactionFn broadcasts a base64-encoded wire transaction and returns the
// signature identifying it. Core has no RPC dependency, so the network hop is
// always injected: implement it with whatever transport the caller already has,
// an rpc.Client.SendEncodedTransaction call or a relayer endpoint.
type SendTransactionFn func(ctx context.Context, encodedTransaction string) (solana.Signature, error)

// SignAndSendTransaction gets tx on chain with one call, whichever shape the
// signer has. A TransactionBroadcaster signs and broadcasts through its provider,
// so its own signature identifies the transaction; any other signer signs and send
// broadcasts the result.
//
// send is required for signers that do not broadcast and ignored by the ones that
// do. It is checked before signing so a missing one cannot waste a signature.
func SignAndSendTransaction(ctx context.Context, s Signer, tx *solana.Transaction, send SendTransactionFn) (solana.Signature, error) {
	broadcaster, ok := s.(TransactionBroadcaster)
	broadcasts := ok && broadcaster.BroadcastsTransactions()
	if !broadcasts && send == nil {
		return solana.Signature{}, NewSignerError(CodeConfigError,
			"this signer cannot broadcast transactions; supply a SendTransactionFn to broadcast the signed one")
	}

	signed, err := s.SignTransaction(ctx, tx)
	if err != nil {
		return solana.Signature{}, err
	}
	if broadcasts {
		return signed.Signature, nil
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
