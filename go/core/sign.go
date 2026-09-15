package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"

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
// and send is ignored; a TransactionSigner or a ModifyingSigner signs and send
// broadcasts the result, which for a ModifyingSigner is the transaction its
// provider rewrote.
//
// send is checked before signing so a missing one cannot waste a signature. A
// send failure reports CodeBroadcastUnconfirmed with the completed transaction's
// fee-payer signature.
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

	signTransaction := signOnlyEntryPoint(s)
	if signTransaction == nil {
		return solana.Signature{}, NewSignerError(CodeSigningFailed,
			"this signer supports none of SignTransaction, ModifyAndSignTransaction and SignAndSendTransaction")
	}

	if send == nil {
		return solana.Signature{}, NewSignerError(CodeConfigError,
			"this signer cannot broadcast transactions; supply a SendTransactionFn to broadcast the signed one")
	}

	signed, err := signTransaction(ctx, tx)
	if err != nil {
		return solana.Signature{}, err
	}
	if !signed.IsComplete() {
		return solana.Signature{}, NewSignerError(CodeSigningFailed,
			"transaction is still missing signatures after signing and cannot be broadcast")
	}
	if len(tx.Signatures) == 0 || tx.Signatures[0].IsZero() {
		return solana.Signature{}, NewSignerError(CodeSigningFailed,
			"broadcast transaction has no fee payer signature to identify it by")
	}
	sig, err := send(ctx, signed.EncodedTransaction)
	if err == nil {
		return sig, nil
	}
	unconfirmed := NewBroadcastUnconfirmedError("",
		"the transaction may have been broadcast; reconcile its signature before retrying")
	unconfirmed.TransactionSignature = tx.Signatures[0]
	unconfirmed.cause = err
	return solana.Signature{}, unconfirmed
}

// signOnlyEntryPoint returns the entry point s uses to sign a transaction the
// caller then broadcasts, or nil when s carries neither.
func signOnlyEntryPoint(s SolanaSigner) func(context.Context, *solana.Transaction) (SignedTransaction, error) {
	if signer, ok := s.(TransactionSigner); ok {
		return signer.SignTransaction
	}
	if signer, ok := s.(ModifyingSigner); ok {
		return signer.ModifyAndSignTransaction
	}
	return nil
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

// ed25519SPKIPrefix is the DER SubjectPublicKeyInfo header for an Ed25519 key:
// SEQUENCE, AlgorithmIdentifier with OID 1.3.101.112, then a 33-byte BIT STRING
// with zero unused bits.
var ed25519SPKIPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// PublicKeyFromSPKIDER extracts the Ed25519 public key carried by a DER-encoded
// SubjectPublicKeyInfo. ok is false when der is not one.
func PublicKeyFromSPKIDER(der []byte) (key solana.PublicKey, ok bool) {
	if len(der) != len(ed25519SPKIPrefix)+len(key) {
		return solana.PublicKey{}, false
	}
	if !bytes.Equal(der[:len(ed25519SPKIPrefix)], ed25519SPKIPrefix) {
		return solana.PublicKey{}, false
	}
	copy(key[:], der[len(ed25519SPKIPrefix):])
	return key, true
}

// PublicKeyFromSPKIPEM extracts the Ed25519 public key carried by a PEM-encoded
// SubjectPublicKeyInfo. ok is false when pem is not one.
func PublicKeyFromSPKIPEM(pemText string) (solana.PublicKey, bool) {
	var body strings.Builder
	for _, line := range strings.Split(pemText, "\n") {
		if strings.HasPrefix(line, "-----") {
			continue
		}
		body.WriteString(strings.TrimSpace(line))
	}
	der, err := base64.StdEncoding.DecodeString(body.String())
	if err != nil {
		return solana.PublicKey{}, false
	}
	return PublicKeyFromSPKIDER(der)
}

// PublicKeyFromRawEd25519 renders a raw 32-byte Ed25519 key as a public key.
// ok is false for any other length.
func PublicKeyFromRawEd25519(raw []byte) (key solana.PublicKey, ok bool) {
	if len(raw) != len(key) {
		return solana.PublicKey{}, false
	}
	copy(key[:], raw)
	return key, true
}
