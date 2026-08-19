package core

import (
	"encoding/base64"

	"github.com/gagliardetto/solana-go"
)

// Serialize encodes a transaction to a base64 string. solana-go's MarshalBinary
// targets the canonical wire format, whose layout depends on the message version:
// legacy and v0 lead with their signatures, v1 leads with the message.
func Serialize(tx *solana.Transaction) (string, error) {
	b, err := tx.MarshalBinary()
	if err != nil {
		return "", WrapSignerError(CodeSerializationError, "failed to serialize transaction", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// SigningPosition returns the index in the transaction's required-signer list where
// pubkey's signature belongs.
func SigningPosition(tx *solana.Transaction, pubkey solana.PublicKey) (int, error) {
	numRequired := int(tx.Message.Header.NumRequiredSignatures)
	if len(tx.Message.AccountKeys) < numRequired {
		return 0, NewSignerError(CodeSigningFailed, "invalid account index: not enough account keys")
	}
	for i := 0; i < numRequired; i++ {
		if tx.Message.AccountKeys[i] == pubkey {
			return i, nil
		}
	}
	return 0, NewSignerError(CodeSigningFailed, "pubkey "+pubkey.String()+" not found in transaction signers")
}

// AddSignature places signature at pubkey's required-signer position, growing the
// signatures slice (zero-filling) to NumRequiredSignatures first.
func AddSignature(tx *solana.Transaction, pubkey solana.PublicKey, signature solana.Signature) error {
	pos, err := SigningPosition(tx, pubkey)
	if err != nil {
		return err
	}
	numRequired := int(tx.Message.Header.NumRequiredSignatures)
	for len(tx.Signatures) < numRequired {
		tx.Signatures = append(tx.Signatures, solana.Signature{})
	}
	tx.Signatures[pos] = signature
	return nil
}

// HasAllRequiredSignatures reports whether every required signature slot is filled
// with a non-zero signature.
func HasAllRequiredSignatures(tx *solana.Transaction) bool {
	numRequired := int(tx.Message.Header.NumRequiredSignatures)
	if len(tx.Signatures) < numRequired {
		return false
	}
	for i := 0; i < numRequired; i++ {
		if tx.Signatures[i].IsZero() {
			return false
		}
	}
	return true
}

// Classify wraps an encoded transaction and signature into a SignedTransaction,
// tagging it Complete or Partial.
func Classify(tx *solana.Transaction, encoded string, sig solana.Signature) SignedTransaction {
	c := Partial
	if HasAllRequiredSignatures(tx) {
		c = Complete
	}
	return SignedTransaction{EncodedTransaction: encoded, Signature: sig, Completeness: c}
}
