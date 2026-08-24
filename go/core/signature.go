package core

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/base58"
)

// SignatureComponentLength is the byte length of the r and s halves of an
// Ed25519 signature.
const SignatureComponentLength = SignatureLength / 2

// SignatureFromBytes returns raw as a Solana signature, rejecting any length
// other than SignatureLength.
func SignatureFromBytes(raw []byte, provider string) (solana.Signature, error) {
	if len(raw) != SignatureLength {
		return solana.Signature{}, NewSignerError(CodeSigningFailed,
			"invalid signature length from "+provider+": expected "+strconv.Itoa(SignatureLength)+
				" bytes, got "+strconv.Itoa(len(raw)))
	}
	var sig solana.Signature
	copy(sig[:], raw)
	return sig, nil
}

// DecodeSignatureBase58 decodes a base58-encoded 64-byte signature.
func DecodeSignatureBase58(encoded, provider string) (solana.Signature, error) {
	raw, err := base58.Decode(encoded)
	if err != nil {
		return solana.Signature{}, decodeFailure(provider, "base58", err)
	}
	return SignatureFromBytes(raw, provider)
}

// DecodeSignatureBase64 decodes a base64-encoded 64-byte signature.
func DecodeSignatureBase64(encoded, provider string) (solana.Signature, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return solana.Signature{}, decodeFailure(provider, "base64", err)
	}
	return SignatureFromBytes(raw, provider)
}

// DecodeSignatureHex decodes a hex-encoded 64-byte signature, tolerating a
// leading "0x".
func DecodeSignatureHex(encoded, provider string) (solana.Signature, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(encoded, "0x"))
	if err != nil {
		return solana.Signature{}, decodeFailure(provider, "hex", err)
	}
	return SignatureFromBytes(raw, provider)
}

// SignatureFromHexComponents assembles a signature from hex-encoded r and s
// components, each tolerating a leading "0x". Components shorter than 32 bytes
// are left-padded when pad is set, which providers that strip leading zeros
// require; otherwise both must be exactly 32 bytes.
func SignatureFromHexComponents(r, s, provider string, pad bool) (solana.Signature, error) {
	rBytes, err := hex.DecodeString(strings.TrimPrefix(r, "0x"))
	if err != nil {
		return solana.Signature{}, decodeFailure(provider, "hex r component", err)
	}
	sBytes, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return solana.Signature{}, decodeFailure(provider, "hex s component", err)
	}
	if pad {
		if len(rBytes) > SignatureComponentLength || len(sBytes) > SignatureComponentLength {
			return solana.Signature{}, componentLengthError(provider)
		}
	} else if len(rBytes) != SignatureComponentLength || len(sBytes) != SignatureComponentLength {
		return solana.Signature{}, componentLengthError(provider)
	}
	var sig solana.Signature
	copy(sig[SignatureComponentLength-len(rBytes):SignatureComponentLength], rBytes)
	copy(sig[SignatureLength-len(sBytes):SignatureLength], sBytes)
	return sig, nil
}

func decodeFailure(provider, encoding string, err error) error {
	return WrapSignerError(CodeSerializationError, "failed to decode "+encoding+" signature from "+provider, err)
}

func componentLengthError(provider string) error {
	return NewSignerError(CodeSigningFailed,
		"invalid signature component length from "+provider+": expected "+
			strconv.Itoa(SignatureComponentLength)+"-byte r and s")
}
