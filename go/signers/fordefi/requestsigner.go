package fordefi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// RequestSigner signs Fordefi API-request payloads for the x-signature header.
//
// Implementations receive the fully-formatted payload
// ({path}|{timestamp}|{body}) and must return the exact base64 value Fordefi
// expects: base64 of the DER-encoded ECDSA P-256 signature over
// SHA-256(payload). Implement this interface to keep the request key in a
// KMS/HSM instead of handing over raw PEM material (e.g. AWS KMS Sign with
// ECDSA_SHA_256 already returns a DER signature; base64-encode it).
type RequestSigner interface {
	// SignRequest signs payload and returns the base64-encoded x-signature value.
	SignRequest(ctx context.Context, payload []byte) (string, error)
}

// PemRequestSigner is the built-in RequestSigner backed by a PEM-encoded ECDSA
// P-256 private key. It supports both PKCS#8 and SEC1 (EC) PEM encodings.
type PemRequestSigner struct {
	key *ecdsa.PrivateKey
}

// NewPemRequestSigner parses an ECDSA P-256 private key from PEM.
func NewPemRequestSigner(privateKeyPEM string) (*PemRequestSigner, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errInvalidPEM()
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok || key.Curve != elliptic.P256() {
			return nil, errInvalidPEM()
		}
		return &PemRequestSigner{key: key}, nil
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil || key.Curve != elliptic.P256() {
		return nil, errInvalidPEM()
	}
	return &PemRequestSigner{key: key}, nil
}

func errInvalidPEM() error {
	return core.NewSignerError(core.CodeInvalidPrivateKey,
		"failed to parse PEM as an ECDSA P-256 key (tried PKCS#8 and SEC1)")
}

// SignRequest signs payload with ECDSA P-256 over its SHA-256 digest and
// returns the base64-encoded DER signature.
func (p *PemRequestSigner) SignRequest(_ context.Context, payload []byte) (string, error) {
	digest := sha256.Sum256(payload)
	der, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	if err != nil {
		return "", core.WrapSignerError(core.CodeSigningFailed, "failed to sign fordefi api request", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}
