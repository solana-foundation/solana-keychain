package turnkey

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// stampScheme is the signature scheme Turnkey expects for API-key stamps.
const stampScheme = "SIGNATURE_SCHEME_TK_API_P256"

// stampPayload is the JSON body of the X-Stamp header. Field order matches the
// alphabetical key order the Rust implementation emits via serde_json, and the
// snake_case key names match the Rust stamp exactly.
type stampPayload struct {
	PublicKey string `json:"public_key"`
	Scheme    string `json:"scheme"`
	Signature string `json:"signature"`
}

// createStamp builds the base64url (unpadded) X-Stamp header value for a
// request body: the body is signed with the P-256 ECDSA API private key
// (SHA-256 digest, DER-encoded signature, hex) and wrapped in the Turnkey
// stamp JSON. Port of the Rust TurnkeySigner::create_stamp.
func (s *Signer) createStamp(message string) (string, error) {
	priv, err := parseP256PrivateKey(s.apiPrivateKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(message))
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return "", core.WrapSignerError(core.CodeSigningFailed, "failed to sign request stamp", err)
	}
	stamp := stampPayload{
		PublicKey: s.apiPublicKey,
		Scheme:    stampScheme,
		Signature: hex.EncodeToString(der),
	}
	stampJSON, err := json.Marshal(stamp)
	if err != nil {
		return "", core.WrapSignerError(core.CodeSerializationError, "failed to serialize stamp", err)
	}
	return base64.RawURLEncoding.EncodeToString(stampJSON), nil
}

// parseP256PrivateKey decodes a hex-encoded 32-byte P-256 scalar into an ECDSA
// private key. Error mapping mirrors the Rust create_stamp: hex/length/scalar
// failures are all InvalidPrivateKey.
func parseP256PrivateKey(hexKey string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPrivateKey, "failed to decode private key hex", err)
	}
	if len(keyBytes) != 32 {
		return nil, core.NewSignerError(core.CodeInvalidPrivateKey, "invalid private key length")
	}
	ecdhKey, err := ecdh.P256().NewPrivateKey(keyBytes)
	if err != nil {
		return nil, core.NewSignerError(core.CodeInvalidPrivateKey, "invalid signing key: scalar out of range")
	}
	// ecdh exposes the public key only as an uncompressed point
	// (0x04 || X || Y); split it back into the ecdsa coordinate form.
	point := ecdhKey.PublicKey().Bytes()
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(point[1:33]),
			Y:     new(big.Int).SetBytes(point[33:65]),
		},
		D: new(big.Int).SetBytes(keyBytes),
	}, nil
}
