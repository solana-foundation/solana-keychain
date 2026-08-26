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
	"strconv"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// stampScheme is the signature scheme Turnkey expects for API-key stamps.
const stampScheme = "SIGNATURE_SCHEME_TK_API_P256"

// P-256 API-key material lengths (hex-decoded).
const (
	p256PrivateKeyLength          = 32
	p256CompressedPublicKeyLength = 33
)

// validateAPIKeyMaterial rejects malformed Turnkey API-key material at
// construction time instead of at stamp-creation time: both keys must be valid
// hex, the public key a 33-byte compressed P-256 point that decompresses to a
// valid curve point, and the private key 32 bytes.
func validateAPIKeyMaterial(privateKeyHex, publicKeyHex string) error {
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return core.NewSignerError(core.CodeConfigError, "Turnkey API keys must be valid hex strings")
	}
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return core.NewSignerError(core.CodeConfigError, "Turnkey API keys must be valid hex strings")
	}
	if len(publicKeyBytes) != p256CompressedPublicKeyLength {
		return core.NewSignerError(core.CodeConfigError,
			"public key must be "+strconv.Itoa(p256CompressedPublicKeyLength)+
				" bytes (compressed P-256 format), got "+strconv.Itoa(len(publicKeyBytes)))
	}
	if len(privateKeyBytes) != p256PrivateKeyLength {
		return core.NewSignerError(core.CodeConfigError,
			"private key must be "+strconv.Itoa(p256PrivateKeyLength)+
				" bytes, got "+strconv.Itoa(len(privateKeyBytes)))
	}
	if x, _ := elliptic.UnmarshalCompressed(elliptic.P256(), publicKeyBytes); x == nil {
		return core.NewSignerError(core.CodeConfigError, "public key is not a valid P-256 point")
	}
	return nil
}

// stampPayload is the JSON body of the X-Stamp header. Keys are snake_case and
// marshal in alphabetical order.
type stampPayload struct {
	PublicKey string `json:"public_key"`
	Scheme    string `json:"scheme"`
	Signature string `json:"signature"`
}

// createStamp builds the base64url (unpadded) X-Stamp header value for a
// request body: the body is signed with the P-256 ECDSA API private key
// (SHA-256 digest, DER-encoded signature, hex) and wrapped in the Turnkey
// stamp JSON.
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
// private key. Hex, length, and scalar failures all map to InvalidPrivateKey.
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
