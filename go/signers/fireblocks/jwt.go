package fireblocks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// JWT lifetime constants, matching the Rust jwt.rs module.
const (
	jwtTTLSecs        = 120
	jwtSkewLeewaySecs = 60
)

// parseSigningKey parses the Fireblocks RSA API secret once for token reuse.
// Port of the Rust jwt::parse_encoding_key (accepts PKCS#1 and PKCS#8 PEM).
func parseSigningKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyPEM))
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPrivateKey, "failed to parse RSA key", err)
	}
	return key, nil
}

// createJWT builds the per-request RS256 JWT for Fireblocks API authentication.
// Port of the Rust jwt::create_jwt: claims are uri, a random UUIDv4 nonce,
// iat = nbf = now - skew leeway, exp = now + TTL, sub = apiKey, and bodyHash =
// hex(sha256(body)) (empty string body for GET requests).
func createJWT(apiKey string, signingKey *rsa.PrivateKey, uri, body string) (string, error) {
	nonce, err := newNonce()
	if err != nil {
		return "", core.WrapSignerError(core.CodeSigningFailed, "failed to create JWT", err)
	}

	bodyHash := sha256.Sum256([]byte(body))

	now := time.Now().Unix()
	issuedAt := now - jwtSkewLeewaySecs

	claims := jwt.MapClaims{
		"uri":      uri,
		"nonce":    nonce,
		"iat":      issuedAt,
		"nbf":      issuedAt,
		"exp":      now + jwtTTLSecs,
		"sub":      apiKey,
		"bodyHash": hex.EncodeToString(bodyHash[:]),
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(signingKey)
	if err != nil {
		return "", core.WrapSignerError(core.CodeSigningFailed, "failed to create JWT", err)
	}
	return token, nil
}

// newNonce generates a random UUIDv4 string (Go analog of the Rust Uuid::new_v4
// nonce; the standard library has no UUID type, so the 16 random bytes are
// version/variant-tagged and formatted manually).
func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
