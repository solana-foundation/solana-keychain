package fireblocks

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// JWT lifetime constants.
const (
	jwtTTLSecs        = 120
	jwtSkewLeewaySecs = 60
)

// parseSigningKey parses the Fireblocks RSA API secret (PKCS#1 or PKCS#8 PEM)
// once for token reuse.
func parseSigningKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyPEM))
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPrivateKey, "failed to parse RSA key", err)
	}
	return key, nil
}

// createJWT builds the per-request RS256 JWT for Fireblocks API authentication.
// Claims are uri, a random UUIDv4 nonce, iat = nbf = now - skew leeway,
// exp = now + TTL, sub = apiKey, and bodyHash = hex(sha256(body)) (empty string
// body for GET requests).
func createJWT(apiKey string, signingKey *rsa.PrivateKey, uri, body string) (string, error) {
	nonce, err := core.RandomUUIDv4()
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
