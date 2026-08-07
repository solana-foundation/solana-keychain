package cdp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// jwtTTL is the JWT validity window in seconds.
const jwtTTL = 120

// jwtURI builds the URI claim value for a CDP JWT: "<METHOD> <host><path>".
func jwtURI(host, method, path string) string {
	return method + " " + host + path
}

// extractHost returns the request host (including port if present) from a base
// URL.
func extractHost(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", core.WrapSignerError(core.CodeConfigError, "invalid CDP base URL: "+baseURL, err)
	}
	if u.Host == "" {
		return "", core.NewSignerError(core.CodeConfigError, "missing host in CDP base URL: "+baseURL)
	}
	return u.Host, nil
}

// marshalCanonicalJSON serializes v to compact JSON with recursively sorted
// object keys (encoding/json sorts map keys at every nesting level) and no
// HTML escaping, producing the canonical bytes hashed into reqHash.
func marshalCanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// computeReqHash computes the hex-encoded SHA-256 of the canonical JSON request
// body for wallet authentication. It reports ok=false when the body is absent or
// an empty object, in which case no reqHash claim is included.
func computeReqHash(body map[string]any) (string, bool, error) {
	if len(body) == 0 {
		return "", false, nil
	}
	canonical, err := marshalCanonicalJSON(body)
	if err != nil {
		return "", false, core.WrapSignerError(core.CodeSerializationError, "failed to serialize request body", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), true, nil
}

// validateEd25519KeypairBytes checks a decoded CDP API key (seed || pubkey):
// the length must be 64 and the public half must match the key derived from the
// seed.
func validateEd25519KeypairBytes(keyBytes []byte) error {
	if len(keyBytes) != ed25519.PrivateKeySize {
		return core.NewSignerError(core.CodeInvalidPrivateKey,
			"invalid Ed25519 key length: expected 64 bytes, got "+strconv.Itoa(len(keyBytes)))
	}
	derived := ed25519.NewKeyFromSeed(keyBytes[:ed25519.SeedSize])
	if !bytes.Equal(derived[ed25519.SeedSize:], keyBytes[ed25519.SeedSize:]) {
		return core.NewSignerError(core.CodeInvalidPrivateKey, "Ed25519 public key does not match seed")
	}
	return nil
}

// randomNonce returns a 32-hex-char random nonce for the auth JWT header.
func randomNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", core.WrapSignerError(core.CodeSigningFailed, "failed to generate JWT nonce", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// randomUUID returns a random version-4 UUID string for the wallet JWT jti claim.
func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", core.WrapSignerError(core.CodeSigningFailed, "failed to generate JWT id", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// createAuthJWT creates the main CDP API authentication JWT (Authorization
// bearer token). The API key secret must be a base64-encoded 64-byte Ed25519
// key (seed || pubkey); the token is signed with EdDSA and carries a `nonce`
// header field for replay prevention.
func createAuthJWT(apiKeyID, apiKeySecret, host, method, path string) (string, error) {
	if strings.HasPrefix(apiKeySecret, "-----BEGIN") {
		return "", core.NewSignerError(core.CodeInvalidPrivateKey,
			"PEM EC keys are not supported; use base64 Ed25519 key")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(apiKeySecret)
	if err != nil {
		return "", core.WrapSignerError(core.CodeInvalidPrivateKey,
			"failed to decode Ed25519 private key from base64", err)
	}
	if err := validateEd25519KeypairBytes(keyBytes); err != nil {
		return "", err
	}
	key := ed25519.NewKeyFromSeed(keyBytes[:ed25519.SeedSize])

	nonce, err := randomNonce()
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"sub":  apiKeyID,
		"iss":  "cdp",
		"iat":  now,
		"nbf":  now,
		"exp":  now + jwtTTL,
		"uris": []string{jwtURI(host, method, path)},
	})
	token.Header["kid"] = apiKeyID
	token.Header["nonce"] = nonce

	signed, err := token.SignedString(key)
	if err != nil {
		return "", core.WrapSignerError(core.CodeSigningFailed, "failed to create CDP authentication JWT", err)
	}
	return signed, nil
}

// createWalletJWT creates the CDP wallet authentication JWT (X-Wallet-Auth
// header), required for the signing endpoints. The wallet secret must be a
// base64-encoded PKCS#8 DER EC (P-256) private key; the token is signed with
// ES256 and carries a reqHash claim over the canonical request body when one is
// present.
func createWalletJWT(walletSecret, host, method, path string, requestBody map[string]any) (string, error) {
	derBytes, err := base64.StdEncoding.DecodeString(walletSecret)
	if err != nil {
		return "", core.WrapSignerError(core.CodeInvalidPrivateKey,
			"failed to decode walletSecret from base64", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		return "", core.WrapSignerError(core.CodeInvalidPrivateKey,
			"failed to parse walletSecret as EC private key", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return "", core.NewSignerError(core.CodeInvalidPrivateKey,
			"failed to parse walletSecret as EC private key")
	}

	reqHash, hasReqHash, err := computeReqHash(requestBody)
	if err != nil {
		return "", err
	}
	jti, err := randomUUID()
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"uris": []string{jwtURI(host, method, path)},
		"iat":  now,
		"nbf":  now,
		"exp":  now + jwtTTL,
		"jti":  jti,
	}
	if hasReqHash {
		claims["reqHash"] = reqHash
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(key)
	if err != nil {
		return "", core.WrapSignerError(core.CodeSigningFailed, "failed to create CDP wallet JWT", err)
	}
	return signed, nil
}
