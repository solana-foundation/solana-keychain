package openfort

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// jwtLifetimeSecs is how long a wallet-auth JWT stays valid (parity with the
// Rust JWT_LIFETIME_SECS).
const jwtLifetimeSecs int64 = 120

// jwtURI formats the JWT `uris` claim entry as "<METHOD> <HOST><PATH>". Port
// of the Rust jwt_uri.
func jwtURI(host, method, path string) string {
	return method + " " + host + path
}

// marshalCanonical serializes v to compact JSON with object keys sorted
// (encoding/json sorts map keys) and without HTML escaping, matching the byte
// output of Rust's serde_json over a sorted map.
func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, core.WrapSignerError(core.CodeSerializationError, "failed to serialize request body", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// computeReqHash returns hex(sha256(canonical-JSON(body))), where the
// canonical form recursively sorts object keys so the hash is key-order
// invariant. Port of the Rust sort_json + compute_req_hash.
func computeReqHash(body []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", core.WrapSignerError(core.CodeSerializationError, "failed to serialize request body", err)
	}
	canonical, err := marshalCanonical(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// walletSecretToPEM normalizes the wallet secret to a PEM string. A full PEM
// input is passed through verbatim; a bare base64 PKCS#8 DER body (the
// convenient single-line form) has whitespace stripped and is wrapped in PEM
// headers. Port of the Rust wallet_secret_to_pem.
func walletSecretToPEM(walletSecret string) string {
	if strings.HasPrefix(strings.TrimLeftFunc(walletSecret, unicode.IsSpace), "-----BEGIN") {
		return walletSecret
	}
	var b strings.Builder
	b.Grow(len(walletSecret))
	for _, r := range walletSecret {
		if !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	return "-----BEGIN PRIVATE KEY-----\n" + b.String() + "\n-----END PRIVATE KEY-----\n"
}

// parseWalletSecret parses the wallet secret into an ECDSA private key,
// accepting bare base64 PKCS#8 DER or full PEM (parity with the Rust
// EncodingKey::from_ec_pem call).
func parseWalletSecret(walletSecret string) (*ecdsa.PrivateKey, error) {
	key, err := jwt.ParseECPrivateKeyFromPEM([]byte(walletSecretToPEM(walletSecret)))
	if err != nil {
		return nil, core.NewSignerError(core.CodeInvalidPrivateKey,
			"failed to parse openfort wallet secret as EC P-256 private key (expected base64 PKCS#8 DER or PEM)")
	}
	return key, nil
}

// newUUIDv4 returns an RFC 4122 version-4 UUID string for the JWT `jti` claim
// (the Go analog of the Rust Uuid::new_v4).
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", core.WrapSignerError(core.CodeSigningFailed, "failed to generate jwt request id", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// createWalletJWT builds the x-wallet-auth ES256 JWT for an Openfort backend
// wallet request. Claims mirror the Rust WalletClaims: uris, iat, nbf, exp,
// jti, and reqHash over the request body. Port of the Rust create_wallet_jwt.
func createWalletJWT(walletSecret, host, method, path string, requestBody []byte) (string, error) {
	key, err := parseWalletSecret(walletSecret)
	if err != nil {
		return "", err
	}
	reqHash, err := computeReqHash(requestBody)
	if err != nil {
		return "", err
	}
	jti, err := newUUIDv4()
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"uris":    []string{jwtURI(host, method, path)},
		"iat":     now,
		"nbf":     now,
		"exp":     now + jwtLifetimeSecs,
		"jti":     jti,
		"reqHash": reqHash,
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(key)
	if err != nil {
		return "", core.NewSignerError(core.CodeSigningFailed, "failed to create openfort wallet JWT")
	}
	return signed, nil
}
