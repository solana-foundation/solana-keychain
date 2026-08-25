package openfort

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// jwtLifetimeSecs is how long a wallet-auth JWT stays valid.
const jwtLifetimeSecs int64 = 120

// jwtURI formats the JWT `uris` claim entry as "<METHOD> <HOST><PATH>".
func jwtURI(host, method, path string) string {
	return method + " " + host + path
}

// computeReqHash returns hex(sha256(canonical-JSON(body))), where the
// canonical form recursively sorts object keys so the hash is key-order
// invariant.
func computeReqHash(body []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", core.WrapSignerError(core.CodeSerializationError, "failed to serialize request body", err)
	}
	return core.CanonicalRequestHash(v)
}

// walletSecretToPEM normalizes the wallet secret to a PEM string. A full PEM
// input is passed through verbatim; a bare base64 PKCS#8 DER body (the
// convenient single-line form) has whitespace stripped and is wrapped in PEM
// headers.
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
// accepting bare base64 PKCS#8 DER or full PEM.
func parseWalletSecret(walletSecret string) (*ecdsa.PrivateKey, error) {
	key, err := jwt.ParseECPrivateKeyFromPEM([]byte(walletSecretToPEM(walletSecret)))
	if err != nil {
		return nil, core.NewSignerError(core.CodeInvalidPrivateKey,
			"failed to parse openfort wallet secret as EC P-256 private key (expected base64 PKCS#8 DER or PEM)")
	}
	return key, nil
}

// createWalletJWT builds the x-wallet-auth ES256 JWT for an Openfort backend
// wallet request. Claims: uris, iat, nbf, exp, jti, and reqHash over the
// request body.
func createWalletJWT(walletSecret, host, method, path string, requestBody []byte) (string, error) {
	key, err := parseWalletSecret(walletSecret)
	if err != nil {
		return "", err
	}
	reqHash, err := computeReqHash(requestBody)
	if err != nil {
		return "", err
	}
	jti, err := core.RandomUUIDv4()
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
