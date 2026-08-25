package privy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// DefaultAuthorizationRequestExpiryMs is the privy-request-expiry window applied
// when an authorization context is configured and no override is set.
const DefaultAuthorizationRequestExpiryMs uint64 = 15 * 60 * 1000

// AuthorizationSignFn is an external signer that receives the exact canonical
// authorization payload bytes and returns a base64-encoded signature.
type AuthorizationSignFn func(payload []byte) (string, error)

// AuthorizationContext supplies the material used to build the
// privy-authorization-signature header for quorum-controlled wallets.
type AuthorizationContext struct {
	// AuthorizationPrivateKeys are PKCS#8 P-256 private keys exported by Privy,
	// either base64 DER or PEM (literal "\n" sequences are converted to real
	// newlines). "wallet-auth:" and "wallet-api:" prefixes are accepted.
	AuthorizationPrivateKeys []string

	// Signatures are precomputed base64 authorization signatures for this exact
	// request.
	Signatures []string

	// SignFns are external signers invoked with the exact canonical payload bytes.
	SignFns []AuthorizationSignFn
}

// authorizationRequestInput is the value that gets canonicalized and signed.
type authorizationRequestInput struct {
	Version int
	Method  string
	URL     string
	Body    any
	Headers map[string]string
}

// authorizationHeaders carries the computed authorization header values; empty
// strings mean the header is omitted.
type authorizationHeaders struct {
	signature     string
	requestExpiry string
}

// resolveAuthorizationRequestExpiryMs maps the Config expiry fields to the
// effective window: Omit -> nil, zero -> the 15-minute default, anything
// else -> the configured window.
func resolveAuthorizationRequestExpiryMs(cfg Config) *uint64 {
	if cfg.OmitAuthorizationRequestExpiry {
		return nil
	}
	ms := cfg.AuthorizationRequestExpiryMs
	if ms == 0 {
		ms = DefaultAuthorizationRequestExpiryMs
	}
	return &ms
}

// prepareAuthorizationHeaders builds the privy-authorization-signature and
// privy-request-expiry headers for one signing request, or nothing when no
// authorization context is configured.
func (s *Signer) prepareAuthorizationHeaders(method, url string, body any) (authorizationHeaders, error) {
	if s.authorizationContext == nil {
		return authorizationHeaders{}, nil
	}

	var requestExpiry string
	if s.authorizationRequestExpiryMs != nil {
		requestExpiry = strconv.FormatUint(uint64(time.Now().UnixMilli())+*s.authorizationRequestExpiryMs, 10)
	}

	headers := map[string]string{"privy-app-id": s.appID}
	if requestExpiry != "" {
		headers["privy-request-expiry"] = requestExpiry
	}

	input := authorizationRequestInput{
		Version: 1,
		Method:  method,
		URL:     url,
		Body:    body,
		Headers: headers,
	}

	signatures, err := generateAuthorizationSignatures(input, s.authorizationContext)
	if err != nil {
		return authorizationHeaders{}, err
	}
	if len(signatures) == 0 {
		return authorizationHeaders{}, core.NewSignerError(core.CodeConfigError,
			"authorization context must include AuthorizationPrivateKeys, Signatures, or SignFns")
	}

	return authorizationHeaders{
		signature:     strings.Join(signatures, ","),
		requestExpiry: requestExpiry,
	}, nil
}

// generateAuthorizationSignatures collects the precomputed signatures, then one
// signature per private key, then one per sign fn — order preserved.
func generateAuthorizationSignatures(input authorizationRequestInput, authorizationContext *AuthorizationContext) ([]string, error) {
	payload, err := formatAuthorizationSignaturePayload(input)
	if err != nil {
		return nil, err
	}

	signatures := append([]string(nil), authorizationContext.Signatures...)
	for _, privateKey := range authorizationContext.AuthorizationPrivateKeys {
		signature, err := generateAuthorizationSignature(privateKey, payload)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, signature)
	}
	for _, signFn := range authorizationContext.SignFns {
		signature, err := signFn(payload)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, signature)
	}
	return signatures, nil
}

// formatAuthorizationSignaturePayload renders the request as canonical JSON
// (sorted keys, no whitespace), replacing an empty-object body with "" like
// Privy's SDK.
func formatAuthorizationSignaturePayload(input authorizationRequestInput) ([]byte, error) {
	bodyValue, err := toJSONValue(input.Body)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize privy authorization request", err)
	}
	if object, ok := bodyValue.(map[string]any); ok && len(object) == 0 {
		bodyValue = ""
	}

	headers := make(map[string]any, len(input.Headers))
	for name, value := range input.Headers {
		headers[name] = value
	}

	canonical, ok := canonicalizeJSON(map[string]any{
		"version": json.Number(strconv.Itoa(input.Version)),
		"method":  input.Method,
		"url":     input.URL,
		"body":    bodyValue,
		"headers": headers,
	})
	if !ok {
		return nil, core.NewSignerError(core.CodeSerializationError,
			"failed to serialize privy authorization request")
	}
	return []byte(canonical), nil
}

// generateAuthorizationSignature signs the payload with ECDSA P-256 over SHA-256
// and returns the DER signature base64-encoded.
func generateAuthorizationSignature(authorizationPrivateKey string, payload []byte) (string, error) {
	signingKey, err := parseAuthorizationPrivateKey(authorizationPrivateKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, signingKey, digest[:])
	if err != nil {
		return "", core.WrapSignerError(core.CodeSigningFailed,
			"failed to create privy authorization signature", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// parseAuthorizationPrivateKey accepts wallet-auth:/wallet-api:-prefixed base64
// PKCS#8 DER or PEM keys. Error details are fixed strings that never echo the key
// material.
func parseAuthorizationPrivateKey(authorizationPrivateKey string) (*ecdsa.PrivateKey, error) {
	normalized := strings.TrimSpace(stripAuthorizationKeyPrefix(authorizationPrivateKey))

	if strings.Contains(normalized, "-----BEGIN") {
		block, _ := pem.Decode([]byte(strings.ReplaceAll(normalized, `\n`, "\n")))
		if block == nil || block.Type != "PRIVATE KEY" {
			return nil, core.NewSignerError(core.CodeInvalidPrivateKey,
				"invalid privy authorization private key")
		}
		return parseP256PKCS8DER(block.Bytes)
	}

	compact := strings.Join(strings.Fields(normalized), "")
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, core.NewSignerError(core.CodeInvalidPrivateKey,
			"invalid privy authorization private key encoding")
	}
	return parseP256PKCS8DER(der)
}

func stripAuthorizationKeyPrefix(authorizationPrivateKey string) string {
	if stripped, ok := strings.CutPrefix(authorizationPrivateKey, "wallet-auth:"); ok {
		return stripped
	}
	if stripped, ok := strings.CutPrefix(authorizationPrivateKey, "wallet-api:"); ok {
		return stripped
	}
	return authorizationPrivateKey
}

func parseP256PKCS8DER(der []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, core.NewSignerError(core.CodeInvalidPrivateKey,
			"invalid privy authorization private key")
	}
	signingKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || signingKey.Curve != elliptic.P256() {
		return nil, core.NewSignerError(core.CodeInvalidPrivateKey,
			"invalid privy authorization private key")
	}
	return signingKey, nil
}

// toJSONValue normalizes any JSON-marshalable value into the generic form
// canonicalizeJSON consumes, preserving number literals via json.Number.
func toJSONValue(body any) (any, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// canonicalizeJSON serializes a JSON value deterministically: object keys sorted
// bytewise, no whitespace, no HTML escaping. The output bytes are what get
// signed, so the form must never change.
func canonicalizeJSON(value any) (string, bool) {
	switch v := value.(type) {
	case nil:
		return "null", true
	case bool:
		return strconv.FormatBool(v), true
	case json.Number:
		return v.String(), true
	case string:
		return encodeJSONString(v)
	case []any:
		items := make([]string, len(v))
		for i, item := range v {
			serialized, ok := canonicalizeJSON(item)
			if !ok {
				return "", false
			}
			items[i] = serialized
		}
		return "[" + strings.Join(items, ",") + "]", true
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		entries := make([]string, 0, len(v))
		for _, key := range keys {
			serializedKey, ok := encodeJSONString(key)
			if !ok {
				return "", false
			}
			serializedValue, ok := canonicalizeJSON(v[key])
			if !ok {
				return "", false
			}
			entries = append(entries, serializedKey+":"+serializedValue)
		}
		return "{" + strings.Join(entries, ",") + "}", true
	default:
		return "", false
	}
}

// encodeJSONString marshals a string without Go's default HTML escaping so
// characters like <, >, and & stay literal in the canonical payload.
func encodeJSONString(value string) (string, bool) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", false
	}
	return strings.TrimSuffix(buf.String(), "\n"), true
}
