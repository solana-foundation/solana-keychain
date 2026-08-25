package core

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
)

// MarshalCanonicalJSON serializes v to compact JSON with recursively sorted
// object keys (encoding/json sorts map keys at every nesting level) and no HTML
// escaping, so `<`, `>`, and `&` survive into the bytes a provider signs over.
func MarshalCanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, WrapSignerError(CodeSerializationError, "failed to serialize request body", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// CanonicalRequestHash returns hex(sha256(MarshalCanonicalJSON(v))), the request
// digest wallet-auth JWTs bind a request body to.
func CanonicalRequestHash(v any) (string, error) {
	canonical, err := MarshalCanonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// FormatUUID renders 16 bytes as a version-4 RFC 4122 UUID string, tagging the
// version and variant bits in place.
func FormatUUID(b [16]byte) string {
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// RandomUUIDv4 returns a random version-4 UUID, used for JWT jti and nonce
// claims.
func RandomUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", WrapSignerError(CodeSigningFailed, "failed to generate random identifier", err)
	}
	return FormatUUID(b), nil
}

// HostFromURL returns the host (with port, if present) of baseURL.
func HostFromURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", WrapSignerError(CodeConfigError, "invalid base URL: "+baseURL, err)
	}
	if u.Host == "" {
		return "", NewSignerError(CodeConfigError, "missing host in base URL: "+baseURL)
	}
	return u.Host, nil
}
