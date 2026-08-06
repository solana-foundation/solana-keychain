package cdp

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// decodeJWTPart base64url-decodes one JWT segment into a JSON map.
func decodeJWTPart(t *testing.T, part string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatalf("failed to decode JWT part: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("failed to parse JWT part: %v", err)
	}
	return m
}

func TestJWTURIFormat(t *testing.T) {
	uri := jwtURI("api.cdp.coinbase.com", "POST", "/platform/v2/solana/accounts/abc/sign/transaction")
	want := "POST api.cdp.coinbase.com/platform/v2/solana/accounts/abc/sign/transaction"
	if uri != want {
		t.Errorf("jwtURI = %q, want %q", uri, want)
	}
}

func TestExtractHost(t *testing.T) {
	cases := map[string]struct {
		baseURL string
		want    string
		wantErr bool
	}{
		"host only":      {baseURL: "https://api.cdp.coinbase.com", want: "api.cdp.coinbase.com"},
		"host with port": {baseURL: "http://127.0.0.1:8080", want: "127.0.0.1:8080"},
		"missing host":   {baseURL: "not-a-url", wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := extractHost(tc.baseURL)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("extractHost = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestComputeReqHashOmittedForEmptyBody(t *testing.T) {
	for name, body := range map[string]map[string]any{
		"nil body":     nil,
		"empty object": {},
	} {
		t.Run(name, func(t *testing.T) {
			_, ok, err := computeReqHash(body)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				t.Error("expected no reqHash for an absent/empty body")
			}
		})
	}
}

func TestAuthJWTShape(t *testing.T) {
	const host = "api.cdp.coinbase.com"
	const path = "/platform/v2/solana/accounts/abc/sign/transaction"
	token, err := createAuthJWT("test-api-key", testEd25519Key(), host, "POST", path)
	if err != nil {
		t.Fatalf("createAuthJWT failed: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}

	header := decodeJWTPart(t, parts[0])
	if header["alg"] != "EdDSA" || header["typ"] != "JWT" || header["kid"] != "test-api-key" {
		t.Errorf("unexpected header fields: %v", header)
	}
	nonce, _ := header["nonce"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(nonce) {
		t.Errorf("nonce = %q, want 32 lowercase hex chars", nonce)
	}

	claims := decodeJWTPart(t, parts[1])
	if claims["iss"] != "cdp" || claims["sub"] != "test-api-key" {
		t.Errorf("unexpected claims: %v", claims)
	}
	uris, _ := claims["uris"].([]any)
	if len(uris) != 1 || uris[0] != "POST "+host+path {
		t.Errorf("uris = %v, want [POST %s%s]", uris, host, path)
	}
	iat, iatOK := claims["iat"].(float64)
	exp, expOK := claims["exp"].(float64)
	if !iatOK || !expOK || exp-iat != jwtTTL {
		t.Errorf("exp - iat = %v - %v, want %d", exp, iat, jwtTTL)
	}

	// The token must verify against the public key derived from the test seed.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	pub := ed25519.NewKeyFromSeed(seed).Public()
	parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"EdDSA"}))
	if err != nil || !parsed.Valid {
		t.Errorf("auth JWT should verify with the API key's public key: %v", err)
	}
}

func TestAuthJWTRejectsPEMKey(t *testing.T) {
	_, err := createAuthJWT("key", "-----BEGIN EC PRIVATE KEY-----", "host", "POST", "/p")
	assertCode(t, err, core.CodeInvalidPrivateKey)
}

func TestWalletJWTIncludesReqHash(t *testing.T) {
	requestBody := map[string]any{
		"b": 2,
		"a": map[string]any{
			"d": 4,
			"c": 3,
		},
	}

	expectedHash, ok, err := computeReqHash(requestBody)
	if err != nil {
		t.Fatalf("failed to compute reqHash: %v", err)
	}
	if !ok {
		t.Fatal("expected a reqHash for a non-empty body")
	}

	token, err := createWalletJWT(
		testWalletSecret(),
		"api.cdp.coinbase.com",
		"POST",
		"/platform/v2/solana/accounts/abc/sign/message",
		requestBody,
	)
	if err != nil {
		t.Fatalf("failed to create wallet JWT: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}

	header := decodeJWTPart(t, parts[0])
	if header["alg"] != "ES256" || header["typ"] != "JWT" {
		t.Errorf("unexpected header fields: %v", header)
	}

	payload := decodeJWTPart(t, parts[1])
	reqHash, _ := payload["reqHash"].(string)
	if reqHash == "" {
		t.Fatal("reqHash missing in wallet JWT payload")
	}
	if reqHash != expectedHash {
		t.Errorf("reqHash = %q, want %q", reqHash, expectedHash)
	}
	jti, _ := payload["jti"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(jti) {
		t.Errorf("jti = %q, want a version-4 UUID", jti)
	}
}
