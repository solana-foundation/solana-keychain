package privy

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"slices"
	"strings"
	"testing"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// testP256PKCS8PEM and testP256PKCS8Base64 are the same fixed P-256 PKCS#8 key
// in PEM and base64 DER form.
const testP256PKCS8PEM = "-----BEGIN PRIVATE KEY-----\n" +
	"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNVGLQN9VkU26M2JG\n" +
	"3hbSFACbGLXkQlB69ZxAhXGqf/mhRANCAATjr6H28PJiFSlRz9kfkzu9Fy6vt1uY\n" +
	"9Egu4yP/e2qnDZ+SjpcQo1hpF6Cb1h6S1a2b7qi3IEEnh+d/vzlOHAaf\n" +
	"-----END PRIVATE KEY-----"

const testP256PKCS8Base64 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNVGLQN9VkU26M2JG" +
	"3hbSFACbGLXkQlB69ZxAhXGqf/mhRANCAATjr6H28PJiFSlRz9kfkzu9Fy6vt1uY" +
	"9Egu4yP/e2qnDZ+SjpcQo1hpF6Cb1h6S1a2b7qi3IEEnh+d/vzlOHAaf"

func authorizationRequest(body any) authorizationRequestInput {
	return authorizationRequestInput{
		Version: 1,
		Method:  "POST",
		URL:     "https://api.privy.test/wallets/test-wallet-id/rpc",
		Body:    body,
		Headers: map[string]string{
			"privy-app-id":         "test-app-id",
			"privy-request-expiry": "1900000",
		},
	}
}

func testP256PublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(testP256PKCS8PEM))
	if block == nil {
		t.Fatal("failed to decode test P-256 PEM fixture")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse test P-256 key fixture: %v", err)
	}
	return &parsed.(*ecdsa.PrivateKey).PublicKey
}

// TestFormatAuthorizationPayloadEmptyBody checks that an empty JSON object body
// is canonicalized as the empty string, matching Privy's SDK.
func TestFormatAuthorizationPayloadEmptyBody(t *testing.T) {
	payload, err := formatAuthorizationSignaturePayload(authorizationRequest(map[string]any{}))
	if err != nil {
		t.Fatalf("formatAuthorizationSignaturePayload: %v", err)
	}

	want := `{"body":"","headers":{"privy-app-id":"test-app-id","privy-request-expiry":"1900000"},` +
		`"method":"POST","url":"https://api.privy.test/wallets/test-wallet-id/rpc","version":1}`
	if string(payload) != want {
		t.Errorf("payload = %s, want %s", payload, want)
	}
}

// TestGenerateAuthorizationSignaturesFromPrivateKeys checks that a prefixed
// PKCS#8 key yields a base64 DER ECDSA signature that verifies against the
// corresponding public key over the canonical payload. The PEM subtest covers
// the escaped-newline PEM path.
func TestGenerateAuthorizationSignaturesFromPrivateKeys(t *testing.T) {
	keys := map[string]string{
		"wallet-auth base64 DER": "wallet-auth:" + testP256PKCS8Base64,
		"wallet-api escaped PEM": "wallet-api:" + strings.ReplaceAll(testP256PKCS8PEM, "\n", `\n`),
	}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			request := authorizationRequest(map[string]any{
				"chain_type": "solana",
				"method":     "signMessage",
				"params": map[string]any{
					"encoding": "base64",
					"message":  "AQIDBA==",
				},
			})
			authorizationContext := &AuthorizationContext{
				AuthorizationPrivateKeys: []string{key},
			}

			signatures, err := generateAuthorizationSignatures(request, authorizationContext)
			if err != nil {
				t.Fatalf("generateAuthorizationSignatures: %v", err)
			}
			if len(signatures) != 1 {
				t.Fatalf("got %d signatures, want 1", len(signatures))
			}

			payload, err := formatAuthorizationSignaturePayload(request)
			if err != nil {
				t.Fatal(err)
			}
			signatureDER, err := base64.StdEncoding.DecodeString(signatures[0])
			if err != nil {
				t.Fatalf("signature is not valid base64: %v", err)
			}
			digest := sha256.Sum256(payload)
			if !ecdsa.VerifyASN1(testP256PublicKey(t), digest[:], signatureDER) {
				t.Error("signature should verify against the canonical payload with the key's public key")
			}
		})
	}
}

// TestAuthorizationSignatureOrder checks that precomputed signatures come
// first, then sign-fn signatures.
func TestAuthorizationSignatureOrder(t *testing.T) {
	request := authorizationRequest(map[string]any{"method": "signMessage"})
	authorizationContext := &AuthorizationContext{
		Signatures: []string{"provided"},
		SignFns: []AuthorizationSignFn{
			func([]byte) (string, error) { return "sign-fn", nil },
		},
	}

	signatures, err := generateAuthorizationSignatures(request, authorizationContext)
	if err != nil {
		t.Fatalf("generateAuthorizationSignatures: %v", err)
	}
	if want := []string{"provided", "sign-fn"}; !slices.Equal(signatures, want) {
		t.Errorf("signatures = %v, want %v", signatures, want)
	}
}

// TestInvalidAuthorizationPrivateKeyErrors checks that every parse failure is
// CodeInvalidPrivateKey with a fixed detail that never echoes the key.
func TestInvalidAuthorizationPrivateKeyErrors(t *testing.T) {
	cases := []struct {
		key        string
		wantDetail string
	}{
		{
			"wallet-auth:not-secret-but-sensitive",
			"invalid privy authorization private key encoding",
		},
		{
			"-----BEGIN PRIVATE KEY-----\nnot-secret-but-sensitive\n-----END PRIVATE KEY-----",
			"invalid privy authorization private key",
		},
		{
			base64.StdEncoding.EncodeToString([]byte("not-secret-but-sensitive")),
			"invalid privy authorization private key",
		},
	}

	for _, tc := range cases {
		_, err := parseAuthorizationPrivateKey(tc.key)
		assertCode(t, err, core.CodeInvalidPrivateKey)
		detail := detailOf(t, err)
		if detail != tc.wantDetail {
			t.Errorf("detail = %q, want %q", detail, tc.wantDetail)
		}
		if strings.Contains(detail, tc.key) || strings.Contains(detail, "not-secret-but-sensitive") {
			t.Errorf("detail %q leaks key material", detail)
		}
	}
}
