package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

const (
	testVaultAddr = "https://vault.example.com"
	testToken     = "test-token"
	testKeyName   = "test-key"
	testPubkey    = "2vfDxWYbhRt7GXiRYKf1Dr5Z8y7zVQCSERbDTKyBaAqQ"

	signPath = "/v1/transit/sign/test-key"
	keysPath = "/v1/transit/keys/test-key"
)

func newTestSigner(t *testing.T, vaultAddr, pubkey string, client *http.Client) *Signer {
	t.Helper()
	s, err := New(Config{
		VaultAddr:  vaultAddr,
		Token:      testToken,
		KeyName:    testKeyName,
		Pubkey:     pubkey,
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// signHandler mocks the transit sign endpoint: it asserts the request shape
// (method, path, X-Vault-Token header, and — when wantInput is non-empty — the
// base64 "input" body field), counts calls, and replies with status/body.
func signHandler(t *testing.T, wantInput string, status int, body string, calls *int32) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != signPath {
			t.Errorf("path = %s, want %s", r.URL.Path, signPath)
		}
		if got := r.Header.Get("X-Vault-Token"); got != testToken {
			t.Errorf("X-Vault-Token = %q, want %q", got, testToken)
		}
		if wantInput != "" {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read request body: %v", err)
			}
			var req struct {
				Input string `json:"input"`
			}
			if err := json.Unmarshal(raw, &req); err != nil {
				t.Errorf("unmarshal request body: %v", err)
			}
			if req.Input != wantInput {
				t.Errorf("input = %q, want %q", req.Input, wantInput)
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func signSuccessBody(prefix string, sig solana.Signature) string {
	return `{"data":{"signature":"` + prefix + base64.StdEncoding.EncodeToString(sig[:]) + `"}}`
}

func TestNew(t *testing.T) {
	s, err := New(Config{
		VaultAddr: testVaultAddr,
		Token:     testToken,
		KeyName:   testKeyName,
		Pubkey:    testPubkey,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil signer")
	}
}

func TestNewInvalidPubkey(t *testing.T) {
	_, err := New(Config{
		VaultAddr: testVaultAddr,
		Token:     testToken,
		KeyName:   testKeyName,
		Pubkey:    "invalid-pubkey",
	})
	if err == nil {
		t.Fatal("expected error for invalid pubkey")
	}
	if code, _ := core.CodeOf(err); code != core.CodeInvalidPublicKey {
		t.Errorf("code = %s, want %s", code, core.CodeInvalidPublicKey)
	}
}

func TestPubkey(t *testing.T) {
	s := newTestSigner(t, testVaultAddr, testPubkey, nil)
	if got := s.Pubkey().String(); got != testPubkey {
		t.Errorf("pubkey = %s, want %s", got, testPubkey)
	}
}

func TestStripVaultSignaturePrefix(t *testing.T) {
	cases := map[string]struct {
		in, want string
	}{
		"v1":                      {"vault:v1:abc123", "abc123"},
		"higher version":          {"vault:v27:abc123", "abc123"},
		"no prefix":               {"abc123", "abc123"},
		"non-digit version":       {"vault:vx:abc123", "vault:vx:abc123"},
		"empty version segment":   {"vault:v:abc123", "vault:v:abc123"},
		"missing second colon":    {"vault:v1", "vault:v1"},
		"mixed digits and letter": {"vault:v1x:abc123", "vault:v1x:abc123"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := stripVaultSignaturePrefix(tc.in); got != tc.want {
				t.Errorf("stripVaultSignaturePrefix(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A caller-supplied client is the one used for outbound requests. The mock
// server is plain HTTP, so the
// default (HTTPS-only) client could never reach it — precisely the point of the
// HTTPClient override: the caller owns the TLS (or lack thereof) policy.
func TestSuppliedHTTPClientIsUsed(t *testing.T) {
	priv := testutils.TestPrivateKey()
	message := []byte("with-client-message")
	sig := testutils.SignWith(priv, message)
	wantInput := base64.StdEncoding.EncodeToString(message)

	var calls int32
	srv := httptest.NewServer(signHandler(t, wantInput, http.StatusOK, signSuccessBody("vault:v1:", sig), &calls))
	defer srv.Close()

	s := newTestSigner(t, srv.URL, testutils.PubkeyOf(priv).String(), srv.Client())
	got, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if got != sig {
		t.Errorf("signature = %s, want %s", got, sig)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("sign endpoint called %d times, want 1", n)
	}
}

func TestSignMessageSuccess(t *testing.T) {
	priv := testutils.TestPrivateKey()
	message := []byte("vault-message")
	sig := testutils.SignWith(priv, message)
	wantInput := base64.StdEncoding.EncodeToString(message)

	var calls int32
	srv := httptest.NewServer(signHandler(t, wantInput, http.StatusOK, signSuccessBody("vault:v1:", sig), &calls))
	defer srv.Close()

	s := newTestSigner(t, srv.URL, testutils.PubkeyOf(priv).String(), srv.Client())
	got, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if got != sig {
		t.Errorf("signature = %s, want %s", got, sig)
	}
	if !core.VerifyEd25519(s.Pubkey(), message, got) {
		t.Error("signature should verify against the signer's pubkey")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("sign endpoint called %d times, want 1", n)
	}
}

// Vault returns a valid signature made by a different key, so verification against the
// configured pubkey must fail with CodeSigningFailed.
func TestSignMessageSignatureVerificationFailure(t *testing.T) {
	signingPriv := testutils.TestPrivateKey()
	differentPriv, _ := testutils.KeyFromSeed(0xAB)
	message := []byte("vault-message")
	sig := testutils.SignWith(signingPriv, message)
	wantInput := base64.StdEncoding.EncodeToString(message)

	var calls int32
	srv := httptest.NewServer(signHandler(t, wantInput, http.StatusOK, signSuccessBody("vault:v1:", sig), &calls))
	defer srv.Close()

	s := newTestSigner(t, srv.URL, testutils.PubkeyOf(differentPriv).String(), srv.Client())
	_, err := s.SignMessage(context.Background(), message)
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("code = %s, want %s", code, core.CodeSigningFailed)
	}
}

func TestSignMessageAPIError(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(signHandler(t, "", http.StatusUnauthorized, `{"errors":["unauthorized"]}`, &calls))
	defer srv.Close()

	s := newTestSigner(t, srv.URL, testPubkey, srv.Client())
	_, err := s.SignMessage(context.Background(), []byte("hello"))
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("code = %s, want %s", code, core.CodeRemoteAPIError)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("sign endpoint called %d times, want 1", n)
	}
}

// Hostile remote error bodies must pass through core.SanitizeRemoteResponse
// before landing in the (opt-in) error detail.
func TestSignMessageErrorBodySanitized(t *testing.T) {
	hostile := "bad\x00thing\x1b[31m " + strings.Repeat("x", 1000)
	srv := httptest.NewServer(signHandler(t, "", http.StatusInternalServerError, hostile, new(int32)))
	defer srv.Close()

	s := newTestSigner(t, srv.URL, testPubkey, srv.Client())
	_, err := s.SignMessage(context.Background(), []byte("hello"))
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	var se *core.SignerError
	if !errors.As(err, &se) {
		t.Fatalf("error is not a *core.SignerError: %v", err)
	}
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("code = %s, want %s", code, core.CodeRemoteAPIError)
	}
	detail := se.Detail()
	if strings.ContainsAny(detail, "\x00\x1b") {
		t.Errorf("detail contains raw control characters: %q", detail)
	}
	if !strings.Contains(detail, "[truncated]") {
		t.Errorf("long hostile body should be truncated, got %q", detail)
	}
}

func TestSignTransactionSuccess(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.PubkeyOf(priv)

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sig := testutils.SignWith(priv, msg)
	wantInput := base64.StdEncoding.EncodeToString(msg)

	var calls int32
	srv := httptest.NewServer(signHandler(t, wantInput, http.StatusOK, signSuccessBody("vault:v2:", sig), &calls))
	defer srv.Close()

	s := newTestSigner(t, srv.URL, pub.String(), srv.Client())
	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	if res.Signature != sig {
		t.Errorf("signature = %s, want %s", res.Signature, sig)
	}
	if res.EncodedTransaction == "" {
		t.Error("encoded transaction should not be empty")
	}
	if !res.IsComplete() {
		t.Error("single-signer transaction should be Complete")
	}
	if len(tx.Signatures) != 1 {
		t.Fatalf("tx has %d signatures, want 1", len(tx.Signatures))
	}
	if tx.Signatures[0] != sig {
		t.Error("transaction signature mismatch at position 0")
	}
	decoded, err := solana.TransactionFromBase64(res.EncodedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Signatures[0] != sig {
		t.Error("encoded transaction signature mismatch at position 0")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("sign endpoint called %d times, want 1", n)
	}
}

func TestIsAvailable(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		want   bool
	}{
		"success": {
			http.StatusOK,
			`{"data":{"name":"test-key","supports_signing":true,"type":"ed25519"}}`,
			true,
		},
		"unsupported key type": {
			http.StatusOK,
			`{"data":{"name":"test-key","supports_signing":true,"type":"rsa-2048"}}`,
			false,
		},
		"key does not support signing": {
			http.StatusOK,
			`{"data":{"name":"test-key","supports_signing":false,"type":"ed25519"}}`,
			false,
		},
		"api failure": {
			http.StatusForbidden,
			`{"errors":["forbidden"]}`,
			false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var calls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&calls, 1)
				if r.Method != http.MethodGet {
					t.Errorf("method = %s, want GET", r.Method)
				}
				if r.URL.Path != keysPath {
					t.Errorf("path = %s, want %s", r.URL.Path, keysPath)
				}
				if got := r.Header.Get("X-Vault-Token"); got != testToken {
					t.Errorf("X-Vault-Token = %q, want %q", got, testToken)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			s := newTestSigner(t, srv.URL, testPubkey, srv.Client())
			if got := s.IsAvailable(context.Background()); got != tc.want {
				t.Errorf("IsAvailable = %v, want %v", got, tc.want)
			}
			if n := atomic.LoadInt32(&calls); n != 1 {
				t.Errorf("keys endpoint called %d times, want 1", n)
			}
		})
	}
}

// The default client (nil Config.HTTPClient) enforces HTTPS: any request to an
// http:// Vault address must fail with CodeConfigError and never reach the wire.
func TestDefaultClientRejectsHTTP(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(signHandler(t, "", http.StatusOK, "{}", &calls))
	defer srv.Close()

	s := newTestSigner(t, srv.URL, testPubkey, nil)
	_, err := s.SignMessage(context.Background(), []byte("hello"))
	if err == nil {
		t.Fatal("expected error for http:// address with the default client")
	}
	if code, _ := core.CodeOf(err); code != core.CodeConfigError {
		t.Errorf("code = %s, want %s", code, core.CodeConfigError)
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("sign endpoint called %d times, want 0", n)
	}
	if s.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be false over http:// with the default client")
	}
}
