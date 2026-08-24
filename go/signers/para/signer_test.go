package para

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
	"github.com/solana-foundation/solana-keychain/go/testutils"
)

// testWalletID is a syntactically valid Para wallet UUID used across tests.
const testWalletID = "12345678-1234-1234-1234-123456789abc"

const walletPath = "/v1/wallets/" + testWalletID

const signRawPath = walletPath + "/sign-raw"

// newBareSigner builds a Signer struct directly, bypassing New (and thus the
// wallet fetch in init).
func newBareSigner(srv *httptest.Server, apiKey string) *Signer {
	return &Signer{apiKey: apiKey, walletID: testWalletID, baseURL: srv.URL, client: srv.Client()}
}

func testConfig(srv *httptest.Server, apiKey string) Config {
	return Config{APIKey: apiKey, WalletID: testWalletID, APIBaseURL: srv.URL, HTTPClient: srv.Client()}
}

// signFixture returns the deterministic test keypair, a test transaction's
// message bytes, and a real ed25519 signature over them so verification
// passes.
func signFixture(t *testing.T) (pub solana.PublicKey, msg []byte, sig []byte) {
	t.Helper()
	priv := testutils.TestPrivateKey()
	pub = testutils.TestPublicKey()
	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatalf("failed to build test transaction: %v", err)
	}
	msg, err = tx.Message.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to serialize test message: %v", err)
	}
	return pub, msg, ed25519.Sign(priv, msg)
}

// --- Validation tests ---

func TestNewValidatesAPIKeyPrefix(t *testing.T) {
	_, err := New(context.Background(), Config{APIKey: "bad-key", WalletID: testWalletID})
	testutils.AssertCode(t, err, core.CodeConfigError)
	if err.Error() != "Configuration error" {
		t.Fatalf("expected generic message, got %q", err.Error())
	}
}

func TestNewValidatesWalletIDUUID(t *testing.T) {
	_, err := New(context.Background(), Config{APIKey: "sk_test-key", WalletID: "not-a-uuid"})
	testutils.AssertCode(t, err, core.CodeConfigError)
	if err.Error() != "Configuration error" {
		t.Fatalf("expected generic message, got %q", err.Error())
	}
}

func TestNewValidatesEmptyFields(t *testing.T) {
	for name, cfg := range map[string]Config{
		"empty api key":   {APIKey: "", WalletID: testWalletID},
		"empty wallet id": {APIKey: "sk_test-key", WalletID: ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), cfg)
			testutils.AssertCode(t, err, core.CodeConfigError)
		})
	}
}

func TestNewValid(t *testing.T) {
	// Validation/normalization only; newUninitialized does not fetch the wallet.
	s, err := newUninitialized(Config{APIKey: "sk_test-key", WalletID: testWalletID})
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if s.baseURL != DefaultBaseURL {
		t.Errorf("expected default base URL %q, got %q", DefaultBaseURL, s.baseURL)
	}
	if !s.pubkey.IsZero() {
		t.Errorf("expected zero public key before init, got %s", s.pubkey)
	}
}

func TestNewCustomURLStripsTrailingSlash(t *testing.T) {
	s, err := newUninitialized(Config{
		APIKey:     "sk_test-key",
		WalletID:   testWalletID,
		APIBaseURL: "https://custom.api.com/",
	})
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if s.baseURL != "https://custom.api.com" {
		t.Errorf("expected trailing slash stripped, got %q", s.baseURL)
	}
}

func TestNewRejectsHTTPURL(t *testing.T) {
	// Default client (nil HTTPClient) must reject a non-HTTPS base URL.
	_, err := New(context.Background(), Config{
		APIKey:     "sk_test-key",
		WalletID:   testWalletID,
		APIBaseURL: "http://insecure.example.com",
	})
	testutils.AssertCode(t, err, core.CodeConfigError)
}

func TestNewRejectsHTTPURLWithCustomClient(t *testing.T) {
	// A caller-supplied HTTPClient must not bypass the HTTPS requirement; the
	// base URL is always validated.
	_, err := New(context.Background(), Config{
		APIKey:     "sk_test-key",
		WalletID:   testWalletID,
		APIBaseURL: "http://insecure.example.com",
		HTTPClient: http.DefaultClient,
	})
	testutils.AssertCode(t, err, core.CodeConfigError)
}

func TestIsValidUUID(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"12345678-1234-1234-1234-123456789abc", true},
		{"ABCDEF01-2345-6789-ABCD-EF0123456789", true},
		{"not-a-uuid", false},
		{"", false},
		{"12345678123412341234123456789abc", false},     // no dashes
		{"1234567g-1234-1234-1234-123456789abc", false}, // 'g' is not hex
	}
	for _, tc := range cases {
		if got := isValidUUID(tc.input); got != tc.want {
			t.Errorf("isValidUUID(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// --- Sign before init ---

func TestSignMessageBeforeInit(t *testing.T) {
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("no request expected before init")
	}))
	s := newBareSigner(srv, "test-api-key")

	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeConfigError)
}

// --- Init tests ---

func TestNewInitSuccess(t *testing.T) {
	pub := testutils.TestPublicKey()
	var calls atomic.Int32
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != walletPath {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-API-Key"); got != "sk_test-key" {
			t.Errorf("expected X-API-Key header, got %q", got)
		}
		testutils.WriteJSON(w, http.StatusOK, map[string]any{
			"id":      testWalletID,
			"address": pub.String(),
			"type":    "SOLANA",
			"status":  "ACTIVE",
		})
	}))

	s, err := New(context.Background(), testConfig(srv, "sk_test-key"))
	if err != nil {
		t.Fatalf("expected init success, got %v", err)
	}
	if s.Pubkey() != pub {
		t.Errorf("expected pubkey %s, got %s", pub, s.Pubkey())
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 wallet fetch, got %d", calls.Load())
	}
}

func TestNewInitCaseInsensitiveType(t *testing.T) {
	pub := testutils.TestPublicKey()
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{
			"id":      testWalletID,
			"address": pub.String(),
			"type":    "Solana",
			"status":  "active",
		})
	}))

	if _, err := New(context.Background(), testConfig(srv, "sk_test-key")); err != nil {
		t.Fatalf("expected mixed-case type/status to be accepted, got %v", err)
	}
}

func TestNewInitNonSolanaWallet(t *testing.T) {
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{
			"id":      testWalletID,
			"address": "0xabc123",
			"type":    "EVM",
			"status":  "ACTIVE",
		})
	}))

	_, err := New(context.Background(), testConfig(srv, "sk_test-key"))
	testutils.AssertCode(t, err, core.CodeConfigError)
}

func TestNewInitNoAddress(t *testing.T) {
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{
			"id":     testWalletID,
			"type":   "SOLANA",
			"status": "ACTIVE",
		})
	}))

	_, err := New(context.Background(), testConfig(srv, "sk_test-key"))
	testutils.AssertCode(t, err, core.CodeConfigError)
}

func TestNewInitInvalidPubkey(t *testing.T) {
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{
			"id":      testWalletID,
			"address": "not-a-valid-pubkey",
			"type":    "SOLANA",
			"status":  "ACTIVE",
		})
	}))

	_, err := New(context.Background(), testConfig(srv, "sk_test-key"))
	testutils.AssertCode(t, err, core.CodeInvalidPublicKey)
}

func TestNewInitUnauthorized(t *testing.T) {
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusUnauthorized, map[string]any{"message": "Invalid API key"})
	}))

	_, err := New(context.Background(), testConfig(srv, "sk_bad-api-key"))
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)
	if err.Error() != "Remote API error" {
		t.Fatalf("expected generic message, got %q", err.Error())
	}
}

func TestNewInitMalformedJSON(t *testing.T) {
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "not json")
	}))

	_, err := New(context.Background(), testConfig(srv, "sk_test-key"))
	testutils.AssertCode(t, err, core.CodeSerializationError)
}

func TestNewInitMissingTypeField(t *testing.T) {
	// The JSON decoder tolerates a missing "type" field, so this surfaces as
	// the SOLANA type check failing.
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{
			"id":      testWalletID,
			"address": "11111111111111111111111111111111",
			"status":  "ACTIVE",
		})
	}))

	_, err := New(context.Background(), testConfig(srv, "sk_test-key"))
	testutils.AssertCode(t, err, core.CodeConfigError)
}

func TestNewInitCreatingStatusWithAddress(t *testing.T) {
	// init does not check status; only IsAvailable does.
	pub := testutils.TestPublicKey()
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{
			"id":      testWalletID,
			"address": pub.String(),
			"type":    "SOLANA",
			"status":  "CREATING",
		})
	}))

	s, err := New(context.Background(), testConfig(srv, "sk_test-key"))
	if err != nil {
		t.Fatalf("expected init to ignore CREATING status, got %v", err)
	}
	if s.Pubkey() != pub {
		t.Errorf("expected pubkey %s, got %s", pub, s.Pubkey())
	}
}

// --- Sign tests ---

func TestSignMessageSuccess(t *testing.T) {
	pub, msg, sig := signFixture(t)
	var calls atomic.Int32
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != signRawPath {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-API-Key"); got != "test-api-key" {
			t.Errorf("expected X-API-Key header, got %q", got)
		}
		var req signRawRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode sign-raw request: %v", err)
		}
		if req.Encoding != "hex" || req.Data != hex.EncodeToString(msg) {
			t.Errorf("unexpected sign-raw request body: %+v", req)
		}
		testutils.WriteJSON(w, http.StatusOK, map[string]any{"signature": hex.EncodeToString(sig)})
	}))
	s := newBareSigner(srv, "test-api-key")
	s.pubkey = pub

	got, err := s.SignMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("expected sign success, got %v", err)
	}
	if !bytes.Equal(got[:], sig) {
		t.Errorf("signature mismatch: got %s", got)
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 sign-raw call, got %d", calls.Load())
	}
}

func TestSignMessage0xPrefix(t *testing.T) {
	pub, msg, sig := signFixture(t)
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{"signature": "0x" + hex.EncodeToString(sig)})
	}))
	s := newBareSigner(srv, "test-api-key")
	s.pubkey = pub

	got, err := s.SignMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("expected sign success, got %v", err)
	}
	if !bytes.Equal(got[:], sig) {
		t.Errorf("signature mismatch: got %s", got)
	}
}

func TestSignTransaction(t *testing.T) {
	pub, msg, sig := signFixture(t)
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != signRawPath {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		testutils.WriteJSON(w, http.StatusOK, map[string]any{"signature": hex.EncodeToString(sig)})
	}))
	s := newBareSigner(srv, "test-api-key")
	s.pubkey = pub

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatalf("failed to build test transaction: %v", err)
	}
	signed, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("expected sign success, got %v", err)
	}
	if !bytes.Equal(signed.Signature[:], sig) {
		t.Errorf("signature mismatch: got %s", signed.Signature)
	}
	if signed.EncodedTransaction == "" {
		t.Error("expected non-empty encoded transaction")
	}
	if !signed.IsComplete() {
		t.Error("expected single-signer transaction to be complete")
	}
	if !core.VerifyEd25519(pub, msg, signed.Signature) {
		t.Error("expected returned signature to verify against the message")
	}
}

func TestSignMessageUnauthorized(t *testing.T) {
	pub, _, _ := signFixture(t)
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusUnauthorized, map[string]any{"message": "Unauthorized"})
	}))
	s := newBareSigner(srv, "bad-api-key")
	s.pubkey = pub

	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)
}

func TestSignMessageMissingSignature(t *testing.T) {
	pub, _, _ := signFixture(t)
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{})
	}))
	s := newBareSigner(srv, "test-api-key")
	s.pubkey = pub

	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeSigningFailed)
}

func TestSignMessageInvalidHexLength(t *testing.T) {
	pub, _, _ := signFixture(t)
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{"signature": "aabbccdd"})
	}))
	s := newBareSigner(srv, "test-api-key")
	s.pubkey = pub

	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeSigningFailed)
}

func TestSignMessageInvalidHexChars(t *testing.T) {
	pub, _, _ := signFixture(t)
	// 128 chars but not valid hex.
	badHex := strings.Repeat("z", 128)
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{"signature": badHex})
	}))
	s := newBareSigner(srv, "test-api-key")
	s.pubkey = pub

	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeSigningFailed)
}

func TestSignMessageMalformedJSON(t *testing.T) {
	pub, _, _ := signFixture(t)
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "not json")
	}))
	s := newBareSigner(srv, "test-api-key")
	s.pubkey = pub

	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeSerializationError)
}

func TestSignMessageVerificationFailure(t *testing.T) {
	// A valid-format but wrong signature (64 zero bytes) must fail verification.
	pub, _, _ := signFixture(t)
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{"signature": strings.Repeat("00", 64)})
	}))
	s := newBareSigner(srv, "test-api-key")
	s.pubkey = pub

	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeSigningFailed)
}

func TestSignMessageErrorStatusCodeOnly(t *testing.T) {
	// Error output must stay generic and never include API response text.
	pub, _, _ := signFixture(t)
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusForbidden, map[string]any{"message": "Wallet is locked"})
	}))
	s := newBareSigner(srv, "test-api-key")
	s.pubkey = pub

	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)
	if err.Error() != "Remote API error" {
		t.Errorf("expected generic message, got %q", err.Error())
	}
	var se *core.SignerError
	if !errors.As(err, &se) {
		t.Fatalf("expected *core.SignerError, got %T", err)
	}
	if se.Detail() != "API error 403" {
		t.Errorf("expected detail to carry only the status code, got %q", se.Detail())
	}
	if strings.Contains(se.Detail(), "Wallet is locked") {
		t.Error("detail must not contain the remote response body")
	}
}

// --- IsAvailable tests ---

func TestIsAvailable(t *testing.T) {
	cases := []struct {
		name       string
		walletType string
		status     string
		want       bool
	}{
		{"ready", "SOLANA", "READY", true},
		{"active", "SOLANA", "ACTIVE", true},
		{"creating", "SOLANA", "CREATING", false},
		{"non-solana", "EVM", "ACTIVE", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != walletPath {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				testutils.WriteJSON(w, http.StatusOK, map[string]any{
					"id":      testWalletID,
					"address": testutils.TestPublicKey().String(),
					"type":    tc.walletType,
					"status":  tc.status,
				})
			}))
			s := newBareSigner(srv, "test-api-key")

			if got := s.IsAvailable(context.Background()); got != tc.want {
				t.Errorf("IsAvailable() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsAvailableAPIError(t *testing.T) {
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	s := newBareSigner(srv, "test-api-key")

	if s.IsAvailable(context.Background()) {
		t.Error("expected false on API error")
	}
}

func TestIsAvailableTimeout(t *testing.T) {
	// The handler blocks until the client gives up, exercising the bounded
	// health check without a 5s wait: the caller context expires first.
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	s := newBareSigner(srv, "test-api-key")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if s.IsAvailable(ctx) {
		t.Error("expected false on timeout")
	}
}

// --- Redaction ---

func TestStringHidesSecrets(t *testing.T) {
	s := &Signer{apiKey: "secret-api-key", walletID: "secret-wallet-id", baseURL: DefaultBaseURL}

	for _, rendered := range []string{
		fmt.Sprintf("%v", s),
		fmt.Sprintf("%+v", s),
		fmt.Sprintf("%#v", s),
		s.String(),
	} {
		if strings.Contains(rendered, "secret-api-key") || strings.Contains(rendered, "secret-wallet-id") {
			t.Errorf("rendered signer leaks secrets: %q", rendered)
		}
		if !strings.Contains(rendered, "para.Signer") {
			t.Errorf("expected para.Signer marker, got %q", rendered)
		}
	}
}

// roundTripFunc adapts a function to http.RoundTripper for transport-level tests.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestDoRequestPreservesTransportSignerError guards the passthrough of
// SignerError codes raised inside the transport (e.g. the HTTPS-only guard's
// CodeConfigError): they must not be re-wrapped as CodeHTTPError.
func TestDoRequestPreservesTransportSignerError(t *testing.T) {
	blocked := core.NewSignerError(core.CodeConfigError, "non-HTTPS request blocked")
	s := &Signer{apiKey: "sk_test-key", walletID: testWalletID, baseURL: "https://example.invalid",
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, blocked
		})}}
	_, err := s.doRequest(context.Background(), http.MethodGet, s.baseURL+"/x", nil)
	testutils.AssertCode(t, err, core.CodeConfigError)
}
