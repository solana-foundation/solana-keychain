package openfort

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/golang-jwt/jwt/v5"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

const (
	// testPubkey is a fixed foreign address (we do not hold its key).
	testPubkey    = "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV"
	testAccountID = "acc_e0b84653-1741-4a3d-9e91-2b0fd2942f60"
	testSecretKey = "sk_test_secret"
)

// mockAPI serves the two Openfort endpoints the signer uses. The account
// response can be swapped mid-test (atomically) so behavior can change after
// New has initialized the signer.
type mockAPI struct {
	srv            *httptest.Server
	accountStatus  atomic.Int64
	accountAddress atomic.Value // string
}

func newMockAPI(t *testing.T, address string, signHandler http.HandlerFunc) *mockAPI {
	t.Helper()
	m := &mockAPI{}
	m.accountStatus.Store(http.StatusOK)
	m.accountAddress.Store(address)

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+accountsPath+"/"+testAccountID, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testSecretKey {
			t.Error("account fetch missing Authorization bearer header")
		}
		if status := int(m.accountStatus.Load()); status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"address": m.accountAddress.Load().(string)})
	})
	if signHandler != nil {
		mux.HandleFunc("POST "+backendPath+"/"+testAccountID+"/sign", signHandler)
	}

	m.srv = httptest.NewTLSServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockAPI) config() Config {
	return Config{
		SecretKey:    testSecretKey,
		AccountID:    testAccountID,
		WalletSecret: testWalletSecretB64(),
		APIBaseURL:   m.srv.URL,
		HTTPClient:   m.srv.Client(),
	}
}

// signStatusHandler responds to the sign endpoint with a bare status code.
func signStatusHandler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}
}

// signResponder responds to the sign endpoint with the given signature value
// after checking the auth headers.
func signResponder(t *testing.T, sigHex string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testSecretKey {
			t.Error("sign request missing Authorization bearer header")
		}
		if r.Header.Get("x-wallet-auth") == "" {
			t.Error("sign request missing x-wallet-auth header")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"object":    "signature",
			"account":   testAccountID,
			"signature": sigHex,
		})
	}
}

// verifyWalletJWT fully verifies the x-wallet-auth token: ES256 signature
// against the test wallet key, uris claim of the form "<METHOD> <HOST><PATH>",
// reqHash over the exact request body, and a v4-UUID jti.
func verifyWalletJWT(t *testing.T, r *http.Request, body []byte) {
	t.Helper()
	tokenStr := r.Header.Get("x-wallet-auth")
	if tokenStr == "" {
		t.Error("sign request missing x-wallet-auth header")
		return
	}
	key, err := parseWalletSecret(testWalletSecretB64())
	if err != nil {
		t.Errorf("test wallet secret should parse: %v", err)
		return
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims,
		func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}))
	if err != nil || !token.Valid {
		t.Errorf("wallet JWT failed verification: %v", err)
		return
	}
	wantURI := "POST " + r.Host + backendPath + "/" + testAccountID + "/sign"
	uris, _ := claims["uris"].([]any)
	if len(uris) != 1 || uris[0] != wantURI {
		t.Errorf("uris claim = %v, want [%q]", uris, wantURI)
	}
	wantHash, err := computeReqHash(body)
	if err != nil {
		t.Errorf("computeReqHash: %v", err)
		return
	}
	if claims["reqHash"] != wantHash {
		t.Errorf("reqHash claim = %v, want %s", claims["reqHash"], wantHash)
	}
	if jti, _ := claims["jti"].(string); len(jti) != 36 || strings.Count(jti, "-") != 4 {
		t.Errorf("jti claim = %v, want a v4 UUID string", claims["jti"])
	}
}

func TestNewFetchesAddress(t *testing.T) {
	api := newMockAPI(t, testPubkey, nil)
	s, err := New(context.Background(), api.config())
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Pubkey().String(); got != testPubkey {
		t.Errorf("pubkey = %s, want %s", got, testPubkey)
	}
}

func TestNewRejectsEmptyFields(t *testing.T) {
	cases := map[string]Config{
		"empty secret key":    {SecretKey: "", AccountID: testAccountID, WalletSecret: testWalletSecretB64()},
		"empty account id":    {SecretKey: testSecretKey, AccountID: "", WalletSecret: testWalletSecretB64()},
		"empty wallet secret": {SecretKey: testSecretKey, AccountID: testAccountID, WalletSecret: ""},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), cfg)
			if err == nil {
				t.Fatal("expected error for config with an empty field")
			}
			if code, _ := core.CodeOf(err); code != core.CodeConfigError {
				t.Errorf("got %s, want CONFIG_ERROR", code)
			}
		})
	}
}

func TestNewUnauthorized(t *testing.T) {
	api := newMockAPI(t, testPubkey, nil)
	api.accountStatus.Store(http.StatusUnauthorized)
	_, err := New(context.Background(), api.config())
	if err == nil {
		t.Fatal("expected error for 401 account fetch")
	}
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("got %s, want REMOTE_API_ERROR", code)
	}
}

func TestNewRejectsNonSolanaAddress(t *testing.T) {
	api := newMockAPI(t, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", nil)
	_, err := New(context.Background(), api.config())
	if err == nil {
		t.Fatal("expected error for non-Solana address")
	}
	if code, _ := core.CodeOf(err); code != core.CodeInvalidPublicKey {
		t.Errorf("got %s, want INVALID_PUBLIC_KEY", code)
	}
}

func TestNewTrimsTrailingSlashes(t *testing.T) {
	api := newMockAPI(t, testPubkey, nil)
	cfg := api.config()
	cfg.APIBaseURL = api.srv.URL + "///"
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.baseURL != api.srv.URL {
		t.Errorf("baseURL = %q, want %q", s.baseURL, api.srv.URL)
	}
}

func TestNewRejectsNonHTTPSBaseURL(t *testing.T) {
	// The config-level HTTPS check fires before any request is issued,
	// regardless of whether a custom client is supplied (alignment with
	// crossmint/para/utila).
	for name, client := range map[string]*http.Client{
		"default client": nil,
		"custom client":  http.DefaultClient,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), Config{
				SecretKey:    testSecretKey,
				AccountID:    testAccountID,
				WalletSecret: testWalletSecretB64(),
				APIBaseURL:   "http://api.openfort.io",
				HTTPClient:   client,
			})
			if err == nil {
				t.Fatal("expected error for non-HTTPS base URL")
			}
			if code, _ := core.CodeOf(err); code != core.CodeConfigError {
				t.Errorf("got %s, want CONFIG_ERROR", code)
			}
		})
	}
}

func TestNewRejectsInvalidBaseURL(t *testing.T) {
	_, err := New(context.Background(), Config{
		SecretKey:    testSecretKey,
		AccountID:    testAccountID,
		WalletSecret: testWalletSecretB64(),
		APIBaseURL:   "not a url",
		HTTPClient:   http.DefaultClient,
	})
	if err == nil {
		t.Fatal("expected error for invalid base URL")
	}
	if code, _ := core.CodeOf(err); code != core.CodeConfigError {
		t.Errorf("got %s, want CONFIG_ERROR", code)
	}
}

func TestIsAvailable(t *testing.T) {
	t.Run("returns true when address matches", func(t *testing.T) {
		api := newMockAPI(t, testPubkey, nil)
		s, err := New(context.Background(), api.config())
		if err != nil {
			t.Fatal(err)
		}
		if !s.IsAvailable(context.Background()) {
			t.Error("expected IsAvailable to be true when the address matches")
		}
	})

	t.Run("returns false when address changed", func(t *testing.T) {
		api := newMockAPI(t, testPubkey, nil)
		s, err := New(context.Background(), api.config())
		if err != nil {
			t.Fatal(err)
		}
		api.accountAddress.Store(testutils.TestPublicKey().String())
		if s.IsAvailable(context.Background()) {
			t.Error("expected IsAvailable to be false when the remote address changed")
		}
	})

	t.Run("returns false on remote error", func(t *testing.T) {
		api := newMockAPI(t, testPubkey, nil)
		s, err := New(context.Background(), api.config())
		if err != nil {
			t.Fatal(err)
		}
		api.accountStatus.Store(http.StatusUnauthorized)
		if s.IsAvailable(context.Background()) {
			t.Error("expected IsAvailable to be false on a remote error")
		}
	})
}

func TestSignMessageSuccess(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)
	sigHex := "0x" + hex.EncodeToString(signature)

	signHandler := func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read sign request body: %v", err)
		}
		verifyWalletJWT(t, r, body)
		var req struct {
			Data string `json:"data"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("failed to decode sign request body: %v", err)
		}
		if want := "0x" + hex.EncodeToString(message); req.Data != want {
			t.Errorf("sign request data = %q, want %q", req.Data, want)
		}
		signResponder(t, sigHex)(w, r)
	}

	api := newMockAPI(t, pub.String(), signHandler)
	s, err := New(context.Background(), api.config())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}
	if hex.EncodeToString(sig[:]) != hex.EncodeToString(signature) {
		t.Error("returned signature does not match the expected signature")
	}
	if !core.VerifyEd25519(pub, message, sig) {
		t.Error("returned signature should verify against the signer's pubkey")
	}
}

func TestSignMessageSignatureVerificationFailure(t *testing.T) {
	// Signature made with a key that does NOT correspond to the account
	// address the signer resolved at init.
	message := []byte("test message")
	signature := ed25519.Sign(testutils.TestPrivateKey(), message)
	sigHex := "0x" + hex.EncodeToString(signature)

	api := newMockAPI(t, testPubkey, signResponder(t, sigHex))
	s, err := New(context.Background(), api.config())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), message)
	if err == nil {
		t.Fatal("expected error for signature that fails verification")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

func TestSignMessageInvalidSignatureLength(t *testing.T) {
	api := newMockAPI(t, testPubkey, signResponder(t, "0x1234"))
	s, err := New(context.Background(), api.config())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for short signature")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

func TestSignMessageInvalidHexSignature(t *testing.T) {
	api := newMockAPI(t, testPubkey, signResponder(t, "0xZZZZ"))
	s, err := New(context.Background(), api.config())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for non-hex signature")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSerializationError {
		t.Errorf("got %s, want SERIALIZATION_ERROR", code)
	}
}

func TestSignUnauthorized(t *testing.T) {
	api := newMockAPI(t, testPubkey, signStatusHandler(http.StatusUnauthorized))
	s, err := New(context.Background(), api.config())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for 401 sign response")
	}
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("got %s, want REMOTE_API_ERROR", code)
	}
}

// A non-2xx body lands sanitized in the (opt-in) detail; Error() stays generic.
func TestSignErrorBodySanitizedIntoDetail(t *testing.T) {
	api := newMockAPI(t, testPubkey, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("policy\x01denied"))
	})
	s, err := New(context.Background(), api.config())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)
	testutils.AssertDetailContains(t, err, "openfort API error 403")
	testutils.AssertDetailContains(t, err, "policy denied")
	if strings.Contains(err.Error(), "policy") {
		t.Errorf("Error() must not surface the remote body, got %q", err.Error())
	}
}

func TestSignMessageInvalidWalletSecret(t *testing.T) {
	// The wallet secret is only parsed at signing time, so New succeeds and
	// SignMessage fails.
	api := newMockAPI(t, testPubkey, nil)
	cfg := api.config()
	cfg.WalletSecret = "not-a-pem-key"
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for invalid wallet secret")
	}
	if code, _ := core.CodeOf(err); code != core.CodeInvalidPrivateKey {
		t.Errorf("got %s, want INVALID_PRIVATE_KEY", code)
	}
}

func TestSignTransactionSuccess(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()
	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(priv, msg)
	sigHex := "0x" + hex.EncodeToString(signature)

	api := newMockAPI(t, pub.String(), signResponder(t, sigHex))
	s, err := New(context.Background(), api.config())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SignTransaction failed: %v", err)
	}
	if res.EncodedTransaction == "" {
		t.Error("encoded transaction should not be empty")
	}
	if !res.IsComplete() {
		t.Error("single-signer transaction should be Complete")
	}
	if hex.EncodeToString(res.Signature[:]) != hex.EncodeToString(signature) {
		t.Error("returned signature does not match the expected signature")
	}
	decoded, err := solana.TransactionFromBase64(res.EncodedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Signatures[0] != res.Signature {
		t.Error("encoded transaction signature mismatch at position 0")
	}
}

// roundTripFunc adapts a function to http.RoundTripper for transport-level tests.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestDoPreservesTransportSignerError guards the passthrough of SignerError
// codes raised inside the transport (e.g. the HTTPS-only guard's
// CodeConfigError): they must not be re-wrapped as CodeHTTPError.
func TestDoPreservesTransportSignerError(t *testing.T) {
	blocked := core.NewSignerError(core.CodeConfigError, "non-HTTPS request blocked")
	s := &Signer{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, blocked
	})}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.invalid/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.do(req)
	if code, _ := core.CodeOf(err); code != core.CodeConfigError {
		t.Errorf("got code %s, want CONFIG_ERROR", code)
	}
}
