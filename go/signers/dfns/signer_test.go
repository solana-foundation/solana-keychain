package dfns

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	testKeyID     = "test-key-id"
	testPubkeyHex = "5da30b28c87836b0ee76ae7b07e3a2e3be1a4c12e48fce3aee18de0a13040b9a"
	// testPubkey is the base58 encoding of the hex bytes above.
	testPubkey = "7JX7XMJ9TpfkKmz5u85DowRFyQabHsUgWajTmhToUfgM"

	testUserActionToken = "test-user-action-token"
)

// walletJSON renders the Dfns wallet response with the given hex public key.
func walletJSON(pubkeyHex string) string {
	return `{"id":"test-wallet-id","status":"Active","network":"Solana","signingKey":` +
		`{"id":"` + testKeyID + `","scheme":"EdDSA","curve":"ed25519","publicKey":"` + pubkeyHex + `"}}`
}

// walletJSONWith renders the wallet response with the given status, scheme,
// and curve, the fields the availability tests mutate.
func walletJSONWith(status, scheme, curve string) string {
	return `{"id":"test-wallet-id","status":"` + status + `","network":"Solana","signingKey":` +
		`{"id":"` + testKeyID + `","scheme":"` + scheme + `","curve":"` + curve + `","publicKey":"` + testPubkeyHex + `"}}`
}

// walletHandler serves the wallet endpoint with a fixed public key.
func walletHandler(pubkeyHex string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, walletJSON(pubkeyHex))
	}
}

// mountUserActionFlow registers the /auth/action/init and /auth/action
// handlers, verifying the client data bytes and their credential signature
// exactly as Dfns would (challenge signed with testEd25519PEM).
func mountUserActionFlow(t *testing.T, mux *http.ServeMux) {
	t.Helper()
	credentialPub := testEd25519CredentialPublicKey(t)

	mux.HandleFunc("POST /auth/action/init", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"challenge":"test-challenge","challengeIdentifier":"test-challenge-id",`+
			`"allowCredentials":{"key":[{"id":"test-cred-id"}]}}`)
	})
	mux.HandleFunc("POST /auth/action", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ChallengeIdentifier string `json:"challengeIdentifier"`
			FirstFactor         struct {
				Kind                string `json:"kind"`
				CredentialAssertion struct {
					CredID     string `json:"credId"`
					ClientData string `json:"clientData"`
					Signature  string `json:"signature"`
				} `json:"credentialAssertion"`
			} `json:"firstFactor"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad user action sign request: %v", err)
		}
		if req.ChallengeIdentifier != "test-challenge-id" || req.FirstFactor.Kind != "Key" ||
			req.FirstFactor.CredentialAssertion.CredID != "test-cred-id" {
			t.Errorf("unexpected user action sign request: %+v", req)
		}
		clientDataBytes, err := base64.RawURLEncoding.DecodeString(req.FirstFactor.CredentialAssertion.ClientData)
		if err != nil {
			t.Errorf("clientData is not base64url (no padding): %v", err)
		}
		// The exact client data bytes the signer must produce and sign.
		if want := `{"challenge":"test-challenge","type":"key.get"}`; string(clientDataBytes) != want {
			t.Errorf("clientData = %q, want %q", clientDataBytes, want)
		}
		sig, err := base64.RawURLEncoding.DecodeString(req.FirstFactor.CredentialAssertion.Signature)
		if err != nil {
			t.Errorf("signature is not base64url (no padding): %v", err)
		}
		if !ed25519.Verify(credentialPub, clientDataBytes, sig) {
			t.Error("challenge signature should verify against the credential public key")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"userAction":"`+testUserActionToken+`"}`)
	})
}

// signedResponseJSON renders a Signed Keys API response with sig split into
// its r and s hex components, as Dfns returns them.
func signedResponseJSON(sig []byte) string {
	return `{"id":"sig-123","status":"Signed","signature":{"r":"` +
		hex.EncodeToString(sig[:32]) + `","s":"` + hex.EncodeToString(sig[32:]) + `"}}`
}

// testConfig returns the standard test config pointed at srv.
func testConfig(srv *httptest.Server) Config {
	return Config{
		AuthToken:     "test-auth-token",
		CredID:        "test-cred-id",
		PrivateKeyPEM: testEd25519PEM,
		WalletID:      "test-wallet-id",
		APIBaseURL:    srv.URL,
		HTTPClient:    srv.Client(),
	}
}

// newTestSigner builds a ready-to-use signer against srv.
func newTestSigner(t *testing.T, srv *httptest.Server) *Signer {
	t.Helper()
	s, err := New(context.Background(), testConfig(srv))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestNewDefaultBaseURL checks that an empty APIBaseURL resolves to the
// production Dfns endpoint.
func TestNewDefaultBaseURL(t *testing.T) {
	var gotURL string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(walletJSON(testPubkeyHex))),
		}, nil
	})}
	s, err := New(context.Background(), Config{
		AuthToken:     "token",
		CredID:        "cred",
		PrivateKeyPEM: testEd25519PEM,
		WalletID:      "wallet",
		HTTPClient:    client,
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := DefaultAPIBaseURL + "/wallets/wallet"; gotURL != want {
		t.Errorf("request URL = %s, want %s", gotURL, want)
	}
	if s.Pubkey().String() != testPubkey {
		t.Errorf("pubkey = %s, want %s", s.Pubkey(), testPubkey)
	}
}

// TestNewMissingConfig checks that each required field is validated with a
// CONFIG_ERROR.
func TestNewMissingConfig(t *testing.T) {
	base := Config{
		AuthToken:     "token",
		CredID:        "cred",
		PrivateKeyPEM: testEd25519PEM,
		WalletID:      "wallet",
	}
	cases := map[string]func(Config) Config{
		"auth token":  func(c Config) Config { c.AuthToken = ""; return c },
		"cred id":     func(c Config) Config { c.CredID = ""; return c },
		"private key": func(c Config) Config { c.PrivateKeyPEM = ""; return c },
		"wallet id":   func(c Config) Config { c.WalletID = ""; return c },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), mutate(base))
			if err == nil {
				t.Fatal("expected error for missing " + name)
			}
			if code, _ := core.CodeOf(err); code != core.CodeConfigError {
				t.Errorf("got %s, want CONFIG_ERROR", code)
			}
		})
	}
}

// TestNewSuccess checks that New resolves the pubkey and key ID from a single
// wallet fetch.
func TestNewSuccess(t *testing.T) {
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /wallets/test-wallet-id", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		walletHandler(testPubkeyHex)(w, r)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	s := newTestSigner(t, srv)
	if s.Pubkey().String() != testPubkey {
		t.Errorf("pubkey = %s, want %s", s.Pubkey(), testPubkey)
	}
	if s.keyID != testKeyID {
		t.Errorf("keyID = %s, want %s", s.keyID, testKeyID)
	}
	if hits.Load() != 1 {
		t.Errorf("wallet endpoint hit %d times, want 1", hits.Load())
	}
}

// TestNewAPIError checks that a non-2xx wallet response fails New with a
// REMOTE_API_ERROR.
func TestNewAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /wallets/test-wallet-id", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := New(context.Background(), testConfig(srv))
	if err == nil {
		t.Fatal("expected error for 401 wallet response")
	}
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("got %s, want REMOTE_API_ERROR", code)
	}
}

// TestNewInvalidScheme checks that a non-EdDSA signing key fails New with a
// CONFIG_ERROR.
func TestNewInvalidScheme(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /wallets/test-wallet-id", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"test-wallet-id","status":"Active","network":"Ethereum",`+
			`"signingKey":{"id":"key-id","scheme":"ECDSA","curve":"secp256k1","publicKey":"abcd"}}`)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := New(context.Background(), testConfig(srv))
	if err == nil {
		t.Fatal("expected error for non-EdDSA signing key")
	}
	if code, _ := core.CodeOf(err); code != core.CodeConfigError {
		t.Errorf("got %s, want CONFIG_ERROR", code)
	}
}

// TestNewHTTPSEnforcement checks that a plain-HTTP base URL is refused with a
// CONFIG_ERROR at construction, for both the default and a custom client (a
// custom client must not be able to bypass HTTPS enforcement).
func TestNewHTTPSEnforcement(t *testing.T) {
	for name, client := range map[string]*http.Client{
		"default client": nil,
		"custom client":  http.DefaultClient,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{
				AuthToken:     "test-token",
				CredID:        "test-cred",
				PrivateKeyPEM: testEd25519PEM,
				WalletID:      "test-wallet-id",
				APIBaseURL:    "http://127.0.0.1:1",
				HTTPClient:    client,
			}
			_, err := New(context.Background(), cfg)
			if err == nil {
				t.Fatal("expected error for http:// base URL")
			}
			if code, _ := core.CodeOf(err); code != core.CodeConfigError {
				t.Errorf("got %s, want CONFIG_ERROR", code)
			}
		})
	}
}

// TestRemoteErrorSanitized checks that hostile remote error bodies are
// sanitized before landing in the error detail.
func TestRemoteErrorSanitized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /wallets/test-wallet-id", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "evil\x00body\nwith\tcontrol\x1bchars")
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := New(context.Background(), testConfig(srv))
	if err == nil {
		t.Fatal("expected error for 500 wallet response")
	}
	var se *core.SignerError
	if !errors.As(err, &se) {
		t.Fatalf("expected *core.SignerError, got %T", err)
	}
	detail := se.Detail()
	if !strings.Contains(detail, "500") {
		t.Errorf("detail should mention the status code, got %q", detail)
	}
	if !strings.Contains(detail, "evil body with control chars") {
		t.Errorf("detail should contain the sanitized body, got %q", detail)
	}
	if strings.ContainsAny(detail, "\x00\n\t\x1b") {
		t.Errorf("detail should not contain raw control characters, got %q", detail)
	}
}

// TestSignMessageSuccess checks the happy-path signing flow: the user-action
// token is attached, the request carries the hex-encoded message, and the
// returned signature is surfaced.
func TestSignMessageSuccess(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()
	message := []byte("test message")
	sig := ed25519.Sign(priv, message)

	var sigHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /wallets/test-wallet-id", walletHandler(hex.EncodeToString(pub[:])))
	mountUserActionFlow(t, mux)
	mux.HandleFunc("POST /keys/"+testKeyID+"/signatures", func(w http.ResponseWriter, r *http.Request) {
		sigHits.Add(1)
		if got := r.Header.Get("x-dfns-useraction"); got != testUserActionToken {
			t.Errorf("x-dfns-useraction = %q, want %q", got, testUserActionToken)
		}
		var req generateSignatureRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad signature request: %v", err)
		}
		if req.Kind != "Message" || req.Message != "0x"+hex.EncodeToString(message) {
			t.Errorf("unexpected signature request: %+v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, signedResponseJSON(sig))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	s := newTestSigner(t, srv)
	got, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	var want solana.Signature
	copy(want[:], sig)
	if got != want {
		t.Errorf("signature = %s, want %s", got, want)
	}
	if sigHits.Load() != 1 {
		t.Errorf("signatures endpoint hit %d times, want 1", sigHits.Load())
	}
}

// TestSignMessageVerificationFailure checks the case where the remote returns
// a signature from a different key than the wallet's public key.
func TestSignMessageVerificationFailure(t *testing.T) {
	signingPriv := testutils.TestPrivateKey()
	differentPriv := ed25519.NewKeyFromSeed(func() []byte {
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = 0x77
		}
		return seed
	}())
	differentPub := differentPriv.Public().(ed25519.PublicKey)
	message := []byte("test message")
	sig := ed25519.Sign(signingPriv, message)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /wallets/test-wallet-id", walletHandler(hex.EncodeToString(differentPub)))
	mountUserActionFlow(t, mux)
	mux.HandleFunc("POST /keys/"+testKeyID+"/signatures", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, signedResponseJSON(sig))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	s := newTestSigner(t, srv)
	_, err := s.SignMessage(context.Background(), message)
	if err == nil {
		t.Fatal("expected signature verification failure")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

// TestSignMessageAPIError checks the case where the signatures endpoint fails
// after a successful user-action flow.
func TestSignMessageAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /wallets/test-wallet-id", walletHandler(testPubkeyHex))
	mountUserActionFlow(t, mux)
	mux.HandleFunc("POST /keys/"+testKeyID+"/signatures", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	s := newTestSigner(t, srv)
	_, err := s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for 500 signature response")
	}
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("got %s, want REMOTE_API_ERROR", code)
	}
}

// TestSignTransactionSuccess checks the happy-path transaction signing flow.
func TestSignTransactionSuccess(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, msgBytes)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /wallets/test-wallet-id", walletHandler(hex.EncodeToString(pub[:])))
	mountUserActionFlow(t, mux)
	mux.HandleFunc("POST /keys/"+testKeyID+"/signatures", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-dfns-useraction"); got != testUserActionToken {
			t.Errorf("x-dfns-useraction = %q, want %q", got, testUserActionToken)
		}
		var req generateSignatureRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad signature request: %v", err)
		}
		if req.Kind != "Transaction" || req.BlockchainKind != "Solana" || !strings.HasPrefix(req.Transaction, "0x") {
			t.Errorf("unexpected signature request: %+v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, signedResponseJSON(sig))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	s := newTestSigner(t, srv)
	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	var want solana.Signature
	copy(want[:], sig)
	if res.Signature != want {
		t.Errorf("signature = %s, want %s", res.Signature, want)
	}
	if !res.IsComplete() {
		t.Error("single-signer transaction should be Complete")
	}
	decoded, err := solana.TransactionFromBase64(res.EncodedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Signatures[0] != want {
		t.Error("encoded transaction signature mismatch at position 0")
	}
}

// TestSignTransactionVerificationFailure checks that a signature from a key
// other than the wallet's is rejected.
func TestSignTransactionVerificationFailure(t *testing.T) {
	signingPriv := testutils.TestPrivateKey()
	differentPriv := ed25519.NewKeyFromSeed(func() []byte {
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = 0x55
		}
		return seed
	}())
	differentPub := differentPriv.Public().(ed25519.PublicKey)

	var walletPub solana.PublicKey
	copy(walletPub[:], differentPub)
	tx, err := testutils.CreateTestTransaction(walletPub)
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(signingPriv, msgBytes)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /wallets/test-wallet-id", walletHandler(hex.EncodeToString(differentPub)))
	mountUserActionFlow(t, mux)
	mux.HandleFunc("POST /keys/"+testKeyID+"/signatures", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, signedResponseJSON(sig))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	s := newTestSigner(t, srv)
	_, err = s.SignTransaction(context.Background(), tx)
	if err == nil {
		t.Fatal("expected signature verification failure")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

// TestIsAvailable covers the healthy wallet plus the archived, wrong-scheme,
// wrong-curve, and API-error cases. New needs a healthy wallet, so the
// unavailable cases serve one on the first call and the degraded response
// afterwards.
func TestIsAvailable(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewTLSServer(walletHandler(testPubkeyHex))
		defer srv.Close()

		s := newTestSigner(t, srv)
		if !s.IsAvailable(context.Background()) {
			t.Error("expected IsAvailable to be true")
		}
	})

	serveJSON := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		}
	}
	for name, degraded := range map[string]http.HandlerFunc{
		"archived wallet": serveJSON(walletJSONWith("Archived", "EdDSA", "ed25519")),
		"wrong scheme":    serveJSON(walletJSONWith("Active", "ECDSA", "ed25519")),
		"wrong curve":     serveJSON(walletJSONWith("Active", "EdDSA", "secp256k1")),
		"api error": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc("GET /wallets/test-wallet-id", func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					// First call backs New; subsequent availability checks see
					// the degraded response.
					walletHandler(testPubkeyHex)(w, r)
					return
				}
				degraded(w, r)
			})
			srv := httptest.NewTLSServer(mux)
			defer srv.Close()

			s := newTestSigner(t, srv)
			if s.IsAvailable(context.Background()) {
				t.Error("expected IsAvailable to be false")
			}
		})
	}
}

// TestStringDoesNotLeakSecrets checks that no fmt rendering of the signer
// exposes the credential private key or the auth token.
func TestStringDoesNotLeakSecrets(t *testing.T) {
	srv := httptest.NewTLSServer(walletHandler(testPubkeyHex))
	defer srv.Close()

	s := newTestSigner(t, srv)
	for _, rendered := range []string{
		fmt.Sprintf("%v", s),
		fmt.Sprintf("%+v", s),
		fmt.Sprintf("%#v", s),
		fmt.Sprintf("%v", *s),
		fmt.Sprintf("%+v", *s),
		fmt.Sprintf("%s", *s), //nolint:staticcheck // deliberately exercising the %s verb path
		fmt.Sprintf("%#v", *s),
		fmt.Sprintf("%s", s), //nolint:staticcheck // deliberately exercising the %s verb path
	} {
		if strings.Contains(rendered, testEd25519PEM) || strings.Contains(rendered, "test-auth-token") {
			t.Errorf("rendered signer leaks secrets: %s", rendered)
		}
		if !strings.Contains(rendered, "dfns.Signer") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
	}
}

// TestCombineSignatureRejectsMisalignedComponents guards the per-component
// length check: r and s must each be exactly 32 bytes, so a misaligned split
// (which could never verify) fails with an accurate error instead of a
// downstream verification failure.
func TestCombineSignatureRejectsMisalignedComponents(t *testing.T) {
	for name, tc := range map[string]struct{ rLen, sLen int }{
		"short r long s":  {30, 34},
		"long r short s":  {34, 30},
		"total too short": {31, 32},
		"total too long":  {33, 32},
	} {
		t.Run(name, func(t *testing.T) {
			r := "0x" + strings.Repeat("ab", tc.rLen)
			s := "0x" + strings.Repeat("cd", tc.sLen)
			_, err := combineSignature(r, s)
			if err == nil {
				t.Fatal("expected error for misaligned components")
			}
			if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
				t.Errorf("got code %s, want SIGNING_FAILED", code)
			}
		})
	}
}
