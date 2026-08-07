package fireblocks

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
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
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/golang-jwt/jwt/v5"

	"github.com/solana-foundation/solana-keychain/go/core"
	"github.com/solana-foundation/solana-keychain/go/testutils"
)

const (
	testAPIKey    = "test-api-key"
	testVaultID   = "test-vault-id"
	addressesPath = "/v1/vault/accounts/test-vault-id/SOL/addresses_paginated"
)

// keyFromSeed derives a deterministic throwaway Ed25519 keypair from a single
// seed byte.
func keyFromSeed(seedByte byte) (ed25519.PrivateKey, solana.PublicKey) {
	var seed [ed25519.SeedSize]byte
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed[:])
	var pub solana.PublicKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return priv, pub
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newTestSigner starts an httptest server serving addressesPath (returning
// address) plus any handlers registered by configure, and constructs an
// initialized signer against it.
func newTestSigner(t *testing.T, address string, configure func(mux *http.ServeMux)) *Signer {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(addressesPath, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"addresses": []map[string]string{{"address": address}}})
	})
	if configure != nil {
		configure(mux)
	}
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	s, err := New(context.Background(), Config{
		APIKey:          testAPIKey,
		PrivateKeyPEM:   testRSAKey,
		VaultAccountID:  testVaultID,
		APIBaseURL:      srv.URL,
		PollInterval:    time.Millisecond,
		MaxPollAttempts: 3,
		HTTPClient:      srv.Client(),
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return s
}

// Defaults resolve and the pubkey is fetched during construction.
func TestNewDefaultsAndFetchesPubkey(t *testing.T) {
	want := testutils.TestPublicKey()
	s := newTestSigner(t, want.String(), nil)

	if s.assetID != "SOL" {
		t.Errorf("assetID = %s, want SOL", s.assetID)
	}
	if s.pollInterval != time.Millisecond || s.maxPollAttempts != 3 {
		t.Error("configured poll settings should be honored")
	}
	if s.Pubkey() != want {
		t.Errorf("Pubkey() = %s, want %s", s.Pubkey(), want)
	}
}

// The unsupported PROGRAM_CALL mode fails New with a config error and, failing
// closed, no request may reach Fireblocks before the rejection.
func TestNewRejectsProgramCallBeforeAnyNetworkCall(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writeJSON(w, map[string]any{"addresses": []map[string]string{{"address": testutils.TestPublicKey().String()}}})
	}))
	t.Cleanup(srv.Close)

	_, err := New(context.Background(), Config{
		APIKey:         testAPIKey,
		PrivateKeyPEM:  testRSAKey,
		VaultAccountID: testVaultID,
		APIBaseURL:     srv.URL,
		UseProgramCall: true,
		HTTPClient:     srv.Client(),
	})
	if err == nil {
		t.Fatal("expected New to reject UseProgramCall")
	}
	if code, _ := core.CodeOf(err); code != core.CodeConfigError {
		t.Errorf("got %s, want CONFIG_ERROR", code)
	}
	var se *core.SignerError
	if errors.As(err, &se) && !strings.Contains(se.Detail(), "use_program_call") {
		t.Errorf("detail = %q, want mention of use_program_call", se.Detail())
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("New must reject use_program_call before any network call, server saw %d requests", got)
	}
}

// A non-2xx during the pubkey fetch fails New.
func TestNewAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(addressesPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	_, err := New(context.Background(), Config{
		APIKey:         testAPIKey,
		PrivateKeyPEM:  testRSAKey,
		VaultAccountID: testVaultID,
		APIBaseURL:     srv.URL,
		HTTPClient:     srv.Client(),
	})
	if err == nil {
		t.Fatal("expected error when the address fetch fails")
	}
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("got %s, want REMOTE_API_ERROR", code)
	}
}

// An unparseable RSA key fails New with INVALID_PRIVATE_KEY.
func TestNewInvalidRSAKey(t *testing.T) {
	_, err := New(context.Background(), Config{
		APIKey:         testAPIKey,
		PrivateKeyPEM:  "invalid-key",
		VaultAccountID: testVaultID,
	})
	if err == nil {
		t.Fatal("expected error for invalid RSA key")
	}
	if code, _ := core.CodeOf(err); code != core.CodeInvalidPrivateKey {
		t.Errorf("got %s, want INVALID_PRIVATE_KEY", code)
	}
}

// The default client (nil HTTPClient) must reject non-HTTPS base URLs.
func TestNewHTTPSEnforcement(t *testing.T) {
	_, err := New(context.Background(), Config{
		APIKey:         testAPIKey,
		PrivateKeyPEM:  testRSAKey,
		VaultAccountID: testVaultID,
		APIBaseURL:     "http://127.0.0.1:1",
	})
	if err == nil {
		t.Fatal("expected error for non-HTTPS base URL with the default client")
	}
	if code, _ := core.CodeOf(err); code != core.CodeConfigError {
		t.Errorf("got %s, want CONFIG_ERROR", code)
	}
}

// Every fmt rendering of the signer must omit the API key and RSA key material
// (both the PEM text and the private exponent a struct dump would print).
func TestStringDoesNotLeakSecrets(t *testing.T) {
	s := newTestSigner(t, testutils.TestPublicKey().String(), nil)
	pemBody := strings.Split(testRSAKey, "\n")[1]
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
		if strings.Contains(rendered, testAPIKey) {
			t.Errorf("rendered signer leaks the API key: %s", rendered)
		}
		if strings.Contains(rendered, pemBody) || strings.Contains(rendered, s.signingKey.D.String()) {
			t.Errorf("rendered signer leaks RSA key material: %s", rendered)
		}
		if !strings.Contains(rendered, "fireblocks.Signer") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
	}
}

// Happy-path message signing, with assertions on the RAW request wire shape
// and the JWT carried in the Authorization header (claims tested directly in
// jwt_test.go; here the token must also verify against the RSA key).
func TestSignMessageSuccess(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()
	message := []byte("test message")
	signature := solana.SignatureFromBytes(ed25519.Sign(priv, message))

	rsaKey, err := parseSigningKey(testRSAKey)
	if err != nil {
		t.Fatal(err)
	}

	s := newTestSigner(t, pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			if got := r.Header.Get("X-API-Key"); got != testAPIKey {
				t.Errorf("X-API-Key = %q, want %q", got, testAPIKey)
			}
			body, _ := io.ReadAll(r.Body)

			// The Authorization JWT must be RS256-signed by the API secret and
			// carry the request uri and the sha256 hex of the exact body sent.
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			claims := jwt.MapClaims{}
			if _, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) {
				return &rsaKey.PublicKey, nil
			}, jwt.WithValidMethods([]string{"RS256"})); err != nil {
				t.Errorf("authorization JWT should verify: %v", err)
			}
			if claims["uri"] != "/v1/transactions" || claims["sub"] != testAPIKey {
				t.Errorf("unexpected JWT claims: uri=%v sub=%v", claims["uri"], claims["sub"])
			}
			bodyHash := sha256.Sum256(body)
			if claims["bodyHash"] != hex.EncodeToString(bodyHash[:]) {
				t.Error("JWT bodyHash should be the sha256 hex of the request body")
			}

			var req map[string]any
			if err := json.Unmarshal(body, &req); err != nil {
				t.Errorf("request body should be JSON: %v", err)
			}
			if req["operation"] != "RAW" || req["assetId"] != "SOL" {
				t.Errorf("unexpected request: operation=%v assetId=%v", req["operation"], req["assetId"])
			}
			if !strings.Contains(string(body), `"content":"`+hex.EncodeToString(message)+`"`) {
				t.Error("RAW request should carry the hex-encoded message content")
			}

			writeJSON(w, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{
				"id":     "tx-123",
				"status": "COMPLETED",
				"signedMessages": []map[string]any{
					{"signature": map[string]string{"fullSig": hex.EncodeToString(signature[:])}},
				},
			})
		})
	})

	got, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if got != signature {
		t.Errorf("signature = %s, want %s", got, signature)
	}
}

// A signature that does not verify against the signer's pubkey is rejected.
func TestSignMessageVerificationFailure(t *testing.T) {
	signingPriv, _ := keyFromSeed(0x24)
	_, differentPub := keyFromSeed(0x25)
	message := []byte("test message")
	signature := ed25519.Sign(signingPriv, message)

	s := newTestSigner(t, differentPub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{
				"id":     "tx-123",
				"status": "COMPLETED",
				"signedMessages": []map[string]any{
					{"signature": map[string]string{"fullSig": hex.EncodeToString(signature)}},
				},
			})
		})
	})

	_, err := s.SignMessage(context.Background(), message)
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

// A non-2xx from the transactions endpoint surfaces a REMOTE_API_ERROR.
func TestSignMessageAPIError(t *testing.T) {
	s := newTestSigner(t, testutils.TestPublicKey().String(), func(mux *http.ServeMux) {
		mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
	})

	_, err := s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for API failure")
	}
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("got %s, want REMOTE_API_ERROR", code)
	}
}

// A terminal FAILED status aborts polling with a signing failure.
func TestSignMessageTransactionFailed(t *testing.T) {
	s := newTestSigner(t, testutils.TestPublicKey().String(), func(mux *http.ServeMux) {
		mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"id": "tx-123", "status": "FAILED", "signedMessages": []any{}})
		})
	})

	_, err := s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for FAILED transaction")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

// Exercises the polling-timeout branch: a transaction that never reaches a
// terminal state exhausts maxPollAttempts.
func TestSignMessagePollingTimeout(t *testing.T) {
	s := newTestSigner(t, testutils.TestPublicKey().String(), func(mux *http.ServeMux) {
		mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
	})

	_, err := s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected polling timeout error")
	}
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("got %s, want REMOTE_API_ERROR", code)
	}
	var se *core.SignerError
	if errors.As(err, &se) && !strings.Contains(se.Detail(), "polling timeout") {
		t.Errorf("detail = %q, want polling timeout message", se.Detail())
	}
}

// A hostile remote error body must never reach the error detail: only the
// status code is surfaced for non-2xx responses.
func TestRemoteErrorBodyNotLeaked(t *testing.T) {
	hostile := "evil\x01<script>alert(1)</script>"
	s := newTestSigner(t, testutils.TestPublicKey().String(), func(mux *http.ServeMux) {
		mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(hostile))
		})
	})

	_, err := s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for API failure")
	}
	var se *core.SignerError
	if !errors.As(err, &se) {
		t.Fatalf("expected *core.SignerError, got %T", err)
	}
	if se.Detail() != "API error 500" {
		t.Errorf("detail = %q, want %q", se.Detail(), "API error 500")
	}
	if strings.Contains(se.Detail(), "script") || strings.Contains(se.Detail(), "evil") {
		t.Error("hostile remote body must not appear in the error detail")
	}
}

// IsAvailable is true on a 2xx vault-account response and false otherwise.
func TestIsAvailable(t *testing.T) {
	cases := map[string]struct {
		status int
		want   bool
	}{
		"success": {status: http.StatusOK, want: true},
		"failure": {status: http.StatusUnauthorized, want: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := newTestSigner(t, testutils.TestPublicKey().String(), func(mux *http.ServeMux) {
				mux.HandleFunc("/v1/vault/accounts/"+testVaultID, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tc.status)
					if tc.status == http.StatusOK {
						writeJSON(w, map[string]string{"id": testVaultID, "name": "Test Vault"})
					}
				})
			})
			if got := s.IsAvailable(context.Background()); got != tc.want {
				t.Errorf("IsAvailable = %v, want %v", got, tc.want)
			}
		})
	}
}

// IsAvailable must swallow transport errors (unreachable server) and return false.
func TestIsAvailableUnreachable(t *testing.T) {
	s := newTestSigner(t, testutils.TestPublicKey().String(), nil)
	s2 := *s
	s2.apiBaseURL = "http://127.0.0.1:1"
	if s2.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be false when the API is unreachable")
	}
}

// RAW-mode transaction signing succeeds end-to-end and reports Complete for a
// single-signer transaction; the message bytes are what gets remotely signed.
func TestSignTransactionRawComplete(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()

	reference, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := reference.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	signature := solana.SignatureFromBytes(ed25519.Sign(priv, msgBytes))

	s := newTestSigner(t, pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{
				"id":     "tx-123",
				"status": "COMPLETED",
				"signedMessages": []map[string]any{
					{"signature": map[string]string{"fullSig": hex.EncodeToString(signature[:])}},
				},
			})
		})
	})

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsComplete() {
		t.Error("single-signer transaction should be Complete")
	}
	if res.Signature != signature {
		t.Errorf("signature = %s, want %s", res.Signature, signature)
	}
	decoded, err := solana.TransactionFromBase64(res.EncodedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Signatures[0] != signature {
		t.Error("encoded transaction should carry the signature at position 0")
	}
}

// A COMPLETED RAW response without signed messages fails signing.
func TestSignMessageNoSignedMessages(t *testing.T) {
	s := newTestSigner(t, testutils.TestPublicKey().String(), func(mux *http.ServeMux) {
		mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"id": "tx-123", "status": "COMPLETED"})
		})
	})

	_, err := s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error when no signed messages are returned")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}
