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

	"github.com/golang-jwt/jwt/v5"
	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

const (
	testAPIKey    = "test-api-key"
	testVaultID   = "test-vault-id"
	addressesPath = "/v1/vault/accounts/test-vault-id/SOL/addresses_paginated"
)

// newTestSigner starts an httptest server serving addressesPath (returning
// address) plus any handlers registered by configure, and constructs an
// initialized signer against it.
func newTestSigner(t *testing.T, address string, configure func(mux *http.ServeMux)) *Signer {
	t.Helper()
	return newTestSignerWithProgramCall(t, address, false, configure)
}

// newTestSignerWithProgramCall is newTestSigner with the signing mode selectable.
func newTestSignerWithProgramCall(t *testing.T, address string, useProgramCall bool, configure func(mux *http.ServeMux)) *Signer {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(addressesPath, func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{"addresses": []map[string]string{{"address": address}}})
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
		UseProgramCall:  useProgramCall,
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

// newSignerWithAddresses serves the given addresses_paginated entries.
func newSignerWithAddresses(t *testing.T, entries []map[string]string) (*Signer, error) {
	t.Helper()
	return newSignerWithAssetAddresses(t, "", addressesPath, entries)
}

// newSignerWithAssetAddresses serves entries at path for the given configured
// asset id ("" means the default).
func newSignerWithAssetAddresses(t *testing.T, assetID, path string, entries []map[string]string) (*Signer, error) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{"addresses": entries})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	return New(context.Background(), Config{
		APIKey:          testAPIKey,
		PrivateKeyPEM:   testRSAKey,
		VaultAccountID:  testVaultID,
		AssetID:         assetID,
		APIBaseURL:      srv.URL,
		PollInterval:    time.Millisecond,
		MaxPollAttempts: 3,
		HTTPClient:      srv.Client(),
	})
}

func TestNewSelectsAddressForConfiguredAsset(t *testing.T) {
	want := testutils.TestPublicKey().String()
	s, err := newSignerWithAddresses(t, []map[string]string{
		{"address": "6dNUL7bY6oNCM4vXfB6HrCa3Wa2QhTVowsPYqzTGMTfd", "assetId": "SOL_TEST"},
		{"address": want, "assetId": "SOL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Pubkey().String(); got != want {
		t.Errorf("pubkey = %s, want the SOL address %s", got, want)
	}
}

func TestNewSelectsAddressForCustomAssetID(t *testing.T) {
	want := testutils.TestPublicKey().String()
	s, err := newSignerWithAssetAddresses(t, "SOL_TEST",
		"/v1/vault/accounts/"+testVaultID+"/SOL_TEST/addresses_paginated",
		[]map[string]string{
			{"address": "6dNUL7bY6oNCM4vXfB6HrCa3Wa2QhTVowsPYqzTGMTfd", "assetId": "SOL"},
			{"address": want, "assetId": "SOL_TEST"},
		})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Pubkey().String(); got != want {
		t.Errorf("pubkey = %s, want the SOL_TEST address %s", got, want)
	}
}

func TestNewRejectsAmbiguousAddresses(t *testing.T) {
	_, err := newSignerWithAddresses(t, []map[string]string{
		{"address": testutils.TestPublicKey().String(), "assetId": "SOL"},
		{"address": "6dNUL7bY6oNCM4vXfB6HrCa3Wa2QhTVowsPYqzTGMTfd", "assetId": "SOL"},
	})
	if err == nil {
		t.Fatal("expected two addresses for the configured asset to be rejected")
	}
	if code, _ := core.CodeOf(err); code != core.CodeInvalidPublicKey {
		t.Errorf("got %s, want INVALID_PUBLIC_KEY", code)
	}
}

func TestNewRejectsNoAddressForConfiguredAsset(t *testing.T) {
	_, err := newSignerWithAddresses(t, []map[string]string{
		{"address": testutils.TestPublicKey().String(), "assetId": "SOL_TEST"},
	})
	if err == nil {
		t.Fatal("expected an asset-id mismatch to be rejected")
	}
	if code, _ := core.CodeOf(err); code != core.CodeInvalidPublicKey {
		t.Errorf("got %s, want INVALID_PUBLIC_KEY", code)
	}
}

// Duplicate entries for the same address are not ambiguous.
func TestNewAcceptsDuplicateAddressEntries(t *testing.T) {
	want := testutils.TestPublicKey().String()
	s, err := newSignerWithAddresses(t, []map[string]string{
		{"address": want, "assetId": "SOL"},
		{"address": want, "assetId": "SOL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Pubkey().String(); got != want {
		t.Errorf("pubkey = %s, want %s", got, want)
	}
}

// programCallSigner serves a create plus a single poll response for a
// PROGRAM_CALL signer, and records the create request body.
func programCallSigner(t *testing.T, address string, poll map[string]any) (*Signer, *atomic.Pointer[map[string]any]) {
	t.Helper()
	created := &atomic.Pointer[map[string]any]{}
	s := newTestSignerWithProgramCall(t, address, true, func(mux *http.ServeMux) {
		mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Error(err)
			}
			created.Store(&decoded)
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-789", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-789", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, poll)
		})
	})
	return s, created
}

// A sign-only PROGRAM_CALL submits the serialized transaction and yields the
// signature from signedMessages.
func TestSignTransactionProgramCallSignOnly(t *testing.T) {
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
	encoded, err := core.Serialize(tx)
	if err != nil {
		t.Fatal(err)
	}
	signature := solana.SignatureFromBytes(ed25519.Sign(priv, msgBytes))

	s, created := programCallSigner(t, pub.String(), map[string]any{
		"id":     "tx-789",
		"status": "SIGNED",
		"signedMessages": []map[string]any{
			{"signature": map[string]string{"fullSig": hex.EncodeToString(signature[:])}},
		},
	})

	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Signature != signature {
		t.Errorf("signature = %s, want %s", res.Signature, signature)
	}

	request := created.Load()
	if request == nil {
		t.Fatal("no create request recorded")
	}
	if got := (*request)["operation"]; got != operationProgramCall {
		t.Errorf("operation = %v, want %s", got, operationProgramCall)
	}
	extra, ok := (*request)["extraParameters"].(map[string]any)
	if !ok {
		t.Fatalf("extraParameters = %v, want an object", (*request)["extraParameters"])
	}
	if got := extra["programCallData"]; got != encoded {
		t.Errorf("programCallData = %v, want the serialized transaction", got)
	}
	if extra["signOnly"] != true || extra["useDurableNonce"] != false {
		t.Errorf("signOnly = %v, useDurableNonce = %v; want true, false", extra["signOnly"], extra["useDurableNonce"])
	}
}

func TestSignTransactionProgramCallCarriesAMessageDerivedExternalTxID(t *testing.T) {
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
	signature := solana.SignatureFromBytes(ed25519.Sign(priv, msgBytes))

	s, created := programCallSigner(t, pub.String(), map[string]any{
		"id":     "tx-789",
		"status": "SIGNED",
		"signedMessages": []map[string]any{
			{"signature": map[string]string{"fullSig": hex.EncodeToString(signature[:])}},
		},
	})

	if _, err := s.SignTransaction(context.Background(), tx); err != nil {
		t.Fatal(err)
	}

	want := core.IdempotencyKeyFromMessage(
		append([]byte("fireblocks:solana:program_call:SOL:"+testVaultID+":"), msgBytes...))
	request := created.Load()
	if request == nil {
		t.Fatal("no create request recorded")
	}
	if got := (*request)["externalTxId"]; got != want {
		t.Errorf("externalTxId = %v, want %s", got, want)
	}
}

func TestSignMessageRawCarriesNoExternalTxID(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()
	message := []byte("hello")
	signature := solana.SignatureFromBytes(ed25519.Sign(priv, message))

	created := &atomic.Pointer[map[string]any]{}
	s := newTestSigner(t, pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Error(err)
			}
			created.Store(&decoded)
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-raw", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-raw", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
				"id":     "tx-raw",
				"status": "COMPLETED",
				"signedMessages": []map[string]any{
					{"signature": map[string]string{"fullSig": hex.EncodeToString(signature[:])}},
				},
			})
		})
	})

	if _, err := s.SignMessage(context.Background(), message); err != nil {
		t.Fatal(err)
	}

	request := created.Load()
	if request == nil {
		t.Fatal("no create request recorded")
	}
	if _, present := (*request)["externalTxId"]; present {
		t.Error("a RAW create must carry no externalTxId")
	}
}

// The signature may arrive as the txHash of the signed transaction.
func TestSignTransactionProgramCallTxHashCarrier(t *testing.T) {
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
	signature := solana.SignatureFromBytes(ed25519.Sign(priv, msgBytes))

	s, _ := programCallSigner(t, pub.String(), map[string]any{
		"id":     "tx-789",
		"status": "SIGNED",
		"txHash": signature.String(),
	})

	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Signature != signature {
		t.Errorf("signature = %s, want %s", res.Signature, signature)
	}
}

// A txHash that is some other signer's signature fails verification and must not
// reach the transaction.
func TestSignTransactionProgramCallRejectsForeignTxHash(t *testing.T) {
	pub := testutils.TestPublicKey()
	foreignPriv, _ := testutils.KeyFromSeed(9)

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	foreign := solana.SignatureFromBytes(ed25519.Sign(foreignPriv, msgBytes))

	s, _ := programCallSigner(t, pub.String(), map[string]any{
		"id":     "tx-789",
		"status": "SIGNED",
		"txHash": foreign.String(),
	})

	_, err = s.SignTransaction(context.Background(), tx)
	if err == nil {
		t.Fatal("expected an unverifiable signature to fail signing")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
	for _, sig := range tx.Signatures {
		if sig != (solana.Signature{}) {
			t.Error("an unverified signature must not reach the transaction")
		}
	}
}

// A workspace that ignores signOnly and broadcasts is reported as unconfirmed,
// not as a plain failure.
func TestSignTransactionProgramCallBroadcastIsUnconfirmed(t *testing.T) {
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
	signature := solana.SignatureFromBytes(ed25519.Sign(priv, msgBytes))

	s, _ := programCallSigner(t, pub.String(), map[string]any{
		"id":     "tx-789",
		"status": "BROADCASTING",
		"txHash": signature.String(),
	})

	_, err = s.SignTransaction(context.Background(), tx)
	if code, _ := core.CodeOf(err); code != core.CodeBroadcastUnconfirmed {
		t.Fatalf("got %s, want BROADCAST_UNCONFIRMED", code)
	}
	var se *core.SignerError
	if errors.As(err, &se) && se.ProviderTxID != "tx-789" {
		t.Errorf("ProviderTxID = %q, want tx-789", se.ProviderTxID)
	}
}

func TestSignTransactionProgramCallUnresolvedPollKeepsTransactionID(t *testing.T) {
	pub := testutils.TestPublicKey()

	for _, tc := range []struct {
		name       string
		pollStatus int
		pollBody   map[string]any
	}{
		{"budget exhausted", http.StatusOK, map[string]any{"id": "tx-789", "status": "SUBMITTED"}},
		{"poll failed", http.StatusServiceUnavailable, map[string]any{"error": "unavailable"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := testutils.CreateTestTransaction(pub)
			if err != nil {
				t.Fatal(err)
			}

			s := newTestSignerWithProgramCall(t, pub.String(), true, func(mux *http.ServeMux) {
				mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, _ *http.Request) {
					testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-789", "status": "SUBMITTED"})
				})
				mux.HandleFunc("/v1/transactions/tx-789", func(w http.ResponseWriter, _ *http.Request) {
					testutils.WriteJSON(w, tc.pollStatus, tc.pollBody)
				})
			})

			_, err = s.SignTransaction(context.Background(), tx)
			if code, _ := core.CodeOf(err); code != core.CodeBroadcastUnconfirmed {
				t.Fatalf("got %s, want BROADCAST_UNCONFIRMED", code)
			}
			var se *core.SignerError
			if errors.As(err, &se) && se.ProviderTxID != "tx-789" {
				t.Errorf("ProviderTxID = %q, want tx-789", se.ProviderTxID)
			}
		})
	}
}

func TestCreateWithUnusableBody(t *testing.T) {
	for _, tc := range []struct {
		name           string
		useProgramCall bool
		wantCode       core.Code
		wantTxID       string
	}{
		{"program call reports unconfirmed with the id", true, core.CodeBroadcastUnconfirmed, "tx-accepted"},
		{"raw stays a plain failure", false, core.CodeSerializationError, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub := testutils.TestPublicKey()
			s := newTestSignerWithProgramCall(t, pub.String(), tc.useProgramCall, func(mux *http.ServeMux) {
				mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"id":"tx-accepted","status":123}`)
				})
			})

			tx, err := testutils.CreateTestTransaction(pub)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.SignTransaction(context.Background(), tx)
			if code, _ := core.CodeOf(err); code != tc.wantCode {
				t.Fatalf("got %s, want %s", code, tc.wantCode)
			}
			var se *core.SignerError
			if errors.As(err, &se) && se.ProviderTxID != tc.wantTxID {
				t.Errorf("ProviderTxID = %q, want %q", se.ProviderTxID, tc.wantTxID)
			}
		})
	}
}

// PROGRAM_CALL accepts legacy and v0 only, so a v1 message is rejected before
// any transaction is created.
func TestSignTransactionProgramCallRejectsV1(t *testing.T) {
	pub := testutils.TestPublicKey()
	var requests atomic.Int64

	s := newTestSignerWithProgramCall(t, pub.String(), true, func(mux *http.ServeMux) {
		mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-789", "status": "SUBMITTED"})
		})
	})

	tx, err := testutils.CreateTestV1Transaction(pub)
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.SignTransaction(context.Background(), tx)
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Fatalf("got %s, want SIGNING_FAILED", code)
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("a v1 message must be rejected before the PROGRAM_CALL is created, server saw %d requests", got)
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

			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
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
	signingPriv, _ := testutils.KeyFromSeed(0x24)
	_, differentPub := testutils.KeyFromSeed(0x25)
	message := []byte("test message")
	signature := ed25519.Sign(signingPriv, message)

	s := newTestSigner(t, differentPub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc("/v1/transactions", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
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
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123", "status": "FAILED", "signedMessages": []any{}})
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
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
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
	if errors.As(err, &se) && !strings.Contains(se.Detail(), "polling timed out") {
		t.Errorf("detail = %q, want polling timeout message", se.Detail())
	}
}

func TestRemoteErrorBodySanitizedIntoDetail(t *testing.T) {
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
	if strings.Contains(err.Error(), "evil") {
		t.Errorf("Error() must not surface the remote body, got %q", err.Error())
	}
	detail := se.Detail()
	if !strings.Contains(detail, "API error 500") {
		t.Errorf("detail = %q, want the status code", detail)
	}
	if !strings.Contains(detail, "evil <script>alert(1)</script>") {
		t.Errorf("detail = %q, want the sanitized body", detail)
	}
	if strings.ContainsRune(detail, '\x01') {
		t.Errorf("detail contains raw control characters: %q", detail)
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
						testutils.WriteJSON(w, http.StatusOK, map[string]string{"id": testVaultID, "name": "Test Vault"})
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
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
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
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123", "status": "SUBMITTED"})
		})
		mux.HandleFunc("/v1/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123", "status": "COMPLETED"})
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
