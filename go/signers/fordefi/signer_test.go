package fordefi

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

const (
	testAccessToken = "test-access-token"
	testVaultID     = "test-vault-id"
	vaultPath       = "/api/v1/vaults/test-vault-id"
)

func testP256Key(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return key, string(pemBytes)
}

func baseConfig(t *testing.T) Config {
	t.Helper()
	_, pemKey := testP256Key(t)
	return Config{
		AccessToken:   testAccessToken,
		VaultID:       testVaultID,
		PublicKey:     testutils.TestPublicKey().String(),
		PrivateKeyPEM: pemKey,
	}
}

// newTestServer starts a TLS server whose vault endpoint reports address, plus
// any handlers registered by configure.
func newTestServer(t *testing.T, address string, configure func(mux *http.ServeMux)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(vaultPath, func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": testVaultID, "address": address})
	})
	if configure != nil {
		configure(mux)
	}
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestSigner(t *testing.T, cfg Config, address string, configure func(mux *http.ServeMux)) *Signer {
	t.Helper()
	srv := newTestServer(t, address, configure)
	cfg.APIBaseURL = srv.URL
	cfg.HTTPClient = srv.Client()
	cfg.PollInterval = time.Millisecond
	cfg.MaxPollAttempts = 3
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return s
}

func TestNewValidatesConfig(t *testing.T) {
	_, pemKey := testP256Key(t)
	pubkey := testutils.TestPublicKey().String()
	cases := map[string]struct {
		mutate   func(cfg *Config)
		wantCode core.Code
	}{
		"empty access token": {
			mutate:   func(cfg *Config) { cfg.AccessToken = "" },
			wantCode: core.CodeConfigError,
		},
		"empty vault id": {
			mutate:   func(cfg *Config) { cfg.VaultID = "" },
			wantCode: core.CodeConfigError,
		},
		"empty public key": {
			mutate:   func(cfg *Config) { cfg.PublicKey = "" },
			wantCode: core.CodeConfigError,
		},
		"both pem and request signer": {
			mutate:   func(cfg *Config) { cfg.RequestSigner = &PemRequestSigner{} },
			wantCode: core.CodeConfigError,
		},
		"neither pem nor request signer": {
			mutate:   func(cfg *Config) { cfg.PrivateKeyPEM = "" },
			wantCode: core.CodeConfigError,
		},
		"invalid chain": {
			mutate:   func(cfg *Config) { cfg.Chain = "solana_testnet" },
			wantCode: core.CodeConfigError,
		},
		"fee without chain": {
			mutate:   func(cfg *Config) { cfg.Fee = &Fee{Type: FeeTypePriority, PriorityLevel: PriorityMedium} },
			wantCode: core.CodeConfigError,
		},
		"non-https base url": {
			mutate:   func(cfg *Config) { cfg.APIBaseURL = "http://127.0.0.1:1" },
			wantCode: core.CodeConfigError,
		},
		"invalid public key": {
			mutate:   func(cfg *Config) { cfg.PublicKey = "not-a-pubkey" },
			wantCode: core.CodeInvalidPublicKey,
		},
		"invalid pem": {
			mutate:   func(cfg *Config) { cfg.PrivateKeyPEM = "invalid-key" },
			wantCode: core.CodeInvalidPrivateKey,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := Config{
				AccessToken:   testAccessToken,
				VaultID:       testVaultID,
				PublicKey:     pubkey,
				PrivateKeyPEM: pemKey,
			}
			tc.mutate(&cfg)
			_, err := New(context.Background(), cfg)
			if err == nil {
				t.Fatal("expected New to fail")
			}
			if code, _ := core.CodeOf(err); code != tc.wantCode {
				t.Errorf("got %s, want %s", code, tc.wantCode)
			}
		})
	}
}

// Config validation must fail closed: no request may reach Fordefi before an
// invalid config is rejected.
func TestNewValidationRejectsBeforeAnyNetworkCall(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": testVaultID, "address": testutils.TestPublicKey().String()})
	}))
	t.Cleanup(srv.Close)

	cfg := baseConfig(t)
	cfg.APIBaseURL = srv.URL
	cfg.HTTPClient = srv.Client()
	cfg.Fee = &Fee{Type: FeeTypePriority, PriorityLevel: PriorityMedium}
	if _, err := New(context.Background(), cfg); err == nil {
		t.Fatal("expected New to reject fee without chain")
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("invalid config must be rejected before any network call, server saw %d requests", got)
	}
}

func TestPemRequestSignerSignsVerifiably(t *testing.T) {
	key, pemKey := testP256Key(t)
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sec1PEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))

	for name, encoded := range map[string]string{"pkcs8": pemKey, "sec1": sec1PEM} {
		t.Run(name, func(t *testing.T) {
			signer, err := NewPemRequestSigner(encoded)
			if err != nil {
				t.Fatalf("NewPemRequestSigner: %v", err)
			}
			payload := []byte("/api/v1/transactions|1700000000000|{}")
			sigB64, err := signer.SignRequest(context.Background(), payload)
			if err != nil {
				t.Fatal(err)
			}
			der, err := base64.StdEncoding.DecodeString(sigB64)
			if err != nil {
				t.Fatalf("signature is not valid base64: %v", err)
			}
			digest := sha256.Sum256(payload)
			if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
				t.Error("signature must verify as ECDSA P-256 over SHA-256(payload)")
			}
		})
	}
}

func TestNewRejectsNonP256PEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p384PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := NewPemRequestSigner(p384PEM); err == nil {
		t.Fatal("expected a non-P-256 key to be rejected")
	}
}

func TestNewVerifiesVaultOwnership(t *testing.T) {
	pub := testutils.TestPublicKey()
	otherKey := make([]byte, 32)
	otherKey[0] = 1

	cases := map[string]struct {
		vault    map[string]any
		wantErr  bool
		wantCode core.Code
	}{
		"address match": {
			vault: map[string]any{"id": testVaultID, "address": pub.String()},
		},
		"compressed key match": {
			vault: map[string]any{"id": testVaultID, "public_key_compressed": base64.StdEncoding.EncodeToString(pub.Bytes())},
		},
		"address mismatch": {
			vault:    map[string]any{"id": testVaultID, "address": solana.PublicKeyFromBytes(otherKey).String()},
			wantErr:  true,
			wantCode: core.CodeConfigError,
		},
		"invalid address": {
			vault:    map[string]any{"id": testVaultID, "address": "not-base58!!"},
			wantErr:  true,
			wantCode: core.CodeInvalidPublicKey,
		},
		"neither field": {
			vault:    map[string]any{"id": testVaultID},
			wantErr:  true,
			wantCode: core.CodeConfigError,
		},
		"compressed key wrong length": {
			vault:    map[string]any{"id": testVaultID, "public_key_compressed": base64.StdEncoding.EncodeToString([]byte("short"))},
			wantErr:  true,
			wantCode: core.CodeInvalidPublicKey,
		},
		"compressed key invalid base64": {
			vault:    map[string]any{"id": testVaultID, "public_key_compressed": "!!!not-base64!!!"},
			wantErr:  true,
			wantCode: core.CodeSerializationError,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc(vaultPath, func(w http.ResponseWriter, _ *http.Request) {
				testutils.WriteJSON(w, http.StatusOK, tc.vault)
			})
			srv := httptest.NewTLSServer(mux)
			t.Cleanup(srv.Close)

			cfg := baseConfig(t)
			cfg.APIBaseURL = srv.URL
			cfg.HTTPClient = srv.Client()
			_, err := New(context.Background(), cfg)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("New failed: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected New to fail vault verification")
			}
			if code, _ := core.CodeOf(err); code != tc.wantCode {
				t.Errorf("got %s, want %s", code, tc.wantCode)
			}
		})
	}
}

func TestNewVaultFetchAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(vaultPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	cfg := baseConfig(t)
	cfg.APIBaseURL = srv.URL
	cfg.HTTPClient = srv.Client()
	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error when the vault fetch fails")
	}
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("got %s, want REMOTE_API_ERROR", code)
	}
}

// respondSigned registers a black-box submit handler plus a poll handler that
// returns state with the given signature entries.
func respondSigned(t *testing.T, state string, sigData []map[string]string) func(mux *http.ServeMux) {
	t.Helper()
	return func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123"})
		})
		mux.HandleFunc(transactionsPath+"/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"state": state, "signatures": sigData})
		})
	}
}

func TestSignMessageBlackBoxSuccess(t *testing.T) {
	key, pemKey := testP256Key(t)
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	cfg := baseConfig(t)
	cfg.PrivateKeyPEM = pemKey
	s := newTestSigner(t, cfg, pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer "+testAccessToken {
				t.Errorf("Authorization = %q, want bearer token", got)
			}
			body, _ := io.ReadAll(r.Body)

			// The x-signature header must be the base64 DER ECDSA P-256
			// signature over SHA-256("{path}|{x-timestamp}|{body}").
			timestamp := r.Header.Get("x-timestamp")
			if _, err := strconv.ParseInt(timestamp, 10, 64); err != nil {
				t.Errorf("x-timestamp = %q, want unix milliseconds", timestamp)
			}
			der, err := base64.StdEncoding.DecodeString(r.Header.Get("x-signature"))
			if err != nil {
				t.Errorf("x-signature is not valid base64: %v", err)
			}
			payload := transactionsPath + "|" + timestamp + "|" + string(body)
			digest := sha256.Sum256([]byte(payload))
			if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
				t.Error("x-signature must verify over the {path}|{timestamp}|{body} payload")
			}

			var req map[string]any
			if err := json.Unmarshal(body, &req); err != nil {
				t.Errorf("request body should be JSON: %v", err)
			}
			if req["type"] != "black_box_signature" || req["vault_id"] != testVaultID ||
				req["signer_type"] != "api_signer" || req["sign_mode"] != "auto" {
				t.Errorf("unexpected request envelope: %v", req)
			}
			details, _ := req["details"].(map[string]any)
			if details["format"] != "hash_binary" ||
				details["hash_binary"] != base64.StdEncoding.EncodeToString(message) {
				t.Errorf("unexpected black box details: %v", details)
			}
			if got := r.Header.Get("x-idempotence-id"); got != "" {
				t.Errorf("x-idempotence-id = %q, want none on the black-box path", got)
			}

			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123"})
		})
		mux.HandleFunc(transactionsPath+"/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
				"state":      "signed",
				"signatures": []map[string]string{{"data": base64.StdEncoding.EncodeToString(signature)}},
			})
		})
	})

	got, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if got != solana.SignatureFromBytes(signature) {
		t.Errorf("signature = %s, want %s", got, solana.SignatureFromBytes(signature))
	}
}

func TestSignMessageVerificationFailure(t *testing.T) {
	message := []byte("test message")
	wrongSignature := ed25519.Sign(testutils.TestPrivateKey(), []byte("different message"))

	s := newTestSigner(t, baseConfig(t), testutils.TestPublicKey().String(),
		respondSigned(t, "signed", []map[string]string{{"data": base64.StdEncoding.EncodeToString(wrongSignature)}}))

	_, err := s.SignMessage(context.Background(), message)
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

func TestSignMessageTerminalState(t *testing.T) {
	s := newTestSigner(t, baseConfig(t), testutils.TestPublicKey().String(),
		respondSigned(t, "aborted", nil))

	_, err := s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for terminal state")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
	var se *core.SignerError
	if errors.As(err, &se) && !strings.Contains(se.Detail(), "aborted") {
		t.Errorf("detail = %q, want mention of the terminal state", se.Detail())
	}
}

func TestSignMessagePollingTimeout(t *testing.T) {
	s := newTestSigner(t, baseConfig(t), testutils.TestPublicKey().String(),
		respondSigned(t, "pending", nil))

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

func TestSignMessageAPIErrorDoesNotLeakBody(t *testing.T) {
	hostile := "evil\x01<script>alert(1)</script>"
	s := newTestSigner(t, baseConfig(t), testutils.TestPublicKey().String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
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
	if se.Code != core.CodeRemoteAPIError {
		t.Errorf("got %s, want REMOTE_API_ERROR", se.Code)
	}
	if se.Detail() != "API error 500" {
		t.Errorf("detail = %q, want %q", se.Detail(), "API error 500")
	}
}

func TestSignMessageNoSignatures(t *testing.T) {
	s := newTestSigner(t, baseConfig(t), testutils.TestPublicKey().String(),
		respondSigned(t, "signed", nil))

	_, err := s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error when no signatures are returned")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

func TestSignMessageInvalidSignatureLength(t *testing.T) {
	s := newTestSigner(t, baseConfig(t), testutils.TestPublicKey().String(),
		respondSigned(t, "signed", []map[string]string{{"data": base64.StdEncoding.EncodeToString([]byte("short"))}}))

	_, err := s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for a non-64-byte signature")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

func TestSignTransactionBlackBoxComplete(t *testing.T) {
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

	s := newTestSigner(t, baseConfig(t), pub.String(),
		respondSigned(t, "signed", []map[string]string{{"data": base64.StdEncoding.EncodeToString(signature[:])}}))

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

// nativeConfig returns a devnet native-mode config.
func nativeConfig(t *testing.T) Config {
	t.Helper()
	cfg := baseConfig(t)
	cfg.Chain = ChainSolanaDevnet
	return cfg
}

// Native mode broadcasts, so batch helpers must reject it; black box may batch.
func TestBroadcastsTransactionsFollowsMode(t *testing.T) {
	pub := testutils.TestPublicKey()
	native := newTestSigner(t, nativeConfig(t), pub.String(), func(*http.ServeMux) {})
	if !native.BroadcastsTransactions() {
		t.Error("native mode must report broadcasting")
	}
	blackBox := newTestSigner(t, baseConfig(t), pub.String(), func(*http.ServeMux) {})
	if blackBox.BroadcastsTransactions() {
		t.Error("black-box mode must not report broadcasting")
	}
}

func TestSignTransactionNativeSuccess(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()

	returned, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	returnedMsg, err := returned.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	signature := solana.SignatureFromBytes(ed25519.Sign(priv, returnedMsg))
	returned.Signatures = []solana.Signature{signature}
	wireBytes, err := returned.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	cfg := nativeConfig(t)
	cfg.Fee = &Fee{Type: FeeTypePriority, PriorityLevel: PriorityMedium}
	s := newTestSigner(t, cfg, pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			if err := json.Unmarshal(body, &req); err != nil {
				t.Errorf("request body should be JSON: %v", err)
			}
			if req["type"] != "solana_transaction" {
				t.Errorf("type = %v, want solana_transaction", req["type"])
			}
			details, _ := req["details"].(map[string]any)
			if details["type"] != "solana_serialized_transaction_message" ||
				details["chain"] != string(ChainSolanaDevnet) || details["push_mode"] != "auto" {
				t.Errorf("unexpected native details: %v", details)
			}
			fee, _ := details["fee"].(map[string]any)
			if fee["type"] != FeeTypePriority || fee["priority_level"] != string(PriorityMedium) {
				t.Errorf("unexpected fee: %v", fee)
			}
			encodedData, _ := details["data"].(string)
			submittedMessage, decodeErr := base64.StdEncoding.DecodeString(encodedData)
			if decodeErr != nil {
				t.Errorf("decode submitted message: %v", decodeErr)
			}
			digest := sha256.Sum256(submittedMessage)
			id := digest[:16]
			id[6] = (id[6] & 0x0f) | 0x40
			id[8] = (id[8] & 0x3f) | 0x80
			want := fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
			if got := r.Header.Get("x-idempotence-id"); got != want {
				t.Errorf("x-idempotence-id = %q, want %q", got, want)
			}
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123"})
		})
		mux.HandleFunc(transactionsPath+"/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
				"state":           "completed",
				"raw_transaction": base64.StdEncoding.EncodeToString(wireBytes),
			})
		})
	})

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.SignAndSendTransaction(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if res != signature {
		t.Errorf("signature = %s, want %s", res, signature)
	}
	for _, sig := range tx.Signatures {
		if !sig.IsZero() {
			t.Error("the caller's transaction must be left untouched by provider-chosen bytes")
		}
	}
}

// Native mode signs "signed" as insufficient: a pushable transaction must
// reach "completed" before polling stops.
func TestSignTransactionNativeWaitsForCompleted(t *testing.T) {
	pub := testutils.TestPublicKey()
	s := newTestSigner(t, nativeConfig(t), pub.String(),
		respondSigned(t, "signed", nil))

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignAndSendTransaction(context.Background(), tx)
	if err == nil {
		t.Fatal("expected polling timeout when a pushable transaction never completes")
	}
	assertBroadcastUnconfirmed(t, err, "tx-123")
}

// assertBroadcastUnconfirmed checks that err is a CodeBroadcastUnconfirmed
// SignerError carrying the expected provider transaction id.
func assertBroadcastUnconfirmed(t *testing.T, err error, wantTxID string) {
	t.Helper()
	if code, _ := core.CodeOf(err); code != core.CodeBroadcastUnconfirmed {
		t.Errorf("got %s, want BROADCAST_UNCONFIRMED", code)
	}
	var se *core.SignerError
	if !errors.As(err, &se) || se.ProviderTxID != wantTxID {
		t.Errorf("error must carry provider transaction id %q, got %v", wantTxID, err)
	}
	if !strings.Contains(err.Error(), wantTxID) {
		t.Errorf("Error() must surface the provider transaction id, got %q", err.Error())
	}
}

func TestSignTransactionNativeSubmitServerErrorIsUnconfirmedWithoutID(t *testing.T) {
	pub := testutils.TestPublicKey()
	s := newTestSigner(t, nativeConfig(t), pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		})
	})

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignAndSendTransaction(context.Background(), tx)
	if err == nil {
		t.Fatal("expected a failed submit to be reported")
	}
	assertBroadcastUnconfirmedWithoutID(t, err, http.StatusBadGateway)
}

func TestSignTransactionNativeSubmitWithoutIDIsUnconfirmed(t *testing.T) {
	pub := testutils.TestPublicKey()
	s := newTestSigner(t, nativeConfig(t), pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"state": "pending"})
		})
	})

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignAndSendTransaction(context.Background(), tx)
	if err == nil {
		t.Fatal("expected an accepted submit without an id to be reported")
	}
	assertBroadcastUnconfirmedWithoutID(t, err, 0)
}

func TestSignTransactionNativeSubmitRejectionStaysPlainFailure(t *testing.T) {
	pub := testutils.TestPublicKey()
	s := newTestSigner(t, nativeConfig(t), pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
	})

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignAndSendTransaction(context.Background(), tx)
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("got %s, want REMOTE_API_ERROR", code)
	}
}

// Black-box mode only signs, so a failed submit has no on-chain outcome to be unconfirmed about.
func TestSignTransactionBlackBoxSubmitServerErrorIsNotUnconfirmed(t *testing.T) {
	pub := testutils.TestPublicKey()
	s := newTestSigner(t, baseConfig(t), pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		})
	})

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignTransaction(context.Background(), tx)
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("got %s, want REMOTE_API_ERROR", code)
	}
}

// assertBroadcastUnconfirmedWithoutID checks for an unconfirmed broadcast with no
// id, carrying wantStatus (0 when the provider sent no failing status).
func assertBroadcastUnconfirmedWithoutID(t *testing.T, err error, wantStatus int) {
	t.Helper()
	if code, _ := core.CodeOf(err); code != core.CodeBroadcastUnconfirmed {
		t.Errorf("got %s, want BROADCAST_UNCONFIRMED", code)
	}
	var se *core.SignerError
	if !errors.As(err, &se) || se.ProviderTxID != "" {
		t.Errorf("error must carry no provider transaction id, got %v", err)
	}
	if se != nil && se.ProviderStatus != wantStatus {
		t.Errorf("provider status = %d, want %d", se.ProviderStatus, wantStatus)
	}
}

func TestSignTransactionNativeRejectsMultiSigner(t *testing.T) {
	pub := testutils.TestPublicKey()
	var requests atomic.Int64
	s := newTestSigner(t, nativeConfig(t), pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123"})
		})
	})

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	tx.Message.Header.NumRequiredSignatures = 2
	_, err = s.SignAndSendTransaction(context.Background(), tx)
	if err == nil {
		t.Fatal("expected multi-signer transaction to be rejected")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("rejection must happen before any signing request, server saw %d", got)
	}
}

func TestSignTransactionNativeMissingRawTransaction(t *testing.T) {
	pub := testutils.TestPublicKey()
	s := newTestSigner(t, nativeConfig(t), pub.String(),
		respondSigned(t, "completed", nil))

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignAndSendTransaction(context.Background(), tx)
	if err == nil {
		t.Fatal("expected error when raw_transaction is missing")
	}
	assertBroadcastUnconfirmed(t, err, "tx-123")
}

func TestSignTransactionNativeUndecodableRawTransaction(t *testing.T) {
	pub := testutils.TestPublicKey()
	s := newTestSigner(t, nativeConfig(t), pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123"})
		})
		mux.HandleFunc(transactionsPath+"/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
				"state":           "completed",
				"raw_transaction": base64.StdEncoding.EncodeToString([]byte{0xff, 0xff}),
			})
		})
	})

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignAndSendTransaction(context.Background(), tx)
	if err == nil {
		t.Fatal("expected error for an undecodable wire transaction")
	}
	assertBroadcastUnconfirmed(t, err, "tx-123")
}

func TestSignMessageNativeUsesSolanaMessage(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()
	message := []byte("native message")
	signature := ed25519.Sign(priv, message)

	s := newTestSigner(t, nativeConfig(t), pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			if err := json.Unmarshal(body, &req); err != nil {
				t.Errorf("request body should be JSON: %v", err)
			}
			if req["type"] != "solana_message" {
				t.Errorf("type = %v, want solana_message", req["type"])
			}
			details, _ := req["details"].(map[string]any)
			if details["type"] != "personal_message_type" ||
				details["chain"] != string(ChainSolanaDevnet) ||
				details["raw_data"] != base64.StdEncoding.EncodeToString(message) {
				t.Errorf("unexpected message details: %v", details)
			}
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "tx-123"})
		})
		mux.HandleFunc(transactionsPath+"/tx-123", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
				"state":      "signed",
				"signatures": []map[string]string{{"data": base64.StdEncoding.EncodeToString(signature)}},
			})
		})
	})

	got, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if got != solana.SignatureFromBytes(signature) {
		t.Errorf("signature = %s, want %s", got, solana.SignatureFromBytes(signature))
	}
}

func TestIsAvailable(t *testing.T) {
	s := newTestSigner(t, baseConfig(t), testutils.TestPublicKey().String(), nil)
	if !s.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be true when the vault is reachable")
	}
}

func TestIsAvailableFailure(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc(vaultPath, func(w http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": testVaultID, "address": testutils.TestPublicKey().String()})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	cfg := baseConfig(t)
	cfg.APIBaseURL = srv.URL
	cfg.HTTPClient = srv.Client()
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	healthy.Store(false)
	if s.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be false when the vault fetch fails")
	}
}

func TestIsAvailableUnreachable(t *testing.T) {
	s := newTestSigner(t, baseConfig(t), testutils.TestPublicKey().String(), nil)
	s2 := *s
	s2.apiBaseURL = "https://127.0.0.1:1"
	if s2.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be false when the API is unreachable")
	}
}

// Every fmt rendering of the signer must omit the access token and the P-256
// request-signing key material.
func TestStringDoesNotLeakSecrets(t *testing.T) {
	cfg := baseConfig(t)
	pemBody := strings.Split(cfg.PrivateKeyPEM, "\n")[1]
	s := newTestSigner(t, cfg, testutils.TestPublicKey().String(), nil)
	pemSigner, ok := s.requestSigner.(*PemRequestSigner)
	if !ok {
		t.Fatal("expected the built-in PEM request signer")
	}
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
		if strings.Contains(rendered, testAccessToken) {
			t.Errorf("rendered signer leaks the access token: %s", rendered)
		}
		if strings.Contains(rendered, pemBody) || strings.Contains(rendered, pemSigner.key.D.String()) {
			t.Errorf("rendered signer leaks P-256 key material: %s", rendered)
		}
		if !strings.Contains(rendered, "fordefi.Signer") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
	}
}
