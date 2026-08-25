package cdp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/base58"

	"github.com/solana-foundation/solana-keychain/go/core"
	"github.com/solana-foundation/solana-keychain/go/testutils"
)

const testPubkeyStr = "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV"

// testEd25519Key returns a deterministic Ed25519 key in the CDP base64 format
// (seed || pubkey). It must be a real keypair to pass JWT key validation
// (seed = 32 x 0x42).
func testEd25519Key() string {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return base64.StdEncoding.EncodeToString(priv) // priv is already seed || pubkey
}

// testWalletSecret returns a valid wallet secret: base64 of a minimal 67-byte
// P-256 PKCS#8 DER fixture.
func testWalletSecret() string {
	der := []byte{
		// outer SEQUENCE (65 bytes)
		0x30, 0x41,
		// version INTEGER 0
		0x02, 0x01, 0x00,
		// AlgorithmIdentifier SEQUENCE (19 bytes)
		0x30, 0x13,
		// OID ecPublicKey (1.2.840.10045.2.1)
		0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
		// OID prime256v1 (1.2.840.10045.3.1.7)
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
		// privateKey OCTET STRING (39 bytes)
		0x04, 0x27,
		// ECPrivateKey SEQUENCE (37 bytes)
		0x30, 0x25,
		// version INTEGER 1
		0x02, 0x01, 0x01,
		// privateKey OCTET STRING (32 bytes) — scalar in [1, n-1]
		0x04, 0x20,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
	return base64.StdEncoding.EncodeToString(der)
}

// testConfig builds a valid Config pointing at baseURL.
func testConfig(baseURL string, client *http.Client) Config {
	return Config{
		APIKeyID:     "test-api-key",
		APIKeySecret: testEd25519Key(),
		WalletSecret: testWalletSecret(),
		Address:      testPubkeyStr,
		APIBaseURL:   baseURL,
		HTTPClient:   client,
	}
}

// newTestSigner builds a signer against an httptest server.
func newTestSigner(t *testing.T, srv *httptest.Server, address string) *Signer {
	t.Helper()
	cfg := testConfig(srv.URL, srv.Client())
	cfg.Address = address
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return s
}

// transferTx builds a single-signer System transfer to an explicit recipient.
func transferTx(t *testing.T, payer, recipient solana.PublicKey) *solana.Transaction {
	t.Helper()
	tx, err := testutils.CreateTestTransactionTo(payer, recipient)
	if err != nil {
		t.Fatalf("failed to build test transaction: %v", err)
	}
	return tx
}

func TestNewValid(t *testing.T) {
	s, err := New(testConfig("", nil))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if s.Pubkey().String() != testPubkeyStr {
		t.Errorf("pubkey = %s, want %s", s.Pubkey(), testPubkeyStr)
	}
}

func TestNewRejectsEmptyFields(t *testing.T) {
	mutations := map[string]func(*Config){
		"empty api key id":     func(c *Config) { c.APIKeyID = "" },
		"empty api key secret": func(c *Config) { c.APIKeySecret = "" },
		"empty wallet secret":  func(c *Config) { c.WalletSecret = "" },
		"empty address":        func(c *Config) { c.Address = "" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig("", nil)
			mutate(&cfg)
			_, err := New(cfg)
			testutils.AssertCode(t, err, core.CodeConfigError)
		})
	}
}

func TestNewRejectsInvalidAddress(t *testing.T) {
	cfg := testConfig("", nil)
	cfg.Address = "not-a-valid-pubkey"
	_, err := New(cfg)
	testutils.AssertCode(t, err, core.CodeInvalidPublicKey)
}

func TestPubkey(t *testing.T) {
	s, err := New(testConfig("https://localhost", nil))
	if err != nil {
		t.Fatal(err)
	}
	if s.Pubkey().String() != testPubkeyStr {
		t.Errorf("pubkey = %s, want %s", s.Pubkey(), testPubkeyStr)
	}
}

func TestStringDoesNotLeakSecrets(t *testing.T) {
	s, err := New(testConfig("https://localhost", nil))
	if err != nil {
		t.Fatal(err)
	}
	testutils.AssertRedacted(t, s, "cdp.Signer", []string{testEd25519Key(), testWalletSecret()})
}

func TestSignMessageInvalidAPIKeySecret(t *testing.T) {
	cfg := testConfig("https://localhost", nil)
	cfg.APIKeySecret = "not-base64"
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeInvalidPrivateKey)
}

func TestSignMessageInvalidWalletSecret(t *testing.T) {
	cfg := testConfig("https://localhost", nil)
	cfg.WalletSecret = "not-base64"
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeInvalidPrivateKey)
}

func TestSignMessageSuccess(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()
	message := []byte("test message")
	sigBytes := ed25519.Sign(priv, message)

	var calls atomic.Int32
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if want := basePath + "/" + pub.String() + "/sign/message"; r.URL.Path != want {
			t.Errorf("path = %s, want %s", r.URL.Path, want)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Error("missing Bearer Authorization header")
		}
		if r.Header.Get("X-Wallet-Auth") == "" {
			t.Error("missing X-Wallet-Auth header")
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %s, want application/json", ct)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		} else if body["message"] != string(message) {
			t.Errorf("request message = %v, want %s", body["message"], message)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"signature": base58.Encode(sigBytes)})
	}))

	s := newTestSigner(t, srv, pub.String())
	sig, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatalf("SignMessage failed: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if !bytes.Equal(sig[:], sigBytes) {
		t.Error("returned signature does not match the remote signature")
	}
	if calls.Load() != 1 {
		t.Errorf("expected exactly 1 request, got %d", calls.Load())
	}
}

func TestSignMessageSignatureVerificationFailure(t *testing.T) {
	// Signature from a different key than the signer's address.
	signingPriv := testutils.TestPrivateKey()
	message := []byte("test message")
	sigBytes := ed25519.Sign(signingPriv, message)

	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"signature": base58.Encode(sigBytes)})
	}))

	s := newTestSigner(t, srv, testPubkeyStr)
	_, err := s.SignMessage(context.Background(), message)
	testutils.AssertCode(t, err, core.CodeSigningFailed)
}

func TestSignMessageAPIError(t *testing.T) {
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	s := newTestSigner(t, srv, testPubkeyStr)
	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)
}

func TestSignMessageInvalidSignatureLength(t *testing.T) {
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A base58 value that decodes to != 64 bytes.
		_ = json.NewEncoder(w).Encode(map[string]string{"signature": base58.Encode(make([]byte, 10))})
	}))

	s := newTestSigner(t, srv, testPubkeyStr)
	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeSigningFailed)
}

func TestSignMessageRejectsNonUTF8(t *testing.T) {
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("no request should be sent for a non-UTF-8 message")
	}))

	s := newTestSigner(t, srv, testPubkeyStr)
	_, err := s.SignMessage(context.Background(), []byte{0xff, 0xfe, 0xfd})
	testutils.AssertCode(t, err, core.CodeSerializationError)
}

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
	sigBytes := ed25519.Sign(priv, msgBytes)
	var sig solana.Signature
	copy(sig[:], sigBytes)

	// Build the remote's fully-signed transaction (same message, our signature).
	signedTx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	signedTx.Signatures = []solana.Signature{sig}
	signedWire, err := signedTx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if want := basePath + "/" + pub.String() + "/sign/transaction"; r.URL.Path != want {
			t.Errorf("path = %s, want %s", r.URL.Path, want)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		} else if _, ok := body["transaction"].(string); !ok {
			t.Errorf("request body missing transaction field: %v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"signedTransaction": base64.StdEncoding.EncodeToString(signedWire),
		})
	}))

	s := newTestSigner(t, srv, pub.String())
	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SignTransaction failed: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.EncodedTransaction == "" {
		t.Error("encoded transaction should not be empty")
	}
	if res.Signature != sig {
		t.Error("returned signature does not match the remote signature")
	}
	want, err := core.Serialize(tx)
	if err != nil {
		t.Fatal(err)
	}
	if res.EncodedTransaction != want {
		t.Error("encoded transaction should match the re-serialized input transaction")
	}
	if !res.IsComplete() {
		t.Error("single-signer transaction should be Complete")
	}
	if calls.Load() != 1 {
		t.Errorf("expected exactly 1 request, got %d", calls.Load())
	}
}

func TestSignTransactionRejectsTamperedRemoteTransaction(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	originalMsg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a compromised API returning a signature over a different transaction.
	tamperedRecipient := solana.MustPublicKeyFromBase58(testPubkeyStr)
	tamperedTx := transferTx(t, pub, tamperedRecipient)
	tamperedMsg, err := tamperedTx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var tamperedSig solana.Signature
	copy(tamperedSig[:], ed25519.Sign(priv, tamperedMsg))
	tamperedTx.Signatures = []solana.Signature{tamperedSig}
	tamperedWire, err := tamperedTx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"signedTransaction": base64.StdEncoding.EncodeToString(tamperedWire),
		})
	}))

	s := newTestSigner(t, srv, pub.String())
	_, err = s.SignTransaction(context.Background(), tx)
	testutils.AssertCode(t, err, core.CodeSigningFailed)

	afterMsg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalMsg, afterMsg) {
		t.Error("transaction message must be unchanged after a rejected response")
	}
}

func TestSignTransactionAPIError(t *testing.T) {
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	s := newTestSigner(t, srv, testPubkeyStr)
	tx, err := testutils.CreateTestTransaction(solana.MustPublicKeyFromBase58(testPubkeyStr))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignTransaction(context.Background(), tx)
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)
}

func TestIsAvailable(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var calls atomic.Int32
		srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if r.Method != http.MethodGet {
				t.Errorf("method = %s, want GET", r.Method)
			}
			if want := basePath + "/" + testPubkeyStr; r.URL.Path != want {
				t.Errorf("path = %s, want %s", r.URL.Path, want)
			}
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				t.Error("missing Bearer Authorization header")
			}
			if r.Header.Get("X-Wallet-Auth") != "" {
				t.Error("GET requests must not carry X-Wallet-Auth")
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"address": testPubkeyStr})
		}))

		s := newTestSigner(t, srv, testPubkeyStr)
		if !s.IsAvailable(context.Background()) {
			t.Error("IsAvailable should be true on a 2xx response")
		}
		if calls.Load() != 1 {
			t.Errorf("expected exactly 1 request, got %d", calls.Load())
		}
	})

	t.Run("failure", func(t *testing.T) {
		srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))

		s := newTestSigner(t, srv, testPubkeyStr)
		if s.IsAvailable(context.Background()) {
			t.Error("IsAvailable should be false on a non-2xx response")
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.NotFoundHandler())
		srv.Close() // immediately unreachable
		cfg := testConfig(srv.URL, srv.Client())
		s, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if s.IsAvailable(context.Background()) {
			t.Error("IsAvailable should be false when the API is unreachable")
		}
	})
}

func TestHTTPSEnforcementDefaultClient(t *testing.T) {
	// The scheme check fires at construction, regardless of client (a custom
	// client must not be able to bypass HTTPS enforcement).
	for name, client := range map[string]*http.Client{
		"default client": nil,
		"custom client":  http.DefaultClient,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(testConfig("http://127.0.0.1:1", client))
			if err == nil {
				t.Fatal("expected error for http:// base URL")
			}
			testutils.AssertCode(t, err, core.CodeConfigError)
		})
	}
}
