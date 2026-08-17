package turnkey

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
	"github.com/solana-foundation/solana-keychain/go/testutils"
)

// newTestAPIKeys generates a P-256 API key pair: hex private scalar and hex
// uncompressed public point.
func newTestAPIKeys(t *testing.T) (pubHex, privHex string, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privHex = hex.EncodeToString(key.D.FillBytes(make([]byte, 32)))
	ecdhPub, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	pubHex = hex.EncodeToString(ecdhPub.Bytes())
	return pubHex, privHex, key
}

// testConfig builds a Config with fresh API keys, pointing at srv when non-nil.
func testConfig(t *testing.T, pubkey string, srv *httptest.Server) Config {
	t.Helper()
	pubHex, privHex, _ := newTestAPIKeys(t)
	cfg := Config{
		APIPublicKey:   pubHex,
		APIPrivateKey:  privHex,
		OrganizationID: "test-org-id",
		PrivateKeyID:   "test-key-id",
		PublicKey:      pubkey,
	}
	if srv != nil {
		cfg.APIBaseURL = srv.URL
		cfg.HTTPClient = srv.Client()
	}
	return cfg
}

// signResultBody renders the activity JSON Turnkey returns for a signature,
// split into hex r and s components.
func signResultBody(sig []byte) string {
	return `{"activity":{"status":"ACTIVITY_STATUS_COMPLETED","result":{"signRawPayloadResult":{"r":"` +
		hex.EncodeToString(sig[:32]) + `","s":"` + hex.EncodeToString(sig[32:]) + `"}}}}`
}

// signServer serves the sign_raw_payload endpoint with a fixed status and
// body, counting calls and checking method/path/headers.
func signServer(t *testing.T, status int, body string, calls *int32) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != signRawPayloadPath {
			t.Errorf("path = %s, want %s", r.URL.Path, signRawPayloadPath)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		if r.Header.Get("X-Stamp") == "" {
			t.Error("missing X-Stamp header")
		}
		w.WriteHeader(status)
		if _, err := io.WriteString(w, body); err != nil {
			t.Error(err)
		}
	}))
}

// otherKeypair returns a deterministic Ed25519 keypair distinct from the
// testutils fixture, for negative verification tests.
func otherKeypair() (ed25519.PrivateKey, solana.PublicKey) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	var pub solana.PublicKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return priv, pub
}

func TestNew(t *testing.T) {
	want := testutils.TestPublicKey()
	s, err := New(testConfig(t, want.String(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if s.organizationID != "test-org-id" {
		t.Errorf("organizationID = %q, want test-org-id", s.organizationID)
	}
	if s.privateKeyID != "test-key-id" {
		t.Errorf("privateKeyID = %q, want test-key-id", s.privateKeyID)
	}
	if s.publicKey != want {
		t.Errorf("publicKey = %s, want %s", s.publicKey, want)
	}
	if s.apiBaseURL != DefaultAPIBaseURL {
		t.Errorf("apiBaseURL = %q, want %q", s.apiBaseURL, DefaultAPIBaseURL)
	}
}

func TestNewInvalidPublicKey(t *testing.T) {
	_, err := New(testConfig(t, "not-a-valid-pubkey", nil))
	if err == nil {
		t.Fatal("expected error for invalid public key")
	}
	if code, _ := core.CodeOf(err); code != core.CodeInvalidPublicKey {
		t.Errorf("got %s, want INVALID_PUBLIC_KEY", code)
	}
}

func TestPubkey(t *testing.T) {
	want := testutils.TestPublicKey()
	s, err := New(testConfig(t, want.String(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if s.Pubkey() != want {
		t.Errorf("Pubkey() = %s, want %s", s.Pubkey(), want)
	}
}

func TestSignMessage(t *testing.T) {
	priv := testutils.TestPrivateKey()
	message := []byte("test message")
	sig := ed25519.Sign(priv, message)

	var calls int32
	srv := signServer(t, http.StatusOK, signResultBody(sig), &calls)
	defer srv.Close()

	s, err := New(testConfig(t, testutils.TestPublicKey().String(), srv))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	var want solana.Signature
	copy(want[:], sig)
	if got != want {
		t.Errorf("signature = %s, want %s", got, want)
	}
	if calls != 1 {
		t.Errorf("sign endpoint called %d times, want 1", calls)
	}
}

func TestSignMessageRequestBody(t *testing.T) {
	priv := testutils.TestPrivateKey()
	message := []byte("test message")
	sig := ed25519.Sign(priv, message)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.Type != "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2" {
			t.Errorf("type = %q", req.Type)
		}
		if req.TimestampMs == "" {
			t.Error("missing timestampMs")
		}
		if req.OrganizationID != "test-org-id" {
			t.Errorf("organizationId = %q", req.OrganizationID)
		}
		if req.Parameters.SignWith != "test-key-id" {
			t.Errorf("signWith = %q", req.Parameters.SignWith)
		}
		if req.Parameters.Payload != hex.EncodeToString(message) {
			t.Errorf("payload = %q, want hex of message", req.Parameters.Payload)
		}
		if req.Parameters.Encoding != "PAYLOAD_ENCODING_HEXADECIMAL" {
			t.Errorf("encoding = %q", req.Parameters.Encoding)
		}
		if req.Parameters.HashFunction != "HASH_FUNCTION_NOT_APPLICABLE" {
			t.Errorf("hashFunction = %q", req.Parameters.HashFunction)
		}
		if _, err := io.WriteString(w, signResultBody(sig)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	s, err := New(testConfig(t, testutils.TestPublicKey().String(), srv))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignMessage(context.Background(), message); err != nil {
		t.Fatal(err)
	}
}

func TestSignMessageVerificationFailure(t *testing.T) {
	// Signature comes from the fixture keypair, but the signer is configured
	// with a different public key, so local verification must fail.
	priv := testutils.TestPrivateKey()
	message := []byte("test message")
	sig := ed25519.Sign(priv, message)
	_, differentPub := otherKeypair()

	var calls int32
	srv := signServer(t, http.StatusOK, signResultBody(sig), &calls)
	defer srv.Close()

	s, err := New(testConfig(t, differentPub.String(), srv))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), message)
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
	if calls != 1 {
		t.Errorf("sign endpoint called %d times, want 1", calls)
	}
}

func TestSignTransaction(t *testing.T) {
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
	sig := ed25519.Sign(priv, msg)

	var calls int32
	srv := signServer(t, http.StatusOK, signResultBody(sig), &calls)
	defer srv.Close()

	s, err := New(testConfig(t, pub.String(), srv))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	var want solana.Signature
	copy(want[:], sig)
	if res.Signature != want {
		t.Errorf("signature = %s, want %s", res.Signature, want)
	}
	if res.EncodedTransaction == "" {
		t.Error("encoded transaction should not be empty")
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
	if calls != 1 {
		t.Errorf("sign endpoint called %d times, want 1", calls)
	}
}

func TestSignUnauthorized(t *testing.T) {
	var calls int32
	srv := signServer(t, http.StatusUnauthorized, `{"message":"Unauthorized"}`, &calls)
	defer srv.Close()

	s, err := New(testConfig(t, testutils.TestPublicKey().String(), srv))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
		t.Errorf("got %s, want REMOTE_API_ERROR", code)
	}
	if calls != 1 {
		t.Errorf("sign endpoint called %d times, want 1", calls)
	}
}

func TestSignInvalidResponse(t *testing.T) {
	var calls int32
	srv := signServer(t, http.StatusOK, `{"activity":{"status":"ACTIVITY_STATUS_COMPLETED"}}`, &calls)
	defer srv.Close()

	s, err := New(testConfig(t, testutils.TestPublicKey().String(), srv))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for response without result")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

func TestSignInvalidHex(t *testing.T) {
	var calls int32
	body := `{"activity":{"status":"ACTIVITY_STATUS_COMPLETED","result":{"signRawPayloadResult":{"r":"not-valid-hex!!!","s":"also-not-valid-hex!!!"}}}}`
	srv := signServer(t, http.StatusOK, body, &calls)
	defer srv.Close()

	s, err := New(testConfig(t, testutils.TestPublicKey().String(), srv))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for invalid hex components")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSerializationError {
		t.Errorf("got %s, want SERIALIZATION_ERROR", code)
	}
}

func TestSignRejectsNonCompletedActivity(t *testing.T) {
	var calls int32
	srv := signServer(t, http.StatusOK, `{"activity":{"status":"ACTIVITY_STATUS_CONSENSUS_NEEDED"}}`, &calls)
	defer srv.Close()

	s, err := New(testConfig(t, testutils.TestPublicKey().String(), srv))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for non-completed activity")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
	var se *core.SignerError
	if !errors.As(err, &se) || !strings.Contains(se.Detail(), "ACTIVITY_STATUS_CONSENSUS_NEEDED") {
		t.Errorf("error must name the received status, got %v", err)
	}
}

func TestSignRejectsMissingActivityStatus(t *testing.T) {
	var calls int32
	srv := signServer(t, http.StatusOK, `{"activity":{}}`, &calls)
	defer srv.Close()

	s, err := New(testConfig(t, testutils.TestPublicKey().String(), srv))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for missing activity status")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

func TestSignOversizedComponent(t *testing.T) {
	var calls int32
	body := `{"activity":{"status":"ACTIVITY_STATUS_COMPLETED","result":{"signRawPayloadResult":{"r":"` +
		hex.EncodeToString(bytes.Repeat([]byte{0xFF}, 33)) + `","s":"` +
		hex.EncodeToString(bytes.Repeat([]byte{0x01}, 32)) + `"}}}}`
	srv := signServer(t, http.StatusOK, body, &calls)
	defer srv.Close()

	s, err := New(testConfig(t, testutils.TestPublicKey().String(), srv))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for oversized r component")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

func TestIsAvailable(t *testing.T) {
	var calls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Method != http.MethodPost || r.URL.Path != whoAmIPath {
			t.Errorf("got %s %s, want POST %s", r.Method, r.URL.Path, whoAmIPath)
		}
		if r.Header.Get("X-Stamp") == "" {
			t.Error("missing X-Stamp header")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(body) != `{"organizationId":"test-org-id"}` {
			t.Errorf("whoami body = %s", body)
		}
		resp := `{"organizationId":"test-org-id","organizationName":"Test Org","userId":"test-user-id","username":"test@example.com"}`
		if _, err := io.WriteString(w, resp); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	s, err := New(testConfig(t, testutils.TestPublicKey().String(), srv))
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be true for a 200 whoami response")
	}
	if calls != 1 {
		t.Errorf("whoami called %d times, want 1", calls)
	}
}

func TestIsNotAvailable(t *testing.T) {
	var calls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s, err := New(testConfig(t, testutils.TestPublicKey().String(), srv))
	if err != nil {
		t.Fatal(err)
	}
	if s.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be false for a 500 whoami response")
	}
	if calls != 1 {
		t.Errorf("whoami called %d times, want 1", calls)
	}
}

func TestIsNotAvailableUnreachable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client := srv.Client()
	url := srv.URL
	srv.Close() // connection refused from here on

	cfg := testConfig(t, testutils.TestPublicKey().String(), nil)
	cfg.APIBaseURL = url
	cfg.HTTPClient = client
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be false when the API is unreachable")
	}
}

func TestCreateStamp(t *testing.T) {
	pubHex, privHex, key := newTestAPIKeys(t)
	cfg := testConfig(t, testutils.TestPublicKey().String(), nil)
	cfg.APIPublicKey = pubHex
	cfg.APIPrivateKey = privHex
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	message := "test message"
	stamp, err := s.createStamp(message)
	if err != nil {
		t.Fatal(err)
	}

	// Valid unpadded base64url.
	decoded, err := base64.RawURLEncoding.DecodeString(stamp)
	if err != nil {
		t.Fatalf("stamp is not valid base64url: %v", err)
	}

	// Valid JSON with the expected stamp shape.
	var payload map[string]string
	if err := json.Unmarshal(decoded, &payload); err != nil {
		t.Fatalf("stamp is not valid JSON: %v", err)
	}
	if payload["public_key"] != pubHex {
		t.Errorf("public_key = %q, want %q", payload["public_key"], pubHex)
	}
	if payload["scheme"] != stampScheme {
		t.Errorf("scheme = %q, want %q", payload["scheme"], stampScheme)
	}
	if payload["signature"] == "" {
		t.Error("missing signature")
	}

	// The signature must be DER-encoded P-256 ECDSA over SHA-256(message).
	der, err := hex.DecodeString(payload["signature"])
	if err != nil {
		t.Fatalf("signature is not valid hex: %v", err)
	}
	digest := sha256.Sum256([]byte(message))
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
		t.Error("stamp signature does not verify against the API public key")
	}
}

func TestCreateStampInvalidPrivateKey(t *testing.T) {
	cases := map[string]string{
		"not hex":      "zz-not-hex",
		"wrong length": hex.EncodeToString(bytes.Repeat([]byte{1}, 16)),
		"zero scalar":  hex.EncodeToString(make([]byte, 32)),
	}
	for name, privHex := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t, testutils.TestPublicKey().String(), nil)
			cfg.APIPrivateKey = privHex
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.createStamp("test")
			if err == nil {
				t.Fatal("expected error for invalid api private key")
			}
			if code, _ := core.CodeOf(err); code != core.CodeInvalidPrivateKey {
				t.Errorf("got %s, want INVALID_PRIVATE_KEY", code)
			}
		})
	}
}

func TestAssembleSignatureLeftPads(t *testing.T) {
	// Short components must be right-aligned (left-padded with zeros) to 32
	// bytes each.
	rBytes := bytes.Repeat([]byte{0xAB}, 31) // 31 bytes: one leading zero
	sBytes := bytes.Repeat([]byte{0xCD}, 30) // 30 bytes: two leading zeros

	sig, err := assembleSignature(hex.EncodeToString(rBytes), hex.EncodeToString(sBytes))
	if err != nil {
		t.Fatal(err)
	}
	var want solana.Signature
	copy(want[32-len(rBytes):32], rBytes)
	copy(want[64-len(sBytes):64], sBytes)
	if sig != want {
		t.Errorf("signature = %x, want %x", sig, want)
	}
	if sig[0] != 0 {
		t.Error("r component should be left-padded with a zero byte")
	}
	if sig[32] != 0 || sig[33] != 0 {
		t.Error("s component should be left-padded with two zero bytes")
	}
}

func TestHTTPSEnforcement(t *testing.T) {
	// The scheme check fires at construction, regardless of client (a custom
	// client must not be able to bypass HTTPS enforcement).
	for name, client := range map[string]*http.Client{
		"default client": nil,
		"custom client":  http.DefaultClient,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t, testutils.TestPublicKey().String(), nil)
			cfg.APIBaseURL = "http://127.0.0.1:1"
			cfg.HTTPClient = client
			_, err := New(cfg)
			if err == nil {
				t.Fatal("expected error for non-HTTPS base URL")
			}
			if code, _ := core.CodeOf(err); code != core.CodeConfigError {
				t.Errorf("got %s, want CONFIG_ERROR", code)
			}
		})
	}
}
