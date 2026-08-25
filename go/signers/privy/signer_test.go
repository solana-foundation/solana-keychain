package privy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

const (
	testAppID     = "test-app-id"
	testAppSecret = "test-app-secret"
	testWalletID  = "test-wallet-id"
	// base64("test-app-id:test-app-secret").
	testAuthHeader = "Basic dGVzdC1hcHAtaWQ6dGVzdC1hcHAtc2VjcmV0"

	walletPath = "/wallets/" + testWalletID
	rpcPath    = "/wallets/" + testWalletID + "/rpc"
)

func testConfig(srv *httptest.Server) Config {
	return Config{
		AppID:      testAppID,
		AppSecret:  testAppSecret,
		WalletID:   testWalletID,
		APIBaseURL: srv.URL,
		HTTPClient: srv.Client(),
	}
}

// addWalletRoute serves GET /wallets/{id} with the given address, asserting the
// Basic auth and privy-app-id headers.
func addWalletRoute(t *testing.T, mux *http.ServeMux, address string) {
	t.Helper()
	mux.HandleFunc("GET "+walletPath, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != testAuthHeader {
			t.Errorf("Authorization = %q, want %q", got, testAuthHeader)
		}
		if got := r.Header.Get("privy-app-id"); got != testAppID {
			t.Errorf("privy-app-id = %q, want %q", got, testAppID)
		}
		testutils.WriteJSON(w, http.StatusOK, map[string]any{
			"id":         testWalletID,
			"address":    address,
			"chain_type": "solana",
		})
	})
}

// addRPCRoute serves POST /wallets/{id}/rpc, asserting headers and the exact
// wire-format JSON body (method "signMessage", chain_type "solana", base64
// params), then delegates the response to respond with the decoded message
// bytes.
func addRPCRoute(t *testing.T, mux *http.ServeMux, respond func(w http.ResponseWriter, message []byte)) {
	t.Helper()
	mux.HandleFunc("POST "+rpcPath, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != testAuthHeader {
			t.Errorf("Authorization = %q, want %q", got, testAuthHeader)
		}
		if got := r.Header.Get("privy-app-id"); got != testAppID {
			t.Errorf("privy-app-id = %q, want %q", got, testAppID)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read signing request body: %v", err)
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("failed to decode signing request: %v", err)
		}
		params, _ := got["params"].(map[string]any)
		encoded, _ := params["message"].(string)
		want := map[string]any{
			"method":     "signMessage",
			"chain_type": "solana",
			"params": map[string]any{
				"message":  encoded,
				"encoding": "base64",
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("signing request body = %s, want exactly %s", body, mustJSON(t, want))
		}
		message, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Errorf("request message is not valid base64: %v", err)
		}
		respond(w, message)
	})
}

// addSignTransactionRPCRoute registers the wallet RPC route asserting the
// signTransaction request shape.
func addSignTransactionRPCRoute(t *testing.T, mux *http.ServeMux, respond func(w http.ResponseWriter, unsignedWire []byte)) {
	t.Helper()
	mux.HandleFunc("POST "+rpcPath, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read signing request body: %v", err)
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("failed to decode signing request: %v", err)
		}
		params, _ := got["params"].(map[string]any)
		encoded, _ := params["transaction"].(string)
		want := map[string]any{
			"method":     "signTransaction",
			"chain_type": "solana",
			"params": map[string]any{
				"transaction": encoded,
				"encoding":    "base64",
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("signing request body = %s, want exactly %s", body, mustJSON(t, want))
		}
		unsignedWire, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Errorf("request transaction is not valid base64: %v", err)
		}
		respond(w, unsignedWire)
	})
}

// signedTransactionResponse signs the unsigned wire transaction with priv and
// writes the signTransaction response body.
func signedTransactionResponse(t *testing.T, w http.ResponseWriter, priv ed25519.PrivateKey, unsignedWire []byte) {
	t.Helper()
	tx, err := solana.TransactionFromBytes(unsignedWire)
	if err != nil {
		t.Errorf("failed to decode unsigned wire transaction: %v", err)
		return
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Errorf("failed to serialize message: %v", err)
		return
	}
	tx.Signatures = []solana.Signature{testutils.SignWith(priv, msg)}
	signedWire, err := tx.MarshalBinary()
	if err != nil {
		t.Errorf("failed to serialize signed transaction: %v", err)
		return
	}
	testutils.WriteJSON(w, http.StatusOK, map[string]any{
		"method": "signTransaction",
		"data": map[string]any{
			"signed_transaction": base64.StdEncoding.EncodeToString(signedWire),
			"encoding":           "base64",
		},
	})
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %v: %v", v, err)
	}
	return string(b)
}

func signatureResponse(w http.ResponseWriter, sig solana.Signature) {
	testutils.WriteJSON(w, http.StatusOK, map[string]any{
		"method": "signMessage",
		"data": map[string]any{
			"signature": base64.StdEncoding.EncodeToString(sig[:]),
			"encoding":  "base64",
		},
	})
}

// newTestSigner starts an httptest server for mux and returns a ready signer.
func newTestSigner(t *testing.T, mux *http.ServeMux) *Signer {
	t.Helper()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	s, err := New(context.Background(), testConfig(srv))
	if err != nil {
		t.Fatalf("New: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	return s
}

func TestNewMissingConfig(t *testing.T) {
	cases := map[string]Config{
		"missing app id":     {AppSecret: testAppSecret, WalletID: testWalletID},
		"missing app secret": {AppID: testAppID, WalletID: testWalletID},
		"missing wallet id":  {AppID: testAppID, AppSecret: testAppSecret},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), cfg)
			testutils.AssertCode(t, err, core.CodeConfigError)
		})
	}
}

// TestNewFetchesPublicKey checks that New performs the wallet lookup with the
// exact auth headers and resolves the pubkey.
func TestNewFetchesPublicKey(t *testing.T) {
	want := testutils.TestPublicKey()
	mux := http.NewServeMux()
	addWalletRoute(t, mux, want.String())

	s := newTestSigner(t, mux)
	if s.Pubkey() != want {
		t.Errorf("Pubkey() = %s, want %s", s.Pubkey(), want)
	}
}

// TestNewUnauthorized checks that an unauthorized wallet fetch maps to
// CodeRemoteAPIError.
func TestNewUnauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+walletPath, func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "Unauthorized"})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	_, err := New(context.Background(), testConfig(srv))
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)
}

// TestNewInvalidPublicKey checks that an unparsable wallet address maps to
// CodeInvalidPublicKey.
func TestNewInvalidPublicKey(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+walletPath, func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{
			"id":         testWalletID,
			"address":    "not-a-valid-pubkey",
			"chain_type": "solana",
		})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	_, err := New(context.Background(), testConfig(srv))
	testutils.AssertCode(t, err, core.CodeInvalidPublicKey)
}

// TestNewRejectsNonSolanaWallet guards the wallet-shape checks: a wallet with
// the wrong chain_type or no address must fail with CodeRemoteAPIError before
// any public key parsing.
func TestNewRejectsNonSolanaWallet(t *testing.T) {
	cases := map[string]map[string]any{
		"wrong chain type": {
			"id":         testWalletID,
			"address":    "0x1111111111111111111111111111111111111111",
			"chain_type": "ethereum",
		},
		"missing address": {
			"id":         testWalletID,
			"chain_type": "solana",
		},
	}
	for name, wallet := range cases {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("GET "+walletPath, func(w http.ResponseWriter, _ *http.Request) {
				testutils.WriteJSON(w, http.StatusOK, wallet)
			})
			srv := httptest.NewTLSServer(mux)
			t.Cleanup(srv.Close)

			_, err := New(context.Background(), testConfig(srv))
			testutils.AssertCode(t, err, core.CodeRemoteAPIError)
		})
	}
}

// TestNewDefaultClientRejectsHTTP checks the HTTPS enforcement path: with no
// HTTPClient override, an http:// base URL must fail with CodeConfigError.
func TestNewDefaultClientRejectsHTTP(t *testing.T) {
	_, err := New(context.Background(), Config{
		AppID:      testAppID,
		AppSecret:  testAppSecret,
		WalletID:   testWalletID,
		APIBaseURL: "http://127.0.0.1:1",
	})
	testutils.AssertCode(t, err, core.CodeConfigError)
}

// TestStringDoesNotLeakSecrets guards the redacting String/GoString: no fmt verb
// may expose the app secret, the derived Basic auth header, or any authorization
// context material (private keys, precomputed signatures).
func TestStringDoesNotLeakSecrets(t *testing.T) {
	mux := http.NewServeMux()
	addWalletRoute(t, mux, testutils.TestPublicKey().String())
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	cfg := testConfig(srv)
	cfg.AuthorizationContext = &AuthorizationContext{
		AuthorizationPrivateKeys: []string{"wallet-auth:" + testP256PKCS8Base64},
		Signatures:               []string{"precomputed-authorization-signature"},
	}
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v (detail: %s)", err, testutils.Detail(t, err))
	}

	for _, rendered := range []string{
		fmt.Sprintf("%v", s),
		fmt.Sprintf("%+v", s),
		fmt.Sprintf("%s", s), //nolint:staticcheck // deliberately exercising the %s verb path
		fmt.Sprintf("%#v", s),
		fmt.Sprintf("%v", *s),
		fmt.Sprintf("%+v", *s),
		fmt.Sprintf("%s", *s), //nolint:staticcheck // deliberately exercising the %s verb path
		fmt.Sprintf("%#v", *s),
	} {
		if strings.Contains(rendered, testAppSecret) || strings.Contains(rendered, s.authHeader()) {
			t.Errorf("rendered signer leaks secrets: %s", rendered)
		}
		if strings.Contains(rendered, testP256PKCS8Base64) ||
			strings.Contains(rendered, "precomputed-authorization-signature") {
			t.Errorf("rendered signer leaks authorization context material: %s", rendered)
		}
		if !strings.Contains(rendered, "privy.Signer") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
	}
}

// TestSignMessage checks that the remote returns a real signature over the
// transaction message bytes and the signer surfaces it.
func TestSignMessage(t *testing.T) {
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
	want := testutils.SignWith(priv, msg)

	mux := http.NewServeMux()
	addWalletRoute(t, mux, pub.String())
	addRPCRoute(t, mux, func(w http.ResponseWriter, message []byte) {
		if string(message) != string(msg) {
			t.Errorf("remote received message %x, want %x", message, msg)
		}
		signatureResponse(w, want)
	})

	s := newTestSigner(t, mux)
	sig, err := s.SignMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("SignMessage: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if sig != want {
		t.Errorf("signature = %s, want %s", sig, want)
	}
	if !core.VerifyEd25519(pub, msg, sig) {
		t.Error("signature should verify against the signer's pubkey")
	}
}

// TestSignMessageAuthorizationContextHeaders checks that with a precomputed
// authorization signature and expiry omitted, the RPC request carries the
// privy-authorization-signature header, no privy-request-expiry header, and the
// exact wire-format body.
func TestSignMessageAuthorizationContextHeaders(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()
	message := []byte{1, 2, 3, 4}
	want := testutils.SignWith(priv, message)

	mux := http.NewServeMux()
	addWalletRoute(t, mux, pub.String())
	mux.HandleFunc("POST "+rpcPath, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("privy-authorization-signature"); got != "authorization-signature" {
			t.Errorf("privy-authorization-signature = %q, want %q", got, "authorization-signature")
		}
		if got := r.Header.Get("privy-request-expiry"); got != "" {
			t.Errorf("privy-request-expiry = %q, want omitted", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read signing request body: %v", err)
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("failed to decode signing request: %v", err)
		}
		wantBody := map[string]any{
			"method":     "signMessage",
			"chain_type": "solana",
			"params": map[string]any{
				"message":  "AQIDBA==",
				"encoding": "base64",
			},
		}
		if !reflect.DeepEqual(got, wantBody) {
			t.Errorf("signing request body = %s, want exactly %s", body, mustJSON(t, wantBody))
		}
		signatureResponse(w, want)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	cfg := testConfig(srv)
	cfg.AuthorizationContext = &AuthorizationContext{Signatures: []string{"authorization-signature"}}
	cfg.OmitAuthorizationRequestExpiry = true

	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	sig, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatalf("SignMessage: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if sig != want {
		t.Errorf("signature = %s, want %s", sig, want)
	}
}

// TestSignMessageAuthorizationRequestExpiry pins the default-expiry wiring: the
// privy-request-expiry header lands inside the 15-minute window and the exact
// canonical payload handed to sign fns embeds the same expiry, app ID, method,
// URL, and body the server received.
func TestSignMessageAuthorizationRequestExpiry(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()
	message := []byte{1, 2, 3, 4}

	var mu sync.Mutex
	var payloads, expiries []string

	mux := http.NewServeMux()
	addWalletRoute(t, mux, pub.String())
	mux.HandleFunc("POST "+rpcPath, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("privy-authorization-signature"); got != "sign-fn-signature" {
			t.Errorf("privy-authorization-signature = %q, want %q", got, "sign-fn-signature")
		}
		mu.Lock()
		expiries = append(expiries, r.Header.Get("privy-request-expiry"))
		mu.Unlock()
		signatureResponse(w, testutils.SignWith(priv, message))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	cfg := testConfig(srv)
	cfg.AuthorizationContext = &AuthorizationContext{
		SignFns: []AuthorizationSignFn{func(payload []byte) (string, error) {
			mu.Lock()
			payloads = append(payloads, string(payload))
			mu.Unlock()
			return "sign-fn-signature", nil
		}},
	}

	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	before := time.Now().UnixMilli()
	if _, err := s.SignMessage(context.Background(), message); err != nil {
		t.Fatalf("SignMessage: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	after := time.Now().UnixMilli()

	if len(payloads) != 1 || len(expiries) != 1 {
		t.Fatalf("got %d payloads and %d expiries, want 1 each", len(payloads), len(expiries))
	}
	expiry, err := strconv.ParseInt(expiries[0], 10, 64)
	if err != nil {
		t.Fatalf("privy-request-expiry %q is not an integer: %v", expiries[0], err)
	}
	window := int64(DefaultAuthorizationRequestExpiryMs)
	if expiry < before+window || expiry > after+window {
		t.Errorf("expiry %d outside [%d, %d]", expiry, before+window, after+window)
	}

	wantPayload := `{"body":{"chain_type":"solana","method":"signMessage",` +
		`"params":{"encoding":"base64","message":"AQIDBA=="}},` +
		`"headers":{"privy-app-id":"` + testAppID + `","privy-request-expiry":"` + expiries[0] + `"},` +
		`"method":"POST","url":"` + srv.URL + rpcPath + `","version":1}`
	if payloads[0] != wantPayload {
		t.Errorf("canonical payload = %s, want %s", payloads[0], wantPayload)
	}
}

// TestSignMessageEmptyAuthorizationContext checks that a context with no keys,
// signatures, or sign fns fails with CodeConfigError before any RPC request is
// sent (no RPC route is registered, so a sent request would surface as
// CodeRemoteAPIError instead).
func TestSignMessageEmptyAuthorizationContext(t *testing.T) {
	mux := http.NewServeMux()
	addWalletRoute(t, mux, testutils.TestPublicKey().String())
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	cfg := testConfig(srv)
	cfg.AuthorizationContext = &AuthorizationContext{}

	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	_, err = s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeConfigError)
}

// TestSignMessageVerificationFailure checks the case where the remote signs
// with a different key than the wallet's advertised pubkey.
func TestSignMessageVerificationFailure(t *testing.T) {
	signingPriv := testutils.TestPrivateKey()
	_, differentPub := testutils.KeyFromSeed(7)
	msg := []byte("test message")

	mux := http.NewServeMux()
	addWalletRoute(t, mux, differentPub.String())
	addRPCRoute(t, mux, func(w http.ResponseWriter, _ []byte) {
		signatureResponse(w, testutils.SignWith(signingPriv, msg))
	})

	s := newTestSigner(t, mux)
	_, err := s.SignMessage(context.Background(), msg)
	testutils.AssertCode(t, err, core.CodeSigningFailed)
}

// TestSignMessageInvalidBase64Signature checks that a non-base64 signature in
// the response maps to CodeSerializationError.
func TestSignMessageInvalidBase64Signature(t *testing.T) {
	mux := http.NewServeMux()
	addWalletRoute(t, mux, testutils.TestPublicKey().String())
	addRPCRoute(t, mux, func(w http.ResponseWriter, _ []byte) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{
			"method": "signMessage",
			"data": map[string]any{
				"signature": "not-base64###",
				"encoding":  "base64",
			},
		})
	})

	s := newTestSigner(t, mux)
	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeSerializationError)
}

// TestSignMessageWrongLengthSignature checks that a valid-base64 payload that
// is not 64 bytes maps to CodeSigningFailed.
func TestSignMessageWrongLengthSignature(t *testing.T) {
	mux := http.NewServeMux()
	addWalletRoute(t, mux, testutils.TestPublicKey().String())
	addRPCRoute(t, mux, func(w http.ResponseWriter, _ []byte) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{
			"method": "signMessage",
			"data": map[string]any{
				"signature": base64.StdEncoding.EncodeToString([]byte("short")),
				"encoding":  "base64",
			},
		})
	})

	s := newTestSigner(t, mux)
	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeSigningFailed)
}

// TestSignMessageUnauthorized checks that an unauthorized signing request maps
// to CodeRemoteAPIError.
func TestSignMessageUnauthorized(t *testing.T) {
	mux := http.NewServeMux()
	addWalletRoute(t, mux, testutils.TestPublicKey().String())
	mux.HandleFunc("POST "+rpcPath, func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "Unauthorized"})
	})

	s := newTestSigner(t, mux)
	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)
}

// TestSignMessageRemoteErrorBodyDiscarded checks that non-2xx response bodies
// never reach the error detail: only the status code does.
func TestSignMessageRemoteErrorBodyDiscarded(t *testing.T) {
	mux := http.NewServeMux()
	addWalletRoute(t, mux, testutils.TestPublicKey().String())
	mux.HandleFunc("POST "+rpcPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("bad\x00\x01thing\n\n   with   \x1b[31mcontrol\x7f chars"))
	})

	s := newTestSigner(t, mux)
	_, err := s.SignMessage(context.Background(), []byte("test"))
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)

	detail := testutils.Detail(t, err)
	if !strings.Contains(detail, "API error 500") {
		t.Errorf("detail %q should mention the status", detail)
	}
	// The response body is deliberately discarded on non-2xx; only the status
	// code may appear in the detail.
	if strings.Contains(detail, "bad thing") {
		t.Errorf("detail %q should not embed the remote response body", detail)
	}
	for _, r := range detail {
		if r < 0x20 || r == 0x7f {
			t.Errorf("detail %q contains unsanitized control character %q", detail, r)
		}
	}
}

// TestSignTransaction checks that signing a transaction inserts the signature
// at position 0 and yields a complete encoded transaction.
func TestSignTransactionRejectsSignatureOverDifferentBytes(t *testing.T) {
	priv := testutils.TestPrivateKey()
	pub := testutils.TestPublicKey()
	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	addWalletRoute(t, mux, pub.String())
	addSignTransactionRPCRoute(t, mux, func(w http.ResponseWriter, unsignedWire []byte) {
		other, err := solana.TransactionFromBytes(unsignedWire)
		if err != nil {
			t.Errorf("failed to decode unsigned wire transaction: %v", err)
			return
		}
		other.Message.RecentBlockhash = solana.Hash{1}
		otherWire, err := other.MarshalBinary()
		if err != nil {
			t.Errorf("failed to serialize perturbed transaction: %v", err)
			return
		}
		signedTransactionResponse(t, w, priv, otherWire)
	})

	s := newTestSigner(t, mux)
	_, err = s.SignTransaction(context.Background(), tx)
	if err == nil {
		t.Fatal("expected a signature over different bytes to be rejected")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

func TestSignTransactionRejectsMissingSignedTransaction(t *testing.T) {
	pub := testutils.TestPublicKey()
	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	addWalletRoute(t, mux, pub.String())
	addSignTransactionRPCRoute(t, mux, func(w http.ResponseWriter, _ []byte) {
		testutils.WriteJSON(w, http.StatusOK, map[string]any{
			"method": "signTransaction",
			"data":   map[string]any{},
		})
	})

	s := newTestSigner(t, mux)
	_, err = s.SignTransaction(context.Background(), tx)
	if err == nil {
		t.Fatal("expected error for a response without signed_transaction")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSerializationError {
		t.Errorf("got %s, want SERIALIZATION_ERROR", code)
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
	want := testutils.SignWith(priv, msg)

	mux := http.NewServeMux()
	addWalletRoute(t, mux, pub.String())
	addSignTransactionRPCRoute(t, mux, func(w http.ResponseWriter, unsignedWire []byte) {
		signedTransactionResponse(t, w, priv, unsignedWire)
	})

	s := newTestSigner(t, mux)
	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.Signature != want {
		t.Errorf("signature = %s, want %s", res.Signature, want)
	}
	if !res.IsComplete() {
		t.Error("single-signer transaction should be Complete")
	}
	if res.EncodedTransaction == "" {
		t.Error("encoded transaction should not be empty")
	}
	decoded, err := solana.TransactionFromBase64(res.EncodedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Signatures[0] != want {
		t.Error("encoded transaction signature mismatch at position 0")
	}
	if !core.VerifyEd25519(pub, msg, res.Signature) {
		t.Error("transaction signature should verify against the message bytes")
	}
}

// TestIsAvailable checks that availability is true while the wallet still
// resolves to the same pubkey, and false on a changed address or a remote
// failure.
func TestIsAvailable(t *testing.T) {
	pub := testutils.TestPublicKey()

	var mu sync.Mutex
	address := pub.String()
	status := http.StatusOK

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+walletPath, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		addr, code := address, status
		mu.Unlock()
		if code != http.StatusOK {
			testutils.WriteJSON(w, code, map[string]any{"error": "Unauthorized"})
			return
		}
		testutils.WriteJSON(w, code, map[string]any{
			"id":         testWalletID,
			"address":    addr,
			"chain_type": "solana",
		})
	})

	s := newTestSigner(t, mux)

	t.Run("available", func(t *testing.T) {
		if !s.IsAvailable(context.Background()) {
			t.Error("signer should be available while the wallet resolves to the same pubkey")
		}
	})

	t.Run("pubkey mismatch", func(t *testing.T) {
		mu.Lock()
		_, otherPub := testutils.KeyFromSeed(7)
		address = otherPub.String()
		mu.Unlock()
		if s.IsAvailable(context.Background()) {
			t.Error("signer should not be available when the wallet resolves to a different pubkey")
		}
	})

	t.Run("remote failure", func(t *testing.T) {
		mu.Lock()
		status = http.StatusUnauthorized
		mu.Unlock()
		if s.IsAvailable(context.Background()) {
			t.Error("signer should not be available when the remote API fails")
		}
	})
}
