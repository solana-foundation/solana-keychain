package utila

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/golang-jwt/jwt/v5"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

const (
	testEmail      = "service-account@vault.utilaserviceaccount.io"
	testVaultID    = "vault-test"
	testWalletID   = "wallet-test"
	testNetwork    = "networks/solana-devnet"
	testWalletPath = "/v2/vaults/vault-test/wallets/wallet-test"
)

// testRSAKey is the PKCS#8 RSA private key test fixture.
const testRSAKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDKKw7fHhfK3/Ts
rAqsNCrDsjmyBTHx/AUCOTM+tZph2ZOyDSH9nZO4JkzLrW6Vfk7EZvlP3QjLiXEG
m9qQgAh9sXgp07GicWU5omSILTMdd18yR6aIXVw/YzgjD7EVLRQU6YHc3BYgR8P8
PBbJcxzYrrUDSGEXX2b44cZO72RxIPM+yeY3ZXiztgFQSpfEIKX488/k/PgUHMHK
/04VoL/jiQa5dOs44CmHHT6MbBT1Sb/VR0G1hHtfMSIQCtdvzt+VBZhg7sxm50h/
cT+n0UVOBwEp2IY2x4lzlwOdptZl7P3D1+A2rAbalXg5WO+LVEjx5ym++XbCGyvU
rlH+ILOPAgMBAAECggEAXio3F5J/N4YgITqzD+mOf69cc0A7NsCRnqsA5PUWbvw2
cIjwa55BZ1UjkPz7lJML4iwqdNn51j/yzsa6Q3L3QYBvfV/2jbiuku1CUTFobRGk
XBmGhl6h8H5o79/HthrUjzcCP1qdzbRPo4Vjgbpl1cFuW5STcJ0Fq+gRg8O6b3w7
A2843mcF9EA9ZFjXpn+VtpzLe4nHVRZFYXvXSlfdYc6WQbThnLLiLQYsVMqhYQAU
I4c9hfgasfgZ6iCV5hMK2ZPX45+/OVQzjh4+I8zlvNWp2cKNoEhMHU2G/In11yBF
wHGRuvbwx9Wc4Okqq+GvfTO0jCAinAQQu8C+eIcNcQKBgQDo9dzw2cNsJmaUvaL5
I7gEtbPdr+CTgVjGoVUIlGeI0OBHt1DJEwczS2tycScE9SUDLdmegYA8ubHsAs/6
PFEJ+779h9/IDzL3Fe9Zp1fiQgWOKF1uCS7+b8QwFMhh2u0OLWmI1rdFmqX2KCPf
AfD/Pvp6bgapXTN1EoB3LQ/4PwKBgQDeKZeJMk9CZzWFe+m5x2yzJBK62ZvKzyjZ
Y3IeK75V0xG+Y7ZAb0zTXPkgBpBiQOqdFRgt6bp/S/6Tq/OXfeV9xVURSz4zRtCR
lRoONL8ZSl0h4VptEjXrYfBnH2j4gtjhnTATJZBp0rYrExbz0jVbQtRzPLs+k3+p
TuZA8+XwsQKBgCocn8buJpR7UJncugQ9f7tiOVR+waMIg8rMSTnW0ex6jcCJE9J1
XRzZql+ysrIDuqAbfrZXhJ31l4Mpcv0yQBgE6R6dnEdm7/iYf37+cDWXZ7et9k24
3UTjYVyrtRlzYNzqOqSg49pyPUQFN47NpAoQEWlmUE/3aCDmqlBg1f0zAoGAamv+
HUiuUx7hspnTMp1nYsEq/7ryOErYRJqwtec6fB5p54wYZ/FpGe71n/PFAmwadzj9
pjDKl+QthUvfmnhCkOcQgwJKP4Hys2p7WsbFrDXFO0+aY5lPnvwBj0SqojD798e2
mdVqwmafwS6Z1h6iVJ9E6hbzk1xQ0SfsgLzVL2ECgYBN6fJ99og4fkp4iA5C31TB
UKlH64yqwxFu4vuVMqBOpGPkdsLNGhE/vpdP7yYxC/MP+v8ow/sCa40Ely20Yqqa
znT9Ik5JV4eRXyRG9iwllKvcrmczFDIuxFmXPff4G9nmyB9fLQfSM0gD+yDR05Hx
p6B5CCtpBPgD01Vm+bT/JQ==
-----END PRIVATE KEY-----`

func parsedTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := parseSigningKey(testRSAKey)
	if err != nil {
		t.Fatalf("parseSigningKey: %v", err)
	}
	return key
}

func walletJSON(address string) string {
	return fmt.Sprintf(`{"wallet":{"solanaDetails":{"address":%q}}}`, address)
}

// walletHandler serves the wallet fetch that New performs, checking the
// bearer authorization the signer attaches to every request.
func walletHandler(t *testing.T, address string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("authorization = %q, want a Bearer token", got)
		}
		testutils.WriteRawJSON(w, http.StatusOK, walletJSON(address))
	}
}

func baseConfig(srv *httptest.Server) Config {
	return Config{
		ServiceAccountEmail:         testEmail,
		ServiceAccountPrivateKeyPEM: testRSAKey,
		VaultID:                     testVaultID,
		WalletID:                    testWalletID,
		Network:                     testNetwork,
		APIBaseURL:                  srv.URL,
		PollInterval:                time.Millisecond,
		MaxPollAttempts:             2,
		HTTPClient:                  srv.Client(),
	}
}

func newTestSigner(t *testing.T, cfg Config) *Signer {
	t.Helper()
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	return s
}

// newDirectSigner constructs a Signer directly, skipping the wallet fetch New
// performs.
func newDirectSigner(t *testing.T, srv *httptest.Server, pubkey solana.PublicKey) *Signer {
	t.Helper()
	return &Signer{
		serviceAccountEmail: testEmail,
		signingKey:          parsedTestKey(t),
		vaultID:             testVaultID,
		walletID:            testWalletID,
		network:             testNetwork,
		apiBaseURL:          strings.TrimRight(srv.URL, "/"),
		client:              srv.Client(),
		pubkey:              pubkey,
		pollInterval:        time.Millisecond,
		maxPollAttempts:     2,
		designatedSigners:   []string{"users/" + testEmail},
	}
}

// signedTransactionPayload builds a deterministic unsigned transaction for
// priv's pubkey, its base64 wire form (with a zero placeholder signature), the
// signed wire form, and the signature.
func signedTransactionPayload(t *testing.T, priv ed25519.PrivateKey) (unsigned *solana.Transaction, unsignedRaw, signedRaw string, sig solana.Signature) {
	t.Helper()
	pub := testutils.PubkeyOf(priv)

	unsigned, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	unsignedBytes, err := unsigned.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	unsignedRaw = base64.StdEncoding.EncodeToString(unsignedBytes)

	signedTx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := signedTx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sig = testutils.SignWith(priv, msg)
	if err := core.AddSignature(signedTx, pub, sig); err != nil {
		t.Fatal(err)
	}
	signedBytes, err := signedTx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	signedRaw = base64.StdEncoding.EncodeToString(signedBytes)
	return unsigned, unsignedRaw, signedRaw, sig
}

// initiateHandler asserts the exact transactions:initiate request body and
// replies with responseBody.
func initiateHandler(t *testing.T, unsignedRaw string, status int, responseBody string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("authorization = %q, want a Bearer token", got)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %s, want application/json", ct)
		}
		raw, _ := io.ReadAll(r.Body)
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("decode initiate request: %v", err)
		}
		want := map[string]any{
			"details": map[string]any{
				"solanaSerializedTransaction": map[string]any{
					"network":             testNetwork,
					"rawTransaction":      unsignedRaw,
					"publish":             false,
					"replaceBlockhash":    false,
					"tryReplaceBlockhash": false,
				},
			},
			"designatedSigners": []any{"users/" + testEmail},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("initiate request body = %v, want %v", got, want)
		}
		testutils.WriteRawJSON(w, status, responseBody)
	}
}

func transactionJSON(name string, state transactionState) string {
	return fmt.Sprintf(`{"transaction":{"name":%q,"state":%q}}`, name, state)
}

func signedTransactionJSON(name, signedRaw string) string {
	return fmt.Sprintf(`{"transaction":{"name":%q,"state":"SIGNED","solanaTransaction":{"rawTransaction":%q}}}`,
		name, signedRaw)
}

// TestNewValidatesConfig covers every required config field plus the negative
// poll settings and an unparseable key.
func TestNewValidatesConfig(t *testing.T) {
	cases := map[string]struct {
		mutate   func(*Config)
		wantCode core.Code
	}{
		"empty service_account_email": {func(c *Config) { c.ServiceAccountEmail = "" }, core.CodeConfigError},
		"whitespace email":            {func(c *Config) { c.ServiceAccountEmail = "  \n " }, core.CodeConfigError},
		"empty private key pem":       {func(c *Config) { c.ServiceAccountPrivateKeyPEM = "" }, core.CodeConfigError},
		"empty vault_id":              {func(c *Config) { c.VaultID = "" }, core.CodeConfigError},
		"empty wallet_id":             {func(c *Config) { c.WalletID = "" }, core.CodeConfigError},
		"empty network":               {func(c *Config) { c.Network = "" }, core.CodeConfigError},
		"negative poll interval":      {func(c *Config) { c.PollInterval = -time.Second }, core.CodeConfigError},
		"negative max poll attempts":  {func(c *Config) { c.MaxPollAttempts = -1 }, core.CodeConfigError},
		"unparseable rsa private key": {func(c *Config) { c.ServiceAccountPrivateKeyPEM = "not-a-pem" }, core.CodeInvalidPrivateKey},
		"ed25519 pem instead of rsa": {func(c *Config) {
			c.ServiceAccountPrivateKeyPEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----"
		}, core.CodeInvalidPrivateKey},
		"api_base_url not a base url": {func(c *Config) { c.APIBaseURL = "https:opaque" }, core.CodeConfigError},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := Config{
				ServiceAccountEmail:         testEmail,
				ServiceAccountPrivateKeyPEM: testRSAKey,
				VaultID:                     testVaultID,
				WalletID:                    testWalletID,
				Network:                     testNetwork,
				APIBaseURL:                  "https://127.0.0.1:1",
			}
			tc.mutate(&cfg)
			_, err := New(context.Background(), cfg)
			testutils.AssertCode(t, err, tc.wantCode)
		})
	}
}

// TestNewRejectsInsecureAPIBaseURL verifies an http:// base URL is a config
// error, even with a custom HTTP client.
func TestNewRejectsInsecureAPIBaseURL(t *testing.T) {
	for name, client := range map[string]*http.Client{
		"default client": nil,
		"custom client":  {},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), Config{
				ServiceAccountEmail:         testEmail,
				ServiceAccountPrivateKeyPEM: testRSAKey,
				VaultID:                     testVaultID,
				WalletID:                    testWalletID,
				Network:                     testNetwork,
				APIBaseURL:                  "http://api.utila.test",
				HTTPClient:                  client,
			})
			testutils.AssertCode(t, err, core.CodeConfigError)
			testutils.AssertDetailContains(t, err, "api_base_url must use HTTPS")
		})
	}
}

// TestCreateAccessTokenClaims verifies the JWT payload carries sub = service
// account email, aud = the fixed Utila audience, and a numeric exp.
func TestCreateAccessTokenClaims(t *testing.T) {
	token, err := createAccessToken(testEmail, parsedTestKey(t))
	if err != nil {
		t.Fatalf("createAccessToken: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d segments, want 3", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode jwt header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parse jwt header: %v", err)
	}
	if header["alg"] != "RS256" {
		t.Errorf("alg = %v, want RS256", header["alg"])
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode jwt payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parse jwt payload: %v", err)
	}
	if payload["sub"] != testEmail {
		t.Errorf("sub = %v, want %s", payload["sub"], testEmail)
	}
	if payload["aud"] != utilaAPIAudience {
		t.Errorf("aud = %v, want %s", payload["aud"], utilaAPIAudience)
	}
	exp, ok := payload["exp"].(float64)
	if !ok {
		t.Fatalf("exp = %v, want a number", payload["exp"])
	}
	if int64(exp) <= time.Now().Unix() {
		t.Errorf("exp = %d, want it in the future", int64(exp))
	}

	// The token must verify under the RSA public key it claims to be signed with.
	if _, err := jwt.Parse(token, func(*jwt.Token) (any, error) {
		return &parsedTestKey(t).PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(utilaAPIAudience)); err != nil {
		t.Errorf("jwt does not verify: %v", err)
	}
}

// TestNewAcceptsEscapedNewlinePEM verifies a key delivered with literal "\n"
// sequences (or CRLF line endings) parses.
func TestNewAcceptsEscapedNewlinePEM(t *testing.T) {
	for name, pem := range map[string]string{
		"escaped newlines": strings.ReplaceAll(testRSAKey, "\n", `\n`),
		"crlf endings":     strings.ReplaceAll(testRSAKey, "\n", "\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testutils.TestPublicKey().String()))
			srv := testutils.StartTLSServer(t, mux)

			cfg := baseConfig(srv)
			cfg.ServiceAccountPrivateKeyPEM = pem
			newTestSigner(t, cfg)
		})
	}
}

// TestNewFetchesSolanaAddress verifies New adopts the wallet's Solana address
// as the signer pubkey.
func TestNewFetchesSolanaAddress(t *testing.T) {
	want := testutils.TestPublicKey()
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, want.String()))
	srv := testutils.StartTLSServer(t, mux)

	s := newTestSigner(t, baseConfig(srv))
	if s.Pubkey() != want {
		t.Errorf("pubkey = %s, want %s", s.Pubkey(), want)
	}
}

// TestNewEncodesResourceIDs verifies vault and wallet ids containing '/' or
// spaces stay inside a single encoded path segment.
func TestNewEncodesResourceIDs(t *testing.T) {
	want := testutils.TestPublicKey()
	const wantPath = "/v2/vaults/vault%2Fwith%20space/wallets/wallet%2Fwith%20space"

	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != wantPath {
			t.Errorf("request path = %s, want %s", got, wantPath)
		}
		testutils.WriteRawJSON(w, http.StatusOK, walletJSON(want.String()))
	}))

	cfg := baseConfig(srv)
	cfg.VaultID = "vault/with space"
	cfg.WalletID = "wallet/with space"
	s := newTestSigner(t, cfg)
	if s.Pubkey() != want {
		t.Errorf("pubkey = %s, want %s", s.Pubkey(), want)
	}
}

// TestNewTrimsResourceIdentifiers verifies the vault_id "vaults/" prefix and a
// full wallet resource name are reduced to bare ids before hitting the wire.
func TestNewTrimsResourceIdentifiers(t *testing.T) {
	want := testutils.TestPublicKey()
	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != testWalletPath {
			t.Errorf("request path = %s, want %s", got, testWalletPath)
		}
		testutils.WriteRawJSON(w, http.StatusOK, walletJSON(want.String()))
	}))

	cfg := baseConfig(srv)
	cfg.VaultID = "vaults/" + testVaultID
	cfg.WalletID = "vaults/" + testVaultID + "/wallets/" + testWalletID
	newTestSigner(t, cfg)
}

// TestInitiateTransactionEncodesVaultID verifies the vault id is
// percent-encoded in the transactions:initiate path.
func TestInitiateTransactionEncodesVaultID(t *testing.T) {
	const wantPath = "/v2/vaults/vault%2Fwith%20space/transactions:initiate"

	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.URL.EscapedPath(); got != wantPath {
			t.Errorf("request path = %s, want %s", got, wantPath)
		}
		testutils.WriteRawJSON(w, http.StatusOK,
			transactionJSON("vaults/vault/with space/transactions/tx-1", "AWAITING_SIGNATURE"))
	}))

	s := newDirectSigner(t, srv, solana.PublicKey{})
	s.vaultID = "vault/with space"

	transaction, err := s.initiateTransaction(context.Background(), "raw-transaction")
	if err != nil {
		t.Fatalf("initiateTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if transaction.Name != "vaults/vault/with space/transactions/tx-1" {
		t.Errorf("transaction name = %q, want %q", transaction.Name, "vaults/vault/with space/transactions/tx-1")
	}
}

// TestSignMessageNotSupported verifies Utila intentionally does not support
// raw message signing for Solana wallets.
func TestSignMessageNotSupported(t *testing.T) {
	s := &Signer{pubkey: testutils.TestPublicKey()}
	_, err := s.SignMessage(context.Background(), []byte("hello"))
	testutils.AssertCode(t, err, core.CodeSigningFailed)
	testutils.AssertDetailContains(t, err, "not supported")
}

// TestSignTransactionPostsPayloadAndPollsSignedResponse verifies the exact
// initiate payload is posted, the AWAITING_SIGNATURE transaction is polled
// (FULL view), and the signature from the returned wire transaction is
// installed on the local transaction.
func TestSignTransactionPostsPayloadAndPollsSignedResponse(t *testing.T) {
	priv := testutils.TestPrivateKey()
	transaction, unsignedRaw, signedRaw, expectedSignature := signedTransactionPayload(t, priv)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v2/vaults/vault-test/transactions:initiate",
		initiateHandler(t, unsignedRaw, http.StatusOK,
			transactionJSON("vaults/vault-test/transactions/tx-1", "AWAITING_SIGNATURE")))
	mux.HandleFunc("GET /v2/vaults/vault-test/transactions/tx-1", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("view"); got != "FULL" {
			t.Errorf("view query param = %q, want FULL", got)
		}
		testutils.WriteRawJSON(w, http.StatusOK, signedTransactionJSON("vaults/vault-test/transactions/tx-1", signedRaw))
	})
	srv := testutils.StartTLSServer(t, mux)

	s := newDirectSigner(t, srv, testutils.PubkeyOf(priv))
	res, err := s.SignTransaction(context.Background(), transaction)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.Signature != expectedSignature {
		t.Errorf("signature = %s, want %s", res.Signature, expectedSignature)
	}
	if transaction.Signatures[0] != expectedSignature {
		t.Error("transaction signature mismatch at position 0")
	}
	if !res.IsComplete() {
		t.Error("single-signer transaction should be Complete")
	}
	decoded, err := solana.TransactionFromBase64(res.EncodedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Signatures[0] != expectedSignature {
		t.Error("encoded transaction signature mismatch at position 0")
	}
}

// TestSignTransactionTerminalFailure verifies a terminal-failure state fails
// signing.
func TestSignTransactionTerminalFailure(t *testing.T) {
	priv := testutils.TestPrivateKey()
	transaction, unsignedRaw, _, _ := signedTransactionPayload(t, priv)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v2/vaults/vault-test/transactions:initiate",
		initiateHandler(t, unsignedRaw, http.StatusOK,
			transactionJSON("vaults/vault-test/transactions/tx-1", "FAILED")))
	srv := testutils.StartTLSServer(t, mux)

	s := newDirectSigner(t, srv, testutils.PubkeyOf(priv))
	_, err := s.SignTransaction(context.Background(), transaction)
	testutils.AssertCode(t, err, core.CodeSigningFailed)
	testutils.AssertDetailContains(t, err, "terminal state FAILED")
}

// TestSignTransactionTimeout verifies a transaction that never leaves
// AWAITING_SIGNATURE exhausts the poll budget.
func TestSignTransactionTimeout(t *testing.T) {
	priv := testutils.TestPrivateKey()
	transaction, unsignedRaw, _, _ := signedTransactionPayload(t, priv)
	pending := transactionJSON("vaults/vault-test/transactions/tx-1", "AWAITING_SIGNATURE")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v2/vaults/vault-test/transactions:initiate",
		initiateHandler(t, unsignedRaw, http.StatusOK, pending))
	mux.HandleFunc("GET /v2/vaults/vault-test/transactions/tx-1", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusOK, pending)
	})
	srv := testutils.StartTLSServer(t, mux)

	s := newDirectSigner(t, srv, testutils.PubkeyOf(priv))
	_, err := s.SignTransaction(context.Background(), transaction)
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)
	testutils.AssertDetailContains(t, err, "polling timed out after 2 attempts")
}

// TestSignTransactionRejectsMismatchedReturnedTransaction verifies a signed
// transaction whose message bytes differ from the requested ones is rejected.
func TestSignTransactionRejectsMismatchedReturnedTransaction(t *testing.T) {
	priv := testutils.TestPrivateKey()
	transaction, unsignedRaw, _, _ := signedTransactionPayload(t, priv)

	otherPriv := ed25519.NewKeyFromSeed(func() []byte {
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = 7
		}
		return seed
	}())
	_, _, mismatchedRaw, _ := signedTransactionPayload(t, otherPriv)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v2/vaults/vault-test/transactions:initiate",
		initiateHandler(t, unsignedRaw, http.StatusOK,
			signedTransactionJSON("vaults/vault-test/transactions/tx-1", mismatchedRaw)))
	srv := testutils.StartTLSServer(t, mux)

	s := newDirectSigner(t, srv, testutils.PubkeyOf(priv))
	_, err := s.SignTransaction(context.Background(), transaction)
	testutils.AssertCode(t, err, core.CodeSigningFailed)
	testutils.AssertDetailContains(t, err, "different message bytes")
}

// TestSignTransactionMissingRawTransaction verifies a SIGNED response carrying
// no solanaTransaction.rawTransaction fails signing.
func TestSignTransactionMissingRawTransaction(t *testing.T) {
	priv := testutils.TestPrivateKey()
	transaction, unsignedRaw, _, _ := signedTransactionPayload(t, priv)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v2/vaults/vault-test/transactions:initiate",
		initiateHandler(t, unsignedRaw, http.StatusOK,
			transactionJSON("vaults/vault-test/transactions/tx-1", "SIGNED")))
	srv := testutils.StartTLSServer(t, mux)

	s := newDirectSigner(t, srv, testutils.PubkeyOf(priv))
	_, err := s.SignTransaction(context.Background(), transaction)
	testutils.AssertCode(t, err, core.CodeSigningFailed)
	testutils.AssertDetailContains(t, err, "missing solanaTransaction.rawTransaction")
}

// TestNewWalletErrorPaths covers the wallet fetch error mapping: non-2xx
// statuses, undecodable bodies, and wallet payloads without a usable Solana
// address.
func TestNewWalletErrorPaths(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantCode core.Code
		wantIn   string
	}{
		{
			name:     "remote api error",
			status:   http.StatusUnauthorized,
			body:     `{"message":"unauthorized"}`,
			wantCode: core.CodeRemoteAPIError,
			wantIn:   "Utila API fetch_wallet error 401",
		},
		{
			name:     "non-json body",
			status:   http.StatusOK,
			body:     "not json at all",
			wantCode: core.CodeSerializationError,
			wantIn:   "Failed to parse Utila fetch_wallet response",
		},
		{
			name:     "missing wallet envelope",
			status:   http.StatusOK,
			body:     `{}`,
			wantCode: core.CodeSerializationError,
			wantIn:   "Failed to parse Utila fetch_wallet response",
		},
		{
			name:     "missing solanaDetails",
			status:   http.StatusOK,
			body:     `{"wallet":{}}`,
			wantCode: core.CodeInvalidPublicKey,
			wantIn:   "did not include solanaDetails",
		},
		{
			name:     "invalid solana address",
			status:   http.StatusOK,
			body:     walletJSON("not-a-valid-key!!"),
			wantCode: core.CodeInvalidPublicKey,
			wantIn:   "Invalid Solana address returned by Utila wallet",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				testutils.WriteRawJSON(w, tc.status, tc.body)
			}))
			_, err := New(context.Background(), baseConfig(srv))
			testutils.AssertCode(t, err, tc.wantCode)
			testutils.AssertDetailContains(t, err, tc.wantIn)
		})
	}
}

// TestIsAvailable verifies availability is true while the wallet endpoint is
// healthy and false on remote errors or an unreachable endpoint.
func TestIsAvailable(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)

	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			testutils.WriteRawJSON(w, http.StatusInternalServerError, `{"message":"down"}`)
			return
		}
		testutils.WriteRawJSON(w, http.StatusOK, walletJSON(testutils.TestPublicKey().String()))
	}))

	s := newDirectSigner(t, srv, solana.PublicKey{})
	if !s.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be true while the wallet endpoint is healthy")
	}
	healthy.Store(false)
	if s.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be false when the wallet endpoint errors")
	}

	unreachable := newDirectSigner(t, srv, solana.PublicKey{})
	unreachable.apiBaseURL = "https://127.0.0.1:1"
	if unreachable.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be false when the endpoint is unreachable")
	}
}

// TestStringDoesNotLeakSecrets verifies the fmt renderings never expose the
// service-account private key or email while still identifying the signer.
func TestStringDoesNotLeakSecrets(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testutils.TestPublicKey().String()))
	srv := testutils.StartTLSServer(t, mux)

	s := newTestSigner(t, baseConfig(srv))

	leaks := []string{
		testRSAKey,
		"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDKKw7fHhfK3/Ts",
		testEmail,
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
		for _, leak := range leaks {
			if strings.Contains(rendered, leak) {
				t.Errorf("rendered signer leaks secrets: %s", rendered)
			}
		}
		if !strings.Contains(rendered, "utila.Signer") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
		for _, want := range []string{testVaultID, testWalletID, testNetwork} {
			if !strings.Contains(rendered, want) {
				t.Errorf("rendered signer should include %q: %s", want, rendered)
			}
		}
	}
}
