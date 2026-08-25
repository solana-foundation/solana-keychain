package crossmint

import (
	"bytes"
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
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/base58"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

const (
	testAPIKey     = "test-api-key"
	testWalletPath = "/" + walletsAPIVersion + "/wallets/test-wallet"
)

func createTestTransactionWithRecipient(t *testing.T, payer, recipient solana.PublicKey) *solana.Transaction {
	t.Helper()
	tx, err := testutils.CreateTestTransactionTo(payer, recipient)
	if err != nil {
		t.Fatalf("build transaction: %v", err)
	}
	return tx
}

// signAndEncodeB58 signs tx's message with priv, adds the signature, and
// returns the base58-encoded wire transaction plus the signature, for use as
// an onChain.transaction fixture.
func signAndEncodeB58(t *testing.T, tx *solana.Transaction, priv ed25519.PrivateKey) (string, solana.Signature) {
	t.Helper()
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatalf("serialize message: %v", err)
	}
	sig := testutils.SignWith(priv, msg)
	if err := core.AddSignature(tx, testutils.PubkeyOf(priv), sig); err != nil {
		t.Fatalf("add signature: %v", err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("serialize transaction: %v", err)
	}
	return base58.Encode(raw), sig
}

func walletJSON(address string) string {
	return fmt.Sprintf(`{"chainType":"solana","type":"smart","address":%q}`, address)
}

// walletHandler serves the wallet fetch that New performs, checking the
// X-API-KEY header.
func walletHandler(t *testing.T, apiKey, address string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-API-KEY"); got != apiKey {
			t.Errorf("x-api-key = %q, want %q", got, apiKey)
		}
		testutils.WriteRawJSON(w, http.StatusOK, walletJSON(address))
	}
}

func baseConfig(srv *httptest.Server) Config {
	return Config{
		APIKey:          testAPIKey,
		WalletLocator:   "test-wallet",
		APIBaseURL:      srv.URL,
		PollInterval:    time.Millisecond,
		MaxPollAttempts: 2,
		HTTPClient:      srv.Client(),
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

// TestBuildWalletsAPIURL: raw slashes, dot segments, pre-encoded traversal
// sequences, and query/fragment metacharacters in a wallet locator must all
// stay inside a single encoded path segment.
func TestBuildWalletsAPIURL(t *testing.T) {
	cases := []struct {
		name     string
		locator  string
		segments []string
		wantPath string
	}{
		{
			name:     "encodes raw slashes in wallet locator",
			locator:  "userId:test-user/child:solana:smart",
			wantPath: "/api/2025-06-09/wallets/userId%3Atest-user%2Fchild%3Asolana%3Asmart",
		},
		{
			name:     "prevents dot segment retargeting",
			locator:  "userId:attacker/../victim:solana:smart",
			segments: []string{"transactions"},
			wantPath: "/api/2025-06-09/wallets/userId%3Aattacker%2F..%2Fvictim%3Asolana%3Asmart/transactions",
		},
		{
			name:     "double encodes encoded slash",
			locator:  "userId:attacker%2Fvictim:solana:smart",
			wantPath: "/api/2025-06-09/wallets/userId%3Aattacker%252Fvictim%3Asolana%3Asmart",
		},
		{
			name:     "double encodes encoded dot traversal",
			locator:  "userId:attacker%2e%2e%2Fvictim:solana:smart",
			wantPath: "/api/2025-06-09/wallets/userId%3Aattacker%252e%252e%252Fvictim%3Asolana%3Asmart",
		},
		{
			name:     "encodes query and fragment metacharacters",
			locator:  "userId:test?wallet#fragment:solana:smart",
			wantPath: "/api/2025-06-09/wallets/userId%3Atest%3Fwallet%23fragment%3Asolana%3Asmart",
		},
		{
			name:     "matches encodeURIComponent unreserved set",
			locator:  "userId:alice/../wallet?draft#frag:solana:smart",
			segments: []string{"transactions", "tx-123", "approvals"},
			wantPath: "/api/2025-06-09/wallets/userId%3Aalice%2F..%2Fwallet%3Fdraft%23frag%3Asolana%3Asmart/transactions/tx-123/approvals",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Signer{apiBaseURL: "https://example.com/api", walletLocator: tc.locator}
			built, err := s.buildWalletsAPIURL(tc.segments...)
			if err != nil {
				t.Fatalf("buildWalletsAPIURL: %v", err)
			}
			wantURL := "https://example.com" + tc.wantPath
			if built != wantURL {
				t.Errorf("url = %s, want %s", built, wantURL)
			}
			parsed, err := url.Parse(built)
			if err != nil {
				t.Fatalf("parse built url: %v", err)
			}
			if got := parsed.EscapedPath(); got != tc.wantPath {
				t.Errorf("path = %s, want %s", got, tc.wantPath)
			}
			if strings.Contains(parsed.EscapedPath(), "/victim") || strings.Contains(parsed.EscapedPath(), "/child") {
				t.Errorf("wallet locator escaped its path segment: %s", parsed.EscapedPath())
			}
		})
	}
}

// TestNewRejectsInsecureAPIBaseURL: an http:// base URL is a config error,
// even with a custom HTTP client.
func TestNewRejectsInsecureAPIBaseURL(t *testing.T) {
	for name, client := range map[string]*http.Client{
		"default client": nil,
		"custom client":  {},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), Config{
				APIKey:        testAPIKey,
				WalletLocator: "test-wallet",
				APIBaseURL:    "http://insecure.example.com",
				HTTPClient:    client,
			})
			testutils.AssertCode(t, err, core.CodeConfigError)
		})
	}
}

func TestNewValidatesConfig(t *testing.T) {
	validSecret := signerSecretPrefix + strings.Repeat("ab", 32)
	cases := map[string]Config{
		"empty api_key":              {WalletLocator: "test-wallet"},
		"empty wallet_locator":       {APIKey: testAPIKey},
		"negative poll interval":     {APIKey: testAPIKey, WalletLocator: "w", PollInterval: -time.Second},
		"negative max poll attempts": {APIKey: testAPIKey, WalletLocator: "w", MaxPollAttempts: -1},
		"signer_secret wrong length": {APIKey: "sk_staging_" + base58.Encode([]byte("p:sig")), WalletLocator: "w", SignerSecret: "xmsk1_abcd"},
		"signer_secret not hex":      {APIKey: "sk_staging_" + base58.Encode([]byte("p:sig")), WalletLocator: "w", SignerSecret: signerSecretPrefix + strings.Repeat("zz", 32)},
		"invalid api key format":     {APIKey: testAPIKey, WalletLocator: "w", SignerSecret: validSecret},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), cfg)
			testutils.AssertCode(t, err, core.CodeConfigError)
		})
	}
}

func TestNewSuccess(t *testing.T) {
	want := testutils.TestPublicKey()
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, want.String()))
	srv := testutils.StartTLSServer(t, mux)

	s := newTestSigner(t, baseConfig(srv))
	if s.Pubkey() != want {
		t.Errorf("pubkey = %s, want %s", s.Pubkey(), want)
	}
}

// TestNewURLEncodesWalletLocator: the locator must reach the wire
// percent-encoded.
func TestNewURLEncodesWalletLocator(t *testing.T) {
	want := testutils.TestPublicKey()
	const wantPath = "/" + walletsAPIVersion + "/wallets/userId%3Atest-user%3Asolana%3Asmart"

	srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != wantPath {
			t.Errorf("request path = %s, want %s", got, wantPath)
		}
		testutils.WriteRawJSON(w, http.StatusOK, walletJSON(want.String()))
	}))

	cfg := baseConfig(srv)
	cfg.WalletLocator = "userId:test-user:solana:smart"
	s := newTestSigner(t, cfg)
	if s.Pubkey() != want {
		t.Errorf("pubkey = %s, want %s", s.Pubkey(), want)
	}
}

// TestNewWalletValidation covers the wallet checks New performs and the
// fetchWallet error paths.
func TestNewWalletValidation(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantCode core.Code
		wantIn   string
	}{
		{
			name:     "wrong chain type",
			status:   http.StatusOK,
			body:     `{"chainType":"ethereum","type":"smart","address":"abc"}`,
			wantCode: core.CodeConfigError,
			wantIn:   "chainType=ethereum",
		},
		{
			name:     "unsupported wallet type",
			status:   http.StatusOK,
			body:     `{"chainType":"solana","type":"custodial","address":"abc"}`,
			wantCode: core.CodeConfigError,
			wantIn:   "unsupported Crossmint wallet type: custodial",
		},
		{
			name:     "invalid address",
			status:   http.StatusOK,
			body:     `{"chainType":"solana","type":"smart","address":"not-a-valid-key!!"}`,
			wantCode: core.CodeInvalidPublicKey,
			wantIn:   "invalid Solana public key",
		},
		{
			name:     "missing address field",
			status:   http.StatusOK,
			body:     `{"chainType":"solana","type":"smart"}`,
			wantCode: core.CodeSerializationError,
			wantIn:   "fetch_wallet: missing expected field 'address' in response",
		},
		{
			name:     "remote api error",
			status:   http.StatusUnauthorized,
			body:     `{"message":"unauthorized"}`,
			wantCode: core.CodeRemoteAPIError,
			wantIn:   "fetch_wallet: unauthorized",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := testutils.StartTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				testutils.WriteRawJSON(w, tc.status, tc.body)
			}))
			_, err := New(context.Background(), baseConfig(srv))
			testutils.AssertCode(t, err, tc.wantCode)
			if detail := testutils.Detail(t, err); !strings.Contains(detail, tc.wantIn) {
				t.Errorf("detail = %q, want it to contain %q", detail, tc.wantIn)
			}
		})
	}
}

// TestSignMessageNotSupported: Crossmint intentionally does not support raw
// message signing for Solana wallets.
func TestSignMessageNotSupported(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, testutils.TestPublicKey().String()))
	srv := testutils.StartTLSServer(t, mux)
	s := newTestSigner(t, baseConfig(srv))

	_, err := s.SignMessage(context.Background(), []byte("hello"))
	testutils.AssertCode(t, err, core.CodeSigningFailed)
	if detail := testutils.Detail(t, err); !strings.Contains(detail, "not supported") {
		t.Errorf("detail = %q, want it to contain %q", detail, "not supported")
	}
}

func TestSignTransactionSuccess(t *testing.T) {
	priv := testutils.TestPrivateKey()
	signerPubkey := testutils.PubkeyOf(priv)

	localTx, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	remoteTx, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	onChainTransaction, expectedSignature := signAndEncodeB58(t, remoteTx, priv)

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, signerPubkey.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-API-KEY"); got != testAPIKey {
			t.Errorf("x-api-key = %q, want %q", got, testAPIKey)
		}
		body, _ := io.ReadAll(r.Body)
		var req createTransactionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("decode create request: %v", err)
		}
		if req.Params.Transaction == "" {
			t.Error("create request missing base58 transaction")
		}
		submittedMessage, marshalErr := localTx.Message.MarshalBinary()
		if marshalErr != nil {
			t.Errorf("serialize submitted message: %v", marshalErr)
		}
		digest := sha256.Sum256(submittedMessage)
		key := digest[:16]
		key[6] = (key[6] & 0x0f) | 0x40
		key[8] = (key[8] & 0x3f) | 0x80
		want := fmt.Sprintf("%x-%x-%x-%x-%x", key[0:4], key[4:6], key[6:8], key[8:10], key[10:16])
		if got := r.Header.Get("x-idempotency-key"); got != want {
			t.Errorf("x-idempotency-key = %q, want %q", got, want)
		}
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-123","status":"success","chainType":"solana","walletType":"smart","onChain":{"transaction":%q}}`,
			onChainTransaction))
	})
	srv := testutils.StartTLSServer(t, mux)

	s := newTestSigner(t, baseConfig(srv))
	res, err := s.SignTransaction(context.Background(), localTx)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.Signature != expectedSignature {
		t.Errorf("signature = %s, want %s", res.Signature, expectedSignature)
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
	if decoded.Signatures[0] != expectedSignature {
		t.Error("encoded transaction signature mismatch at position 0")
	}
}

// createStatusSigner points a signer at a create endpoint answering status/body.
func createStatusSigner(t *testing.T, status int, body string) *Signer {
	t.Helper()
	priv := testutils.TestPrivateKey()
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, testutils.PubkeyOf(priv).String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, status, body)
	})
	cfg := baseConfig(testutils.StartTLSServer(t, mux))
	cfg.MaxPollAttempts = 1
	return newTestSigner(t, cfg)
}

// assertUnconfirmedWithoutID checks for an unconfirmed broadcast with no id,
// carrying wantStatus (0 when the provider sent no failing status).
func assertUnconfirmedWithoutID(t *testing.T, err error, wantStatus int) {
	t.Helper()
	testutils.AssertCode(t, err, core.CodeBroadcastUnconfirmed)
	var se *core.SignerError
	if !errors.As(err, &se) || se.ProviderTxID != "" {
		t.Errorf("error must carry no provider transaction id, got %v", err)
	}
	if se != nil && se.ProviderStatus != wantStatus {
		t.Errorf("provider status = %d, want %d", se.ProviderStatus, wantStatus)
	}
}

func TestCreateServerErrorIsUnconfirmedWithoutID(t *testing.T) {
	s := createStatusSigner(t, http.StatusServiceUnavailable, `{"message":"unavailable"}`)
	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignTransaction(context.Background(), tx)
	assertUnconfirmedWithoutID(t, err, http.StatusServiceUnavailable)
}

func TestCreateAcceptedWithoutIDIsUnconfirmed(t *testing.T) {
	s := createStatusSigner(t, http.StatusCreated, `{"status":"pending"}`)
	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignTransaction(context.Background(), tx)
	assertUnconfirmedWithoutID(t, err, 0)
}

func TestCreateRejectionStaysPlainFailure(t *testing.T) {
	s := createStatusSigner(t, http.StatusBadRequest, `{"message":"invalid transaction"}`)
	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignTransaction(context.Background(), tx)
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)
}

// TestSignTransactionRejectsApprovalSignaturesForLocalTransactionBytes:
// approval signatures (over Crossmint's internal payload) must never be used
// as the transaction signature.
func TestSignTransactionRejectsApprovalSignaturesForLocalTransactionBytes(t *testing.T) {
	priv := testutils.TestPrivateKey()
	signerPubkey := testutils.PubkeyOf(priv)

	approvalPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	approvalSignature := testutils.SignWith(approvalPriv, []byte("crossmint-approval-payload"))

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, signerPubkey.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-approval","status":"success","approvals":{"submitted":[{"signature":%q}]}}`,
			base58.Encode(approvalSignature[:])))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.MaxPollAttempts = 1
	s := newTestSigner(t, cfg)

	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignTransaction(context.Background(), tx)
	testutils.AssertCode(t, err, core.CodeBroadcastUnconfirmed)
	if detail := testutils.Detail(t, err); !strings.Contains(detail, "unable to extract signature") {
		t.Errorf("detail = %q, want it to contain %q", detail, "unable to extract signature")
	}
}

// TestSignTransactionAcceptsSignatureFromOnChainTransactionBytes: the
// signature is verified against the onChain transaction's own message bytes,
// even when Crossmint modified the transaction (e.g. a smart-wallet rewrite).
func TestSignTransactionAcceptsSignatureFromOnChainTransactionBytes(t *testing.T) {
	priv := testutils.TestPrivateKey()
	signerPubkey := testutils.PubkeyOf(priv)

	recipient := testutils.PubkeyOf(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize)))
	remoteTx := createTestTransactionWithRecipient(t, signerPubkey, recipient)
	remoteOnChainTransaction, remoteSignature := signAndEncodeB58(t, remoteTx, priv)

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, signerPubkey.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-mismatch","status":"success","onChain":{"transaction":%q}}`,
			remoteOnChainTransaction))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.MaxPollAttempts = 1
	s := newTestSigner(t, cfg)

	localTx, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.SignTransaction(context.Background(), localTx)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.Signature != remoteSignature {
		t.Errorf("signature = %s, want %s", res.Signature, remoteSignature)
	}
	// Crossmint sponsors gas, so it is the fee payer and the message it signs
	// differs from the caller's. Its signature must never be placed in the
	// caller's transaction, which could not verify with it.
	if res.EncodedTransaction != "" {
		t.Error("a Crossmint-broadcast transaction leaves nothing for the caller to send")
	}
	for _, sig := range localTx.Signatures {
		if !sig.IsZero() {
			t.Error("the caller's transaction must not carry a signature over other bytes")
		}
	}
}

// A returned transaction whose message matches the submitted one really is signed
// over the caller's bytes, so the signature belongs in the caller's transaction.
// A smart wallet is signed by its delegated signer, not by the wallet address the
// API reports, so the delegated key must be a verification candidate.
func TestSignTransactionLocatesDelegatedSignerSignature(t *testing.T) {
	secret := signerSecretPrefix + strings.Repeat("ab", 32)
	derivableAPIKey := "sk_staging_" + base58.Encode([]byte("proj:sig"))
	delegatedPriv, err := deriveSigningKey(secret, derivableAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	delegated := solana.PublicKeyFromBytes(delegatedPriv.Public().(ed25519.PublicKey))
	walletPub := testutils.TestPublicKey()
	if delegated.Equals(walletPub) {
		t.Fatal("delegated signer must differ from the wallet address for this test")
	}

	rewritten, err := testutils.CreateTestTransaction(delegated)
	if err != nil {
		t.Fatal(err)
	}
	rewrittenMsg, err := rewritten.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	expectedSignature := solana.SignatureFromBytes(ed25519.Sign(delegatedPriv, rewrittenMsg))
	rewritten.Signatures = []solana.Signature{expectedSignature}
	wireBytes, err := rewritten.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, derivableAPIKey, walletPub.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-delegated","status":"success","onChain":{"transaction":%q}}`,
			base58.Encode(wireBytes)))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.APIKey = derivableAPIKey
	cfg.MaxPollAttempts = 1
	cfg.SignerSecret = secret
	s := newTestSigner(t, cfg)

	localTx, err := testutils.CreateTestTransaction(walletPub)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.SignTransaction(context.Background(), localTx)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.Signature != expectedSignature {
		t.Errorf("signature = %s, want %s", res.Signature, expectedSignature)
	}
	if !s.Pubkey().Equals(walletPub) {
		t.Error("the wallet address remains the signer's public identity")
	}
}

// Under sponsorship the returned signature must be the sponsor fee-payer's
// slot-0 signature, not the wallet's approval, so RPC lookups resolve.
func TestSignTransactionSponsoredReturnsFeePayerTransactionID(t *testing.T) {
	secret := signerSecretPrefix + strings.Repeat("cd", 32)
	derivableAPIKey := "sk_staging_" + base58.Encode([]byte("proj:sig"))
	delegatedPriv, err := deriveSigningKey(secret, derivableAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	delegated := solana.PublicKeyFromBytes(delegatedPriv.Public().(ed25519.PublicKey))
	walletPub := testutils.TestPublicKey()

	sponsorPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5e}, ed25519.SeedSize))
	sponsor := solana.PublicKeyFromBytes(sponsorPriv.Public().(ed25519.PublicKey))
	executed, err := testutils.CreateTestTransaction(sponsor)
	if err != nil {
		t.Fatal(err)
	}
	executedMsg, err := executed.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	feePayerSignature := solana.SignatureFromBytes(ed25519.Sign(sponsorPriv, executedMsg))
	executed.Signatures = []solana.Signature{feePayerSignature}
	wireBytes, err := executed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	approvalSignature := solana.SignatureFromBytes(ed25519.Sign(delegatedPriv, executedMsg))

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, derivableAPIKey, walletPub.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-sponsored","status":"success","approvals":{"submitted":[{"signature":%q,"signer":{"address":%q}}]},"onChain":{"transaction":%q}}`,
			approvalSignature.String(), delegated.String(), base58.Encode(wireBytes)))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.APIKey = derivableAPIKey
	cfg.MaxPollAttempts = 1
	cfg.SignerSecret = secret
	s := newTestSigner(t, cfg)

	localTx, err := testutils.CreateTestTransaction(walletPub)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.SignTransaction(context.Background(), localTx)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.Signature != feePayerSignature {
		t.Errorf("signature = %s, want fee payer %s", res.Signature, feePayerSignature)
	}
	if res.Signature == approvalSignature {
		t.Error("the approval signature must not be returned as the transaction id")
	}
	if res.EncodedTransaction != "" {
		t.Error("a Crossmint-broadcast transaction leaves nothing for the caller to send")
	}
}

// A wallet can be configured with both SignerSecret and an explicit Signer locator
// naming a different key, e.g. the wallet's admin signer. Either may be the key
// that actually signs, so both must be candidates.
func TestSignTransactionExplicitLocatorSignerIsACandidate(t *testing.T) {
	walletPub := testutils.TestPublicKey()
	adminPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x7c}, ed25519.SeedSize))
	admin := solana.PublicKeyFromBytes(adminPriv.Public().(ed25519.PublicKey))

	rewritten, err := testutils.CreateTestTransaction(admin)
	if err != nil {
		t.Fatal(err)
	}
	rewrittenMsg, err := rewritten.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	expectedSignature := solana.SignatureFromBytes(ed25519.Sign(adminPriv, rewrittenMsg))
	rewritten.Signatures = []solana.Signature{expectedSignature}
	wireBytes, err := rewritten.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	derivableAPIKey := "sk_staging_" + base58.Encode([]byte("proj:sig"))
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, derivableAPIKey, walletPub.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-admin","status":"success","onChain":{"transaction":%q}}`, base58.Encode(wireBytes)))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.APIKey = derivableAPIKey
	cfg.MaxPollAttempts = 1
	cfg.SignerSecret = signerSecretPrefix + strings.Repeat("ab", 32)
	cfg.Signer = "server:" + admin.String()
	s := newTestSigner(t, cfg)

	localTx, err := testutils.CreateTestTransaction(walletPub)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.SignTransaction(context.Background(), localTx)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.Signature != expectedSignature {
		t.Errorf("signature = %s, want %s", res.Signature, expectedSignature)
	}
}

// Widening the candidate set must not accept a key that is neither the wallet
// address nor the configured delegated signer.
func TestSignTransactionRejectsUnrelatedSignerKey(t *testing.T) {
	walletPub := testutils.TestPublicKey()
	strangerPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	stranger := solana.PublicKeyFromBytes(strangerPriv.Public().(ed25519.PublicKey))

	rewritten, err := testutils.CreateTestTransaction(stranger)
	if err != nil {
		t.Fatal(err)
	}
	rewrittenMsg, err := rewritten.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	rewritten.Signatures = []solana.Signature{solana.SignatureFromBytes(ed25519.Sign(strangerPriv, rewrittenMsg))}
	wireBytes, err := rewritten.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	derivableAPIKey := "sk_staging_" + base58.Encode([]byte("proj:sig"))
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, derivableAPIKey, walletPub.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-stranger","status":"success","onChain":{"transaction":%q}}`,
			base58.Encode(wireBytes)))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.APIKey = derivableAPIKey
	cfg.MaxPollAttempts = 1
	cfg.SignerSecret = signerSecretPrefix + strings.Repeat("ab", 32)
	s := newTestSigner(t, cfg)

	localTx, err := testutils.CreateTestTransaction(walletPub)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignTransaction(context.Background(), localTx)
	if code, _ := core.CodeOf(err); code != core.CodeBroadcastUnconfirmed {
		t.Errorf("got %s, want BROADCAST_UNCONFIRMED", code)
	}
}

func TestSignTransactionUnrewrittenTransactionSignsCallerBytes(t *testing.T) {
	priv := testutils.TestPrivateKey()
	signerPubkey := testutils.PubkeyOf(priv)

	localTx, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	returned, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	onChainTransaction, expectedSignature := signAndEncodeB58(t, returned, priv)

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, signerPubkey.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-exact","status":"success","onChain":{"transaction":%q}}`, onChainTransaction))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.MaxPollAttempts = 1
	s := newTestSigner(t, cfg)

	res, err := s.SignTransaction(context.Background(), localTx)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.EncodedTransaction == "" {
		t.Error("an unrewritten transaction is the caller's to broadcast")
	}
	if len(localTx.Signatures) == 0 || localTx.Signatures[0] != expectedSignature {
		t.Error("the signature covers the caller's bytes and belongs in its transaction")
	}
}

func TestSignTransactionPrefersOnChainTransactionSignatureOverTxIDFallback(t *testing.T) {
	priv := testutils.TestPrivateKey()
	signerPubkey := testutils.PubkeyOf(priv)

	recipient := testutils.PubkeyOf(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, ed25519.SeedSize)))
	remoteTx := createTestTransactionWithRecipient(t, signerPubkey, recipient)
	remoteOnChainTransaction, remoteSignature := signAndEncodeB58(t, remoteTx, priv)
	// txId is only valid for the remote transaction bytes, not the local ones.
	txID := base58.Encode(remoteSignature[:])

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, signerPubkey.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-fallthrough","status":"success","onChain":{"transaction":%q,"txId":%q}}`,
			remoteOnChainTransaction, txID))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.MaxPollAttempts = 1
	s := newTestSigner(t, cfg)

	localTx, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.SignTransaction(context.Background(), localTx)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.Signature != remoteSignature {
		t.Errorf("signature = %s, want %s", res.Signature, remoteSignature)
	}
}

// TestSignTransactionAwaitingApproval: without a configured signer secret,
// awaiting-approval is a terminal failure.
func TestSignTransactionAwaitingApproval(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, testutils.TestPublicKey().String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated,
			`{"id":"tx-123","status":"awaiting-approval","chainType":"solana","walletType":"smart"}`)
	})
	srv := testutils.StartTLSServer(t, mux)

	s := newTestSigner(t, baseConfig(srv))
	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignTransaction(context.Background(), tx)
	testutils.AssertCode(t, err, core.CodeBroadcastUnconfirmed)
	if detail := testutils.Detail(t, err); !strings.Contains(detail, "awaiting approval") {
		t.Errorf("detail = %q, want it to contain %q", detail, "awaiting approval")
	}
}

// TestSignTransactionSuccessOnLastPolledResponse: a success arriving on the
// final poll attempt is still honored.
func TestSignTransactionSuccessOnLastPolledResponse(t *testing.T) {
	priv := testutils.TestPrivateKey()
	signerPubkey := testutils.PubkeyOf(priv)

	tx, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	expectedSignature := testutils.SignWith(priv, msg)
	txID := base58.Encode(expectedSignature[:])

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, signerPubkey.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated,
			`{"id":"tx-123","status":"pending","chainType":"solana","walletType":"smart"}`)
	})
	mux.HandleFunc("GET "+testWalletPath+"/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusOK, fmt.Sprintf(
			`{"id":"tx-123","status":"success","chainType":"solana","walletType":"smart","onChain":{"txId":%q}}`,
			txID))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.MaxPollAttempts = 1
	s := newTestSigner(t, cfg)

	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.Signature != expectedSignature {
		t.Errorf("signature = %s, want %s", res.Signature, expectedSignature)
	}
}

// TestSignTransactionFailedStatus covers the "failed" terminal status: the
// remote error payload is surfaced (sanitized) in the SigningFailed detail.
func TestSignTransactionFailedStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, testutils.TestPublicKey().String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated,
			`{"id":"tx-9","status":"failed","error":{"reason":"insufficient funds"}}`)
	})
	srv := testutils.StartTLSServer(t, mux)

	s := newTestSigner(t, baseConfig(srv))
	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignTransaction(context.Background(), tx)
	testutils.AssertCode(t, err, core.CodeBroadcastUnconfirmed)
	detail := testutils.Detail(t, err)
	if !strings.Contains(detail, "Crossmint transaction failed") || !strings.Contains(detail, "insufficient funds") {
		t.Errorf("detail = %q, want it to contain the failed-status message and remote reason", detail)
	}
}

// TestSignTransactionPollingTimesOut covers the poll-exhaustion path.
func TestSignTransactionPollingTimesOut(t *testing.T) {
	pending := `{"id":"tx-123","status":"pending"}`
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, testutils.TestPublicKey().String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated, pending)
	})
	mux.HandleFunc("GET "+testWalletPath+"/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusOK, pending)
	})
	srv := testutils.StartTLSServer(t, mux)

	s := newTestSigner(t, baseConfig(srv))
	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignTransaction(context.Background(), tx)
	testutils.AssertCode(t, err, core.CodeBroadcastUnconfirmed)
	if detail := testutils.Detail(t, err); !strings.Contains(detail, "polling timed out after 2 attempts") {
		t.Errorf("detail = %q, want it to contain %q", detail, "polling timed out after 2 attempts")
	}
	var se *core.SignerError
	if !errors.As(err, &se) || se.ProviderTxID != "tx-123" {
		t.Errorf("ProviderTxID = %v, want tx-123", se)
	}
}

// TestCreateTransactionRemoteAPIError covers the
// parseResponseWithRequiredField error extraction: message string, error
// string, error object, and the status-code fallback.
func TestCreateTransactionRemoteAPIError(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		wantIn string
	}{
		{"message field", `{"message":"invalid transaction"}`, "create_transaction: invalid transaction"},
		{"error string", `{"error":"string error"}`, "create_transaction: string error"},
		{"error object message", `{"error":{"message":"nested message"}}`, "create_transaction: nested message"},
		{"no message", `{}`, "create_transaction: Crossmint API error 400"},
		{"non-json body", `not json at all`, "create_transaction: Crossmint API error 400"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, testutils.TestPublicKey().String()))
			mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
				testutils.WriteRawJSON(w, http.StatusBadRequest, tc.body)
			})
			srv := testutils.StartTLSServer(t, mux)

			s := newTestSigner(t, baseConfig(srv))
			tx, err := testutils.CreateTestTransaction(s.Pubkey())
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.SignTransaction(context.Background(), tx)
			testutils.AssertCode(t, err, core.CodeRemoteAPIError)
			if detail := testutils.Detail(t, err); !strings.Contains(detail, tc.wantIn) {
				t.Errorf("detail = %q, want it to contain %q", detail, tc.wantIn)
			}
		})
	}
}

// TestRemoteAPIErrorSanitizesHostileBody verifies untrusted remote error text
// passes through core.SanitizeRemoteResponse before landing in error details.
func TestRemoteAPIErrorSanitizesHostileBody(t *testing.T) {
	hostile := "evil\x07payload\nwith\x1bcontrols " + strings.Repeat("x", 400)
	hostileBody, err := json.Marshal(map[string]string{"message": hostile})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusInternalServerError, string(hostileBody))
	})
	srv := testutils.StartTLSServer(t, mux)

	_, err = New(context.Background(), baseConfig(srv))
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)
	detail := testutils.Detail(t, err)
	if strings.ContainsAny(detail, "\x07\x1b\n") {
		t.Errorf("detail contains raw control characters: %q", detail)
	}
	if !strings.Contains(detail, "evil payload") {
		t.Errorf("detail = %q, want it to contain the sanitized message", detail)
	}
	if !strings.Contains(detail, "[truncated]") {
		t.Errorf("detail = %q, want the oversized message to be truncated", detail)
	}
}

// TestSignTransactionSubmitsApprovalWithDerivedKey exercises the server-signer
// flow: HKDF key derivation from the signer secret + API key, the
// "server:<pubkey>" locator, and approval submission for an awaiting-approval
// transaction.
func TestSignTransactionSubmitsApprovalWithDerivedKey(t *testing.T) {
	priv := testutils.TestPrivateKey()
	signerPubkey := testutils.PubkeyOf(priv)

	apiKey := "sk_staging_" + base58.Encode([]byte("project-123:signature-data"))
	secret := signerSecretPrefix + strings.Repeat("4d", 32)

	derivedKey, err := deriveSigningKey(secret, apiKey)
	if err != nil {
		t.Fatalf("deriveSigningKey: %v", err)
	}
	derivedPub := derivedKey.Public().(ed25519.PublicKey)
	wantLocator := "server:" + base58.Encode(derivedPub)

	approvalMessage := []byte("crossmint-approval-message-bytes")
	approvalMessageB58 := base58.Encode(approvalMessage)

	localTx, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	remoteTx, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	onChainTransaction, expectedSignature := signAndEncodeB58(t, remoteTx, priv)

	var approvalCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, apiKey, signerPubkey.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, r *http.Request) {
		var req createTransactionRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("decode create request: %v", err)
		}
		if req.Params.Signer != wantLocator {
			t.Errorf("create request signer = %q, want %q", req.Params.Signer, wantLocator)
		}
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-1","status":"awaiting-approval","approvals":{"pending":[{"signer":{"locator":%q},"message":%q}]}}`,
			wantLocator, approvalMessageB58))
	})
	mux.HandleFunc("POST "+testWalletPath+"/transactions/tx-1/approvals", func(w http.ResponseWriter, r *http.Request) {
		approvalCalls.Add(1)
		var req approvalRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("decode approval request: %v", err)
		}
		if len(req.Approvals) != 1 {
			t.Fatalf("approvals length = %d, want 1", len(req.Approvals))
		}
		if req.Approvals[0].Signer != wantLocator {
			t.Errorf("approval signer = %q, want %q", req.Approvals[0].Signer, wantLocator)
		}
		sigBytes, err := base58.Decode(req.Approvals[0].Signature)
		if err != nil || len(sigBytes) != core.SignatureLength {
			t.Fatalf("approval signature is not a valid base58 64-byte signature: %v", err)
		}
		if !ed25519.Verify(derivedPub, approvalMessage, sigBytes) {
			t.Error("approval signature does not verify under the derived server signer key")
		}
		testutils.WriteRawJSON(w, http.StatusOK, fmt.Sprintf(
			`{"id":"tx-1","status":"success","onChain":{"transaction":%q}}`,
			onChainTransaction))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.APIKey = apiKey
	cfg.SignerSecret = secret
	cfg.MaxPollAttempts = 3
	s := newTestSigner(t, cfg)

	res, err := s.SignTransaction(context.Background(), localTx)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.Signature != expectedSignature {
		t.Errorf("signature = %s, want %s", res.Signature, expectedSignature)
	}
	if got := approvalCalls.Load(); got != 1 {
		t.Errorf("approval endpoint called %d times, want 1", got)
	}
}

// TestSignTransactionAwaitingApprovalNoPendingMessage: with a derived signer
// key and a pending challenge addressed to it but carrying no message, signing
// fails.
func TestSignTransactionAwaitingApprovalNoPendingMessage(t *testing.T) {
	apiKey := "sk_staging_" + base58.Encode([]byte("project-123:signature-data"))
	secret := signerSecretPrefix + strings.Repeat("4d", 32)
	derivedKey, err := deriveSigningKey(secret, apiKey)
	if err != nil {
		t.Fatalf("deriveSigningKey: %v", err)
	}
	wantLocator := "server:" + base58.Encode(derivedKey.Public().(ed25519.PublicKey))

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, apiKey, testutils.TestPublicKey().String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-1","status":"awaiting-approval","approvals":{"pending":[{"signer":{"locator":%q}}]}}`,
			wantLocator))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.APIKey = apiKey
	cfg.SignerSecret = secret
	s := newTestSigner(t, cfg)

	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SignTransaction(context.Background(), tx)
	testutils.AssertCode(t, err, core.CodeBroadcastUnconfirmed)
	if detail := testutils.Detail(t, err); !strings.Contains(detail, "no pending message found") {
		t.Errorf("detail = %q, want it to contain %q", detail, "no pending message found")
	}
}

// attachApprovalSigner injects an approval key and locator directly into the
// signer.
func attachApprovalSigner(s *Signer, locator string, key ed25519.PrivateKey) {
	s.signingKey = key
	s.signerLocator = locator
}

// TestSignTransactionSubmitsApprovalOnceAndPollsAfterAsyncRegistration:
// when Crossmint acknowledges the approval but still reports awaiting-approval
// (async registration), the signer must not re-submit; it keeps polling until
// the transaction succeeds.
func TestSignTransactionSubmitsApprovalOnceAndPollsAfterAsyncRegistration(t *testing.T) {
	priv := testutils.TestPrivateKey()
	signerPubkey := testutils.PubkeyOf(priv)
	locator := "server:test-approver"
	approvalKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	approvalMessage := base58.Encode([]byte("approval-challenge"))

	tx, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	expectedSignature := testutils.SignWith(priv, msg)
	txID := base58.Encode(expectedSignature[:])

	var approvalCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, signerPubkey.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-123","status":"awaiting-approval","approvals":{"pending":[{"signer":{"locator":%q},"message":%q}]}}`,
			locator, approvalMessage))
	})
	// The approval is acknowledged but Crossmint has not registered it yet:
	// the transaction still reports awaiting-approval with nothing pending.
	mux.HandleFunc("POST "+testWalletPath+"/transactions/tx-123/approvals", func(w http.ResponseWriter, _ *http.Request) {
		approvalCalls.Add(1)
		testutils.WriteRawJSON(w, http.StatusOK,
			`{"id":"tx-123","status":"awaiting-approval","approvals":{"pending":[]}}`)
	})
	mux.HandleFunc("GET "+testWalletPath+"/transactions/tx-123", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusOK, fmt.Sprintf(
			`{"id":"tx-123","status":"success","onChain":{"txId":%q}}`, txID))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.MaxPollAttempts = 5
	s := newTestSigner(t, cfg)
	attachApprovalSigner(s, locator, approvalKey)

	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.Signature != expectedSignature {
		t.Errorf("signature = %s, want %s", res.Signature, expectedSignature)
	}
	if got := approvalCalls.Load(); got != 1 {
		t.Errorf("approval endpoint called %d times, want 1", got)
	}
}

// TestSignTransactionSelectsPendingApprovalMatchingSignerLocator: on a
// multi-approver wallet only the pending challenge addressed to this signer's
// locator is signed, never pending[0].
func TestSignTransactionSelectsPendingApprovalMatchingSignerLocator(t *testing.T) {
	priv := testutils.TestPrivateKey()
	signerPubkey := testutils.PubkeyOf(priv)
	locator := "server:test-approver"
	approvalKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

	ourMessageBytes := []byte("our-approval-challenge")
	ourMessage := base58.Encode(ourMessageBytes)
	otherMessage := base58.Encode([]byte("someone-elses-challenge"))
	expectedApprovalSignature := base58.Encode(ed25519.Sign(approvalKey, ourMessageBytes))

	tx, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	expectedTxSignature := testutils.SignWith(priv, msg)
	txID := base58.Encode(expectedTxSignature[:])

	var approvalCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, signerPubkey.String()))
	// pending[0] belongs to another approver; ours is second.
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, _ *http.Request) {
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-multi","status":"awaiting-approval","approvals":{"pending":[`+
				`{"signer":{"locator":"server:other-approver"},"message":%q},`+
				`{"signer":{"locator":%q},"message":%q}]}}`,
			otherMessage, locator, ourMessage))
	})
	// Only an approval whose signature covers OUR challenge bytes (and carries
	// our locator) is accepted; signing pending[0] fails the test here.
	mux.HandleFunc("POST "+testWalletPath+"/transactions/tx-multi/approvals", func(w http.ResponseWriter, r *http.Request) {
		approvalCalls.Add(1)
		var req approvalRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("decode approval request: %v", err)
		}
		if len(req.Approvals) != 1 {
			t.Errorf("approvals length = %d, want 1", len(req.Approvals))
		} else {
			if req.Approvals[0].Signer != locator {
				t.Errorf("approval signer = %q, want %q", req.Approvals[0].Signer, locator)
			}
			if req.Approvals[0].Signature != expectedApprovalSignature {
				t.Errorf("approval signature = %q, want the signature over our challenge bytes %q",
					req.Approvals[0].Signature, expectedApprovalSignature)
			}
		}
		testutils.WriteRawJSON(w, http.StatusOK, fmt.Sprintf(
			`{"id":"tx-multi","status":"success","onChain":{"txId":%q}}`, txID))
	})
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.MaxPollAttempts = 5
	s := newTestSigner(t, cfg)
	attachApprovalSigner(s, locator, approvalKey)

	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}
	if res.Signature != expectedTxSignature {
		t.Errorf("signature = %s, want %s", res.Signature, expectedTxSignature)
	}
	if got := approvalCalls.Load(); got != 1 {
		t.Errorf("approval endpoint called %d times, want 1", got)
	}
}

// TestDeriveSigningKey verifies the HKDF derivation is deterministic, sensitive
// to the API key environment/project, and prefix-agnostic on the secret.
func TestDeriveSigningKey(t *testing.T) {
	secretHex := strings.Repeat("4d", 32)
	stagingKey := "sk_staging_" + base58.Encode([]byte("project-123:sig"))
	productionKey := "sk_production_" + base58.Encode([]byte("project-123:sig"))
	otherProjectKey := "sk_staging_" + base58.Encode([]byte("project-456:sig"))

	a, err := deriveSigningKey(signerSecretPrefix+secretHex, stagingKey)
	if err != nil {
		t.Fatalf("deriveSigningKey: %v", err)
	}
	b, err := deriveSigningKey(signerSecretPrefix+secretHex, stagingKey)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Error("derivation should be deterministic for identical inputs")
	}

	noPrefix, err := deriveSigningKey(secretHex, stagingKey)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(noPrefix) {
		t.Error("the xmsk1_ prefix must be optional and not affect derivation")
	}

	prod, err := deriveSigningKey(signerSecretPrefix+secretHex, productionKey)
	if err != nil {
		t.Fatal(err)
	}
	if a.Equal(prod) {
		t.Error("different environments must derive different keys")
	}

	other, err := deriveSigningKey(signerSecretPrefix+secretHex, otherProjectKey)
	if err != nil {
		t.Fatal(err)
	}
	if a.Equal(other) {
		t.Error("different projects must derive different keys")
	}
}

// TestIsAvailable checks both outcomes of the wallet-fetch health probe.
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

	s := newTestSigner(t, baseConfig(srv))
	if !s.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be true while the wallet endpoint is healthy")
	}
	healthy.Store(false)
	if s.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be false when the wallet endpoint errors")
	}
}

// TestStringDoesNotLeakSecrets verifies the fmt renderings never expose the
// API key, the signer secret, or the derived approval key material.
func TestStringDoesNotLeakSecrets(t *testing.T) {
	apiKey := "sk_staging_" + base58.Encode([]byte("project-123:signature-data"))
	secret := signerSecretPrefix + strings.Repeat("4d", 32)

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, apiKey, testutils.TestPublicKey().String()))
	srv := testutils.StartTLSServer(t, mux)

	cfg := baseConfig(srv)
	cfg.APIKey = apiKey
	cfg.SignerSecret = secret
	s := newTestSigner(t, cfg)

	seed := s.signingKey.Seed()
	leaks := []string{
		apiKey,
		secret,
		strings.Repeat("4d", 32),
		hex.EncodeToString(seed),
		base58.Encode(seed),
		base58.Encode(s.signingKey),
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
		if !strings.Contains(rendered, "crossmint.Signer") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
	}
}

// An unsigned transaction is serialized as a zero placeholder signature per
// required signer followed by the message bytes; the transaction posted to
// Crossmint must use exactly that wire encoding.
func TestSignTransactionSendsPlaceholderSignatures(t *testing.T) {
	priv := testutils.TestPrivateKey()
	signerPubkey := testutils.PubkeyOf(priv)

	localTx, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	expectedMessage, err := localTx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	remoteTx, err := testutils.CreateTestTransaction(signerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	onChainTransaction, _ := signAndEncodeB58(t, remoteTx, priv)

	var postedB58 string
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+testWalletPath, walletHandler(t, testAPIKey, signerPubkey.String()))
	mux.HandleFunc("POST "+testWalletPath+"/transactions", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req createTransactionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("decode create request: %v", err)
		}
		postedB58 = req.Params.Transaction
		testutils.WriteRawJSON(w, http.StatusCreated, fmt.Sprintf(
			`{"id":"tx-123","status":"success","chainType":"solana","walletType":"smart","onChain":{"transaction":%q}}`,
			onChainTransaction))
	})
	srv := testutils.StartTLSServer(t, mux)

	s := newTestSigner(t, baseConfig(srv))
	if _, err := s.SignTransaction(context.Background(), localTx); err != nil {
		t.Fatalf("SignTransaction: %v (detail: %s)", err, testutils.Detail(t, err))
	}

	posted, err := base58.Decode(postedB58)
	if err != nil {
		t.Fatalf("posted transaction is not valid base58: %v", err)
	}
	required := int(localTx.Message.Header.NumRequiredSignatures)
	if len(posted) != 1+required*64+len(expectedMessage) {
		t.Fatalf("posted transaction length = %d, want %d", len(posted), 1+required*64+len(expectedMessage))
	}
	if int(posted[0]) != required {
		t.Errorf("signature count = %d, want %d placeholder(s)", posted[0], required)
	}
	if !bytes.Equal(posted[1:1+required*64], make([]byte, required*64)) {
		t.Error("placeholder signatures must be all-zero")
	}
	if !bytes.Equal(posted[1+required*64:], expectedMessage) {
		t.Errorf("message bytes differ from the local transaction:\n got =%x\n want=%x", posted[1+required*64:], expectedMessage)
	}
}
