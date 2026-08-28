package fordefi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

// manualConfig returns a devnet native-mode config with manual push mode.
func manualConfig(t *testing.T) Config {
	t.Helper()
	cfg := nativeConfig(t)
	cfg.PushMode = PushModeManual
	return cfg
}

func newManualTestSigner(t *testing.T, cfg Config, address string, configure func(mux *http.ServeMux)) *NativeManualSigner {
	t.Helper()
	s, err := NewNativeManual(context.Background(), testConfig(t, cfg, address, configure))
	if err != nil {
		t.Fatalf("NewNativeManual failed: %v", err)
	}
	return s
}

// rewrittenTransaction is what Fordefi hands back: the same transfer under a
// blockhash it chose, signed over those bytes.
func rewrittenTransaction(t *testing.T, payer solana.PublicKey) (*solana.Transaction, []byte, solana.Signature) {
	t.Helper()
	tx, err := testutils.CreateTestTransaction(payer)
	if err != nil {
		t.Fatal(err)
	}
	var blockhash solana.Hash
	for i := range blockhash {
		blockhash[i] = 0x5a
	}
	tx.Message.RecentBlockhash = blockhash

	message, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	signature := solana.SignatureFromBytes(ed25519.Sign(testutils.TestPrivateKey(), message))
	tx.Signatures = []solana.Signature{signature}
	return tx, message, signature
}

// wireBase64 renders a transaction as the base64 raw_transaction Fordefi returns.
func wireBase64(t *testing.T, tx *solana.Transaction) string {
	t.Helper()
	wire, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(wire)
}

// submittedRequest is a create request captured while its body is still open.
type submittedRequest struct {
	body   []byte
	header http.Header
}

// respondManual registers a manual submit handler plus a poll handler returning
// state with the given raw transaction, and reports the submitted create.
func respondManual(t *testing.T, state, rawTransaction string, submitted chan<- submittedRequest) func(mux *http.ServeMux) {
	t.Helper()
	return func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, r *http.Request) {
			if submitted != nil {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read create body: %v", err)
				}
				submitted <- submittedRequest{body: body, header: r.Header.Clone()}
			}
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "manual-tx-1"})
		})
		mux.HandleFunc(transactionsPath+"/manual-tx-1", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
				"state":           state,
				"raw_transaction": rawTransaction,
			})
		})
	}
}

// Manual mode is a third type, not a flag on the native one: it rewrites the
// transaction but does not broadcast it, so it must carry
// ModifyAndSignTransaction and neither of the other two entry points.
func TestNewSelectsTheManualSignerTypeFromPushMode(t *testing.T) {
	pub := testutils.TestPublicKey()

	manual, err := New(context.Background(), testConfig(t, manualConfig(t), pub.String(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := manual.(core.ModifyingSigner); !ok {
		t.Error("manual push mode must be a ModifyingSigner")
	}
	if _, ok := manual.(core.SendingSigner); ok {
		t.Error("manual push mode does not broadcast, so it must expose no SignAndSendTransaction")
	}
	if _, ok := manual.(core.TransactionSigner); ok {
		t.Error("manual push mode rewrites the transaction, so it must expose no SignTransaction")
	}
}

// Each constructor owns one mode, so a config meant for another must be refused
// rather than silently signing in a mode the caller did not ask for.
func TestManualConstructorRejectionMatrix(t *testing.T) {
	blackBoxWithPushMode := baseConfig(t)
	blackBoxWithPushMode.PushMode = PushModeManual

	autoConfig := nativeConfig(t)

	unknownPushMode := nativeConfig(t)
	unknownPushMode.PushMode = "later"

	cases := map[string]func() error{
		"NewNativeManual without a chain": func() error {
			_, err := NewNativeManual(context.Background(), baseConfig(t))
			return err
		},
		"NewNativeManual with the auto push mode": func() error {
			_, err := NewNativeManual(context.Background(), autoConfig)
			return err
		},
		"NewNativeManual with an unknown push mode": func() error {
			_, err := NewNativeManual(context.Background(), unknownPushMode)
			return err
		},
		"NewNativeAuto with the manual push mode": func() error {
			_, err := NewNativeAuto(context.Background(), manualConfig(t))
			return err
		},
		"NewBlackBox with a push mode": func() error {
			_, err := NewBlackBox(context.Background(), blackBoxWithPushMode)
			return err
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			testutils.AssertCode(t, build(), core.CodeConfigError)
		})
	}
}

// Fordefi rewrites the message, so the caller has to end up holding the bytes
// the returned signature covers rather than the ones it submitted.
func TestModifyAndSignTransactionReplacesTheCallersTransaction(t *testing.T) {
	pub := testutils.TestPublicKey()
	returned, returnedMessage, signature := rewrittenTransaction(t, pub)

	submitted := make(chan submittedRequest, 1)
	s := newManualTestSigner(t, manualConfig(t), pub.String(),
		respondManual(t, "signed", wireBase64(t, returned), submitted))

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	submittedMessage, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.ModifyAndSignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Signature != signature {
		t.Errorf("signature = %s, want %s", res.Signature, signature)
	}
	if !res.IsComplete() {
		t.Error("a single-signer transaction Fordefi signed should be Complete")
	}
	if res.EncodedTransaction == "" {
		t.Error("manual mode does not broadcast, so the caller needs the encoded transaction")
	}

	message, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, returnedMessage) {
		t.Error("the caller's transaction must become the one the signature covers")
	}
	if bytes.Equal(message, submittedMessage) {
		t.Error("the rewritten message must differ from the submitted one for this test to mean anything")
	}
	if !ed25519.Verify(pub[:], returnedMessage, res.Signature[:]) {
		t.Error("the signature must verify against the returned message")
	}

	request := <-submitted
	var req map[string]any
	if err := json.Unmarshal(request.body, &req); err != nil {
		t.Fatalf("request body should be JSON: %v", err)
	}
	details, _ := req["details"].(map[string]any)
	if details["push_mode"] != string(PushModeManual) {
		t.Errorf("push_mode = %v, want manual", details["push_mode"])
	}
	if details["chain"] != string(ChainSolanaDevnet) {
		t.Errorf("chain = %v, want %s", details["chain"], ChainSolanaDevnet)
	}
	if got, want := request.header.Get("x-idempotence-id"), s.idempotencyKey(submittedMessage); got != want {
		t.Errorf("x-idempotence-id = %q, want %q", got, want)
	}
}

// The manual key is namespaced so a resend of these bytes cannot be deduplicated
// against an earlier auto create that did broadcast them.
func TestManualIdempotencyKeyIsNamespacedAwayFromAuto(t *testing.T) {
	pub := testutils.TestPublicKey()
	s := newManualTestSigner(t, manualConfig(t), pub.String(), nil)

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	message, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if s.idempotencyKey(message) == core.IdempotencyKeyFromMessage(message) {
		t.Error("the manual key must not equal the auto key for the same message bytes")
	}

	namespaced := append([]byte("fordefi:solana:manual:solana_devnet:"+testVaultID+"::"), message...)
	if got, want := s.idempotencyKey(message), core.IdempotencyKeyFromMessage(namespaced); got != want {
		t.Errorf("manual key = %q, want the key over the namespaced bytes %q", got, want)
	}
}

// Fordefi rewrites the Compute Budget instructions from the fee the create
// carries, so two creates over identical bytes with different fees are different
// operations and must not deduplicate onto each other.
func TestNativeIdempotencyKeyBindsChainAndFee(t *testing.T) {
	message := []byte("serialized message bytes")
	base := nativeIdempotencyKey(PushModeAuto, ChainSolanaMainnet, testVaultID, nil, message)

	variants := map[string]string{
		"another chain": nativeIdempotencyKey(PushModeAuto, ChainSolanaDevnet, testVaultID, nil, message),
		"another vault": nativeIdempotencyKey(PushModeAuto, ChainSolanaMainnet, "other-vault", nil, message),
		"a custom fee": nativeIdempotencyKey(PushModeAuto, ChainSolanaMainnet, testVaultID,
			&Fee{Type: FeeTypeCustom, UnitPrice: "10"}, message),
		"a high priority fee": nativeIdempotencyKey(PushModeAuto, ChainSolanaMainnet, testVaultID,
			&Fee{Type: FeeTypePriority, PriorityLevel: PriorityHigh}, message),
		"a low priority fee": nativeIdempotencyKey(PushModeAuto, ChainSolanaMainnet, testVaultID,
			&Fee{Type: FeeTypePriority, PriorityLevel: PriorityLow}, message),
	}
	seen := map[string]string{base: "no fee"}
	for name, key := range variants {
		if previous, collided := seen[key]; collided {
			t.Errorf("%s produced the same key as %s", name, previous)
		}
		seen[key] = name
	}
}

// Fordefi only signs a transaction it pays for, and the rejection has to land
// before the vault is asked to sign anything.
func TestModifyAndSignTransactionRejectsATransactionItDoesNotPayFor(t *testing.T) {
	pub := testutils.TestPublicKey()
	var requests atomic.Int64
	s := newManualTestSigner(t, manualConfig(t), pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "manual-tx-1"})
		})
	})

	_, otherPayer := testutils.KeyFromSeed(0x11)
	tx, err := testutils.CreateTestTransaction(otherPayer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ModifyAndSignTransaction(context.Background(), tx)
	testutils.AssertCode(t, err, core.CodeSigningFailed)
	if got := requests.Load(); got != 0 {
		t.Errorf("rejection must happen before any signing request, server saw %d", got)
	}
}

// Manual signing never broadcasts, so submitting bytes that already carry
// signatures is the caller's call. The rewrite voids them, and the transaction
// the caller ends up holding carries only what Fordefi returned.
func TestModifyAndSignTransactionAcceptsAnAlreadySignedTransaction(t *testing.T) {
	pub := testutils.TestPublicKey()
	returned, _, signature := rewrittenTransaction(t, pub)
	s := newManualTestSigner(t, manualConfig(t), pub.String(),
		respondManual(t, "signed", wireBase64(t, returned), make(chan submittedRequest, 1)))

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	stale := testutils.SignWith(testutils.TestPrivateKey(), []byte("some earlier message"))
	tx.Signatures = []solana.Signature{stale}

	res, err := s.ModifyAndSignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Signature != signature {
		t.Errorf("signature = %s, want %s", res.Signature, signature)
	}
	for _, got := range tx.Signatures {
		if got == stale {
			t.Error("the void signature must not survive the rewrite")
		}
	}
}

// The rewrite is Fordefi's to make and is not diffed, but the signature has to
// cover the message it came back with or the caller would hold bytes nothing
// signed.
func TestModifyAndSignTransactionRejectsASignatureOverOtherBytes(t *testing.T) {
	pub := testutils.TestPublicKey()
	returned, _, _ := rewrittenTransaction(t, pub)
	returned.Signatures = []solana.Signature{
		testutils.SignWith(testutils.TestPrivateKey(), []byte("some other message")),
	}

	s := newManualTestSigner(t, manualConfig(t), pub.String(),
		respondManual(t, "signed", wireBase64(t, returned), nil))

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	submittedMessage, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.ModifyAndSignTransaction(context.Background(), tx)
	testutils.AssertCode(t, err, core.CodeSigningFailed)

	message, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, submittedMessage) {
		t.Error("a rejected result must leave the caller's transaction alone")
	}
}

// Manual mode never reaches "completed" because nobody pushed the transaction,
// so "signed" is the terminal success state.
func TestModifyAndSignTransactionAcceptsTheSignedState(t *testing.T) {
	pub := testutils.TestPublicKey()
	returned, _, signature := rewrittenTransaction(t, pub)
	s := newManualTestSigner(t, manualConfig(t), pub.String(),
		respondManual(t, "signed", wireBase64(t, returned), nil))

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ModifyAndSignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Signature != signature {
		t.Errorf("signature = %s, want %s", res.Signature, signature)
	}
}

// Manual mode does not broadcast, so a failed submit has no on-chain outcome to
// be unconfirmed about and must not push callers into reconciliation.
func TestModifyAndSignTransactionSubmitServerErrorIsNotUnconfirmed(t *testing.T) {
	pub := testutils.TestPublicKey()
	s := newManualTestSigner(t, manualConfig(t), pub.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		})
	})

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ModifyAndSignTransaction(context.Background(), tx)
	testutils.AssertCode(t, err, core.CodeRemoteAPIError)
}

// A manual response with no transaction in it leaves nothing to broadcast.
func TestModifyAndSignTransactionMissingRawTransaction(t *testing.T) {
	pub := testutils.TestPublicKey()
	s := newManualTestSigner(t, manualConfig(t), pub.String(),
		respondManual(t, "signed", "", nil))

	tx, err := testutils.CreateTestTransaction(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ModifyAndSignTransaction(context.Background(), tx)
	testutils.AssertCode(t, err, core.CodeSigningFailed)
}

// Every fmt rendering of the manual signer must omit the access token and the
// P-256 request-signing key material.
func TestNativeManualStringDoesNotLeakSecrets(t *testing.T) {
	cfg := manualConfig(t)
	pemBody := strings.Split(cfg.PrivateKeyPEM, "\n")[1]
	s := newManualTestSigner(t, cfg, testutils.TestPublicKey().String(), nil)

	for _, rendered := range []string{
		fmt.Sprintf("%v", s),
		fmt.Sprintf("%#v", s),
		fmt.Sprintf("%v", *s),
		fmt.Sprintf("%#v", *s),
	} {
		if strings.Contains(rendered, testAccessToken) {
			t.Errorf("rendered signer leaks the access token: %s", rendered)
		}
		if strings.Contains(rendered, pemBody) {
			t.Errorf("rendered signer leaks P-256 key material: %s", rendered)
		}
		if !strings.Contains(rendered, "fordefi.NativeManualSigner") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
	}
}
