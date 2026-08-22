package fordefi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
	"github.com/solana-foundation/solana-keychain/go/testutils"
)

func nativeManualConfig(t *testing.T) Config {
	t.Helper()
	cfg := nativeConfig(t)
	cfg.PushMode = PushModeManual
	return cfg
}

func createVersionedManualTestTransaction(t *testing.T, payer solana.PublicKey, version solana.MessageVersion) *solana.Transaction {
	t.Helper()
	var (
		tx  *solana.Transaction
		err error
	)
	if version == solana.MessageVersionV1 {
		tx, err = testutils.CreateTestV1Transaction(payer)
	} else {
		tx, err = testutils.CreateTestTransaction(payer)
	}
	if err != nil {
		t.Fatal(err)
	}
	if version == solana.MessageVersionV0 {
		message, setErr := tx.Message.SetVersion(solana.MessageVersionV0)
		if setErr != nil {
			t.Fatal(setErr)
		}
		tx.Message = *message
	}
	return tx
}

func setManualTestBlockhash(tx *solana.Transaction, marker byte) {
	for i := range tx.Message.RecentBlockhash {
		tx.Message.RecentBlockhash[i] = marker
	}
}

func signManualReturnedTransaction(t *testing.T, tx *solana.Transaction, privateKey ed25519.PrivateKey) solana.Signature {
	t.Helper()
	message, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	signature := solana.SignatureFromBytes(ed25519.Sign(privateKey, message))
	numRequired := int(tx.Message.Header.NumRequiredSignatures)
	tx.Signatures = make([]solana.Signature, numRequired)
	tx.Signatures[0] = signature
	return signature
}

func encodeManualReturnedTransaction(t *testing.T, tx *solana.Transaction) string {
	t.Helper()
	wire, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(wire)
}

func manualResponse(state, rawTransaction string, inspect func(*http.Request)) func(*http.ServeMux) {
	return func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, r *http.Request) {
			if inspect != nil {
				inspect(r)
			}
			writeJSON(w, map[string]any{"id": "manual-tx"})
		})
		mux.HandleFunc(transactionsPath+"/manual-tx", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{
				"state":           state,
				"raw_transaction": rawTransaction,
			})
		})
	}
}

func transactionWire(t *testing.T, tx *solana.Transaction) []byte {
	t.Helper()
	wire, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func assertErrorCode(t *testing.T, err error, want core.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error", want)
	}
	if code, ok := core.CodeOf(err); !ok || code != want {
		t.Fatalf("got code %q (ok=%v), want %s: %v", code, ok, want, err)
	}
	if code, _ := core.CodeOf(err); code == core.CodeBroadcastUnconfirmed {
		t.Fatal("manual signing errors must never be broadcast-unconfirmed")
	}
}

func assertManualFailureLeavesTransactionUntouched(
	t *testing.T,
	tx *solana.Transaction,
	call func() error,
	wantCode core.Code,
) {
	t.Helper()
	before := transactionWire(t, tx)
	err := call()
	assertErrorCode(t, err, wantCode)
	after := transactionWire(t, tx)
	if !bytes.Equal(after, before) {
		t.Error("failed manual signing must leave the caller transaction untouched")
	}
}

func TestSignTransactionNativeManualReplacesSupportedVersions(t *testing.T) {
	versions := []struct {
		name    string
		version solana.MessageVersion
		state   string
	}{
		{name: "legacy signed", version: solana.MessageVersionLegacy, state: stateSigned},
		{name: "v0 completed", version: solana.MessageVersionV0, state: stateCompleted},
		{name: "v1 signed", version: solana.MessageVersionV1, state: stateSigned},
	}

	for i, tc := range versions {
		t.Run(tc.name, func(t *testing.T) {
			privateKey := testutils.TestPrivateKey()
			publicKey := testutils.TestPublicKey()
			input := createVersionedManualTestTransaction(t, publicKey, tc.version)
			inputMessage, err := input.Message.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			returned := createVersionedManualTestTransaction(t, publicKey, tc.version)
			setManualTestBlockhash(returned, byte(0x30+i))
			wantSignature := signManualReturnedTransaction(t, returned, privateKey)
			returnedWire := transactionWire(t, returned)

			cfg := nativeManualConfig(t)
			cfg.Fee = &Fee{Type: FeeTypePriority, PriorityLevel: PriorityMedium}
			signer := newTestSigner(t, cfg, publicKey.String(), manualResponse(
				tc.state,
				base64.StdEncoding.EncodeToString(returnedWire),
				func(r *http.Request) {
					body, readErr := io.ReadAll(r.Body)
					if readErr != nil {
						t.Errorf("read request: %v", readErr)
						return
					}
					var request map[string]any
					if err := json.Unmarshal(body, &request); err != nil {
						t.Errorf("request body should be JSON: %v", err)
						return
					}
					if request["type"] != "solana_transaction" || request["sign_mode"] != "auto" {
						t.Errorf("unexpected request envelope: %v", request)
					}
					details, _ := request["details"].(map[string]any)
					if details["type"] != "solana_serialized_transaction_message" ||
						details["chain"] != string(ChainSolanaDevnet) ||
						details["push_mode"] != string(PushModeManual) ||
						details["data"] != base64.StdEncoding.EncodeToString(inputMessage) {
						t.Errorf("unexpected manual details: %v", details)
					}
					fee, _ := details["fee"].(map[string]any)
					if fee["type"] != FeeTypePriority || fee["priority_level"] != string(PriorityMedium) {
						t.Errorf("unexpected manual fee: %v", fee)
					}
					idempotencyInput := append(
						[]byte("fordefi:solana:manual:"+string(ChainSolanaDevnet)+":"+testVaultID+":"),
						inputMessage...,
					)
					wantID := core.IdempotencyKeyFromMessage(idempotencyInput)
					if got := r.Header.Get("x-idempotence-id"); got != wantID {
						t.Errorf("x-idempotence-id = %q, want %q", got, wantID)
					}
					if wantID == core.IdempotencyKeyFromMessage(inputMessage) {
						t.Error("manual and auto idempotency keys must be mode-separated")
					}
				},
			))

			result, err := signer.SignTransaction(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsComplete() {
				t.Error("sole-signer manual result must be Complete")
			}
			if result.Signature != wantSignature {
				t.Errorf("signature = %s, want %s", result.Signature, wantSignature)
			}
			if result.EncodedTransaction == "" {
				t.Fatal("manual mode must return a non-empty encoded transaction")
			}
			if result.EncodedTransaction != base64.StdEncoding.EncodeToString(returnedWire) {
				t.Error("manual result must contain the canonical Fordefi-returned transaction")
			}
			if !bytes.Equal(transactionWire(t, input), returnedWire) {
				t.Error("manual mode must replace the caller transaction")
			}
			returnedMessage, err := input.Message.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !core.VerifyEd25519(publicKey, returnedMessage, result.Signature) {
				t.Error("manual signature must verify against the returned message")
			}
			if bytes.Equal(returnedMessage, inputMessage) {
				t.Error("test response should exercise a provider-modified message")
			}
			if input.Message.GetVersion() != tc.version {
				t.Errorf("returned version = %v, want %v", input.Message.GetVersion(), tc.version)
			}
		})
	}
}

func deterministicDownstreamKey() (solana.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x55
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return solana.PublicKeyFromBytes(privateKey.Public().(ed25519.PublicKey)), privateKey
}

func makeManualMultisignerTransaction(t *testing.T, payer, downstream solana.PublicKey) *solana.Transaction {
	t.Helper()
	tx := createVersionedManualTestTransaction(t, payer, solana.MessageVersionLegacy)
	tx.Message.Header.NumRequiredSignatures = 2
	tx.Message.AccountKeys = append(
		solana.PublicKeySlice{payer, downstream},
		tx.Message.AccountKeys[1:]...,
	)
	return tx
}

func TestSignTransactionNativeManualReturnsPartialMultisigner(t *testing.T) {
	privateKey := testutils.TestPrivateKey()
	publicKey := testutils.TestPublicKey()
	downstream, downstreamPrivateKey := deterministicDownstreamKey()
	input := makeManualMultisignerTransaction(t, publicKey, downstream)
	returned := makeManualMultisignerTransaction(t, publicKey, downstream)
	setManualTestBlockhash(returned, 0x44)
	wantSignature := signManualReturnedTransaction(t, returned, privateKey)

	signer := newTestSigner(t, nativeManualConfig(t), publicKey.String(), manualResponse(
		stateSigned,
		encodeManualReturnedTransaction(t, returned),
		nil,
	))
	result, err := signer.SignTransaction(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsComplete() {
		t.Error("manual multisigner result must be Partial")
	}
	if result.Signature != wantSignature || input.Signatures[0] != wantSignature {
		t.Error("manual result must carry the Fordefi signature in slot zero")
	}
	if len(input.Signatures) != 2 || !input.Signatures[1].IsZero() {
		t.Error("downstream signature slot must remain intact and unsigned")
	}
	message, err := input.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	downstreamSignature := solana.SignatureFromBytes(ed25519.Sign(downstreamPrivateKey, message))
	if err := core.AddSignature(input, downstream, downstreamSignature); err != nil {
		t.Fatal(err)
	}
	if !core.HasAllRequiredSignatures(input) {
		t.Error("a downstream signer must be able to complete the returned transaction")
	}
}

func TestSignMessageNativeManualStillUsesSolanaMessage(t *testing.T) {
	privateKey := testutils.TestPrivateKey()
	publicKey := testutils.TestPublicKey()
	message := []byte("manual native message")
	signature := ed25519.Sign(privateKey, message)

	signer := newTestSigner(t, nativeManualConfig(t), publicKey.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var request map[string]any
			_ = json.Unmarshal(body, &request)
			if request["type"] != "solana_message" {
				t.Errorf("type = %v, want solana_message", request["type"])
			}
			details, _ := request["details"].(map[string]any)
			if details["raw_data"] != base64.StdEncoding.EncodeToString(message) {
				t.Errorf("unexpected message details: %v", details)
			}
			writeJSON(w, map[string]any{"id": "manual-message"})
		})
		mux.HandleFunc(transactionsPath+"/manual-message", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{
				"state":      stateSigned,
				"signatures": []map[string]string{{"data": base64.StdEncoding.EncodeToString(signature)}},
			})
		})
	})

	got, err := signer.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if got != solana.SignatureFromBytes(signature) {
		t.Error("manual-mode native message signature mismatch")
	}
}

func TestSignTransactionNativeManualRejectsInvalidInputsBeforePost(t *testing.T) {
	publicKey := testutils.TestPublicKey()
	cases := []struct {
		name   string
		makeTx func(*testing.T) *solana.Transaction
	}{
		{
			name: "pre-signed",
			makeTx: func(t *testing.T) *solana.Transaction {
				tx := createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
				tx.Signatures = []solana.Signature{{1}}
				return tx
			},
		},
		{
			name: "non-Fordefi fee payer",
			makeTx: func(t *testing.T) *solana.Transaction {
				downstream, _ := deterministicDownstreamKey()
				return createVersionedManualTestTransaction(t, downstream, solana.MessageVersionLegacy)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var posts atomic.Int64
			signer := newTestSigner(t, nativeManualConfig(t), publicKey.String(), func(mux *http.ServeMux) {
				mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
					posts.Add(1)
					writeJSON(w, map[string]any{"id": "unexpected"})
				})
			})
			tx := tc.makeTx(t)
			assertManualFailureLeavesTransactionUntouched(t, tx, func() error {
				_, err := signer.SignTransaction(context.Background(), tx)
				return err
			}, core.CodeSigningFailed)
			if got := posts.Load(); got != 0 {
				t.Errorf("invalid input reached Fordefi: %d POST requests", got)
			}
		})
	}
}

func TestSignTransactionNativeManualRejectsInvalidReturnedTransactions(t *testing.T) {
	privateKey := testutils.TestPrivateKey()
	publicKey := testutils.TestPublicKey()
	downstream, downstreamPrivateKey := deterministicDownstreamKey()

	tests := []struct {
		name      string
		makeInput func(*testing.T) *solana.Transaction
		makeRaw   func(*testing.T) string
		wantCode  core.Code
	}{
		{
			name: "missing raw transaction",
			makeInput: func(t *testing.T) *solana.Transaction {
				return createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
			},
			makeRaw:  func(*testing.T) string { return "" },
			wantCode: core.CodeSigningFailed,
		},
		{
			name: "malformed base64",
			makeInput: func(t *testing.T) *solana.Transaction {
				return createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
			},
			makeRaw:  func(*testing.T) string { return "%%%" },
			wantCode: core.CodeSerializationError,
		},
		{
			name: "malformed wire transaction",
			makeInput: func(t *testing.T) *solana.Transaction {
				return createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
			},
			makeRaw: func(*testing.T) string {
				return base64.StdEncoding.EncodeToString([]byte{0xff, 0xff})
			},
			wantCode: core.CodeSerializationError,
		},
		{
			name: "oversized wire transaction",
			makeInput: func(t *testing.T) *solana.Transaction {
				return createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
			},
			makeRaw: func(*testing.T) string {
				return base64.StdEncoding.EncodeToString(make([]byte, solanaPacketDataSize+1))
			},
			wantCode: core.CodeSerializationError,
		},
		{
			name: "changed signer set",
			makeInput: func(t *testing.T) *solana.Transaction {
				return createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
			},
			makeRaw: func(t *testing.T) string {
				returned := createVersionedManualTestTransaction(t, downstream, solana.MessageVersionLegacy)
				signManualReturnedTransaction(t, returned, downstreamPrivateKey)
				return encodeManualReturnedTransaction(t, returned)
			},
			wantCode: core.CodeSigningFailed,
		},
		{
			name: "invalid signature slot count",
			makeInput: func(t *testing.T) *solana.Transaction {
				return createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
			},
			makeRaw: func(t *testing.T) string {
				returned := createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
				signature := signManualReturnedTransaction(t, returned, privateKey)
				returned.Signatures = []solana.Signature{signature, {}}
				return encodeManualReturnedTransaction(t, returned)
			},
			wantCode: core.CodeSigningFailed,
		},
		{
			name: "missing vault signature",
			makeInput: func(t *testing.T) *solana.Transaction {
				return createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
			},
			makeRaw: func(t *testing.T) string {
				returned := createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
				returned.Signatures = []solana.Signature{{}}
				return encodeManualReturnedTransaction(t, returned)
			},
			wantCode: core.CodeSigningFailed,
		},
		{
			name: "invalid vault signature",
			makeInput: func(t *testing.T) *solana.Transaction {
				return createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
			},
			makeRaw: func(t *testing.T) string {
				returned := createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
				returned.Signatures = []solana.Signature{{1}}
				return encodeManualReturnedTransaction(t, returned)
			},
			wantCode: core.CodeSigningFailed,
		},
		{
			name: "populated downstream signature",
			makeInput: func(t *testing.T) *solana.Transaction {
				return makeManualMultisignerTransaction(t, publicKey, downstream)
			},
			makeRaw: func(t *testing.T) string {
				returned := makeManualMultisignerTransaction(t, publicKey, downstream)
				signManualReturnedTransaction(t, returned, privateKey)
				message, err := returned.Message.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				returned.Signatures[1] = solana.SignatureFromBytes(ed25519.Sign(downstreamPrivateKey, message))
				return encodeManualReturnedTransaction(t, returned)
			},
			wantCode: core.CodeSigningFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tx := tc.makeInput(t)
			signer := newTestSigner(t, nativeManualConfig(t), publicKey.String(), manualResponse(
				stateSigned,
				tc.makeRaw(t),
				nil,
			))
			assertManualFailureLeavesTransactionUntouched(t, tx, func() error {
				_, err := signer.SignTransaction(context.Background(), tx)
				return err
			}, tc.wantCode)
		})
	}
}

func TestSignTransactionNativeManualErrorsAreNeverBroadcastUnconfirmed(t *testing.T) {
	publicKey := testutils.TestPublicKey()
	tests := []struct {
		name      string
		configure func(*http.ServeMux)
		wantCode  core.Code
	}{
		{
			name: "submit failure",
			configure: func(mux *http.ServeMux) {
				mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusBadGateway)
				})
			},
			wantCode: core.CodeRemoteAPIError,
		},
		{
			name:      "terminal failure",
			configure: respondSigned(t, "error_signing", nil),
			wantCode:  core.CodeSigningFailed,
		},
		{
			name:      "polling timeout",
			configure: respondSigned(t, "pending", nil),
			wantCode:  core.CodeRemoteAPIError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tx := createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
			signer := newTestSigner(t, nativeManualConfig(t), publicKey.String(), tc.configure)
			assertManualFailureLeavesTransactionUntouched(t, tx, func() error {
				_, err := signer.SignTransaction(context.Background(), tx)
				return err
			}, tc.wantCode)
		})
	}
}

func TestSignTransactionNativeManualPollingCancellationIsOrdinaryHTTPError(t *testing.T) {
	publicKey := testutils.TestPublicKey()
	polled := make(chan struct{})
	signer := newTestSigner(t, nativeManualConfig(t), publicKey.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"id": "manual-cancel"})
		})
		mux.HandleFunc(transactionsPath+"/manual-cancel", func(w http.ResponseWriter, _ *http.Request) {
			select {
			case <-polled:
			default:
				close(polled)
			}
			writeJSON(w, map[string]any{"state": "pending"})
		})
	})
	signer.pollInterval = time.Hour
	tx := createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := signer.SignTransaction(ctx, tx)
		done <- err
	}()
	select {
	case <-polled:
		cancel()
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("manual signing never reached polling")
	}
	select {
	case err := <-done:
		assertErrorCode(t, err, core.CodeHTTPError)
		if !errors.Is(err, context.Canceled) {
			t.Error("polling cancellation must retain context.Canceled in the error chain")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("manual polling did not stop after context cancellation")
	}
}

func TestSignTransactionNativeManualSubmissionCancellationIsOrdinaryHTTPError(t *testing.T) {
	publicKey := testutils.TestPublicKey()
	submitted := make(chan struct{})
	signer := newTestSigner(t, nativeManualConfig(t), publicKey.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-submitted:
			default:
				close(submitted)
			}
			<-r.Context().Done()
		})
	})
	tx := createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
	before := transactionWire(t, tx)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := signer.SignTransaction(ctx, tx)
		done <- err
	}()
	select {
	case <-submitted:
		cancel()
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("manual signing never reached submission")
	}
	select {
	case err := <-done:
		assertErrorCode(t, err, core.CodeHTTPError)
		if !errors.Is(err, context.Canceled) {
			t.Error("submission cancellation must retain context.Canceled in the error chain")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("manual submission did not stop after context cancellation")
	}
	if !bytes.Equal(transactionWire(t, tx), before) {
		t.Error("cancelled manual submission must leave the caller transaction untouched")
	}
}

func TestSignTransactionsBatchesNativeManualResults(t *testing.T) {
	privateKey := testutils.TestPrivateKey()
	publicKey := testutils.TestPublicKey()
	inputs := []*solana.Transaction{
		createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy),
		createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy),
	}
	setManualTestBlockhash(inputs[0], 0x11)
	setManualTestBlockhash(inputs[1], 0x22)
	returned := []*solana.Transaction{
		createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy),
		createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy),
	}
	setManualTestBlockhash(returned[0], 0x33)
	setManualTestBlockhash(returned[1], 0x44)
	for _, tx := range returned {
		signManualReturnedTransaction(t, tx, privateKey)
	}
	returnedRaw := []string{
		encodeManualReturnedTransaction(t, returned[0]),
		encodeManualReturnedTransaction(t, returned[1]),
	}

	var creates atomic.Int64
	signer := newTestSigner(t, nativeManualConfig(t), publicKey.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(w http.ResponseWriter, _ *http.Request) {
			id := creates.Add(1)
			writeJSON(w, map[string]any{"id": "manual-batch-" + strconv.FormatInt(id, 10)})
		})
		mux.HandleFunc(transactionsPath+"/manual-batch-1", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{
				"state":           stateSigned,
				"raw_transaction": returnedRaw[0],
			})
		})
		mux.HandleFunc(transactionsPath+"/manual-batch-2", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{
				"state":           stateCompleted,
				"raw_transaction": returnedRaw[1],
			})
		})
	})

	results, err := core.SignTransactions(context.Background(), signer, inputs, core.BatchOptions{
		MaxConcurrency: 1,
		RequestDelay:   time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || creates.Load() != 2 {
		t.Fatalf("got %d results and %d creates, want 2 and 2", len(results), creates.Load())
	}
	for i := range results {
		if !results[i].IsComplete() || results[i].EncodedTransaction == "" {
			t.Errorf("batch result %d must be a complete, encoded manual transaction", i)
		}
		if !bytes.Equal(transactionWire(t, inputs[i]), transactionWire(t, returned[i])) {
			t.Errorf("batch transaction %d was not replaced in order", i)
		}
	}
}

func TestPushModeStringValues(t *testing.T) {
	if string(PushModeAuto) != "auto" || string(PushModeManual) != "manual" {
		t.Fatalf("unexpected push mode values: auto=%q manual=%q", PushModeAuto, PushModeManual)
	}
	if strings.TrimSpace(string(PushModeManual)) != string(PushModeManual) {
		t.Error("manual push mode must be serialized without whitespace")
	}
}
