package fordefi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
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

func cloneManualTestTransaction(tx *solana.Transaction) *solana.Transaction {
	return &solana.Transaction{
		Signatures: append([]solana.Signature(nil), tx.Signatures...),
		Message:    cloneManualMessage(tx.Message),
	}
}

func prependManualComputeBudgetInstruction(tx *solana.Transaction, discriminator byte, value uint64) {
	programIndex := -1
	for i, key := range tx.Message.AccountKeys {
		if key == solana.ComputeBudget {
			programIndex = i
			break
		}
	}
	if programIndex == -1 {
		programIndex = len(tx.Message.AccountKeys)
		tx.Message.AccountKeys = append(tx.Message.AccountKeys, solana.ComputeBudget)
		tx.Message.Header.NumReadonlyUnsignedAccounts++
	}
	data := []byte{discriminator}
	switch discriminator {
	case setComputeUnitLimitDiscriminator:
		data = make([]byte, 5)
		data[0] = discriminator
		binary.LittleEndian.PutUint32(data[1:], uint32(value))
	case setComputeUnitPriceDiscriminator:
		data = make([]byte, 9)
		data[0] = discriminator
		binary.LittleEndian.PutUint64(data[1:], value)
	}
	tx.Message.Instructions = append([]solana.CompiledInstruction{{
		ProgramIDIndex: uint16(programIndex),
		Data:           data,
	}}, tx.Message.Instructions...)
}

func TestValidateManualMessageMutationFeePolicy(t *testing.T) {
	publicKey := testutils.TestPublicKey()
	base := createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionV0)

	t.Run("accepts blockhash and fee insertion", func(t *testing.T) {
		returned := cloneManualTestTransaction(base)
		setManualTestBlockhash(returned, 0x52)
		prependManualComputeBudgetInstruction(returned, setComputeUnitLimitDiscriminator, 300_000)
		prependManualComputeBudgetInstruction(returned, setComputeUnitPriceDiscriminator, 7)
		if err := (&Signer{}).validateManualMessageMutation(base, returned); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("accepts limit adjustment and removal without an original price", func(t *testing.T) {
		original := cloneManualTestTransaction(base)
		prependManualComputeBudgetInstruction(original, setComputeUnitLimitDiscriminator, 200_000)
		adjusted := cloneManualTestTransaction(base)
		prependManualComputeBudgetInstruction(adjusted, setComputeUnitLimitDiscriminator, 400_000)
		if err := (&Signer{}).validateManualMessageMutation(original, adjusted); err != nil {
			t.Fatalf("adjusted limit: %v", err)
		}
		if err := (&Signer{}).validateManualMessageMutation(original, cloneManualTestTransaction(base)); err != nil {
			t.Fatalf("removed limit: %v", err)
		}
	})

	t.Run("preserves non-fee Compute Budget instructions", func(t *testing.T) {
		original := cloneManualTestTransaction(base)
		prependManualComputeBudgetInstruction(original, 1, 0)
		original.Message.Instructions[0].Data = []byte{1, 0, 128, 0, 0}
		returned := cloneManualTestTransaction(original)
		prependManualComputeBudgetInstruction(returned, setComputeUnitPriceDiscriminator, 5)
		if err := (&Signer{}).validateManualMessageMutation(original, returned); err != nil {
			t.Fatal(err)
		}
		returned.Message.Instructions[len(returned.Message.Instructions)-len(base.Message.Instructions)-1].Data[1] ^= 1
		if err := (&Signer{}).validateManualMessageMutation(original, returned); err == nil {
			t.Fatal("expected a changed heap-frame instruction to be rejected")
		}
	})

	t.Run("freezes all fees when the original sets a price", func(t *testing.T) {
		original := cloneManualTestTransaction(base)
		prependManualComputeBudgetInstruction(original, setComputeUnitPriceDiscriminator, 5)
		if err := (&Signer{}).validateManualMessageMutation(original, cloneManualTestTransaction(original)); err != nil {
			t.Fatalf("unchanged caller-supplied price: %v", err)
		}
		returned := cloneManualTestTransaction(base)
		prependManualComputeBudgetInstruction(returned, setComputeUnitPriceDiscriminator, 6)
		if err := (&Signer{}).validateManualMessageMutation(original, returned); err == nil {
			t.Fatal("expected a caller-supplied price mutation to be rejected")
		}
	})

	t.Run("rejects malformed duplicate account-bearing and out-of-range fees", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(*solana.Transaction)
		}{
			{name: "malformed", mutate: func(tx *solana.Transaction) {
				prependManualComputeBudgetInstruction(tx, setComputeUnitLimitDiscriminator, 1)
				tx.Message.Instructions[0].Data = []byte{setComputeUnitLimitDiscriminator, 1}
			}},
			{name: "duplicate", mutate: func(tx *solana.Transaction) {
				prependManualComputeBudgetInstruction(tx, setComputeUnitPriceDiscriminator, 1)
				prependManualComputeBudgetInstruction(tx, setComputeUnitPriceDiscriminator, 2)
			}},
			{name: "account-bearing", mutate: func(tx *solana.Transaction) {
				prependManualComputeBudgetInstruction(tx, setComputeUnitPriceDiscriminator, 1)
				tx.Message.Instructions[0].Accounts = []uint16{0}
			}},
			{name: "out-of-range", mutate: func(tx *solana.Transaction) {
				prependManualComputeBudgetInstruction(tx, setComputeUnitLimitDiscriminator, maxComputeUnitLimit+1)
			}},
			{name: "unknown", mutate: func(tx *solana.Transaction) {
				prependManualComputeBudgetInstruction(tx, 9, 0)
			}},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				returned := cloneManualTestTransaction(base)
				tc.mutate(returned)
				if err := (&Signer{}).validateManualMessageMutation(base, returned); err == nil {
					t.Fatal("expected invalid fee mutation to be rejected")
				}
			})
		}
	})

	t.Run("enforces custom fee constraints", func(t *testing.T) {
		missing := cloneManualTestTransaction(base)
		if err := (&Signer{fee: &Fee{Type: FeeTypeCustom, UnitPrice: "10"}}).
			validateManualMessageMutation(base, missing); err == nil {
			t.Fatal("expected a missing custom unit price to be rejected")
		}
		returned := cloneManualTestTransaction(base)
		prependManualComputeBudgetInstruction(returned, setComputeUnitLimitDiscriminator, 200_000)
		prependManualComputeBudgetInstruction(returned, setComputeUnitPriceDiscriminator, 10)
		if err := (&Signer{fee: &Fee{Type: FeeTypeCustom, UnitPrice: "10", PriorityFee: "2"}}).
			validateManualMessageMutation(base, returned); err != nil {
			t.Fatalf("matching custom fee: %v", err)
		}
		if err := (&Signer{fee: &Fee{Type: FeeTypeCustom, PriorityFee: "1"}}).
			validateManualMessageMutation(base, returned); err == nil {
			t.Fatal("expected effective fee above the cap to be rejected")
		}
		originalPrice := cloneManualTestTransaction(base)
		prependManualComputeBudgetInstruction(originalPrice, setComputeUnitPriceDiscriminator, 10)
		if err := (&Signer{fee: &Fee{Type: FeeTypeCustom, UnitPrice: "11"}}).
			validateManualMessageMutation(originalPrice, cloneManualTestTransaction(originalPrice)); err == nil {
			t.Fatal("expected a caller-supplied price that conflicts with custom unit_price to be rejected")
		}
	})
}

func TestValidateManualFeeCeiling(t *testing.T) {
	payer := solana.MustPublicKeyFromBase58("11111111111111111111111111111112")
	base := createVersionedManualTestTransaction(t, payer, solana.MessageVersionLegacy)

	// ceilingPrice is the largest compute-unit price that still lands on the
	// default ceiling when Fordefi also sets the maximum compute-unit limit.
	const ceilingPrice = DefaultMaxPriorityFeeLamports * microLamportsPerLamport / maxComputeUnitLimit

	withFee := func(signer *Signer, price, limit uint64) error {
		returned := cloneManualTestTransaction(base)
		prependManualComputeBudgetInstruction(returned, setComputeUnitLimitDiscriminator, limit)
		prependManualComputeBudgetInstruction(returned, setComputeUnitPriceDiscriminator, price)
		return signer.validateManualMessageMutation(base, returned)
	}

	t.Run("default ceiling rejects a drain-sized fee in every uncapped mode", func(t *testing.T) {
		for _, fee := range []*Fee{
			nil,
			{Type: FeeTypePriority, PriorityLevel: PriorityHigh},
			{Type: FeeTypeCustom},
		} {
			if err := withFee(&Signer{fee: fee}, math.MaxUint64, maxComputeUnitLimit); err == nil {
				t.Fatalf("expected rejection for fee %+v", fee)
			}
		}
	})

	t.Run("default ceiling allows ordinary and congestion-level fees", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			price uint64
			limit uint64
		}{
			{"ordinary", 1_000_000, 200_000},
			{"congestion", 10_000_000, maxComputeUnitLimit},
			{"exactly at the ceiling", ceilingPrice, maxComputeUnitLimit},
		} {
			if err := withFee(&Signer{}, tc.price, tc.limit); err != nil {
				t.Fatalf("%s: unexpected rejection: %v", tc.name, err)
			}
		}
	})

	t.Run("one micro-lamport past the ceiling is rejected", func(t *testing.T) {
		if err := withFee(&Signer{}, ceilingPrice+1, maxComputeUnitLimit); err == nil {
			t.Fatal("expected rejection just above the default ceiling")
		}
	})

	t.Run("an absent compute-unit limit is charged at the runtime maximum", func(t *testing.T) {
		returned := cloneManualTestTransaction(base)
		prependManualComputeBudgetInstruction(returned, setComputeUnitPriceDiscriminator, ceilingPrice+1)
		if err := (&Signer{}).validateManualMessageMutation(base, returned); err == nil {
			t.Fatal("expected a priceonly fee to be charged at the maximum compute-unit limit")
		}
	})

	t.Run("an explicit ceiling overrides the default in both directions", func(t *testing.T) {
		raised := uint64(10_000_000_000)
		if err := withFee(&Signer{maxPriorityFeeLamports: &raised}, 1_000_000_000, maxComputeUnitLimit); err != nil {
			t.Fatalf("raised ceiling should permit 1.4 SOL: %v", err)
		}
		lowered := uint64(1_000)
		if err := withFee(&Signer{maxPriorityFeeLamports: &lowered}, 1_000_000, 200_000); err == nil {
			t.Fatal("lowered ceiling should reject an otherwise ordinary fee")
		}
	})

	t.Run("a custom priority_fee governs instead of the default ceiling", func(t *testing.T) {
		// 0.42 SOL exceeds the 0.1 SOL default but honors the caller's own bound.
		signer := &Signer{fee: &Fee{Type: FeeTypeCustom, PriorityFee: "500000000"}}
		if err := withFee(signer, 300_000_000, maxComputeUnitLimit); err != nil {
			t.Fatalf("caller-stated bound should govern: %v", err)
		}
		if err := withFee(signer, 400_000_000, maxComputeUnitLimit); err == nil {
			t.Fatal("expected rejection above the caller-stated bound")
		}
	})

	t.Run("an explicit ceiling still applies alongside a custom priority_fee", func(t *testing.T) {
		tight := uint64(1_000)
		signer := &Signer{
			fee:                    &Fee{Type: FeeTypeCustom, PriorityFee: "500000000"},
			maxPriorityFeeLamports: &tight,
		}
		if err := withFee(signer, 300_000_000, maxComputeUnitLimit); err == nil {
			t.Fatal("an explicit ceiling should not be widened by a custom priority_fee")
		}
	})

	t.Run("a caller-authored price is never subject to the ceiling", func(t *testing.T) {
		// The caller set the price themselves, so the message is compared
		// byte-for-byte and Fordefi has no discretion left to bound.
		original := cloneManualTestTransaction(base)
		prependManualComputeBudgetInstruction(original, setComputeUnitLimitDiscriminator, maxComputeUnitLimit)
		prependManualComputeBudgetInstruction(original, setComputeUnitPriceDiscriminator, math.MaxUint64)
		returned := cloneManualTestTransaction(original)
		setManualTestBlockhash(returned, 0x7f)
		if err := (&Signer{}).validateManualMessageMutation(original, returned); err != nil {
			t.Fatalf("caller-authored fee should be accepted: %v", err)
		}
	})

	t.Run("a fee with no price is unaffected", func(t *testing.T) {
		returned := cloneManualTestTransaction(base)
		prependManualComputeBudgetInstruction(returned, setComputeUnitLimitDiscriminator, maxComputeUnitLimit)
		if err := (&Signer{}).validateManualMessageMutation(base, returned); err != nil {
			t.Fatalf("limit-only mutation should be accepted: %v", err)
		}
	})
}

func TestValidateManualMessageMutationRestrictsV1AndDurableNonce(t *testing.T) {
	publicKey := testutils.TestPublicKey()
	signer := &Signer{}

	v1 := createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionV1)
	v1Blockhash := cloneManualTestTransaction(v1)
	setManualTestBlockhash(v1Blockhash, 0x61)
	if err := signer.validateManualMessageMutation(v1, v1Blockhash); err != nil {
		t.Fatalf("v1 blockhash replacement: %v", err)
	}
	v1ConfigChanged := cloneManualTestTransaction(v1Blockhash)
	v1ConfigChanged.Message.TransactionConfig = solana.TransactionConfig{}.WithPriorityFee(99)
	if err := signer.validateManualMessageMutation(v1, v1ConfigChanged); err == nil {
		t.Fatal("expected v1 inline configuration mutation to be rejected")
	}

	nonce := createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
	nonce.Message.Instructions[0].Data = []byte{4, 0, 0, 0}
	if !nonce.UsesDurableNonce() {
		t.Fatal("test transaction must be recognized as durable nonce")
	}
	nonceChanged := cloneManualTestTransaction(nonce)
	setManualTestBlockhash(nonceChanged, 0x62)
	if err := signer.validateManualMessageMutation(nonce, nonceChanged); err == nil {
		t.Fatal("expected durable-nonce lifetime mutation to be rejected")
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
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "manual-tx"})
		})
		mux.HandleFunc(transactionsPath+"/manual-tx", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
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
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "manual-message"})
		})
		mux.HandleFunc(transactionsPath+"/manual-message", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
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
					testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "unexpected"})
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
			name: "changed instruction content",
			makeInput: func(t *testing.T) *solana.Transaction {
				return createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
			},
			makeRaw: func(t *testing.T) string {
				returned := createVersionedManualTestTransaction(t, publicKey, solana.MessageVersionLegacy)
				returned.Message.Instructions[0].Data = append(
					[]byte(nil), returned.Message.Instructions[0].Data...,
				)
				returned.Message.Instructions[0].Data[len(returned.Message.Instructions[0].Data)-1] ^= 0x01
				signManualReturnedTransaction(t, returned, privateKey)
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
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "manual-cancel"})
		})
		mux.HandleFunc(transactionsPath+"/manual-cancel", func(w http.ResponseWriter, _ *http.Request) {
			select {
			case <-polled:
			default:
				close(polled)
			}
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"state": "pending"})
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
	// Cancelling the client abandons the request without the test server seeing
	// a connection close, so the handler's request context never fires. Release
	// it from the test instead: this defer runs before t.Cleanup closes the
	// server, which would otherwise block forever on the in-flight request.
	release := make(chan struct{})
	defer close(release)
	signer := newTestSigner(t, nativeManualConfig(t), publicKey.String(), func(mux *http.ServeMux) {
		mux.HandleFunc(transactionsPath, func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-submitted:
			default:
				close(submitted)
			}
			select {
			case <-r.Context().Done():
			case <-release:
			}
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
			testutils.WriteJSON(w, http.StatusOK, map[string]any{"id": "manual-batch-" + strconv.FormatInt(id, 10)})
		})
		mux.HandleFunc(transactionsPath+"/manual-batch-1", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
				"state":           stateSigned,
				"raw_transaction": returnedRaw[0],
			})
		})
		mux.HandleFunc(transactionsPath+"/manual-batch-2", func(w http.ResponseWriter, _ *http.Request) {
			testutils.WriteJSON(w, http.StatusOK, map[string]any{
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
