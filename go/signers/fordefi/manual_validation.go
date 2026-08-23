package fordefi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/gagliardetto/solana-go"
)

const (
	setComputeUnitLimitDiscriminator = 2
	setComputeUnitPriceDiscriminator = 3
	maxComputeUnitLimit              = 1_400_000
	microLamportsPerLamport          = 1_000_000
)

type manualFeeInstructions struct {
	hasLimit bool
	limit    uint32
	hasPrice bool
	price    uint64
}

// validateManualMessageMutation accepts only the mutations Fordefi applies to
// an unsigned native transaction: a fresh recent blockhash and, when the
// caller did not set a compute-unit price, the two priority-fee instructions.
func (s *Signer) validateManualMessageMutation(original, returned *solana.Transaction) error {
	if original.Message.GetVersion() != returned.Message.GetVersion() {
		return fmt.Errorf("changed the transaction message version")
	}

	// A nonce value is transaction intent rather than a replaceable recent
	// blockhash. Fordefi documents durable nonces outside its refresh flow.
	if original.UsesDurableNonce() {
		if err := compareManualMessagesExactly(original.Message, returned.Message, false); err != nil {
			return err
		}
		if original.Message.GetVersion() == solana.MessageVersionV1 {
			return nil
		}
		_, originalFee, err := normalizeManualFeeMessage(original.Message)
		if err != nil {
			return fmt.Errorf("original durable-nonce transaction has invalid priority-fee instructions: %w", err)
		}
		return s.validateManualCustomFee(originalFee)
	}

	// V1 carries its compute budget inline. Fordefi's current mutation path is
	// instruction-based, so every v1 field except the lifetime hash is immutable.
	if original.Message.GetVersion() == solana.MessageVersionV1 {
		return compareManualMessagesExactly(original.Message, returned.Message, true)
	}

	normalizedOriginal, originalFee, err := normalizeManualFeeMessage(original.Message)
	if err != nil {
		return fmt.Errorf("original transaction has invalid priority-fee instructions: %w", err)
	}
	if originalFee.hasPrice {
		if err := compareManualMessagesExactly(original.Message, returned.Message, true); err != nil {
			return err
		}
		return s.validateManualCustomFee(originalFee)
	}

	normalizedReturned, returnedFee, err := normalizeManualFeeMessage(returned.Message)
	if err != nil {
		return fmt.Errorf("returned transaction has invalid priority-fee instructions: %w", err)
	}
	// The caller set no compute-unit price, so any price here is Fordefi's own
	// and is bounded by the absolute ceiling as well as any custom fee config.
	if err := s.validateManualFeeCeiling(returnedFee); err != nil {
		return err
	}
	if err := s.validateManualCustomFee(returnedFee); err != nil {
		return err
	}

	normalizedReturned.RecentBlockhash = normalizedOriginal.RecentBlockhash
	originalBytes, err := normalizedOriginal.MarshalBinary()
	if err != nil {
		return fmt.Errorf("serialize normalized original message: %w", err)
	}
	returnedBytes, err := normalizedReturned.MarshalBinary()
	if err != nil {
		return fmt.Errorf("serialize normalized returned message: %w", err)
	}
	if !bytes.Equal(originalBytes, returnedBytes) {
		return fmt.Errorf("changed transaction content outside the recent blockhash and priority fee")
	}
	return nil
}

func compareManualMessagesExactly(original, returned solana.Message, replaceableBlockhash bool) error {
	if replaceableBlockhash {
		returned.RecentBlockhash = original.RecentBlockhash
	}
	originalBytes, err := original.MarshalBinary()
	if err != nil {
		return fmt.Errorf("serialize original message: %w", err)
	}
	returnedBytes, err := returned.MarshalBinary()
	if err != nil {
		return fmt.Errorf("serialize returned message: %w", err)
	}
	if !bytes.Equal(originalBytes, returnedBytes) {
		return fmt.Errorf("changed transaction content outside the permitted fields")
	}
	return nil
}

// normalizeManualFeeMessage removes only SetComputeUnitLimit and
// SetComputeUnitPrice. All other Compute Budget instructions remain in place
// and are covered by the final byte-for-byte comparison.
func normalizeManualFeeMessage(message solana.Message) (solana.Message, manualFeeInstructions, error) {
	normalized := cloneManualMessage(message)
	var fee manualFeeInstructions
	kept := make([]solana.CompiledInstruction, 0, len(normalized.Instructions))

	for _, instruction := range normalized.Instructions {
		if int(instruction.ProgramIDIndex) >= len(normalized.AccountKeys) ||
			normalized.AccountKeys[instruction.ProgramIDIndex] != solana.ComputeBudget ||
			len(instruction.Data) == 0 ||
			(instruction.Data[0] != setComputeUnitLimitDiscriminator &&
				instruction.Data[0] != setComputeUnitPriceDiscriminator) {
			kept = append(kept, instruction)
			continue
		}
		if len(instruction.Accounts) != 0 {
			return solana.Message{}, manualFeeInstructions{}, fmt.Errorf("fee instruction has accounts")
		}

		switch instruction.Data[0] {
		case setComputeUnitLimitDiscriminator:
			if fee.hasLimit {
				return solana.Message{}, manualFeeInstructions{}, fmt.Errorf("duplicate SetComputeUnitLimit")
			}
			if len(instruction.Data) != 5 {
				return solana.Message{}, manualFeeInstructions{}, fmt.Errorf("malformed SetComputeUnitLimit")
			}
			fee.limit = binary.LittleEndian.Uint32(instruction.Data[1:])
			if fee.limit == 0 || fee.limit > maxComputeUnitLimit {
				return solana.Message{}, manualFeeInstructions{}, fmt.Errorf("SetComputeUnitLimit is out of range")
			}
			fee.hasLimit = true
		case setComputeUnitPriceDiscriminator:
			if fee.hasPrice {
				return solana.Message{}, manualFeeInstructions{}, fmt.Errorf("duplicate SetComputeUnitPrice")
			}
			if len(instruction.Data) != 9 {
				return solana.Message{}, manualFeeInstructions{}, fmt.Errorf("malformed SetComputeUnitPrice")
			}
			fee.price = binary.LittleEndian.Uint64(instruction.Data[1:])
			fee.hasPrice = true
		}
	}
	normalized.Instructions = kept
	pruneUnusedComputeBudgetKey(&normalized)
	return normalized, fee, nil
}

func cloneManualMessage(message solana.Message) solana.Message {
	cloned := message
	cloned.AccountKeys = append(solana.PublicKeySlice(nil), message.AccountKeys...)
	cloned.Instructions = make([]solana.CompiledInstruction, len(message.Instructions))
	for i, instruction := range message.Instructions {
		cloned.Instructions[i] = instruction
		cloned.Instructions[i].Accounts = append([]uint16(nil), instruction.Accounts...)
		cloned.Instructions[i].Data = append([]byte(nil), instruction.Data...)
	}
	cloned.AddressTableLookups = append(solana.MessageAddressTableLookupSlice(nil), message.AddressTableLookups...)
	for i, lookup := range message.AddressTableLookups {
		cloned.AddressTableLookups[i].WritableIndexes = append(solana.Uint8SliceAsNum(nil), lookup.WritableIndexes...)
		cloned.AddressTableLookups[i].ReadonlyIndexes = append(solana.Uint8SliceAsNum(nil), lookup.ReadonlyIndexes...)
	}
	return cloned
}

func pruneUnusedComputeBudgetKey(message *solana.Message) {
	keyIndex := -1
	for i, key := range message.AccountKeys {
		if key == solana.ComputeBudget {
			if keyIndex != -1 {
				return // Duplicate keys are retained so the exact comparison rejects them.
			}
			keyIndex = i
		}
	}
	if keyIndex == -1 || !isReadonlyUnsignedKey(message, keyIndex) {
		return
	}
	for _, instruction := range message.Instructions {
		if int(instruction.ProgramIDIndex) == keyIndex {
			return
		}
		for _, accountIndex := range instruction.Accounts {
			if int(accountIndex) == keyIndex {
				return
			}
		}
	}

	message.AccountKeys = append(message.AccountKeys[:keyIndex], message.AccountKeys[keyIndex+1:]...)
	message.Header.NumReadonlyUnsignedAccounts--
	for i := range message.Instructions {
		if int(message.Instructions[i].ProgramIDIndex) > keyIndex {
			message.Instructions[i].ProgramIDIndex--
		}
		for j, accountIndex := range message.Instructions[i].Accounts {
			if int(accountIndex) > keyIndex {
				message.Instructions[i].Accounts[j]--
			}
		}
	}
}

func isReadonlyUnsignedKey(message *solana.Message, index int) bool {
	if message.Header.NumReadonlyUnsignedAccounts == 0 || index < int(message.Header.NumRequiredSignatures) {
		return false
	}
	firstReadonlyUnsigned := len(message.AccountKeys) - int(message.Header.NumReadonlyUnsignedAccounts)
	return index >= firstReadonlyUnsigned
}

func (s *Signer) validateManualCustomFee(fee manualFeeInstructions) error {
	if s.fee == nil || s.fee.Type != FeeTypeCustom {
		return nil
	}
	if s.fee.UnitPrice != "" {
		expected, ok := new(big.Int).SetString(s.fee.UnitPrice, 10)
		if !ok || expected.Sign() < 0 || !fee.hasPrice ||
			expected.Cmp(new(big.Int).SetUint64(fee.price)) != 0 {
			return fmt.Errorf("returned compute-unit price does not match the configured custom unit_price")
		}
	}
	if s.fee.PriorityFee != "" && fee.hasPrice {
		maximum, ok := new(big.Int).SetString(s.fee.PriorityFee, 10)
		if !ok || maximum.Sign() < 0 {
			return fmt.Errorf("configured custom priority_fee is invalid")
		}
		if effectiveManualPriorityFeeLamports(fee).Cmp(maximum) > 0 {
			return fmt.Errorf("returned priority fee exceeds the configured custom priority_fee")
		}
	}
	return nil
}

// effectiveManualPriorityFeeLamports converts a compute-unit price into the
// lamports it can actually cost, rounding up. A message with no explicit limit
// is charged at the maximum the runtime allows.
func effectiveManualPriorityFeeLamports(fee manualFeeInstructions) *big.Int {
	limit := uint64(maxComputeUnitLimit)
	if fee.hasLimit {
		limit = uint64(fee.limit)
	}
	effective := new(big.Int).Mul(new(big.Int).SetUint64(fee.price), new(big.Int).SetUint64(limit))
	effective.Add(effective, big.NewInt(microLamportsPerLamport-1))
	return effective.Div(effective, big.NewInt(microLamportsPerLamport))
}

// manualPriorityFeeCeiling reports the absolute lamport bound for a
// Fordefi-introduced priority fee, or nil when the caller already stated their
// own total bound through a custom priority_fee.
func (s *Signer) manualPriorityFeeCeiling() *big.Int {
	if s.maxPriorityFeeLamports != nil {
		return new(big.Int).SetUint64(*s.maxPriorityFeeLamports)
	}
	if s.fee != nil && s.fee.Type == FeeTypeCustom && s.fee.PriorityFee != "" {
		return nil
	}
	return new(big.Int).SetUint64(DefaultMaxPriorityFeeLamports)
}

// validateManualFeeCeiling bounds a priority fee Fordefi introduced on its own
// initiative, so a compromised or malfunctioning response cannot drain the fee
// payer even when no custom fee bound is configured.
func (s *Signer) validateManualFeeCeiling(fee manualFeeInstructions) error {
	if !fee.hasPrice {
		return nil
	}
	ceiling := s.manualPriorityFeeCeiling()
	if ceiling == nil {
		return nil
	}
	effective := effectiveManualPriorityFeeLamports(fee)
	if effective.Cmp(ceiling) > 0 {
		return fmt.Errorf(
			"returned priority fee of %s lamports exceeds the %s lamport ceiling; raise Config.MaxPriorityFeeLamports to allow it",
			effective, ceiling)
	}
	return nil
}
