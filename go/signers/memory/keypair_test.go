package memory

import (
	"testing"

	"github.com/solana-foundation/solana-keychain/go/core"
)

func TestPrivateKeyFromBytesInvalidLength(t *testing.T) {
	_, err := privateKeyFromBytes(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
	if code, _ := core.CodeOf(err); code != core.CodeInvalidPrivateKey {
		t.Errorf("got %s, want INVALID_PRIVATE_KEY", code)
	}
}

func TestPrivateKeyFromStringInvalid(t *testing.T) {
	if _, err := privateKeyFromString("not valid base58 !!!"); err == nil {
		t.Error("expected error for invalid base58 string")
	}
	if _, err := privateKeyFromString("[1,2,3]"); err == nil {
		t.Error("expected error for too-short u8 array")
	}
}

// Canonical cross-language test vector shared with the Rust (memory/mod.rs) and
// TypeScript suites. Parsing either encoding MUST yield this exact pubkey — this
// is the authoritative proof that Go's key handling (seed‖pubkey interpretation
// and base58 encoding) matches the other two implementations byte-for-byte.
const (
	canonicalKeypairU8Array = "[41,99,180,88,51,57,48,80,61,63,219,75,176,49,116,254,227,176,196,204,122,47,166,133,155,252,217,0,253,17,49,143,47,94,121,167,195,136,72,22,157,48,77,88,63,96,57,122,181,243,236,188,241,134,174,224,100,246,17,170,104,17,151,48]"
	canonicalKeypairBase58  = "pzjkwgQ5shhq3Awijz6CjDjZrXPX7YKKgkTipBK7JAq8XW5GbDynBFChESMBrz4SvFiZ8qJAtUB6sL3PpVCnbR1"
	canonicalPubkey         = "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR"
)

func TestCanonicalVectorParity(t *testing.T) {
	for name, key := range map[string]string{
		"u8 array": canonicalKeypairU8Array,
		"base58":   canonicalKeypairBase58,
	} {
		t.Run(name, func(t *testing.T) {
			s, err := New(Config{PrivateKeyString: key})
			if err != nil {
				t.Fatal(err)
			}
			if got := s.Pubkey().String(); got != canonicalPubkey {
				t.Errorf("pubkey = %s, want canonical %s", got, canonicalPubkey)
			}
		})
	}
}
