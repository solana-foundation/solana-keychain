package core

import (
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/solana-foundation/solana-go/v2"
)

// Zcash ZIP-215 vectors the runtime accepts and crypto/ed25519 rejects.
func TestVerifyEd25519AcceptsZIP215Signatures(t *testing.T) {
	cases := []struct {
		name   string
		pubkey string
		sig    string
	}{
		{
			name:   "small order A, mixed order R",
			pubkey: "0100000000000000000000000000000000000000000000000000000000000000",
			sig:    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:   "non-canonical R",
			pubkey: "0100000000000000000000000000000000000000000000000000000000000000",
			sig:    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:   "mixed order A, small order R",
			pubkey: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
			sig:    "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
	}

	message := []byte("Zcash")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pubkeyBytes := mustUnhex(t, tc.pubkey)
			sigBytes := mustUnhex(t, tc.sig)

			var pubkey solana.PublicKey
			copy(pubkey[:], pubkeyBytes)
			var sig solana.Signature
			copy(sig[:], sigBytes)

			if !VerifyEd25519(pubkey, message, sig) {
				t.Fatal("expected ZIP-215 vector to verify")
			}
			if stded25519.Verify(pubkeyBytes, message, sigBytes) {
				t.Fatal("expected the standard library to reject the vector, vectors need refreshing")
			}
		})
	}
}

func mustUnhex(t *testing.T, s string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %s: %v", s, err)
	}
	return decoded
}
