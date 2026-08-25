package gcpkms

import (
	"testing"

	"github.com/solana-foundation/solana-keychain/go/testutils"
)

func TestStringDoesNotLeakConfig(t *testing.T) {
	s := newTestSigner(t, &stubKMS{})
	testutils.AssertRedacted(t, s, "gcpkms.Signer", []string{testKeyName}, s.Pubkey().String())
}
