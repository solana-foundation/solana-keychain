package awskms

import (
	"testing"

	"github.com/solana-foundation/solana-keychain/go/testutils"
)

func TestStringDoesNotLeakConfig(t *testing.T) {
	s := newStubSigner(t, &fakeKMS{})
	testutils.AssertRedacted(t, s, "awskms.Signer", []string{testKeyID}, s.Pubkey().String())
}
