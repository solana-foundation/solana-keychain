package vault

import (
	"testing"

	"github.com/solana-foundation/solana-keychain/go/testutils"
)

func TestStringDoesNotLeakSecrets(t *testing.T) {
	s := newTestSigner(t, testVaultAddr, testPubkey, nil)
	testutils.AssertRedacted(t, s, "vault.Signer", []string{testToken})
}
