package turnkey

import (
	"testing"

	"github.com/solana-foundation/solana-keychain/go/testutils"
)

func TestStringDoesNotLeakSecrets(t *testing.T) {
	pubHex, privHex, _ := newTestAPIKeys(t)
	s, err := New(Config{
		APIPublicKey:   pubHex,
		APIPrivateKey:  privHex,
		OrganizationID: "test-org-id",
		PrivateKeyID:   "test-key-id",
		PublicKey:      testutils.TestPublicKey().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	testutils.AssertRedacted(t, s, "turnkey.Signer", []string{privHex})
}
