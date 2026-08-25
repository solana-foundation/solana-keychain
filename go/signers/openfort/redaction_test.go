package openfort

import (
	"testing"

	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

func TestStringDoesNotLeakSecrets(t *testing.T) {
	s := &Signer{
		secretKey:    testSecretKey,
		accountID:    testAccountID,
		walletSecret: testWalletSecretB64(),
		pubkey:       testutils.TestPublicKey(),
		baseURL:      "https://api.openfort.io",
	}
	testutils.AssertRedacted(t, s, "openfort.Signer", []string{testSecretKey, testWalletSecretB64()})
}
