package openfort

import (
	"fmt"
	"strings"
	"testing"

	"github.com/solana-foundation/solana-keychain/go/testutils"
)

func TestStringDoesNotLeakSecrets(t *testing.T) {
	s := &Signer{
		secretKey:    testSecretKey,
		accountID:    testAccountID,
		walletSecret: testWalletSecretB64(),
		pubkey:       testutils.TestPublicKey(),
		baseURL:      "https://api.openfort.io",
	}
	for _, rendered := range []string{
		fmt.Sprintf("%v", s),
		fmt.Sprintf("%+v", s),
		fmt.Sprintf("%s", s), //nolint:staticcheck // deliberately exercising the %s verb path
		fmt.Sprintf("%#v", s),
		fmt.Sprintf("%v", *s),
		fmt.Sprintf("%+v", *s),
		fmt.Sprintf("%s", *s), //nolint:staticcheck // deliberately exercising the %s verb path
		fmt.Sprintf("%#v", *s),
	} {
		if strings.Contains(rendered, testSecretKey) || strings.Contains(rendered, testWalletSecretB64()) {
			t.Errorf("rendered signer leaks secrets: %s", rendered)
		}
		if !strings.Contains(rendered, "openfort.Signer") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
	}
}
