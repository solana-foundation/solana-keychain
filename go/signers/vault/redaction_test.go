package vault

import (
	"fmt"
	"strings"
	"testing"
)

func TestStringDoesNotLeakSecrets(t *testing.T) {
	s := newTestSigner(t, testVaultAddr, testPubkey, nil)
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
		if strings.Contains(rendered, testToken) {
			t.Errorf("rendered signer leaks the vault token: %s", rendered)
		}
		if !strings.Contains(rendered, "vault.Signer") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
	}
}
