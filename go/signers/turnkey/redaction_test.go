package turnkey

import (
	"fmt"
	"strings"
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
	for _, rendered := range []string{
		fmt.Sprintf("%v", s),
		fmt.Sprintf("%+v", s),
		fmt.Sprintf("%s", s), //nolint:staticcheck // deliberately exercising the %s verb path
		fmt.Sprintf("%#v", s),
	} {
		if strings.Contains(rendered, privHex) {
			t.Errorf("rendered signer leaks the API private key: %s", rendered)
		}
		if !strings.Contains(rendered, "turnkey.Signer") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
	}
}
