package memory

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/solana-foundation/solana-keychain/go/testutils"
)

func TestStringDoesNotLeakSecrets(t *testing.T) {
	priv := testutils.TestPrivateKey()
	s, err := New(Config{PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	// Render the seed a few ways a reflective dump could surface it.
	seedFragments := []string{
		fmt.Sprintf("%d %d %d %d", priv[0], priv[1], priv[2], priv[3]),
		base64.StdEncoding.EncodeToString(priv[:8]),
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
		for _, fragment := range seedFragments {
			if strings.Contains(rendered, fragment) {
				t.Errorf("rendered signer leaks private key material: %s", rendered)
			}
		}
		if !strings.Contains(rendered, "memory.Signer") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
		if !strings.Contains(rendered, s.Pubkey().String()) {
			t.Errorf("rendered signer should include the pubkey: %s", rendered)
		}
	}
}
