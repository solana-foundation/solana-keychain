package gcpkms

import (
	"fmt"
	"strings"
	"testing"
)

func TestStringDoesNotLeakConfig(t *testing.T) {
	s := newTestSigner(t, &stubKMS{})
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
		if strings.Contains(rendered, testKeyName) {
			t.Errorf("rendered signer leaks the key resource name: %s", rendered)
		}
		if !strings.Contains(rendered, "gcpkms.Signer") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
		if !strings.Contains(rendered, s.Pubkey().String()) {
			t.Errorf("rendered signer should include the pubkey: %s", rendered)
		}
	}
}
