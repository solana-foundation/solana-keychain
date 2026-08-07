package awskms

import (
	"fmt"
	"strings"
	"testing"
)

func TestStringDoesNotLeakConfig(t *testing.T) {
	s := newStubSigner(t, &fakeKMS{})
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
		if strings.Contains(rendered, testKeyID) {
			t.Errorf("rendered signer leaks the key ARN: %s", rendered)
		}
		if !strings.Contains(rendered, "awskms.Signer") {
			t.Errorf("rendered signer should identify the type: %s", rendered)
		}
		if !strings.Contains(rendered, s.Pubkey().String()) {
			t.Errorf("rendered signer should include the pubkey: %s", rendered)
		}
	}
}
