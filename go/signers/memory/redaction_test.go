package memory

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
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
	testutils.AssertRedacted(t, s, "memory.Signer", seedFragments, s.Pubkey().String())
}
