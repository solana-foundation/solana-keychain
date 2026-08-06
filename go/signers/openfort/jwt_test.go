package openfort

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// p256PKCS8DER is a minimal valid P-256 PKCS#8 DER private key whose scalar is
// [0x01; 32] (in the valid range [1, n-1]) — the same fixture the Rust tests use.
var p256PKCS8DER = []byte{
	0x30, 0x41,
	0x02, 0x01, 0x00,
	0x30, 0x13,
	0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
	0x04, 0x27,
	0x30, 0x25,
	0x02, 0x01, 0x01,
	0x04, 0x20,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
}

// testWalletSecretB64 is the bare base64 wallet-secret form — the same shape
// the Openfort dashboard and env vars deliver.
func testWalletSecretB64() string {
	return base64.StdEncoding.EncodeToString(p256PKCS8DER)
}

// testWalletSecretPEM is the same key wrapped in PEM headers — used to
// exercise the PEM-input path.
func testWalletSecretPEM() string {
	return "-----BEGIN PRIVATE KEY-----\n" + testWalletSecretB64() + "\n-----END PRIVATE KEY-----\n"
}

func TestJWTURIFormat(t *testing.T) {
	uri := jwtURI("api.openfort.io", "POST", "/v2/accounts/backend/acc_abc/sign")
	want := "POST api.openfort.io/v2/accounts/backend/acc_abc/sign"
	if uri != want {
		t.Errorf("jwtURI = %q, want %q", uri, want)
	}
}

func TestWalletSecretToPEMPassthroughForPEMInput(t *testing.T) {
	pem := testWalletSecretPEM()
	if got := walletSecretToPEM(pem); got != pem {
		t.Errorf("walletSecretToPEM(pem) = %q, want unchanged input", got)
	}
}

func TestWalletSecretToPEMWrapsBareBase64(t *testing.T) {
	bare := testWalletSecretB64()
	pem := walletSecretToPEM(bare)
	if !strings.HasPrefix(pem, "-----BEGIN PRIVATE KEY-----\n") {
		t.Errorf("wrapped PEM missing BEGIN header: %q", pem)
	}
	if !strings.Contains(pem, bare) {
		t.Error("wrapped PEM should contain the bare base64 body")
	}
	if !strings.HasSuffix(strings.TrimRight(pem, "\n"), "-----END PRIVATE KEY-----") {
		t.Errorf("wrapped PEM missing END header: %q", pem)
	}
	// The wrapped form must still be parseable — exercise it.
	if _, err := parseWalletSecret(bare); err != nil {
		t.Errorf("wrapped PEM should parse: %v", err)
	}
}

func TestWalletSecretToPEMStripsWhitespaceInBareInput(t *testing.T) {
	bare := testWalletSecretB64()
	withWhitespace := " " + bare[:20] + "\n  " + bare[20:] + "  "
	if _, err := parseWalletSecret(withWhitespace); err != nil {
		t.Errorf("whitespaced base64 should still parse: %v", err)
	}
}

func TestParseWalletSecretInvalid(t *testing.T) {
	_, err := parseWalletSecret("not-a-pem-key")
	if err == nil {
		t.Fatal("expected error for invalid wallet secret")
	}
	if code, _ := core.CodeOf(err); code != core.CodeInvalidPrivateKey {
		t.Errorf("got %s, want INVALID_PRIVATE_KEY", code)
	}
}

func TestComputeReqHashSortedIsKeyOrderInvariant(t *testing.T) {
	h1, err := computeReqHash([]byte(`{"a":1,"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	h2, err := computeReqHash([]byte(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("req hash should be key-order invariant: %s != %s", h1, h2)
	}
}
