package core

import (
	"errors"
	"net/http"
	"testing"
)

// NewHTTPClient must refuse to follow any redirect: replaying auth headers
// (X-Vault-Token, privy-app-id, ...) against a host chosen by the response
// would leak credentials, and the TS fetchSignerJson uses redirect: 'error'.
func TestCheckRedirectRejectsAllRedirects(t *testing.T) {
	client := NewHTTPClient(HTTPClientConfig{})

	req, err := http.NewRequest(http.MethodGet, "https://example.com/next", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = client.CheckRedirect(req, []*http.Request{req})

	var se *SignerError
	if !errors.As(err, &se) {
		t.Fatalf("CheckRedirect = %v, want *SignerError", err)
	}
	if se.Code != CodeHTTPError {
		t.Errorf("code = %s, want %s", se.Code, CodeHTTPError)
	}
}

// The transport must block plaintext requests before they leave the process,
// mirroring reqwest's https_only(true) and the TS assertHttpsUrl.
func TestHTTPSOnlyTransportBlocksPlaintext(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = httpsOnlyTransport{base: http.DefaultTransport}.RoundTrip(req)

	var se *SignerError
	if !errors.As(err, &se) {
		t.Fatalf("RoundTrip = %v, want *SignerError", err)
	}
	if se.Code != CodeConfigError {
		t.Errorf("code = %s, want %s", se.Code, CodeConfigError)
	}
}
