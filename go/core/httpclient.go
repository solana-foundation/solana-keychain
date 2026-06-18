package core

import (
	"net"
	"net/http"
	"time"
)

// Default HTTP timeouts for remote signers, matching the Rust HttpClientConfig.
const (
	DefaultRequestTimeout = 30 * time.Second
	DefaultConnectTimeout = 5 * time.Second
)

// HTTPClientConfig holds optional HTTP timeout settings for remote signers. Zero
// values fall back to DefaultRequestTimeout / DefaultConnectTimeout. Mirrors the
// Rust HttpClientConfig.
type HTTPClientConfig struct {
	RequestTimeout time.Duration
	ConnectTimeout time.Duration
}

// ResolvedRequestTimeout returns the configured request timeout or the default.
func (c HTTPClientConfig) ResolvedRequestTimeout() time.Duration {
	if c.RequestTimeout > 0 {
		return c.RequestTimeout
	}
	return DefaultRequestTimeout
}

// ResolvedConnectTimeout returns the configured connect timeout or the default.
func (c HTTPClientConfig) ResolvedConnectTimeout() time.Duration {
	if c.ConnectTimeout > 0 {
		return c.ConnectTimeout
	}
	return DefaultConnectTimeout
}

// httpsOnlyTransport rejects any request whose URL scheme is not https — the Go
// analog of reqwest's .https_only(true) and the TS non-HTTPS apiBaseUrl rejection.
type httpsOnlyTransport struct{ base http.RoundTripper }

func (t httpsOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" {
		return nil, NewSignerError(CodeConfigError, "non-HTTPS request blocked: signer requests must use https")
	}
	return t.base.RoundTrip(req)
}

// NewHTTPClient builds an *http.Client that enforces HTTPS and applies the
// configured (or default) request and connect timeouts. Mirrors the per-backend
// reqwest client builders in the Rust crate.
func NewHTTPClient(cfg HTTPClientConfig) *http.Client {
	dialer := &net.Dialer{Timeout: cfg.ResolvedConnectTimeout()}
	base := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   cfg.ResolvedConnectTimeout(),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Timeout:   cfg.ResolvedRequestTimeout(),
		Transport: httpsOnlyTransport{base: base},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Scheme != "https" {
				return NewSignerError(CodeConfigError, "non-HTTPS redirect blocked")
			}
			return nil
		},
	}
}
