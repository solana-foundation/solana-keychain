package core

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Default HTTP timeouts for remote signers.
const (
	DefaultRequestTimeout = 30 * time.Second
	DefaultConnectTimeout = 5 * time.Second
)

// HTTPClientConfig holds optional HTTP timeout settings for remote signers. Zero
// values fall back to DefaultRequestTimeout / DefaultConnectTimeout.
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

// httpsOnlyTransport rejects any request whose URL scheme is not https.
type httpsOnlyTransport struct{ base http.RoundTripper }

func (t httpsOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" {
		return nil, NewSignerError(CodeConfigError, "non-HTTPS request blocked: signer requests must use https")
	}
	return t.base.RoundTrip(req)
}

// NewHTTPClient builds an *http.Client that enforces HTTPS and applies the
// configured (or default) request and connect timeouts.
func NewHTTPClient(cfg HTTPClientConfig) *http.Client {
	dialer := &net.Dialer{Timeout: cfg.ResolvedConnectTimeout()}
	base := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
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
		// Refuse all redirects: following them would replay auth headers such as
		// X-Vault-Token against whatever host the response points at.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return NewSignerError(CodeHTTPError, "HTTP redirect blocked: remote signer APIs must respond directly")
		},
	}
}

// AvailabilityTimeout bounds the health check an IsAvailable implementation
// performs, so a hung remote cannot stall a caller for the full request timeout.
const AvailabilityTimeout = 5 * time.Second

// NormalizeHTTPSBaseURL returns raw, or defaultURL when raw is empty, with
// trailing slashes trimmed. The result must be an absolute HTTPS URL with a
// host; field names the configuration field in the error detail.
func NormalizeHTTPSBaseURL(raw, defaultURL, field string) (string, error) {
	if raw == "" {
		raw = defaultURL
	}
	normalized := strings.TrimRight(raw, "/")
	parsed, err := url.Parse(normalized)
	if err != nil {
		return "", WrapSignerError(CodeConfigError, "invalid "+field, err)
	}
	if parsed.Scheme != "https" {
		return "", NewSignerError(CodeConfigError, field+" must use HTTPS")
	}
	if parsed.Opaque != "" || parsed.Host == "" {
		return "", NewSignerError(CodeConfigError, field+" cannot be used as a base URL")
	}
	return normalized, nil
}

// ResolveHTTPClient returns the caller-supplied client, or a new one built from
// cfg when none was supplied.
func ResolveHTTPClient(client *http.Client, cfg HTTPClientConfig) *http.Client {
	if client != nil {
		return client
	}
	return NewHTTPClient(cfg)
}
