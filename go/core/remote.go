package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MaxResponseBytes caps how much of a remote API response a signer reads.
const MaxResponseBytes = 1 << 20

// IsSuccess reports whether status is a 2xx status code.
func IsSuccess(status int) bool { return status >= 200 && status < 300 }

// SendRequest sends req and returns the status code and the size-capped body.
// Transport failures map to CodeHTTPError, except that a *SignerError raised
// inside the client (the HTTPS-only transport and the redirect guard) is
// surfaced as-is so its code survives.
func SendRequest(client *http.Client, req *http.Request, provider string) (int, []byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		var se *SignerError
		if errors.As(err, &se) {
			return 0, nil, se
		}
		return 0, nil, WrapSignerError(CodeHTTPError, "request to "+provider+" api failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))
	if err != nil {
		return 0, nil, WrapSignerError(CodeHTTPError, "failed to read "+provider+" response body", err)
	}
	return resp.StatusCode, data, nil
}

// EncodeURIComponent percent-encodes every byte except the JavaScript
// encodeURIComponent unreserved set (A-Z a-z 0-9 - _ . ! ~ * ' ( )), so a path
// segment cannot smuggle '/', "..", '?', or '#' into a request URL.
func EncodeURIComponent(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for i := 0; i < len(input); i++ {
		c := input[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '-' || c == '_' || c == '.' || c == '!' || c == '~' ||
			c == '*' || c == '\'' || c == '(' || c == ')':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// SleepContext waits for d, returning a cancellation error if ctx ends first.
func SleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return WrapSignerError(CodeHTTPError, "transaction polling cancelled", ctx.Err())
	case <-timer.C:
		return nil
	}
}

// SleepContextUnconfirmed is SleepContext for a poll loop whose transaction the
// provider may already be executing: cancellation cannot rule the broadcast out, so
// it reports CodeBroadcastUnconfirmed rather than a failure the caller may retry.
func SleepContextUnconfirmed(ctx context.Context, d time.Duration, providerTxID string) error {
	if err := SleepContext(ctx, d); err == nil {
		return nil
	}
	return &SignerError{
		Code:         CodeBroadcastUnconfirmed,
		ProviderTxID: providerTxID,
		detail:       "transaction polling cancelled after the provider accepted the transaction",
		cause:        ctx.Err(),
	}
}

// ResolvePollBounds validates a backend's poll configuration, substituting the
// backend defaults for zero values and rejecting negative ones.
func ResolvePollBounds(interval, defaultInterval time.Duration, attempts, defaultAttempts int) (time.Duration, int, error) {
	if interval < 0 {
		return 0, 0, NewSignerError(CodeConfigError, "poll_interval must be greater than 0")
	}
	if attempts < 0 {
		return 0, 0, NewSignerError(CodeConfigError, "max_poll_attempts must be greater than 0")
	}
	if interval == 0 {
		interval = defaultInterval
	}
	if attempts == 0 {
		attempts = defaultAttempts
	}
	return interval, attempts, nil
}

// PollTimeoutError reports that a transaction never reached a terminal state
// within the attempt budget; the signing request may still complete remotely.
func PollTimeoutError(provider string, attempts int) error {
	return NewSignerError(CodeRemoteAPIError,
		provider+" transaction polling timed out after "+strconv.Itoa(attempts)+
			" attempts; the signing request may still complete")
}
