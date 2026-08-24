package core

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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
