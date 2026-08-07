package dfns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// maxResponseBytes caps how much of a Dfns response body is read.
const maxResponseBytes = 1 << 20 // 1 MiB

// marshalJSON encodes v without HTML escaping, leaving `<`, `>`, and `&`
// intact. This matters for the user-action client data, whose exact bytes are
// signed and verified by Dfns.
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, core.WrapSignerError(core.CodeSerializationError, "failed to serialize request body", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// do sends a Dfns API request and returns the response body on 2xx.
//
// It sets the Authorization bearer header on every request, Content-Type for
// bodies, and any extra headers (e.g. x-dfns-useraction). Transport failures
// map to CodeHTTPError — except errors that already carry a signer code (such
// as the HTTPS-only transport's CodeConfigError), whose code is preserved.
// Non-2xx responses map to CodeRemoteAPIError with the sanitized body appended
// to errPrefix.
func (s *Signer) do(ctx context.Context, method, path string, body []byte, extraHeaders map[string]string, errPrefix string) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.apiBaseURL+path, reader)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeHTTPError, "failed to build dfns request", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.authToken)
	req.Header.Set("User-Agent", "solana-keychain")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		// Preserve SignerError codes raised inside the transport (e.g. the
		// HTTPS-only guard's CodeConfigError), consistent with the other backends.
		var se *core.SignerError
		if errors.As(err, &se) {
			return nil, se
		}
		return nil, core.WrapSignerError(core.CodeHTTPError, "dfns request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, core.WrapSignerError(core.CodeHTTPError, "failed to read dfns response body", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, core.NewSignerError(core.CodeRemoteAPIError,
			errPrefix+" "+strconv.Itoa(resp.StatusCode)+": "+core.SanitizeRemoteResponse(string(data)))
	}
	return data, nil
}
