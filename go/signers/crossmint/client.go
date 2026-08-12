package crossmint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// walletResponse is the subset of the Crossmint wallet object the signer needs.
type walletResponse struct {
	ChainType string `json:"chainType"`
	Type      string `json:"type"`
	Address   string `json:"address"`
}

// createTransactionRequest is the create-transaction request body.
type createTransactionRequest struct {
	Params createTransactionParams `json:"params"`
}

type createTransactionParams struct {
	Transaction string `json:"transaction"`
	Signer      string `json:"signer,omitempty"`
}

// transactionResponse is the Crossmint transaction object; optional fields are
// pointers/raw JSON so absent and null are treated alike.
type transactionResponse struct {
	ID        string          `json:"id"`
	Status    string          `json:"status"`
	OnChain   *onChainData    `json:"onChain"`
	Approvals *approvalsData  `json:"approvals"`
	Error     json.RawMessage `json:"error"`
}

type onChainData struct {
	Transaction *string `json:"transaction"`
	TxID        *string `json:"txId"`
}

type approvalsData struct {
	Pending []pendingApproval `json:"pending"`
	// Submitted carries the approvals Crossmint has already collected. A rewritten
	// transaction's wallet signature appears here rather than in a signature slot
	// of the returned transaction.
	Submitted []submittedApproval `json:"submitted"`
}

type submittedApproval struct {
	Signature *string         `json:"signature"`
	Signer    *approvalSigner `json:"signer"`
}

type pendingApproval struct {
	Message *string         `json:"message"`
	Signer  *approvalSigner `json:"signer"`
}

// approvalSigner identifies which approver an approval belongs to.
type approvalSigner struct {
	Locator *string `json:"locator"`
	Address *string `json:"address"`
}

// approvalRequest is the submit-approval request body.
type approvalRequest struct {
	Approvals []approvalEntry `json:"approvals"`
}

type approvalEntry struct {
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

// fetchWallet retrieves the wallet object; the response must carry an
// "address".
func (s *Signer) fetchWallet(ctx context.Context) (walletResponse, error) {
	u, err := s.buildWalletsAPIURL()
	if err != nil {
		return walletResponse{}, err
	}
	status, body, err := s.doRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return walletResponse{}, err
	}
	return parseResponseWithRequiredField[walletResponse](status, body, "address", "fetch_wallet")
}

// createTransaction submits a base58-encoded transaction for signing.
func (s *Signer) createTransaction(ctx context.Context, transaction string) (transactionResponse, error) {
	u, err := s.buildWalletsAPIURL("transactions")
	if err != nil {
		return transactionResponse{}, err
	}
	req := createTransactionRequest{Params: createTransactionParams{
		Transaction: transaction,
		Signer:      s.signerLocator,
	}}
	status, body, err := s.doRequest(ctx, http.MethodPost, u, req)
	if err != nil {
		return transactionResponse{}, err
	}
	return parseResponseWithRequiredField[transactionResponse](status, body, "id", "create_transaction")
}

// getTransaction fetches the current state of a transaction.
func (s *Signer) getTransaction(ctx context.Context, transactionID string) (transactionResponse, error) {
	u, err := s.buildWalletsAPIURL("transactions", transactionID)
	if err != nil {
		return transactionResponse{}, err
	}
	status, body, err := s.doRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return transactionResponse{}, err
	}
	return parseResponseWithRequiredField[transactionResponse](status, body, "id", "get_transaction")
}

// submitApprovalRequest posts a signed approval for a pending transaction.
func (s *Signer) submitApprovalRequest(ctx context.Context, transactionID string, req approvalRequest) (transactionResponse, error) {
	u, err := s.buildWalletsAPIURL("transactions", transactionID, "approvals")
	if err != nil {
		return transactionResponse{}, err
	}
	status, body, err := s.doRequest(ctx, http.MethodPost, u, req)
	if err != nil {
		return transactionResponse{}, err
	}
	return parseResponseWithRequiredField[transactionResponse](status, body, "id", "submit_approval")
}

// buildWalletsAPIURL joins the base URL, API version, percent-encoded wallet
// locator, and extra path segments. Every segment is encoded with
// encodeURIComponent semantics so locators containing '/', "..", '?', or '#'
// stay inside a single path segment.
func (s *Signer) buildWalletsAPIURL(segments ...string) (string, error) {
	base, err := url.Parse(s.apiBaseURL)
	if err != nil {
		return "", core.WrapSignerError(core.CodeConfigError, "invalid api_base_url", err)
	}
	if !base.IsAbs() || base.Opaque != "" || base.Host == "" {
		return "", core.NewSignerError(core.CodeConfigError, "api_base_url cannot be used as a base URL")
	}

	var b strings.Builder
	b.WriteString(strings.TrimRight(s.apiBaseURL, "/"))
	b.WriteString("/" + walletsAPIVersion + "/wallets/")
	b.WriteString(encodeURIComponent(s.walletLocator))
	for _, segment := range segments {
		b.WriteByte('/')
		b.WriteString(encodeURIComponent(segment))
	}
	return b.String(), nil
}

// encodeURIComponent percent-encodes every byte except the JavaScript
// encodeURIComponent unreserved set (A-Z a-z 0-9 - _ . ! ~ * ' ( )).
func encodeURIComponent(input string) string {
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

// doRequest issues an authenticated request and returns the status code and
// (size-capped) body. Transport failures map to CodeHTTPError, except that a
// *core.SignerError raised inside the client (e.g. the HTTPS-only transport's
// CodeConfigError) is surfaced as-is.
func (s *Signer) doRequest(ctx context.Context, method, u string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, core.WrapSignerError(core.CodeSerializationError, "failed to encode request body", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return 0, nil, core.WrapSignerError(core.CodeHTTPError, "failed to build request", err)
	}
	req.Header.Set("X-API-KEY", s.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		var se *core.SignerError
		if errors.As(err, &se) {
			return 0, nil, se
		}
		return 0, nil, core.WrapSignerError(core.CodeHTTPError, "request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, core.WrapSignerError(core.CodeHTTPError, "failed to read response body", err)
	}
	return resp.StatusCode, data, nil
}

// parseResponseWithRequiredField turns non-2xx statuses into RemoteApiError
// with any extractable API message; a 2xx body missing the required field
// becomes RemoteApiError (if the body carries an error message) or
// SerializationError, and only then is the body decoded into T.
func parseResponseWithRequiredField[T any](status int, body []byte, requiredField, opContext string) (T, error) {
	var zero T
	var value map[string]json.RawMessage
	// Undecodable bodies degrade to an empty object.
	_ = json.Unmarshal(body, &value)

	if status >= 400 {
		message, ok := extractErrorMessage(value)
		if !ok {
			message = fmt.Sprintf("Crossmint API error %d", status)
		}
		return zero, core.NewSignerError(core.CodeRemoteAPIError, opContext+": "+core.SanitizeRemoteResponse(message))
	}

	if _, ok := value[requiredField]; !ok {
		if message, ok := extractErrorMessage(value); ok {
			return zero, core.NewSignerError(core.CodeRemoteAPIError, opContext+": "+core.SanitizeRemoteResponse(message))
		}
		return zero, core.NewSignerError(core.CodeSerializationError,
			opContext+": missing expected field '"+requiredField+"' in response")
	}

	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		return zero, core.WrapSignerError(core.CodeSerializationError, opContext+": failed to parse JSON response", err)
	}
	return out, nil
}

// extractErrorMessage pulls a human-readable message out of a Crossmint error
// body: a top-level "message" string, an "error" string, or an "error" object
// with a "message" string.
func extractErrorMessage(value map[string]json.RawMessage) (string, bool) {
	if raw, ok := value["message"]; ok {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s, true
		}
	}
	if raw, ok := value["error"]; ok {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s, true
		}
		var obj struct {
			Message *string `json:"message"`
		}
		if json.Unmarshal(raw, &obj) == nil && obj.Message != nil {
			return *obj.Message, true
		}
	}
	return "", false
}
