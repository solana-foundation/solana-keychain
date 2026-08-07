package utila

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// parseSigningKey normalizes and parses the service-account RSA private key:
// escaped `\n` sequences are expanded, carriage returns are stripped, and the
// result is trimmed before parsing (PKCS#1 and PKCS#8 PEM are both accepted).
func parseSigningKey(pem string) (*rsa.PrivateKey, error) {
	normalized := strings.ReplaceAll(pem, `\n`, "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "")
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(strings.TrimSpace(normalized)))
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPrivateKey,
			"Failed to parse Utila service account RSA private key", err)
	}
	return key, nil
}

// createAccessToken mints the RS256 service-account JWT that authenticates every
// Utila API request. The claims are sub = service account email,
// aud = utilaAPIAudience, exp = now + tokenTTL.
func createAccessToken(serviceAccountEmail string, signingKey *rsa.PrivateKey) (string, error) {
	claims := jwt.MapClaims{
		"sub": serviceAccountEmail,
		"aud": utilaAPIAudience,
		"exp": time.Now().Add(tokenTTL).Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(signingKey)
	if err != nil {
		return "", core.WrapSignerError(core.CodeSigningFailed, "Failed to create Utila access token", err)
	}
	return token, nil
}

// normalizeAPIBaseURL applies the default, trims trailing slashes, and validates
// the URL, which must be usable as a base URL. It runs regardless of whether a
// custom HTTP client is supplied, so HTTPS is always enforced.
func normalizeAPIBaseURL(raw string) (string, error) {
	if raw == "" {
		raw = DefaultAPIBaseURL
	}
	normalized := strings.TrimRight(raw, "/")

	parsed, err := url.Parse(normalized)
	if err != nil {
		return "", core.WrapSignerError(core.CodeConfigError, "invalid api_base_url", err)
	}
	if parsed.Scheme != "https" {
		return "", core.NewSignerError(core.CodeConfigError, "api_base_url must use HTTPS")
	}
	if parsed.Opaque != "" || parsed.Host == "" {
		return "", core.NewSignerError(core.CodeConfigError, "api_base_url cannot be used as a base URL")
	}
	return normalized, nil
}

// fetchWallet retrieves the wallet object holding the Solana address. The
// "wallet" envelope (and, when solanaDetails is present, its address) is
// required.
func (s *Signer) fetchWallet(ctx context.Context) (walletResponse, error) {
	path := "/v2/vaults/" + encodeURIComponent(s.vaultID) + "/wallets/" + encodeURIComponent(s.walletID)
	status, body, err := s.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return walletResponse{}, err
	}
	wallet, err := parseResponse[walletResponse](status, body, "fetch_wallet")
	if err != nil {
		return walletResponse{}, err
	}
	if wallet.Wallet == nil || (wallet.Wallet.SolanaDetails != nil && wallet.Wallet.SolanaDetails.Address == nil) {
		return walletResponse{}, core.NewSignerError(core.CodeSerializationError,
			"Failed to parse Utila fetch_wallet response")
	}
	return wallet, nil
}

// initiateTransaction submits the base64 wire transaction for signing (publish
// and blockhash replacement disabled).
func (s *Signer) initiateTransaction(ctx context.Context, rawTransaction string) (utilaTransaction, error) {
	path := "/v2/vaults/" + encodeURIComponent(s.vaultID) + "/transactions:initiate"
	request := initiateTransactionRequest{
		Details: initiateTransactionDetails{
			SolanaSerializedTransaction: solanaSerializedTransaction{
				Network:        s.network,
				RawTransaction: rawTransaction,
			},
		},
		DesignatedSigners: s.designatedSigners,
	}
	status, body, err := s.doRequest(ctx, http.MethodPost, path, request)
	if err != nil {
		return utilaTransaction{}, err
	}
	return parseTransactionEnvelope(status, body, "initiate_transaction")
}

// getTransaction fetches the current state of a Utila transaction (FULL view, so
// the signed rawTransaction is included).
func (s *Signer) getTransaction(ctx context.Context, transactionID string) (utilaTransaction, error) {
	path := "/v2/vaults/" + encodeURIComponent(s.vaultID) +
		"/transactions/" + encodeURIComponent(transactionID) + "?view=FULL"
	status, body, err := s.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return utilaTransaction{}, err
	}
	return parseTransactionEnvelope(status, body, "get_transaction")
}

// doRequest issues an authenticated request (a fresh access token per call)
// and returns the status code and size-capped body.
// Transport failures map to CodeHTTPError, except that a *core.SignerError raised
// inside the client (e.g. the HTTPS-only transport's CodeConfigError) is
// surfaced as-is.
func (s *Signer) doRequest(ctx context.Context, method, path string, body any) (int, []byte, error) {
	token, err := createAccessToken(s.serviceAccountEmail, s.signingKey)
	if err != nil {
		return 0, nil, err
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, core.WrapSignerError(core.CodeSerializationError, "failed to encode request body", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, s.apiBaseURL+path, reader)
	if err != nil {
		return 0, nil, core.WrapSignerError(core.CodeHTTPError, "failed to build request", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		var se *core.SignerError
		if errors.As(err, &se) {
			return 0, nil, se
		}
		return 0, nil, core.WrapSignerError(core.CodeHTTPError, "request to utila api failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, core.WrapSignerError(core.CodeHTTPError, "failed to read utila response body", err)
	}
	return resp.StatusCode, data, nil
}

// parseResponse maps any 4xx/5xx status to RemoteApiError carrying only the
// context and status code (never the body), and an undecodable 2xx body to
// SerializationError.
func parseResponse[T any](status int, body []byte, opContext string) (T, error) {
	var zero T
	if status >= 400 {
		return zero, core.NewSignerError(core.CodeRemoteAPIError,
			fmt.Sprintf("Utila API %s error %d", opContext, status))
	}
	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		return zero, core.WrapSignerError(core.CodeSerializationError,
			"Failed to parse Utila "+opContext+" response", err)
	}
	return out, nil
}

// parseTransactionEnvelope decodes a transaction envelope and requires the
// transaction, its name, and its state.
func parseTransactionEnvelope(status int, body []byte, opContext string) (utilaTransaction, error) {
	envelope, err := parseResponse[transactionEnvelope](status, body, opContext)
	if err != nil {
		return utilaTransaction{}, err
	}
	if envelope.Transaction == nil || envelope.Transaction.Name == "" || envelope.Transaction.State == "" {
		return utilaTransaction{}, core.NewSignerError(core.CodeSerializationError,
			"Failed to parse Utila "+opContext+" response")
	}
	return *envelope.Transaction, nil
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
