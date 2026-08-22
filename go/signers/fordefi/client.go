package fordefi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// Fordefi protocol constants (request discriminators and the transaction
// states the polling loop reacts to).
const (
	transactionsPath = "/api/v1/transactions"

	stateSigned    = "signed"
	stateCompleted = "completed"
)

// terminalFailureStates are the transaction states that abort polling with a
// signing failure.
var terminalFailureStates = map[string]bool{
	"aborted":                     true,
	"cancelled":                   true,
	"completed_reverted":          true,
	"dropped":                     true,
	"error_pushing_to_blockchain": true,
	"error_signing":               true,
	"insufficient_funds":          true,
	"mined_reverted":              true,
}

// maxResponseBytes caps how much of a Fordefi response body is read.
const maxResponseBytes = 1 << 20

// Wire types for the Fordefi REST API.

type transactionRequest struct {
	VaultID    string `json:"vault_id"`
	SignerType string `json:"signer_type"`
	SignMode   string `json:"sign_mode"`
	Type       string `json:"type"`
	Details    any    `json:"details"`
}

type blackBoxDetails struct {
	Format     string `json:"format"`
	HashBinary string `json:"hash_binary"`
}

type solanaTransactionDetails struct {
	Type     string   `json:"type"`
	Chain    Chain    `json:"chain"`
	Data     string   `json:"data"`
	PushMode PushMode `json:"push_mode"`
	Fee      *Fee     `json:"fee,omitempty"`
}

type solanaMessageDetails struct {
	Type    string `json:"type"`
	Chain   Chain  `json:"chain"`
	RawData string `json:"raw_data"`
}

type createTransactionResponse struct {
	ID string `json:"id"`
}

type signatureEntry struct {
	Data string `json:"data"`
}

// transactionStatusResponse is the polled transaction state. RawTransaction is
// the base64-encoded signed wire transaction, present on solana_transaction
// responses.
type transactionStatusResponse struct {
	State          string           `json:"state"`
	Signatures     []signatureEntry `json:"signatures"`
	RawTransaction string           `json:"raw_transaction"`
}

// vaultResponse is GET /api/v1/vaults/{id}. Chain-specific vaults expose a
// base58 address; black-box vaults expose the same 32-byte Ed25519 key as
// base64 public_key_compressed.
type vaultResponse struct {
	Address             string `json:"address"`
	PublicKeyCompressed string `json:"public_key_compressed"`
}

func (s *Signer) newRequest(ctx context.Context, method, path, body string) (*http.Request, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.apiBaseURL+path, reader)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeHTTPError, "failed to build fordefi request", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.accessToken)
	return req, nil
}

func (s *Signer) send(req *http.Request) (int, []byte, error) {
	resp, err := s.client.Do(req)
	if err != nil {
		var se *core.SignerError
		if errors.As(err, &se) {
			return 0, nil, se
		}
		return 0, nil, core.WrapSignerError(core.CodeHTTPError, "request to fordefi api failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, core.WrapSignerError(core.CodeHTTPError, "failed to read fordefi response body", err)
	}
	return resp.StatusCode, data, nil
}

// doGet sends an authenticated GET and returns the status code and body.
func (s *Signer) doGet(ctx context.Context, path string) (int, []byte, error) {
	req, err := s.newRequest(ctx, http.MethodGet, path, "")
	if err != nil {
		return 0, nil, err
	}
	return s.send(req)
}

// signRequest produces the x-signature value over the {path}|{timestamp}|{body}
// payload via the configured RequestSigner.
func (s *Signer) signRequest(ctx context.Context, path string, timestamp int64, body string) (string, error) {
	payload := path + "|" + strconv.FormatInt(timestamp, 10) + "|" + body
	return s.requestSigner.SignRequest(ctx, []byte(payload))
}

// submitTransaction POSTs a signing request to /api/v1/transactions with
// request-level P-256 signing and returns the Fordefi transaction ID.
//
// broadcastManaged marks a submit whose acceptance means Fordefi is already
// broadcasting, so an unresolved failure is reported as unconfirmed.
func (s *Signer) submitTransaction(ctx context.Context, request transactionRequest, idempotenceID string, broadcastManaged bool) (string, error) {
	classify := func(status int, err error) error {
		if !broadcastManaged {
			return err
		}
		return core.UnconfirmedUnlessRejected(status, err)
	}

	body, err := json.Marshal(request)
	if err != nil {
		return "", core.WrapSignerError(core.CodeSerializationError, "failed to serialize fordefi request", err)
	}

	timestamp := time.Now().UnixMilli()
	signature, err := s.signRequest(ctx, transactionsPath, timestamp, string(body))
	if err != nil {
		return "", err
	}

	req, err := s.newRequest(ctx, http.MethodPost, transactionsPath, string(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-signature", signature)
	req.Header.Set("x-timestamp", strconv.FormatInt(timestamp, 10))
	if idempotenceID != "" {
		req.Header.Set("x-idempotence-id", idempotenceID)
	}

	status, respBody, err := s.send(req)
	if err != nil {
		return "", classify(status, err)
	}
	if !is2xx(status) {
		return "", classify(status, core.NewSignerError(core.CodeRemoteAPIError, fmt.Sprintf("API error %d", status)))
	}

	var created createTransactionResponse
	if err := json.Unmarshal(respBody, &created); err != nil || created.ID == "" {
		return "", classify(status, core.NewSignerError(core.CodeSerializationError, "failed to parse response"))
	}
	return created.ID, nil
}

// getTransaction fetches the current state of a Fordefi transaction.
func (s *Signer) getTransaction(ctx context.Context, txID string) (transactionStatusResponse, error) {
	status, body, err := s.doGet(ctx, transactionsPath+"/"+url.PathEscape(txID))
	if err != nil {
		return transactionStatusResponse{}, err
	}
	if !is2xx(status) {
		return transactionStatusResponse{}, core.NewSignerError(core.CodeRemoteAPIError, fmt.Sprintf("API error %d", status))
	}

	var tx transactionStatusResponse
	if err := json.Unmarshal(body, &tx); err != nil {
		return transactionStatusResponse{}, core.WrapSignerError(core.CodeSerializationError, "failed to parse response", err)
	}
	return tx, nil
}

// pollForResult polls the transaction until it reaches a terminal state or the
// attempt budget is exhausted. When pushable is true (native Solana
// transactions, auto-broadcast) the only success state is "completed"; when
// false (black box / messages) "signed" succeeds, with "completed" accepted
// defensively. Cancellation of ctx aborts the wait.
func (s *Signer) pollForResult(ctx context.Context, txID string, pushable bool) (transactionStatusResponse, error) {
	for attempt := 0; attempt < s.maxPollAttempts; attempt++ {
		response, err := s.getTransaction(ctx, txID)
		if err != nil {
			return transactionStatusResponse{}, err
		}

		success := response.State == stateCompleted || (!pushable && response.State == stateSigned)
		if success {
			return response, nil
		}
		if terminalFailureStates[response.State] {
			return transactionStatusResponse{}, core.NewSignerError(core.CodeSigningFailed,
				"transaction "+txID+" reached terminal state: "+response.State)
		}

		if attempt+1 < s.maxPollAttempts {
			timer := time.NewTimer(s.pollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return transactionStatusResponse{}, core.WrapSignerError(core.CodeHTTPError, "polling cancelled", ctx.Err())
			case <-timer.C:
			}
		}
	}

	return transactionStatusResponse{}, core.NewSignerError(core.CodeRemoteAPIError, fmt.Sprintf(
		"Polling timeout after %d attempts", s.maxPollAttempts))
}

// extractSignature pulls the 64-byte Ed25519 signature out of a completed poll
// response.
func extractSignature(response transactionStatusResponse) (solana.Signature, error) {
	if len(response.Signatures) == 0 || response.Signatures[0].Data == "" {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"transaction signed but no signatures in response")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(response.Signatures[0].Data)
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to decode signature base64", err)
	}
	if len(sigBytes) != core.SignatureLength {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			fmt.Sprintf("expected %d-byte Ed25519 signature, got %d", core.SignatureLength, len(sigBytes)))
	}
	return solana.SignatureFromBytes(sigBytes), nil
}

// fetchVault fetches the configured vault from Fordefi.
func (s *Signer) fetchVault(ctx context.Context) (vaultResponse, error) {
	status, body, err := s.doGet(ctx, "/api/v1/vaults/"+url.PathEscape(s.vaultID))
	if err != nil {
		return vaultResponse{}, err
	}
	if !is2xx(status) {
		return vaultResponse{}, core.NewSignerError(core.CodeRemoteAPIError, fmt.Sprintf("API error %d", status))
	}

	var vault vaultResponse
	if err := json.Unmarshal(body, &vault); err != nil {
		return vaultResponse{}, core.WrapSignerError(core.CodeSerializationError, "failed to parse response", err)
	}
	return vault, nil
}

// vaultPublicKey resolves the authoritative Solana public key of a Fordefi
// vault: chain-specific vaults expose a base58 address, black-box vaults
// expose the same 32-byte Ed25519 key as base64 public_key_compressed.
func vaultPublicKey(vault vaultResponse) (solana.PublicKey, error) {
	if vault.Address != "" {
		pubkey, err := solana.PublicKeyFromBase58(vault.Address)
		if err != nil {
			return solana.PublicKey{}, core.WrapSignerError(core.CodeInvalidPublicKey,
				"fordefi vault returned an invalid Solana address", err)
		}
		return pubkey, nil
	}
	if vault.PublicKeyCompressed == "" {
		return solana.PublicKey{}, core.NewSignerError(core.CodeConfigError,
			"fordefi vault response included neither address nor public_key_compressed; cannot verify public_key ownership")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(vault.PublicKeyCompressed)
	if err != nil {
		return solana.PublicKey{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to decode fordefi vault public_key_compressed as base64", err)
	}
	if len(keyBytes) != solana.PublicKeyLength {
		return solana.PublicKey{}, core.NewSignerError(core.CodeInvalidPublicKey,
			"fordefi vault public_key_compressed must decode to 32 bytes")
	}
	return solana.PublicKeyFromBytes(keyBytes), nil
}

// is2xx reports whether status is a success status.
func is2xx(status int) bool { return status >= 200 && status <= 299 }
