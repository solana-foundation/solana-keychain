package fordefi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
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
	Type     string `json:"type"`
	Chain    Chain  `json:"chain"`
	Data     string `json:"data"`
	PushMode string `json:"push_mode"`
	Fee      *Fee   `json:"fee,omitempty"`
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

func (s *signerCore) newRequest(ctx context.Context, method, path, body string) (*http.Request, error) {
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

func (s *signerCore) send(req *http.Request) (int, []byte, error) {
	return core.SendRequest(s.client, req, "fordefi")
}

// doGet sends an authenticated GET and returns the status code and body.
func (s *signerCore) doGet(ctx context.Context, path string) (int, []byte, error) {
	req, err := s.newRequest(ctx, http.MethodGet, path, "")
	if err != nil {
		return 0, nil, err
	}
	return s.send(req)
}

// signRequest produces the x-signature value over the {path}|{timestamp}|{body}
// payload via the configured RequestSigner.
func (s *signerCore) signRequest(ctx context.Context, path string, timestamp int64, body string) (string, error) {
	payload := path + "|" + strconv.FormatInt(timestamp, 10) + "|" + body
	return s.requestSigner.SignRequest(ctx, []byte(payload))
}

// submitTransaction POSTs a signing request to /api/v1/transactions with
// request-level P-256 signing and returns the Fordefi transaction ID.
//
// broadcastManaged marks a submit whose acceptance means Fordefi is already
// broadcasting, so an unresolved failure is reported as unconfirmed.
func (s *signerCore) submitTransaction(ctx context.Context, request transactionRequest, idempotenceID string, broadcastManaged bool) (string, error) {
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
	if !core.IsSuccess(status) {
		return "", classify(status, core.NewRemoteAPIError("API error", status, respBody))
	}

	var created createTransactionResponse
	if err := json.Unmarshal(respBody, &created); err != nil || created.ID == "" {
		return "", classify(status, core.NewSignerError(core.CodeSerializationError, "failed to parse response"))
	}
	return created.ID, nil
}

// getTransaction fetches the current state of a Fordefi transaction.
func (s *signerCore) getTransaction(ctx context.Context, txID string) (transactionStatusResponse, error) {
	status, body, err := s.doGet(ctx, transactionsPath+"/"+url.PathEscape(txID))
	if err != nil {
		return transactionStatusResponse{}, err
	}
	if !core.IsSuccess(status) {
		return transactionStatusResponse{}, core.NewRemoteAPIError("API error", status, body)
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
// defensively. Cancellation of ctx aborts the wait, reported as
// CodeBroadcastUnconfirmed when pushable because Fordefi may already have executed it.
func (s *signerCore) pollForResult(ctx context.Context, txID string, pushable bool) (transactionStatusResponse, error) {
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
			var err error
			if pushable {
				err = core.SleepContextUnconfirmed(ctx, s.pollInterval, txID)
			} else {
				err = core.SleepContext(ctx, s.pollInterval)
			}
			if err != nil {
				return transactionStatusResponse{}, err
			}
		}
	}

	return transactionStatusResponse{}, core.PollTimeoutError("fordefi", s.maxPollAttempts)
}

// extractSignature pulls the 64-byte Ed25519 signature out of a completed poll
// response.
func extractSignature(response transactionStatusResponse) (solana.Signature, error) {
	if len(response.Signatures) == 0 || response.Signatures[0].Data == "" {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"transaction signed but no signatures in response")
	}
	return core.DecodeSignatureBase64(response.Signatures[0].Data, "fordefi")
}

// probeVault fetches the configured vault as a reachability and authentication
// check. The body is not interpreted: the configured public key is the source
// of truth for the signer's identity.
func (s *signerCore) probeVault(ctx context.Context) error {
	status, body, err := s.doGet(ctx, "/api/v1/vaults/"+url.PathEscape(s.vaultID))
	if err != nil {
		return err
	}
	if !core.IsSuccess(status) {
		return core.NewRemoteAPIError("API error", status, body)
	}
	return nil
}
