package fireblocks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// Fireblocks protocol constants (operation name, source type, and the
// transaction status values the polling loop reacts to).
const (
	operationRaw         = "RAW"
	operationProgramCall = "PROGRAM_CALL"
	sourceVaultAccount   = "VAULT_ACCOUNT"

	statusCompleted    = "COMPLETED"
	statusSigned       = "SIGNED"
	statusBroadcasting = "BROADCASTING"
	statusConfirming   = "CONFIRMING"
	statusFailed       = "FAILED"
	statusCancelled    = "CANCELLED"
	statusRejected     = "REJECTED"
	statusBlocked      = "BLOCKED"
)

// Wire types for the Fireblocks REST API.

type createTransactionRequest struct {
	AssetID         string            `json:"assetId"`
	Operation       string            `json:"operation"`
	Source          transactionSource `json:"source"`
	ExtraParameters any               `json:"extraParameters"`
}

type transactionSource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type rawExtraParameters struct {
	RawMessageData rawMessageData `json:"rawMessageData"`
}

type rawMessageData struct {
	Messages []rawMessage `json:"messages"`
}

type rawMessage struct {
	Content string `json:"content"`
}

// programCallExtraParameters carries a serialized transaction for PROGRAM_CALL
// signing. UseDurableNonce defaults to true on the Fireblocks side, which
// prepends an AdvanceNonce instruction to the submitted message; the signature
// would then cover different bytes than the caller's transaction.
type programCallExtraParameters struct {
	ProgramCallData string `json:"programCallData"`
	SignOnly        bool   `json:"signOnly"`
	UseDurableNonce bool   `json:"useDurableNonce"`
}

type createTransactionResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// transactionResponse is the polled transaction state.
type transactionResponse struct {
	ID             string          `json:"id"`
	Status         string          `json:"status"`
	SubStatus      string          `json:"subStatus"`
	SignedMessages []signedMessage `json:"signedMessages"`
	TxHash         string          `json:"txHash"`
}

type signedMessage struct {
	Signature signatureData `json:"signature"`
}

type signatureData struct {
	FullSig string `json:"fullSig"`
}

type vaultAddressesResponse struct {
	Addresses []vaultAddress `json:"addresses"`
}

type vaultAddress struct {
	Address string `json:"address"`
	AssetID string `json:"assetId"`
}

// doRequest sends an authenticated request to the Fireblocks API and returns the
// status code and body. The per-request JWT is computed over uri and body (empty
// body for GET requests).
func (s *Signer) doRequest(ctx context.Context, method, uri, body string) (int, []byte, error) {
	token, err := createJWT(s.apiKey, s.signingKey, uri, body)
	if err != nil {
		return 0, nil, err
	}

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.apiBaseURL+uri, reader)
	if err != nil {
		return 0, nil, core.WrapSignerError(core.CodeHTTPError, "failed to build fireblocks request", err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-API-Key", s.apiKey)
	req.Header.Set("Authorization", "Bearer "+token)

	return core.SendRequest(s.client, req, "fireblocks")
}

// fetchPublicKey retrieves the vault account's Solana address.
func (s *Signer) fetchPublicKey(ctx context.Context) (solana.PublicKey, error) {
	uri := "/v1/vault/accounts/" + s.vaultAccountID + "/" + s.assetID + "/addresses_paginated"
	status, body, err := s.doRequest(ctx, http.MethodGet, uri, "")
	if err != nil {
		return solana.PublicKey{}, err
	}
	if !core.IsSuccess(status) {
		return solana.PublicKey{}, core.NewRemoteAPIError("API error", status, body)
	}

	var addresses vaultAddressesResponse
	if err := json.Unmarshal(body, &addresses); err != nil {
		return solana.PublicKey{}, core.WrapSignerError(core.CodeSerializationError, "failed to parse Fireblocks response", err)
	}
	address, err := s.selectVaultAddress(addresses.Addresses)
	if err != nil {
		return solana.PublicKey{}, err
	}
	pubkey, err := solana.PublicKeyFromBase58(address)
	if err != nil {
		return solana.PublicKey{}, core.WrapSignerError(core.CodeInvalidPublicKey, "invalid public key from Fireblocks", err)
	}
	return pubkey, nil
}

// selectVaultAddress picks the address for the configured asset, failing on an
// empty or ambiguous response: a mistyped vault account or asset id must not
// yield a working signer bound to an unintended fee payer. Entries without an
// assetId are kept, since the endpoint is already scoped by asset.
func (s *Signer) selectVaultAddress(addresses []vaultAddress) (string, error) {
	unique := make([]string, 0, len(addresses))
	seen := make(map[string]bool, len(addresses))
	for _, entry := range addresses {
		if entry.Address == "" || (entry.AssetID != "" && entry.AssetID != s.assetID) {
			continue
		}
		if !seen[entry.Address] {
			seen[entry.Address] = true
			unique = append(unique, entry.Address)
		}
	}
	switch len(unique) {
	case 1:
		return unique[0], nil
	case 0:
		return "", core.NewSignerError(core.CodeInvalidPublicKey,
			"Fireblocks returned no address for vault account "+s.vaultAccountID+" asset "+s.assetID)
	default:
		return "", core.NewSignerError(core.CodeInvalidPublicKey,
			"Fireblocks returned "+strconv.Itoa(len(unique))+" addresses for vault account "+
				s.vaultAccountID+" asset "+s.assetID+"; cannot choose a signing identity")
	}
}

// createTransaction creates a signing request in Fireblocks.
func (s *Signer) createTransaction(ctx context.Context, request createTransactionRequest) (createTransactionResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return createTransactionResponse{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize fireblocks request", err)
	}

	status, respBody, err := s.doRequest(ctx, http.MethodPost, "/v1/transactions", string(body))
	if err != nil {
		return createTransactionResponse{}, err
	}
	if !core.IsSuccess(status) {
		return createTransactionResponse{}, core.NewRemoteAPIError("API error", status, respBody)
	}

	var created createTransactionResponse
	if err := json.Unmarshal(respBody, &created); err != nil {
		return createTransactionResponse{}, core.WrapSignerError(core.CodeSerializationError, "failed to parse response", err)
	}
	return created, nil
}

// getTransaction fetches the current status of a Fireblocks transaction.
func (s *Signer) getTransaction(ctx context.Context, txID string) (transactionResponse, error) {
	status, body, err := s.doRequest(ctx, http.MethodGet, "/v1/transactions/"+txID, "")
	if err != nil {
		return transactionResponse{}, err
	}
	if !core.IsSuccess(status) {
		return transactionResponse{}, core.NewRemoteAPIError("Fireblocks API error", status, body)
	}

	var tx transactionResponse
	if err := json.Unmarshal(body, &tx); err != nil {
		return transactionResponse{}, core.WrapSignerError(core.CodeSerializationError, "failed to parse response", err)
	}
	return tx, nil
}

// pollForSignature polls the transaction until it reaches a terminal state or the
// attempt budget is exhausted. COMPLETED returns the response (SIGNED for a
// sign-only PROGRAM_CALL); FAILED/CANCELLED/REJECTED/BLOCKED fail signing; a
// PROGRAM_CALL that reached the network despite signOnly reports
// CodeBroadcastUnconfirmed; anything else waits pollInterval and retries.
// Cancellation of ctx aborts the wait.
func (s *Signer) pollForSignature(ctx context.Context, txID string, programCall bool) (transactionResponse, error) {
	for attempt := 0; attempt < s.maxPollAttempts; attempt++ {
		response, err := s.getTransaction(ctx, txID)
		if err != nil {
			return transactionResponse{}, err
		}

		if programCall {
			switch response.Status {
			case statusSigned:
				return response, nil
			case statusBroadcasting, statusConfirming, statusCompleted:
				return transactionResponse{}, core.NewBroadcastUnconfirmedError(txID,
					"fireblocks broadcast the PROGRAM_CALL despite signOnly (status "+response.Status+
						"); the transaction may already be executing")
			}
		}

		switch response.Status {
		case statusCompleted:
			return response, nil
		case statusFailed, statusCancelled, statusRejected, statusBlocked:
			return transactionResponse{}, core.NewSignerError(core.CodeSigningFailed,
				"transaction "+response.Status+": "+txID)
		default:
			if attempt+1 < s.maxPollAttempts {
				if err := core.SleepContext(ctx, s.pollInterval); err != nil {
					return transactionResponse{}, err
				}
			}
		}
	}

	return transactionResponse{}, core.PollTimeoutError("fireblocks", s.maxPollAttempts)
}
