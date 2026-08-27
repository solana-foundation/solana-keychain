package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// signRequest is the transit sign request body: the base64-encoded payload.
type signRequest struct {
	Input string `json:"input"`
}

// signResponse is the subset of the transit sign response the signer reads.
type signResponse struct {
	Data struct {
		Signature string `json:"signature"`
	} `json:"data"`
}

// keyReadResponse is the subset of the transit key-read response used by the
// IsAvailable health check.
type keyReadResponse struct {
	Data struct {
		SupportsSigning bool   `json:"supports_signing"`
		Type            string `json:"type"`
	} `json:"data"`
}

// Signer signs with an Ed25519 key held in HashiCorp Vault's transit engine.
// All fields are immutable after New, so a Signer is safe for concurrent use.
type Signer struct {
	client    *http.Client
	vaultAddr string
	token     string
	keyName   string
	pubkey    solana.PublicKey
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.TransactionSigner = (*Signer)(nil)

// New builds a Vault signer from cfg. Construction performs no I/O; only the
// base58 public key is validated.
func New(cfg Config) (*Signer, error) {
	pubkey, err := solana.PublicKeyFromBase58(cfg.Pubkey)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPublicKey, "failed to decode base58 public key", err)
	}
	client := core.ResolveHTTPClient(cfg.HTTPClient, cfg.HTTPClientConfig)
	return &Signer{
		client:    client,
		vaultAddr: cfg.VaultAddr,
		token:     cfg.Token,
		keyName:   cfg.KeyName,
		pubkey:    pubkey,
	}, nil
}

// Pubkey returns the signer's public key.
func (s *Signer) Pubkey() solana.PublicKey { return s.pubkey }

// String renders the signer without any secret material.
func (s Signer) String() string {
	return "vault.Signer{pubkey: " + s.pubkey.String() + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s Signer) GoString() string { return s.String() }

// SignMessage signs arbitrary bytes via the Vault transit sign endpoint.
func (s *Signer) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	return s.signBytes(ctx, message)
}

// SignTransaction signs the transaction's message bytes via Vault and inserts
// the signature at this signer's required-signer position, returning the encoded
// transaction and its completeness.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	return core.SignTransactionWith(ctx, tx, s.pubkey, s.signBytes)
}

// IsAvailable reads the transit key's metadata as a health check and reports
// whether it is a signing-capable ed25519 key. All errors are swallowed and
// reported as false.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, core.AvailabilityTimeout)
	defer cancel()
	url := s.vaultAddr + "/v1/transit/keys/" + s.keyName
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-Vault-Token", s.token)

	status, body, err := core.SendRequest(s.client, req, "vault")
	if err != nil || !core.IsSuccess(status) {
		return false
	}

	var parsed keyReadResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	return parsed.Data.SupportsSigning && parsed.Data.Type == "ed25519"
}

// signBytes posts the payload to the transit sign endpoint, decodes the returned
// signature (stripping the "vault:vN:" prefix), and verifies it against the
// configured public key before returning it.
func (s *Signer) signBytes(ctx context.Context, message []byte) (solana.Signature, error) {
	url := s.vaultAddr + "/v1/transit/sign/" + s.keyName
	payload, err := json.Marshal(signRequest{Input: base64.StdEncoding.EncodeToString(message)})
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to encode vault sign request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeRemoteAPIError, "failed to build vault sign request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", s.token)

	status, body, err := core.SendRequest(s.client, req, "vault")
	if err != nil {
		return solana.Signature{}, err
	}
	if !core.IsSuccess(status) {
		return solana.Signature{}, core.NewRemoteAPIError("vault API error", status, body)
	}

	var parsed signResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to parse vault response", err)
	}
	if parsed.Data.Signature == "" {
		return solana.Signature{}, core.NewSignerError(core.CodeRemoteAPIError, "no signature in vault response")
	}

	sig, err := core.DecodeSignatureBase64(stripVaultSignaturePrefix(parsed.Data.Signature), "vault")
	if err != nil {
		return solana.Signature{}, err
	}

	if err := core.VerifySignature(s.pubkey, message, sig); err != nil {
		return solana.Signature{}, err
	}
	return sig, nil
}

// stripVaultSignaturePrefix removes a versioned Vault transit prefix (e.g.
// "vault:v1:", "vault:v27:") from a signature string. Anything that does not
// match "vault:v<digits>:" exactly is returned unchanged.
func stripVaultSignaturePrefix(signature string) string {
	rest, ok := strings.CutPrefix(signature, "vault:v")
	if !ok {
		return signature
	}
	version, encoded, ok := strings.Cut(rest, ":")
	if !ok || version == "" {
		return signature
	}
	for _, c := range version {
		if c < '0' || c > '9' {
			return signature
		}
	}
	return encoded
}
