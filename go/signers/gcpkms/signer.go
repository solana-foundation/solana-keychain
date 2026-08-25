package gcpkms

import (
	"context"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// Signer signs with an Ed25519 key held in Google Cloud KMS. AsymmetricSign is
// invoked in PureEdDSA mode with the raw message bytes, and every returned
// signature is verified against the configured public key before being
// surfaced.
//
// A Signer is immutable after New and safe for concurrent use.
type Signer struct {
	client  KMSClient
	keyName string
	pubkey  solana.PublicKey
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// String renders the signer without config detail, so fmt's reflective struct
// printing cannot surface the key resource name or client internals.
func (s Signer) String() string {
	return "gcpkms.Signer{pubkey: " + s.pubkey.String() + "}"
}

// GoString mirrors String so %#v cannot leak either.
func (s Signer) GoString() string { return s.String() }

// New builds a GCP KMS signer from cfg. When cfg.Client is nil it dials the
// official KMS client (I/O), so the returned signer is ready to use.
func New(ctx context.Context, cfg Config) (*Signer, error) {
	pubkey, err := solana.PublicKeyFromBase58(cfg.PublicKey)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPublicKey, "invalid public key", err)
	}

	client := cfg.Client
	if client == nil {
		c, err := kms.NewKeyManagementClient(ctx, cfg.ClientOptions...)
		if err != nil {
			return nil, core.WrapSignerError(core.CodeRemoteAPIError, "failed to create KMS client", err)
		}
		client = c
	}

	return &Signer{client: client, keyName: cfg.KeyName, pubkey: pubkey}, nil
}

// Pubkey returns the signer's Solana public key.
func (s *Signer) Pubkey() solana.PublicKey { return s.pubkey }

// KeyName returns the full resource name of the crypto key version.
func (s *Signer) KeyName() string { return s.keyName }

// Close releases the underlying KMS client's connections, including a client
// supplied via Config.Client — callers sharing one client across signers should
// close it themselves instead of calling Close here.
func (s *Signer) Close() error { return s.client.Close() }

// signBytes signs message with GCP KMS EdDSA signing. EC_SIGN_ED25519 operates
// in PureEdDSA mode, so the raw message bytes go in the request's data field
// (not a digest).
func (s *Signer) signBytes(ctx context.Context, message []byte) (solana.Signature, error) {
	resp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: s.keyName,
		Data: message,
	})
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeRemoteAPIError, "GCP KMS Sign operation failed", err)
	}

	sigBytes := resp.GetSignature()
	if len(sigBytes) == 0 {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed, "no signature in GCP KMS response")
	}
	sig, err := core.SignatureFromBytes(sigBytes, "gcp kms")
	if err != nil {
		return solana.Signature{}, err
	}

	if err := core.VerifySignature(s.pubkey, message, sig); err != nil {
		return solana.Signature{}, err
	}
	return sig, nil
}

// SignMessage signs arbitrary bytes with the KMS-held key.
func (s *Signer) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	return s.signBytes(ctx, message)
}

// SignTransaction signs the transaction's message bytes and inserts the
// signature at this signer's required-signer position, returning the encoded
// transaction and its completeness.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	return core.SignTransactionWith(ctx, tx, s.pubkey, s.signBytes)
}

// IsAvailable reports whether the crypto key version is reachable and uses the
// EC_SIGN_ED25519 algorithm. All errors are swallowed and reported as false.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	resp, err := s.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: s.keyName})
	if err != nil {
		return false
	}
	return resp.GetAlgorithm() == kmspb.CryptoKeyVersion_EC_SIGN_ED25519
}
