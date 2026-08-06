package gcpkms

import (
	"context"
	"strconv"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// Signer signs with an Ed25519 key held in Google Cloud KMS. Port of the Rust
// GcpKmsSigner: AsymmetricSign is invoked in PureEdDSA mode with the raw message
// bytes, and every returned signature is verified against the configured public
// key before being surfaced.
//
// A Signer is immutable after New and safe for concurrent use.
type Signer struct {
	client  KMSClient
	keyName string
	pubkey  solana.PublicKey
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// New builds a GCP KMS signer from cfg. When cfg.Client is nil it dials the
// official KMS client (I/O), so the returned signer is ready to use — parity
// with the Rust Signer::from_gcp_kms and the TS async factory.
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

// KeyName returns the full resource name of the crypto key version (parity with
// the Rust key_name accessor).
func (s *Signer) KeyName() string { return s.keyName }

// Close releases the underlying KMS client's connections, including a client
// supplied via Config.Client — callers sharing one client across signers should
// close it themselves instead of calling Close here. (Go-specific: the Rust
// client needs no explicit shutdown.)
func (s *Signer) Close() error { return s.client.Close() }

// signBytes signs message with GCP KMS EdDSA signing. Port of the Rust
// sign_bytes: EC_SIGN_ED25519 operates in PureEdDSA mode, so the raw message
// bytes go in the request's data field (not a digest).
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
	if len(sigBytes) != core.SignatureLength {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"invalid signature length: expected 64 bytes, got "+strconv.Itoa(len(sigBytes)))
	}

	var sig solana.Signature
	copy(sig[:], sigBytes)

	if !core.VerifyEd25519(s.pubkey, message, sig) {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed: the returned signature does not match the public key")
	}
	return sig, nil
}

// SignMessage signs arbitrary bytes with the KMS-held key.
func (s *Signer) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	return s.signBytes(ctx, message)
}

// SignTransaction signs the transaction's message bytes and inserts the
// signature at this signer's required-signer position, returning the encoded
// transaction and its completeness (port of the Rust sign_and_serialize +
// classify_signed_transaction flow).
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
	sig, err := s.signBytes(ctx, msg)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	if err := core.AddSignature(tx, s.pubkey, sig); err != nil {
		return core.SignedTransaction{}, err
	}
	encoded, err := core.Serialize(tx)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	return core.Classify(tx, encoded, sig), nil
}

// IsAvailable reports whether the crypto key version is reachable and uses the
// EC_SIGN_ED25519 algorithm. All errors are swallowed and reported as false
// (parity with the Rust check_availability GetPublicKey health check).
func (s *Signer) IsAvailable(ctx context.Context) bool {
	resp, err := s.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: s.keyName})
	if err != nil {
		return false
	}
	return resp.GetAlgorithm() == kmspb.CryptoKeyVersion_EC_SIGN_ED25519
}
