package awskms

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

const (
	signingAlgorithm = kmstypes.SigningAlgorithmSpecEd25519Sha512
	requiredKeySpec  = kmstypes.KeySpecEccNistEdwards25519
	requiredKeyUsage = kmstypes.KeyUsageTypeSignVerify
)

// Signer signs with an Ed25519 key held in AWS KMS. All fields are immutable
// after New, and the underlying KMS client is concurrency-safe, so a Signer is
// safe for concurrent use.
type Signer struct {
	client API
	keyID  string
	pub    solana.PublicKey
}

var _ core.TransactionSigner = (*Signer)(nil)

// String renders the signer without config detail, so fmt's reflective struct
// printing cannot surface the key ARN or client internals.
func (s Signer) String() string {
	return "awskms.Signer{pubkey: " + s.pub.String() + "}"
}

// GoString mirrors String so %#v cannot leak either.
func (s Signer) GoString() string { return s.String() }

// New builds an AWS KMS signer from cfg. The public key is validated before
// any AWS configuration is loaded. When cfg.Client is nil, the default AWS
// configuration is loaded (credentials chain, cfg.Region override) and the KMS
// client is built with an HTTPS-enforcing core.NewHTTPClient transport.
func New(ctx context.Context, cfg Config) (*Signer, error) {
	pub, err := solana.PublicKeyFromBase58(cfg.PublicKey)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPublicKey, "invalid public key: "+err.Error(), err)
	}

	client := cfg.Client
	if client == nil {
		opts := []func(*config.LoadOptions) error{
			config.WithHTTPClient(core.NewHTTPClient(cfg.HTTPClientConfig)),
		}
		if cfg.Region != "" {
			opts = append(opts, config.WithRegion(cfg.Region))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, core.WrapSignerError(core.CodeConfigError, "failed to load aws configuration", err)
		}
		client = kms.NewFromConfig(awsCfg)
	}

	return &Signer{client: client, keyID: cfg.KeyID, pub: pub}, nil
}

func (s *Signer) Pubkey() solana.PublicKey { return s.pub }

func (s *Signer) KeyID() string { return s.keyID }

// SignMessage signs arbitrary bytes via the KMS Sign operation and verifies the
// returned signature against the configured public key before surfacing it.
func (s *Signer) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	return s.signBytes(ctx, message)
}

// SignTransaction signs the transaction's message bytes via AWS KMS, inserts the
// signature at this signer's required-signer position, and returns the encoded
// transaction with its completeness.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	return core.SignTransactionWith(ctx, tx, s.pub, s.signBytes)
}

// IsAvailable reports whether the KMS key is reachable and usable for Solana
// signing: DescribeKey must succeed and the key must be an enabled
// ECC_NIST_EDWARDS25519 key with SIGN_VERIFY usage. All errors are swallowed
// and reported as false.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	out, err := s.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(s.keyID)})
	if err != nil || out.KeyMetadata == nil {
		return false
	}
	md := out.KeyMetadata
	return md.KeySpec == requiredKeySpec && md.Enabled && md.KeyUsage == requiredKeyUsage
}

// signBytes performs the KMS Sign call with MessageType RAW and the
// ED25519_SHA_512 signing algorithm, validates the 64-byte signature, and
// verifies it against the configured public key.
func (s *Signer) signBytes(ctx context.Context, message []byte) (solana.Signature, error) {
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          message,
		MessageType:      kmstypes.MessageTypeRaw,
		SigningAlgorithm: signingAlgorithm,
	})
	if err != nil {
		// Preserve SignerError codes raised inside the transport (e.g. the
		// HTTPS-only guard's CodeConfigError), consistent with the other backends.
		var se *core.SignerError
		if errors.As(err, &se) {
			return solana.Signature{}, se
		}
		return solana.Signature{}, core.WrapSignerError(core.CodeRemoteAPIError, "aws kms sign operation failed", err)
	}

	if len(out.Signature) == 0 {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed, "no signature in aws kms response")
	}
	sig, err := core.SignatureFromBytes(out.Signature, "aws kms")
	if err != nil {
		return solana.Signature{}, err
	}

	if err := core.VerifySignature(s.pub, message, sig); err != nil {
		return solana.Signature{}, err
	}
	return sig, nil
}
