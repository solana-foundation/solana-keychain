// Package awskms provides an AWS KMS-backed SolanaSigner using EdDSA (Ed25519)
// signing. The KMS key must be created with key spec ECC_NIST_EDWARDS25519 and
// key usage SIGN_VERIFY; the corresponding Solana public key is supplied in
// the configuration (base58).
package awskms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// API is the subset of the AWS KMS client this signer uses. *kms.Client
// satisfies it. Supplying a pre-built client through Config.Client lets tests
// and advanced callers control the endpoint, credentials, and HTTP transport,
// and it bypasses the HTTPS-enforcing default client, so the caller owns that
// security posture.
type API interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	// DescribeKey performs the KMS DescribeKey operation (used as a health check).
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// Config configures an AWS KMS signer.
type Config struct {
	// KeyID is the AWS KMS key ID, key ARN, or alias. The key must be an
	// ECC_NIST_EDWARDS25519 key with SIGN_VERIFY usage.
	KeyID string

	// PublicKey is the base58-encoded Solana public key corresponding to the
	// KMS key.
	PublicKey string

	// Region optionally overrides the AWS region. When empty, the region is
	// resolved from the default AWS configuration chain.
	Region string

	// HTTPClientConfig holds request/connect timeouts for the default HTTP
	// client. The zero value applies core's defaults. Ignored when Client is set.
	HTTPClientConfig core.HTTPClientConfig

	// Client is an optional pre-built KMS client (or stub). When nil, New loads
	// the default AWS configuration and builds a client whose HTTP transport is
	// core.NewHTTPClient(HTTPClientConfig) — HTTPS-only with the configured
	// timeouts. When set, AWS config loading is skipped entirely and the caller
	// is responsible for the client's transport security.
	//
	// Note: the default client is a plain *http.Client, which the AWS config
	// loader cannot retrofit with a custom CA bundle. If your environment sets
	// AWS_CA_BUNDLE, construction fails with a config error — supply a
	// pre-built client here instead.
	Client API
}
