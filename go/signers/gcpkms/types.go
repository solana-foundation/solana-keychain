// Package gcpkms provides a Google Cloud KMS-backed SolanaSigner using EdDSA
// (Ed25519) signing.
//
// The KMS crypto key must be created with purpose ASYMMETRIC_SIGN and algorithm
// EC_SIGN_ED25519. Cloud KMS operates in PureEdDSA mode for that algorithm, so
// AsymmetricSign is called with the raw message bytes in the request's data
// field — never a pre-computed digest.
package gcpkms

import (
	"context"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
)

// KMSClient is the subset of the Cloud KMS API the signer uses. It is satisfied
// by *kms.KeyManagementClient and exists so tests (and callers with bespoke
// client setups) can supply a stub via Config.Client.
type KMSClient interface {
	// AsymmetricSign signs data with the named crypto key version.
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	// GetPublicKey fetches the public key of the named crypto key version.
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
	// Close releases the client's underlying connections.
	Close() error
}

// Compile-time proof that the official client satisfies KMSClient.
var _ KMSClient = (*kms.KeyManagementClient)(nil)

// Config configures a GCP KMS signer.
type Config struct {
	// KeyName is the full resource name of the crypto key version, e.g.
	// "projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1".
	KeyName string

	// PublicKey is the signer's Solana public key (base58-encoded). Cloud KMS
	// never returns the raw key with signatures, so the caller supplies it up
	// front; every returned signature is verified against it.
	PublicKey string

	// Client optionally supplies a pre-built KMS client. When set, New performs
	// no dialing and the caller owns the client's configuration — including its
	// endpoint and transport security posture. When nil, New dials the official
	// client with ClientOptions.
	Client KMSClient

	// ClientOptions are passed through to kms.NewKeyManagementClient when
	// Client is nil (credentials, endpoint, etc.). The zero value uses
	// Application Default Credentials.
	ClientOptions []option.ClientOption
}
