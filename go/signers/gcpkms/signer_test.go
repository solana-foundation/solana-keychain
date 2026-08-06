package gcpkms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/gagliardetto/solana-go"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/solana-foundation/solana-keychain/go/core"
	"github.com/solana-foundation/solana-keychain/go/testutils"
)

// testKeyName mirrors TEST_KEY_NAME in the Rust tests.
const testKeyName = "projects/test-project/locations/us-east1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1"

// stubKMS is a KMSClient stub, standing in for the Rust tests' wiremock server.
type stubKMS struct {
	sign   func(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error)
	getPub func(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error)
	closed bool
}

func (s *stubKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	if s.sign == nil {
		return nil, errors.New("unexpected AsymmetricSign call")
	}
	return s.sign(ctx, req)
}

func (s *stubKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	if s.getPub == nil {
		return nil, errors.New("unexpected GetPublicKey call")
	}
	return s.getPub(ctx, req)
}

func (s *stubKMS) Close() error {
	s.closed = true
	return nil
}

// signingStub returns a stub whose AsymmetricSign produces a real Ed25519
// signature over the request data with priv — the analog of the Rust tests
// mocking the response with keypair.sign_message bytes.
func signingStub(t *testing.T, priv ed25519.PrivateKey) *stubKMS {
	t.Helper()
	return &stubKMS{
		sign: func(_ context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
			if req.GetName() != testKeyName {
				t.Errorf("AsymmetricSign name = %q, want %q", req.GetName(), testKeyName)
			}
			if req.GetDigest() != nil {
				t.Error("AsymmetricSign must send raw data (PureEdDSA), not a digest")
			}
			return &kmspb.AsymmetricSignResponse{Signature: ed25519.Sign(priv, req.GetData())}, nil
		},
	}
}

// newTestSigner builds a signer over client with the deterministic test pubkey.
func newTestSigner(t *testing.T, client KMSClient) *Signer {
	t.Helper()
	s, err := New(context.Background(), Config{
		KeyName:   testKeyName,
		PublicKey: testutils.TestPublicKey().String(),
		Client:    client,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Port of test_gcp_kms_new_invalid_pubkey and test_gcp_kms_new_empty_pubkey.
func TestNewRejectsBadPublicKey(t *testing.T) {
	cases := map[string]string{
		"invalid": "invalid-pubkey",
		"empty":   "",
	}
	for name, pubkey := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), Config{
				KeyName:   testKeyName,
				PublicKey: pubkey,
				Client:    &stubKMS{},
			})
			if err == nil {
				t.Fatal("expected error for bad public key")
			}
			if code, _ := core.CodeOf(err); code != core.CodeInvalidPublicKey {
				t.Errorf("got %s, want INVALID_PUBLIC_KEY", code)
			}
		})
	}
}

// Port of test_gcp_kms_new_valid_pubkey, test_gcp_kms_pubkey, and
// test_gcp_kms_key_id_accessor.
func TestNewValidPublicKeyAndAccessors(t *testing.T) {
	want := testutils.TestPublicKey()
	s := newTestSigner(t, &stubKMS{})
	if s.Pubkey() != want {
		t.Errorf("Pubkey() = %s, want %s", s.Pubkey(), want)
	}
	if s.Pubkey().String() != want.String() {
		t.Errorf("Pubkey().String() = %s, want %s", s.Pubkey().String(), want.String())
	}
	if s.KeyName() != testKeyName {
		t.Errorf("KeyName() = %q, want %q", s.KeyName(), testKeyName)
	}
}

// Port of test_gcp_kms_sign_message_success.
func TestSignMessageSuccess(t *testing.T) {
	s := newTestSigner(t, signingStub(t, testutils.TestPrivateKey()))

	message := []byte("test message")
	sig, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatalf("sign message failed: %v", err)
	}
	if len(sig) != core.SignatureLength {
		t.Errorf("signature length = %d, want %d", len(sig), core.SignatureLength)
	}
	if !core.VerifyEd25519(s.Pubkey(), message, sig) {
		t.Error("signature should verify against the signer's pubkey")
	}
}

// Port of test_gcp_kms_sign_message_signature_verification_failure: the remote
// signs with one key while the signer is configured with a different pubkey.
func TestSignMessageVerificationFailure(t *testing.T) {
	otherSeed := bytes.Repeat([]byte{0x77}, ed25519.SeedSize)
	signingKey := ed25519.NewKeyFromSeed(otherSeed)

	s := newTestSigner(t, signingStub(t, signingKey))

	_, err := s.SignMessage(context.Background(), []byte("test message"))
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

// Port of test_gcp_kms_sign_transaction_success.
func TestSignTransactionSuccess(t *testing.T) {
	s := newTestSigner(t, signingStub(t, testutils.TestPrivateKey()))

	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("sign transaction failed: %v", err)
	}
	if res.EncodedTransaction == "" {
		t.Error("encoded transaction should not be empty")
	}
	if len(res.Signature) != core.SignatureLength {
		t.Errorf("signature length = %d, want %d", len(res.Signature), core.SignatureLength)
	}
	if !res.IsComplete() {
		t.Error("single-signer transaction should be Complete")
	}
	msgBytes, _ := tx.Message.MarshalBinary()
	if !core.VerifyEd25519(s.Pubkey(), msgBytes, res.Signature) {
		t.Error("transaction signature should verify against the message bytes")
	}
	decoded, err := solana.TransactionFromBase64(res.EncodedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Signatures[0] != res.Signature {
		t.Error("encoded transaction signature mismatch at position 0")
	}
}

// Empty-signature branch of the Rust sign_bytes (signature_bytes.is_empty()).
func TestSignMessageEmptySignature(t *testing.T) {
	s := newTestSigner(t, &stubKMS{
		sign: func(context.Context, *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
			return &kmspb.AsymmetricSignResponse{}, nil
		},
	})

	_, err := s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for empty signature")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

// Port of test_gcp_kms_sign_message_invalid_signature_length (32-byte response).
func TestSignMessageInvalidSignatureLength(t *testing.T) {
	s := newTestSigner(t, &stubKMS{
		sign: func(context.Context, *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
			return &kmspb.AsymmetricSignResponse{Signature: make([]byte, 32)}, nil
		},
	})

	_, err := s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error for 32-byte signature")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

// Port of test_gcp_kms_sign_api_error and test_gcp_kms_sign_unauthorized: any
// AsymmetricSign failure maps to REMOTE_API_ERROR with a fixed detail (the Rust
// code never copies remote error text into the error).
func TestSignRemoteAPIErrors(t *testing.T) {
	cases := map[string]error{
		"invalid argument":  status.Error(codes.InvalidArgument, "Key is not valid for signing"),
		"permission denied": status.Error(codes.PermissionDenied, "Permission denied"),
	}
	for name, apiErr := range cases {
		t.Run(name, func(t *testing.T) {
			s := newTestSigner(t, &stubKMS{
				sign: func(context.Context, *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
					return nil, apiErr
				},
			})

			_, err := s.SignMessage(context.Background(), []byte("test"))
			if err == nil {
				t.Fatal("expected remote API error")
			}
			if code, _ := core.CodeOf(err); code != core.CodeRemoteAPIError {
				t.Errorf("got %s, want REMOTE_API_ERROR", code)
			}
			var se *core.SignerError
			if !errors.As(err, &se) {
				t.Fatal("expected *core.SignerError")
			}
			if se.Detail() != "GCP KMS Sign operation failed" {
				t.Errorf("detail = %q, want fixed message without remote text", se.Detail())
			}
			if !errors.Is(err, apiErr) {
				t.Error("cause should be reachable via errors.Is")
			}
		})
	}
}

// Port of test_gcp_kms_is_available_success.
func TestIsAvailableSuccess(t *testing.T) {
	s := newTestSigner(t, &stubKMS{
		getPub: func(_ context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
			if req.GetName() != testKeyName {
				t.Errorf("GetPublicKey name = %q, want %q", req.GetName(), testKeyName)
			}
			return &kmspb.PublicKey{
				Name:      testKeyName,
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
			}, nil
		},
	})

	if !s.IsAvailable(context.Background()) {
		t.Error("expected available for EC_SIGN_ED25519 key")
	}
}

// Port of test_gcp_kms_is_available_wrong_algorithm.
func TestIsAvailableWrongAlgorithm(t *testing.T) {
	s := newTestSigner(t, &stubKMS{
		getPub: func(context.Context, *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
			return &kmspb.PublicKey{
				Name:      testKeyName,
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
			}, nil
		},
	})

	if s.IsAvailable(context.Background()) {
		t.Error("availability check should fail for wrong algorithm")
	}
}

// The Err branch of the Rust check_availability: errors are swallowed → false.
func TestIsAvailableError(t *testing.T) {
	s := newTestSigner(t, &stubKMS{
		getPub: func(context.Context, *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
			return nil, status.Error(codes.PermissionDenied, "Permission denied")
		},
	})

	if s.IsAvailable(context.Background()) {
		t.Error("availability check should swallow errors and report false")
	}
}

// Close delegates to the underlying client (Go-specific resource management).
func TestCloseDelegatesToClient(t *testing.T) {
	stub := &stubKMS{}
	s := newTestSigner(t, stub)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !stub.closed {
		t.Error("Close should close the underlying client")
	}
}
