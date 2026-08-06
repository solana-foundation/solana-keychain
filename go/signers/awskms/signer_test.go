package awskms

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
	"github.com/solana-foundation/solana-keychain/go/testutils"
)

const (
	testKeyID  = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
	testRegion = "us-east-1"
)

// otherPrivateKey is a second deterministic keypair, distinct from
// testutils.TestPrivateKey, for signature-mismatch cases.
func otherPrivateKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	return ed25519.NewKeyFromSeed(seed)
}

// fakeKMS stubs the API interface so unit tests never touch the network — the
// Go analog of the Rust wiremock setup behind with_client.
type fakeKMS struct {
	signOut *kms.SignOutput
	signErr error
	descOut *kms.DescribeKeyOutput
	descErr error

	lastSignInput *kms.SignInput
}

func (f *fakeKMS) Sign(_ context.Context, params *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.lastSignInput = params
	if f.signErr != nil {
		return nil, f.signErr
	}
	return f.signOut, nil
}

func (f *fakeKMS) DescribeKey(_ context.Context, _ *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if f.descErr != nil {
		return nil, f.descErr
	}
	return f.descOut, nil
}

// setDefaultChainEnv pins the AWS default configuration chain to deterministic,
// offline values for tests that exercise New's nil-Client path: static env
// credentials, no IMDS, and no custom CA bundle (the default client is a plain
// *http.Client, which the config loader cannot retrofit with AWS_CA_BUNDLE).
func setDefaultChainEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CA_BUNDLE", "")
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
}

// newStubSigner builds a signer around a fakeKMS with the standard test pubkey.
func newStubSigner(t *testing.T, fake *fakeKMS) *Signer {
	t.Helper()
	s, err := New(context.Background(), Config{
		KeyID:     testKeyID,
		PublicKey: testutils.TestPublicKey().String(),
		Client:    fake,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// newHTTPTestClient builds a real *kms.Client pointed at an httptest server —
// the Go analog of the Rust create_test_client(endpoint_url) used with wiremock.
// Using the server's own client intentionally bypasses HTTPS enforcement, like
// Rust with_client.
func newHTTPTestClient(srv *httptest.Server) *kms.Client {
	return kms.New(kms.Options{
		Region:           testRegion,
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.NewStaticCredentialsProvider("test", "test", "test"),
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	})
}

// Port of test_kms_new_invalid_pubkey, test_kms_new_empty_pubkey, and
// test_kms_with_client_invalid_pubkey: an invalid public key fails before any
// AWS config is loaded, with or without a pre-built client.
func TestNewInvalidPublicKey(t *testing.T) {
	cases := map[string]Config{
		"invalid base58":                         {KeyID: testKeyID, PublicKey: "not-a-valid-pubkey", Region: testRegion},
		"empty":                                  {KeyID: testKeyID, PublicKey: "", Region: testRegion},
		"invalid with client (Rust with_client)": {KeyID: testKeyID, PublicKey: "not-a-valid-pubkey", Client: &fakeKMS{}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), cfg)
			if err == nil {
				t.Fatal("expected error for invalid public key")
			}
			if code, _ := core.CodeOf(err); code != core.CodeInvalidPublicKey {
				t.Errorf("got %s, want INVALID_PUBLIC_KEY", code)
			}
		})
	}
}

// Port of test_kms_new_valid_pubkey, test_kms_new_without_region,
// test_kms_pubkey, and test_kms_key_id_accessor.
func TestNewValidPublicKey(t *testing.T) {
	want := testutils.TestPublicKey()
	for _, region := range []string{testRegion, ""} {
		s, err := New(context.Background(), Config{
			KeyID:     testKeyID,
			PublicKey: want.String(),
			Region:    region,
			Client:    &fakeKMS{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if s.Pubkey() != want {
			t.Errorf("pubkey = %s, want %s", s.Pubkey(), want)
		}
		if s.Pubkey().String() != want.String() {
			t.Errorf("pubkey string round-trip mismatch")
		}
		if s.KeyID() != testKeyID {
			t.Errorf("key ID = %s, want %s", s.KeyID(), testKeyID)
		}
	}
}

// Port of test_kms_key_id_variations: ARN, bare key ID, and alias forms are all
// accepted verbatim.
func TestNewKeyIDVariations(t *testing.T) {
	keyIDs := []string{
		"arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		"12345678-1234-1234-1234-123456789012",
		"alias/my-key",
	}
	for _, keyID := range keyIDs {
		s, err := New(context.Background(), Config{
			KeyID:     keyID,
			PublicKey: testutils.TestPublicKey().String(),
			Client:    &fakeKMS{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if s.KeyID() != keyID {
			t.Errorf("key ID = %s, want %s", s.KeyID(), keyID)
		}
	}
}

// Port of test_kms_new_valid_pubkey / test_kms_different_regions through the
// default (nil Client) path: New loads the AWS config chain without error for
// any region. Static env credentials keep the chain deterministic and offline.
func TestNewDefaultClientDifferentRegions(t *testing.T) {
	setDefaultChainEnv(t)

	for _, region := range []string{"us-east-1", "us-west-2", "eu-west-1"} {
		s, err := New(context.Background(), Config{
			KeyID:     testKeyID,
			PublicKey: testutils.TestPublicKey().String(),
			Region:    region,
		})
		if err != nil {
			t.Fatalf("region %s: %v", region, err)
		}
		if s.Pubkey() != testutils.TestPublicKey() {
			t.Errorf("region %s: pubkey mismatch", region)
		}
	}
}

// Port of test_signing_algorithm_spec_from_str and test_message_type_raw, plus
// the key-spec/key-usage constants: pins the exact wire values the Rust module
// hardcodes as strings.
func TestKMSConstants(t *testing.T) {
	if got := string(signingAlgorithm); got != "ED25519_SHA_512" {
		t.Errorf("signing algorithm = %q, want ED25519_SHA_512", got)
	}
	if got := string(kmstypes.MessageTypeRaw); got != "RAW" {
		t.Errorf("message type = %q, want RAW", got)
	}
	if got := string(requiredKeySpec); got != "ECC_NIST_EDWARDS25519" {
		t.Errorf("key spec = %q, want ECC_NIST_EDWARDS25519", got)
	}
	if got := string(requiredKeyUsage); got != "SIGN_VERIFY" {
		t.Errorf("key usage = %q, want SIGN_VERIFY", got)
	}
}

// Port of test_kms_sign_message_success. Also asserts the exact Sign request
// parameters (key ID, raw message, RAW message type, ED25519_SHA_512), which the
// Rust test delegates to the SDK/wiremock.
func TestSignMessageSuccess(t *testing.T) {
	message := []byte("test message")
	sig := ed25519.Sign(testutils.TestPrivateKey(), message)

	fake := &fakeKMS{signOut: &kms.SignOutput{
		KeyId:            aws.String(testKeyID),
		Signature:        sig,
		SigningAlgorithm: signingAlgorithm,
	}}
	s := newStubSigner(t, fake)

	got, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatalf("sign message failed: %v", err)
	}
	if len(got) != core.SignatureLength {
		t.Errorf("signature length = %d, want %d", len(got), core.SignatureLength)
	}
	if !core.VerifyEd25519(s.Pubkey(), message, got) {
		t.Error("signature should verify against the signer's pubkey")
	}

	in := fake.lastSignInput
	if in == nil {
		t.Fatal("Sign was not called")
	}
	if aws.ToString(in.KeyId) != testKeyID {
		t.Errorf("request key ID = %s, want %s", aws.ToString(in.KeyId), testKeyID)
	}
	if string(in.Message) != string(message) {
		t.Error("request message bytes should be the raw message")
	}
	if in.MessageType != kmstypes.MessageTypeRaw {
		t.Errorf("request message type = %s, want RAW", in.MessageType)
	}
	if in.SigningAlgorithm != signingAlgorithm {
		t.Errorf("request signing algorithm = %s, want ED25519_SHA_512", in.SigningAlgorithm)
	}
}

// Port of test_kms_sign_message_signature_verification_failure: a valid 64-byte
// signature from the wrong key must be rejected with SIGNING_FAILED.
func TestSignMessageVerificationFailure(t *testing.T) {
	message := []byte("test message")
	wrongSig := ed25519.Sign(otherPrivateKey(), message)

	s := newStubSigner(t, &fakeKMS{signOut: &kms.SignOutput{Signature: wrongSig}})

	_, err := s.SignMessage(context.Background(), message)
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

// Port of test_kms_sign_message_invalid_signature_length and the
// test_signature_length_validation_logic table: any non-64-byte signature
// (including a missing one) is SIGNING_FAILED.
func TestSignMessageInvalidSignatureLength(t *testing.T) {
	cases := map[string]int{
		"too short":   63,
		"too long":    65,
		"empty":       0,
		"half length": 32,
	}
	for name, length := range cases {
		t.Run(name, func(t *testing.T) {
			s := newStubSigner(t, &fakeKMS{signOut: &kms.SignOutput{Signature: make([]byte, length)}})
			_, err := s.SignMessage(context.Background(), []byte("test"))
			if err == nil {
				t.Fatal("expected error for invalid signature length")
			}
			if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
				t.Errorf("got %s, want SIGNING_FAILED", code)
			}
		})
	}
}

// Port of test_kms_sign_api_error and test_kms_sign_unauthorized, exercised
// through the real AWS SDK client against an httptest endpoint (the Go analog of
// wiremock): KMS API errors map to REMOTE_API_ERROR, and the hostile remote
// message never reaches the error detail (the Rust module uses a fixed message).
func TestSignAPIError(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"invalid key usage (400)": {
			status: http.StatusBadRequest,
			body:   `{"__type":"InvalidKeyUsageException","message":"Key is not valid for signing"}`,
		},
		"unauthorized (403)": {
			status: http.StatusForbidden,
			body:   `{"__type":"AccessDeniedException","message":"User is not authorized to perform kms:Sign"}`,
		},
		"hostile error body": {
			status: http.StatusBadRequest,
			body:   "{\"__type\":\"InvalidKeyUsageException\",\"message\":\"evil\u0000\u001b[2Jsecret-leak\"}",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			s, err := New(context.Background(), Config{
				KeyID:     testKeyID,
				PublicKey: testutils.TestPublicKey().String(),
				Client:    newHTTPTestClient(srv),
			})
			if err != nil {
				t.Fatal(err)
			}

			_, err = s.SignMessage(context.Background(), []byte("test"))
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
			if se.Detail() != "aws kms sign operation failed" {
				t.Errorf("detail = %q; remote error text must not leak into the detail", se.Detail())
			}
		})
	}
}

// Port of test_kms_sign_message_success through the real SDK client + httptest
// endpoint, mirroring the wiremock JSON body (base64 Signature) exactly.
func TestSignMessageSuccessHTTPEndpoint(t *testing.T) {
	message := []byte("test message")
	sig := ed25519.Sign(testutils.TestPrivateKey(), message)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"KeyId":"` + testKeyID + `","Signature":"` +
			base64.StdEncoding.EncodeToString(sig) + `","SigningAlgorithm":"ED25519_SHA_512"}`))
	}))
	defer srv.Close()

	s, err := New(context.Background(), Config{
		KeyID:     testKeyID,
		PublicKey: testutils.TestPublicKey().String(),
		Client:    newHTTPTestClient(srv),
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.SignMessage(context.Background(), message)
	if err != nil {
		t.Fatalf("sign message failed: %v", err)
	}
	if !core.VerifyEd25519(s.Pubkey(), message, got) {
		t.Error("signature should verify against the signer's pubkey")
	}
}

// Port of test_kms_is_available_success, _wrong_key_spec, _wrong_key_usage,
// _disabled_key, plus the missing-metadata and transport-error branches of the
// Rust check_availability.
func TestIsAvailable(t *testing.T) {
	metadata := func(spec kmstypes.KeySpec, usage kmstypes.KeyUsageType, enabled bool) *kms.DescribeKeyOutput {
		return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
			KeyId:    aws.String(testKeyID),
			KeySpec:  spec,
			KeyUsage: usage,
			Enabled:  enabled,
		}}
	}
	cases := map[string]struct {
		fake *fakeKMS
		want bool
	}{
		"success":        {&fakeKMS{descOut: metadata(requiredKeySpec, requiredKeyUsage, true)}, true},
		"wrong key spec": {&fakeKMS{descOut: metadata(kmstypes.KeySpecRsa2048, requiredKeyUsage, true)}, false},
		"wrong key usage": {
			&fakeKMS{descOut: metadata(requiredKeySpec, kmstypes.KeyUsageTypeEncryptDecrypt, true)}, false,
		},
		"disabled key": {&fakeKMS{descOut: metadata(requiredKeySpec, requiredKeyUsage, false)}, false},
		"no metadata":  {&fakeKMS{descOut: &kms.DescribeKeyOutput{}}, false},
		"describe error": {
			&fakeKMS{descErr: core.NewSignerError(core.CodeRemoteAPIError, "boom")}, false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := newStubSigner(t, tc.fake)
			if got := s.IsAvailable(context.Background()); got != tc.want {
				t.Errorf("IsAvailable = %v, want %v", got, tc.want)
			}
		})
	}
}

// Port of test_kms_sign_transaction_success: KMS signs the transaction's message
// bytes; the result is complete, encodable, and carries the signature at the
// payer's position.
func TestSignTransactionSuccess(t *testing.T) {
	tx, err := testutils.CreateTestTransaction(testutils.TestPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(testutils.TestPrivateKey(), msg)

	fake := &fakeKMS{signOut: &kms.SignOutput{Signature: sig}}
	s := newStubSigner(t, fake)

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
	if string(fake.lastSignInput.Message) != string(msg) {
		t.Error("KMS should be asked to sign the transaction message bytes")
	}
	decoded, err := solana.TransactionFromBase64(res.EncodedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Signatures[0] != res.Signature {
		t.Error("encoded transaction signature mismatch at position 0")
	}
}

// HTTPS enforcement: with no Client override, the signer's SDK client uses
// core.NewHTTPClient, which blocks non-HTTPS endpoints with CONFIG_ERROR. The
// endpoint is redirected to an http:// URL via the SDK's standard
// AWS_ENDPOINT_URL_KMS environment variable; no request ever leaves the process.
func TestDefaultClientRejectsHTTPEndpoint(t *testing.T) {
	setDefaultChainEnv(t)
	t.Setenv("AWS_ENDPOINT_URL_KMS", "http://127.0.0.1:1")

	s, err := New(context.Background(), Config{
		KeyID:     testKeyID,
		PublicKey: testutils.TestPublicKey().String(),
		Region:    testRegion,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.SignMessage(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected HTTPS enforcement error")
	}
	if code, _ := core.CodeOf(err); code != core.CodeConfigError {
		t.Errorf("got %s, want CONFIG_ERROR", code)
	}

	if s.IsAvailable(context.Background()) {
		t.Error("IsAvailable should be false when the transport blocks the request")
	}
}
