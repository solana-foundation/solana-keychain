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
	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

const (
	testKeyID  = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
	testRegion = "us-east-1"
)

// fakeKMS stubs the API interface so unit tests never touch the network.
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

// newHTTPTestClient builds a real *kms.Client pointed at an httptest server.
// Using the server's own client intentionally bypasses HTTPS enforcement.
func newHTTPTestClient(srv *httptest.Server) *kms.Client {
	return kms.New(kms.Options{
		Region:           testRegion,
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.NewStaticCredentialsProvider("test", "test", "test"),
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	})
}

func TestNewInvalidPublicKey(t *testing.T) {
	cases := map[string]Config{
		"invalid base58":                {KeyID: testKeyID, PublicKey: "not-a-valid-pubkey", Region: testRegion},
		"empty":                         {KeyID: testKeyID, PublicKey: "", Region: testRegion},
		"invalid with pre-built client": {KeyID: testKeyID, PublicKey: "not-a-valid-pubkey", Client: &fakeKMS{}},
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

func TestSignMessageVerificationFailure(t *testing.T) {
	message := []byte("test message")
	otherPriv, _ := testutils.KeyFromSeed(7)
	wrongSig := ed25519.Sign(otherPriv, message)

	s := newStubSigner(t, &fakeKMS{signOut: &kms.SignOutput{Signature: wrongSig}})

	_, err := s.SignMessage(context.Background(), message)
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if code, _ := core.CodeOf(err); code != core.CodeSigningFailed {
		t.Errorf("got %s, want SIGNING_FAILED", code)
	}
}

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
