package dfns

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// Dfns User Action Signing flow. See
// https://docs.dfns.co/api-reference/auth/signing-flows#asymetric-keys-signing-flow

// userActionInitRequest is the challenge request posted to /auth/action/init.
type userActionInitRequest struct {
	UserActionPayload    string `json:"userActionPayload"`
	UserActionHTTPMethod string `json:"userActionHttpMethod"`
	UserActionHTTPPath   string `json:"userActionHttpPath"`
	UserActionServerKind string `json:"userActionServerKind"`
}

// userActionInitResponse is the challenge returned by /auth/action/init.
type userActionInitResponse struct {
	Challenge           string           `json:"challenge"`
	ChallengeIdentifier string           `json:"challengeIdentifier"`
	AllowCredentials    allowCredentials `json:"allowCredentials"`
}

type allowCredentials struct {
	Key []allowCredential `json:"key"`
}

type allowCredential struct {
	ID string `json:"id"`
}

// userActionSignRequest is the signed assertion posted to /auth/action.
type userActionSignRequest struct {
	ChallengeIdentifier string       `json:"challengeIdentifier"`
	FirstFactor         keyAssertion `json:"firstFactor"`
}

type keyAssertion struct {
	Kind                string              `json:"kind"`
	CredentialAssertion credentialAssertion `json:"credentialAssertion"`
}

type credentialAssertion struct {
	CredID     string `json:"credId"`
	ClientData string `json:"clientData"`
	Signature  string `json:"signature"`
}

// userActionResponse carries the token returned by /auth/action.
type userActionResponse struct {
	UserAction string `json:"userAction"`
}

// clientData is the challenge payload signed by the credential key. The field
// order (challenge, then type) fixes the exact byte layout that is signed and
// verified by Dfns.
type clientData struct {
	Challenge string `json:"challenge"`
	Type      string `json:"type"`
}

// signUserAction performs the Dfns User Action Signing flow for a mutating API
// request and returns the token to include as the x-dfns-useraction header.
func (s *Signer) signUserAction(ctx context.Context, httpMethod, httpPath, body string) (string, error) {
	// Request a challenge.
	initBody, err := core.MarshalCanonicalJSON(userActionInitRequest{
		UserActionPayload:    body,
		UserActionHTTPMethod: httpMethod,
		UserActionHTTPPath:   httpPath,
		UserActionServerKind: "Api",
	})
	if err != nil {
		return "", err
	}
	initData, err := s.do(ctx, http.MethodPost, "/auth/action/init", initBody, nil, "user action init failed with status")
	if err != nil {
		return "", err
	}
	var challenge userActionInitResponse
	if err := json.Unmarshal(initData, &challenge); err != nil {
		return "", core.WrapSignerError(core.CodeSerializationError, "failed to parse action init response", err)
	}

	// Verify the credential is allowed.
	allowed := false
	for _, c := range challenge.AllowCredentials.Key {
		if c.ID == s.credID {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", core.NewSignerError(core.CodeConfigError, "credential "+s.credID+" not in allowed credentials")
	}

	// Sign the challenge.
	clientDataBytes, err := core.MarshalCanonicalJSON(clientData{Challenge: challenge.Challenge, Type: "key.get"})
	if err != nil {
		return "", err
	}
	signatureBytes, err := signChallenge(s.privateKeyPEM, clientDataBytes)
	if err != nil {
		return "", err
	}

	// Submit the signed challenge.
	signBody, err := core.MarshalCanonicalJSON(userActionSignRequest{
		ChallengeIdentifier: challenge.ChallengeIdentifier,
		FirstFactor: keyAssertion{
			Kind: "Key",
			CredentialAssertion: credentialAssertion{
				CredID:     s.credID,
				ClientData: base64.RawURLEncoding.EncodeToString(clientDataBytes),
				Signature:  base64.RawURLEncoding.EncodeToString(signatureBytes),
			},
		},
	})
	if err != nil {
		return "", err
	}
	signData, err := s.do(ctx, http.MethodPost, "/auth/action", signBody, nil, "user action sign failed with status")
	if err != nil {
		return "", err
	}
	var action userActionResponse
	if err := json.Unmarshal(signData, &action); err != nil {
		return "", core.WrapSignerError(core.CodeSerializationError, "failed to parse action response", err)
	}
	return action.UserAction, nil
}

// signChallenge signs the challenge client data with an Ed25519, ECDSA P-256,
// or RSA private key in PEM format. Ed25519 yields a raw 64-byte signature,
// P-256 an ASN.1 DER-encoded ECDSA signature over the SHA-256 digest, and RSA
// a PKCS#1 v1.5 signature over the SHA-256 digest.
func signChallenge(privateKeyPEM string, data []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errUnsupportedKey()
	}

	// PKCS#8: Ed25519, ECDSA P-256, or RSA.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k := key.(type) {
		case ed25519.PrivateKey:
			return ed25519.Sign(k, data), nil
		case *ecdsa.PrivateKey:
			if k.Curve == elliptic.P256() {
				return signECDSAP256(k, data)
			}
		case *rsa.PrivateKey:
			digest := sha256.Sum256(data)
			sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
			if err != nil {
				return nil, core.WrapSignerError(core.CodeSigningFailed, "failed to sign challenge with RSA key", err)
			}
			return sig, nil
		}
		return nil, errUnsupportedKey()
	}

	// SEC1: ECDSA P-256 ("EC PRIVATE KEY" blocks).
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil && key.Curve == elliptic.P256() {
		return signECDSAP256(key, data)
	}

	return nil, errUnsupportedKey()
}

// signECDSAP256 produces a DER-encoded ECDSA signature over the SHA-256 digest
// of data.
func signECDSAP256(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, core.WrapSignerError(core.CodeSigningFailed, "failed to sign challenge with P256 key", err)
	}
	return sig, nil
}

// errUnsupportedKey is the shared error for unparseable or unsupported PEM keys.
func errUnsupportedKey() error {
	return core.NewSignerError(core.CodeInvalidPrivateKey, "unsupported PEM key type (expected Ed25519, P256, or RSA)")
}
