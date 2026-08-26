package memory

import (
	"context"
	"crypto/ed25519"

	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// Signer is an in-memory Ed25519 signer.
type Signer struct {
	priv ed25519.PrivateKey
	pub  solana.PublicKey
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// New builds a memory signer from cfg. Exactly one key source must be provided.
func New(cfg Config) (*Signer, error) {
	priv, err := resolvePrivateKey(cfg)
	if err != nil {
		return nil, err
	}
	var pub solana.PublicKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return &Signer{priv: priv, pub: pub}, nil
}

// Pubkey returns the signer's public key.
func (s *Signer) Pubkey() solana.PublicKey { return s.pub }

// String renders the signer without any secret material — without it, fmt's
// reflective struct printing would dump the raw private-key bytes.
func (s Signer) String() string {
	return "memory.Signer{pubkey: " + s.pub.String() + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s Signer) GoString() string { return s.String() }

// SignMessage signs arbitrary bytes with the in-memory key. Ed25519 signing is
// deterministic and never fails for a valid key, so it always returns a nil error.
func (s *Signer) SignMessage(_ context.Context, message []byte) (solana.Signature, error) {
	var sig solana.Signature
	copy(sig[:], ed25519.Sign(s.priv, message))
	return sig, nil
}

// SignTransaction signs the transaction's message bytes and inserts the signature
// at this signer's required-signer position, returning the encoded transaction and
// its completeness.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	return core.SignTransactionWith(ctx, tx, s.pub, s.SignMessage)
}

// IsAvailable always reports true for an in-memory signer.
func (s *Signer) IsAvailable(_ context.Context) bool { return true }
