package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/solana-foundation/solana-go/v2"
	"github.com/solana-foundation/solana-go/v2/programs/system"
)

// Golden wire-format vectors: pin the exact serialized bytes this library must
// produce for one canonical transaction. These constants are frozen — if any
// assertion here fails, the signer's serialized output has drifted from the
// Solana wire format and every transaction it emits is suspect. Never
// regenerate the vectors to make the suite pass.
const (
	goldenPubkey      = "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR"
	goldenMessageB64  = "AQABAy9eeafDiEgWnTBNWD9gOXq18+y88Yau4GT2EapoEZcwAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQICAAEMAgAAAEBCDwAAAAAA"
	goldenSignedTxB64 = "AaynSvis6Ib7Ryu0FHtVWQEOaHwqjVtlBUmx5dS8lnDzYlucZlaLBuiwHh2yKYxh9BpT4SnIu2Lkp+dmBFf9IgcBAAEDL155p8OISBadME1YP2A5erXz7Lzxhq7gZPYRqmgRlzACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAgIAAQwCAAAAQEIPAAAAAAA="
)

// canonicalKeypairBytes is the 64-byte (seed‖pubkey) Ed25519 keypair behind the
// golden vectors. Its base58 pubkey is goldenPubkey.
var canonicalKeypairBytes = []byte{
	41, 99, 180, 88, 51, 57, 48, 80, 61, 63, 219, 75, 176, 49, 116, 254,
	227, 176, 196, 204, 122, 47, 166, 133, 155, 252, 217, 0, 253, 17, 49, 143,
	47, 94, 121, 167, 195, 136, 72, 22, 157, 48, 77, 88, 63, 96, 57, 122,
	181, 243, 236, 188, 241, 134, 174, 224, 100, 246, 17, 170, 104, 17, 151, 48,
}

// buildGoldenTransaction builds the canonical transaction behind the golden
// vectors: a System transfer of 1_000_000 lamports from the canonical signer
// to the all-0x02 recipient, zero recent blockhash, payer = signer.
func buildGoldenTransaction(t *testing.T) (priv ed25519.PrivateKey, from solana.PublicKey, tx *solana.Transaction) {
	t.Helper()
	priv = ed25519.PrivateKey(canonicalKeypairBytes)
	copy(from[:], priv.Public().(ed25519.PublicKey))

	var to solana.PublicKey
	for i := range to {
		to[i] = 2
	}

	inst := system.NewTransferInstruction(1_000_000, from, to).Build()
	var err error
	tx, err = solana.NewTransaction(
		[]solana.Instruction{inst},
		solana.Hash{},
		solana.TransactionPayer(from),
	)
	if err != nil {
		t.Fatal(err)
	}
	return priv, from, tx
}

func TestGoldenVectors(t *testing.T) {
	priv, from, tx := buildGoldenTransaction(t)

	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var sig solana.Signature
	copy(sig[:], ed25519.Sign(priv, msgBytes))
	if err := AddSignature(tx, from, sig); err != nil {
		t.Fatal(err)
	}
	encoded, err := Serialize(tx)
	if err != nil {
		t.Fatal(err)
	}
	gotMsg := base64.StdEncoding.EncodeToString(msgBytes)

	if from.String() != goldenPubkey {
		t.Errorf("pubkey = %s, want %s", from.String(), goldenPubkey)
	}
	if gotMsg != goldenMessageB64 {
		t.Errorf("message-bytes drift from golden vector:\n got =%s\n want=%s", gotMsg, goldenMessageB64)
	}
	if encoded != goldenSignedTxB64 {
		t.Errorf("signed-tx drift from golden vector:\n got =%s\n want=%s", encoded, goldenSignedTxB64)
	}
	if !VerifyEd25519(from, msgBytes, sig) {
		t.Error("signature must verify")
	}
}
