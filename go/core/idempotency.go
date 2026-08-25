package core

import (
	"crypto/sha256"
)

// IdempotencyKeyFromMessage derives a UUID from SHA-256(message bytes), so a
// retry of the same bytes reuses the key and the provider deduplicates the
// create.
func IdempotencyKeyFromMessage(messageBytes []byte) string {
	digest := sha256.Sum256(messageBytes)
	var key [16]byte
	copy(key[:], digest[:16])
	return FormatUUID(key)
}
