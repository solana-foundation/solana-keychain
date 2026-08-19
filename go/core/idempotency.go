package core

import (
	"crypto/sha256"
	"fmt"
)

// IdempotencyKeyFromMessage derives a UUID from SHA-256(message bytes), so a
// retry of the same bytes reuses the key and the provider deduplicates the
// create.
func IdempotencyKeyFromMessage(messageBytes []byte) string {
	digest := sha256.Sum256(messageBytes)
	key := digest[:16]
	key[6] = (key[6] & 0x0f) | 0x40
	key[8] = (key[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", key[0:4], key[4:6], key[6:8], key[8:10], key[10:16])
}
