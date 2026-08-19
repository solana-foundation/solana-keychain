package core

import (
	"regexp"
	"testing"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestIdempotencyKeyFromMessageIsDeterministicAndUUIDShaped(t *testing.T) {
	message := []byte("message-bytes")
	key := IdempotencyKeyFromMessage(message)
	if !uuidPattern.MatchString(key) {
		t.Errorf("key %q is not a version-4-shaped UUID", key)
	}
	if IdempotencyKeyFromMessage(message) != key {
		t.Error("same message bytes must derive the same key")
	}
	if IdempotencyKeyFromMessage([]byte("other-bytes")) == key {
		t.Error("different message bytes must derive a different key")
	}
}
