package core

import (
	"errors"
	"strings"
	"testing"
)

// TestErrorMessageIsRedacted ports the Rust test_display_is_redacted_for_all_variants:
// neither Error() nor GoString() may ever contain the per-error detail or cause.
func TestErrorMessageIsRedacted(t *testing.T) {
	const secret = "sensitive-secret-material"
	codes := []Code{
		CodeConfigError, CodeExpectedSolanaSigner, CodeHTTPError, CodeInvalidPrivateKey,
		CodeInvalidPublicKey, CodeIOError, CodeNotAvailable, CodeParsingError,
		CodeRemoteAPIError, CodeSerializationError, CodeNotInitialized, CodeSigningFailed, CodeOther,
	}
	for _, code := range codes {
		err := NewSignerError(code, secret)
		if strings.Contains(err.Error(), secret) {
			t.Errorf("Error() leaked detail for %s: %q", code, err.Error())
		}
		if strings.Contains(err.GoString(), secret) {
			t.Errorf("GoString() leaked detail for %s: %q", code, err.GoString())
		}
		wrapped := WrapSignerError(code, secret, errors.New(secret))
		if strings.Contains(wrapped.Error(), secret) {
			t.Errorf("Error() leaked wrapped cause for %s", code)
		}
	}
}

// TestErrorStableMessages ports the Rust test_display_messages_are_stable_and_generic.
func TestErrorStableMessages(t *testing.T) {
	cases := map[Code]string{
		CodeInvalidPrivateKey:  "Invalid private key format",
		CodeInvalidPublicKey:   "Invalid public key",
		CodeSigningFailed:      "Signing failed",
		CodeRemoteAPIError:     "Remote API error",
		CodeHTTPError:          "HTTP request failed",
		CodeSerializationError: "Serialization error",
		CodeConfigError:        "Configuration error",
		CodeNotAvailable:       "Signer not available",
		CodeIOError:            "IO error",
		CodeOther:              "Signer error",
	}
	for code, want := range cases {
		if got := NewSignerError(code, "x").Error(); got != want {
			t.Errorf("code %s: Error() = %q, want %q", code, got, want)
		}
	}
}

func TestErrorsIsAndCodeOf(t *testing.T) {
	err := WrapSignerError(CodeConfigError, "detail", errors.New("boom"))
	if !errors.Is(err, &SignerError{Code: CodeConfigError}) {
		t.Error("errors.Is should match by code")
	}
	if errors.Is(err, &SignerError{Code: CodeHTTPError}) {
		t.Error("errors.Is should not match a different code")
	}
	if got, ok := CodeOf(err); !ok || got != CodeConfigError {
		t.Errorf("CodeOf = %q,%v want CodeConfigError,true", got, ok)
	}
	if errors.Unwrap(err) == nil {
		t.Error("Unwrap should return the wrapped cause")
	}
}

func TestSanitizeRemoteResponse(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"empty", "", "[empty remote response]"},
		{"whitespace only", "   \t\n ", "[empty remote response]"},
		{"collapse whitespace", "a   b\t\nc", "a b c"},
		{"trim", "  hello  ", "hello"},
		{"control chars replaced", "a\x00b\x07c", "a b c"},
		{"keeps normal text", "Bad Request: invalid wallet", "Bad Request: invalid wallet"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeRemoteResponse(tc.in); got != tc.want {
				t.Errorf("SanitizeRemoteResponse(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeRemoteResponseTruncates(t *testing.T) {
	in := strings.Repeat("x", 300)
	got := SanitizeRemoteResponseN(in, 256)
	want := strings.Repeat("x", 256) + " [truncated]"
	if got != want {
		t.Errorf("truncation mismatch: got %d chars ending %q", len(got), got[len(got)-15:])
	}
}
