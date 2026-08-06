// Package core defines the shared SolanaSigner contract, error types, and
// transaction utilities mirrored across the Rust and TypeScript implementations
// of solana-keychain. It is the Go analog of the `@solana/keychain-core` package
// and the shared modules in the Rust crate (traits.rs, error.rs, transaction_util.rs,
// http_client_config.rs).
package core

import (
	"errors"
	"regexp"
	"strings"
)

// Code identifies a category of signer error. The string values are kept
// identical to the TypeScript `SignerErrorCode` values so the two
// implementations report the same codes.
type Code string

// The stable error codes, matching the TypeScript SignerErrorCode values.
const (
	CodeConfigError          Code = "SIGNER_CONFIG_ERROR"
	CodeExpectedSolanaSigner Code = "SIGNER_EXPECTED_SOLANA_SIGNER"
	CodeHTTPError            Code = "SIGNER_HTTP_ERROR"
	CodeInvalidPrivateKey    Code = "SIGNER_INVALID_PRIVATE_KEY"
	CodeInvalidPublicKey     Code = "SIGNER_INVALID_PUBLIC_KEY"
	CodeIOError              Code = "SIGNER_IO_ERROR"
	CodeNotAvailable         Code = "SIGNER_NOT_AVAILABLE"
	CodeParsingError         Code = "SIGNER_PARSING_ERROR"
	CodeRemoteAPIError       Code = "SIGNER_REMOTE_API_ERROR"
	CodeSerializationError   Code = "SIGNER_SERIALIZATION_ERROR"
	CodeNotInitialized       Code = "SIGNER_NOT_INITIALIZED"
	CodeSigningFailed        Code = "SIGNER_SIGNING_FAILED"
	CodeOther                Code = "SIGNER_ERROR"
)

// genericMessages maps each code to a fixed, non-sensitive message. This mirrors
// the Rust `Display` impl (rust/src/error.rs), which intentionally never includes
// the per-error detail string so that secrets cannot leak through log output.
var genericMessages = map[Code]string{
	CodeConfigError:          "Configuration error",
	CodeExpectedSolanaSigner: "Expected a Solana signer",
	CodeHTTPError:            "HTTP request failed",
	CodeInvalidPrivateKey:    "Invalid private key format",
	CodeInvalidPublicKey:     "Invalid public key",
	CodeIOError:              "IO error",
	CodeNotAvailable:         "Signer not available",
	CodeParsingError:         "Parsing error",
	CodeRemoteAPIError:       "Remote API error",
	CodeSerializationError:   "Serialization error",
	CodeNotInitialized:       "Signer not initialized",
	CodeSigningFailed:        "Signing failed",
	CodeOther:                "Signer error",
}

func (c Code) message() string {
	if m, ok := genericMessages[c]; ok {
		return m
	}
	return "Signer error"
}

// SignerError is the unified error type returned by every signer operation.
//
// Security: the per-error `detail` and the wrapped `cause` are unexported and are
// NEVER printed by Error() or GoString(); only the fixed generic message for the
// Code is surfaced. This mirrors the redaction discipline in the Rust crate
// (custom Debug impl) and the TypeScript core, ensuring key material and raw
// remote-API responses never leak through formatted output or logs.
type SignerError struct {
	Code   Code
	detail string
	cause  error
}

// NewSignerError builds a SignerError with a (private) detail string. Analog of
// the Rust `SignerError::Variant(String)` constructors and the TS
// `createSignerError`.
func NewSignerError(code Code, detail string) *SignerError {
	return &SignerError{Code: code, detail: detail}
}

// WrapSignerError builds a SignerError that wraps an underlying cause. The cause
// is reachable via errors.Unwrap but is never rendered by Error()/GoString().
func WrapSignerError(code Code, detail string, cause error) *SignerError {
	return &SignerError{Code: code, detail: detail, cause: cause}
}

// Error returns the fixed, generic message for the error's Code. It never
// includes the detail or cause (parity with Rust's Display impl).
func (e *SignerError) Error() string {
	return e.Code.message()
}

// GoString controls the `%#v` representation so that the detail/cause cannot leak
// when an error is logged with the Go-syntax verb. Mirrors Rust's redacting Debug.
func (e *SignerError) GoString() string {
	return "core.SignerError{Code: " + string(e.Code) + ", detail: [REDACTED]}"
}

// Unwrap exposes the wrapped cause for errors.Is/errors.As traversal.
func (e *SignerError) Unwrap() error { return e.cause }

// Is reports a match against another *SignerError purely by Code, so callers can
// write errors.Is(err, &core.SignerError{Code: core.CodeConfigError}).
func (e *SignerError) Is(target error) bool {
	t, ok := target.(*SignerError)
	return ok && t.Code == e.Code
}

// Detail returns the unredacted detail string. It is opt-in: nothing calls this
// during normal formatting, so detail only surfaces when a caller explicitly asks.
func (e *SignerError) Detail() string { return e.detail }

// CodeOf extracts the Code from an error if it is (or wraps) a *SignerError.
func CodeOf(err error) (Code, bool) {
	var se *SignerError
	if errors.As(err, &se) {
		return se.Code, true
	}
	return "", false
}

const defaultRemoteErrorResponseMaxLength = 256

var whitespaceRun = regexp.MustCompile(`\s+`)

// isDisallowedASCIIControl matches the same code points the TypeScript core
// strips: everything <= 0x08, 0x0b, 0x0c, 0x0e–0x1f, and 0x7f. Tab (0x09),
// newline (0x0a), and carriage return (0x0d) are intentionally allowed (they get
// collapsed by the whitespace pass).
func isDisallowedASCIIControl(r rune) bool {
	return r <= 0x08 || r == 0x0b || r == 0x0c || (r >= 0x0e && r <= 0x1f) || r == 0x7f
}

// SanitizeRemoteResponse normalizes untrusted remote-API error text before it is
// attached to an error's detail or any log. Byte-for-byte port of the TS
// `sanitizeRemoteErrorResponse`: replace disallowed control chars with spaces,
// collapse whitespace, trim, fall back to a placeholder when empty, and truncate
// past maxLength with a " [truncated]" marker.
func SanitizeRemoteResponse(responseText string) string {
	return SanitizeRemoteResponseN(responseText, defaultRemoteErrorResponseMaxLength)
}

// SanitizeRemoteResponseN is SanitizeRemoteResponse with an explicit max length.
func SanitizeRemoteResponseN(responseText string, maxLength int) string {
	var b strings.Builder
	b.Grow(len(responseText))
	for _, r := range responseText {
		if isDisallowedASCIIControl(r) {
			b.WriteByte(' ')
		} else {
			b.WriteRune(r)
		}
	}
	normalized := strings.TrimSpace(whitespaceRun.ReplaceAllString(b.String(), " "))

	if normalized == "" {
		return "[empty remote response]"
	}
	runes := []rune(normalized)
	if len(runes) <= maxLength {
		return normalized
	}
	return string(runes[:maxLength]) + " [truncated]"
}
