// Package core defines the shared SolanaSigner contract, error types, and
// transaction utilities used by every solana-keychain Go backend.
package core

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
)

// Code identifies a category of signer error. The string values are stable
// identifiers surfaced to callers and must not change.
type Code string

// The stable error codes.
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
	CodeBroadcastUnconfirmed Code = "SIGNER_BROADCAST_UNCONFIRMED"
	CodeOther                Code = "SIGNER_ERROR"
)

// genericMessages maps each code to a fixed, non-sensitive message. The
// per-error detail string is intentionally never included so that secrets
// cannot leak through log output.
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
	CodeBroadcastUnconfirmed: "Broadcast unconfirmed; the provider may have executed the transaction",
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
// Code is surfaced, ensuring key material and raw remote-API responses never leak
// through formatted output or logs.
type SignerError struct {
	Code Code
	// ProviderTxID is the provider-side transaction id for
	// CodeBroadcastUnconfirmed errors ("" otherwise). It is deliberately
	// exported and rendered by Error(): it is the caller's only handle to check
	// the transaction's outcome before retrying, and contains no secret
	// material.
	ProviderTxID string
	// ProviderStatus is the provider's HTTP status when its response was the
	// failure, and 0 otherwise. Exported for the same reason as ProviderTxID.
	ProviderStatus int
	// IdempotencyKey is the key used to submit an ambiguous create, when available.
	IdempotencyKey string
	detail         string
	cause          error
}

// NewSignerError builds a SignerError with a (private) detail string.
func NewSignerError(code Code, detail string) *SignerError {
	return &SignerError{Code: code, detail: detail}
}

// WrapSignerError builds a SignerError that wraps an underlying cause. The cause
// is reachable via errors.Unwrap but is never rendered by Error()/GoString().
func WrapSignerError(code Code, detail string, cause error) *SignerError {
	return &SignerError{Code: code, detail: detail, cause: cause}
}

// Error returns the fixed, generic message for the error's Code plus the
// provider transaction id when present. It never includes the detail or cause.
func (e *SignerError) Error() string {
	if e.ProviderTxID != "" {
		return e.Code.message() + " (provider transaction id: " + e.ProviderTxID + ")"
	}
	return e.Code.message()
}

// GoString controls the `%#v` representation so that the detail/cause cannot leak
// when an error is logged with the Go-syntax verb.
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

// NewBroadcastUnconfirmedError reports a failure after the provider has
// accepted a transaction it broadcasts itself, carrying the provider-side
// transaction id the caller must check before retrying. providerTxID is "" when
// the create failed before an id was known.
func NewBroadcastUnconfirmedError(providerTxID, detail string) *SignerError {
	return &SignerError{Code: CodeBroadcastUnconfirmed, ProviderTxID: providerTxID, detail: detail}
}

// UnconfirmedUnlessRejected reports a failed create as CodeBroadcastUnconfirmed
// unless a 4xx other than 408 rules the transaction out. A 408 is a timeout
// reached while the request was being processed, so it does not rule the
// transaction out. status is 0 when no response arrived,
// and is passed on only when the response was the failure. providerTxID is the id
// read out of the response body when one was readable there, and "" when the
// failure came before any id was known. idempotencyKey is the key the create was
// submitted under, and "" for a backend that sends none.
func UnconfirmedUnlessRejected(status int, providerTxID, idempotencyKey string, err error) error {
	if status >= 400 && status < 500 && status != http.StatusRequestTimeout {
		return err
	}
	detail := err.Error()
	var se *SignerError
	if errors.As(err, &se) {
		detail = se.Detail()
	}
	out := NewBroadcastUnconfirmedError(providerTxID, detail)
	out.IdempotencyKey = idempotencyKey
	if status >= 400 {
		out.ProviderStatus = status
	}
	return out
}

// CodeOf extracts the Code from an error if it is (or wraps) a *SignerError.
func CodeOf(err error) (Code, bool) {
	var se *SignerError
	if errors.As(err, &se) {
		return se.Code, true
	}
	return "", false
}

const defaultRemoteErrorResponseMaxLength = 256

// whitespaceRun matches runs of whitespace. Go's \s covers only ASCII
// whitespace, so Unicode space separators (\p{Zs}: NBSP, ideographic space, …),
// line/paragraph separators (U+2028/U+2029), and the BOM (U+FEFF) are added
// explicitly so the collapse covers those code points too.
var whitespaceRun = regexp.MustCompile(`[\s\p{Zs}\x{2028}\x{2029}\x{FEFF}]+`)

// isDisallowedASCIIControl matches the control code points that get stripped:
// everything <= 0x08, 0x0b, 0x0c, 0x0e–0x1f, and 0x7f. Tab (0x09), newline
// (0x0a), and carriage return (0x0d) are intentionally allowed (they get
// collapsed by the whitespace pass).
func isDisallowedASCIIControl(r rune) bool {
	return r <= 0x08 || r == 0x0b || r == 0x0c || (r >= 0x0e && r <= 0x1f) || r == 0x7f
}

// SanitizeRemoteResponse normalizes untrusted remote-API error text before it is
// attached to an error's detail or any log: replace disallowed control chars with
// spaces, collapse whitespace, trim, fall back to a placeholder when empty, and
// truncate past maxLength with a " [truncated]" marker.
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

// NewNotInitializedError reports that a signer was used before its remote
// identity was resolved.
func NewNotInitializedError(backend string) error {
	return NewSignerError(CodeNotInitialized, backend+" signer is not initialized")
}
