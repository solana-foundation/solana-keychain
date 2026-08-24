package testutils

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// RequireEnv returns the trimmed value of the environment variable key, failing
// the test if it is unset or blank.
func RequireEnv(t *testing.T, key string) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		t.Fatalf("%s must be set for integration tests", key)
	}
	return v
}

// AssertCode fails the test unless err carries the wanted core error code.
func AssertCode(t *testing.T, err error, want core.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", want)
	}
	got, ok := core.CodeOf(err)
	if !ok {
		t.Fatalf("expected *core.SignerError, got %T: %v", err, err)
	}
	if got != want {
		t.Errorf("error code = %s, want %s (detail: %s)", got, want, Detail(t, err))
	}
}

// Detail returns the redacted detail of a *core.SignerError, failing the test
// if err is not one.
func Detail(t *testing.T, err error) string {
	t.Helper()
	var se *core.SignerError
	if !errors.As(err, &se) {
		t.Fatalf("expected *core.SignerError, got %T: %v", err, err)
	}
	return se.Detail()
}

// AssertDetailContains fails the test unless err is a *core.SignerError whose
// detail contains want.
func AssertDetailContains(t *testing.T, err error, want string) {
	t.Helper()
	if detail := Detail(t, err); !strings.Contains(detail, want) {
		t.Errorf("detail = %q, want it to contain %q", detail, want)
	}
}

// AssertRedacted renders signer (and, for a pointer, its element) through the
// %v, %+v, %s, and %#v verbs and fails the test if any rendering contains one
// of secrets, omits typeName, or omits one of mustContain.
func AssertRedacted(t *testing.T, signer any, typeName string, secrets []string, mustContain ...string) {
	t.Helper()
	values := []any{signer}
	if v := reflect.ValueOf(signer); v.Kind() == reflect.Pointer && !v.IsNil() {
		values = append(values, v.Elem().Interface())
	}
	for _, v := range values {
		for _, rendered := range []string{
			fmt.Sprintf("%v", v),
			fmt.Sprintf("%+v", v),
			fmt.Sprintf("%s", v),
			fmt.Sprintf("%#v", v),
		} {
			for _, secret := range secrets {
				if strings.Contains(rendered, secret) {
					t.Errorf("rendered signer leaks secret material: %s", rendered)
				}
			}
			if !strings.Contains(rendered, typeName) {
				t.Errorf("rendered signer should identify the type: %s", rendered)
			}
			for _, want := range mustContain {
				if !strings.Contains(rendered, want) {
					t.Errorf("rendered signer should include %q: %s", want, rendered)
				}
			}
		}
	}
}

// StartTLSServer starts an httptest TLS server for handler and closes it on
// test cleanup.
func StartTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// WriteJSON writes status and the JSON encoding of body to w.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// WriteRawJSON writes status and a pre-encoded JSON body to w.
func WriteRawJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
