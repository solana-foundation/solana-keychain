package core

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSleepContextReportsCancellationAsAFailedRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := SleepContext(ctx, time.Minute)
	if code, ok := CodeOf(err); !ok || code != CodeHTTPError {
		t.Errorf("got code %q (ok=%v), want CodeHTTPError", code, ok)
	}
}

// A plain failure here would invite a retry of a transaction already on chain.
func TestSleepContextUnconfirmedReportsCancellationAsUnconfirmed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := SleepContextUnconfirmed(ctx, time.Minute, "provider-tx-1")

	var se *SignerError
	if !errors.As(err, &se) {
		t.Fatalf("got %v, want a *SignerError", err)
	}
	if se.Code != CodeBroadcastUnconfirmed {
		t.Errorf("got code %q, want CodeBroadcastUnconfirmed", se.Code)
	}
	if se.ProviderTxID != "provider-tx-1" {
		t.Errorf("got provider transaction id %q, want provider-tx-1", se.ProviderTxID)
	}
	if !errors.Is(err, context.Canceled) {
		t.Error("the cancellation cause is not reachable via errors.Is")
	}
}

func TestSleepContextUnconfirmedReturnsNilWhenTheWaitCompletes(t *testing.T) {
	if err := SleepContextUnconfirmed(context.Background(), time.Millisecond, "provider-tx-1"); err != nil {
		t.Fatal(err)
	}
}

// A silently truncated body would surface as a confusing JSON parse error, so
// anything over MaxResponseBytes must be rejected explicitly.
func TestSendRequestRejectsOversizedBody(t *testing.T) {
	cases := map[string]struct {
		size    int
		wantErr bool
	}{
		"at the cap":    {size: MaxResponseBytes},
		"one byte over": {size: MaxResponseBytes + 1, wantErr: true},
		"well over":     {size: MaxResponseBytes * 2, wantErr: true},
		"well under":    {size: 128},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(bytes.Repeat([]byte("a"), tc.size))
			}))
			defer srv.Close()

			req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			status, body, err := SendRequest(srv.Client(), req, "test")
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("SendRequest failed: %v", err)
				}
				if status != http.StatusOK || len(body) != tc.size {
					t.Errorf("got status %d, %d body bytes; want 200, %d", status, len(body), tc.size)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error for an oversized body")
			}
			var se *SignerError
			if !errors.As(err, &se) {
				t.Fatalf("expected *SignerError, got %T", err)
			}
			if se.Code != CodeSerializationError {
				t.Errorf("code = %s, want %s", se.Code, CodeSerializationError)
			}
			if !strings.Contains(se.Detail(), "response exceeded maximum size") {
				t.Errorf("detail = %q, want the over-size message", se.Detail())
			}
		})
	}
}

func TestNewRemoteAPIError(t *testing.T) {
	err := NewRemoteAPIError("acme API error", 503, []byte("boom\x01\ttoday"))

	if err.Code != CodeRemoteAPIError {
		t.Errorf("code = %s, want %s", err.Code, CodeRemoteAPIError)
	}
	if got, want := err.Detail(), "acme API error 503: boom today"; got != want {
		t.Errorf("detail = %q, want %q", got, want)
	}
	if err.Error() != "Remote API error" {
		t.Errorf("Error() = %q, want the generic message only", err.Error())
	}
}
