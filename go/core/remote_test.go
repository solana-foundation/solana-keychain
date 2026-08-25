package core

import (
	"context"
	"errors"
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
