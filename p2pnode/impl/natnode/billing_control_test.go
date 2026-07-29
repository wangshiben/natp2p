package natnode

import (
	"testing"
	"time"
)

func TestBillingControlBackoffRequiresStableConnectionBeforeReset(t *testing.T) {
	now := time.Now()
	connectedAt := now.Add(-billingControlStableDuration / 2)
	backoff := nextBillingControlBackoff(time.Second, connectedAt, now)
	if backoff != 2*time.Second {
		t.Fatalf("short-lived control backoff = %s, want 2s", backoff)
	}

	connectedAt = now.Add(-billingControlStableDuration)
	backoff = nextBillingControlBackoff(billingControlMaximumBackoff, connectedAt, now)
	if backoff != billingControlInitialBackoff {
		t.Fatalf("stable control backoff = %s, want %s", backoff, billingControlInitialBackoff)
	}
}

func TestBillingControlBackoffIsCapped(t *testing.T) {
	backoff := billingControlInitialBackoff
	for attempt := 0; attempt < 10; attempt++ {
		backoff = nextBillingControlBackoff(backoff, time.Time{}, time.Now())
	}
	if backoff != billingControlMaximumBackoff {
		t.Fatalf("billing control backoff = %s, want cap %s", backoff, billingControlMaximumBackoff)
	}
}
