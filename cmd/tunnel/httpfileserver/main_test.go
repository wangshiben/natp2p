package main

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRequestedSizeMB(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		want      int
		wantError bool
	}{
		{name: "default", want: 100},
		{name: "minimum", query: "?size_mb=1", want: 1},
		{name: "maximum", query: "?size_mb=200", want: 200},
		{name: "zero", query: "?size_mb=0", wantError: true},
		{name: "too large", query: "?size_mb=201", wantError: true},
		{name: "not integer", query: "?size_mb=large", wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/file"+tc.query, nil)
			got, err := requestedSizeMB(req, 100, 200)
			if (err != nil) != tc.wantError {
				t.Fatalf("requestedSizeMB() error = %v, wantError = %v", err, tc.wantError)
			}
			if !tc.wantError && got != tc.want {
				t.Fatalf("requestedSizeMB() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestWritePayloadUnlimited(t *testing.T) {
	payload := bytes.Repeat([]byte("bnfs"), 4096)
	var output bytes.Buffer

	written, err := writePayload(&output, payload, 0)
	if err != nil {
		t.Fatalf("writePayload() error = %v", err)
	}
	if written != len(payload) {
		t.Fatalf("writePayload() written = %d, want %d", written, len(payload))
	}
	if !bytes.Equal(output.Bytes(), payload) {
		t.Fatal("writePayload() changed payload bytes")
	}
}

func TestResolveSendRateBytesSupportsHalfMiB(t *testing.T) {
	rate, err := resolveSendRateBytes(0, 512)
	if err != nil {
		t.Fatalf("resolveSendRateBytes() error = %v", err)
	}
	if rate != 512*1024 {
		t.Fatalf("resolveSendRateBytes() = %d, want %d", rate, 512*1024)
	}
	if _, err := resolveSendRateBytes(1, 512); err == nil {
		t.Fatal("mixed MiB/s and KiB/s rates were accepted")
	}
}

func TestVariantPayloadMatchesChecksumAndDiffers(t *testing.T) {
	payload := bytes.Repeat([]byte("bnfs-variant"), 8192)
	var first bytes.Buffer
	var second bytes.Buffer
	if _, err := writeVariantPayload(&first, payload, 0, "client-001"); err != nil {
		t.Fatalf("write first variant: %v", err)
	}
	if _, err := writeVariantPayload(&second, payload, 0, "client-002"); err != nil {
		t.Fatalf("write second variant: %v", err)
	}
	if bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("different variants generated identical content")
	}
	if got, want := checksumPayload(payload, "client-001"), checksumPayload(first.Bytes(), ""); got != want {
		t.Fatalf("variant checksum=%s, transformed checksum=%s", got, want)
	}
}

func TestAggregateRateLimiterIsSharedAcrossConcurrentResponses(t *testing.T) {
	const (
		responseCount = 4
		rateBytes     = 8 * bytesPerMiB
	)
	payload := make([]byte, 2*64*1024)
	limiter := newAggregateRateLimiter(rateBytes)
	start := make(chan struct{})
	errors := make(chan error, responseCount)
	var writers sync.WaitGroup
	for range responseCount {
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			_, err := writeVariantPayloadWithLimiter(
				context.Background(), io.Discard, payload, limiter, "",
			)
			errors <- err
		}()
	}
	startedAt := time.Now()
	close(start)
	writers.Wait()
	elapsed := time.Since(startedAt)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent limited write: %v", err)
		}
	}

	// 八个 64 KiB chunk 共享调度，首个 chunk 可立即发送，其余七个至少占用约 55 ms。
	if elapsed < 40*time.Millisecond {
		t.Fatalf("responses used independent rate limits: completed in %s", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("aggregate limiter stalled: completed in %s", elapsed)
	}
}

func TestRequestedVariantRejectsUnsafeValue(t *testing.T) {
	valid := httptest.NewRequest("GET", "/file?variant=client-001.bin", nil)
	if variant, err := requestedVariant(valid); err != nil || variant != "client-001.bin" {
		t.Fatalf("valid variant=(%q, %v)", variant, err)
	}
	invalid := httptest.NewRequest("GET", "/file?variant=../client%2F001", nil)
	if _, err := requestedVariant(invalid); err == nil {
		t.Fatal("unsafe variant was accepted")
	}
}
