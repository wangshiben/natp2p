package main

import (
	"bytes"
	"net/http/httptest"
	"testing"
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
