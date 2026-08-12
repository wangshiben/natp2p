package admission

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSettleVoucherClassifiesServerFailureAsRetryable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != PathVoucherSettle {
			t.Fatalf("path = %s, want %s", request.URL.Path, PathVoucherSettle)
		}
		writer.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"error": map[string]string{"code": "server_busy", "message": "busy"},
		})
	}))
	defer server.Close()

	response, err := NewCAClient(server.URL).SettleVoucher(context.Background(), VoucherSettleRequest{})
	if err == nil {
		t.Fatal("temporary CA failure was accepted")
	}
	if response == nil || !response.Retryable || response.ErrorCode != VoucherErrorTemporarilyUnavailable {
		t.Fatalf("temporary response = %+v", response)
	}
	if response.Error == "" || response.Frozen {
		t.Fatalf("temporary response lost safe retry semantics: %+v", response)
	}
}

func TestSettleVoucherKeepsClientRejectionTerminal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(writer).Encode(VoucherSettleResponse{Error: "terminal policy rejection", Frozen: true})
	}))
	defer server.Close()

	response, err := NewCAClient(server.URL).SettleVoucher(context.Background(), VoucherSettleRequest{})
	if err == nil {
		t.Fatal("terminal CA rejection was accepted")
	}
	if response == nil || response.Retryable || !response.Frozen {
		t.Fatalf("terminal response = %+v", response)
	}
}

func TestSettleVoucherTreatsRateLimitAsRetryable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Retry-After", "3")
		writer.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(writer).Encode(VoucherSettleResponse{Error: "slow down"})
	}))
	defer server.Close()

	response, err := NewCAClient(server.URL).SettleVoucher(context.Background(), VoucherSettleRequest{})
	if err == nil {
		t.Fatal("rate-limited voucher was accepted")
	}
	if response == nil || !response.Retryable || response.ErrorCode != VoucherErrorRateLimited || response.Frozen {
		t.Fatalf("rate-limited response = %+v", response)
	}
}
