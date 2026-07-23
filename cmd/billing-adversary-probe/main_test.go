package main

import "testing"

func TestDecodeRequestIsStrict(t *testing.T) {
	request, err := decodeRequest([]byte(`{"scenario":"relay_request_replay","nonce":"test-1"}`))
	if err != nil || request.Scenario != "relay_request_replay" || request.Nonce != "test-1" {
		t.Fatalf("request=%+v err=%v", request, err)
	}
	for _, encoded := range [][]byte{
		[]byte(`{"scenario":"relay_request_replay","nonce":"test-1","extra":true}`),
		[]byte(`{"scenario":"relay_request_replay","nonce":"test-1"} {}`),
		[]byte(`not-json`),
	} {
		if _, err := decodeRequest(encoded); err == nil {
			t.Fatalf("accepted malformed request %q", encoded)
		}
	}
}
