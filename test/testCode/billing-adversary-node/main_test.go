package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"bnfs_p2p/admission"
	"bnfs_p2p/billingvoucher"
)

func TestRelayFeeOverrideIgnoresConcurrentLegitimateBaseline(t *testing.T) {
	const concurrentBaselineBytes = int64(768 << 10)
	var balance atomic.Int64
	balance.Store(defaultCreditBytes)
	signEntered := make(chan struct{})
	releaseSign := make(chan struct{})
	node, payer, candidate := newRelayFeeOverrideTestNode(t, &balance, func(writer http.ResponseWriter, request *http.Request) {
		close(signEntered)
		<-releaseSign
		writeJSON(writer, http.StatusConflict, signResponse{ErrorCode: "nat_meter_mismatch"})
	})

	attackDone := make(chan statusEvent, 1)
	go func() {
		releaseFixture := node.lockRelayFixture()
		event := node.expectNatRefusal(context.Background(), "relay_fee_override", "relay-4", candidate, payer, "nat_rejected_policy_override")
		releaseFixture()
		attackDone <- event
	}()
	select {
	case <-signEntered:
	case <-time.After(time.Second):
		t.Fatal("fee override request did not reach the malicious NAT fixture")
	}

	baselineEntered := make(chan struct{})
	baselineDone := make(chan struct{})
	baselineHandler := node.serializeRelayFixture(func(http.ResponseWriter, *http.Request) {
		balance.Add(-concurrentBaselineBytes)
		close(baselineEntered)
	})
	go func() {
		defer close(baselineDone)
		baselineHandler(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/relay/baseline", nil))
	}()
	select {
	case <-baselineEntered:
		t.Fatal("legitimate baseline interleaved with the rejected fee override")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseSign)
	var event statusEvent
	select {
	case event = <-attackDone:
	case <-time.After(time.Second):
		t.Fatal("fee override probe did not finish")
	}
	select {
	case <-baselineDone:
	case <-time.After(time.Second):
		t.Fatal("legitimate baseline did not resume after the fee override probe")
	}
	if !event.Passed || event.BalanceDelta != 0 || event.StateChanged {
		t.Fatalf("concurrent legitimate baseline caused a false violation: %+v", event)
	}
	if got := balance.Load(); got != defaultCreditBytes-concurrentBaselineBytes {
		t.Fatalf("legitimate baseline balance=%d, want %d", got, defaultCreditBytes-concurrentBaselineBytes)
	}
}

func TestActorRemainsStartingUntilRoleCoverageIsComplete(t *testing.T) {
	node := &attackerNode{snapshot: statusSnapshot{
		Status: "STARTING",
		Coverage: map[string]coverageCounter{
			"first":  {},
			"second": {},
		},
	}}

	node.record(statusEvent{Scenario: "first", Passed: true})
	if node.snapshot.Status != "STARTING" {
		t.Fatalf("partial coverage status=%q, want STARTING", node.snapshot.Status)
	}
	node.record(statusEvent{Scenario: "second", Passed: true})
	if node.snapshot.Status != "RUNNING" {
		t.Fatalf("complete coverage status=%q, want RUNNING", node.snapshot.Status)
	}
}

func TestBalanceUsesMeasuredIdentityAuthorization(t *testing.T) {
	const payerNodeID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const payerAuthorizationID = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != admission.PathBalance {
			http.NotFound(writer, request)
			return
		}
		if request.URL.Query().Get("node") != payerNodeID ||
			request.URL.Query().Get("authorization_id") != payerAuthorizationID {
			writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "identity_mismatch"})
			return
		}
		writeJSON(writer, http.StatusOK, map[string]int64{
			"balance": 12345, "authorization_consumed_bytes": 678, "authorization_earned_bytes": 90,
		})
	}))
	defer server.Close()

	node := &attackerNode{
		config: configuration{caURL: server.URL},
		identity: identityWire{Cert: admission.SignedCert{Cert: admission.Cert{
			AuthorizationID: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		}}},
		http: &http.Client{Timeout: time.Second},
	}
	payer := identityWire{NodeID: payerNodeID, Cert: admission.SignedCert{Cert: admission.Cert{
		AuthorizationID: payerAuthorizationID,
	}}}
	balance, status, err := node.balance(context.Background(), payer)
	if err != nil || status != http.StatusOK || balance.Balance != 12345 ||
		balance.AuthorizationConsumedBytes != 678 || balance.AuthorizationEarnedBytes != 90 || !balance.AuthorizationScoped {
		t.Fatalf("balance=%+v status=%d err=%v", balance, status, err)
	}
}

func TestAuthorizationBalanceIgnoresConcurrentAccountMutation(t *testing.T) {
	before := balanceSnapshot{
		Balance: 1000, AuthorizationConsumedBytes: 200, AuthorizationEarnedBytes: 40, AuthorizationScoped: true,
	}
	after := before
	after.Balance = 500
	delta, changed := balanceDifference(before, after)
	if delta != 0 || changed {
		t.Fatalf("unrelated account mutation delta=%d changed=%v", delta, changed)
	}

	after.AuthorizationConsumedBytes += 64 << 10
	delta, changed = balanceDifference(before, after)
	if delta != 64<<10 || !changed {
		t.Fatalf("authorization mutation delta=%d changed=%v", delta, changed)
	}
}

func TestRelayFeeOverrideStillDetectsCausalBalanceMutation(t *testing.T) {
	const maliciousDelta = int64(64 << 10)
	var balance atomic.Int64
	balance.Store(defaultCreditBytes)
	node, payer, candidate := newRelayFeeOverrideTestNode(t, &balance, func(writer http.ResponseWriter, request *http.Request) {
		balance.Add(-maliciousDelta)
		writeJSON(writer, http.StatusConflict, signResponse{ErrorCode: "nat_meter_mismatch"})
	})

	releaseFixture := node.lockRelayFixture()
	event := node.expectNatRefusal(context.Background(), "relay_fee_override", "relay-4", candidate, payer, "nat_rejected_policy_override")
	releaseFixture()
	if event.Passed || event.FailureCode != "malicious_relay_claim_not_contained" ||
		event.BalanceDelta != maliciousDelta || !event.StateChanged {
		t.Fatalf("causal mutation was not reported: %+v", event)
	}
}

func TestNatAttackBaselineRetriesOnlyTransientSetupFailures(t *testing.T) {
	tests := []struct {
		name            string
		responses       []baselineResponse
		peerStatuses    []int
		wantRequests    int
		wantError       bool
		wantUnavailable bool
	}{
		{
			name:         "bad gateway then fresh settlement",
			responses:    []baselineResponse{{}, {HTTPStatus: http.StatusOK, Delta: 512 << 10}},
			peerStatuses: []int{http.StatusBadGateway, http.StatusOK},
			wantRequests: 2,
		},
		{
			name:         "unknown first result then idempotent replay",
			responses:    []baselineResponse{{}, {HTTPStatus: http.StatusOK, Delta: 0, Replayed: true}},
			peerStatuses: []int{http.StatusGatewayTimeout, http.StatusOK},
			wantRequests: 2,
		},
		{
			name:         "payer rejection is not retried",
			responses:    []baselineResponse{{HTTPStatus: http.StatusPaymentRequired}},
			peerStatuses: []int{http.StatusOK},
			wantRequests: 1,
			wantError:    true,
		},
		{
			name:            "bounded transient failures remain fail closed",
			responses:       []baselineResponse{{}, {}, {}},
			peerStatuses:    []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout},
			wantRequests:    3,
			wantError:       true,
			wantUnavailable: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				index := int(calls.Add(1)) - 1
				writeJSON(writer, test.peerStatuses[index], test.responses[index])
			}))
			defer server.Close()
			node := &attackerNode{
				config: configuration{peerURL: server.URL},
				http:   &http.Client{Timeout: time.Second},
			}
			_, statuses, requests, err := node.establishNatAttackBaseline(
				context.Background(), payerProposal{}, 512<<10,
			)
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v, wantError=%v", err, test.wantError)
			}
			if errors.Is(err, errNatAttackBaselineUnavailable) != test.wantUnavailable {
				t.Fatalf("unavailable=%v, want=%v", errors.Is(err, errNatAttackBaselineUnavailable), test.wantUnavailable)
			}
			if requests != test.wantRequests || int(calls.Load()) != test.wantRequests {
				t.Fatalf("requests=%d calls=%d want=%d", requests, calls.Load(), test.wantRequests)
			}
			if len(statuses) < test.wantRequests {
				t.Fatalf("statuses=%v do not account for %d requests", statuses, test.wantRequests)
			}
		})
	}
}

func TestRelayReplayBaselineRetriesOnlyTransientSetupFailures(t *testing.T) {
	tests := []struct {
		name            string
		responses       []admission.VoucherSettleResponse
		statuses        []int
		wantRequests    int
		wantError       bool
		wantUnavailable bool
	}{
		{
			name:         "bad gateway then fresh settlement",
			responses:    []admission.VoucherSettleResponse{{}, {Delta: 1 << 20}},
			statuses:     []int{http.StatusBadGateway, http.StatusOK},
			wantRequests: 2,
		},
		{
			name:         "unknown first result then idempotent replay",
			responses:    []admission.VoucherSettleResponse{{}, {Delta: 0, Replayed: true}},
			statuses:     []int{http.StatusGatewayTimeout, http.StatusOK},
			wantRequests: 2,
		},
		{
			name:         "payer rejection is not retried",
			responses:    []admission.VoucherSettleResponse{{}},
			statuses:     []int{http.StatusPaymentRequired},
			wantRequests: 1,
			wantError:    true,
		},
		{
			name:            "bounded transient failures remain fail closed",
			responses:       []admission.VoucherSettleResponse{{}, {}, {}},
			statuses:        []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout},
			wantRequests:    3,
			wantError:       true,
			wantUnavailable: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				index := int(calls.Add(1)) - 1
				writeJSON(writer, test.statuses[index], test.responses[index])
			}))
			defer server.Close()
			node := &attackerNode{
				config: configuration{caURL: server.URL},
				http:   &http.Client{Timeout: time.Second},
			}
			_, statuses, requests, err := node.establishRelayReplayBaseline(
				context.Background(), admission.VoucherSettleRequest{}, 1<<20,
			)
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v, wantError=%v", err, test.wantError)
			}
			if errors.Is(err, errRelayReplayBaselineUnavailable) != test.wantUnavailable {
				t.Fatalf("unavailable=%v, want=%v", errors.Is(err, errRelayReplayBaselineUnavailable), test.wantUnavailable)
			}
			if requests != test.wantRequests || int(calls.Load()) != test.wantRequests {
				t.Fatalf("requests=%d calls=%d want=%d", requests, calls.Load(), test.wantRequests)
			}
			if len(statuses) != test.wantRequests {
				t.Fatalf("statuses=%v do not account for %d requests", statuses, test.wantRequests)
			}
		})
	}
}

func TestValidateAttackSchedule(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		offset   time.Duration
		wantErr  bool
	}{
		{name: "no offset", interval: time.Minute},
		{name: "staggered actors", interval: time.Minute, offset: 30 * time.Second},
		{name: "interval too short", interval: 500 * time.Millisecond, wantErr: true},
		{name: "negative offset", interval: time.Minute, offset: -time.Second, wantErr: true},
		{name: "offset reaches interval", interval: time.Minute, offset: time.Minute, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateAttackSchedule(test.interval, test.offset); (err != nil) != test.wantErr {
				t.Fatalf("validateAttackSchedule() error=%v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func newRelayFeeOverrideTestNode(t *testing.T, balance *atomic.Int64, natHandler http.HandlerFunc) (*attackerNode, identityWire, billingvoucher.VoucherBody) {
	t.Helper()
	caServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != admission.PathBalance {
			http.NotFound(writer, request)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]int64{"balance": balance.Load()})
	}))
	t.Cleanup(caServer.Close)
	natServer := httptest.NewServer(natHandler)
	t.Cleanup(natServer.Close)

	relayPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relayID, err := billingvoucher.NodeIDFromPublicKey(relayPrivate.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	payerID := identifier("fee-override-payer")
	payer := identityWire{NodeID: payerID.String()}
	candidate := fixtureBody("relay-4", payerID, relayID, 1, 512<<10, billingvoucher.Identifier{}, "main")
	candidate.PolicyDigest[0] ^= 1
	node := &attackerNode{
		config: configuration{
			role:    "relay",
			caURL:   caServer.URL,
			peerURL: natServer.URL,
		},
		private: relayPrivate,
		http:    &http.Client{Timeout: time.Second},
	}
	return node, payer, candidate
}
