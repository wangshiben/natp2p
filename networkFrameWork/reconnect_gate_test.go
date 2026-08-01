package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type blockingReconnectGate struct {
	requests chan ReconnectGateRequest
}

func (gate *blockingReconnectGate) Wait(ctx context.Context, request ReconnectGateRequest) error {
	gate.requests <- request
	<-ctx.Done()
	return ctx.Err()
}

type reconnectGateTestRelayPolicy struct {
	target RelayDialTarget
	gate   ReconnectGate
}

func (policy *reconnectGateTestRelayPolicy) CurrentRelay() (RelayDialTarget, error) {
	return policy.target, nil
}

func (*reconnectGateTestRelayPolicy) ReportRelayDialResult(RelayDialTarget, error) {}

func (policy *reconnectGateTestRelayPolicy) ReconnectGate() ReconnectGate {
	return policy.gate
}

func TestHTTPReconnectGateWaitSendsReconnectMetadata(t *testing.T) {
	requestSeen := make(chan ReconnectGateRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		var value ReconnectGateRequest
		if err := json.NewDecoder(request.Body).Decode(&value); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		if request.Header.Get("Authorization") != "Bearer gate-token" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		requestSeen <- value
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"granted":true,"delaySeconds":0,"retryAfterSeconds":0}`))
	}))
	defer server.Close()

	gate := NewHTTPReconnectGate(server.URL, "gate-token")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := gate.Wait(ctx, ReconnectGateRequest{
		RelayAddress: "relay.test:9000",
		Transport:    "kcp",
		NodeID:       "node",
		ConnectionID: "connection",
		Attempt:      2,
		Role:         "natclient",
	})
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	select {
	case value := <-requestSeen:
		if value.RelayAddress != "relay.test:9000" || value.Transport != "kcp" ||
			value.NodeID != "node" || value.ConnectionID != "connection" ||
			value.Attempt != 2 || value.Role != "natclient" {
			t.Fatalf("request metadata = %+v", value)
		}
	case <-time.After(time.Second):
		t.Fatal("reconnect gate request was not observed")
	}
}

func TestNatClientInitialDialSkipsGateAndRecoveryWaits(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "1")
	relayAddr, cover, _, _, stopRelay := startTCPRelayDroppingAccept(t, -1)
	defer stopRelay()
	serverIdentity, err := newRelayTestIdentity("reconnect-gate-server")
	if err != nil {
		t.Fatalf("create server identity: %v", err)
	}
	serverStream, err := registerRelayTCPOnly(serverIdentity, relayAddr)
	if err != nil {
		t.Fatalf("register server: %v", err)
	}
	defer serverStream.Close()
	if err := waitForRelayGroup(cover, serverIdentity.nodeID, 3*time.Second); err != nil {
		t.Fatalf("wait for server registration: %v", err)
	}

	clientIdentity, err := newRelayTestIdentity("reconnect-gate-client")
	if err != nil {
		t.Fatalf("create client identity: %v", err)
	}
	gate := &blockingReconnectGate{requests: make(chan ReconnectGateRequest, 2)}
	policy := &reconnectGateTestRelayPolicy{
		target: RelayDialTarget{Address: relayAddr, Generation: 1},
		gate:   gate,
	}
	connectionID := "reconnect-gate-client-connection"
	firstMessage := &network.Message{
		Header: &network.Header{
			NodeId:        serverIdentity.nodeID,
			NodeIdVersion: 1,
			ConnectionId:  connectionID,
		},
		Payload: []byte(clientIdentity.publicKey),
	}
	stream, err := clientStreamWithRelayPolicy(
		firstMessage,
		relayAddr,
		serverIdentity.nodeID,
		connectionID,
		true,
		policy,
	)
	if err != nil {
		t.Fatalf("initial client dial: %v", err)
	}
	defer stream.Close()
	select {
	case request := <-gate.requests:
		t.Fatalf("initial client dial unexpectedly entered reconnect gate: %+v", request)
	default:
	}

	dual, ok := stream.(*DualStream)
	if !ok {
		t.Fatalf("client stream type=%T, want *DualStream", stream)
	}
	dual.reconnectMu.Lock()
	reconnectDialer := dual.reconnectDialers[streamTransportTCP]
	dual.reconnectMu.Unlock()
	if reconnectDialer == nil {
		t.Fatal("TCP reconnect dialer was not installed")
	}
	reconnectCtx, cancelReconnect := context.WithCancel(context.Background())
	reconnectResult := make(chan error, 1)
	go func() {
		reconnected, reconnectErr := reconnectDialer(withReconnectAttempt(reconnectCtx, 3))
		if reconnected != nil {
			_ = reconnected.Close()
		}
		reconnectResult <- reconnectErr
	}()
	select {
	case request := <-gate.requests:
		if request.RelayAddress != relayAddr || request.Transport != "tcp" ||
			request.NodeID != serverIdentity.nodeID || request.ConnectionID != connectionID ||
			request.Attempt != 3 || request.Role != "natclient" {
			t.Fatalf("recovery gate request = %+v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("client recovery did not enter reconnect gate")
	}
	cancelReconnect()
	select {
	case reconnectErr := <-reconnectResult:
		if reconnectErr == nil {
			t.Fatal("canceled reconnect gate unexpectedly permitted a dial")
		}
	case <-time.After(time.Second):
		t.Fatal("client recovery did not stop after gate cancellation")
	}
}

func TestHTTPReconnectGateFallbackRespectsContext(t *testing.T) {
	gate := NewHTTPReconnectGate("http://127.0.0.1:1", "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	startedAt := time.Now()
	err := gate.Wait(ctx, ReconnectGateRequest{RelayAddress: "relay.test:9000", Transport: "tcp"})
	if err == nil {
		t.Fatal("Wait unexpectedly succeeded while gate was unavailable")
	}
	if time.Since(startedAt) > time.Second {
		t.Fatalf("fallback did not respect context: elapsed=%s", time.Since(startedAt))
	}
}

func TestNewReconnectGateFromEnvironment(t *testing.T) {
	t.Setenv("BNFS_RECONNECT_GATE_URL", "http://127.0.0.1:18912")
	t.Setenv("BNFS_RECONNECT_GATE_TOKEN", "gate-token")
	if NewReconnectGateFromEnvironment() == nil {
		t.Fatal("environment gate was not created")
	}
	t.Setenv("BNFS_RECONNECT_GATE_URL", "")
	if NewReconnectGateFromEnvironment() != nil {
		t.Fatal("empty environment URL created a gate")
	}
}
