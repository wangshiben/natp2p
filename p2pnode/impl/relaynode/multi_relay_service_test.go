package relaynode

import (
	"context"
	"net"
	"testing"
	"time"

	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
)

func reserveMultiRelayTestAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve Relay address: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release Relay address: %v", err)
	}
	return addr
}

func waitForHostRouteCount(t *testing.T, relay *RelayNode, target string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		relay.mu.RLock()
		count := 0
		for _, record := range relay.hostRoutes[target] {
			if record.wire.Active && time.Now().Before(time.Unix(0, record.wire.LeaseUntil)) {
				count++
			}
		}
		relay.mu.RUnlock()
		if count == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	relay.mu.RLock()
	got := len(relay.hostRoutes[target])
	relay.mu.RUnlock()
	t.Fatalf("host route count for %.16s=%d, want %d", target, got, want)
}

func dialMultiRelayService(t *testing.T, ctx context.Context, client *natnode.NATNode, target p2pnode.NodeID) p2pnode.Connection {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		connection, err := client.DialService(ctx, target)
		if err == nil {
			return connection
		}
		lastErr = err
		select {
		case <-ctx.Done():
			t.Fatalf("dial multi-Relay service: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("dial multi-Relay service: %v", lastErr)
	return nil
}

func multiRelayRoundTrip(t *testing.T, ctx context.Context, listener *natnode.ServiceListener, client *natnode.NATNode, target p2pnode.NodeID, payload string) {
	t.Helper()
	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept(ctx)
		if err != nil {
			serverResult <- err
			return
		}
		defer connection.Close()
		message, err := connection.Receive(ctx)
		if err != nil {
			serverResult <- err
			return
		}
		serverResult <- connection.Send(ctx, &p2pnode.Message{
			Type: p2pnode.MsgAppData, Payload: append([]byte("echo:"), message.Payload...),
		})
	}()

	connection := dialMultiRelayService(t, ctx, client, target)
	defer connection.Close()
	if err := connection.Send(ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: []byte(payload)}); err != nil {
		t.Fatalf("send %q: %v", payload, err)
	}
	response, err := connection.Receive(ctx)
	if err != nil {
		t.Fatalf("receive %q: %v", payload, err)
	}
	if got, want := string(response.Payload), "echo:"+payload; got != want {
		t.Fatalf("response=%q, want %q", got, want)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server round trip %q: %v", payload, err)
	}
}

func TestMultiRelayServiceRoutesThroughIndexAndSurvivesOneHostRelay(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "1")
	indexAddr := reserveMultiRelayTestAddr(t)
	relayOneAddr := reserveMultiRelayTestAddr(t)
	relayTwoAddr := reserveMultiRelayTestAddr(t)
	ingressAddr := reserveMultiRelayTestAddr(t)

	index := startRelay(t, indexAddr, indexAddr)
	defer index.Close()
	relayOne := startRelay(t, relayOneAddr, relayOneAddr)
	defer relayOne.Close()
	relayTwo := startRelay(t, relayTwoAddr, relayTwoAddr)
	defer relayTwo.Close()
	ingress := startRelay(t, ingressAddr, ingressAddr)
	defer ingress.Close()

	relayOne.ConnectPeer(indexAddr)
	relayTwo.ConnectPeer(indexAddr)
	ingress.ConnectPeer(indexAddr)

	server, err := natnode.NewNATNode(nil, relayOneAddr)
	if err != nil {
		t.Fatalf("create service server: %v", err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	listener, err := server.ListenServiceRelays(ctx, []string{relayOneAddr, relayTwoAddr}, natnode.ServiceOptions{
		MaxSessions: 4, AcceptQueue: 4,
	})
	if err != nil {
		t.Fatalf("listen on two Relays: %v", err)
	}
	defer listener.Close()

	waitForHostRouteCount(t, index, string(server.ID()), 2)
	waitForHostRouteCount(t, ingress, string(server.ID()), 2)

	client, err := natnode.NewNATNode(nil, ingressAddr)
	if err != nil {
		t.Fatalf("create ingress client: %v", err)
	}
	defer client.Close()
	multiRelayRoundTrip(t, ctx, listener, client, server.ID(), "before-relay-failure")

	if err := relayOne.Close(); err != nil {
		t.Fatalf("close first host Relay: %v", err)
	}
	waitForHostRouteCount(t, index, string(server.ID()), 1)
	waitForHostRouteCount(t, ingress, string(server.ID()), 1)
	multiRelayRoundTrip(t, ctx, listener, client, server.ID(), "after-relay-failure")

	snapshot := listener.Snapshot()
	if len(snapshot.Carriers) != 2 {
		t.Fatalf("carrier count=%d, want 2: %+v", len(snapshot.Carriers), snapshot.Carriers)
	}
	connected := 0
	for _, carrier := range snapshot.Carriers {
		if carrier.Connected {
			connected++
		}
	}
	if connected == 0 {
		t.Fatalf("no service carrier survived: %+v", snapshot.Carriers)
	}
}
