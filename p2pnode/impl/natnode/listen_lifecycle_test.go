package natnode

import (
	"context"
	"errors"
	"testing"
	"time"

	"bnfs_p2p/admission"
	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/network"
	"bnfs_p2p/p2pnode"
)

type fixedRegistrationTransport struct {
	stream network.Stream
}

func (transport fixedRegistrationTransport) Register(context.Context, string, string) (network.Stream, error) {
	return transport.stream, nil
}

func (fixedRegistrationTransport) Dial(context.Context, string, p2pnode.NodeID) (network.Stream, string, error) {
	return nil, "", context.Canceled
}

func TestListenAcceptsSequentialConnectionsWithoutReplacingBillingMeter(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "1")
	_, relayAddr, closeRelay := startRelay(t)
	defer closeRelay()

	server, err := NewNATNode(nil, relayAddr)
	if err != nil {
		t.Fatalf("NewNATNode server: %v", err)
	}
	defer server.Close()

	billingMeter := server.billingMeter
	sessionID := billingvoucher.Identifier{1}
	billingSession := newNatBillingSession()
	billingSession.cumulative = 777
	billingMeter.mu.Lock()
	billingMeter.sessions[sessionID] = billingSession
	billingMeter.mu.Unlock()

	accepted := make(chan p2pnode.Connection, 2)
	releases := make(chan (<-chan struct{}), 2)
	server.OnConnection(func(connection p2pnode.Connection) {
		release := <-releases
		accepted <- connection
		<-release
		_ = connection.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var previousEntry *relayEntry
	for sessionNumber := 1; sessionNumber <= 2; sessionNumber++ {
		client, clientErr := NewNATNode(nil, relayAddr)
		if clientErr != nil {
			t.Fatalf("NewNATNode client %d: %v", sessionNumber, clientErr)
		}

		listenResult := make(chan error, 1)
		go func() {
			listenResult <- server.Listen(ctx, relayAddr)
		}()
		previousEntry = waitForReplacementRegistration(t, server, relayAddr, previousEntry)

		release := make(chan struct{})
		releases <- release
		outgoing, connectErr := client.Connect(ctx, server.ID())
		if connectErr != nil {
			_ = client.Close()
			t.Fatalf("client %d Connect: %v", sessionNumber, connectErr)
		}
		var incoming p2pnode.Connection
		select {
		case incoming = <-accepted:
		case <-ctx.Done():
			_ = outgoing.Close()
			_ = client.Close()
			t.Fatalf("server did not accept session %d: %v", sessionNumber, ctx.Err())
		}

		select {
		case listenErr := <-listenResult:
			t.Fatalf("Listen returned while session %d callback was active: %v", sessionNumber, listenErr)
		case <-time.After(50 * time.Millisecond):
		}
		payload := []byte{byte(sessionNumber)}
		if sendErr := outgoing.Send(ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: payload}); sendErr != nil {
			t.Fatalf("session %d Send: %v", sessionNumber, sendErr)
		}
		received, receiveErr := incoming.Receive(ctx)
		if receiveErr != nil || len(received.Payload) != 1 || received.Payload[0] != payload[0] {
			t.Fatalf("session %d Receive = (%v, %v)", sessionNumber, received, receiveErr)
		}

		close(release)
		select {
		case listenErr := <-listenResult:
			if listenErr != nil {
				t.Fatalf("session %d Listen: %v", sessionNumber, listenErr)
			}
		case <-ctx.Done():
			t.Fatalf("session %d Listen did not return: %v", sessionNumber, ctx.Err())
		}
		_ = outgoing.Close()
		_ = client.Close()
	}

	if server.billingMeter != billingMeter {
		t.Fatal("sequential Listen replaced the billing meter")
	}
	billingMeter.mu.Lock()
	preserved := billingMeter.sessions[sessionID]
	billingMeter.mu.Unlock()
	if preserved != billingSession || preserved.cumulative != 777 {
		t.Fatalf("billing tail state was not preserved: %+v", preserved)
	}
}

func waitForReplacementRegistration(
	t *testing.T,
	node *NATNode,
	relayAddr string,
	previous *relayEntry,
) *relayEntry {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		node.mu.RLock()
		current := node.registeredRelays[relayAddr]
		node.mu.RUnlock()
		if current != nil && current != previous {
			return current
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("replacement registration was not installed")
	return nil
}

func TestRegisterAndServeRemovesEntryWhenBillingReadinessFails(t *testing.T) {
	node, err := NewNATNode(nil, "relay-a:9000")
	if err != nil {
		t.Fatalf("NewNATNode: %v", err)
	}
	defer node.Close()

	stream, carrier := newRegistrationDual(t)
	node.transport = fixedRegistrationTransport{stream: stream}
	node.billingMeter.mu.Lock()
	node.billingMeter.cert = &admission.SignedCert{}
	node.billingMeter.mu.Unlock()
	node.cancel()

	if err := node.registerAndServe("relay-a:9000"); err == nil {
		t.Fatal("billing readiness failure unexpectedly passed")
	}
	node.mu.RLock()
	remaining := len(node.registeredRelays)
	node.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("failed registration left %d relay entries", remaining)
	}
	if carrier.closeCount.Load() != 1 {
		t.Fatalf("failed registration stream close count = %d, want 1", carrier.closeCount.Load())
	}
}

func TestRegisterAndServeRejectsStreamAfterNodeClosed(t *testing.T) {
	node, err := NewNATNode(nil, "relay-a:9000")
	if err != nil {
		t.Fatalf("NewNATNode: %v", err)
	}

	stream, carrier := newRegistrationDual(t)
	node.transport = fixedRegistrationTransport{stream: stream}
	if err := node.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := node.registerAndServe("relay-a:9000"); !errors.Is(err, context.Canceled) {
		t.Fatalf("registerAndServe after Close error = %v, want context.Canceled", err)
	}
	if carrier.closeCount.Load() != 1 {
		t.Fatalf("late registration stream close count = %d, want 1", carrier.closeCount.Load())
	}
}
