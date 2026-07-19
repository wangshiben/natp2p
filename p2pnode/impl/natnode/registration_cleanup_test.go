package natnode

import (
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/p2pnode"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type registrationRead struct {
	message *network.Message
	err     error
}

type registrationCarrier struct {
	conn net.Conn

	reads  chan registrationRead
	closed chan struct{}

	closeOnce  sync.Once
	closeCount atomic.Int32

	identityMu   sync.RWMutex
	nodeID       string
	connectionID string
}

func newRegistrationCarrier(t *testing.T) *registrationCarrier {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	return &registrationCarrier{
		conn:   conn,
		reads:  make(chan registrationRead, 2),
		closed: make(chan struct{}),
	}
}

func (s *registrationCarrier) Close() error {
	s.closeOnce.Do(func() {
		s.closeCount.Add(1)
		close(s.closed)
		_ = s.conn.Close()
	})
	return nil
}

func (s *registrationCarrier) NextMessage(ctx context.Context) (*network.Message, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, errors.New("registration carrier closed")
	case result := <-s.reads:
		return result.message, result.err
	}
}

func (s *registrationCarrier) SendMessage(context.Context, *network.Message) error {
	select {
	case <-s.closed:
		return errors.New("registration carrier closed")
	default:
		return nil
	}
}

func (s *registrationCarrier) SendMessageAsync(ctx context.Context, message *network.Message, callback network.MessageResultCallback) error {
	err := s.SendMessage(ctx, message)
	if callback != nil {
		callback(network.MessageResult{Success: err == nil, Error: err})
	}
	return err
}

func (s *registrationCarrier) NodeId() string {
	s.identityMu.RLock()
	defer s.identityMu.RUnlock()
	return s.nodeID
}

func (s *registrationCarrier) ConnectionId() string {
	s.identityMu.RLock()
	defer s.identityMu.RUnlock()
	return s.connectionID
}

func (s *registrationCarrier) SetCryptoSuite(network.EncrypSuite) {}

func (s *registrationCarrier) SetIdentity(nodeID, connectionID string) {
	s.identityMu.Lock()
	s.nodeID = nodeID
	s.connectionID = connectionID
	s.identityMu.Unlock()
}

func (s *registrationCarrier) Connection() net.Conn { return s.conn }

func (s *registrationCarrier) queue(message *network.Message, err error) {
	s.reads <- registrationRead{message: message, err: err}
}

type successfulIncomingHandshake struct {
	peer p2pnode.PeerInfo
}

func (h successfulIncomingHandshake) HandshakeIncoming(context.Context, network.Stream, *network.Message) (p2pnode.PeerInfo, error) {
	return h.peer, nil
}

func (successfulIncomingHandshake) HandshakeOutgoing(context.Context, network.Stream, p2pnode.NodeID) (p2pnode.PeerInfo, error) {
	return p2pnode.PeerInfo{}, errors.New("unexpected outgoing handshake")
}

func newRegistrationDual(t *testing.T) (*networkFrameWork.DualStream, *registrationCarrier) {
	t.Helper()
	carrier := newRegistrationCarrier(t)
	return networkFrameWork.EnsureDualStream(carrier), carrier
}

func malformedRegistrationHello() *network.Message {
	return &network.Message{
		Header:  &network.Header{ConnectionId: "bad-registration"},
		Payload: []byte("not-a-p256-public-key"),
	}
}

func TestHandleInboundHelloFailureClosesAndRemovesMovedRegistration(t *testing.T) {
	node, err := NewNATNode(nil, "relay-old:9000")
	if err != nil {
		t.Fatalf("NewNATNode: %v", err)
	}
	defer node.Close()

	dual, carrier := newRegistrationDual(t)
	entry := &relayEntry{addr: "relay-old:9000", stream: dual}
	node.registeredRelays[entry.addr] = entry

	errorResult := make(chan error, 1)
	go func() {
		errorResult <- node.handleInboundHello("relay-old:9000", entry)
	}()

	node.relayActivated("relay-new:9000")
	carrier.queue(malformedRegistrationHello(), nil)

	select {
	case err := <-errorResult:
		if err == nil {
			t.Fatal("malformed first frame unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("handleInboundHello did not return after malformed first frame")
	}

	node.mu.RLock()
	remaining := len(node.registeredRelays)
	node.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("failed registration remained after relay key migration: %d entries", remaining)
	}
	if carrier.closeCount.Load() != 1 {
		t.Fatalf("failed registration DualStream did not close its carrier exactly once: %d", carrier.closeCount.Load())
	}
}

func TestHandleInboundHelloStaleFailurePreservesNewRegistration(t *testing.T) {
	node, err := NewNATNode(nil, "relay-a:9000")
	if err != nil {
		t.Fatalf("NewNATNode: %v", err)
	}
	defer node.Close()

	oldDual, oldCarrier := newRegistrationDual(t)
	oldEntry := &relayEntry{addr: "relay-a:9000", stream: oldDual}
	node.registeredRelays[oldEntry.addr] = oldEntry

	errorResult := make(chan error, 1)
	go func() {
		errorResult <- node.handleInboundHello("relay-a:9000", oldEntry)
	}()

	newDual, newCarrier := newRegistrationDual(t)
	newEntry := &relayEntry{addr: "relay-a:9000", stream: newDual}
	node.mu.Lock()
	node.registeredRelays[newEntry.addr] = newEntry
	node.mu.Unlock()
	oldCarrier.queue(malformedRegistrationHello(), nil)

	select {
	case err := <-errorResult:
		if err == nil {
			t.Fatal("malformed stale registration unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("stale handleInboundHello did not return")
	}

	node.mu.RLock()
	current := node.registeredRelays[newEntry.addr]
	node.mu.RUnlock()
	if current != newEntry {
		t.Fatal("stale registration failure removed the newer relay entry")
	}
	if oldCarrier.closeCount.Load() != 1 {
		t.Fatalf("stale failed registration was not closed: %d", oldCarrier.closeCount.Load())
	}
	if newCarrier.closeCount.Load() != 0 {
		t.Fatalf("stale failure closed the newer registration: %d", newCarrier.closeCount.Load())
	}
}

func TestHandleInboundHelloSuccessRetainsConsumedRegistration(t *testing.T) {
	node, err := NewNATNode(nil, "relay-a:9000")
	if err != nil {
		t.Fatalf("NewNATNode: %v", err)
	}
	defer node.Close()

	peer, err := NewNATNode(nil, "relay-peer:9000")
	if err != nil {
		t.Fatalf("NewNATNode peer: %v", err)
	}
	defer peer.Close()
	node.handshake = successfulIncomingHandshake{peer: p2pnode.PeerInfo{ID: peer.ID()}}

	dual, carrier := newRegistrationDual(t)
	entry := &relayEntry{addr: "relay-a:9000", stream: dual}
	node.registeredRelays[entry.addr] = entry
	carrier.queue(&network.Message{
		Header:  &network.Header{ConnectionId: "successful-registration"},
		Payload: []byte(peer.PubKeyHex()),
	}, nil)
	carrier.queue(newHandshakeMessage(string(peer.ID()), "successful-registration", []string{"relay-peer:9000"}), nil)

	if err := node.handleInboundHello(entry.addr, entry); err != nil {
		t.Fatalf("handleInboundHello: %v", err)
	}

	node.mu.RLock()
	current := node.registeredRelays[entry.addr]
	node.mu.RUnlock()
	if current != entry {
		t.Fatal("successful consumed registration was removed")
	}
	if carrier.closeCount.Load() != 0 {
		t.Fatalf("successful consumed registration was closed: %d", carrier.closeCount.Load())
	}
}
