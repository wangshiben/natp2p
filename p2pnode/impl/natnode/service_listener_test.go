package natnode

import (
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/p2pnode"

	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type serviceSnapshotTestConnection struct {
	peer       p2pnode.PeerInfo
	sendErr    error
	closed     atomic.Bool
	closeCalls atomic.Int32
}

type carrierReconnectTestTransport struct {
	gateRequests  chan networkFrameWork.ReconnectGateRequest
	gateRelease   chan struct{}
	registerCalls atomic.Int32
	registerSeen  chan struct{}
}

func newCarrierReconnectTestTransport() *carrierReconnectTestTransport {
	return &carrierReconnectTestTransport{
		gateRequests: make(chan networkFrameWork.ReconnectGateRequest, 4),
		gateRelease:  make(chan struct{}),
		registerSeen: make(chan struct{}, 4),
	}
}

func (transport *carrierReconnectTestTransport) Register(
	context.Context,
	string,
	string,
) (network.Stream, error) {
	transport.registerCalls.Add(1)
	transport.registerSeen <- struct{}{}
	return nil, errors.New("test registration failure")
}

func (*carrierReconnectTestTransport) Dial(
	context.Context,
	string,
	p2pnode.NodeID,
) (network.Stream, string, error) {
	return nil, "", context.Canceled
}

func (transport *carrierReconnectTestTransport) WaitForReconnect(
	ctx context.Context,
	request networkFrameWork.ReconnectGateRequest,
) error {
	transport.gateRequests <- request
	select {
	case <-transport.gateRelease:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (connection *serviceSnapshotTestConnection) Peer() p2pnode.PeerInfo { return connection.peer }
func (connection *serviceSnapshotTestConnection) Send(context.Context, *p2pnode.Message) error {
	return connection.sendErr
}
func (connection *serviceSnapshotTestConnection) Receive(context.Context) (*p2pnode.Message, error) {
	return nil, context.Canceled
}
func (connection *serviceSnapshotTestConnection) Raw() network.Stream { return nil }
func (connection *serviceSnapshotTestConnection) Close() error {
	connection.closed.Store(true)
	connection.closeCalls.Add(1)
	return nil
}

func TestServiceConnectionOnlyClosesOnFatalSendError(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		sendErr   error
		wantClose bool
	}{
		{
			name:    "recoverable reconciliation wait",
			sendErr: markRecoverableServiceSendError(context.DeadlineExceeded),
		},
		{
			name:      "fatal transport failure",
			sendErr:   errors.New("transport stream closed"),
			wantClose: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			underlying := &serviceSnapshotTestConnection{
				peer:    p2pnode.PeerInfo{ID: "peer"},
				sendErr: testCase.sendErr,
			}
			connection := &serviceConnection{Connection: underlying}
			err := connection.Send(context.Background(), &p2pnode.Message{Payload: []byte("payload")})
			if !errors.Is(err, testCase.sendErr) {
				t.Fatalf("Send error=%v, want %v", err, testCase.sendErr)
			}
			if underlying.closed.Load() != testCase.wantClose {
				t.Fatalf("closed=%t, want %t", underlying.closed.Load(), testCase.wantClose)
			}
			wantCloseCalls := int32(0)
			if testCase.wantClose {
				wantCloseCalls = 1
			}
			if got := underlying.closeCalls.Load(); got != wantCloseCalls {
				t.Fatalf("close calls=%d, want %d", got, wantCloseCalls)
			}
		})
	}
}

func TestServiceCarrierFirstRecoveryWaitsForReconnectGate(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		releaseGate bool
	}{
		{name: "cancellation prevents dial"},
		{name: "grant permits dial", releaseGate: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			node, err := NewNATNode(nil, "relay.test:9000")
			if err != nil {
				t.Fatalf("NewNATNode: %v", err)
			}
			defer node.Close()
			transport := newCarrierReconnectTestTransport()
			node.transport = transport
			listenerCtx, cancel := context.WithCancel(context.Background())
			listener := &ServiceListener{node: node, ctx: listenerCtx, cancel: cancel}
			carrier := &serviceCarrier{addr: "relay.test:9000"}
			done := make(chan struct{})
			go func() {
				listener.maintainCarrier(carrier)
				close(done)
			}()

			select {
			case request := <-transport.gateRequests:
				if request.RelayAddress != carrier.addr || request.Transport != "carrier" ||
					request.Role != "natserver" || request.Attempt != 1 ||
					request.NodeID != string(node.ID()) {
					t.Fatalf("first recovery request = %+v", request)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("first carrier recovery did not enter reconnect gate")
			}
			if calls := transport.registerCalls.Load(); calls != 0 {
				t.Fatalf("carrier dialed before gate grant: calls=%d", calls)
			}

			if testCase.releaseGate {
				close(transport.gateRelease)
				select {
				case <-transport.registerSeen:
				case <-time.After(time.Second):
					t.Fatal("carrier did not dial after gate grant")
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("carrier recovery did not stop after cancellation")
			}
			wantCalls := int32(0)
			if testCase.releaseGate {
				wantCalls = 1
			}
			if calls := transport.registerCalls.Load(); calls != wantCalls {
				t.Fatalf("carrier register calls=%d, want %d", calls, wantCalls)
			}
		})
	}
}

func TestServiceListenerAcceptsConcurrentClients(t *testing.T) {
	relay, relayAddr, closeRelay := startRelay(t)
	defer closeRelay()

	server, err := NewNATNode(nil, relayAddr)
	if err != nil {
		t.Fatalf("create service server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	listener, err := server.ListenService(ctx, relayAddr, ServiceOptions{
		MaxSessions: 32,
		AcceptQueue: 8,
	})
	if err != nil {
		t.Fatalf("ListenService: %v", err)
	}
	defer listener.Close()
	deadline := time.Now().Add(3 * time.Second)
	for !relay.Cover().HasGroup(string(server.ID())) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !relay.Cover().HasGroup(string(server.ID())) {
		t.Fatal("relay did not activate the persistent service registration")
	}

	const clientCount = 8
	serverErrors := make(chan error, clientCount)
	for index := 0; index < clientCount; index++ {
		go func() {
			connection, acceptErr := listener.Accept(ctx)
			if acceptErr != nil {
				serverErrors <- fmt.Errorf("accept: %w", acceptErr)
				return
			}
			defer connection.Close()
			message, receiveErr := connection.Receive(ctx)
			if receiveErr != nil {
				serverErrors <- fmt.Errorf("server receive: %w", receiveErr)
				return
			}
			if sendErr := connection.Send(ctx, &p2pnode.Message{
				Type:    p2pnode.MsgAppData,
				Path:    message.Path,
				Payload: append([]byte("echo:"), message.Payload...),
			}); sendErr != nil {
				serverErrors <- fmt.Errorf("server send: %w", sendErr)
				return
			}
			serverErrors <- nil
		}()
	}

	clientErrors := make(chan error, clientCount)
	releaseClients := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseClients) }) }
	defer release()
	var clients sync.WaitGroup
	for index := 0; index < clientCount; index++ {
		index := index
		clients.Add(1)
		go func() {
			defer clients.Done()
			client, createErr := NewNATNode(nil, relayAddr)
			if createErr != nil {
				clientErrors <- fmt.Errorf("create client %d: %w", index, createErr)
				return
			}
			defer client.Close()

			connection, dialErr := dialServiceForTest(ctx, client, server.ID())
			if dialErr != nil {
				clientErrors <- fmt.Errorf("dial client %d: %w", index, dialErr)
				return
			}
			defer connection.Close()

			payload := []byte{byte(index + 1)}
			if sendErr := connection.Send(ctx, &p2pnode.Message{
				Type:    p2pnode.MsgAppData,
				Path:    "/service/echo",
				Payload: payload,
			}); sendErr != nil {
				clientErrors <- fmt.Errorf("client %d send: %w", index, sendErr)
				return
			}
			response, receiveErr := connection.Receive(ctx)
			if receiveErr != nil {
				clientErrors <- fmt.Errorf("client %d receive: %w", index, receiveErr)
				return
			}
			want := append([]byte("echo:"), payload...)
			if string(response.Payload) != string(want) {
				clientErrors <- fmt.Errorf("client %d response = %q, want %q", index, response.Payload, want)
				return
			}
			clientErrors <- nil
			<-releaseClients
		}()
	}
	for index := 0; index < clientCount; index++ {
		clientErr := <-clientErrors
		if clientErr != nil {
			t.Fatal(clientErr)
		}
	}

	for index := 0; index < clientCount; index++ {
		select {
		case serverErr := <-serverErrors:
			if serverErr != nil {
				t.Fatal(serverErr)
			}
		case <-ctx.Done():
			t.Fatal("server did not finish concurrent service sessions")
		}
	}
	release()
	clients.Wait()

	server.mu.RLock()
	registered := server.registeredRelays[relayAddr]
	server.mu.RUnlock()
	if registered == nil {
		t.Fatal("service registration disappeared after concurrent clients")
	}

	listener.mu.Lock()
	activeSessions := len(listener.active)
	listener.mu.Unlock()
	deadline = time.Now().Add(3 * time.Second)
	for activeSessions != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		listener.mu.Lock()
		activeSessions = len(listener.active)
		listener.mu.Unlock()
	}
	if activeSessions != 0 {
		t.Fatalf("active service sessions after close = %d", activeSessions)
	}
}

func TestServiceListenerAcceptsClientsThroughTwoRelays(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "1")
	relayOne, relayOneAddr, closeRelayOne := startRelay(t)
	defer closeRelayOne()
	relayTwo, relayTwoAddr, closeRelayTwo := startRelay(t)
	defer closeRelayTwo()

	server, err := NewNATNode(nil, relayOneAddr)
	if err != nil {
		t.Fatalf("create multi-Relay server: %v", err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	listener, err := server.ListenServiceRelays(ctx, []string{relayOneAddr, relayTwoAddr}, ServiceOptions{
		MaxSessions: 2, AcceptQueue: 2,
	})
	if err != nil {
		t.Fatalf("ListenServiceRelays: %v", err)
	}
	defer listener.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) &&
		(!relayOne.Cover().HasGroup(string(server.ID())) || !relayTwo.Cover().HasGroup(string(server.ID()))) {
		time.Sleep(10 * time.Millisecond)
	}
	if !relayOne.Cover().HasGroup(string(server.ID())) || !relayTwo.Cover().HasGroup(string(server.ID())) {
		t.Fatal("same service NodeID was not active on both Relays")
	}

	type clientResult struct {
		relay string
		err   error
	}
	clientResults := make(chan clientResult, 2)
	for _, relayAddr := range []string{relayOneAddr, relayTwoAddr} {
		relayAddr := relayAddr
		go func() {
			client, createErr := NewNATNode(nil, relayAddr)
			if createErr != nil {
				clientResults <- clientResult{relay: relayAddr, err: createErr}
				return
			}
			defer client.Close()
			connection, dialErr := dialServiceForTest(ctx, client, server.ID())
			if dialErr != nil {
				clientResults <- clientResult{relay: relayAddr, err: dialErr}
				return
			}
			defer connection.Close()
			if sendErr := connection.Send(ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: []byte(relayAddr)}); sendErr != nil {
				clientResults <- clientResult{relay: relayAddr, err: sendErr}
				return
			}
			response, receiveErr := connection.Receive(ctx)
			if receiveErr != nil {
				clientResults <- clientResult{relay: relayAddr, err: receiveErr}
				return
			}
			if string(response.Payload) != "ack:"+relayAddr {
				clientResults <- clientResult{relay: relayAddr, err: fmt.Errorf("response=%q", response.Payload)}
				return
			}
			clientResults <- clientResult{relay: relayAddr}
		}()
	}

	seenRelays := make(map[string]bool)
	for index := 0; index < 2; index++ {
		connection, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			t.Fatalf("accept multi-Relay client: %v", acceptErr)
		}
		message, receiveErr := connection.Receive(ctx)
		if receiveErr != nil {
			t.Fatalf("receive multi-Relay request: %v", receiveErr)
		}
		relayAddr := string(message.Payload)
		seenRelays[relayAddr] = true
		if sendErr := connection.Send(ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: []byte("ack:" + relayAddr)}); sendErr != nil {
			t.Fatalf("send multi-Relay response: %v", sendErr)
		}
	}
	for index := 0; index < 2; index++ {
		if result := <-clientResults; result.err != nil {
			t.Fatalf("client via %s failed: %v", result.relay, result.err)
		}
	}
	if !seenRelays[relayOneAddr] || !seenRelays[relayTwoAddr] {
		t.Fatalf("accepted sessions did not cover both Relays: %v", seenRelays)
	}
	snapshot := listener.Snapshot()
	if len(snapshot.Carriers) != 2 {
		t.Fatalf("carrier snapshot count=%d, want 2", len(snapshot.Carriers))
	}
	for _, carrier := range snapshot.Carriers {
		if !carrier.Connected {
			t.Fatalf("carrier %s is not connected: %+v", carrier.RelayAddress, carrier)
		}
	}
}

func dialServiceForTest(ctx context.Context, client *NATNode, target p2pnode.NodeID) (p2pnode.Connection, error) {
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		connection, err := client.DialService(ctx, target)
		if err == nil {
			return connection, nil
		}
		lastErr = err
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func TestServiceListenerSnapshotAndCloseAreConcurrentSafe(t *testing.T) {
	listenerCtx, cancel := context.WithCancel(context.Background())
	listener := &ServiceListener{
		ctx:      listenerCtx,
		cancel:   cancel,
		options:  ServiceOptions{MaxSessions: 16, AcceptQueue: 16},
		accepted: make(chan p2pnode.Connection, 16),
		sessions: make(chan struct{}, 16),
		active:   make(map[string]p2pnode.Connection),
	}
	for index := 0; index < 16; index++ {
		connectionID := fmt.Sprintf("connection-%02d", index)
		listener.active[connectionID] = &serviceSnapshotTestConnection{
			peer: p2pnode.PeerInfo{ID: p2pnode.NodeID(fmt.Sprintf("peer-%02d", index))},
		}
		listener.sessions <- struct{}{}
	}

	var waitGroup sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for iteration := 0; iteration < 500; iteration++ {
				_ = listener.Snapshot()
			}
		}()
	}
	for index := 0; index < 16; index++ {
		index := index
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			listener.removeSession(fmt.Sprintf("connection-%02d", index))
		}()
	}
	waitGroup.Wait()
	if snapshot := listener.Snapshot(); snapshot.ActiveSessions != 0 {
		t.Fatalf("active sessions after concurrent removal = %d", snapshot.ActiveSessions)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
}

func TestServiceListenerSnapshotUsesMigratedRelayAddress(t *testing.T) {
	listener := &ServiceListener{
		addr:     "relay01:9000",
		entry:    &relayEntry{addr: "relay02:9000"},
		options:  ServiceOptions{MaxSessions: 8, AcceptQueue: 8},
		active:   make(map[string]p2pnode.Connection),
		accepted: make(chan p2pnode.Connection, 8),
	}
	if snapshot := listener.Snapshot(); snapshot.RelayAddress != "relay02:9000" {
		t.Fatalf("snapshot relay address = %q, want migrated relay", snapshot.RelayAddress)
	}
}
