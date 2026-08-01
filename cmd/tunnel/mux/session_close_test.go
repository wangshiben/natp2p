package mux

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bnfs_p2p/p2pnode"
)

type countingConnection struct {
	p2pnode.Connection
	sends atomic.Int32
	mu    sync.Mutex
	paths []string
}

func (connection *countingConnection) Send(ctx context.Context, message *p2pnode.Message) error {
	connection.sends.Add(1)
	connection.mu.Lock()
	connection.paths = append(connection.paths, message.Path)
	connection.mu.Unlock()
	return connection.Connection.Send(ctx, message)
}

func TestSessionCloseNotifiesPeerWithoutEcho(t *testing.T) {
	clientConnection, serverConnection := newPipePair(0)
	clientCarrier := &countingConnection{Connection: clientConnection}
	serverCarrier := &countingConnection{Connection: serverConnection}
	clientSession := NewSession(context.Background(), clientCarrier, true)
	serverSession := NewSession(context.Background(), serverCarrier, false)

	if err := clientSession.Close(); err != nil {
		t.Fatalf("client Close: %v", err)
	}
	select {
	case <-serverSession.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("peer session did not close after SESSION_CLOSE")
	}
	if clientCarrier.sends.Load() != 1 {
		t.Fatalf("client sends = %d, want one SESSION_CLOSE", clientCarrier.sends.Load())
	}
	clientCarrier.mu.Lock()
	paths := append([]string(nil), clientCarrier.paths...)
	clientCarrier.mu.Unlock()
	if len(paths) != 1 || paths[0] != p2pnode.TransportControlPath {
		t.Fatalf("session close paths = %v, want transport control path", paths)
	}
	if serverCarrier.sends.Load() != 0 {
		t.Fatalf("server echoed %d close messages", serverCarrier.sends.Load())
	}
	if _, err := serverSession.Accept(); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Accept after peer close = %v, want ErrSessionClosed", err)
	}
}
