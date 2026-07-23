package mux

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"bnfs_p2p/p2pnode"
)

type countingConnection struct {
	p2pnode.Connection
	sends atomic.Int32
}

func (connection *countingConnection) Send(ctx context.Context, message *p2pnode.Message) error {
	connection.sends.Add(1)
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
	if serverCarrier.sends.Load() != 0 {
		t.Fatalf("server echoed %d close messages", serverCarrier.sends.Load())
	}
	if _, err := serverSession.Accept(); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Accept after peer close = %v, want ErrSessionClosed", err)
	}
}
