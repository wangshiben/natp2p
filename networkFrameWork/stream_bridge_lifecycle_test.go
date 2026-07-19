package networkFrameWork

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestCrossRelayBridgeSignalsDoneAfterLastLocalLegCloses(t *testing.T) {
	localBridgeConn, localPeer := net.Pipe()
	peerBridgeConn, peerRemote := net.Pipe()
	t.Cleanup(func() {
		_ = localPeer.Close()
		_ = peerRemote.Close()
	})

	bridge := NewCrossRelayBridge(context.Background(), "peer", "target", "origin", "connection")
	bridge.SetDialFunc(func(string, string, string, string) (net.Conn, error) {
		return peerBridgeConn, nil
	})
	t.Cleanup(bridge.Close)

	stream := newTcpStream("node", "connection", localBridgeConn)
	if err := bridge.SpliceLeg(stream); err != nil {
		t.Fatalf("splice bridge leg: %v", err)
	}
	if err := localPeer.Close(); err != nil {
		t.Fatalf("close local peer: %v", err)
	}

	select {
	case <-bridge.Done():
	case <-time.After(time.Second):
		t.Fatal("bridge did not signal completion after its last local leg closed")
	}
	if err := bridge.SpliceLeg(newTcpStream("node", "late", localBridgeConn)); err == nil {
		t.Fatal("completed bridge accepted a late failover leg")
	}
}
