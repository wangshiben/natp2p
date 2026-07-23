package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

func TestRelayKCPIncompleteHandshakeDoesNotBlockFollowingConnection(t *testing.T) {
	addr := freeLocalAddr(t)
	starter := NewRelayStarter(addr)
	go starter.StartListen()
	t.Cleanup(func() { starter.Close() })
	waitForRelayStarterReady(t, starter)

	poison, err := kcp.DialWithOptions(addr, nil, 1, 1)
	if err != nil {
		t.Fatalf("创建不完整 KCP 会话失败: %v", err)
	}
	t.Cleanup(func() { _ = poison.Close() })
	if _, err := poison.Write([]byte{0}); err != nil {
		t.Fatalf("发送不完整 KCP 首帧失败: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	identity, err := newRelayTestIdentity("relay-kcp-hol")
	if err != nil {
		t.Fatalf("创建测试身份失败: %v", err)
	}
	message := &network.Message{
		Header: &network.Header{
			NodeId:        identity.nodeID,
			NodeIdVersion: 1,
			LegSessionId:  "relay-kcp-hol-session",
		},
		Payload: []byte(identity.publicKey),
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialHandshakeTimeout)
	defer cancel()
	stream, err := kcpStreamContext(ctx, message, addr, identity.nodeID, "", true)
	if err != nil {
		t.Fatalf("后续合法 KCP 会话被不完整握手阻塞: %v", err)
	}
	defer stream.Close()
}

func TestRelayStarterBindFailureIsVisibleAndCloseDoesNotBlock(t *testing.T) {
	tests := []struct {
		name       string
		occupyPort func(*testing.T) (string, func())
		wantError  string
	}{
		{name: "TCP", occupyPort: occupyRelayTCPPort, wantError: "listen TCP"},
		{name: "KCP", occupyPort: occupyRelayUDPPort, wantError: "listen KCP"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addr, release := test.occupyPort(t)
			defer release()
			starter := NewRelayStarter(addr)
			go starter.StartListen()

			select {
			case <-starter.Done():
			case <-time.After(time.Second):
				t.Fatal("port conflict did not finish relay startup")
			}
			startErr := starter.StartError()
			if startErr == nil || !strings.Contains(startErr.Error(), test.wantError) {
				t.Fatalf("startup error = %v, want error containing %q", startErr, test.wantError)
			}
			select {
			case <-starter.Ready():
				t.Fatal("relay reported ready after bind failure")
			default:
			}

			requireRelayStarterCallReturns(t, starter.Close)
			requireRelayStarterCallReturns(t, starter.Close)
		})
	}
}

func TestRelayStarterCloseBeforeStartIsIdempotent(t *testing.T) {
	starter := NewRelayStarter(freeLocalAddr(t))
	requireRelayStarterCallReturns(t, starter.Close)
	requireRelayStarterCallReturns(t, starter.Close)

	select {
	case <-starter.Done():
	default:
		t.Fatal("Close before StartListen did not signal shutdown completion")
	}
	if !errors.Is(starter.StartError(), ErrRelayStarterClosed) {
		t.Fatalf("startup error = %v, want ErrRelayStarterClosed", starter.StartError())
	}
	requireRelayStarterCallReturns(t, starter.StartListen)
}

func TestDispatchRelayConnectionRejectsAtHandshakeLimit(t *testing.T) {
	slots := make(chan struct{}, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	first, firstPeer := net.Pipe()
	defer first.Close()
	defer firstPeer.Close()

	if !dispatchRelayConnection("TEST", first, slots, func(net.Conn) error {
		close(entered)
		<-release
		close(done)
		return nil
	}) {
		t.Fatal("第一个握手应进入处理器")
	}
	<-entered

	second, secondPeer := net.Pipe()
	defer secondPeer.Close()
	if dispatchRelayConnection("TEST", second, slots, func(net.Conn) error { return nil }) {
		t.Fatal("达到握手并发上限后必须拒绝新连接")
	}
	_ = secondPeer.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := secondPeer.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("被拒绝的连接必须关闭，实际错误: %v", err)
	}

	close(release)
	<-done
}

func waitForRelayStarterReady(t *testing.T, starter *RelayStarter) {
	t.Helper()
	select {
	case <-starter.Ready():
		if err := starter.StartError(); err != nil {
			t.Fatalf("relay reported ready with startup error: %v", err)
		}
	case <-starter.Done():
		t.Fatalf("relay startup failed: %v", starter.StartError())
	case <-time.After(3 * time.Second):
		t.Fatal("relay startup readiness timed out")
	}
}

func requireRelayStarterCallReturns(t *testing.T, call func()) {
	t.Helper()
	returned := make(chan struct{})
	go func() {
		call()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("relay starter lifecycle call blocked")
	}
}

func occupyRelayTCPPort(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy relay TCP port: %v", err)
	}
	return listener.Addr().String(), func() { _ = listener.Close() }
}

func occupyRelayUDPPort(t *testing.T) (string, func()) {
	t.Helper()
	connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy relay UDP port: %v", err)
	}
	return connection.LocalAddr().String(), func() { _ = connection.Close() }
}
