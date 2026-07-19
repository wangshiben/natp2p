package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

func TestRelayKCPIncompleteHandshakeDoesNotBlockFollowingConnection(t *testing.T) {
	addr := freeLocalAddr(t)
	starter := NewRelayStarter(addr)
	go starter.StartListen()
	t.Cleanup(func() { starter.Close() })

	deadline := time.Now().Add(3 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay %s 未在期限内启动: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

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
