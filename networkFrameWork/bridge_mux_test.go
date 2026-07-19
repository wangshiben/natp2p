package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestMuxOpenLegFlagsWireCompatibility(t *testing.T) {
	const (
		target = "target-node"
		pubKey = "origin-pub-key"
	)
	flags := uint8(network.LegFlagExtra | network.LegFlagResume)

	if got, want := string(encodeMuxOpen(target, pubKey)), target+"\n"+pubKey; got != want {
		t.Fatalf("旧单 leg OPEN 编码变化: got %q want %q", got, want)
	}
	if got, want := string(encodeMuxOpen(target, pubKey, 0)), target+"\n"+pubKey; got != want {
		t.Fatalf("flags=0 的单 leg OPEN 编码变化: got %q want %q", got, want)
	}
	if got, want := string(encodeMuxOpenLeg(target, pubKey, 2, 4)), target+"\n"+pubKey+"\n2\n4"; got != want {
		t.Fatalf("旧条带化 OPEN 编码变化: got %q want %q", got, want)
	}
	if got, want := string(encodeMuxOpenLeg(target, pubKey, 2, 4, 0)), target+"\n"+pubKey+"\n2\n4"; got != want {
		t.Fatalf("flags=0 的条带化 OPEN 编码变化: got %q want %q", got, want)
	}

	tests := []struct {
		name     string
		payload  []byte
		legIndex int
		legCount int
		legFlags uint8
	}{
		{name: "旧单 leg", payload: []byte(target + "\n" + pubKey), legIndex: 0, legCount: 1},
		{name: "旧条带化", payload: []byte(target + "\n" + pubKey + "\n2\n4"), legIndex: 2, legCount: 4},
		{name: "新单 leg", payload: encodeMuxOpen(target, pubKey, flags), legIndex: 0, legCount: 1, legFlags: flags},
		{name: "新条带化", payload: encodeMuxOpenLeg(target, pubKey, 2, 4, flags), legIndex: 2, legCount: 4, legFlags: flags},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := decodeMuxOpen(tt.payload)
			if info.targetNodeID != target || info.originPubKey != pubKey {
				t.Fatalf("OPEN 身份元信息不匹配: target=%q pubKey=%q", info.targetNodeID, info.originPubKey)
			}
			if info.legIndex != tt.legIndex || info.legCount != tt.legCount || info.legFlags != tt.legFlags {
				t.Fatalf("OPEN leg 元信息不匹配: index=%d count=%d flags=%d", info.legIndex, info.legCount, info.legFlags)
			}
		})
	}
}

func TestMuxSession_LegFlagsReachSynthesizedHello(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	client := NewMuxSession(context.Background(), clientConn, true)
	server := NewMuxSession(context.Background(), serverConn, false)
	defer client.Close()
	defer server.Close()

	const (
		connID = "resume-conn"
		target = "target-node"
		pubKey = "origin-pub-key"
	)
	flags := uint8(network.LegFlagExtra | network.LegFlagResume)
	clientStream, err := client.OpenStream(connID, target, pubKey, flags)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer clientStream.Close()

	serverStream, err := server.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got := serverStream.LegFlags(); got != flags {
		t.Fatalf("MuxStream.LegFlags=%d, want %d", got, flags)
	}

	accepted, err := AcceptBridgeMuxStream(serverStream)
	if err != nil {
		t.Fatalf("AcceptBridgeMuxStream: %v", err)
	}
	frame, err := network.ReadFrame(accepted)
	if err != nil {
		t.Fatalf("读取合成 hello 帧: %v", err)
	}
	message, err := network.AssembleFrames([]*network.Frame{frame})
	if err != nil {
		t.Fatalf("解析合成 hello 帧: %v", err)
	}
	if message.Header.LegFlags != flags {
		t.Fatalf("合成 hello LegFlags=%d, want %d", message.Header.LegFlags, flags)
	}
	if message.Header.ConnectionId != connID || message.Header.NodeId != target || string(message.Payload) != pubKey {
		t.Fatalf("合成 hello 元信息不匹配: connID=%q target=%q payload=%q", message.Header.ConnectionId, message.Header.NodeId, message.Payload)
	}
}

func TestAcceptBridgeMuxLogicalConn_LegFlags(t *testing.T) {
	flags := uint8(network.LegFlagExtra | network.LegFlagResume)
	logicalConn := newLogicalConn("striped-resume", nil, nil)
	accepted, err := AcceptBridgeMuxLogicalConn(logicalConn, "target-node", "origin-pub-key", flags)
	if err != nil {
		t.Fatalf("AcceptBridgeMuxLogicalConn: %v", err)
	}
	frame, err := network.ReadFrame(accepted)
	if err != nil {
		t.Fatalf("读取条带化合成 hello 帧: %v", err)
	}
	message, err := network.AssembleFrames([]*network.Frame{frame})
	if err != nil {
		t.Fatalf("解析条带化合成 hello 帧: %v", err)
	}
	if got := message.Header.LegFlags; got != flags {
		t.Fatalf("条带化合成 hello LegFlags=%d, want %d", got, flags)
	}
}

// TestMuxSession_MultiStream 验证一条物理连接(net.Pipe)上多路 stream 并发收发与隔离。
func TestMuxSession_MultiStream(t *testing.T) {
	c1, c2 := net.Pipe()
	ctx := context.Background()
	client := NewMuxSession(ctx, c1, true)
	server := NewMuxSession(ctx, c2, false)
	defer client.Close()
	defer server.Close()

	// server 侧: 每 Accept 一条 stream 就 echo 回写(带 streamID 前缀验证隔离)。
	go func() {
		for {
			st, err := server.Accept()
			if err != nil {
				return
			}
			go func(s *MuxStream) {
				buf := make([]byte, 4096)
				for {
					n, err := s.Read(buf)
					if n > 0 {
						_, _ = s.Write(append([]byte(s.StreamID()+":"), buf[:n]...))
					}
					if err != nil {
						return
					}
				}
			}(st)
		}
	}()

	const numStreams = 8
	var wg sync.WaitGroup
	errCh := make(chan error, numStreams)
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			connID := fmt.Sprintf("conn-%d", idx)
			st, err := client.OpenStream(connID, "target-node", "pubkey-hex")
			if err != nil {
				errCh <- fmt.Errorf("stream %d open: %w", idx, err)
				return
			}
			msg := fmt.Sprintf("hello-from-%d", idx)
			if _, err := st.Write([]byte(msg)); err != nil {
				errCh <- fmt.Errorf("stream %d write: %w", idx, err)
				return
			}
			buf := make([]byte, 4096)
			_ = st.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := st.Read(buf)
			if err != nil && err != io.EOF {
				errCh <- fmt.Errorf("stream %d read: %w", idx, err)
				return
			}
			want := connID + ":" + msg
			if string(buf[:n]) != want {
				errCh <- fmt.Errorf("stream %d got %q want %q", idx, string(buf[:n]), want)
				return
			}
		}(i)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("超时: mux 多 stream 收发未完成")
	}
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if as := client.ActiveStreams(); as != numStreams {
		t.Errorf("client ActiveStreams=%d, want %d", as, numStreams)
	}
}

// TestMuxSession_StreamClose 验证 CLOSE 帧传播与 activeStreams 计数回收。
func TestMuxSession_StreamClose(t *testing.T) {
	c1, c2 := net.Pipe()
	ctx := context.Background()
	client := NewMuxSession(ctx, c1, true)
	server := NewMuxSession(ctx, c2, false)
	defer client.Close()
	defer server.Close()

	accepted := make(chan *MuxStream, 1)
	go func() {
		st, err := server.Accept()
		if err == nil {
			accepted <- st
		}
	}()

	st, err := client.OpenStream("conn-x", "target", "pk")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var srvStream *MuxStream
	select {
	case srvStream = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("server 未 Accept 到 stream")
	}

	// client 关闭 → server 侧 Read 应返回 EOF。
	_ = st.Close()
	buf := make([]byte, 16)
	deadline := time.After(3 * time.Second)
	readDone := make(chan error, 1)
	go func() { _, e := srvStream.Read(buf); readDone <- e }()
	select {
	case e := <-readDone:
		if e != io.EOF {
			t.Errorf("server Read after client close = %v, want EOF", e)
		}
	case <-deadline:
		t.Fatal("server Read 未在关闭后返回")
	}

	if as := client.ActiveStreams(); as != 0 {
		t.Errorf("client ActiveStreams=%d after close, want 0", as)
	}
}
