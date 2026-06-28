package networkFrameWork

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

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
