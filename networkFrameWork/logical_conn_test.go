package networkFrameWork

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestLogicalConn_SingleLegPassthrough 验证 width=1 的 LogicalConn 是对底层 MuxStream
// 的零开销直通：双向字节、Close 语义与裸 MuxStream 等价。
func TestLogicalConn_SingleLegPassthrough(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := NewMuxSession(ctx, c1, true)
	server := NewMuxSession(ctx, c2, false)
	defer client.Close()
	defer server.Close()

	// 入口侧开一条 stream，包成 LogicalConn(width=1)
	st, err := client.OpenStream("lc-1", "target-node", "pubkey")
	if err != nil {
		t.Fatalf("OpenStream 失败: %v", err)
	}
	lc := NewSingleLegConn(st)
	if lc.Width() != 1 {
		t.Fatalf("期望 width=1, 实际 %d", lc.Width())
	}
	if lc.LogicalID() != "lc-1" {
		t.Fatalf("LogicalID 不匹配: %s", lc.LogicalID())
	}

	// 对端 Accept 出 stream
	srvSt, err := server.Accept()
	if err != nil {
		t.Fatalf("Accept 失败: %v", err)
	}

	// 入口 LogicalConn.Write → 对端 stream.Read
	payload := []byte("hello-logical-conn-passthrough")
	go func() {
		_, _ = lc.Write(payload)
	}()
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(srvSt, buf); err != nil {
		t.Fatalf("对端读取失败: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("字节不匹配: got %q want %q", buf, payload)
	}

	// 反向：对端 Write → 入口 LogicalConn.Read
	reply := []byte("reply-bytes-back")
	go func() {
		_, _ = srvSt.Write(reply)
	}()
	rbuf := make([]byte, len(reply))
	if _, err := io.ReadFull(lc, rbuf); err != nil {
		t.Fatalf("LogicalConn 读取失败: %v", err)
	}
	if string(rbuf) != string(reply) {
		t.Fatalf("反向字节不匹配: got %q want %q", rbuf, reply)
	}

	// Close 应关闭底层 leg
	if err := lc.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	// 关闭后对端读到 EOF
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, rerr := srvSt.Read(make([]byte, 8))
		if rerr == io.EOF {
			t.Logf("✔ LogicalConn(width=1) 直通: 双向字节一致, Close 传播到对端")
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("Close 后对端未收到 EOF")
}
