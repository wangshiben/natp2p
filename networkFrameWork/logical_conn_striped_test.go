package networkFrameWork

import (
	"context"
	"crypto/sha256"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

// makeMuxPair 建一对 client/server MuxSession（net.Pipe 背靠背），返回它们。
func makeMuxPair(t *testing.T, ctx context.Context) (*MuxSession, *MuxSession) {
	t.Helper()
	c1, c2 := net.Pipe()
	client := NewMuxSession(ctx, c1, true)
	server := NewMuxSession(ctx, c2, false)
	return client, server
}

// TestReassembler_OutOfOrder 单元验证重排器：乱序+重复+连续缺口补齐后字节按序还原。
func TestReassembler_OutOfOrder(t *testing.T) {
	r := newReassembler()

	// 期望最终顺序: chunk0 chunk1 chunk2 chunk3
	chunks := [][]byte{
		[]byte("AAAA"), []byte("BBBB"), []byte("CCCC"), []byte("DDDD"),
	}
	// 乱序推入: 2, 0, 3, (重复0), 1
	r.push(2, chunks[2])
	r.push(0, chunks[0])
	r.push(3, chunks[3])
	r.push(0, chunks[0]) // 重复旧序号，应被丢弃
	r.push(1, chunks[1])

	got := make([]byte, 0, 16)
	buf := make([]byte, 8)
	deadline := time.Now().Add(2 * time.Second)
	for len(got) < 16 && time.Now().Before(deadline) {
		// read 会阻塞，这里用 goroutine + 超时避免卡死
		done := make(chan struct{})
		var n int
		go func() {
			n, _ = r.read(buf)
			close(done)
		}()
		select {
		case <-done:
			got = append(got, buf[:n]...)
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("read 超时, 已读 %q", got)
		}
	}
	if string(got) != "AAAABBBBCCCCDDDD" {
		t.Fatalf("重排错误: got %q want AAAABBBBCCCCDDDD", got)
	}
	t.Logf("✔ 重排器: 乱序(2,0,3,dup0,1) + 重复 → 正确还原 %q", got)
}

// TestLogicalConn_StripedIntegrity 验证条带化端到端字节完整：
// 入口侧 width=M 条带化写大块 → 经 M 条独立 mux leg 并行传输 → 对端按 group 归并重排 → SHA 一致。
func TestLogicalConn_StripedIntegrity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const M = 3
	// 建 M 对 mux 会话，模拟 M 条独立物理连接。
	clients := make([]*MuxSession, M)
	servers := make([]*MuxSession, M)
	for i := 0; i < M; i++ {
		clients[i], servers[i] = makeMuxPair(t, ctx)
		defer clients[i].Close()
		defer servers[i].Close()
	}

	connID := "striped-1"
	// 入口侧：在每条 mux 上 OpenStream(同 connID) 得到 M 条 leg。
	cliLegs := make([]*MuxStream, M)
	for i := 0; i < M; i++ {
		st, err := clients[i].OpenStream(connID, "tgt", "pub")
		if err != nil {
			t.Fatalf("client#%d OpenStream: %v", i, err)
		}
		cliLegs[i] = st
	}
	sendConn := NewStripedConn(connID, cliLegs)

	// 对端：每条 mux Accept 出对应 leg，归并成一条条带化逻辑连接。
	srvLegs := make([]*MuxStream, M)
	var awg sync.WaitGroup
	for i := 0; i < M; i++ {
		awg.Add(1)
		go func(idx int) {
			defer awg.Done()
			st, err := servers[idx].Accept()
			if err != nil {
				t.Errorf("server#%d Accept: %v", idx, err)
				return
			}
			srvLegs[idx] = st
		}(i)
	}
	awg.Wait()
	for i := 0; i < M; i++ {
		if srvLegs[i] == nil {
			t.Fatalf("server leg #%d 未就绪", i)
		}
	}
	recvConn := NewStripedConn(connID, srvLegs)

	// 准备 1MB 随机数据，入口 striped 写，对端 striped 读，校验 SHA。
	const size = 1 << 20
	payload := make([]byte, size)
	rand.New(rand.NewSource(42)).Read(payload)
	wantHash := sha256.Sum256(payload)

	var rwg sync.WaitGroup
	rwg.Add(1)
	var readErr error
	recv := make([]byte, size)
	go func() {
		defer rwg.Done()
		_, readErr = io.ReadFull(recvConn, recv)
	}()

	if _, err := sendConn.Write(payload); err != nil {
		t.Fatalf("striped Write: %v", err)
	}
	rwg.Wait()
	if readErr != nil {
		t.Fatalf("striped Read: %v", readErr)
	}
	if sha256.Sum256(recv) != wantHash {
		t.Fatalf("条带化字节流 SHA 不一致（重排错误）")
	}
	if sendConn.Width() != M || recvConn.Width() != M {
		t.Fatalf("width 不符: send=%d recv=%d want %d", sendConn.Width(), recvConn.Width(), M)
	}
	t.Logf("✔ 条带化 width=%d: 1MB 经 %d 条独立 leg 并行传输, 重排后 SHA 一致", M, M)
}
