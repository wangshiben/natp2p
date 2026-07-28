package mux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"math/rand"
	"sync"
	"testing"
	"time"

	"bnfs_p2p/network"
	"bnfs_p2p/p2pnode"
)

// pipeConn 是一对方向相连的内存 Connection：a.Send -> b.Receive。
// reorder>0 时，在投递侧对【连续的 DATA 帧】做乱序(小窗口内打乱顺序),模拟流水线下
// 一次 Write 的 W 个并发 chunk 因不同 ACK 时序/重传而乱序到达。OPEN/CLOSE 作为顺序屏障
// (先 flush 缓冲再透传)。生产 DualStream 跨 leg 合流时控制帧仍可能晚于 DATA，另有测试覆盖。
type pipeConn struct {
	out     chan *p2pnode.Message // 本端发出 -> 投递管道
	in      chan *p2pnode.Message // 重排后 -> 本端收
	reorder int
}

func newPipePair(reorder int) (*pipeConn, *pipeConn) {
	abRaw := make(chan *p2pnode.Message, 1024)
	baRaw := make(chan *p2pnode.Message, 1024)
	abOut := make(chan *p2pnode.Message, 1024)
	baOut := make(chan *p2pnode.Message, 1024)
	go reorderPump(abRaw, abOut, reorder)
	go reorderPump(baRaw, baOut, reorder)
	a := &pipeConn{out: abRaw, in: baOut, reorder: reorder}
	b := &pipeConn{out: baRaw, in: abOut, reorder: reorder}
	return a, b
}

// reorderPump 把 raw 中【连续的 DATA 帧】按最多 window 个一批打乱后投递到 out；
// 遇到非 DATA(OPEN/CLOSE) 先把已缓冲的 DATA flush(乱序)再原样透传该控制帧。
func reorderPump(raw <-chan *p2pnode.Message, out chan<- *p2pnode.Message, window int) {
	var batch []*p2pnode.Message
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// 打乱本批 DATA 顺序
		rand.Shuffle(len(batch), func(i, j int) { batch[i], batch[j] = batch[j], batch[i] })
		for _, m := range batch {
			out <- m
		}
		batch = batch[:0]
	}
	for m := range raw {
		if window > 1 && len(m.Payload) > 0 && m.Payload[0] == frameData {
			batch = append(batch, m)
			if len(batch) >= window {
				flush()
			}
			continue
		}
		flush()
		out <- m
	}
	flush()
}

func (c *pipeConn) Peer() p2pnode.PeerInfo { return p2pnode.PeerInfo{} }
func (c *pipeConn) Raw() network.Stream    { return nil }
func (c *pipeConn) Close() error           { return nil }

func (c *pipeConn) Send(ctx context.Context, msg *p2pnode.Message) error {
	// 拷贝 payload，避免调用方复用底层 buffer 造成数据竞争/串改。
	cp := make([]byte, len(msg.Payload))
	copy(cp, msg.Payload)
	m := &p2pnode.Message{Type: msg.Type, Payload: cp}
	select {
	case c.out <- m:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *pipeConn) Receive(ctx context.Context) (*p2pnode.Message, error) {
	select {
	case m := <-c.in:
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type delayedOpenConnection struct {
	p2pnode.Connection
	mu       sync.Mutex
	heldOpen *p2pnode.Message
}

func (c *delayedOpenConnection) Send(ctx context.Context, msg *p2pnode.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(msg.Payload) > 0 && msg.Payload[0] == frameOpen {
		payload := append([]byte(nil), msg.Payload...)
		c.heldOpen = &p2pnode.Message{Type: msg.Type, Payload: payload}
		return nil
	}
	if c.heldOpen == nil {
		return c.Connection.Send(ctx, msg)
	}
	if err := c.Connection.Send(ctx, msg); err != nil {
		return err
	}
	heldOpen := c.heldOpen
	c.heldOpen = nil
	return c.Connection.Send(ctx, heldOpen)
}

// transferOnce: client 开一条 stream 写 payload 并关闭；server accept 后读到 EOF，
// 返回收到的字节。校验顺序/完整性。
func transferOnce(t *testing.T, reorder int, payload []byte) []byte {
	t.Helper()
	ca, cb := newPipePair(reorder)
	ctx := context.Background()
	cli := NewSession(ctx, ca, true)
	srv := NewSession(ctx, cb, false)
	defer cli.Close()
	defer srv.Close()

	var got []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		st, err := srv.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		buf := make([]byte, 32*1024)
		var out []byte
		for {
			n, err := st.Read(buf)
			if n > 0 {
				out = append(out, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		got = out
	}()

	st, err := cli.OpenStream()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// 分多次 Write，模拟 io.CopyBuffer 多次喂数据。
	const writeSize = 256 * 1024
	for off := 0; off < len(payload); off += writeSize {
		end := off + writeSize
		if end > len(payload) {
			end = len(payload)
		}
		if _, err := st.Write(payload[off:end]); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	st.Close()

	wg.Wait()
	return got
}

// TestMux_InOrder 顺序投递(reorder=0)下基本收发完整。
func TestMux_InOrder(t *testing.T) {
	payload := make([]byte, 1<<20) // 1MB
	rand.Read(payload)
	got := transferOnce(t, 0, payload)
	if !bytes.Equal(got, payload) {
		t.Fatalf("数据不一致: got %d bytes, want %d", len(got), len(payload))
	}
	t.Logf("✔ 顺序投递 1MB 完整, SHA=%x", sha256.Sum256(got))
}

// TestMux_Reorder 是核心考验：乱序到达下，收端按序号重排后字节流必须与原文逐字节一致。
// 若重排逻辑有 bug,乱序的 chunk 会错位 -> SHA 不一致 -> 文件损坏。
func TestMux_Reorder(t *testing.T) {
	payload := make([]byte, 1<<20) // 1MB, 64KB chunk -> ~16 帧/Write * 多 Write -> 大量乱序机会
	rand.Read(payload)
	got := transferOnce(t, 8, payload) // reorder 窗口 8ms
	if len(got) != len(payload) {
		t.Fatalf("长度不一致: got %d, want %d", len(got), len(payload))
	}
	if !bytes.Equal(got, payload) {
		// 找出首个差异位置帮助定位
		for i := range got {
			if got[i] != payload[i] {
				t.Fatalf("乱序重排后数据损坏: 首个差异在 byte %d", i)
			}
		}
		t.Fatal("乱序重排后数据损坏(尾部)")
	}
	t.Logf("✔ 乱序到达 1MB 重排后逐字节一致, SHA=%x", sha256.Sum256(got))
}

// TestMux_ReorderManyRounds 多轮乱序,提高暴露竞态/丢尾的概率。
func TestMux_ReorderManyRounds(t *testing.T) {
	for round := 0; round < 20; round++ {
		size := 64*1024 + rand.Intn(512*1024)
		payload := make([]byte, size)
		rand.Read(payload)
		got := transferOnce(t, 5, payload)
		if !bytes.Equal(got, payload) {
			t.Fatalf("round %d: %d bytes 数据损坏(want %d)", round, len(got), len(payload))
		}
	}
	t.Log("✔ 20 轮随机大小乱序传输全部 SHA 一致(无丢尾/无错位)")
}

// TestMux_EmptyStream 空流(只 open+close,无 DATA)收端应正常 EOF 关闭(finalSeq=0)。
func TestMux_EmptyStream(t *testing.T) {
	got := transferOnce(t, 4, nil)
	if len(got) != 0 {
		t.Fatalf("空流应收 0 字节, 得 %d", len(got))
	}
	t.Log("✔ 空流 finalSeq=0 正常关闭")
}

func TestMux_ConcurrentStreams(t *testing.T) {
	const streamCount = 8

	clientConnection, serverConnection := newPipePair(0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientSession := NewSession(ctx, clientConnection, true)
	serverSession := NewSession(ctx, serverConnection, false)
	defer clientSession.Close()
	defer serverSession.Close()

	payloads := make(map[byte][]byte, streamCount)
	for index := 0; index < streamCount; index++ {
		payload := make([]byte, 256*1024)
		payload[0] = byte(index + 1)
		for offset := 1; offset < len(payload); offset++ {
			payload[offset] = byte((index + offset) % 251)
		}
		payloads[payload[0]] = payload
	}

	received := make(chan []byte, streamCount)
	serverErr := make(chan error, 1)
	go func() {
		var readers sync.WaitGroup
		for range streamCount {
			stream, err := serverSession.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			readers.Add(1)
			go func() {
				defer readers.Done()
				payload, err := io.ReadAll(stream)
				if err != nil {
					serverErr <- err
					return
				}
				received <- payload
			}()
		}
		readers.Wait()
		serverErr <- nil
	}()

	start := make(chan struct{})
	writerErr := make(chan error, streamCount)
	var writers sync.WaitGroup
	for _, payload := range payloads {
		payload := payload
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			stream, err := clientSession.OpenStream()
			if err == nil {
				_, err = stream.Write(payload)
				closeErr := stream.Close()
				if err == nil {
					err = closeErr
				}
			}
			writerErr <- err
		}()
	}
	close(start)
	writers.Wait()
	close(writerErr)
	for err := range writerErr {
		if err != nil {
			t.Fatalf("并发打开或写入子流失败: %v", err)
		}
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("服务端并发接收子流失败: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("并发子流传输超时")
	}

	seen := make(map[byte]bool, streamCount)
	for range streamCount {
		payload := <-received
		if len(payload) == 0 {
			t.Fatal("收到空的并发子流")
		}
		expected, ok := payloads[payload[0]]
		if !ok {
			t.Fatalf("收到未知子流标识: %d", payload[0])
		}
		if seen[payload[0]] {
			t.Fatalf("子流 %d 被重复接收", payload[0])
		}
		if !bytes.Equal(payload, expected) {
			t.Fatalf("子流 %d 内容不一致", payload[0])
		}
		seen[payload[0]] = true
	}
}

func TestMux_DataBeforeOpenMaterializesStream(t *testing.T) {
	clientConnection, serverConnection := newPipePair(0)
	clientCarrier := &delayedOpenConnection{Connection: clientConnection}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	clientSession := NewSession(ctx, clientCarrier, true)
	serverSession := NewSession(ctx, serverConnection, false)
	defer clientSession.Close()
	defer serverSession.Close()

	payload := make([]byte, 256*1024)
	rand.Read(payload)
	received := make(chan []byte, 1)
	go func() {
		stream, err := serverSession.Accept()
		if err != nil {
			received <- nil
			return
		}
		var output []byte
		buffer := make([]byte, 32*1024)
		for {
			count, readErr := stream.Read(buffer)
			output = append(output, buffer[:count]...)
			if readErr != nil {
				received <- output
				return
			}
		}
	}()

	stream, err := clientSession.OpenStream()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case output := <-received:
		if !bytes.Equal(output, payload) {
			t.Fatalf("DATA 先于 OPEN 到达后数据不一致: got %d bytes, want %d", len(output), len(payload))
		}
	case <-ctx.Done():
		t.Fatal("DATA 先于 OPEN 到达后 stream 未完成")
	}
}
