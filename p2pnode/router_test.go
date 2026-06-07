package p2pnode

import (
	"bnfs_p2p/network"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeConn 是一个仅供 router 单测使用的 Connection 实现。
// 用 channel 注入"对端发来的消息"和"模拟连接断开"。
type fakeConn struct {
	peer    PeerInfo
	inbound chan *Message
	closed  chan struct{}
	once    sync.Once
}

func newFakeConn(peerID NodeID) *fakeConn {
	return &fakeConn{
		peer:    PeerInfo{ID: peerID, LastSeen: time.Now()},
		inbound: make(chan *Message, 16),
		closed:  make(chan struct{}),
	}
}

func (c *fakeConn) Peer() PeerInfo { return c.peer }

func (c *fakeConn) Send(ctx context.Context, msg *Message) error {
	// router 单测目前不依赖 Send；保留空实现。
	return nil
}

func (c *fakeConn) Receive(ctx context.Context) (*Message, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, errors.New("conn closed")
	case m := <-c.inbound:
		if m == nil {
			return nil, errors.New("conn closed")
		}
		return m, nil
	}
}

func (c *fakeConn) Raw() network.Stream { return nil }

func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// inject 模拟"对端发来的消息"。
func (c *fakeConn) inject(msg *Message) { c.inbound <- msg }

// TestMessageRouter_DispatchByPath 验证：注册的多个 path 各自只命中各自的 handler。
func TestMessageRouter_DispatchByPath(t *testing.T) {
	conn := newFakeConn("peer-1")
	defer conn.Close()

	r := NewMessageRouter(context.Background(), conn)
	defer r.Close()

	var mu sync.Mutex
	chatGot := []string{}
	fileGot := []string{}

	r.Handle("/chat/text", func(_ context.Context, _ Connection, msg *Message) {
		mu.Lock()
		chatGot = append(chatGot, string(msg.Payload))
		mu.Unlock()
	})
	r.Handle("/file/chunk", func(_ context.Context, _ Connection, msg *Message) {
		mu.Lock()
		fileGot = append(fileGot, string(msg.Payload))
		mu.Unlock()
	})
	r.Start()

	conn.inject(&Message{Path: "/chat/text", Payload: []byte("hi")})
	conn.inject(&Message{Path: "/file/chunk", Payload: []byte("bin1")})
	conn.inject(&Message{Path: "/chat/text", Payload: []byte("there")})
	conn.inject(&Message{Path: "/file/chunk", Payload: []byte("bin2")})

	// 简单等待所有消息被消费。
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := len(chatGot) == 2 && len(fileGot) == 2
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(chatGot) != 2 || chatGot[0] != "hi" || chatGot[1] != "there" {
		t.Fatalf("chat handler 收到的消息不对: %v", chatGot)
	}
	if len(fileGot) != 2 || fileGot[0] != "bin1" || fileGot[1] != "bin2" {
		t.Fatalf("file handler 收到的消息不对: %v", fileGot)
	}
}

// TestMessageRouter_Fallback 验证：未注册 path 走 fallback。
func TestMessageRouter_Fallback(t *testing.T) {
	conn := newFakeConn("peer-2")
	defer conn.Close()

	r := NewMessageRouter(context.Background(), conn)
	defer r.Close()

	got := make(chan string, 4)
	r.Handle("/chat/text", func(_ context.Context, _ Connection, msg *Message) {
		got <- "chat:" + string(msg.Payload)
	})
	r.SetFallback(func(_ context.Context, _ Connection, msg *Message) {
		got <- "fallback:" + msg.Path + ":" + string(msg.Payload)
	})
	r.Start()

	conn.inject(&Message{Path: "/chat/text", Payload: []byte("a")})
	conn.inject(&Message{Path: "/unknown", Payload: []byte("b")})
	conn.inject(&Message{Path: "", Payload: []byte("c")}) // 空 path 也走 fallback

	expected := map[string]bool{
		"chat:a":              true,
		"fallback:/unknown:b": true,
		"fallback::c":         true,
	}
	for i := 0; i < len(expected); i++ {
		select {
		case s := <-got:
			if !expected[s] {
				t.Fatalf("意外消息: %q", s)
			}
			delete(expected, s)
		case <-time.After(time.Second):
			t.Fatalf("等待消息超时, 还差: %v", expected)
		}
	}
}

// TestMessageRouter_NoHandlerNoFallback 验证：既无 handler 又无 fallback 时静默丢弃, 不阻塞。
func TestMessageRouter_NoHandlerNoFallback(t *testing.T) {
	conn := newFakeConn("peer-3")
	defer conn.Close()

	r := NewMessageRouter(context.Background(), conn)
	defer r.Close()

	hit := make(chan struct{}, 1)
	r.Handle("/known", func(_ context.Context, _ Connection, _ *Message) { hit <- struct{}{} })
	r.Start()

	conn.inject(&Message{Path: "/dropped"}) // 无人接收
	conn.inject(&Message{Path: "/known"})   // 应触发 hit

	select {
	case <-hit:
	case <-time.After(time.Second):
		t.Fatal("/known handler 没有触发, 推测被前一条 /dropped 卡死")
	}
}

// TestMessageRouter_UnhandleAndOverride 验证 Unhandle 与覆盖注册。
func TestMessageRouter_UnhandleAndOverride(t *testing.T) {
	conn := newFakeConn("peer-4")
	defer conn.Close()

	r := NewMessageRouter(context.Background(), conn)
	defer r.Close()
	r.Start()

	first := make(chan string, 4)
	second := make(chan string, 4)

	r.Handle("/x", func(_ context.Context, _ Connection, msg *Message) { first <- string(msg.Payload) })
	conn.inject(&Message{Path: "/x", Payload: []byte("v1")})
	select {
	case v := <-first:
		if v != "v1" {
			t.Fatalf("首版 handler 收到 %q", v)
		}
	case <-time.After(time.Second):
		t.Fatal("首版 handler 未触发")
	}

	// 覆盖
	r.Handle("/x", func(_ context.Context, _ Connection, msg *Message) { second <- string(msg.Payload) })
	conn.inject(&Message{Path: "/x", Payload: []byte("v2")})
	select {
	case v := <-second:
		if v != "v2" {
			t.Fatalf("第二版 handler 收到 %q", v)
		}
	case <-time.After(time.Second):
		t.Fatal("覆盖后的 handler 未触发")
	}
	select {
	case v := <-first:
		t.Fatalf("旧 handler 不应再被调用, 收到 %q", v)
	case <-time.After(50 * time.Millisecond):
	}

	// Unhandle 后无 fallback → 静默丢弃
	r.Unhandle("/x")
	conn.inject(&Message{Path: "/x", Payload: []byte("v3")})
	select {
	case v := <-second:
		t.Fatalf("Unhandle 后 handler 不应再被调用, 收到 %q", v)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestMessageRouter_CloseStopsLoop 验证 Close 后派发循环立即退出, 不再消费消息。
func TestMessageRouter_CloseStopsLoop(t *testing.T) {
	conn := newFakeConn("peer-5")
	defer conn.Close()

	r := NewMessageRouter(context.Background(), conn)
	called := make(chan struct{}, 1)
	r.Handle("/x", func(_ context.Context, _ Connection, _ *Message) {
		called <- struct{}{}
	})
	r.Start()

	conn.inject(&Message{Path: "/x"})
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("第一条消息未触发")
	}

	if err := r.Close(); err != nil {
		t.Fatalf("Close 返回错误: %v", err)
	}
	select {
	case <-r.Done():
	case <-time.After(time.Second):
		t.Fatal("Close 后 Done 通道未在合理时间内关闭")
	}

	// 再次注入：因为派发已停止, 这条永远不会被处理。
	conn.inject(&Message{Path: "/x"})
	select {
	case <-called:
		t.Fatal("Close 后不应再触发 handler")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestMessageRouter_ConnCloseStopsLoop 验证底层 Connection 断开时, Router 自动收尾。
func TestMessageRouter_ConnCloseStopsLoop(t *testing.T) {
	conn := newFakeConn("peer-6")
	r := NewMessageRouter(context.Background(), conn)
	r.Start()

	_ = conn.Close()

	select {
	case <-r.Done():
	case <-time.After(time.Second):
		t.Fatal("conn 关闭后 router Done 应被关闭")
	}
}
