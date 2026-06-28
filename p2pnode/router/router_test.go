package router

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"bnfs_p2p/network"
	"bnfs_p2p/p2pnode"
)

// mockConnection 模拟 p2pnode.Connection 用于测试
type mockConnection struct {
	peer     p2pnode.PeerInfo
	recvChan chan *p2pnode.Message
	sendChan chan *p2pnode.Message
	closed   bool
	mu       sync.Mutex
}

func newMockConnection(peerID p2pnode.NodeID) *mockConnection {
	return &mockConnection{
		peer:     p2pnode.PeerInfo{ID: peerID},
		recvChan: make(chan *p2pnode.Message, 10),
		sendChan: make(chan *p2pnode.Message, 10),
	}
}

func (m *mockConnection) Peer() p2pnode.PeerInfo {
	return m.peer
}

func (m *mockConnection) Send(ctx context.Context, msg *p2pnode.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("connection closed")
	}
	select {
	case m.sendChan <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *mockConnection) Receive(ctx context.Context) (*p2pnode.Message, error) {
	select {
	case msg := <-m.recvChan:
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *mockConnection) Raw() network.Stream {
	return nil
}

func (m *mockConnection) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	close(m.recvChan)
	close(m.sendChan)
	return nil
}

// 测试辅助：向 mockConnection 推送消息
func (m *mockConnection) pushMessage(msg *p2pnode.Message) {
	m.recvChan <- msg
}

// 测试辅助：从 mockConnection 接收发送的消息
func (m *mockConnection) popSentMessage() *p2pnode.Message {
	select {
	case msg := <-m.sendChan:
		return msg
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

func TestRouter_BasicRouting(t *testing.T) {
	router := New()
	conn := newMockConnection("test-peer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 注册路由
	chatHandlerCalled := false
	router.Handle("/chat", func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {
		chatHandlerCalled = true
		if string(msg.Payload) != "hello" {
			t.Errorf("expected payload 'hello', got %s", string(msg.Payload))
		}
	})

	// 启动 ServeConnection
	go router.ServeConnection(ctx, conn)

	// 发送消息
	conn.pushMessage(&p2pnode.Message{
		Path:    "/chat",
		Payload: []byte("hello"),
	})

	// 等待处理
	time.Sleep(50 * time.Millisecond)

	if !chatHandlerCalled {
		t.Error("chat handler not called")
	}

	cancel()
}

func TestRouter_ParamExtraction(t *testing.T) {
	router := New()
	conn := newMockConnection("test-peer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 注册带参数的路由
	var extractedID string
	router.Handle("/user/:id", func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {
		params := conn.Params(ctx)
		extractedID = params["id"]
	})

	go router.ServeConnection(ctx, conn)

	conn.pushMessage(&p2pnode.Message{
		Path: "/user/123",
	})

	time.Sleep(50 * time.Millisecond)

	if extractedID != "123" {
		t.Errorf("expected id=123, got %s", extractedID)
	}

	cancel()
}

func TestRouter_Reply(t *testing.T) {
	router := New()
	conn := newMockConnection("test-peer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router.Handle("/echo", func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {
		conn.Reply(ctx, msg.Payload)
	})

	go router.ServeConnection(ctx, conn)

	conn.pushMessage(&p2pnode.Message{
		Path:    "/echo",
		Payload: []byte("test"),
	})

	time.Sleep(50 * time.Millisecond)

	// 检查发送的消息
	sent := conn.popSentMessage()
	if sent == nil {
		t.Fatal("no message sent")
	}
	if sent.Code != 200 {
		t.Errorf("expected Code=200, got %d", sent.Code)
	}
	if sent.Path != "/echo" {
		t.Errorf("expected Path=/echo, got %s", sent.Path)
	}
	if string(sent.Payload) != "test" {
		t.Errorf("expected Payload=test, got %s", string(sent.Payload))
	}

	cancel()
}

func TestRouter_SendTo(t *testing.T) {
	router := New()
	conn := newMockConnection("test-peer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router.Handle("/trigger", func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {
		// 跨 Path 发送
		conn.SendTo(ctx, "/notify", []byte("triggered"))
	})

	go router.ServeConnection(ctx, conn)

	conn.pushMessage(&p2pnode.Message{
		Path: "/trigger",
	})

	time.Sleep(50 * time.Millisecond)

	sent := conn.popSentMessage()
	if sent == nil {
		t.Fatal("no message sent")
	}
	if sent.Path != "/notify" {
		t.Errorf("expected Path=/notify, got %s", sent.Path)
	}
	if string(sent.Payload) != "triggered" {
		t.Errorf("expected Payload=triggered, got %s", string(sent.Payload))
	}

	cancel()
}

func TestRouter_NotFound(t *testing.T) {
	router := New()
	conn := newMockConnection("test-peer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fallbackCalled := false
	router.NotFound(func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {
		fallbackCalled = true
		if msg.Path != "/unknown" {
			t.Errorf("expected Path=/unknown, got %s", msg.Path)
		}
	})

	go router.ServeConnection(ctx, conn)

	conn.pushMessage(&p2pnode.Message{
		Path: "/unknown",
	})

	time.Sleep(50 * time.Millisecond)

	if !fallbackCalled {
		t.Error("fallback handler not called")
	}

	cancel()
}

func TestRouter_NoFallback(t *testing.T) {
	router := New()
	conn := newMockConnection("test-peer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 不注册 fallback，未匹配的消息应被丢弃（不 panic）

	go router.ServeConnection(ctx, conn)

	conn.pushMessage(&p2pnode.Message{
		Path: "/nonexistent",
	})

	time.Sleep(50 * time.Millisecond)

	// 没有 panic 即通过
	cancel()
}

func TestRouter_MultipleRoutes(t *testing.T) {
	router := New()
	conn := newMockConnection("test-peer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	route1Called := false
	route2Called := false

	router.Handle("/route1", func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {
		route1Called = true
	})
	router.Handle("/route2", func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {
		route2Called = true
	})

	go router.ServeConnection(ctx, conn)

	conn.pushMessage(&p2pnode.Message{Path: "/route1"})
	conn.pushMessage(&p2pnode.Message{Path: "/route2"})

	time.Sleep(50 * time.Millisecond)

	if !route1Called || !route2Called {
		t.Error("not all routes called")
	}

	cancel()
}

func TestRouter_ConcurrentHandlers(t *testing.T) {
	router := New()
	conn := newMockConnection("test-peer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	callCount := 0

	router.Handle("/concurrent", func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
		callCount++
		mu.Unlock()
	})

	go router.ServeConnection(ctx, conn)

	// 发送多条消息
	for i := 0; i < 5; i++ {
		conn.pushMessage(&p2pnode.Message{Path: "/concurrent"})
	}

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	count := callCount
	mu.Unlock()

	if count != 5 {
		t.Errorf("expected 5 calls, got %d", count)
	}

	cancel()
}
