package p2pnode

import (
	"context"
	"errors"
	"sync"
)

// MessageHandler 是 Path 匹配后回调上层业务的处理函数。
// 它在 MessageRouter 的 dispatch goroutine 中同步调用，
// handler 内部应避免长阻塞或自行 go func 处理大块工作；
// 否则会延迟同一 Connection 上其他 Path 的派发。
//
// 参数：
//
//	ctx — MessageRouter 的生命周期 ctx，handler 应在 ctx.Done() 时尽快退出
//	conn — 消息所在的连接，便于 handler 直接回写
//	msg  — 收到的 p2pnode.Message
type MessageHandler func(ctx context.Context, conn Connection, msg *Message)

// MessageRouter 把一条 Connection 上的入站消息按 Message.Path 分发给注册的 handler。
//
// 类比 HTTP 路由：业务侧只关心"我对哪条 path 感兴趣"，不再自己维护 `for { Receive() ; switch }`。
// 多路复用语义：同一 Connection 可承载多个业务 path，互不干扰。
//
// 设计要点：
//   - 严格的 path 完全匹配，不做前缀/通配（保持简单，由调用方按需自行约定）。
//   - 没有匹配的 handler 时走 fallback；fallback 为 nil 则丢弃。
//   - Router 启动后内部跑一个 receive goroutine；用 Close() 显式停止，或随 ctx 取消而停止。
//   - 业务回调内若想拒绝继续派发，只需 cancel 传入 ctx 或 Close() router。
type MessageRouter struct {
	conn     Connection
	handlers map[string]MessageHandler
	fallback MessageHandler

	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	doneOnce sync.Once
	done     chan struct{}
}

// NewMessageRouter 在 conn 上构造一个空 router，handler 用 Handle/HandleFunc 注册。
// parent 为 nil 等价于 context.Background()。
func NewMessageRouter(parent context.Context, conn Connection) *MessageRouter {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &MessageRouter{
		conn:     conn,
		handlers: make(map[string]MessageHandler),
		ctx:      ctx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
}

// Handle 注册指定 path 的 handler，重复注册会覆盖旧值。
// path 通常以 '/' 开头或采用 'a.b.c' 形式，由业务自行约定。
// handler 为 nil 等价于 Unhandle。
func (r *MessageRouter) Handle(path string, handler MessageHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if handler == nil {
		delete(r.handlers, path)
		return
	}
	r.handlers[path] = handler
}

// Unhandle 取消某个 path 的注册。
func (r *MessageRouter) Unhandle(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.handlers, path)
}

// SetFallback 设置缺省 handler：当 Message.Path 在 handlers 中没有匹配时调用。
// 传 nil 表示无 fallback：未匹配的消息直接丢弃。
func (r *MessageRouter) SetFallback(handler MessageHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallback = handler
}

// Start 启动 router 的内部派发 goroutine。
// 多次调用安全：第二次调用直接返回，不会启动多个 goroutine。
// 业务通常的写法是： go router.Start()
func (r *MessageRouter) Start() {
	r.mu.Lock()
	if r.ctx.Err() != nil {
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	go r.dispatchLoop()
}

// dispatchLoop 持续 Receive → 按 Path 派发，直到 ctx 取消或 conn 断开。
func (r *MessageRouter) dispatchLoop() {
	defer close(r.done)
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}
		msg, err := r.conn.Receive(r.ctx)
		if err != nil {
			// ctx 取消 / 连接断开 / 解码失败 都到这里。
			// 不在这里区分原因，统一让 router 退出，由上层观察 conn 状态决定下一步。
			return
		}
		if msg == nil {
			continue
		}

		r.mu.RLock()
		h := r.handlers[msg.Path]
		if h == nil {
			h = r.fallback
		}
		r.mu.RUnlock()
		if h == nil {
			continue // 既无 path 匹配也无 fallback —— 丢弃
		}
		h(r.ctx, r.conn, msg)
	}
}

// Close 停止 router 的派发 goroutine，并等待其退出。
// 不关闭底层 Connection——是否关闭由调用方决定，因为 Connection 可能被多个 router/业务共享。
// 多次调用安全。
func (r *MessageRouter) Close() error {
	r.doneOnce.Do(func() {
		r.cancel()
	})
	<-r.done
	return nil
}

// Done 返回 router 派发循环退出后会被关闭的 channel，供外部观察 router 生命周期。
func (r *MessageRouter) Done() <-chan struct{} { return r.done }

// ErrRouterClosed 在派发循环结束后调用 Send 之类的语法糖时返回。当前 Router 未提供 Send，
// 保留以备未来扩展。
var ErrRouterClosed = errors.New("p2pnode: message router closed")
