package router

import (
	"context"
	"sync"

	"bnfs_p2p/logx"
	"bnfs_p2p/p2pnode"
)

// Router 管理路由规则并分发消息到对应的 handler。
type Router struct {
	tree     *routeTree // 前缀树路由表
	fallback Handler    // 404 fallback handler
	mu       sync.RWMutex
}

// New 创建一个新的 Router。
func New() *Router {
	return &Router{
		tree: newRouteTree(),
	}
}

// Handle 注册一条路由规则。
// pattern 形如 "/user/:id" 或 "/files/*path"。
// handler 在匹配到此路由时被调用。
func (r *Router) Handle(pattern string, handler Handler) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tree.insert(pattern, handler)
}

// NotFound 注册 404 fallback handler，处理未匹配到任何路由的消息。
// 若不注册，未匹配的消息会被记录日志后丢弃。
func (r *Router) NotFound(handler Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallback = handler
}

// ServeConnection 接管物理连接的 Receive 循环，根据 msg.Path 分发到对应 handler。
// 阻塞直到 ctx 取消或连接断开。
// 每个消息在独立 goroutine 中处理，避免阻塞后续消息接收。
func (r *Router) ServeConnection(ctx context.Context, conn p2pnode.Connection) error {
	for {
		msg, err := conn.Receive(ctx)
		if err != nil {
			// 连接断开或 ctx 取消
			return err
		}

		// 查找路由
		r.mu.RLock()
		handler, params := r.tree.search(msg.Path)
		if handler == nil {
			handler = r.fallback
		}
		r.mu.RUnlock()

		if handler == nil {
			// 无匹配路由且无 fallback，记录日志后丢弃
			logx.Warnf("[router] 未匹配路由且无 fallback: path=%s from=%s", msg.Path, msg.Sender)
			continue
		}

		// 创建 RouterConnection（多路复用视图）
		rconn := newRouterConn(conn, msg.Path, params)

		// 异步调用 handler，避免阻塞 Receive 循环
		go func(ctx context.Context, msg *p2pnode.Message, rconn RouterConnection, params map[string]string) {
			// 注入参数到 context
			ctx = withParams(ctx, params)
			defer func() {
				if r := recover(); r != nil {
					logx.Errorf("[router] handler panic: path=%s error=%v", msg.Path, r)
				}
			}()
			handler(ctx, msg, rconn)
		}(ctx, msg, rconn, params)
	}
}

// ServeConnectionBackground 在后台 goroutine 中运行 ServeConnection。
// 返回一个 done channel，连接断开或出错时关闭。
// 便捷方法，等价于 go router.ServeConnection(ctx, conn)。
func (r *Router) ServeConnectionBackground(ctx context.Context, conn p2pnode.Connection) <-chan error {
	done := make(chan error, 1)
	go func() {
		err := r.ServeConnection(ctx, conn)
		done <- err
		close(done)
	}()
	return done
}
