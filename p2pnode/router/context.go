package router

import (
	"context"

	"bnfs_p2p/network"
	"bnfs_p2p/p2pnode"
)

// RouterConnection 是多路复用的逻辑连接，为单个路由 Path 提供隔离视图。
// 底层共享物理 Connection，但提供便捷的 Reply/SendTo API。
type RouterConnection interface {
	p2pnode.Connection // 继承原有接口

	// Reply 用当前匹配的 Path 发送响应消息（自动填充 Code=200）。
	Reply(ctx context.Context, payload []byte) error

	// SendTo 发送消息到指定 Path（跨 Path 通信），Code 默认 200。
	SendTo(ctx context.Context, path string, payload []byte) error

	// Params 返回当前路由匹配的路径参数（如 /user/:id 匹配 /user/123 得 {"id":"123"}）。
	// 优先从 context 读取（ServeConnection 已注入），若 context 无参数则返回创建时的 params。
	Params(ctx context.Context) map[string]string

	// MatchedPath 返回当前匹配的路由模式（如 /user/:id）。
	MatchedPath() string
}

// routerConn 实现 RouterConnection 接口。
type routerConn struct {
	raw         p2pnode.Connection // 底层物理连接
	matchedPath string             // 当前匹配的路由模式
	params      map[string]string  // 提取的参数
}

// newRouterConn 创建一个 RouterConnection。
func newRouterConn(raw p2pnode.Connection, matchedPath string, params map[string]string) RouterConnection {
	return &routerConn{
		raw:         raw,
		matchedPath: matchedPath,
		params:      params,
	}
}

// Peer 返回对端信息（委托给底层连接）。
func (rc *routerConn) Peer() p2pnode.PeerInfo {
	return rc.raw.Peer()
}

// Send 发送消息（委托给底层连接）。
func (rc *routerConn) Send(ctx context.Context, msg *p2pnode.Message) error {
	return rc.raw.Send(ctx, msg)
}

// Receive 接收消息（委托给底层连接）。
// 注意：ServeConnection 已接管 Receive 循环，handler 内通常不应再调用此方法。
func (rc *routerConn) Receive(ctx context.Context) (*p2pnode.Message, error) {
	return rc.raw.Receive(ctx)
}

// Raw 返回底层 network.Stream。
func (rc *routerConn) Raw() network.Stream {
	return rc.raw.Raw()
}

// Close 关闭底层连接（慎用：会影响所有路由）。
func (rc *routerConn) Close() error {
	return rc.raw.Close()
}

// Reply 用当前匹配的 Path 发送响应消息。
func (rc *routerConn) Reply(ctx context.Context, payload []byte) error {
	msg := &p2pnode.Message{
		Type:    p2pnode.MsgAppData,
		Path:    rc.matchedPath,
		Code:    200,
		Payload: payload,
	}
	return rc.raw.Send(ctx, msg)
}

// SendTo 发送消息到指定 Path（跨 Path 通信）。
func (rc *routerConn) SendTo(ctx context.Context, path string, payload []byte) error {
	msg := &p2pnode.Message{
		Type:    p2pnode.MsgAppData,
		Path:    path,
		Code:    200,
		Payload: payload,
	}
	return rc.raw.Send(ctx, msg)
}

// Params 返回路径参数。
// 优先从 context 读取（ServeConnection 注入的），若无则返回创建时的副本。
func (rc *routerConn) Params(ctx context.Context) map[string]string {
	if p := ParamsFromContext(ctx); p != nil {
		return p
	}
	// 回退到创建时的参数（防御性拷贝）
	result := make(map[string]string, len(rc.params))
	for k, v := range rc.params {
		result[k] = v
	}
	return result
}

// MatchedPath 返回当前匹配的路由模式。
func (rc *routerConn) MatchedPath() string {
	return rc.matchedPath
}

// --- Context 参数存储 ---

type contextKey string

const paramsKey contextKey = "router:params"

// withParams 将路径参数注入 context。
func withParams(ctx context.Context, params map[string]string) context.Context {
	return context.WithValue(ctx, paramsKey, params)
}

// ParamsFromContext 从 context 中提取路径参数。
// 返回 nil 表示 context 中无参数。
func ParamsFromContext(ctx context.Context) map[string]string {
	if p, ok := ctx.Value(paramsKey).(map[string]string); ok {
		return p
	}
	return nil
}
