# P2P Router 使用指南

## 概述

`p2pnode/router` 包提供类似 gin 的路由层，支持在 P2P 连接上按消息 Path 分发到不同的 handler。

## 特性

- ✅ 前缀树路由，支持静态路径 `/user/profile`
- ✅ 参数提取 `/user/:id` 匹配 `/user/123` 得 `{"id":"123"}`
- ✅ 通配符 `/files/*path` 捕获剩余路径
- ✅ 优先级：静态 > 参数 > 通配符
- ✅ 多路复用：一个物理 Connection 按 Path 逻辑拆分
- ✅ 便捷 API：`Reply()` / `SendTo()` 自动填充 Code=200
- ✅ 404 fallback 处理未匹配路由

## 快速开始

### 1. 创建 Router 并注册路由

```go
package main

import (
    "context"
    "fmt"
    
    "bnfs_p2p/p2pnode"
    "bnfs_p2p/p2pnode/router"
)

func main() {
    r := router.New()
    
    // 静态路由
    r.Handle("/chat/text", func(ctx context.Context, msg *p2pnode.Message, conn router.RouterConnection) {
        fmt.Printf("收到聊天消息: %s\n", string(msg.Payload))
        conn.Reply(ctx, []byte("消息已收到"))
    })
    
    // 参数路由
    r.Handle("/user/:id/profile", func(ctx context.Context, msg *p2pnode.Message, conn router.RouterConnection) {
        params := conn.Params(ctx)
        userID := params["id"]
        fmt.Printf("查询用户: %s\n", userID)
        conn.Reply(ctx, []byte(fmt.Sprintf("用户 %s 的资料", userID)))
    })
    
    // 通配符路由
    r.Handle("/files/*path", func(ctx context.Context, msg *p2pnode.Message, conn router.RouterConnection) {
        params := conn.Params(ctx)
        filePath := params["path"]
        fmt.Printf("请求文件: %s\n", filePath)
        // 处理文件请求...
    })
    
    // 404 处理
    r.NotFound(func(ctx context.Context, msg *p2pnode.Message, conn router.RouterConnection) {
        fmt.Printf("路径不存在: %s\n", msg.Path)
        conn.Send(ctx, &p2pnode.Message{
            Type:    p2pnode.MsgAppData,
            Path:    msg.Path,
            Code:    404,
            Payload: []byte("路径不存在"),
        })
    })
}
```

### 2. 集成到 NAT 节点

```go
func runNode(relayAddr string) {
    node, _ := natnode.NewNATNode(nil, relayAddr)
    ctx := context.Background()
    
    // 创建路由器
    r := router.New()
    r.Handle("/chat", handleChat)
    r.Handle("/file/:name", handleFile)
    
    // 在 OnConnection 回调中接管连接
    node.OnConnection(func(conn p2pnode.Connection) {
        go r.ServeConnection(ctx, conn)
    })
    
    // 启动节点
    go node.Listen(ctx, relayAddr)
    
    // ... 业务逻辑
}

func handleChat(ctx context.Context, msg *p2pnode.Message, conn router.RouterConnection) {
    fmt.Printf("收到消息: %s\n", string(msg.Payload))
    conn.Reply(ctx, []byte("已读"))
}

func handleFile(ctx context.Context, msg *p2pnode.Message, conn router.RouterConnection) {
    params := conn.Params(ctx)
    fileName := params["name"]
    fmt.Printf("请求文件: %s\n", fileName)
    // 读取并发送文件...
}
```

## API 参考

### Router

#### `func New() *Router`
创建一个新的路由器。

#### `func (r *Router) Handle(pattern string, handler Handler) error`
注册路由规则。pattern 支持：
- 静态路径：`/user/profile`
- 参数：`/user/:id`（`:id` 可以是任意名称）
- 通配符：`/files/*path`（必须是最后一段）

返回错误情况：
- 路由重复注册
- 参数节点冲突（如 `/:id` 和 `/:name` 同时注册）
- 通配符不在末尾

#### `func (r *Router) NotFound(handler Handler)`
注册 404 fallback handler，处理未匹配的路由。

#### `func (r *Router) ServeConnection(ctx context.Context, conn p2pnode.Connection) error`
接管连接的 Receive 循环，根据 msg.Path 分发到对应 handler。
阻塞直到 ctx 取消或连接断开。

#### `func (r *Router) ServeConnectionBackground(ctx context.Context, conn p2pnode.Connection) <-chan error`
在后台 goroutine 中运行 ServeConnection，返回 done channel。

### RouterConnection

RouterConnection 是多路复用的逻辑连接，继承 `p2pnode.Connection` 的所有方法，并新增：

#### `func Reply(ctx context.Context, payload []byte) error`
用当前匹配的 Path 发送响应消息，自动填充 Code=200。

#### `func SendTo(ctx context.Context, path string, payload []byte) error`
发送消息到指定 Path（跨 Path 通信），Code=200。

#### `func Params(ctx context.Context) map[string]string`
返回路径参数。例如 `/user/:id` 匹配 `/user/123` 返回 `{"id":"123"}`。

#### `func MatchedPath() string`
返回当前匹配的路由模式（如 `/user/:id`）。

### Handler 签名

```go
type Handler func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection)
```

- `ctx`：已注入路径参数（通过 `conn.Params(ctx)` 获取）
- `msg`：接收到的完整消息（包含 Type / Path / Code / Payload 等）
- `conn`：多路复用的逻辑连接

## 高级用法

### 跨 Path 通信

```go
r.Handle("/trigger", func(ctx context.Context, msg *p2pnode.Message, conn router.RouterConnection) {
    // 处理触发逻辑...
    
    // 发送通知到另一个 Path
    conn.SendTo(ctx, "/notify", []byte("任务已触发"))
})
```

### 提取多个参数

```go
r.Handle("/user/:uid/post/:pid", func(ctx context.Context, msg *p2pnode.Message, conn router.RouterConnection) {
    params := conn.Params(ctx)
    userID := params["uid"]    // "123"
    postID := params["pid"]    // "456"
    // ...
})
```

### 通配符捕获

```go
r.Handle("/files/*path", func(ctx context.Context, msg *p2pnode.Message, conn router.RouterConnection) {
    params := conn.Params(ctx)
    filePath := params["path"]  // "a/b/c.txt" (匹配 /files/a/b/c.txt)
    // ...
})
```

### 自定义错误响应

```go
r.NotFound(func(ctx context.Context, msg *p2pnode.Message, conn router.RouterConnection) {
    errResp := &p2pnode.Message{
        Type:    p2pnode.MsgAppData,
        Path:    msg.Path,
        Code:    404,
        Payload: []byte(fmt.Sprintf("路由 %s 不存在", msg.Path)),
    }
    conn.Send(ctx, errResp)
})
```

## Code 字段说明

`p2pnode.Message` 新增了 `Code int` 字段，语义参考 HTTP 状态码：

- `0`：默认值，表示「不关心状态」或「框架层消息」（DHT 控制消息）
- `200`：成功（router 层 Reply/SendTo 自动填充）
- `404`：未找到
- `500`：服务端错误
- 其他：参考 HTTP 状态码

旧代码不设置 Code 时默认为 0，保持向后兼容。

## 注意事项

### 1. 路由优先级

匹配顺序：**静态 > 参数 > 通配符**

```go
r.Handle("/user/admin", handler1)  // 静态
r.Handle("/user/:id", handler2)    // 参数

// 访问 /user/admin 匹配 handler1（静态优先）
// 访问 /user/123   匹配 handler2（参数匹配）
```

### 2. 参数冲突

同一层级不允许多个不同名参数：

```go
r.Handle("/user/:id", handler1)
r.Handle("/user/:name", handler2)  // 错误：参数节点冲突
```

### 3. 通配符限制

通配符必须是路径最后一段：

```go
r.Handle("/files/*path", handler)       // 正确
r.Handle("/files/*path/extra", handler) // 错误：通配符必须在末尾
```

### 4. 并发安全

- `Router.Handle()` 和 `NotFound()` 在运行时修改路由表是安全的（加锁保护）
- 每个消息在独立 goroutine 中处理，handler 内部需自行处理并发
- `RouterConnection` 共享底层物理连接，`Send` 已线程安全

### 5. Close 行为

`RouterConnection.Close()` 会关闭底层物理连接，影响所有路由。
通常不应在 handler 内调用 `Close()`，除非明确要断开整个连接。

## 性能考虑

- 前缀树查找复杂度 O(k)，k 为路径段数，通常 < 10
- 每个消息独立 goroutine 处理，避免阻塞后续消息
- 参数提取用 map 分配，热路径可优化为 slice
- 多路复用无额外开销，只是逻辑视图

## 完整示例

参见 `p2pnode/router/router_test.go` 中的集成测试。

## 许可证

与主项目相同。
