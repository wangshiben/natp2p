package router

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"bnfs_p2p/p2pnode"
)

// Handler 是路由处理函数签名。
// ctx 已注入路径参数（通过 ParamsFromContext 获取）。
// msg 是接收到的完整消息。
// conn 是多路复用的逻辑连接，提供 Reply/SendTo 等便捷方法。
type Handler func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection)

// routeTree 是前缀树路由表，支持静态路径、参数（:id）和通配符（*path）。
type routeTree struct {
	root *routeNode
}

// routeNode 是前缀树的一个节点。
type routeNode struct {
	pattern       string                // 当前段模式："user" / ":id" / "*path"
	isParam       bool                  // 是否参数节点（:id）
	isWildcard    bool                  // 是否通配符（*path）
	handler       Handler               // 叶子节点的处理器
	children      map[string]*routeNode // 静态子节点
	paramChild    *routeNode            // 参数子节点（只能有一个）
	wildcardChild *routeNode            // 通配符子节点（只能有一个）
}

// newRouteTree 创建一个空路由树。
func newRouteTree() *routeTree {
	return &routeTree{
		root: &routeNode{
			children: make(map[string]*routeNode),
		},
	}
}

// insert 注册一条路由规则到前缀树。
// pattern 形如 "/user/:id/profile" 或 "/files/*path"。
// 通配符 * 必须是最后一段，且只能有一个。
func (t *routeTree) insert(pattern string, handler Handler) error {
	if handler == nil {
		return errors.New("handler 不能为 nil")
	}

	segments := splitPath(pattern)
	node := t.root

	// 特殊处理：根路由 "/"
	if len(segments) == 0 {
		if node.handler != nil {
			return fmt.Errorf("路由重复注册: %s", pattern)
		}
		node.handler = handler
		return nil
	}
	for i, seg := range segments {
		if seg == "" {
			continue
		}

		if strings.HasPrefix(seg, "*") {
			// 通配符必须是最后一段
			if i != len(segments)-1 {
				return fmt.Errorf("通配符 %s 必须是路径最后一段", seg)
			}
			if node.wildcardChild != nil {
				return fmt.Errorf("通配符冲突: 已存在 %s", node.wildcardChild.pattern)
			}
			node.wildcardChild = &routeNode{
				pattern:    seg,
				isWildcard: true,
				handler:    handler,
			}
			return nil
		} else if strings.HasPrefix(seg, ":") {
			// 参数节点
			if node.paramChild == nil {
				node.paramChild = &routeNode{
					pattern:  seg,
					isParam:  true,
					children: make(map[string]*routeNode),
				}
			} else if node.paramChild.pattern != seg {
				// 不允许同一层有多个不同名参数（如 /:id 和 /:name）
				return fmt.Errorf("参数节点冲突: 已存在 %s, 尝试注册 %s", node.paramChild.pattern, seg)
			}
			node = node.paramChild
		} else {
			// 静态节点
			if node.children[seg] == nil {
				node.children[seg] = &routeNode{
					pattern:  seg,
					children: make(map[string]*routeNode),
				}
			}
			node = node.children[seg]
		}
	}

	if node.handler != nil {
		return fmt.Errorf("路由重复注册: %s", pattern)
	}
	node.handler = handler
	return nil
}

// search 查找路径对应的 handler 和参数。
// 优先级：静态 > 参数 > 通配符。
// 返回 (handler, params)，未匹配时 handler 为 nil。
func (t *routeTree) search(path string) (Handler, map[string]string) {
	segments := splitPath(path)
	params := make(map[string]string)
	handler := t.searchNode(t.root, segments, 0, params)
	if handler == nil {
		return nil, nil
	}
	return handler, params
}

// searchNode 递归搜索节点。
func (t *routeTree) searchNode(node *routeNode, segments []string, index int, params map[string]string) Handler {
	// 已到达路径末尾
	if index == len(segments) {
		return node.handler
	}

	seg := segments[index]

	// 优先匹配静态节点
	if child, ok := node.children[seg]; ok {
		if h := t.searchNode(child, segments, index+1, params); h != nil {
			return h
		}
	}

	// 其次匹配参数节点
	if node.paramChild != nil {
		paramName := strings.TrimPrefix(node.paramChild.pattern, ":")
		params[paramName] = seg
		if h := t.searchNode(node.paramChild, segments, index+1, params); h != nil {
			return h
		}
		// 回溯：如果参数匹配失败，清除参数
		delete(params, paramName)
	}

	// 最后匹配通配符
	if node.wildcardChild != nil {
		wildcardName := strings.TrimPrefix(node.wildcardChild.pattern, "*")
		// 通配符捕获剩余所有路径
		params[wildcardName] = strings.Join(segments[index:], "/")
		return node.wildcardChild.handler
	}

	return nil
}

// splitPath 将路径拆分为段，过滤空段。
// 例如："/user//profile/" -> ["user", "profile"]。
func splitPath(path string) []string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
