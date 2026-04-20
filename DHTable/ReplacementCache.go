package DHTable

import (
	"bnfs_p2p/interfaces"
	"sync"
)

// DefaultReplacementCache 默认替换缓存实现
type DefaultReplacementCache struct {
	mu      sync.RWMutex
	cache   []interfaces.Node
	maxSize int
}

// NewDefaultReplacementCache 创建替换缓存
func NewDefaultReplacementCache(maxSize int) interfaces.ReplacementCache {
	return &DefaultReplacementCache{
		cache:   make([]interfaces.Node, 0, maxSize),
		maxSize: maxSize,
	}
}

// Push 尝试将新节点加入缓存
func (c *DefaultReplacementCache) Push(peer interfaces.Node) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 检查是否已存在
	for i, node := range c.cache {
		if node.PeerID() == peer.PeerID() {
			// 更新并移到队尾
			c.cache = append(c.cache[:i], c.cache[i+1:]...)
			c.cache = append(c.cache, peer)
			return true
		}
	}

	// 缓存已满，丢弃新节点
	if len(c.cache) >= c.maxSize {
		return false
	}

	// 加入缓存
	c.cache = append(c.cache, peer)
	return true
}

// Pop 移除并返回队列头部节点
func (c *DefaultReplacementCache) Pop() (interfaces.Node, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.cache) == 0 {
		return nil, false
	}

	node := c.cache[0]
	c.cache = c.cache[1:]
	return node, true
}

// Peek 查看队列头部节点但不移除
func (c *DefaultReplacementCache) Peek() (interfaces.Node, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.cache) == 0 {
		return nil, false
	}

	return c.cache[0], true
}

// Remove 显式移除某个特定 ID 的节点
func (c *DefaultReplacementCache) Remove(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, node := range c.cache {
		if node.PeerID() == id {
			c.cache = append(c.cache[:i], c.cache[i+1:]...)
			return true
		}
	}

	return false
}

// Size 返回当前缓存中的节点数量
func (c *DefaultReplacementCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// Clear 清空整个缓存
func (c *DefaultReplacementCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make([]interfaces.Node, 0, c.maxSize)
}
