package DHTable

import (
	"bnfs_p2p/interfaces"
	"math/big"
	"sync"
)

// StoreNode 实现 Buket 接口
type StoreNode struct {
	mu      sync.RWMutex
	nodes   []interfaces.Node
	maxSize int
	cache   interfaces.ReplacementCache
}

func NewStoreNode(maxSize int) *StoreNode {
	return &StoreNode{
		nodes:   make([]interfaces.Node, 0, maxSize),
		maxSize: maxSize,
		cache:   NewDefaultReplacementCache(maxSize),
	}
}

func (s *StoreNode) AddNode(node interfaces.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 检查是否已存在
	for i, n := range s.nodes {
		if n.PeerID() == node.PeerID() {
			// 更新节点并移到队尾
			s.nodes = append(s.nodes[:i], s.nodes[i+1:]...)
			s.nodes = append(s.nodes, node)
			return
		}
	}

	// 桶未满，直接添加
	if len(s.nodes) < s.maxSize {
		s.nodes = append(s.nodes, node)
		return
	}

	// 桶已满，尝试推入替换缓存
	s.cache.Push(node)
}

func (s *StoreNode) MaxSize() int {
	return s.maxSize
}

func (s *StoreNode) Current() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nodes)
}

func (s *StoreNode) Remove(nodeId string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, n := range s.nodes {
		if n.PeerID() == nodeId {
			// 移除节点
			s.nodes = append(s.nodes[:i], s.nodes[i+1:]...)
			// 尝试从替换缓存补充
			if newNode, ok := s.cache.Pop(); ok {
				s.nodes = append(s.nodes, newNode)
			}
			return
		}
	}
}

func (s *StoreNode) Tail() interfaces.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.nodes) == 0 {
		return nil
	}
	return s.nodes[len(s.nodes)-1]
}

func (s *StoreNode) Head() interfaces.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.nodes) == 0 {
		return nil
	}
	return s.nodes[0]
}

func (s *StoreNode) UpdateLastSeen(nodeId string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, n := range s.nodes {
		if n.PeerID() == nodeId {
			// 更新最后活跃时间
			n.UpdateLastSeen()
			// 将节点移动到队尾（最新活跃位置）
			s.nodes = append(s.nodes[:i], s.nodes[i+1:]...)
			s.nodes = append(s.nodes, n)
			return
		}
	}
}

// CalculateXORDistance 计算两个节点 ID 的 XOR 距离
func (s *StoreNode) CalculateXORDistance(id1, id2 string) (*big.Int, error) {
	id1Int, ok := new(big.Int).SetString(id1, 16)
	if !ok {
		return nil, ErrInvalidNodeId
	}

	id2Int, ok := new(big.Int).SetString(id2, 16)
	if !ok {
		return nil, ErrInvalidNodeId
	}

	return new(big.Int).Xor(id1Int, id2Int), nil
}

// GetNodes 获取桶中所有节点（用于 DHT 表分裂时）
func (s *StoreNode) GetNodes() []interfaces.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]interfaces.Node, len(s.nodes))
	copy(result, s.nodes)
	return result
}
