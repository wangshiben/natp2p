package DHTable

import (
	"bnfs_p2p/interfaces"
	"math/big"
	"sync"
	"time"
)

// StoreNode 实现 Buket 接口
type StoreNode struct {
	mu      sync.RWMutex
	nodes   []interfaces.Node
	health  map[string]interfaces.NodeHealth
	maxSize int
	cache   interfaces.ReplacementCache
}

func NewStoreNode(maxSize int) *StoreNode {
	return &StoreNode{
		nodes:   make([]interfaces.Node, 0, maxSize),
		health:  make(map[string]interfaces.NodeHealth),
		maxSize: maxSize,
		cache:   NewDefaultReplacementCache(maxSize),
	}
}

func (s *StoreNode) AddNode(node interfaces.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()

	// 检查是否已存在
	for i, n := range s.nodes {
		if n.PeerID() == node.PeerID() {
			// 更新节点并移到队尾
			s.nodes = append(s.nodes[:i], s.nodes[i+1:]...)
			s.nodes = append(s.nodes, node)
			health := s.health[node.PeerID()]
			health.LastSuccess = now
			if health.ContinuousHealthySince.IsZero() {
				health.ContinuousHealthySince = now
			}
			health.ConsecutiveFailures = 0
			health.Suspect = false
			s.health[node.PeerID()] = health
			return
		}
	}

	// 桶未满，直接添加
	if len(s.nodes) < s.maxSize {
		s.nodes = append(s.nodes, node)
		s.health[node.PeerID()] = defaultNodeHealth(now)
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
			delete(s.health, nodeId)
			// 尝试从替换缓存补充
			if newNode, ok := s.cache.Pop(); ok {
				s.nodes = append(s.nodes, newNode)
				s.health[newNode.PeerID()] = defaultNodeHealth(time.Now())
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
	s.Touch(nodeId, time.Now())
}

func (s *StoreNode) Touch(nodeId string, at time.Time) bool {
	if at.IsZero() {
		at = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, n := range s.nodes {
		if n.PeerID() == nodeId {
			// 更新最后活跃时间
			n.UpdateLastSeen()
			// 将节点移动到队尾（最新活跃位置）
			s.nodes = append(s.nodes[:i], s.nodes[i+1:]...)
			s.nodes = append(s.nodes, n)
			health := s.health[nodeId]
			health.LastSuccess = at
			if health.ContinuousHealthySince.IsZero() {
				health.ContinuousHealthySince = at
			}
			health.ConsecutiveFailures = 0
			health.Suspect = false
			s.health[nodeId] = health
			return true
		}
	}
	return false
}

func (s *StoreNode) SetNodeHealth(nodeId string, health interfaces.NodeHealth) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.health[nodeId]; !ok {
		return false
	}
	current := s.health[nodeId]
	if health.LastSuccess.IsZero() {
		health.LastSuccess = current.LastSuccess
	}
	if health.ContinuousHealthySince.IsZero() {
		health.ContinuousHealthySince = current.ContinuousHealthySince
	}
	s.health[nodeId] = health
	return true
}

func (s *StoreNode) NodeHealth(nodeId string) (interfaces.NodeHealth, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	health, ok := s.health[nodeId]
	return health, ok
}

func (s *StoreNode) RankedNodes(policy interfaces.NodeRankingPolicy) []interfaces.Node {
	s.mu.RLock()
	nodes := append([]interfaces.Node(nil), s.nodes...)
	health := make(map[string]interfaces.NodeHealth, len(s.health))
	for nodeID, entry := range s.health {
		health[nodeID] = entry
	}
	s.mu.RUnlock()
	return rankNodeSnapshot(nodes, health, policy)
}

func (s *StoreNode) Maintain(policy interfaces.DHTMaintenancePolicy) interfaces.MaintenanceResult {
	if policy.Now.IsZero() {
		policy.Now = time.Now()
	}
	if policy.StaleAfter <= 0 {
		policy.StaleAfter = 2 * time.Minute
	}
	if policy.RemoveAfterFailures == 0 {
		policy.RemoveAfterFailures = 2
	}
	if policy.Probe == nil {
		return interfaces.MaintenanceResult{}
	}

	s.mu.RLock()
	if len(s.nodes) == 0 {
		s.mu.RUnlock()
		return interfaces.MaintenanceResult{}
	}
	head := s.nodes[0]
	health := s.health[head.PeerID()]
	s.mu.RUnlock()
	if !health.LastSuccess.IsZero() && policy.Now.Sub(health.LastSuccess) < policy.StaleAfter {
		return interfaces.MaintenanceResult{}
	}

	succeeded := policy.Probe(head)
	s.mu.Lock()
	index := -1
	for i, node := range s.nodes {
		if node.PeerID() == head.PeerID() {
			index = i
			break
		}
	}
	if index < 0 || s.health[head.PeerID()].LastSuccess != health.LastSuccess {
		s.mu.Unlock()
		return interfaces.MaintenanceResult{}
	}
	if succeeded {
		head.UpdateLastSeen()
		health.LastSuccess = policy.Now
		if health.ContinuousHealthySince.IsZero() {
			health.ContinuousHealthySince = policy.Now
		}
		health.ConsecutiveFailures = 0
		health.Suspect = false
		s.health[head.PeerID()] = health
		s.nodes = append(s.nodes[:index], s.nodes[index+1:]...)
		s.nodes = append(s.nodes, head)
		s.mu.Unlock()
		return interfaces.MaintenanceResult{NodeID: head.PeerID(), Action: interfaces.MaintenanceTouched}
	}

	health.ConsecutiveFailures++
	health.Suspect = true
	s.health[head.PeerID()] = health
	result := interfaces.MaintenanceResult{NodeID: head.PeerID(), Failures: health.ConsecutiveFailures, Action: interfaces.MaintenanceSuspect}
	if health.ConsecutiveFailures < policy.RemoveAfterFailures {
		s.mu.Unlock()
		return result
	}
	s.nodes = append(s.nodes[:index], s.nodes[index+1:]...)
	delete(s.health, head.PeerID())
	s.mu.Unlock()
	result.Action = interfaces.MaintenanceRemoved

	for {
		candidate, ok := s.cache.Pop()
		if !ok {
			break
		}
		if !policy.Probe(candidate) {
			continue
		}
		s.mu.Lock()
		if len(s.nodes) < s.maxSize {
			s.nodes = append(s.nodes, candidate)
			s.health[candidate.PeerID()] = defaultNodeHealth(policy.Now)
			result.ReplacementNodeID = candidate.PeerID()
			s.mu.Unlock()
			break
		}
		s.mu.Unlock()
		s.cache.Push(candidate)
		break
	}
	return result
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

func (s *StoreNode) snapshot() ([]interfaces.Node, map[string]interfaces.NodeHealth) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nodes := append([]interfaces.Node(nil), s.nodes...)
	health := make(map[string]interfaces.NodeHealth, len(s.health))
	for nodeID, entry := range s.health {
		health[nodeID] = entry
	}
	return nodes, health
}
