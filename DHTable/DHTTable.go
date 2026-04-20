package DHTable

import (
	"bnfs_p2p/interfaces"
	"math/big"
	"sort"
	"sync"
)

// KBucketImpl K 桶实现，包含距离范围信息
type KBucketImpl struct {
	mu      sync.RWMutex
	bucket  *StoreNode
	sl      *big.Int // 理论最近距离
	el      *big.Int // 理论最远距离
	sr      *big.Int // 实际最短距离
	er      *big.Int // 实际最长距离
	localId *big.Int // 本地节点 ID（用于计算距离）
}

// NewKBucket 创建新的 K 桶
func NewKBucket(maxSize int, localId *big.Int, sl, el *big.Int) *KBucketImpl {
	return &KBucketImpl{
		bucket:  NewStoreNode(maxSize),
		localId: localId,
		sl:      sl,
		el:      el,
		sr:      nil,
		er:      nil,
	}
}

func (k *KBucketImpl) SL() *big.Int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.sl
}

func (k *KBucketImpl) EL() *big.Int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.el
}

func (k *KBucketImpl) SR() *big.Int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.sr
}

func (k *KBucketImpl) ER() *big.Int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.er
}

func (k *KBucketImpl) SetRange(sl, el, sr, er *big.Int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sl = sl
	k.el = el
	k.sr = sr
	k.er = er
}

func (k *KBucketImpl) AddNode(node interfaces.Node) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.bucket.AddNode(node)
	k.updateActualRange()
}

func (k *KBucketImpl) Remove(nodeId string) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.bucket.Remove(nodeId)
	k.updateActualRange()
}

func (k *KBucketImpl) Current() int {
	return k.bucket.Current()
}

func (k *KBucketImpl) MaxSize() int {
	return k.bucket.MaxSize()
}

func (k *KBucketImpl) Tail() interfaces.Node {
	return k.bucket.Tail()
}

func (k *KBucketImpl) Head() interfaces.Node {
	return k.bucket.Head()
}

func (k *KBucketImpl) UpdateLastSeen(nodeId string) {
	k.bucket.UpdateLastSeen(nodeId)
}

// updateActualRange 更新实际距离范围
func (k *KBucketImpl) updateActualRange() {
	nodes := k.bucket.nodes
	if len(nodes) == 0 {
		k.sr = nil
		k.er = nil
		return
	}

	minDist := new(big.Int).SetUint64(^uint64(0))
	minDist.Lsh(minDist, 160) // 设置为最大值
	maxDist := new(big.Int)

	for _, node := range nodes {
		nodeId, _ := new(big.Int).SetString(node.PeerID(), 16)
		dist := new(big.Int).Xor(k.localId, nodeId)

		if dist.Cmp(minDist) < 0 {
			minDist.Set(dist)
		}
		if dist.Cmp(maxDist) > 0 {
			maxDist.Set(dist)
		}
	}

	k.sr = minDist
	k.er = maxDist
}

// ContainsNode 检查节点是否在当前桶的距离范围内
func (k *KBucketImpl) ContainsNode(nodeId string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()

	nodeIdInt, ok := new(big.Int).SetString(nodeId, 16)
	if !ok {
		return false
	}

	dist := new(big.Int).Xor(k.localId, nodeIdInt)

	// 检查是否在理论距离范围内
	if dist.Cmp(k.sl) < 0 || dist.Cmp(k.el) > 0 {
		return false
	}

	return true
}

// IsFull 检查桶是否已满
func (k *KBucketImpl) IsFull() bool {
	return k.bucket.Current() >= k.bucket.MaxSize()
}

// GetNodes 获取桶中所有节点
func (k *KBucketImpl) GetNodes() []interfaces.Node {
	k.mu.RLock()
	defer k.mu.RUnlock()

	result := make([]interfaces.Node, len(k.bucket.nodes))
	copy(result, k.bucket.nodes)
	return result
}

// DHTTableImpl DHT 路由表实现
type DHTTableImpl struct {
	mu      sync.RWMutex
	buckets []*KBucketImpl
	localId *big.Int
	maxSize int
	maxBits int // ID 位数，默认 160
}

// NewDHTTable 创建新的 DHT 路由表
func NewDHTTable(localNodeId string, maxSize int) (*DHTTableImpl, error) {
	localId, ok := new(big.Int).SetString(localNodeId, 16)
	if !ok {
		return nil, ErrInvalidNodeId
	}

	// 初始只有一个桶，覆盖整个 ID 空间（256 位）
	sl := big.NewInt(0)
	el := new(big.Int).Lsh(big.NewInt(1), 256)
	el.Sub(el, big.NewInt(1)) // 2^256 - 1

	table := &DHTTableImpl{
		buckets: make([]*KBucketImpl, 0),
		localId: localId,
		maxSize: maxSize,
		maxBits: 256,
	}

	// 添加初始桶
	initialBucket := NewKBucket(maxSize, localId, sl, el)
	table.buckets = append(table.buckets, initialBucket)

	return table, nil
}

func (d *DHTTableImpl) AddNode(node interfaces.Node) {
	d.mu.Lock()
	defer d.mu.Unlock()

	nodeId, ok := new(big.Int).SetString(node.PeerID(), 16)
	if !ok {
		return
	}

	// 找到合适的桶
	bucketIdx := d.findBucketIndex(nodeId)
	if bucketIdx == -1 {
		return
	}

	bucket := d.buckets[bucketIdx]
	bucket.AddNode(node)

	// 检查是否需要分裂
	if bucket.IsFull() {
		d.splitBucket(bucketIdx)
	}
}

func (d *DHTTableImpl) Remove(nodeId string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bucketIdx := d.findBucketIndexById(nodeId)
	if bucketIdx == -1 {
		return
	}

	d.buckets[bucketIdx].Remove(nodeId)
}

func (d *DHTTableImpl) FindClosest(targetId string, count int) []interfaces.Node {
	d.mu.RLock()
	defer d.mu.RUnlock()

	targetIdInt, ok := new(big.Int).SetString(targetId, 16)
	if !ok {
		return nil
	}

	// 收集所有节点并计算距离
	type nodeDist struct {
		node interfaces.Node
		dist *big.Int
	}

	var allNodes []nodeDist
	for _, bucket := range d.buckets {
		for _, node := range bucket.GetNodes() {
			nodeId, _ := new(big.Int).SetString(node.PeerID(), 16)
			dist := new(big.Int).Xor(targetIdInt, nodeId)
			allNodes = append(allNodes, nodeDist{node: node, dist: dist})
		}
	}

	// 按距离排序
	sort.Slice(allNodes, func(i, j int) bool {
		return allNodes[i].dist.Cmp(allNodes[j].dist) < 0
	})

	// 返回最接近的 count 个节点
	result := make([]interfaces.Node, 0, count)
	for i := 0; i < len(allNodes) && i < count; i++ {
		result = append(result, allNodes[i].node)
	}

	return result
}
func (d *DHTTableImpl) GetBuketHead() []interfaces.Node {
	d.mu.RLock()
	defer d.mu.RUnlock()
	nodes := make([]interfaces.Node, len(d.buckets))
	for i, bucket := range d.buckets {
		nodes[i] = bucket.bucket.Head()
	}
	return nodes
}

func (d *DHTTableImpl) GetBuckets() []interfaces.KBucket {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]interfaces.KBucket, len(d.buckets))
	for i, bucket := range d.buckets {
		result[i] = bucket
	}
	return result
}

func (d *DHTTableImpl) BucketCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.buckets)
}

func (d *DHTTableImpl) LocalNodeId() string {
	return d.localId.Text(16)
}

func (d *DHTTableImpl) UpdateLastSeen(nodeId string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	bucketIdx := d.findBucketIndexById(nodeId)
	if bucketIdx == -1 {
		return
	}

	d.buckets[bucketIdx].UpdateLastSeen(nodeId)
}

// Clear �空路由表
func (d *DHTTableImpl) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 重置为初始状态
	sl := big.NewInt(0)
	el := new(big.Int).Lsh(big.NewInt(1), 256)
	el.Sub(el, big.NewInt(1))

	d.buckets = make([]*KBucketImpl, 0)
	initialBucket := NewKBucket(d.maxSize, d.localId, sl, el)
	d.buckets = append(d.buckets, initialBucket)
}

// findBucketIndex 根据节点 ID 找到对应的桶索引
func (d *DHTTableImpl) findBucketIndex(nodeId *big.Int) int {
	for i, bucket := range d.buckets {
		if bucket.ContainsNode(nodeId.Text(16)) {
			return i
		}
	}
	return -1
}

// findBucketIndexById 根据节点 ID 字符串找到对应的桶索引
func (d *DHTTableImpl) findBucketIndexById(nodeId string) int {
	for i, bucket := range d.buckets {
		if bucket.ContainsNode(nodeId) {
			return i
		}
	}
	return -1
}

// splitBucket 分裂指定索引的桶
func (d *DHTTableImpl) splitBucket(bucketIdx int) {
	oldBucket := d.buckets[bucketIdx]

	// 计算新的距离范围（按 XOR 距离分裂）
	// 找到当前桶距离范围的中间点
	midPoint := new(big.Int).Add(oldBucket.sl, oldBucket.el)
	midPoint.Rsh(midPoint, 1)

	// 创建两个新桶
	newBucket1 := NewKBucket(d.maxSize, d.localId, oldBucket.sl, midPoint)
	newBucket2 := NewKBucket(d.maxSize, d.localId, new(big.Int).Add(midPoint, big.NewInt(1)), oldBucket.el)

	// 获取旧桶的节点（不直接清空，避免并发期间新节点加入旧桶）
	oldBucket.mu.Lock()
	nodes := make([]interfaces.Node, len(oldBucket.bucket.nodes))
	copy(nodes, oldBucket.bucket.nodes)
	oldBucket.mu.Unlock()

	// 使用 map 跟踪已分配的节点，确保不重复
	assignedNodes := make(map[string]bool)

	// 分配节点到两个新桶（基于 XOR 距离）
	for _, node := range nodes {
		nodeId, ok := new(big.Int).SetString(node.PeerID(), 16)
		if !ok {
			continue
		}

		// 避免重复分配
		if assignedNodes[node.PeerID()] {
			continue
		}

		// 计算节点与本地节点的 XOR 距离
		dist := new(big.Int).Xor(d.localId, nodeId)

		// 根据 XOR 距离分配到对应的桶
		if dist.Cmp(midPoint) <= 0 {
			// 直接添加到新桶的内部节点列表，避免触发距离范围更新和递归分裂
			newBucket1.bucket.mu.Lock()
			newBucket1.bucket.nodes = append(newBucket1.bucket.nodes, node)
			newBucket1.bucket.mu.Unlock()
			assignedNodes[node.PeerID()] = true
		} else {
			// 直接添加到新桶的内部节点列表，避免触发距离范围更新和递归分裂
			newBucket2.bucket.mu.Lock()
			newBucket2.bucket.nodes = append(newBucket2.bucket.nodes, node)
			newBucket2.bucket.mu.Unlock()
			assignedNodes[node.PeerID()] = true
		}
	}

	// 更新新桶的实际距离范围
	newBucket1.updateActualRange()
	newBucket2.updateActualRange()

	// 替换旧桶为两个新桶
	d.buckets = append(d.buckets[:bucketIdx], append([]*KBucketImpl{newBucket1, newBucket2}, d.buckets[bucketIdx+1:]...)...)
}

// ErrInvalidNodeId 无效节点 ID 错误
var ErrInvalidNodeId = &nodeError{"invalid node ID"}

type nodeError struct {
	msg string
}

func (e *nodeError) Error() string {
	return e.msg
}
