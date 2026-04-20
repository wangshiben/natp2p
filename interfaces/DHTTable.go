package interfaces

import "math/big"

// KBucket K 桶接口，包含距离范围信息
type KBucket interface {
	// SL 理论最近距离（最短为 1）
	SL() *big.Int
	// EL 理论最远距离（最大为 2^160）
	EL() *big.Int
	// SR 实际最短距离（桶中节点的最小 XOR 距离）
	SR() *big.Int
	// ER 实际最长距离（桶中节点的最大 XOR 距离）
	ER() *big.Int

	// 设置距离范围
	SetRange(sl, el, sr, er *big.Int)

	// 桶相关操作
	AddNode(node Node)
	Remove(nodeId string)
	Current() int
	MaxSize() int
	Tail() Node
	Head() Node
	UpdateLastSeen(nodeId string)

	// 检查节点是否在当前桶的距离范围内
	ContainsNode(nodeId string) bool
}

// DHTTable DHT 路由表接口
type DHTTable interface {
	// 添加节点到路由表
	AddNode(node Node)

	// 移除节点
	Remove(nodeId string)

	// 获取最接近目标 ID 的节点（最多 count 个）
	FindClosest(targetId string, count int) []Node
	GetBuketHead() []Node // 获取当前桶的头节点，以便分发切片

	// 获取所有桶
	GetBuckets() []KBucket

	// 获取桶数量
	BucketCount() int

	// 获取本地节点 ID
	LocalNodeId() string

	// 更新节点最后活跃时间
	UpdateLastSeen(nodeId string)

	// 清空路由表
	Clear()
}
