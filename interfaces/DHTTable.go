package interfaces

import (
	"math/big"
	"time"
)

// NodeHealth 是路由表条目自己的健康状态，不写回可被多张表共享的 Node 对象。
type NodeHealth struct {
	RTT                    time.Duration
	ContinuousHealthySince time.Time
	LastSuccess            time.Time
	ConsecutiveFailures    uint8
	Suspect                bool
}

// NodeRankingPolicy 控制只读网络质量视图。真实桶顺序仍保持 LRU。
type NodeRankingPolicy struct {
	Now          time.Time
	RTTBandMin   time.Duration
	RTTBandRatio float64
}

type MaintenanceAction uint8

const (
	MaintenanceNone MaintenanceAction = iota
	MaintenanceTouched
	MaintenanceSuspect
	MaintenanceRemoved
)

// DHTMaintenancePolicy 定义一次只检查桶头的陈旧节点维护。
type DHTMaintenancePolicy struct {
	Now                 time.Time
	StaleAfter          time.Duration
	RemoveAfterFailures uint8
	Probe               func(Node) bool
}

type MaintenanceResult struct {
	NodeID            string
	ReplacementNodeID string
	Failures          uint8
	Action            MaintenanceAction
}

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
	Touch(nodeId string, at time.Time) bool
	SetNodeHealth(nodeId string, health NodeHealth) bool
	NodeHealth(nodeId string) (NodeHealth, bool)
	RankedNodes(policy NodeRankingPolicy) []Node
	Maintain(policy DHTMaintenancePolicy) MaintenanceResult

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
	Touch(nodeId string, at time.Time) bool
	SetNodeHealth(nodeId string, health NodeHealth) bool
	NodeHealth(nodeId string) (NodeHealth, bool)
	RankedNodes(policy NodeRankingPolicy) []Node
	Maintain(policy DHTMaintenancePolicy) []MaintenanceResult

	// 清空路由表
	Clear()
}
