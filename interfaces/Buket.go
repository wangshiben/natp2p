package interfaces

type Buket interface {
	AddNode(node Node) // 添加节点/更新节点
	MaxSize() int      // 当前最大节点数
	Current() int      // 桶中实际节点数

	Remove(NodeId string) // 删除节点,只有当AddNode()成功时才将内容推送至监听池去监听该节点是否离线
	Tail() Node           // 获取尾节点
	Head() Node           // 获取头节点
	UpdateLastSeen(NodeId string)
}

type ReplacementCache interface {
	// --- 写入操作 (Ingress) ---

	// Push 尝试将新节点加入缓存。
	// 如果节点已存在，更新其 LastSeen 时间并移到队尾 (表示它是最新的候选者)。
	// 如果缓存已满，且节点不存在，则返回 false (丢弃该节点)。
	// 如果成功加入或更新，返回 true。
	Push(peer Node) bool

	// --- 读取/消费操作 (Egress) ---

	// Pop 移除并返回队列头部的节点 (最老的候选者)。
	// 这通常发生在主列表有节点下线，需要填补空缺时。
	// 如果缓存为空，返回 nil, false。
	Pop() (Node, bool)

	// Peek 查看队列头部的节点但不移除。
	// 用于后台协程检查头部节点是否还活着 (Ping 检查)，避免弹出死节点。
	Peek() (Node, bool)

	// --- 维护操作 (Maintenance) ---

	// Remove 显式移除某个特定 ID 的节点。
	// 场景：当后台 Ping 发现缓存中的某个候补节点已经彻底失联时，主动将其剔除。
	// 返回 true 表示找到并移除，false 表示未找到。
	Remove(id string) bool // 移除节点 ,当

	// Size 返回当前缓存中的节点数量。
	// 用于监控或调试。
	Size() int

	// Clear 清空整个缓存。
	// 场景：本地节点重启或网络环境剧烈变化时重置状态。
	Clear()
}
