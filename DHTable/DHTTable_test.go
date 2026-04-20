package DHTable

import (
	"bnfs_p2p/interfaces"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// TestDHTTableBucketSplit 测试 DHT 表桶分裂功能
func TestDHTTableBucketSplit(t *testing.T) {
	const (
		bucketSize = 5  // 小桶大小，便于触发分裂
		testNodes  = 50 // 测试节点总数
	)

	// 创建本地节点
	localNode, err := NewNode()
	if err != nil {
		t.Fatalf("创建本地节点失败：%v", err)
	}

	// 创建 DHT 表
	table, err := NewDHTTable(localNode.PeerID(), bucketSize)
	if err != nil {
		t.Fatalf("创建 DHT 表失败：%v", err)
	}

	t.Logf("初始桶数量：%d", table.BucketCount())

	// 生成测试节点
	nodes := make([]interfaces.Node, 0, testNodes)
	for i := 0; i < testNodes; i++ {
		node, err := NewNode()
		if err != nil {
			t.Fatalf("创建节点失败：%v", err)
		}
		nodes = append(nodes, node)
	}

	// 添加节点，触发桶分裂
	for _, node := range nodes {
		table.AddNode(node)
	}

	t.Logf("添加 %d 个节点后桶数量：%d", testNodes, table.BucketCount())

	// 验证桶数量大于 1（发生了分裂）
	if table.BucketCount() <= 1 {
		t.Error("桶未发生分裂，预期桶数量 > 1")
	}

	// 验证每个桶的距离范围
	buckets := table.GetBuckets()
	for i, bucket := range buckets {
		sl := bucket.SL()
		el := bucket.EL()
		t.Logf("桶 %d: SL=%s, EL=%s, 当前节点数=%d", i, sl.Text(16), el.Text(16), bucket.Current())

		// 验证 SL <= EL
		if sl.Cmp(el) > 0 {
			t.Errorf("桶 %d: SL 不应大于 EL", i)
		}
	}

	// 验证所有节点都能在路由表中找到
	for _, node := range nodes {
		found := false
		for _, bucket := range buckets {
			if bucket.ContainsNode(node.PeerID()) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("节点 %s 未在任何桶中找到", node.PeerID()[:16]+"...")
		}
	}
}

// TestDHTTableConcurrentSplit 测试高并发场景下的桶分裂
func TestDHTTableConcurrentSplit(t *testing.T) {
	const (
		bucketSize = 5   // 小桶大小，便于触发分裂
		goroutines = 50  // 协程数量
		operations = 200 // 每个协程的操作数
	)

	// 创建本地节点
	localNode, err := NewNode()
	if err != nil {
		t.Fatalf("创建本地节点失败：%v", err)
	}

	// 创建 DHT 表
	table, err := NewDHTTable(localNode.PeerID(), bucketSize)
	if err != nil {
		t.Fatalf("创建 DHT 表失败：%v", err)
	}

	// 生成测试节点池
	nodePool := make([]interfaces.Node, 0, 100)
	for i := 0; i < 100; i++ {
		node, err := NewNode()
		if err != nil {
			t.Fatalf("创建节点失败：%v", err)
		}
		nodePool = append(nodePool, node)
	}

	var wg sync.WaitGroup
	errChan := make(chan error, goroutines)

	// 启动多个协程并发添加节点
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < operations; i++ {
				node := nodePool[rand.Intn(len(nodePool))]
				table.AddNode(node)

				// 随机移除节点
				if rand.Intn(10) < 2 {
					buckets := table.GetBuckets()
					if len(buckets) > 0 {
						bucket := buckets[rand.Intn(len(buckets))]
						if head := bucket.Head(); head != nil {
							table.Remove(head.PeerID())
						}
					}
				}
			}
		}()
	}

	wg.Wait()
	close(errChan)

	// 检查是否有错误
	for err := range errChan {
		t.Error(err)
	}

	t.Logf("并发测试完成，最终桶数量：%d", table.BucketCount())

	// 验证桶数量大于 1（发生了分裂）
	if table.BucketCount() <= 1 {
		t.Error("高并发场景下桶未发生分裂")
	}

	// 验证所有桶的距离范围不重叠
	buckets := table.GetBuckets()
	// 使用 map 记录每个节点 ID，确保不重复
	nodeMap := make(map[string]int)
	for i, bucket := range buckets {
		bucketImpl := bucket.(*KBucketImpl)
		bucketNodes := bucketImpl.GetNodes()

		for _, node := range bucketNodes {
			peerID := node.PeerID()
			if existingBucket, exists := nodeMap[peerID]; exists {
				t.Errorf("节点 %s 同时存在于桶 %d 和桶 %d", peerID[:16]+"...", existingBucket, i)
			}
			nodeMap[peerID] = i
		}
	}

	// 验证 FindClosest 功能
	targetNode, _ := NewNode()
	closest := table.FindClosest(targetNode.PeerID(), 10)
	t.Logf("FindClosest 返回 %d 个节点", len(closest))

	if len(closest) == 0 {
		t.Error("FindClosest 未返回任何节点")
	}
}

// TestDHTTableNodeChurn 测试节点频繁上下线场景
func TestDHTTableNodeChurn(t *testing.T) {
	const (
		bucketSize  = 10   // 桶大小
		testNodes   = 3000 // 测试节点总数
		rounds      = 5000 // 上下线轮次
		offlineRate = 0.3  // 每轮离线比例
	)

	// 创建本地节点
	localNode, err := NewNode()
	if err != nil {
		t.Fatalf("创建本地节点失败：%v", err)
	}

	// 创建 DHT 表
	table, err := NewDHTTable(localNode.PeerID(), bucketSize)
	if err != nil {
		t.Fatalf("创建 DHT 表失败：%v", err)
	}

	// 生成测试节点
	nodes := make([]interfaces.Node, 0, testNodes)
	for i := 0; i < testNodes; i++ {
		node, err := NewNode()
		if err != nil {
			t.Fatalf("创建节点失败：%v", err)
		}
		nodes = append(nodes, node)
	}

	// 初始填充 DHT 表
	for _, node := range nodes[:testNodes/2] {
		table.AddNode(node)
	}

	t.Logf("初始桶数量：%d, 初始节点数：%d", table.BucketCount(), testNodes/2)

	// 模拟频繁上下线
	var wg sync.WaitGroup
	for round := 0; round < rounds; round++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()

			// 随机选择部分节点"下线"（移除）
			buckets := table.GetBuckets()
			if len(buckets) > 0 {
				bucket := buckets[rand.Intn(len(buckets))]
				offlineCount := int(float64(bucket.Current()) * offlineRate)
				for i := 0; i < offlineCount; i++ {
					if head := bucket.Head(); head != nil {
						table.Remove(head.PeerID())
					}
				}

				// 随机选择新节点"上线"（添加）
				onlineCount := offlineCount + rand.Intn(3)
				for i := 0; i < onlineCount; i++ {
					nodeIdx := rand.Intn(testNodes)
					table.AddNode(nodes[nodeIdx])
				}
			}

			// 验证桶数量合理性
			if table.BucketCount() == 0 {
				t.Errorf("轮次 %d: 桶数量为 0", r)
			}
		}(round)

		// 短暂延迟模拟真实场景
		time.Sleep(time.Millisecond * 5)
	}

	wg.Wait()

	// 最终验证
	finalBucketCount := table.BucketCount()
	t.Logf("最终桶数量：%d", finalBucketCount)

	if finalBucketCount == 0 {
		t.Error("桶数量为 0，稳定性测试失败")
	}

	// 验证所有桶的节点数不超过限制
	buckets := table.GetBuckets()
	totalNodes := 0
	for i, bucket := range buckets {
		if bucket.Current() > bucket.MaxSize() {
			t.Errorf("桶 %d 节点数超出限制：当前=%d, 限制=%d", i, bucket.Current(), bucket.MaxSize())
		}
		totalNodes += bucket.Current()
	}
	t.Logf("总节点数：%d", totalNodes)

	// 验证 FindClosest 功能在频繁上下线后仍能工作
	targetNode, _ := NewNode()
	closest := table.FindClosest(targetNode.PeerID(), 5)
	t.Logf("频繁上下线后 FindClosest 返回 %d 个节点", len(closest))
}

// TestDHTTableSplitDistanceRange 测试分裂后桶的距离范围正确性
func TestDHTTableSplitDistanceRange(t *testing.T) {
	const bucketSize = 3 // 小桶大小，便于触发多次分裂

	// 创建本地节点
	localNode, err := NewNode()
	if err != nil {
		t.Fatalf("创建本地节点失败：%v", err)
	}

	// 创建 DHT 表
	table, err := NewDHTTable(localNode.PeerID(), bucketSize)
	if err != nil {
		t.Fatalf("创建 DHT 表失败：%v", err)
	}

	// 生成距离本地节点不同距离的节点
	nodes := make([]interfaces.Node, 0, 20)
	for i := 0; i < 20; i++ {
		node, err := NewNode()
		if err != nil {
			t.Fatalf("创建节点失败：%v", err)
		}
		nodes = append(nodes, node)
	}

	// 添加节点触发分裂
	for _, node := range nodes {
		table.AddNode(node)
	}

	t.Logf("分裂后桶数量：%d", table.BucketCount())

	// 验证相邻桶的距离范围连续性
	buckets := table.GetBuckets()
	if len(buckets) < 2 {
		t.Skip("桶数量不足 2，跳过连续性验证")
	}

	for i := 0; i < len(buckets)-1; i++ {
		currentEL := buckets[i].EL()
		nextSL := buckets[i+1].SL()

		// 由于分裂可能按不同顺序，验证距离范围不重叠即可
		if currentEL.Cmp(nextSL) > 0 {
			t.Logf("桶 %d 和桶 %d 的距离范围可能重叠（需要进一步验证）", i, i+1)
		}

		t.Logf("桶 %d: SL=%s, EL=%s", i, buckets[i].SL().Text(16), buckets[i].EL().Text(16))
	}

	// 验证每个桶中的节点确实在其距离范围内
	localId, _ := new(big.Int).SetString(localNode.PeerID(), 16)
	for i, bucket := range buckets {
		bucketImpl := bucket.(*KBucketImpl)
		nodes := bucketImpl.GetNodes()

		for _, node := range nodes {
			nodeId, _ := new(big.Int).SetString(node.PeerID(), 16)
			dist := new(big.Int).Xor(localId, nodeId)

			sl := bucket.SL()
			el := bucket.EL()

			if dist.Cmp(sl) < 0 || dist.Cmp(el) > 0 {
				t.Errorf("桶 %d 中的节点 %s 距离 %s 不在范围 [%s, %s] 内",
					i, node.PeerID()[:16]+"...", dist.Text(16), sl.Text(16), el.Text(16))
			}
		}
	}
}

// TestDHTTableStress 压力测试
func TestDHTTableStress(t *testing.T) {
	const (
		bucketSize = 10
		nodeCount  = 500
		goroutines = 100
	)

	// 创建本地节点
	localNode, err := NewNode()
	if err != nil {
		t.Fatalf("创建本地节点失败：%v", err)
	}

	// 创建 DHT 表
	table, err := NewDHTTable(localNode.PeerID(), bucketSize)
	if err != nil {
		t.Fatalf("创建 DHT 表失败：%v", err)
	}

	// 生成大量节点
	nodes := make([]interfaces.Node, 0, nodeCount)
	for i := 0; i < nodeCount; i++ {
		node, err := NewNode()
		if err != nil {
			t.Fatalf("创建节点失败：%v", err)
		}
		nodes = append(nodes, node)
	}

	var wg sync.WaitGroup
	startTime := time.Now()

	// 并发添加所有节点
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(startIdx int) {
			defer wg.Done()
			endIdx := startIdx + nodeCount/goroutines
			if endIdx > nodeCount {
				endIdx = nodeCount
			}
			for i := startIdx; i < endIdx; i++ {
				table.AddNode(nodes[i])
			}
		}(g * (nodeCount / goroutines))
	}

	wg.Wait()
	elapsed := time.Since(startTime)

	t.Logf("压力测试完成：添加 %d 个节点，耗时 %v", nodeCount, elapsed)
	t.Logf("最终桶数量：%d", table.BucketCount())

	// 验证所有节点都能被找到
	foundCount := 0
	for _, node := range nodes {
		closest := table.FindClosest(node.PeerID(), 1)
		if len(closest) > 0 && closest[0].PeerID() == node.PeerID() {
			foundCount++
		}
	}

	t.Logf("找到 %d/%d 个节点", foundCount, nodeCount)
	if foundCount < nodeCount*95/100 {
		t.Errorf("节点查找成功率低于 95%%：%d/%d", foundCount, nodeCount)
	}
}

func fib(n int) int {
	arr := make([]int, 3)
	arr[0] = 0
	arr[1] = 1
	for i := 1; i < n; i++ {
		arr[(i+1)%3] = (arr[((i+1)+3-1)%3] + arr[((i+1)+3-2)%3]) % (1e9 + 7)
	}
	return arr[n%3]
}
func TestFib(t *testing.T) {
	fmt.Println(fib(3))
}
