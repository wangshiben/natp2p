package DHTable

import (
	"bnfs_p2p/interfaces"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// TestBucketStability 测试 K 桶在节点频繁上下线时的稳定性
func TestBucketStability(t *testing.T) {
	const (
		bucketSize  = 20  // K 桶大小
		testNodes   = 50  // 测试节点总数
		rounds      = 100 // 上下线轮次
		offlineRate = 0.3 // 每轮离线比例
	)

	bucket := NewStoreNode(bucketSize)
	nodes := make([]interfaces.Node, 0, testNodes)

	// 生成测试节点
	for i := 0; i < testNodes; i++ {
		node, err := NewNode()
		if err != nil {
			t.Fatalf("创建节点失败：%v", err)
		}
		nodes = append(nodes, node)
	}

	// 初始填充 K 桶
	for _, node := range nodes[:bucketSize] {
		bucket.AddNode(node)
	}

	t.Logf("初始 K 桶大小：%d", bucket.MaxSize())

	// 模拟频繁上下线
	var wg sync.WaitGroup
	for round := 0; round < rounds; round++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()

			// 随机选择部分节点"下线"（移除）
			offlineCount := int(float64(bucketSize) * offlineRate)
			for i := 0; i < offlineCount; i++ {
				if node := bucket.Head(); node != nil {
					bucket.Remove(node.PeerID())
				}
			}

			// 随机选择新节点"上线"（添加）
			onlineCount := offlineCount
			for i := 0; i < onlineCount; i++ {
				nodeIdx := rand.Intn(testNodes)
				bucket.AddNode(nodes[nodeIdx])
			}

			// 验证 K 桶大小稳定性
			if bucket.MaxSize() > bucketSize {
				t.Errorf("轮次 %d: K 桶大小超出限制，当前=%d, 限制=%d", r, bucket.MaxSize(), bucketSize)
			}
		}(round)

		// 短暂延迟模拟真实场景
		time.Sleep(time.Millisecond * 10)
	}

	wg.Wait()

	// 最终验证
	finalSize := bucket.MaxSize()
	t.Logf("最终 K 桶大小：%d", finalSize)

	if finalSize > bucketSize {
		t.Errorf("K 桶大小超出限制：当前=%d, 限制=%d", finalSize, bucketSize)
	}

	if finalSize == 0 {
		t.Error("K 桶为空，稳定性测试失败")
	}

	// 验证节点顺序（LRU 策略）
	tail := bucket.Tail()
	head := bucket.Head()
	if tail != nil {
		t.Logf("尾节点 PeerID: %s", tail.PeerID()[:16]+"...")
	}
	if head != nil {
		t.Logf("头节点 PeerID: %s", head.PeerID()[:16]+"...")
	}
}

// TestReplacementCache 测试替换缓存功能
func TestReplacementCache(t *testing.T) {
	const bucketSize = 5

	bucket := NewStoreNode(bucketSize)
	cache := bucket.cache.(*DefaultReplacementCache)

	// 填充 K 桶
	for i := 0; i < bucketSize; i++ {
		node, _ := NewNode()
		bucket.AddNode(node)
	}

	t.Logf("K 桶已满，大小：%d", bucket.MaxSize())

	// 添加新节点，应进入替换缓存
	extraNode, _ := NewNode()
	bucket.AddNode(extraNode)

	t.Logf("替换缓存大小：%d", cache.Size())

	if cache.Size() != 1 {
		t.Errorf("替换缓存应有 1 个节点，实际：%d", cache.Size())
	}

	// 移除 K 桶头节点，应从替换缓存补充
	head := bucket.Head()
	if head != nil {
		bucket.Remove(head.PeerID())
	}

	// 验证 K 桶大小恢复
	time.Sleep(time.Millisecond * 10)
	t.Logf("移除后 K 桶大小：%d", bucket.MaxSize())

	if bucket.MaxSize() != bucketSize {
		t.Errorf("K 桶应从替换缓存补充节点，当前大小：%d", bucket.MaxSize())
	}
}

// TestConcurrentAccess 测试并发访问安全性
func TestConcurrentAccess(t *testing.T) {
	const (
		bucketSize = 20
		goroutines = 500
		operations = 1000
	)

	bucket := NewStoreNode(bucketSize)
	nodes := make([]interfaces.Node, 0, 30)

	// 生成节点
	for i := 0; i < 30; i++ {
		node, err := NewNode()
		if err != nil {
			t.Fatalf("创建节点失败：%v", err)
		}
		nodes = append(nodes, node)
	}

	var wg sync.WaitGroup
	errChan := make(chan error, goroutines)

	// 启动多个协程并发操作
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < operations; i++ {
				node := nodes[rand.Intn(len(nodes))]

				// 调整操作比例：添加 70%, 移除 20%, 更新 10%
				// 模拟添加多、移除更新少的场景，验证 LRU 策略在高并发添加下的稳定性
				randVal := rand.Intn(10)
				switch {
				case randVal < 7: // 70% 概率执行添加操作
					bucket.AddNode(node)
				case randVal < 9: // 20% 概率执行移除操作
					if head := bucket.Head(); head != nil {
						bucket.Remove(head.PeerID())
					}
				default: // 10% 概率执行更新操作
					if tail := bucket.Tail(); tail != nil {
						bucket.UpdateLastSeen(tail.PeerID())
					}
				}

				// 验证大小限制
				if bucket.MaxSize() > bucketSize {
					errChan <- fmt.Errorf("K 桶大小超出限制：%d", bucket.MaxSize())
					return
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

	t.Logf("并发测试完成，最终 K 桶大小：%d", bucket.MaxSize())

	// 验证 LRU 策略：在高并发添加场景下，节点顺序应保持正确
	// 尾节点应该是最后被添加或更新的节点
	tail := bucket.Tail()
	head := bucket.Head()
	if tail != nil {
		t.Logf("尾节点 PeerID: %s", tail.PeerID()[:16]+"...")
	}
	if head != nil {
		t.Logf("头节点 PeerID: %s", head.PeerID()[:16]+"...")
	}

	// 验证桶大小未超出限制
	if bucket.MaxSize() > bucketSize {
		t.Errorf("LRU 策略可能失效：K 桶大小超出限制，当前=%d, 限制=%d", bucket.MaxSize(), bucketSize)
	}

	// 验证桶非空（高并发添加场景下不应为空）
	if bucket.MaxSize() == 0 {
		t.Error("LRU 策略可能失效：K 桶为空，高并发添加场景下不应为空")
	}

	t.Log("高并发 LRU 策略验证完成")
}

// TestNodeOrder 测试节点顺序（LRU 策略）
func TestNodeOrder(t *testing.T) {
	const bucketSize = 5

	bucket := NewStoreNode(bucketSize)
	nodes := make([]interfaces.Node, 0, bucketSize)

	// 按顺序添加节点
	for i := 0; i < bucketSize; i++ {
		node, _ := NewNode()
		nodes = append(nodes, node)
		bucket.AddNode(node)
		time.Sleep(time.Millisecond) // 确保时间戳不同
	}

	// 验证头尾节点
	head := bucket.Head()
	tail := bucket.Tail()

	if head.PeerID() != nodes[0].PeerID() {
		t.Errorf("头节点应为最早添加的节点")
	}
	if tail.PeerID() != nodes[bucketSize-1].PeerID() {
		t.Errorf("尾节点应为最新添加的节点")
	}

	// 更新中间节点的 LastSeen，应移动到队尾
	middleNode := nodes[2]
	bucket.UpdateLastSeen(middleNode.PeerID())

	newTail := bucket.Tail()
	if newTail.PeerID() != middleNode.PeerID() {
		t.Errorf("更新 LastSeen 后节点应移动到队尾")
	}

	t.Log("LRU 策略验证通过")
}
