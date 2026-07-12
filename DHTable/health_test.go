package DHTable

import (
	"bnfs_p2p/interfaces"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"
)

func healthTestNode(value int) interfaces.Node {
	return NewNodeFromPeerID(fmt.Sprintf("%064x", value))
}

func TestActualRangeSupportsFull256BitDistance(t *testing.T) {
	localID := big.NewInt(0)
	maximum := new(big.Int).Lsh(big.NewInt(1), 256)
	maximum.Sub(maximum, big.NewInt(1))
	bucket := NewKBucket(2, localID, big.NewInt(0), new(big.Int).Set(maximum))
	node := NewNodeFromPeerID(fmt.Sprintf("%064x", maximum))
	bucket.AddNode(node)
	if bucket.SR().Cmp(maximum) != 0 || bucket.ER().Cmp(maximum) != 0 {
		t.Fatalf("256 位最大距离范围计算错误: sr=%s er=%s", bucket.SR(), bucket.ER())
	}
}

func TestRankedNodesRTTBandThenStableAgePreservesLRU(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	bucket := NewStoreNode(4)
	fastNew := healthTestNode(1)
	fastStable := healthTestNode(2)
	slowStable := healthTestNode(3)
	for _, node := range []interfaces.Node{fastNew, fastStable, slowStable} {
		bucket.AddNode(node)
	}
	bucket.SetNodeHealth(fastNew.PeerID(), interfaces.NodeHealth{RTT: 40 * time.Millisecond, ContinuousHealthySince: now.Add(-time.Hour), LastSuccess: now})
	bucket.SetNodeHealth(fastStable.PeerID(), interfaces.NodeHealth{RTT: 41 * time.Millisecond, ContinuousHealthySince: now.Add(-24 * time.Hour), LastSuccess: now})
	bucket.SetNodeHealth(slowStable.PeerID(), interfaces.NodeHealth{RTT: 60 * time.Millisecond, ContinuousHealthySince: now.Add(-240 * time.Hour), LastSuccess: now})

	headBefore := bucket.Head().PeerID()
	tailBefore := bucket.Tail().PeerID()
	ranked := bucket.RankedNodes(interfaces.NodeRankingPolicy{Now: now})
	if len(ranked) != 3 {
		t.Fatalf("期望 3 个排名节点，实际 %d", len(ranked))
	}
	if ranked[0].PeerID() != fastStable.PeerID() {
		t.Fatalf("同 RTT 档应选择稳定时间最长节点，实际首选 %s", ranked[0].PeerID())
	}
	if ranked[2].PeerID() != slowStable.PeerID() {
		t.Fatalf("稳定时间不能跨 RTT 档反转结果，实际末位 %s", ranked[2].PeerID())
	}
	if bucket.Head().PeerID() != headBefore || bucket.Tail().PeerID() != tailBefore {
		t.Fatal("只读排名不得改变桶内 LRU Head/Tail")
	}
}

func TestMaintainHeadSuccessAndConsecutiveFailureRemoval(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("探测成功移动到尾部", func(t *testing.T) {
		bucket := NewStoreNode(2)
		head := healthTestNode(10)
		tail := healthTestNode(11)
		bucket.AddNode(head)
		bucket.AddNode(tail)
		bucket.SetNodeHealth(head.PeerID(), interfaces.NodeHealth{
			ContinuousHealthySince: now.Add(-time.Hour),
			LastSuccess:            now.Add(-3 * time.Minute),
		})
		result := bucket.Maintain(interfaces.DHTMaintenancePolicy{
			Now: now, StaleAfter: 2 * time.Minute, RemoveAfterFailures: 2,
			Probe: func(node interfaces.Node) bool { return node.PeerID() == head.PeerID() },
		})
		if result.Action != interfaces.MaintenanceTouched || bucket.Tail().PeerID() != head.PeerID() {
			t.Fatalf("探测成功应 Touch 并移动到尾部，结果=%+v", result)
		}
	})

	t.Run("连续失败两次才删除并验证候补", func(t *testing.T) {
		bucket := NewStoreNode(2)
		head := healthTestNode(20)
		tail := healthTestNode(21)
		replacement := healthTestNode(22)
		bucket.AddNode(head)
		bucket.AddNode(tail)
		bucket.AddNode(replacement)
		bucket.SetNodeHealth(head.PeerID(), interfaces.NodeHealth{
			ContinuousHealthySince: now.Add(-time.Hour),
			LastSuccess:            now.Add(-3 * time.Minute),
		})
		policy := interfaces.DHTMaintenancePolicy{
			Now: now, StaleAfter: 2 * time.Minute, RemoveAfterFailures: 2,
			Probe: func(node interfaces.Node) bool { return node.PeerID() == replacement.PeerID() },
		}
		first := bucket.Maintain(policy)
		if first.Action != interfaces.MaintenanceSuspect || first.Failures != 1 || bucket.Head().PeerID() != head.PeerID() {
			t.Fatalf("首次失败只应标记 suspect，结果=%+v", first)
		}
		second := bucket.Maintain(policy)
		if second.Action != interfaces.MaintenanceRemoved || second.Failures != 2 {
			t.Fatalf("第二次失败应删除，结果=%+v", second)
		}
		if second.ReplacementNodeID != replacement.PeerID() || bucket.Tail().PeerID() != replacement.PeerID() {
			t.Fatalf("应只提升探测成功的候补，结果=%+v", second)
		}
	})
}

func TestHealthRankingDoesNotChangeFindClosest(t *testing.T) {
	table, err := NewDHTTable(fmt.Sprintf("%064x", 0), 8)
	if err != nil {
		t.Fatal(err)
	}
	near := healthTestNode(1)
	far := healthTestNode(100)
	table.AddNode(near)
	table.AddNode(far)
	now := time.Unix(1_700_000_000, 0)
	table.SetNodeHealth(near.PeerID(), interfaces.NodeHealth{RTT: 200 * time.Millisecond, ContinuousHealthySince: now.Add(-time.Hour), LastSuccess: now})
	table.SetNodeHealth(far.PeerID(), interfaces.NodeHealth{RTT: 10 * time.Millisecond, ContinuousHealthySince: now.Add(-time.Hour), LastSuccess: now})
	if ranked := table.RankedNodes(interfaces.NodeRankingPolicy{Now: now}); ranked[0].PeerID() != far.PeerID() {
		t.Fatal("网络质量视图应优先低 RTT 节点")
	}
	closest := table.FindClosest(fmt.Sprintf("%064x", 0), 1)
	if len(closest) != 1 || closest[0].PeerID() != near.PeerID() {
		t.Fatal("FindClosest 必须继续严格使用 XOR 距离")
	}
}

func TestHealthRankingConcurrentAccess(t *testing.T) {
	bucket := NewStoreNode(20)
	nodes := make([]interfaces.Node, 20)
	for index := range nodes {
		nodes[index] = healthTestNode(1000 + index)
		bucket.AddNode(nodes[index])
	}
	now := time.Unix(1_700_000_000, 0)
	var waitGroup sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			for iteration := 0; iteration < 200; iteration++ {
				node := nodes[(worker+iteration)%len(nodes)]
				bucket.SetNodeHealth(node.PeerID(), interfaces.NodeHealth{
					RTT:                    time.Duration(10+(iteration%50)) * time.Millisecond,
					ContinuousHealthySince: now.Add(-time.Duration(worker+1) * time.Hour),
					LastSuccess:            now,
				})
				if iteration%3 == 0 {
					bucket.Touch(node.PeerID(), now)
				}
				_ = bucket.RankedNodes(interfaces.NodeRankingPolicy{Now: now})
			}
		}(worker)
	}
	waitGroup.Wait()
	if bucket.Current() != len(nodes) {
		t.Fatalf("并发健康更新不应改变节点数，实际 %d", bucket.Current())
	}
}
