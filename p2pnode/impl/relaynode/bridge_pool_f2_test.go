package relaynode

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/networkFrameWork"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

// TestBridgePool_SpreadLoad 验证模式 A 摊散调度：多条逻辑连接在持续写压力下，依 pendingBytes/
// ActiveStreams 触发扩容并摊散到多条物理连接，避免全挤一条 TCP 的串行队头阻塞。
func TestBridgePool_SpreadLoad(t *testing.T) {
	logx.SetLevel(logx.LevelInfo)
	defer logx.SetLevel(logx.LevelWarn)

	srvRelay, srvAddr := newTestBridgeRelay(t, "server-spread")
	defer srvRelay.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	pool := newRelayPeerPool(ctx, srvAddr, "client-spread", 1)
	defer pool.Close()
	time.Sleep(300 * time.Millisecond)

	// 开 K 条逻辑连接并各自持续写，制造跨连接的并发写压力。
	const K = 6
	const chunk = 64 * 1024
	payload := make([]byte, chunk)
	for i := range payload {
		payload[i] = byte(i)
	}
	lcs := make([]*networkFrameWork.LogicalConn, 0, K)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < K; i++ {
		lc, err := pool.OpenLogicalConn(fmt.Sprintf("spread-%d", i), "tgt", "pub", 1)
		if err != nil {
			t.Fatalf("OpenLogicalConn #%d 失败: %v", i, err)
		}
		lcs = append(lcs, lc)
		wg.Add(1)
		go func(c *networkFrameWork.LogicalConn) {
			defer wg.Done()
			drain := make([]byte, chunk)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := c.Write(payload); err != nil {
					return
				}
				// echo 回来的字节要读掉，避免对端写阻塞
				_, _ = io.ReadFull(c, drain)
			}
		}(lc)
	}

	// 给扩容采样循环(200ms)足够周期去观察写竞争并摊散（CPU 竞争时采样可能偏慢，放宽窗口）。
	deadline := time.Now().Add(8 * time.Second)
	maxConns := 1
	for time.Now().Before(deadline) {
		if c := pool.connCount(); c > maxConns {
			maxConns = c
		}
		if maxConns >= 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	close(stop)
	wg.Wait()
	for _, lc := range lcs {
		_ = lc.Close()
	}

	if maxConns < 2 {
		t.Errorf("期望写竞争触发摊散扩容至 ≥2 条, 实际峰值 %d 条", maxConns)
	} else {
		t.Logf("✔ 模式 A 摊散: K=%d 逻辑连接的并发写压力触发扩容至 %d 条物理连接", K, maxConns)
	}
}

// TestBridgePool_PickLeastLoaded 验证 pickLeastLoaded 选连接以 pendingBytes 为主、
// ActiveStreams 为次：手动扩到多条连接后，新会话应落到写压力最小的那条。
func TestBridgePool_PickLeastLoaded(t *testing.T) {
	logx.SetLevel(logx.LevelWarn)

	srvRelay, srvAddr := newTestBridgeRelay(t, "server-pick")
	defer srvRelay.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool := newRelayPeerPool(ctx, srvAddr, "client-pick", 1)
	defer pool.Close()
	time.Sleep(200 * time.Millisecond)

	// 手动扩到 3 条物理连接
	pool.addPhysConn()
	pool.addPhysConn()
	time.Sleep(400 * time.Millisecond)
	if pool.connCount() != 3 {
		t.Fatalf("期望 3 条物理连接, 实际 %d", pool.connCount())
	}

	// 连续开 9 条逻辑连接（不写数据，pendingBytes≈0，退化为按 ActiveStreams 轮转）。
	for i := 0; i < 9; i++ {
		if _, err := pool.OpenStream(fmt.Sprintf("pick-%d", i), "tgt", "pub"); err != nil {
			t.Fatalf("OpenStream #%d 失败: %v", i, err)
		}
	}
	time.Sleep(100 * time.Millisecond)

	// 断言：9 条流应较均匀分布到 3 条连接（每条约 3），无一条独占。
	pool.mu.Lock()
	dist := make([]int, 0, len(pool.conns))
	for _, pc := range pool.conns {
		pc.mu.Lock()
		sess := pc.sess
		pc.mu.Unlock()
		if sess != nil && !sess.IsClosed() {
			dist = append(dist, sess.ActiveStreams())
		}
	}
	pool.mu.Unlock()

	maxN := 0
	for _, n := range dist {
		if n > maxN {
			maxN = n
		}
	}
	if maxN > 5 {
		t.Errorf("分布不均: 单连接承载 %d 条（9 条/3 连接期望约 3）, dist=%v", maxN, dist)
	} else {
		t.Logf("✔ pickLeastLoaded 均匀分布: 9 条逻辑连接 → 3 条物理连接, 最大 %d 条/连接 dist=%v", maxN, dist)
	}
}
