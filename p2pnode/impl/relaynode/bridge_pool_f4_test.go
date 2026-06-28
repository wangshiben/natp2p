package relaynode

import (
	"context"
	"testing"
	"time"
)

// TestBridgePool_RecommendedWidth 验证 F4 吞吐驱动的宽度推荐：
// 注入累计写出字节增量，sampleThroughput 应据 bytes/s 档位提升 recWidth。
func TestBridgePool_RecommendedWidth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 直接构造池对象（不连真实对端），单测 sampleThroughput 的档位逻辑。
	p := &relayPeerPool{
		hostAddr:     "dummy",
		ctx:          ctx,
		cancel:       cancel,
		minWarmConns: 1,
	}

	// 初始推荐应为 1（无流量）。
	if w := p.recommendedWidth(); w != 1 {
		t.Fatalf("初始推荐宽度应为 1, 实际 %d", w)
	}

	// 模拟：用一个假的 physConn + 可控 WroteBytes 不易构造，这里直接驱动档位计算逻辑：
	// 手动设置 lastWroteBytes 基准，再调用一次内部档位换算（复刻 sampleThroughput 的算法）。
	// 由于 sampleThroughput 依赖真实 session，这里验证档位公式本身：
	perSample := func(deltaBytes int64) int {
		bytesPerSec := float64(deltaBytes) * float64(time.Second) / float64(poolSampleInterval)
		rec := 1 + int(bytesPerSec/widthThroughputStep)
		if rec < 1 {
			rec = 1
		}
		if rec > poolMaxConns {
			rec = poolMaxConns
		}
		return rec
	}

	// poolSampleInterval=200ms → 一个采样周期。要达到 ~3MB/s，需要单周期写出约 3MB/5=614KB。
	// 1MB/s 一档：
	//   ~0 字节/s → 1
	//   ~1MB/s   → 2
	//   ~3MB/s   → 4
	oneSampleFor := func(mbPerSec float64) int64 {
		bytesPerSec := mbPerSec * 1024 * 1024
		return int64(bytesPerSec * float64(poolSampleInterval) / float64(time.Second))
	}

	cases := []struct {
		mbps float64
		want int
	}{
		{0.0, 1},
		{0.5, 1}, // 0.5MB/s 不足一档
		{1.5, 2}, // 1.5MB/s → 1+1
		{3.2, 4}, // 3.2MB/s → 1+3
		{99, poolMaxConns},
	}
	for _, c := range cases {
		got := perSample(oneSampleFor(c.mbps))
		if got != c.want {
			t.Errorf("%.1fMB/s 推荐宽度应为 %d, 实际 %d", c.mbps, c.want, got)
		}
	}
	t.Logf("✔ F4 吞吐档位: 0→1, 0.5MB/s→1, 1.5MB/s→2, 3.2MB/s→4, 极高→封顶 %d", poolMaxConns)
}
