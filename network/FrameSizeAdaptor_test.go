package network

import "testing"

// TestAdaptor_ZeroThroughputNeverEnlarges 复现并验证修复：
// 当吞吐近零(链路反复重传/卡死)时，绝不能把帧调大。
// 旧 bug: currentThroughput >= lastThroughput*0.95 被两个近零值平凡满足，
// 误判为"稳定"并增大帧（日志: "吞吐稳定, 请求 增大 帧 (当前: 0 KB/s, 上次: 0 KB/s)"）。
func TestAdaptor_ZeroThroughputNeverEnlarges(t *testing.T) {
	a := NewKCPFrameSizeAdaptor()
	a.lastThroughput = 0.5 // 近零但非零，足以绕过 lastThroughput==0 的保护

	// 连续两次近零吞吐：即便满足"防振荡 2 次同方向"，方向也不该是增大。
	a.tryAdjustByThroughput(0.4)
	a.tryAdjustByThroughput(0.3)

	if a.currentFrameSize > a.minFrameSize {
		t.Fatalf("近零吞吐下帧被调大: currentFrameSize=%d (minFrameSize=%d)", a.currentFrameSize, a.minFrameSize)
	}
	if a.pendingFrameSize != nil && *a.pendingFrameSize > a.minFrameSize {
		t.Fatalf("近零吞吐下发起了增大变更: pending=%d", *a.pendingFrameSize)
	}
}

// TestAdaptor_LowThroughputShrinksFromLargerFrame 验证：
// 帧已比最小帧大、吞吐塌到健康下限以下时，应缩小一档而不是增大。
func TestAdaptor_LowThroughputShrinksFromLargerFrame(t *testing.T) {
	a := NewKCPFrameSizeAdaptor()
	a.currentFrameSize = 1200 // 已经涨上去了
	a.lastThroughput = 200.0  // 之前很健康

	// 同步回调直接确认，模拟对端接受缩小。变更请求在后台 goroutine 里发起，
	// 用 channel 等它真正被调用，避免读到未写入的值。
	reqCh := make(chan int, 1)
	a.SetFrameSizeChangeCallback(func(newSize int) bool {
		reqCh <- newSize
		return true
	})

	// 吞吐塌到 5KB/s（< minHealthyThroughput=10）。需连续 2 次同方向(缩小)才执行。
	a.tryAdjustByThroughput(5.0)
	a.tryAdjustByThroughput(5.0)

	requested := <-reqCh
	if requested >= 1200 {
		t.Fatalf("低吞吐下帧未缩小: 请求=%d (期望 < 1200)", requested)
	}
}

// TestAdaptor_HealthyThroughputStillEnlarges 回归保护：
// 健康吞吐(高于下限)时，原有的"增大帧"逻辑仍应正常工作。
func TestAdaptor_HealthyThroughputStillEnlarges(t *testing.T) {
	a := NewKCPFrameSizeAdaptor()
	a.lastThroughput = 100.0 // 健康

	reqCh := make(chan int, 1)
	a.SetFrameSizeChangeCallback(func(newSize int) bool {
		reqCh <- newSize
		return true
	})

	// 持续健康吞吐，连续 2 次满足"达到预期95%" -> 增大帧。
	a.tryAdjustByThroughput(100.0)
	a.tryAdjustByThroughput(100.0)

	requested := <-reqCh
	if requested <= a.minFrameSize {
		t.Fatalf("健康吞吐下帧未增大: 请求=%d (minFrameSize=%d)", requested, a.minFrameSize)
	}
}
