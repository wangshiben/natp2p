package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"testing"
	"time"
)

func TestAdaptiveAckTimeout_Logic(t *testing.T) {
	ts := &TcpStream{}
	// 无样本 → initialAckTimeout
	if got := ts.adaptiveAckTimeout(); got != initialAckTimeout {
		t.Fatalf("无样本应为 %v, 得 %v", initialAckTimeout, got)
	}
	// 注入 RTT 样本
	ts.observeRTT(240 * time.Millisecond)
	// 4×240ms=960ms, 在 [800ms,8s] 内
	if got := ts.adaptiveAckTimeout(); got != 960*time.Millisecond {
		t.Fatalf("240ms RTT → 期望 960ms, 得 %v", got)
	}
	// EWMA: 再来一个 80ms 样本 → 7/8*240+1/8*80 = 220ms; 4×220ms=880ms, 仍在区间内
	ts.observeRTT(80 * time.Millisecond)
	exp := ackProgressRTTMultiple * (240*7 + 80) / 8 * int(time.Millisecond)
	if got := ts.adaptiveAckTimeout(); got != time.Duration(exp) {
		t.Fatalf("EWMA 后期望 %v, 得 %v", time.Duration(exp), got)
	}
	// 极小 RTT 钳到 minAckTimeout
	ts2 := &TcpStream{}
	ts2.observeRTT(10 * time.Millisecond)
	if got := ts2.adaptiveAckTimeout(); got != minAckTimeout {
		t.Fatalf("10ms RTT 应钳到 %v, 得 %v", minAckTimeout, got)
	}
	t.Logf("✔ 自适应超时: 无样本=%v, 240ms→960ms, 钳位 min=%v", initialAckTimeout, minAckTimeout)
}

// TestWaitAck_ProgressResetsTimer 验证核心改动：只要持续有 ACK 进展，
// 即使总耗时远超单个 timeout，也不误判超时（大消息/高 RTT 安全）。
func TestWaitAck_ProgressResetsTimer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ts := &TcpStream{streamCtx: ctx}

	tracker := newAckTracker(10) // 10 帧
	// 后台每 30ms 确认一帧，共 10 帧 → 总耗时 ~300ms，远超 80ms 的 timeout。
	go func() {
		for i := uint32(0); i < 10; i++ {
			time.Sleep(30 * time.Millisecond)
			tracker.update([]network.AckRange{{Start: i, End: i}})
		}
	}()

	// timeout=80ms：若是旧的「整消息硬截止」语义，80ms 必超时；
	// 新语义下每 30ms 有进展 < 80ms 阈值，应一路推进到完成。
	err := ts.waitAck(ctx, tracker, 80*time.Millisecond)
	if err != nil {
		t.Fatalf("有持续进展不应超时, 得 %v", err)
	}
	if !tracker.complete() {
		t.Fatal("应已收齐全部 ACK")
	}
	t.Log("✔ 进展即重置: 10 帧×30ms(总300ms) 在 80ms 阈值下未误超时")
}

// TestWaitAck_StallTimesOut 验证：真正卡住（零进展）仍会超时触发重传。
func TestWaitAck_StallTimesOut(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ts := &TcpStream{streamCtx: ctx}

	tracker := newAckTracker(10)
	tracker.update([]network.AckRange{{Start: 0, End: 2}}) // 确认前 3 帧后彻底卡住
	start := time.Now()
	err := ts.waitAck(ctx, tracker, 100*time.Millisecond)
	elapsed := time.Since(start)
	if err != errAckTimeout {
		t.Fatalf("零进展应超时返回 errAckTimeout, 得 %v", err)
	}
	if elapsed < 90*time.Millisecond || elapsed > 400*time.Millisecond {
		t.Fatalf("超时耗时应约 100ms, 得 %v", elapsed)
	}
	t.Logf("✔ 真卡住超时: 停在 3/10 帧, %v 后超时触发重传", elapsed.Round(time.Millisecond))
}
