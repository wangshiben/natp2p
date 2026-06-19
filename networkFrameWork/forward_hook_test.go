package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"errors"
	"sync"
	"testing"
)

// TestForwardHookTriggersOnThreshold 验证转发 hook 在累计字节达到阈值时被调用。
func TestForwardHookTriggersOnThreshold(t *testing.T) {
	var mu sync.Mutex
	hookCalls := 0
	var lastStats *ForwardStats

	config := &ForwardHookConfig{
		ThresholdBytes: 100, // 累计100字节触发
		Hook: func(ctx context.Context, stats *ForwardStats) error {
			mu.Lock()
			defer mu.Unlock()
			hookCalls++
			lastStats = stats
			return nil
		},
	}

	state := newForwardHookState(config)

	// 每帧 payload 50 字节 + FrameHeaderLength 头
	frameSize := 50
	// 需要多少帧才累计到 100 字节阈值
	perFrame := int64(network.FrameHeaderLength + frameSize)

	// 发送足够触发一次 hook 的帧
	framesToThreshold := int((100 + perFrame - 1) / perFrame)
	for i := 0; i < framesToThreshold; i++ {
		f := &network.Frame{
			Payload: make([]byte, frameSize),
		}
		if !state.onFrame(context.Background(), f, "test") {
			t.Fatal("hook 不应返回停止信号（hook 返回 nil）")
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if hookCalls != 1 {
		t.Fatalf("期望 hook 被调用 1 次，实际 %d 次", hookCalls)
	}
	if lastStats == nil {
		t.Fatal("hook stats 不应为 nil")
	}
	if lastStats.TotalBytes < 100 {
		t.Fatalf("累计字节应 >= 100，实际 %d", lastStats.TotalBytes)
	}
}

// TestForwardHookErrorTriggersErrorHook 验证 hook 返回 error 时触发 errorHook 并停止转发。
func TestForwardHookErrorTriggersErrorHook(t *testing.T) {
	hookErr := errors.New("业务拒绝继续转发")

	var mu sync.Mutex
	errorHookCalled := false
	var capturedInfo *ForwardErrorInfo

	config := &ForwardHookConfig{
		ThresholdBytes: 1, // 每帧都触发
		Hook: func(ctx context.Context, stats *ForwardStats) error {
			return hookErr // 总是返回错误
		},
		ErrorHook: func(ctx context.Context, info *ForwardErrorInfo) {
			mu.Lock()
			defer mu.Unlock()
			errorHookCalled = true
			capturedInfo = info
		},
	}

	state := newForwardHookState(config)

	f := &network.Frame{Payload: make([]byte, 10)}
	cont := state.onFrame(context.Background(), f, "client_to_relay")

	if cont {
		t.Fatal("hook 返回 error 时应停止转发（返回 false）")
	}

	mu.Lock()
	defer mu.Unlock()
	if !errorHookCalled {
		t.Fatal("errorHook 应被调用")
	}
	if capturedInfo == nil {
		t.Fatal("errorHook 应收到结构体参数")
	}
	if !errors.Is(capturedInfo.Err, hookErr) {
		t.Fatalf("errorHook 收到的错误应为 hookErr，实际 %v", capturedInfo.Err)
	}
	if capturedInfo.Direction != "client_to_relay" {
		t.Fatalf("方向应为 client_to_relay，实际 %s", capturedInfo.Direction)
	}
	if capturedInfo.Stats == nil {
		t.Fatal("errorHook 的 Stats 不应为 nil")
	}
}

// TestForwardHookNilConfigNoop 验证未配置 hook 时不影响转发。
func TestForwardHookNilConfigNoop(t *testing.T) {
	state := newForwardHookState(nil)

	f := &network.Frame{Payload: make([]byte, 100)}
	// nil config 的 state 应始终返回 true（继续转发）
	if !state.onFrame(context.Background(), f, "test") {
		t.Fatal("nil hook 配置应始终允许转发")
	}
}

// TestForwardHookAccumulatesAcrossFrames 验证多帧累计与重置逻辑。
func TestForwardHookAccumulatesAcrossFrames(t *testing.T) {
	var mu sync.Mutex
	hookCalls := 0

	config := &ForwardHookConfig{
		ThresholdBytes: int64(network.FrameHeaderLength+50) * 3, // 3帧触发一次
		Hook: func(ctx context.Context, stats *ForwardStats) error {
			mu.Lock()
			defer mu.Unlock()
			hookCalls++
			return nil
		},
	}

	state := newForwardHookState(config)

	// 发送 9 帧，应触发 3 次 hook（每 3 帧一次）
	for i := 0; i < 9; i++ {
		f := &network.Frame{Payload: make([]byte, 50)}
		state.onFrame(context.Background(), f, "test")
	}

	mu.Lock()
	defer mu.Unlock()
	if hookCalls != 3 {
		t.Fatalf("期望 hook 被调用 3 次，实际 %d 次", hookCalls)
	}
}
