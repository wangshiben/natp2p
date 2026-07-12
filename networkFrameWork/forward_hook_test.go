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

	state := newForwardHookState(config, "")

	// 净荷口径：每帧只按 payload 字节计（不含帧头）。
	frameSize := 50
	perFrame := int64(frameSize)

	// 发送足够触发一次 hook 的帧
	framesToThreshold := int((100 + perFrame - 1) / perFrame)
	for i := 0; i < framesToThreshold; i++ {
		f := &network.Frame{
			FrameType: network.FrameTypeData,
			Payload:   make([]byte, frameSize),
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

	state := newForwardHookState(config, "")

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
	state := newForwardHookState(nil, "")

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
		ThresholdBytes: int64(50) * 3, // 净荷口径：3 帧 payload 触发一次
		Hook: func(ctx context.Context, stats *ForwardStats) error {
			mu.Lock()
			defer mu.Unlock()
			hookCalls++
			return nil
		},
	}

	state := newForwardHookState(config, "")

	// 发送 9 帧，应触发 3 次 hook（每 3 帧一次）
	for i := 0; i < 9; i++ {
		f := &network.Frame{FrameType: network.FrameTypeData, Payload: make([]byte, 50)}
		state.onFrame(context.Background(), f, "test")
	}

	mu.Lock()
	defer mu.Unlock()
	if hookCalls != 3 {
		t.Fatalf("期望 hook 被调用 3 次，实际 %d 次", hookCalls)
	}
}

// TestForwardHookCountsPayloadOnly 验证净荷口径：
// 首见 Data/Retransmit 均计 payload，ACK / 控制帧不计，且不含帧头。
func TestForwardHookCountsPayloadOnly(t *testing.T) {
	var mu sync.Mutex
	var lastStats *ForwardStats
	hookCalls := 0

	config := &ForwardHookConfig{
		ThresholdBytes: 100,
		Hook: func(ctx context.Context, stats *ForwardStats) error {
			mu.Lock()
			defer mu.Unlock()
			hookCalls++
			lastStats = stats
			return nil
		},
	}
	state := newForwardHookState(config, "")

	// 控制帧不应被计数（payload 各 1000 字节，远超阈值，但应被跳过）。
	for _, ft := range []uint8{network.FrameTypeAck, network.FrameTypeFrameSizeChange} {
		f := &network.Frame{FrameType: ft, Payload: make([]byte, 1000)}
		if !state.onFrame(context.Background(), f, "test") {
			t.Fatal("非数据帧应放行")
		}
	}
	mu.Lock()
	if hookCalls != 0 {
		mu.Unlock()
		t.Fatalf("ACK/控制帧不应触发 hook，实际触发 %d 次", hookCalls)
	}
	mu.Unlock()

	// 首见的 Retransmit 可能是首发帧在 relay 前丢失后的合法补发，也可能是伪造帧；两者都必须计量。
	state.onFrame(context.Background(), &network.Frame{
		FrameType:    network.FrameTypeRetransmit,
		ConnectionId: "conn-retransmit",
		MessageId:    1,
		TotalFrames:  1,
		Payload:      make([]byte, 1000),
	}, "test")
	mu.Lock()
	if hookCalls != 1 || lastStats == nil || lastStats.TotalBytes != 1000 {
		mu.Unlock()
		t.Fatalf("首见 Retransmit 应按 1000B 计量，calls=%d stats=%v", hookCalls, lastStats)
	}
	mu.Unlock()

	// 两个数据帧，各 60 字节 payload → 累计 120 ≥ 100 触发一次。
	for i := 0; i < 2; i++ {
		f := &network.Frame{FrameType: network.FrameTypeData, Payload: make([]byte, 60)}
		state.onFrame(context.Background(), f, "test")
	}

	mu.Lock()
	defer mu.Unlock()
	if hookCalls != 2 {
		t.Fatalf("期望数据帧额外触发 1 次，实际总次数 %d", hookCalls)
	}
	// 累计应为 2*60=120（纯净荷，不含帧头；若含头会是 120+2*39）。
	if lastStats == nil || lastStats.TotalBytes != 120 {
		t.Fatalf("累计应为纯净荷 120 字节，实际 %v", lastStats)
	}
	if lastStats.TotalFrames != 2 {
		t.Fatalf("应只计 2 个数据帧，实际 %d", lastStats.TotalFrames)
	}
}

func TestForwardHookRetransmitDedupeRequiresExactRecentFrame(t *testing.T) {
	var totalBytes int64
	config := &ForwardHookConfig{
		ThresholdBytes: 1,
		Hook: func(ctx context.Context, stats *ForwardStats) error {
			totalBytes += stats.TotalBytes
			return nil
		},
	}
	state := newForwardHookState(config, "server-1")
	original := &network.Frame{
		FrameType:    network.FrameTypeData,
		ConnectionId: "conn-1",
		MessageId:    7,
		SeqId:        3,
		TotalFrames:  4,
		Payload:      []byte("original"),
	}
	if !state.onFrame(context.Background(), original, "relay_to_clients") {
		t.Fatal("首发帧应继续转发")
	}

	repeated := *original
	repeated.FrameType = network.FrameTypeRetransmit
	if !state.onFrame(context.Background(), &repeated, "relay_to_clients") {
		t.Fatal("真实重传应继续转发")
	}
	if totalBytes != int64(len(original.Payload)) {
		t.Fatalf("真实重复帧不应重复计量，实际=%d", totalBytes)
	}

	forged := repeated
	forged.Payload = []byte("forged")
	if !state.onFrame(context.Background(), &forged, "relay_to_clients") {
		t.Fatal("伪造 retransmit 仍应转发并被计量")
	}
	wantAfterForged := int64(len(original.Payload) + len(forged.Payload))
	if totalBytes != wantAfterForged {
		t.Fatalf("载荷不同的 retransmit 必须计量，实际=%d 期望=%d", totalBytes, wantAfterForged)
	}

	for repeatIndex := 1; repeatIndex < retransmitCacheMaxFreeRepeats; repeatIndex++ {
		if !state.onFrame(context.Background(), &repeated, "relay_to_clients") {
			t.Fatal("协议上限内的真实重传应继续转发")
		}
	}
	if totalBytes != wantAfterForged {
		t.Fatalf("最多 6 次真实重传不应重复计量，实际=%d", totalBytes)
	}
	if !state.onFrame(context.Background(), &repeated, "relay_to_clients") {
		t.Fatal("超过免费次数的重传应继续转发")
	}
	wantAfterLimit := wantAfterForged + int64(len(original.Payload))
	if totalBytes != wantAfterLimit {
		t.Fatalf("超过免费次数的重传应重新计量，实际=%d 期望=%d", totalBytes, wantAfterLimit)
	}

	ackRanges := network.FullAckRange(original.TotalFrames)
	config.ensureRetransmitCache().acknowledge(
		"server-1", original.ConnectionId, original.MessageId, original.TotalFrames, ackRanges,
	)
	if !state.onFrame(context.Background(), &repeated, "relay_to_clients") {
		t.Fatal("ACK 回收后的重传应继续转发")
	}
	if totalBytes != wantAfterLimit+int64(len(original.Payload)) {
		t.Fatalf("ACK 回收后应重新计量，实际=%d", totalBytes)
	}
}

func TestGlobalRetransmitCacheSharedAcrossStates(t *testing.T) {
	config := &ForwardHookConfig{ThresholdBytes: 1, Hook: func(context.Context, *ForwardStats) error { return nil }}
	serverStateA := newForwardHookState(config, "server-a")
	serverStateB := newForwardHookState(config, "server-b")
	frame := &network.Frame{
		FrameType:    network.FrameTypeData,
		ConnectionId: "conn-shared",
		MessageId:    11,
		TotalFrames:  1,
		Payload:      []byte("payload"),
	}
	serverStateA.onFrame(context.Background(), frame, "relay_to_clients")
	retransmit := *frame
	retransmit.FrameType = network.FrameTypeRetransmit
	serverStateA.onFrame(context.Background(), &retransmit, "relay_to_clients")
	serverStateB.onFrame(context.Background(), &retransmit, "relay_to_clients")

	stats := config.ensureRetransmitCache().snapshot()
	if stats.Misses != 2 || stats.Hits != 1 || stats.Entries != 2 {
		t.Fatalf("全局缓存应共享但按 NatServer 隔离，stats=%+v", stats)
	}
}

func TestGlobalRetransmitCacheConcurrent(t *testing.T) {
	cache := newGlobalRetransmitCache()
	const workers = 16
	const framesPerWorker = 200
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			for frameIndex := 0; frameIndex < framesPerWorker; frameIndex++ {
				frame := &network.Frame{
					FrameType:    network.FrameTypeData,
					ConnectionId: "conn-concurrent",
					MessageId:    uint64(worker*framesPerWorker + frameIndex),
					TotalFrames:  1,
					Payload:      []byte("payload"),
				}
				if !cache.recordFrame("server-concurrent", frame) {
					t.Errorf("首见帧不应命中缓存 worker=%d frame=%d", worker, frameIndex)
					return
				}
			}
		}(worker)
	}
	waitGroup.Wait()
	stats := cache.snapshot()
	if stats.Misses != workers*framesPerWorker || stats.Entries != workers*framesPerWorker {
		t.Fatalf("并发写入统计不符: %+v", stats)
	}
}
