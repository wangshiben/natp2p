package network

import (
	"sync"
	"time"
)

// FrameSizeAdaptor 动态调整帧大小以适应网络条件
// 采用渐进式策略：先稳定，再探测，根据实际吞吐反馈调整
type FrameSizeAdaptor struct {
	mu sync.RWMutex

	// 当前帧大小
	currentFrameSize int
	// 待确认的新帧大小（nil表示无待确认变更）
	pendingFrameSize *int

	// 吞吐量统计
	bytesSent      uint64    // 累计发送字节数
	lastCheckBytes uint64    // 上次检查时的字节数
	lastCheckTime  time.Time // 上次检查时间
	lastThroughput float64   // 上次测得的吞吐量(KB/s)

	// 调整历史
	adjustmentCount  int       // 调整次数
	lastAdjustTime   time.Time // 上次调整时间
	baselinePhase    bool      // 是否处于基线建立阶段
	lastAdjustDir    int       // 上次调整方向：1=增大，-1=减小，0=无
	sameDirectionCnt int       // 连续同方向计数（防振荡）

	// 配置参数
	minFrameSize     int           // 最小帧大小
	maxFrameSize     int           // 最大帧大小
	checkInterval    time.Duration // 吞吐检查间隔
	baselineDuration time.Duration // 基线建立时长

	// 同步回调：当需要改变帧大小时调用，返回true表示对端已确认
	onFrameSizeChange func(newSize int) bool
}

// NewKCPFrameSizeAdaptor 创建KCP优化的渐进式帧大小自适应器
// 保守策略：从800字节开始，30秒检查，防振荡
func NewKCPFrameSizeAdaptor() *FrameSizeAdaptor {
	now := time.Now()
	return &FrameSizeAdaptor{
		currentFrameSize: 800,                  // 从800字节开始（保守起点）
		minFrameSize:     800,                  // 最小800字节
		maxFrameSize:     1400,                 // 最大1400字节（已验证最优）
		checkInterval:    time.Second * 30,     // 每30秒检查一次（减少调整频率）
		baselineDuration: 0,                    // 无基线期
		lastCheckTime:    now,
		lastAdjustTime:   now,
		baselinePhase:    false,
		lastThroughput:   1.0,
	}
}

// GetFrameSize 获取当前推荐的帧大小
func (a *FrameSizeAdaptor) GetFrameSize() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.currentFrameSize
}

// RecordBytesSent 记录发送的字节数（替代原来的RecordRTT/RecordPacketResult）
func (a *FrameSizeAdaptor) RecordBytesSent(bytes int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.bytesSent += uint64(bytes)

	// 检查是否到达检查时间
	now := time.Now()
	elapsed := now.Sub(a.lastCheckTime)

	if elapsed < a.checkInterval {
		return // 还没到检查时间
	}

	// 检查是否还在基线阶段
	if a.baselinePhase {
		totalElapsed := now.Sub(a.lastAdjustTime) // 从启动开始的总时长
		if totalElapsed >= a.baselineDuration {
			// 基线阶段结束，计算整个基线期的平均吞吐量
			totalBytes := a.bytesSent
			throughputKBps := float64(totalBytes) / 1024.0 / totalElapsed.Seconds()

			a.baselinePhase = false
			a.lastThroughput = throughputKBps
			a.lastCheckBytes = a.bytesSent
			a.lastCheckTime = now
			println("[FrameAdaptor] 基线期结束, 基线吞吐:", int(throughputKBps), "KB/s, 总字节:", totalBytes, ", 耗时:", int(totalElapsed.Seconds()), "秒")
		}
		return // 基线阶段不调整
	}

	// 探测阶段：计算当前吞吐量
	bytesSinceLastCheck := a.bytesSent - a.lastCheckBytes
	throughputKBps := float64(bytesSinceLastCheck) / 1024.0 / elapsed.Seconds()

	// 探测阶段：根据吞吐量调整帧大小
	a.tryAdjustByThroughput(throughputKBps)

	// 更新状态
	a.lastThroughput = throughputKBps
	a.lastCheckBytes = a.bytesSent
	a.lastCheckTime = now
}

// tryAdjustByThroughput 根据吞吐量调整帧大小
// 关键改进：
// 1. 防振荡：需连续2次同方向才调整
// 2. 非阻塞：同步在后台goroutine完成，不影响数据发送
// 3. 限制范围：800-1400字节
func (a *FrameSizeAdaptor) tryAdjustByThroughput(currentThroughput float64) {
	if a.lastThroughput == 0 {
		return
	}

	// 如果有待确认的变更，跳过本次调整
	if a.pendingFrameSize != nil {
		return
	}

	oldSize := a.currentFrameSize
	newSize := oldSize
	direction := 0 // 0=不变，1=增大，-1=减小

	// 策略1: 吞吐量达到预期95%以上 -> 考虑增大帧8%（更保守）
	expectedThroughput := a.lastThroughput * 0.95
	if currentThroughput >= expectedThroughput && oldSize < a.maxFrameSize {
		newSize = int(float64(oldSize) * 1.08)
		if newSize > a.maxFrameSize {
			newSize = a.maxFrameSize
		}
		if newSize != oldSize {
			direction = 1
		}
	} else if currentThroughput < a.lastThroughput*0.85 && oldSize > a.minFrameSize {
		// 策略2: 吞吐量低于上次85% -> 考虑减小帧9%
		newSize = int(float64(oldSize) * 0.91)
		if newSize < a.minFrameSize {
			newSize = a.minFrameSize
		}
		if newSize != oldSize {
			direction = -1
		}
	}

	// 防振荡：检查方向是否一致
	if direction != 0 {
		if direction == a.lastAdjustDir {
			// 同方向，累加计数
			a.sameDirectionCnt++
		} else {
			// 方向变化，重置计数
			a.lastAdjustDir = direction
			a.sameDirectionCnt = 1
		}

		// 需要连续2次同方向才真正调整
		if a.sameDirectionCnt < 2 {
			dirStr := "增大"
			if direction < 0 {
				dirStr = "减小"
			}
			println("[FrameAdaptor] 准备", dirStr, "帧(", oldSize, "->", newSize, "), 等待下次确认（防振荡", a.sameDirectionCnt, "/2）")
			return
		}

		// 连续2次同方向，执行调整
		dirStr := "增大"
		if direction < 0 {
			dirStr = "减小"
		}
		println("[FrameAdaptor] 吞吐稳定, 请求", dirStr, "帧: ", oldSize, " -> ", newSize, " (当前:", int(currentThroughput), "KB/s, 上次:", int(a.lastThroughput), "KB/s)")

		// 发起帧大小变更，等待对端确认
		if a.onFrameSizeChange != nil {
			a.pendingFrameSize = &newSize
			// 异步发送变更请求，不阻塞数据发送
			go func() {
				confirmed := a.onFrameSizeChange(newSize)
				a.mu.Lock()
				defer a.mu.Unlock()

				if confirmed && a.pendingFrameSize != nil && *a.pendingFrameSize == newSize {
					// 对端已确认，应用新帧大小
					a.currentFrameSize = newSize
					a.adjustmentCount++
					a.lastAdjustTime = time.Now()
					a.sameDirectionCnt = 0 // 重置计数
					println("[FrameAdaptor] ✅ 帧大小变更已同步: ", oldSize, " -> ", newSize)
				} else {
					println("[FrameAdaptor] ❌ 帧大小变更被拒绝或超时，保持: ", oldSize)
					a.sameDirectionCnt = 0 // 失败也重置
				}
				a.pendingFrameSize = nil
			}()
		}
	}
}

// SetFrameSizeChangeCallback 设置帧大小变更的同步回调
// callback返回true表示对端已确认新帧大小
func (a *FrameSizeAdaptor) SetFrameSizeChangeCallback(callback func(newSize int) bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onFrameSizeChange = callback
}

// RecordPacketResult 保留接口兼容性（但在新策略中不使用）
func (a *FrameSizeAdaptor) RecordPacketResult(success bool) {
	// 新策略不使用包成功率，仅保留接口避免编译错误
}

// Reset 重置统计
func (a *FrameSizeAdaptor) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	a.bytesSent = 0
	a.lastCheckBytes = 0
	a.lastCheckTime = now
	a.lastThroughput = 0
	a.adjustmentCount = 0
	a.lastAdjustTime = now
	a.baselinePhase = true
	a.currentFrameSize = 1400
}

// GetStats 获取当前统计信息（用于调试）
func (a *FrameSizeAdaptor) GetStats() (frameSize int, throughput float64, adjustments int) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.currentFrameSize, a.lastThroughput, a.adjustmentCount
}

// SetFrameSize 直接设置帧大小（用于对端同步）
func (a *FrameSizeAdaptor) SetFrameSize(newSize int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.currentFrameSize = newSize
}

// RecordRTT 保留接口兼容性（但在新策略中不使用）
func (a *FrameSizeAdaptor) RecordRTT(rtt time.Duration) {
	// 新策略不使用RTT，仅保留接口避免编译错误
}
