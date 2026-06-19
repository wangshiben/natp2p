package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
)

// ForwardHookFunc 是每转发到指定大小时调用的 hook。
// 返回 nil 则继续转发；返回 error 则触发 errorHook 并停止该方向的转发。
type ForwardHookFunc func(ctx context.Context, stats *ForwardStats) error

// ForwardErrorInfo 错误信息（用于 errorHook）
type ForwardErrorInfo struct {
	// Stats 是触发错误时的转发统计
	Stats *ForwardStats
	// Err 是 hook 返回的错误
	Err error
	// Direction 是转发方向："client_to_relay" 或 "relay_to_clients"
	Direction string
}

// ForwardErrorHookFunc 是转发 hook 返回 error 时调用的错误处理函数
type ForwardErrorHookFunc func(ctx context.Context, errorInfo *ForwardErrorInfo)

// ForwardStats 转发统计信息
type ForwardStats struct {
	// TotalBytes 是从上次 hook 调用以来累计转发的字节数
	TotalBytes int64
	// TotalFrames 是从上次 hook 调用以来转发的帧数
	TotalFrames int64
	// LastFrame 是最后一个转发的帧（只读，用于日志/监控）
	LastFrame *network.Frame
}

// ForwardHookConfig 转发 hook 配置
type ForwardHookConfig struct {
	// ThresholdBytes 是触发 hook 的字节数阈值（累计转发到这个大小就调用 hook）
	ThresholdBytes int64
	// Hook 是转发 hook 函数
	Hook ForwardHookFunc
	// ErrorHook 是错误处理 hook
	ErrorHook ForwardErrorHookFunc
}

// forwardHookState 转发 hook 的运行时状态
type forwardHookState struct {
	config        *ForwardHookConfig
	accumulatedBytes int64
	accumulatedFrames int64
	lastFrame     *network.Frame
}

// newForwardHookState 创建 hook 状态
func newForwardHookState(config *ForwardHookConfig) *forwardHookState {
	if config == nil {
		return nil
	}
	return &forwardHookState{
		config: config,
	}
}

// onFrame 在每个帧转发前调用，返回 true 表示可以继续转发，false 表示需要停止
//
// 统计口径 = 净荷（goodput），不是带宽（throughput）：
//   - 只累计「首发数据帧」`FrameTypeData` 的 payload 字节；
//   - **不含帧头**（每帧 39B 头不计）；
//   - **跳过** ACK(`FrameTypeAck`) / 重传(`FrameTypeRetransmit`) / 帧大小控制帧(`FrameTypeFrameSizeChange`)，
//     它们既不携带新的业务净荷（重传是丢包重发的同一份数据），又会在 WAN 上把计数顶高，
//     不计入才能贴近应用层「成功送达的有效载荷」。
// 这样 relay 累计 ≈ 应用层 payload 总量；带宽口径（含双向/重传/头/ACK）见 git 历史。
func (s *forwardHookState) onFrame(ctx context.Context, f *network.Frame, direction string) bool {
	if s == nil || s.config == nil {
		return true
	}

	// 非首发数据帧（ACK/重传/控制帧）不携带新净荷，直接放行不计数。
	if f == nil || f.FrameType != network.FrameTypeData {
		return true
	}

	// 只累计净荷字节（不含帧头）。
	frameSize := int64(len(f.Payload))
	s.accumulatedBytes += frameSize
	s.accumulatedFrames++
	s.lastFrame = f

	// 检查是否达到阈值
	if s.accumulatedBytes >= s.config.ThresholdBytes {
		stats := &ForwardStats{
			TotalBytes:  s.accumulatedBytes,
			TotalFrames: s.accumulatedFrames,
			LastFrame:   s.lastFrame,
		}

		// 调用 hook
		err := s.config.Hook(ctx, stats)

		// 重置累计
		s.accumulatedBytes = 0
		s.accumulatedFrames = 0

		if err != nil {
			// 调用 errorHook
			if s.config.ErrorHook != nil {
				s.config.ErrorHook(ctx, &ForwardErrorInfo{
					Stats:     stats,
					Err:       err,
					Direction: direction,
				})
			}
			return false
		}
	}

	return true
}
