package networkFrameWork

import (
	"bnfs_p2p/billingrecord"
	"bnfs_p2p/billingvoucher"
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"context"
	"errors"
	"fmt"
	"sync"
)

var ErrBillableRecordDeferred = errors.New("billing record is waiting for an earlier sequence")

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
	// NodeID 是产生该转发的 StreamGroup 所代表的对端节点 NodeId（即被托管节点/设备1）。
	// 计费方向据它把上行净荷归属到具体的 serverNode。空串表示调用方未提供归属身份。
	NodeID string
	// Direction 是本次转发方向："relay_to_clients"（被托管节点→客户端，即 serverNode 上行）
	// 或 "client_to_relay"（客户端→被托管节点）。计费只累计 serverNode 上行，据此过滤。
	Direction string
}

type BillableRecord struct {
	NodeID     string
	Direction  string
	SessionID  billingvoucher.Identifier
	Sequence   uint64
	Bytes      uint64
	RecordID   billingvoucher.Identifier
	Connection string
}

// ForwardHookConfig 转发 hook 配置
type ForwardHookConfig struct {
	// ThresholdBytes 是触发 hook 的字节数阈值（累计转发到这个大小就调用 hook）
	ThresholdBytes int64
	// Hook 是转发 hook 函数
	Hook ForwardHookFunc
	// ErrorHook 是错误处理 hook
	ErrorHook ForwardErrorHookFunc
	// BillableRoute 指定必须携带认证计费元数据的 E2E 业务路由。
	BillableRoute string
	// BillableRecordHook 在完整、唯一的 E2E 业务记录即将完成转发时同步调用。
	BillableRecordHook func(context.Context, *BillableRecord) error
	// BillableRecordRequired 决定指定 StreamGroup/方向是否必须执行认证记录门控。
	// nil 保持兼容，表示所有匹配 BillableRoute 的记录都必须执行门控。
	BillableRecordRequired func(nodeID, direction string) bool
	cacheOnce              sync.Once
	cache                  *globalRetransmitCache
	holdbackOnce           sync.Once
	holdback               *messageHoldback
	holdbackLimits         *messageHoldbackLimits
}

// forwardHookState 转发 hook 的运行时状态
type forwardHookState struct {
	config            *ForwardHookConfig
	nodeID            string // 该 hook 所属 StreamGroup 代表的对端 NodeId（计费按节点归因用）
	accumulatedBytes  int64
	accumulatedFrames int64
	lastFrame         *network.Frame
}

// newForwardHookState 创建 hook 状态。
// nodeID 是该 hook 所属 StreamGroup 代表的对端 NodeId，会填入每次触发的 ForwardStats，
// 供计费方向按 serverNode 归因上行流量；不需要归因时传空串即可（向后兼容）。
func newForwardHookState(config *ForwardHookConfig, nodeID string) *forwardHookState {
	if config == nil {
		return nil
	}
	return &forwardHookState{
		config: config,
		nodeID: nodeID,
	}
}

func (c *ForwardHookConfig) ensureRetransmitCache() *globalRetransmitCache {
	if c == nil {
		return nil
	}
	c.cacheOnce.Do(func() {
		c.cache = newGlobalRetransmitCache()
	})
	return c.cache
}

// onFrame 在每个帧转发前调用，返回 true 表示可以继续转发，false 表示需要停止
//
// 统计口径 = 净荷（goodput），不是带宽（throughput）：
//   - 首次见到的 Data 或 Retransmit 帧均累计其 payload 字节；
//   - **不含帧头**（每帧 39B 头不计）；
//   - 跳过 ACK(`FrameTypeAck`) / 帧大小控制帧(`FrameTypeFrameSizeChange`)；
//   - 仅在同一连接的 ACK 回收前（且仍在 TTL/配额内），`(message, seq, total, payload digest)`
//     完全一致的 Data/Retransmit 帧才视为已计量重传并跳过。
//
// 这样 relay 累计 ≈ 应用层 payload 总量；带宽口径（含双向/重传/头/ACK）见 git 历史。
func (s *forwardHookState) onFrame(ctx context.Context, f *network.Frame, direction string) bool {
	if s == nil || s.config == nil {
		return true
	}

	if f == nil {
		return true
	}
	if f.FrameType != network.FrameTypeData && f.FrameType != network.FrameTypeRetransmit {
		return true
	}
	if direction != "client_to_relay" && !s.config.ensureRetransmitCache().recordFrame(s.nodeID, f) {
		return true
	}

	// 只累计净荷字节（不含帧头）。
	frameSize := int64(len(f.Payload))
	s.accumulatedBytes += frameSize
	s.accumulatedFrames++
	s.lastFrame = f

	// 检查是否达到阈值
	if s.config.ThresholdBytes > 0 && s.accumulatedBytes >= s.config.ThresholdBytes && s.config.Hook != nil {
		stats := &ForwardStats{
			NodeID:      s.nodeID,
			Direction:   direction,
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

func (s *forwardHookState) billableRecordRequired(direction string) bool {
	if s == nil || s.config == nil || s.config.BillableRecordHook == nil {
		return false
	}
	if s.config.BillableRecordRequired == nil {
		return true
	}
	return s.config.BillableRecordRequired(s.nodeID, direction)
}

func (s *forwardHookState) observeBillableRecord(ctx context.Context, message *network.Message, direction string) error {
	header := message.Header
	if header.BillingSessionID == ([32]byte{}) || header.BillingSequence == 0 || header.BillingBytes == 0 {
		return fmt.Errorf("billing record metadata is required")
	}
	metadata, err := crypoto.InspectE2ERecord(message.Payload)
	if err != nil {
		return fmt.Errorf("inspect E2E billing record: %w", err)
	}
	if metadata.PlaintextBytes != header.BillingBytes {
		return fmt.Errorf("billing byte count mismatch: header=%d record=%d", header.BillingBytes, metadata.PlaintextBytes)
	}
	if header.BillingBytes > billingvoucher.CumulativeWindowBytes {
		return fmt.Errorf("single billing record exceeds 1 MiB window")
	}
	record := billingrecord.Record{
		SessionID:   billingvoucher.Identifier(header.BillingSessionID),
		Sequence:    header.BillingSequence,
		Bytes:       header.BillingBytes,
		Connection:  header.ConnectionId,
		E2ERecordID: metadata.MessageID,
		Ciphertext:  message.Payload,
	}
	recordID, err := record.ID()
	if err != nil {
		return err
	}
	return s.config.BillableRecordHook(ctx, &BillableRecord{
		NodeID: s.nodeID, Direction: direction, SessionID: record.SessionID,
		Sequence: record.Sequence, Bytes: record.Bytes, RecordID: recordID, Connection: record.Connection,
	})
}

func (s *forwardHookState) rejectRecord(ctx context.Context, frame *network.Frame, direction string, err error) bool {
	if s == nil || s.config == nil {
		return false
	}
	if s.config.ErrorHook != nil {
		s.config.ErrorHook(ctx, &ForwardErrorInfo{
			Stats: &ForwardStats{NodeID: s.nodeID, Direction: direction, LastFrame: frame},
			Err:   err, Direction: direction,
		})
	}
	return false
}

// wouldInvokeHook 保守判断下一帧是否可能跨过 hook 阈值。Relay 批处理在该边界前
// 先写完已积累批次，使外部计费/熔断回调仍只领先当前单帧，而不会领先整个写批次。
// 重传指纹去重可能让实际回调不发生；这种情况只会少合并一帧，不改变计量结果。
func (s *forwardHookState) wouldInvokeHook(f *network.Frame) bool {
	if s == nil || s.config == nil || f == nil {
		return false
	}
	if s.config.ThresholdBytes <= 0 || s.config.Hook == nil {
		return false
	}
	if f.FrameType != network.FrameTypeData && f.FrameType != network.FrameTypeRetransmit {
		return false
	}
	return s.accumulatedBytes+int64(len(f.Payload)) >= s.config.ThresholdBytes
}

func (s *forwardHookState) pendingAccounting() (int64, int64) {
	if s == nil {
		return 0, 0
	}
	return s.accumulatedBytes, s.accumulatedFrames
}

func (s *forwardHookState) rollbackUncommitted(bytes, frames int64) {
	if s == nil {
		return
	}
	if bytes > 0 {
		s.accumulatedBytes -= bytes
	}
	if frames > 0 {
		s.accumulatedFrames -= frames
	}
	if s.accumulatedBytes < 0 {
		s.accumulatedBytes = 0
	}
	if s.accumulatedFrames < 0 {
		s.accumulatedFrames = 0
	}
}
