package networkFrameWork

import (
	"bnfs_p2p/network"
	"errors"
	"sync"
	"time"
)

// errAckTimeout 是 SendMessage 等待 ACK 超时时使用的哨兵错误。
// 它不是连接级错误：sender 接到 errAckTimeout 后会触发指数退避重传，
// 而不是直接 failAndClose 整条流。
var errAckTimeout = errors.New("ack timeout")

// ackTracker 跟踪一条出站消息的 ACK 状态。
//
// 每次 SendMessage 把消息分成 total 帧后，都会建一个 ackTracker：
//   - acked 记录哪些 SeqId 的帧已被对端确认；
//   - ch    用于在收到新的 ACK 时唤醒 waitAck，避免轮询；
//   - mu    保护 acked map 的并发读写。
type ackTracker struct {
	total uint32
	mu    sync.Mutex
	acked map[uint32]bool
	ch    chan struct{}
}

func newAckTracker(total uint32) *ackTracker {
	return &ackTracker{
		total: total,
		acked: make(map[uint32]bool, total),
		ch:    make(chan struct{}, 1),
	}
}

// update 把对端 ACK 帧里携带的 ranges 全部标记为已确认，并唤醒 waitAck。
func (a *ackTracker) update(ranges []network.AckRange) {
	a.mu.Lock()
	for _, r := range ranges {
		for s := r.Start; s <= r.End; s++ {
			a.acked[s] = true
		}
	}
	a.mu.Unlock()
	a.signal()
}

// complete 表示这条消息的所有帧都已被对端确认。
func (a *ackTracker) complete() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return uint32(len(a.acked)) >= a.total
}

// ackedCount 返回当前已确认的帧数。waitAck 用它判断「是否有新进展」以决定是否重置无进展计时器。
func (a *ackTracker) ackedCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.acked)
}

// missing 列出尚未被确认的 SeqId，按升序返回。retransmit 路径会基于它构造重传帧。
func (a *ackTracker) missing() []uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]uint32, 0)
	for s := uint32(0); s < a.total; s++ {
		if !a.acked[s] {
			out = append(out, s)
		}
	}
	return out
}

// signal 非阻塞地唤醒 waitAck；ch 缓冲为 1，重复信号会被合并。
func (a *ackTracker) signal() {
	select {
	case a.ch <- struct{}{}:
	default:
	}
}

// recvTracker 跟踪一条入站消息的 ACK 触发条件。
//
//	total          这条消息一共多少帧（取自首帧 Header）。
//	framesSinceAck 自上次 ACK 至今又收到了几帧；累计到阈值就批量回 ACK。
//	lastFrameTime  最近一次收到帧的时间；recvAckTimer 用它判断是否进入空闲态、需要补 ACK。
type recvTracker struct {
	total          uint32
	framesSinceAck int
	lastFrameTime  time.Time
}
