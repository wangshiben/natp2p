package networkFrameWork

import (
	"net"
	"sync"
	"time"
)

// =============================================================================
// LogicalConn —— 逻辑连接抽象（逻辑/物理 N:M 解耦的一等公民）
//
// 设计（见 plan: relay-pool-nm-abstraction）：
//   - 一条 LogicalConn 对应一条业务跨中继会话（connID），实现 net.Conn，桥接持有它。
//   - 它由 1..M 条物理 leg（*MuxStream，分布在不同 physConn 上）承载：
//       * width=1（模式 A 退化 / 默认）：纯转发到唯一 leg，零额外开销、字节顺序天然保证。
//       * width>1（模式 B 条带化）：出站经 legScheduler 分片摊到多 leg，入站经 reassembler
//         按序号重排。条带化的发/收在后续阶段(F3)接入；F1 仅落抽象骨架，width 恒=1。
//
// 关键：桥接两端只认 net.Conn 接口（pumpLocalToPeer/pumpPeerToLocal 读写 net.Conn），
// 因此把 peerConn 从 *MuxStream 换成 *LogicalConn 后，桥接代码零改动。
// =============================================================================

// legScheduler 决定一次出站写应落到哪条物理 leg（模式 B 用；模式 A 恒选唯一 leg）。
type legScheduler interface {
	// pick 从 legs 中选一条承载本次 chunkLen 字节的出站写。
	pick(legs []*MuxStream, chunkLen int) *MuxStream
}

// singleLeg 是 width=1 的零开销调度：恒返回唯一 leg。
type singleLeg struct{}

func (singleLeg) pick(legs []*MuxStream, _ int) *MuxStream {
	if len(legs) == 0 {
		return nil
	}
	return legs[0]
}

// LogicalConn 是逻辑连接，实现 net.Conn。F1：单 leg 纯转发。
type LogicalConn struct {
	id    string
	mu    sync.Mutex
	legs  []*MuxStream
	sched legScheduler
	// reasm 仅 width>1 时启用（F3 接入）；nil 表示单 leg bypass，直接读唯一 leg。
	reasm *reassembler
}

// newLogicalConn 用给定 legs 组装一条逻辑连接。len(legs)==1 时为单 leg 直通。
func newLogicalConn(id string, legs []*MuxStream, sched legScheduler) *LogicalConn {
	if sched == nil {
		sched = singleLeg{}
	}
	return &LogicalConn{id: id, legs: legs, sched: sched}
}

// NewSingleLegConn 包装单条 MuxStream 为 LogicalConn（width=1）。
func NewSingleLegConn(st *MuxStream) *LogicalConn {
	return newLogicalConn(st.StreamID(), []*MuxStream{st}, singleLeg{})
}

// LogicalID 返回逻辑连接 ID（= 业务 connID）。
func (lc *LogicalConn) LogicalID() string { return lc.id }

// Width 返回当前物理 leg 数。
func (lc *LogicalConn) Width() int {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return len(lc.legs)
}

// snapshotLegs 返回 legs 的快照（持锁外用）。
func (lc *LogicalConn) snapshotLegs() []*MuxStream {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	out := make([]*MuxStream, len(lc.legs))
	copy(out, lc.legs)
	return out
}

// Read 实现 io.Reader。
// 单 leg（reasm==nil）：直接读唯一 leg，字节顺序由该物理连接的 readLoop 天然保证。
// 多 leg：经 reassembler 归并（F3）。
func (lc *LogicalConn) Read(p []byte) (int, error) {
	if lc.reasm == nil {
		legs := lc.snapshotLegs()
		if len(legs) == 0 {
			return 0, errMuxStreamGone
		}
		return legs[0].Read(p)
	}
	return lc.reasm.read(p)
}

// Write 实现 io.Writer。
// 单 leg：直接写唯一 leg（与原 MuxStream.Write 等价，零额外开销）。
// 多 leg：经 legScheduler 把分片摊到多条 leg（F3 接入分片+序号）。
func (lc *LogicalConn) Write(p []byte) (int, error) {
	legs := lc.snapshotLegs()
	if len(legs) == 0 {
		return 0, errMuxStreamGone
	}
	if len(legs) == 1 {
		return legs[0].Write(p)
	}
	// width>1 的分片写在 F3 实现；F1 不会走到这里（width 恒=1）。
	return lc.writeStriped(p, legs)
}

// writeStriped 是条带化写的占位（F3 实现真正的分片+序号）。F1 退化为顺序写首 leg。
func (lc *LogicalConn) writeStriped(p []byte, legs []*MuxStream) (int, error) {
	return legs[0].Write(p)
}

// Close 关闭所有 leg。
func (lc *LogicalConn) Close() error {
	legs := lc.snapshotLegs()
	var firstErr error
	for _, st := range legs {
		if err := st.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// --- net.Conn 其余方法：逻辑连接之上无独立地址/截止语义，安全占位 ---

func (lc *LogicalConn) LocalAddr() net.Addr  { return bridgeMuxAddr{id: lc.id} }
func (lc *LogicalConn) RemoteAddr() net.Addr { return bridgeMuxAddr{id: lc.id} }
func (lc *LogicalConn) SetDeadline(t time.Time) error      { return nil }
func (lc *LogicalConn) SetReadDeadline(t time.Time) error  { return nil }
func (lc *LogicalConn) SetWriteDeadline(t time.Time) error { return nil }

// reassembler 是多 leg 入站重排器，F3 实现；F1 仅声明占位以稳定 LogicalConn 字段。
type reassembler struct{}

func (r *reassembler) read(p []byte) (int, error) { return 0, errMuxStreamGone }
