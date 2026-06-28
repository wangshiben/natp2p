package networkFrameWork

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// LogicalConn —— 逻辑连接抽象（逻辑/物理 N:M 解耦的一等公民）
//
// 设计（见 plan: relay-pool-nm-abstraction）：
//   - 一条 LogicalConn 对应一条业务跨中继会话（connID），实现 net.Conn，桥接持有它。
//   - 它由 1..M 条物理 leg（*MuxStream，分布在不同 physConn 上）承载：
//       * width=1（模式 A 退化 / 默认）：纯转发到唯一 leg，零额外开销、字节顺序天然保证。
//       * width>1（模式 B 条带化）：出站把字节切片轮转摊到多 leg 并打逻辑连接级连续序号；
//         入站经 reassembler 按序号重排还原字节流。多 leg 各走独立物理 TCP（独立 cwnd），
//         单条逻辑连接也能聚合多 TCP 带宽、规避单 TCP 串行写与队头阻塞。
//
// 关键：桥接两端只认 net.Conn 接口（pumpLocalToPeer/pumpPeerToLocal 读写 net.Conn），
// 因此把 peerConn 从 *MuxStream 换成 *LogicalConn 后，桥接代码零改动。
// =============================================================================

// stripeChunkSize 是条带化出站的分片粒度（与 MuxStream.Write 的 maxChunk 一致）。
const stripeChunkSize = 32 * 1024

// legScheduler 决定一次出站写应落到哪条物理 leg（模式 B 用；模式 A 恒选唯一 leg）。
type legScheduler interface {
	// pick 从 legs 中为第 seq 个分片选一条承载的出站 leg。
	pick(legs []*MuxStream, seq uint64) *MuxStream
}

// singleLeg 是 width=1 的零开销调度：恒返回唯一 leg。
type singleLeg struct{}

func (singleLeg) pick(legs []*MuxStream, _ uint64) *MuxStream {
	if len(legs) == 0 {
		return nil
	}
	return legs[0]
}

// roundRobinLeg 把连续分片轮转摊到各 leg（模式 B 默认）。
type roundRobinLeg struct{}

func (roundRobinLeg) pick(legs []*MuxStream, seq uint64) *MuxStream {
	if len(legs) == 0 {
		return nil
	}
	return legs[int(seq%uint64(len(legs)))]
}

// LogicalConn 是逻辑连接，实现 net.Conn。
type LogicalConn struct {
	id    string
	mu    sync.Mutex
	legs  []*MuxStream
	sched legScheduler

	// 出站逻辑连接级序号（每个分片 +1），条带化时随 DATA 帧发出。
	writeSeq uint64

	// reasm 仅 width>1 时启用：按 seq 重排多 leg 乱序字节。nil 表示单 leg 直通。
	reasm *reassembler
}

// newLogicalConn 用给定 legs 组装一条逻辑连接。
//   - len(legs)==1：单 leg 直通（reasm=nil，sched=singleLeg）。
//   - len(legs)>1：条带化（reasm 启用，sched=roundRobin）。
func newLogicalConn(id string, legs []*MuxStream, sched legScheduler) *LogicalConn {
	lc := &LogicalConn{id: id, legs: legs}
	if len(legs) > 1 {
		if sched == nil {
			sched = roundRobinLeg{}
		}
		lc.sched = sched
		lc.reasm = newReassembler()
		lc.attachReasmHooks()
	} else {
		lc.sched = singleLeg{}
	}
	return lc
}

// NewSingleLegConn 包装单条 MuxStream 为 LogicalConn（width=1）。
func NewSingleLegConn(st *MuxStream) *LogicalConn {
	return newLogicalConn(st.StreamID(), []*MuxStream{st}, singleLeg{})
}

// NewStripedConn 用 M 条 leg 组装一条条带化逻辑连接（width=M>1）。
// 所有 leg 必须属于同一逻辑连接（同 streamID/groupID），分布在不同物理连接上。
func NewStripedConn(id string, legs []*MuxStream) *LogicalConn {
	return newLogicalConn(id, legs, roundRobinLeg{})
}

// attachReasmHooks 把每条 leg 的入站投递重定向到本逻辑连接的重排器，
// 并启动看门狗：任一 leg 关闭即视为逻辑连接结束（关重排器唤醒阻塞的 Read）。
func (lc *LogicalConn) attachReasmHooks() {
	for _, st := range lc.legs {
		st.setDeliverHook(func(seq uint64, data []byte) {
			lc.reasm.push(seq, data)
		})
	}
	// 看门狗：任一 leg 的 closedCh 触发 → 关重排器。条带化下任一 leg 断开都意味着
	// 字节流不完整，必须让 Read 解除阻塞（返回 EOF），避免永久挂起。
	for _, st := range lc.legs {
		go func(s *MuxStream) {
			select {
			case <-s.closedCh:
			case <-s.sess.ctx.Done():
			}
			lc.reasm.close()
		}(st)
	}
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
// 多 leg：经 reassembler 按 seq 归并还原顺序。
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
// 多 leg：按 stripeChunkSize 切片，每片打连续 seq 并经调度器轮转到不同 leg 并行发送。
func (lc *LogicalConn) Write(p []byte) (int, error) {
	legs := lc.snapshotLegs()
	if len(legs) == 0 {
		return 0, errMuxStreamGone
	}
	if len(legs) == 1 {
		return legs[0].Write(p)
	}
	return lc.writeStriped(p, legs)
}

// writeStriped 条带化写：切片 + 连续序号 + 轮转多 leg。
// 序号在逻辑连接内严格连续递增，接收端据此重排（即使各 leg 到达乱序）。
func (lc *LogicalConn) writeStriped(p []byte, legs []*MuxStream) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > stripeChunkSize {
			chunk = chunk[:stripeChunkSize]
		}
		seq := atomic.AddUint64(&lc.writeSeq, 1) - 1 // 从 0 开始的连续序号
		leg := lc.sched.pick(legs, seq)
		if leg == nil {
			return total, errMuxStreamGone
		}
		if err := leg.writeChunkSeq(seq, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Close 关闭所有 leg，并唤醒重排器上阻塞的 Read。
func (lc *LogicalConn) Close() error {
	legs := lc.snapshotLegs()
	var firstErr error
	for _, st := range legs {
		if err := st.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if lc.reasm != nil {
		lc.reasm.close()
	}
	return firstErr
}

// --- net.Conn 其余方法：逻辑连接之上无独立地址/截止语义，安全占位 ---

func (lc *LogicalConn) LocalAddr() net.Addr            { return bridgeMuxAddr{id: lc.id} }
func (lc *LogicalConn) RemoteAddr() net.Addr           { return bridgeMuxAddr{id: lc.id} }
func (lc *LogicalConn) SetDeadline(t time.Time) error      { return nil }
func (lc *LogicalConn) SetReadDeadline(t time.Time) error  { return nil }
func (lc *LogicalConn) SetWriteDeadline(t time.Time) error { return nil }
