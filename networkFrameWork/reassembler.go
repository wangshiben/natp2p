package networkFrameWork

import (
	"io"
	"sync"
)

// =============================================================================
// reassembler —— 条带化逻辑连接的入站重排器
//
// 多条物理 leg 并行送达带连续 seq 的分片，到达可能乱序（不同 TCP 的 RTT/拥塞不同）。
// reassembler 按 seq 严格还原顺序后吐给 LogicalConn.Read：
//   - nextSeq 是下一个应交付的序号；命中则直接进入有序缓冲 ready，并尽量连追后续已到的。
//   - 未来序号暂存 pending（map[seq][]byte），等缺口补齐再搬入 ready。
//   - pending 设容量上限，超限视为异常（leg 长时间断流造成无界缓冲），关闭重排器止血。
// =============================================================================

const (
	// reasmMaxPending 乱序暂存的最大分片数。超过视为某 leg 严重滞后/断流，关闭止血。
	// M 条 leg 正常乱序窗口很小（几个分片），给足余量应对短时抖动。
	reasmMaxPending = 4096
)

type reassembler struct {
	mu      sync.Mutex
	cond    *sync.Cond
	nextSeq uint64            // 下一个应交付的逻辑连接级序号
	pending map[uint64][]byte // 未来序号的乱序暂存
	ready   []byte            // 已按序就绪、待 Read 取走的字节
	closed  bool
	overflow bool // pending 溢出（异常），Read 在排空 ready 后返回错误
}

func newReassembler() *reassembler {
	r := &reassembler{
		pending: make(map[uint64][]byte),
	}
	r.cond = sync.NewCond(&r.mu)
	return r
}

// push 投递一个带 seq 的分片（由各 leg 的 deliverHook 调用，可能乱序、可能并发）。
func (r *reassembler) push(seq uint64, data []byte) {
	if len(data) == 0 {
		return
	}
	// 复制一份：底层读缓冲会被复用，不能持有其切片。
	buf := make([]byte, len(data))
	copy(buf, data)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if seq < r.nextSeq {
		// 已交付过的旧序号（重复）：丢弃。
		return
	}
	if seq == r.nextSeq {
		// 命中期望序号：进入 ready，并连追 pending 中后续连续的分片。
		r.ready = append(r.ready, buf...)
		r.nextSeq++
		for {
			nb, ok := r.pending[r.nextSeq]
			if !ok {
				break
			}
			delete(r.pending, r.nextSeq)
			r.ready = append(r.ready, nb...)
			r.nextSeq++
		}
		r.cond.Broadcast()
		return
	}
	// 未来序号：暂存等缺口补齐。
	if _, exists := r.pending[seq]; !exists {
		if len(r.pending) >= reasmMaxPending {
			// 乱序窗口溢出（某 leg 断流）：止血。
			r.overflow = true
			r.cond.Broadcast()
			return
		}
		r.pending[seq] = buf
	}
}

// read 取走已按序就绪的字节；无就绪数据时阻塞，直到有数据 / 关闭 / 溢出。
func (r *reassembler) read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		if len(r.ready) > 0 {
			n := copy(p, r.ready)
			r.ready = r.ready[n:]
			return n, nil
		}
		if r.overflow {
			return 0, errMuxStreamGone
		}
		if r.closed {
			return 0, io.EOF
		}
		r.cond.Wait()
	}
}

// close 唤醒所有阻塞的 read 并标记关闭。
func (r *reassembler) close() {
	r.mu.Lock()
	r.closed = true
	r.pending = nil
	r.cond.Broadcast()
	r.mu.Unlock()
}
