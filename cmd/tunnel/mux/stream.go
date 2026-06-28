package mux

import (
	"io"
	"sync"
	"sync/atomic"
)

// Stream is one logical byte stream over the session. It implements
// io.ReadWriteCloser so it can be piped to/from a net.Conn with io.Copy.
type Stream struct {
	sess *Session
	id   uint32

	// sendSeq 是本流出站 DATA 帧的单调序号分配器(每帧 +1)。Close 时其值即 finalSeq。
	sendSeq atomic.Uint64

	mu       sync.Mutex
	buf      []byte
	dataCh   chan struct{} // signals new data or close
	closed   bool
	closedCh chan struct{}
	once     sync.Once

	// 收端重排状态(均受 mu 保护):
	//   recvExpected 下一个应投递的序号；reorder 暂存乱序先到的帧；
	//   finalSeq/haveFinal 记录对端 CLOSE 携带的 finalSeq，收端排空到它才真正关闭(防丢尾)。
	recvExpected uint64
	reorder      map[uint64][]byte
	finalSeq     uint64
	haveFinal    bool
}

func newStream(sess *Session, id uint32) *Stream {
	return &Stream{
		sess:     sess,
		id:       id,
		dataCh:   make(chan struct{}, 1),
		closedCh: make(chan struct{}),
		reorder:  make(map[uint64][]byte),
	}
}

// deliver 收到一个带序号的 DATA 帧：按 recvExpected 重排，连续前缀按序追加到读缓冲。
// 流水线下并发在途消息可能乱序到达(不同 ACK 时序/重传)，故必须按 seq 重排，
// 否则字节流顺序错乱、文件损坏。
func (st *Stream) deliver(seq uint64, data []byte) {
	if len(data) == 0 {
		return
	}
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	if seq < st.recvExpected {
		st.mu.Unlock() // 重复帧(重传/failover 导致)，已投递过，丢弃
		return
	}
	if seq == st.recvExpected {
		st.buf = append(st.buf, data...)
		st.recvExpected++
		// 排空 reorder 中后续连续序号
		for {
			next, ok := st.reorder[st.recvExpected]
			if !ok {
				break
			}
			st.buf = append(st.buf, next...)
			delete(st.reorder, st.recvExpected)
			st.recvExpected++
		}
	} else {
		// 乱序先到：暂存(拷一份，调用方的底层 buffer 可能复用)
		cp := make([]byte, len(data))
		copy(cp, data)
		st.reorder[seq] = cp
	}
	reachedFinal := st.haveFinal && st.recvExpected >= st.finalSeq
	st.mu.Unlock()

	st.signalData()
	if reachedFinal {
		st.finishClose()
	}
}

// deliverClose 收到对端 CLOSE(携带 finalSeq)。若本流已排空到 finalSeq 则立即关闭；
// 否则记录 finalSeq，待 deliver 把缺口补齐、recvExpected 追上 finalSeq 时再关(防丢尾部数据)。
func (st *Stream) deliverClose(finalSeq uint64) {
	st.mu.Lock()
	st.finalSeq = finalSeq
	st.haveFinal = true
	reached := st.recvExpected >= finalSeq
	st.mu.Unlock()
	if reached {
		st.finishClose()
	}
}

// finishClose 把本流标记关闭并从会话表移除(收端排空完成或本端主动关后调用)。
func (st *Stream) finishClose() {
	st.sess.removeStream(st.id)
	st.closeLocal()
}

func (st *Stream) signalData() {
	select {
	case st.dataCh <- struct{}{}:
	default:
	}
}

// Read implements io.Reader. Blocks until data is available or the stream
// closes (then returns io.EOF once the buffer drains).
func (st *Stream) Read(p []byte) (int, error) {
	for {
		st.mu.Lock()
		if len(st.buf) > 0 {
			n := copy(p, st.buf)
			st.buf = st.buf[n:]
			st.mu.Unlock()
			return n, nil
		}
		closed := st.closed
		st.mu.Unlock()

		if closed {
			return 0, io.EOF
		}

		select {
		case <-st.dataCh:
		case <-st.closedCh:
		case <-st.sess.ctx.Done():
			return 0, io.EOF
		}
	}
}

// Write implements io.Writer. 把一次 Write 切成多个 chunk，并发(受发送窗口限制)发出，
// 等全部送达(端到端 ACK)后返回——这就是流水线：单次 Write 内 W 个 chunk 同时在途，
// 吞吐≈W×chunk/RTT，而非旧的逐 chunk 停等(chunk/RTT)。每个 chunk 带单调序号，
// 收端按序号重排，故乱序完成不影响字节流顺序。返回后底层 buffer 可安全复用(已等齐)。
func (st *Stream) Write(p []byte) (int, error) {
	maxChunk := streamMaxChunk
	total := len(p)

	var wg sync.WaitGroup
	var firstErr atomic.Pointer[error]

	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunk {
			chunk = chunk[:maxChunk]
		}
		seq := st.sendSeq.Add(1) - 1 // 序号从 0 开始
		wg.Add(1)
		go func(seq uint64, data []byte) {
			defer wg.Done()
			if err := st.sess.sendData(st.id, seq, data); err != nil {
				e := err
				firstErr.CompareAndSwap(nil, &e)
			}
		}(seq, chunk)
		p = p[len(chunk):]
	}
	wg.Wait()

	if ep := firstErr.Load(); ep != nil {
		return 0, *ep
	}
	return total, nil
}

// Close sends a CLOSE frame (carrying finalSeq = total DATA frames sent) to the peer
// and tears down the local stream. 调用前所有 DATA 已在 Write 中等齐发送完成，
// 故 CLOSE 之后对端不会再收到本流的 DATA(finalSeq 即收端排空目标)。
func (st *Stream) Close() error {
	st.mu.Lock()
	already := st.closed
	st.mu.Unlock()
	if !already {
		finalSeq := st.sendSeq.Load()
		_ = st.sess.sendClose(st.id, finalSeq)
	}
	st.sess.removeStream(st.id)
	st.closeLocal()
	return nil
}

// closeLocal marks the stream closed without sending a frame (used when the
// peer initiated the close or the session died).
func (st *Stream) closeLocal() {
	st.once.Do(func() {
		st.mu.Lock()
		st.closed = true
		st.mu.Unlock()
		close(st.closedCh)
		select {
		case st.dataCh <- struct{}{}:
		default:
		}
	})
}
