package mux

import (
	"io"
	"sync"
)

// Stream is one logical byte stream over the session. It implements
// io.ReadWriteCloser so it can be piped to/from a net.Conn with io.Copy.
type Stream struct {
	sess *Session
	id   uint32

	mu       sync.Mutex
	buf      []byte
	dataCh   chan struct{} // signals new data or close
	closed   bool
	closedCh chan struct{}
	once     sync.Once
}

func newStream(sess *Session, id uint32) *Stream {
	return &Stream{
		sess:     sess,
		id:       id,
		dataCh:   make(chan struct{}, 1),
		closedCh: make(chan struct{}),
	}
}

// deliver appends inbound data and wakes any blocked Read.
func (st *Stream) deliver(data []byte) {
	if len(data) == 0 {
		return
	}
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	st.buf = append(st.buf, data...)
	st.mu.Unlock()
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

// Write implements io.Writer. Splits large writes into frames that fit
// comfortably inside a single P2P message.
//
// maxChunk 决定「一次 Write 切成几条 mux 消息」。每条 mux 消息 = 底层一次 SendMessage
// = 一个端到端 ACK 往返。chunk 越大，单个 RTT 摊到的字节越多，跨境高 RTT 链路吞吐越高
// （吞吐≈chunk/RTT，直到填满带宽时延积）。底层 SendMessage 内部仍按物理帧大小再分帧、
// 用 sendLock 一次性打包发出、靠部分 range ACK 增量确认——本改动不触碰那套传帧/ACK 逻辑。
// 可用环境变量 TUNNEL_MAX_CHUNK（字节）覆盖，便于压测找 BDP 拐点。
func (st *Stream) Write(p []byte) (int, error) {
	maxChunk := streamMaxChunk
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunk {
			chunk = chunk[:maxChunk]
		}
		if err := st.sess.sendFrame(frameData, st.id, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Close sends a CLOSE frame to the peer and tears down the local stream.
func (st *Stream) Close() error {
	st.mu.Lock()
	already := st.closed
	st.mu.Unlock()
	if !already {
		_ = st.sess.sendFrame(frameClose, st.id, nil)
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
