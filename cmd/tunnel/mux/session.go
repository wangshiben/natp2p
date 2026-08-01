// Package mux multiplexes many logical byte streams over a single
// p2pnode.Connection. Each P2P Message carries exactly one frame:
//
//	[1 byte type][4 bytes streamID big-endian][payload...]
//
// Frame types: OPEN (client announces a new stream), DATA (stream bytes),
// CLOSE (stream finished), and SESSION_CLOSE (the tunnel is shutting down).
// The side that dials local TCP connections opens streams; the peer accepts
// them via the Accept channel.
package mux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"bnfs_p2p/p2pnode"
)

// defaultMaxChunk 是单条 mux 消息承载的最大业务字节数（见 Stream.Write 注释）。
// 64KB：配合流水线(发送窗口 W>1)后，吞吐≈W×chunk/RTT，单 chunk 不必很大；
// 取中等值让重传粒度更细（大 chunk 会放大单次重传的丢失代价）。可用 TUNNEL_MAX_CHUNK 覆盖。
const defaultMaxChunk = 64 * 1024

// 发送窗口分成两级：每条流最多 8 个 DATA chunk 在途，整个 carrier 最多 32 个。
// 每流窗口保证单流可以填满常见公网 BDP；carrier 窗口限制总内存与底层 ACK tracker，
// 同时避免旧的全会话 8 槽让大量业务流彼此停等。
// TUNNEL_STREAM_SEND_WINDOW 和 TUNNEL_SEND_WINDOW 可分别覆盖两级窗口。
const (
	defaultStreamSendWindow  = 8
	defaultSessionSendWindow = 32
	sessionCloseSendTimeout  = 30 * time.Second
	streamCloseSendTimeout   = 30 * time.Second
)

var streamMaxChunk = resolveMaxChunk()

func resolveMaxChunk() int {
	if v := os.Getenv("TUNNEL_MAX_CHUNK"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1024 {
			return n
		}
	}
	return defaultMaxChunk
}

func resolveSessionSendWindow() int {
	if v := os.Getenv("TUNNEL_SEND_WINDOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			return n
		}
	}
	return defaultSessionSendWindow
}

func resolveStreamSendWindow() int {
	if v := os.Getenv("TUNNEL_STREAM_SEND_WINDOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			return n
		}
	}
	return defaultStreamSendWindow
}

const (
	frameOpen         byte = 1
	frameData         byte = 2
	frameClose        byte = 3
	frameSessionClose byte = 4
	frameReset        byte = 5
)

// 帧头布局：
//
//	OPEN：       [1 type][4 streamID]                — 无序号
//	DATA/CLOSE： [1 type][4 streamID][8 seq]         — 带 per-stream 单调序号
//
// DATA 的 seq 供收端重排（流水线下并发在途消息可能乱序到达）；
// CLOSE 的 seq 携带 finalSeq（= 发端已发 DATA 帧总数），收端据此排空到末尾再关，防丢尾。
const (
	headerBase = 5  // type + streamID
	headerSeq  = 13 // type + streamID + seq(8)
)

// ErrSessionClosed is returned once the underlying connection is gone.
var ErrSessionClosed = errors.New("mux: session closed")

// Session multiplexes streams over one p2pnode.Connection.
type Session struct {
	conn   p2pnode.Connection
	ctx    context.Context
	cancel context.CancelFunc

	// sessionSendWindow 是 carrier 级发送窗口：限制全会话同时在途的消息数。
	// 取代旧的 writeMu 跨 ACK 串行——旧实现把 conn.Send(阻塞到端到端 ACK)整段锁住，
	// 全会话同时只有 1 条消息在途(窗口=1)。改为信号量后允许 W 条并发在途，conn.Send
	// 并发安全(底层每条消息独立 messageId/ackTracker)。
	sessionSendWindow chan struct{}
	streamSendWindow  int

	streamCloseTimeout time.Duration

	mu       sync.Mutex
	streams  map[uint32]*Stream
	nextID   uint32
	accept   chan *Stream
	isClient bool
	closed   bool
}

// NewSession wraps conn. If isClient is true, OpenStream allocates odd IDs;
// the server side allocates nothing and only accepts. Using a client flag
// avoids ID collisions if both sides ever open (here only client opens).
func NewSession(ctx context.Context, conn p2pnode.Connection, isClient bool) *Session {
	cctx, cancel := context.WithCancel(ctx)
	s := &Session{
		conn:               conn,
		ctx:                cctx,
		cancel:             cancel,
		sessionSendWindow:  make(chan struct{}, resolveSessionSendWindow()),
		streamSendWindow:   resolveStreamSendWindow(),
		streamCloseTimeout: streamCloseSendTimeout,
		streams:            make(map[uint32]*Stream),
		accept:             make(chan *Stream, 16),
		isClient:           isClient,
		nextID:             1,
	}
	go s.readLoop()
	return s
}

// Accept returns the next stream opened by the peer. Blocks until one arrives
// or the session closes (then returns nil, ErrSessionClosed).
func (s *Session) Accept() (*Stream, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrSessionClosed
	}
	select {
	case st := <-s.accept:
		s.mu.Lock()
		closed = s.closed
		s.mu.Unlock()
		if closed {
			st.closeLocal()
			return nil, ErrSessionClosed
		}
		return st, nil
	case <-s.ctx.Done():
		return nil, ErrSessionClosed
	}
}

// OpenStream allocates a new stream ID and sends an OPEN frame to the peer.
func (s *Session) OpenStream() (*Stream, error) {
	return s.OpenStreamContext(s.ctx)
}

func (s *Session) OpenStreamContext(ctx context.Context) (*Stream, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrSessionClosed
	}
	id := s.nextID
	s.nextID += 2
	st := newStream(s, id)
	s.streams[id] = st
	s.mu.Unlock()

	if err := s.sendOpen(ctx, id); err != nil {
		s.removeStream(id)
		return nil, fmt.Errorf("open stream: %w", err)
	}
	return st, nil
}

// Close tears down the session and all streams.
func (s *Session) Close() error {
	return s.shutdown(true)
}

func (s *Session) shutdown(notifyPeer bool) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	streams := make([]*Stream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.streams = make(map[uint32]*Stream)
	s.mu.Unlock()

	for _, st := range streams {
		st.closeLocal()
	}

	var notifyErr error
	if notifyPeer {
		notifyCtx, notifyCancel := context.WithTimeout(context.Background(), sessionCloseSendTimeout)
		notifyErr = s.sendSessionClose(notifyCtx)
		notifyCancel()
	}

	s.cancel()
	return errors.Join(notifyErr, s.conn.Close())
}
