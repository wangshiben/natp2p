// Package mux multiplexes many logical byte streams over a single
// p2pnode.Connection. Each P2P Message carries exactly one frame:
//
//	[1 byte type][4 bytes streamID big-endian][payload...]
//
// Frame types: OPEN (client announces a new stream), DATA (stream bytes),
// CLOSE (stream finished). The side that dials local TCP connections opens
// streams; the peer accepts them via the Accept channel.
package mux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"bnfs_p2p/p2pnode"
)

// defaultMaxChunk 是单条 mux 消息承载的最大业务字节数（见 Stream.Write 注释）。
// 64KB：配合流水线(发送窗口 W>1)后，吞吐≈W×chunk/RTT，单 chunk 不必很大；
// 取中等值让重传粒度更细（大 chunk 会放大单次重传的丢失代价）。可用 TUNNEL_MAX_CHUNK 覆盖。
const defaultMaxChunk = 64 * 1024

// defaultSendWindow 是全会话允许同时在途(未收齐端到端 ACK)的 DATA 消息数。
// 流水线核心参数：把"窗口=1 停等"提升为"窗口=W"，吞吐≈W×chunk/RTT，直到填满 BDP 或撞节流。
// W≈BDP/chunk；240ms RTT、~1MB/s、chunk 64KB → BDP≈240KB → W≈4，取 8 留余量。
// 可用 TUNNEL_SEND_WINDOW 覆盖。
const defaultSendWindow = 8

var streamMaxChunk = resolveMaxChunk()

func resolveMaxChunk() int {
	if v := os.Getenv("TUNNEL_MAX_CHUNK"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1024 {
			return n
		}
	}
	return defaultMaxChunk
}

func resolveSendWindow() int {
	if v := os.Getenv("TUNNEL_SEND_WINDOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			return n
		}
	}
	return defaultSendWindow
}

const (
	frameOpen  byte = 1
	frameData  byte = 2
	frameClose byte = 3
)

// 帧头布局：
//   OPEN：       [1 type][4 streamID]                — 无序号
//   DATA/CLOSE： [1 type][4 streamID][8 seq]         — 带 per-stream 单调序号
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

	// sendWindow 是发送窗口信号量(容量 = W)：限制全会话同时在途的消息数。
	// 取代旧的 writeMu 跨 ACK 串行——旧实现把 conn.Send(阻塞到端到端 ACK)整段锁住，
	// 全会话同时只有 1 条消息在途(窗口=1)。改为信号量后允许 W 条并发在途，conn.Send
	// 并发安全(底层每条消息独立 messageId/ackTracker)。
	sendWindow chan struct{}

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
		conn:       conn,
		ctx:        cctx,
		cancel:     cancel,
		sendWindow: make(chan struct{}, resolveSendWindow()),
		streams:    make(map[uint32]*Stream),
		accept:     make(chan *Stream, 16),
		isClient:   isClient,
		nextID:     1,
	}
	go s.readLoop()
	return s
}

// Accept returns the next stream opened by the peer. Blocks until one arrives
// or the session closes (then returns nil, ErrSessionClosed).
func (s *Session) Accept() (*Stream, error) {
	select {
	case st, ok := <-s.accept:
		if !ok {
			return nil, ErrSessionClosed
		}
		return st, nil
	case <-s.ctx.Done():
		return nil, ErrSessionClosed
	}
}

// OpenStream allocates a new stream ID and sends an OPEN frame to the peer.
func (s *Session) OpenStream() (*Stream, error) {
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

	if err := s.sendOpen(id); err != nil {
		s.removeStream(id)
		return nil, fmt.Errorf("open stream: %w", err)
	}
	return st, nil
}

// Close tears down the session and all streams.
func (s *Session) Close() error {
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
	close(s.accept)
	s.mu.Unlock()

	s.cancel()
	for _, st := range streams {
		st.closeLocal()
	}
	return s.conn.Close()
}
