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
// 512KB：在双跳 ~240ms RTT 上把单 RTT 吞吐从 32KB/RTT(~136KB/s) 提升约一个数量级，
// 同时单条消息不至于过大导致重传粒度太粗。可用 TUNNEL_MAX_CHUNK 覆盖。
const defaultMaxChunk = 512 * 1024

var streamMaxChunk = resolveMaxChunk()

func resolveMaxChunk() int {
	if v := os.Getenv("TUNNEL_MAX_CHUNK"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1024 {
			return n
		}
	}
	return defaultMaxChunk
}

const (
	frameOpen  byte = 1
	frameData  byte = 2
	frameClose byte = 3
)

const headerLen = 5

// ErrSessionClosed is returned once the underlying connection is gone.
var ErrSessionClosed = errors.New("mux: session closed")

// Session multiplexes streams over one p2pnode.Connection.
type Session struct {
	conn   p2pnode.Connection
	ctx    context.Context
	cancel context.CancelFunc

	writeMu sync.Mutex // serializes conn.Send

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
		conn:     conn,
		ctx:      cctx,
		cancel:   cancel,
		streams:  make(map[uint32]*Stream),
		accept:   make(chan *Stream, 16),
		isClient: isClient,
		nextID:   1,
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

	if err := s.sendFrame(frameOpen, id, nil); err != nil {
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
