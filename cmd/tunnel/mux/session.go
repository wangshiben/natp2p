// Package mux 在单条 p2pnode.Connection 上复用多条逻辑字节流。
// 每条 P2P Message 只携带一个帧：
//
//	[1 byte type][4 bytes streamID big-endian][payload...]（字段长度均为字节）
//
// 帧类型包括 OPEN（客户端声明新流）、DATA（流数据）、CLOSE（流结束）和
// SESSION_CLOSE（隧道关闭）。拨打本地 TCP 连接的一侧打开流，对端通过 Accept 通道接收。
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

// ErrSessionClosed 表示底层连接已经断开。
var ErrSessionClosed = errors.New("mux: session closed")

// Session 在一条 p2pnode.Connection 上复用多条流。
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

// NewSession 包装 conn。isClient 为 true 时 OpenStream 分配奇数 ID；
// 服务端只接收而不分配。客户端标志可在双方都可能开流时避免 ID 冲突，本实现仅客户端开流。
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

// Accept 返回对端打开的下一条流；它会阻塞到流到达或会话关闭，关闭时返回 ErrSessionClosed。
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

// OpenStream 分配新流 ID，并向对端发送 OPEN 帧。
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

// Close 拆除会话及其全部逻辑流。
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
