package mux

import (
	"context"
	"encoding/binary"

	"bnfs_p2p/p2pnode"
)

// readLoop pulls frames off the P2P connection and dispatches them.
func (s *Session) readLoop() {
	defer s.shutdown(false)
	for {
		msg, err := s.conn.Receive(s.ctx)
		if err != nil {
			return
		}
		if len(msg.Payload) < headerBase {
			continue // malformed, skip
		}
		typ := msg.Payload[0]
		id := binary.BigEndian.Uint32(msg.Payload[1:5])

		switch typ {
		case frameOpen:
			s.handleOpen(id)
		case frameData:
			if len(msg.Payload) < headerSeq {
				continue // malformed
			}
			seq := binary.BigEndian.Uint64(msg.Payload[5:13])
			data := msg.Payload[headerSeq:]
			st := s.inboundStream(id)
			if st != nil {
				st.deliver(seq, data)
			}
		case frameClose:
			if len(msg.Payload) < headerSeq {
				continue // malformed
			}
			finalSeq := binary.BigEndian.Uint64(msg.Payload[5:13])
			st := s.inboundStream(id)
			// 不立即从表中删除：收端可能还有 seq<finalSeq 的 DATA 在途/重排缓冲里。
			// 由 deliverClose 在排空到 finalSeq 后再 closeLocal + removeStream。
			if st != nil {
				st.deliverClose(finalSeq)
			}
		case frameSessionClose:
			return
		case frameReset:
			st := s.stream(id)
			if st != nil {
				st.finishClose()
			}
		}
	}
}

// handleOpen registers a peer-opened stream and queues it for Accept.
func (s *Session) handleOpen(id uint32) {
	s.inboundStream(id)
}

func (s *Session) inboundStream(id uint32) *Stream {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	if st := s.streams[id]; st != nil {
		s.mu.Unlock()
		return st
	}
	st := newStream(s, id)
	s.streams[id] = st
	s.mu.Unlock()

	select {
	case s.accept <- st:
	case <-s.ctx.Done():
	}
	return st
}

// sendOpen sends an OPEN frame (no seq, no window — control frame, must precede DATA).
func (s *Session) sendOpen(ctx context.Context, id uint32) error {
	buf := make([]byte, headerBase)
	buf[0] = frameOpen
	binary.BigEndian.PutUint32(buf[1:5], id)
	return s.conn.Send(ctx, &p2pnode.Message{
		Type: p2pnode.MsgAppData, Path: p2pnode.TransportControlPath, Payload: buf,
	})
}

// sendData sends one DATA frame carrying a per-stream sequence number.
// 同时占用本流和 carrier 发送窗口各一个槽；conn.Send 阻塞到端到端 ACK 才返回。
// 两级窗口既允许多个业务流并行，又对总 ACK tracker 和缓冲内存设置硬上限。
func (s *Session) sendData(id uint32, seq uint64, data []byte, streamWindow chan struct{}) error {
	buf := make([]byte, headerSeq+len(data))
	buf[0] = frameData
	binary.BigEndian.PutUint32(buf[1:5], id)
	binary.BigEndian.PutUint64(buf[5:13], seq)
	copy(buf[headerSeq:], data)

	select {
	case streamWindow <- struct{}{}:
	case <-s.ctx.Done():
		return ErrSessionClosed
	}
	defer func() { <-streamWindow }()
	select {
	case s.sessionSendWindow <- struct{}{}:
	case <-s.ctx.Done():
		return ErrSessionClosed
	}
	defer func() { <-s.sessionSendWindow }()
	return s.conn.Send(s.ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: buf})
}

// sendClose sends a CLOSE frame carrying finalSeq (= total DATA frames sent on this stream).
// 不占窗口：调用方(Stream.Close)已等齐本流所有 DATA 发送完成，CLOSE 之后再无在途 DATA。
func (s *Session) sendClose(ctx context.Context, id uint32, finalSeq uint64) error {
	buf := make([]byte, headerSeq)
	buf[0] = frameClose
	binary.BigEndian.PutUint32(buf[1:5], id)
	binary.BigEndian.PutUint64(buf[5:13], finalSeq)
	return s.conn.Send(ctx, &p2pnode.Message{
		Type: p2pnode.MsgAppData, Path: p2pnode.TransportControlPath, Payload: buf,
	})
}

func (s *Session) sendReset(ctx context.Context, id uint32) error {
	buf := make([]byte, headerBase)
	buf[0] = frameReset
	binary.BigEndian.PutUint32(buf[1:5], id)
	return s.conn.Send(ctx, &p2pnode.Message{
		Type: p2pnode.MsgAppData, Path: p2pnode.TransportControlPath, Payload: buf,
	})
}

func (s *Session) sendSessionClose(ctx context.Context) error {
	buf := make([]byte, headerBase)
	buf[0] = frameSessionClose
	return s.conn.Send(ctx, &p2pnode.Message{
		Type: p2pnode.MsgAppData, Path: p2pnode.TransportControlPath, Payload: buf,
	})
}

func (s *Session) stream(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

// removeStream drops a stream from the table.
func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// Context exposes the session context for callers.
func (s *Session) Context() context.Context {
	return s.ctx
}
