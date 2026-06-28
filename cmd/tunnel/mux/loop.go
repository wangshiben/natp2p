package mux

import (
	"context"
	"encoding/binary"

	"bnfs_p2p/p2pnode"
)

// readLoop pulls frames off the P2P connection and dispatches them.
func (s *Session) readLoop() {
	defer s.Close()
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
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			if st != nil {
				st.deliver(seq, data)
			}
		case frameClose:
			if len(msg.Payload) < headerSeq {
				continue // malformed
			}
			finalSeq := binary.BigEndian.Uint64(msg.Payload[5:13])
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			// 不立即从表中删除：收端可能还有 seq<finalSeq 的 DATA 在途/重排缓冲里。
			// 由 deliverClose 在排空到 finalSeq 后再 closeLocal + removeStream。
			if st != nil {
				st.deliverClose(finalSeq)
			}
		}
	}
}

// handleOpen registers a peer-opened stream and queues it for Accept.
func (s *Session) handleOpen(id uint32) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if _, exists := s.streams[id]; exists {
		s.mu.Unlock()
		return
	}
	st := newStream(s, id)
	s.streams[id] = st
	s.mu.Unlock()

	select {
	case s.accept <- st:
	case <-s.ctx.Done():
	}
}

// sendOpen sends an OPEN frame (no seq, no window — control frame, must precede DATA).
func (s *Session) sendOpen(id uint32) error {
	buf := make([]byte, headerBase)
	buf[0] = frameOpen
	binary.BigEndian.PutUint32(buf[1:5], id)
	return s.conn.Send(s.ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: buf})
}

// sendData sends one DATA frame carrying a per-stream sequence number.
// 占用发送窗口一个槽(限制全会话在途消息数)；conn.Send 阻塞到端到端 ACK 才返回，
// 期间窗口槽被占用，形成 W 路并发流水线。conn.Send 并发安全(底层每消息独立 messageId/tracker)。
func (s *Session) sendData(id uint32, seq uint64, data []byte) error {
	buf := make([]byte, headerSeq+len(data))
	buf[0] = frameData
	binary.BigEndian.PutUint32(buf[1:5], id)
	binary.BigEndian.PutUint64(buf[5:13], seq)
	copy(buf[headerSeq:], data)

	select {
	case s.sendWindow <- struct{}{}:
	case <-s.ctx.Done():
		return ErrSessionClosed
	}
	defer func() { <-s.sendWindow }()
	return s.conn.Send(s.ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: buf})
}

// sendClose sends a CLOSE frame carrying finalSeq (= total DATA frames sent on this stream).
// 不占窗口：调用方(Stream.Close)已等齐本流所有 DATA 发送完成，CLOSE 之后再无在途 DATA。
func (s *Session) sendClose(id uint32, finalSeq uint64) error {
	buf := make([]byte, headerSeq)
	buf[0] = frameClose
	binary.BigEndian.PutUint32(buf[1:5], id)
	binary.BigEndian.PutUint64(buf[5:13], finalSeq)
	return s.conn.Send(s.ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: buf})
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
