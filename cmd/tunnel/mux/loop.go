package mux

import (
	"context"
	"encoding/binary"

	"bnfs_p2p/p2pnode"
)

// readLoop 从 P2P 连接读取帧并完成分派。
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

// handleOpen 登记对端打开的流，并放入 Accept 队列。
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

// sendOpen 发送 OPEN 控制帧；它没有序号和窗口，且必须先于 DATA。
func (s *Session) sendOpen(ctx context.Context, id uint32) error {
	buf := make([]byte, headerBase)
	buf[0] = frameOpen
	binary.BigEndian.PutUint32(buf[1:5], id)
	return s.conn.Send(ctx, &p2pnode.Message{
		Type: p2pnode.MsgAppData, Path: p2pnode.TransportControlPath, Payload: buf,
	})
}

// sendData 发送一帧 DATA，并携带流内序号。
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

// sendClose 发送 CLOSE 帧，其中 finalSeq 等于本流已发送的 DATA 帧总数。
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

// removeStream 从会话表中移除逻辑流。
func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// Context 向调用方暴露会话上下文。
func (s *Session) Context() context.Context {
	return s.ctx
}
