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
		if len(msg.Payload) < headerLen {
			continue // malformed, skip
		}
		typ := msg.Payload[0]
		id := binary.BigEndian.Uint32(msg.Payload[1:5])
		data := msg.Payload[headerLen:]

		switch typ {
		case frameOpen:
			s.handleOpen(id)
		case frameData:
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			if st != nil {
				st.deliver(data)
			}
		case frameClose:
			s.mu.Lock()
			st := s.streams[id]
			delete(s.streams, id)
			s.mu.Unlock()
			if st != nil {
				st.closeLocal()
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

// sendFrame serializes a single frame as one P2P message.
func (s *Session) sendFrame(typ byte, id uint32, data []byte) error {
	buf := make([]byte, headerLen+len(data))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:5], id)
	copy(buf[headerLen:], data)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.Send(s.ctx, &p2pnode.Message{
		Type:    p2pnode.MsgAppData,
		Payload: buf,
	})
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
