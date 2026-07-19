package network

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func makeMessage(t *testing.T, payloadSize int) *Message {
	t.Helper()
	hash := sha256.Sum256([]byte("frame-test-node"))
	nodeId := hex.EncodeToString(hash[:])

	payload := make([]byte, payloadSize)
	if payloadSize > 0 {
		if _, err := rand.Read(payload); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
	}
	return &Message{
		Header: &Header{
			NodeId:        nodeId,
			NodeIdVersion: 1,
			RouteName:     "/api/v1/frame",
			ConnectionId:  uuid.New().String(),
		},
		Payload: payload,
	}
}

func TestFrameSerialization(t *testing.T) {
	original := &Frame{
		MessageId:   42,
		SeqId:       3,
		TotalFrames: 10,
		AckId:       7,
		FrameType:   FrameTypeData,
		Payload:     []byte("hello frame"),
	}
	bs, err := original.ParseToBytes()
	if err != nil {
		t.Fatalf("ParseToBytes: %v", err)
	}
	if len(bs) != FrameHeaderLength+len(original.Payload) {
		t.Errorf("unexpected frame size: got %d want %d", len(bs), FrameHeaderLength+len(original.Payload))
	}
	parsed, err := ParseFrame(bs)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if parsed.MessageId != original.MessageId ||
		parsed.SeqId != original.SeqId ||
		parsed.TotalFrames != original.TotalFrames ||
		parsed.AckId != original.AckId ||
		parsed.FrameType != original.FrameType {
		t.Errorf("frame metadata mismatch: %+v vs %+v", parsed, original)
	}
	if !bytes.Equal(parsed.Payload, original.Payload) {
		t.Errorf("payload mismatch")
	}
}

func TestFrameConnectionIdRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		connId  string
		payload []byte
		ftype   uint8
	}{
		{"empty connId data frame", "", []byte("hello"), FrameTypeData},
		{"uuid connId data frame", uuid.New().String(), []byte("world payload"), FrameTypeData},
		{"uuid connId empty payload control frame", uuid.New().String(), nil, FrameTypeFrameSizeChange},
		{"connId with empty payload data frame", uuid.New().String(), nil, FrameTypeData},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := &Frame{
				MessageId:    11,
				SeqId:        2,
				TotalFrames:  5,
				AckId:        800,
				FrameType:    tc.ftype,
				ConnectionId: tc.connId,
				Payload:      tc.payload,
			}
			bs, err := original.ParseToBytes()
			if err != nil {
				t.Fatalf("ParseToBytes: %v", err)
			}
			wantLen := FrameHeaderLength + len(tc.connId) + len(tc.payload)
			if len(bs) != wantLen {
				t.Errorf("serialized size = %d want %d", len(bs), wantLen)
			}

			// 路径1: ParseFrame(完整字节)
			parsed, err := ParseFrame(bs)
			if err != nil {
				t.Fatalf("ParseFrame: %v", err)
			}
			assertFrameEq(t, parsed, original)

			// 路径2: ReadFrame(io.Reader) —— 两段读路径
			read, err := ReadFrame(bytes.NewReader(bs))
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			assertFrameEq(t, read, original)
		})
	}
}

func TestReadFrameRejectsOversizedPayloadBeforeBodyRead(t *testing.T) {
	header := make([]byte, FrameHeaderLength)
	copy(header, []byte(FrameMagic))
	binary.LittleEndian.PutUint32(header[FrameHeaderLength-framePayloadLenLength:], maxFramePayloadLength+1)

	frame, err := ReadFrame(bytes.NewReader(header))
	if !errors.Is(err, errFramePayloadTooLarge) || frame != nil {
		t.Fatalf("ReadFrame oversized payload = (%v, %v), want safety-limit error", frame, err)
	}
}

func assertFrameEq(t *testing.T, got, want *Frame) {
	t.Helper()
	if got.MessageId != want.MessageId || got.SeqId != want.SeqId ||
		got.TotalFrames != want.TotalFrames || got.AckId != want.AckId ||
		got.FrameType != want.FrameType {
		t.Errorf("frame metadata mismatch: got %+v want %+v", got, want)
	}
	if got.ConnectionId != want.ConnectionId {
		t.Errorf("ConnectionId mismatch: got %q want %q", got.ConnectionId, want.ConnectionId)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("payload mismatch: got %q want %q", got.Payload, want.Payload)
	}
}

func TestSplitAndAssemble(t *testing.T) {
	cases := []struct {
		name        string
		payloadSize int
		maxPayload  int
	}{
		{"empty payload", 0, 256},
		{"smaller than one frame", 50, 1024},
		{"exact multiple of frames", 2048, 512},
		{"non-multiple split", 5000, 700},
		{"default max payload", 4500, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := makeMessage(t, tc.payloadSize)
			frames, err := msg.SplitToFrames(99, tc.maxPayload)
			if err != nil {
				t.Fatalf("SplitToFrames: %v", err)
			}
			if len(frames) == 0 {
				t.Fatalf("no frames produced")
			}
			total := frames[0].TotalFrames
			for i, f := range frames {
				if f.MessageId != 99 {
					t.Errorf("frame %d MessageId mismatch", i)
				}
				if f.SeqId != uint32(i) {
					t.Errorf("frame %d SeqId mismatch", i)
				}
				if f.TotalFrames != total {
					t.Errorf("frame %d TotalFrames mismatch", i)
				}
			}

			rebuilt, err := AssembleFrames(frames)
			if err != nil {
				t.Fatalf("AssembleFrames: %v", err)
			}
			if rebuilt.Header.NodeId != msg.Header.NodeId {
				t.Errorf("NodeId mismatch")
			}
			if rebuilt.Header.RouteName != msg.Header.RouteName {
				t.Errorf("RouteName mismatch")
			}
			if rebuilt.Header.ConnectionId != msg.Header.ConnectionId {
				t.Errorf("ConnectionId mismatch")
			}
			if !bytes.Equal(rebuilt.Payload, msg.Payload) {
				t.Errorf("payload mismatch")
			}
		})
	}
}

func TestAssembleFramesOutOfOrder(t *testing.T) {
	msg := makeMessage(t, 3000)
	frames, err := msg.SplitToFrames(7, 400)
	if err != nil {
		t.Fatalf("SplitToFrames: %v", err)
	}
	shuffled := []*Frame{frames[2], frames[0], frames[len(frames)-1]}
	rest := frames[1:2]
	rest = append(rest, frames[3:len(frames)-1]...)
	shuffled = append(shuffled, rest...)

	rebuilt, err := AssembleFrames(shuffled)
	if err != nil {
		t.Fatalf("AssembleFrames out of order: %v", err)
	}
	if !bytes.Equal(rebuilt.Payload, msg.Payload) {
		t.Errorf("payload mismatch after reorder")
	}
}

func TestFrameAssembler(t *testing.T) {
	msg := makeMessage(t, 4000)
	frames, err := msg.SplitToFrames(123, 600)
	if err != nil {
		t.Fatalf("SplitToFrames: %v", err)
	}

	asm := NewFrameAssembler()
	for i := 0; i < len(frames)-1; i++ {
		out, err := asm.Add(frames[i])
		if err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
		if out != nil {
			t.Fatalf("Add[%d] returned message before all frames arrived", i)
		}
	}

	dup, err := asm.Add(frames[0])
	if err != nil {
		t.Fatalf("duplicate Add returned err: %v", err)
	}
	if dup != nil {
		t.Fatalf("duplicate Add returned message prematurely")
	}

	out, err := asm.Add(frames[len(frames)-1])
	if err != nil {
		t.Fatalf("final Add: %v", err)
	}
	if out == nil {
		t.Fatalf("expected reassembled message after final frame")
	}
	if !bytes.Equal(out.Payload, msg.Payload) {
		t.Errorf("payload mismatch after assembler")
	}
}

func TestFrameIdGenerator(t *testing.T) {
	var g FrameIdGenerator
	if id := g.Next(); id != 1 {
		t.Errorf("first id = %d, want 1", id)
	}
	if id := g.Next(); id != 2 {
		t.Errorf("second id = %d, want 2", id)
	}
}
