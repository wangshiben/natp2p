package networkFrameWork

import (
	"bnfs_p2p/network"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newPipeStreams(t *testing.T) (*TcpStream, *TcpStream) {
	t.Helper()
	connA, connB := net.Pipe()
	a := startTcpStream("nodeA", uuid.New().String(), connA)
	b := startTcpStream("nodeB", uuid.New().String(), connB)
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})
	return a, b
}

func makeTestMessage(payloadSize int) *network.Message {
	hash := sha256.Sum256([]byte("frame-stream-test"))
	nodeId := hex.EncodeToString(hash[:])
	payload := make([]byte, payloadSize)
	if payloadSize > 0 {
		_, _ = rand.Read(payload)
	}
	return &network.Message{
		Header: &network.Header{
			NodeId:        nodeId,
			NodeIdVersion: 1,
			RouteName:     "/api/v1/test",
			ConnectionId:  uuid.New().String(),
		},
		Payload: payload,
	}
}

func TestTcpStreamSendBlocksUntilAck(t *testing.T) {
	sender, receiver := newPipeStreams(t)
	msg := makeTestMessage(50)

	done := make(chan error, 1)
	go func() {
		done <- sender.SendMessage(context.Background(), msg)
	}()

	got, err := receiver.NextMessage(context.Background())
	if err != nil {
		t.Fatalf("NextMessage: %v", err)
	}
	if !bytes.Equal(got.Payload, msg.Payload) {
		t.Errorf("payload mismatch")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendMessage: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendMessage did not return after ACK")
	}
}

func TestTcpStreamSendLargeMessageBatchAck(t *testing.T) {
	sender, receiver := newPipeStreams(t)
	msg := makeTestMessage(network.DefaultMaxFramePayload * 250)

	done := make(chan error, 1)
	go func() {
		done <- sender.SendMessage(context.Background(), msg)
	}()

	got, err := receiver.NextMessage(context.Background())
	if err != nil {
		t.Fatalf("NextMessage: %v", err)
	}
	if !bytes.Equal(got.Payload, msg.Payload) {
		t.Errorf("payload mismatch (len=%d vs %d)", len(got.Payload), len(msg.Payload))
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendMessage: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendMessage did not return after ACK")
	}
}

// dropFirstMessageConn 丢弃第一条 SendMessage 写出的所有数据帧（仅 Data 帧），
// 让发送侧触发重传，测试重传后接收侧能拿到完整 Message。
type dropFirstMessageConn struct {
	net.Conn
	dropped atomic.Bool
}

func (d *dropFirstMessageConn) Write(p []byte) (int, error) {
	if d.dropped.Load() {
		return d.Conn.Write(p)
	}
	if len(p) >= network.FrameHeaderLength {
		f, err := network.ParseFrame(p)
		if err == nil && f.FrameType == network.FrameTypeData {
			d.dropped.Store(true)
			return len(p), nil
		}
	}
	return d.Conn.Write(p)
}

func TestTcpStreamRetransmitsAfterTimeout(t *testing.T) {
	connA, connB := net.Pipe()
	dropping := &dropFirstMessageConn{Conn: connA}
	sender := startTcpStream("nodeA", uuid.New().String(), dropping)
	receiver := startTcpStream("nodeB", uuid.New().String(), connB)
	t.Cleanup(func() {
		sender.Close()
		receiver.Close()
	})

	msg := makeTestMessage(200)
	done := make(chan error, 1)
	go func() {
		done <- sender.SendMessage(context.Background(), msg)
	}()

	got, err := receiver.NextMessage(context.Background())
	if err != nil {
		t.Fatalf("NextMessage: %v", err)
	}
	if !bytes.Equal(got.Payload, msg.Payload) {
		t.Errorf("payload mismatch")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendMessage: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SendMessage did not return after retransmit")
	}
}

// silentConn 把全部写丢弃，让发送方耗尽重试次数。
type silentConn struct {
	net.Conn
}

func (s *silentConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func TestTcpStreamSendMaxRetransmits(t *testing.T) {
	connA, connB := net.Pipe()
	sender := startTcpStream("nodeA", uuid.New().String(), &silentConn{Conn: connA})
	t.Cleanup(func() {
		sender.Close()
		connB.Close()
	})

	err := sender.SendMessage(context.Background(), makeTestMessage(50))
	if err == nil {
		t.Fatal("expected error after exhausting retransmits")
	}
}

func TestNextMessageHonorsContextCancel(t *testing.T) {
	_, receiver := newPipeStreams(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err := receiver.NextMessage(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestNextMessageHonorsContextDeadline(t *testing.T) {
	_, receiver := newPipeStreams(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := receiver.NextMessage(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

func TestTcpStreamFatalOnBadFrame(t *testing.T) {
	connA, connB := net.Pipe()
	receiver := startTcpStream("nodeB", uuid.New().String(), connB)
	t.Cleanup(func() {
		receiver.Close()
		connA.Close()
	})

	garbage := make([]byte, network.FrameHeaderLength)
	go func() {
		_, _ = connA.Write(garbage)
	}()

	_, err := receiver.NextMessage(context.Background())
	if err == nil {
		t.Fatal("expected error from bad frame")
	}
	if _, err := receiver.NextMessage(context.Background()); err == nil {
		t.Fatal("expected stream to remain closed after bad frame")
	}
}

func TestTcpStreamSendFailsWhenStreamClosed(t *testing.T) {
	sender, receiver := newPipeStreams(t)
	receiver.Close()
	time.Sleep(50 * time.Millisecond)
	err := sender.SendMessage(context.Background(), makeTestMessage(20))
	if err == nil {
		t.Fatal("expected error after peer closed")
	}
	if errors.Is(err, io.EOF) || err != nil {
		// ok
	}
}

func TestTcpStreamFrameRelayModeDoesNotBlockOnInbox(t *testing.T) {
	sender, receiver := newPipeStreams(t)
	_ = NewTcpFrameAdapter(receiver)

	done := make(chan error, 1)
	go func() {
		for i := 0; i < 80; i++ {
			if err := sender.SendMessage(context.Background(), makeTestMessage(32)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendMessage: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendMessage blocked when relay stream inbox was not consumed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := receiver.NextMessage(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected relay-mode stream to skip inbox delivery, got %v", err)
	}
}
