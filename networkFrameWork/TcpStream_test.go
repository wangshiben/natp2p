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
	"strings"
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

func TestTcpStreamInitialWriteCallbackPrecedesFinalAck(t *testing.T) {
	local, remote := net.Pipe()
	sender := startTcpStream("nodeB", uuid.New().String(), local)
	t.Cleanup(func() {
		sender.Close()
		remote.Close()
	})
	msg := makeTestMessage(50)

	initialWritten := make(chan struct{})
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- sender.SendMessageWithInitialWrite(
			context.Background(),
			msg,
			func() { close(initialWritten) },
		)
	}()

	select {
	case <-initialWritten:
		t.Fatal("initial-write callback fired before the receiver consumed the frame")
	case <-time.After(20 * time.Millisecond):
	}

	frame, err := network.ReadFrame(remote)
	if err != nil {
		t.Fatalf("read initial frame: %v", err)
	}

	select {
	case <-initialWritten:
	case <-time.After(time.Second):
		t.Fatal("initial-write callback did not fire after the frame write")
	}
	select {
	case err := <-sendDone:
		t.Fatalf("send returned before the final ACK: %v", err)
	default:
	}
	ack, err := network.BuildAckFrame(
		frame.MessageId,
		frame.TotalFrames,
		network.FullAckRange(frame.TotalFrames),
	)
	if err != nil {
		t.Fatalf("build ACK: %v", err)
	}
	ack.ConnectionId = frame.ConnectionId
	encoded, err := ack.AppendTo(nil)
	if err != nil {
		t.Fatalf("encode ACK: %v", err)
	}
	if _, err := remote.Write(encoded); err != nil {
		t.Fatalf("write ACK: %v", err)
	}
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("send: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("send did not return after the final ACK")
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

func TestTcpStreamStartKeepAliveClosesSilentLogicalPeer(t *testing.T) {
	local, remote := net.Pipe()
	stream := startTcpStream("silent-peer", uuid.New().String(), local)
	stream.keepAlivePolicy = streamKeepAlivePolicy{
		idleBaseline: 5 * time.Millisecond,
		probeBase:    5 * time.Millisecond,
		maxProbes:    1,
		probeTimeout: 5 * time.Millisecond,
	}
	t.Cleanup(func() {
		stream.Close()
		remote.Close()
	})
	go func() {
		_, _ = io.Copy(io.Discard, remote)
	}()

	stream.StartKeepAlive()
	stream.StartKeepAlive()

	select {
	case <-stream.streamCtx.Done():
	case <-time.After(250 * time.Millisecond):
		t.Fatal("silent logical peer was not reclaimed")
	}
	if err := stream.streamErr(); err == nil || !strings.Contains(err.Error(), "peer unreachable") {
		t.Fatalf("stream error=%v, want keepalive failure", err)
	}
}

func TestTcpStreamKeepAliveAcceptsAckProgressDuringOneWayTransfer(t *testing.T) {
	sender, receiver := newPipeStreams(t)
	sender.keepAlivePolicy = streamKeepAlivePolicy{
		idleBaseline: 10 * time.Millisecond,
		probeBase:    5 * time.Millisecond,
		maxProbes:    2,
		probeTimeout: 20 * time.Millisecond,
	}
	sender.StartKeepAlive()

	receiveErr := make(chan error, 1)
	go func() {
		for index := 0; index < 40; index++ {
			message, err := receiver.NextMessage(context.Background())
			if err != nil {
				receiveErr <- err
				return
			}
			if message == nil || len(message.Payload) == 0 {
				index--
			}
		}
		receiveErr <- nil
	}()

	for index := 0; index < 40; index++ {
		message := makeTestMessage(8 * 1024)
		message.Payload[0] = byte(index)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := sender.SendMessage(ctx, message)
		cancel()
		if err != nil {
			t.Fatalf("one-way message %d: %v", index, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if err := <-receiveErr; err != nil {
		t.Fatalf("receiver: %v", err)
	}
	select {
	case <-sender.streamCtx.Done():
		t.Fatalf("sender was reclaimed despite continuous ACK progress: %v", sender.streamErr())
	default:
	}
}

func TestTcpStreamKeepAliveDefersToPendingBusinessSend(t *testing.T) {
	local, remote := net.Pipe()
	stream := startTcpStream("slow-peer", uuid.New().String(), local)
	stream.keepAlivePolicy = streamKeepAlivePolicy{
		idleBaseline: 5 * time.Millisecond,
		probeBase:    5 * time.Millisecond,
		maxProbes:    1,
		probeTimeout: 5 * time.Millisecond,
	}
	t.Cleanup(func() {
		stream.Close()
		remote.Close()
	})

	received := make(chan *network.Frame, 1)
	go func() {
		frame, _ := network.ReadFrame(remote)
		received <- frame
	}()
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- stream.SendMessage(context.Background(), makeTestMessage(8*1024))
	}()
	select {
	case frame := <-received:
		if frame == nil {
			t.Fatal("business frame was not received")
		}
	case <-time.After(time.Second):
		t.Fatal("business frame did not reach peer")
	}

	stream.StartKeepAlive()
	time.Sleep(4 * stream.keepAlivePolicy.idleBaseline)
	select {
	case <-stream.streamCtx.Done():
		t.Fatalf("keepalive closed a stream with a pending business send: %v", stream.streamErr())
	default:
	}

	_ = remote.Close()
	select {
	case <-sendDone:
	case <-time.After(time.Second):
		t.Fatal("pending business send did not stop after peer close")
	}
}
