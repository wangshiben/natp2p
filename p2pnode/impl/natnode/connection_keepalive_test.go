package natnode

import (
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/p2pnode"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type receiveSequenceStream struct {
	messages chan *network.Message
	closed   atomic.Bool
}

func (stream *receiveSequenceStream) Close() error {
	stream.closed.Store(true)
	return nil
}

func (stream *receiveSequenceStream) NextMessage(ctx context.Context) (*network.Message, error) {
	select {
	case message := <-stream.messages:
		return message, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (*receiveSequenceStream) SendMessage(context.Context, *network.Message) error {
	return errors.New("receive sequence stream is receive-only")
}

func (*receiveSequenceStream) SendMessageAsync(context.Context, *network.Message, network.MessageResultCallback) error {
	return errors.New("receive sequence stream is receive-only")
}

func (*receiveSequenceStream) NodeId() string       { return "receive-peer" }
func (*receiveSequenceStream) ConnectionId() string { return "receive-connection" }
func (*receiveSequenceStream) SetCryptoSuite(network.EncrypSuite) {
}

func TestNATConnectionReceiveSkipsLogicalKeepAlive(t *testing.T) {
	stream := &receiveSequenceStream{messages: make(chan *network.Message, 2)}
	var touches atomic.Int32
	connection := newNATConnection(
		p2pnode.PeerInfo{ID: "receive-peer"},
		stream,
		func() { touches.Add(1) },
		nil,
		nil,
		nil,
	)

	stream.messages <- &network.Message{Header: &network.Header{RouteName: networkFrameWork.KeepAliveRoute}}
	stream.messages <- EncodeMessage(
		&p2pnode.Message{Path: "/file/chunk", RequestID: 42, Payload: []byte("payload")},
		stream.NodeId(),
		stream.ConnectionId(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	message, err := connection.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive returned error after keepalive: %v", err)
	}
	if message == nil || message.RequestID != 42 || string(message.Payload) != "payload" {
		t.Fatalf("received message = %#v, want request 42 payload", message)
	}
	if touches.Load() != 2 {
		t.Fatalf("touch count=%d, want keepalive and application touch", touches.Load())
	}
}
