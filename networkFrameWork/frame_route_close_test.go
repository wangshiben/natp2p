package networkFrameWork

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"bnfs_p2p/network"
)

type closeRouteTestEndpoint struct {
	connectionID string
	incoming     chan *network.Frame
	handled      chan *network.Frame
	messageID    atomic.Uint64
}

func (endpoint *closeRouteTestEndpoint) NextFrame(ctx context.Context) (*network.Frame, error) {
	select {
	case frame := <-endpoint.incoming:
		return frame, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (endpoint *closeRouteTestEndpoint) HandleFrame(ctx context.Context, frame *network.Frame) error {
	select {
	case endpoint.handled <- frame:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (endpoint *closeRouteTestEndpoint) AllocMessageId() uint64 {
	return endpoint.messageID.Add(1)
}

func (*closeRouteTestEndpoint) NodeId() string { return "close-route-node" }

func (endpoint *closeRouteTestEndpoint) ConnectionId() string { return endpoint.connectionID }

func (*closeRouteTestEndpoint) Close() error { return nil }

func TestRelayConnectionCloseBypassesMessageRouteRegistry(t *testing.T) {
	const connectionID = "close-route-connection"
	source := &closeRouteTestEndpoint{
		incoming: make(chan *network.Frame, 1),
		handled:  make(chan *network.Frame, 1),
	}
	destination := &closeRouteTestEndpoint{
		connectionID: connectionID,
		incoming:     make(chan *network.Frame, 1),
		handled:      make(chan *network.Frame, 1),
	}
	routes := newFrameRouteRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		pumpRelayToClients(
			ctx,
			source,
			func(candidate string) FrameRelayEndpoint {
				if candidate == connectionID {
					return destination
				}
				return nil
			},
			routes,
			nil,
			"close-route-node",
			nil,
		)
		close(done)
	}()

	source.incoming <- &network.Frame{
		MessageId:    77,
		FrameType:    network.FrameTypeConnectionClose,
		ConnectionId: connectionID,
	}
	select {
	case frame := <-destination.handled:
		if frame.FrameType != network.FrameTypeConnectionClose ||
			frame.ConnectionId != connectionID ||
			frame.MessageId == 77 {
			t.Fatalf("forwarded close frame = %+v", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not forward connection close")
	}

	routes.mu.Lock()
	pairCount := routes.pairCount
	routes.mu.Unlock()
	if pairCount != 0 {
		t.Fatalf("connection close created %d message routes", pairCount)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay close test pump did not stop")
	}
}

var _ FrameRelayEndpoint = (*closeRouteTestEndpoint)(nil)
