package relaynode

import (
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork/client"
	"context"
	"errors"
	"testing"
	"time"
)

type findFanoutTestStream struct {
	send func(context.Context, *network.Message) error
}

func (*findFanoutTestStream) Close() error { return nil }

func (*findFanoutTestStream) NextMessage(ctx context.Context) (*network.Message, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (stream *findFanoutTestStream) SendMessage(ctx context.Context, message *network.Message) error {
	return stream.send(ctx, message)
}

func (stream *findFanoutTestStream) SendMessageAsync(
	ctx context.Context,
	message *network.Message,
	_ network.MessageResultCallback,
) error {
	return stream.SendMessage(ctx, message)
}

func (*findFanoutTestStream) NodeId() string                     { return "find-fanout-test" }
func (*findFanoutTestStream) ConnectionId() string               { return "find-fanout-test" }
func (*findFanoutTestStream) SetCryptoSuite(network.EncrypSuite) {}

func newFindFanoutPeer(owner *RelayNode, peerID string, stream network.Stream) *peerLink {
	return &peerLink{
		owner:     owner,
		ctx:       owner.ctx,
		cancel:    func() {},
		sc:        client.NewStreamClient(stream),
		peerID:    peerID,
		peerAddr:  "127.0.0.1:1",
		countedUp: true,
	}
}

func TestFindHostRelayFanoutDoesNotBlockBehindStaleInboundLink(t *testing.T) {
	relay, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	t.Cleanup(func() { _ = relay.Close() })

	staleStarted := make(chan struct{})
	staleCanceled := make(chan struct{})
	staleStream := &findFanoutTestStream{
		send: func(ctx context.Context, _ *network.Message) error {
			close(staleStarted)
			<-ctx.Done()
			close(staleCanceled)
			return ctx.Err()
		},
	}
	staleLink := newFindFanoutPeer(relay, "stale-peer", staleStream)

	var healthyLink *peerLink
	healthyStream := &findFanoutTestStream{
		send: func(ctx context.Context, message *network.Message) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			find, err := decodeControl(message)
			if err != nil {
				return err
			}
			if find.Type != ctrlFind {
				return errors.New("unexpected control message")
			}
			relay.deliverFindResp(healthyLink, &controlMessage{
				Type:   ctrlFindResp,
				ReqID:  find.ReqID,
				Target: find.Target,
				Hosts:  true,
			})
			return nil
		},
	}
	healthyLink = newFindFanoutPeer(relay, "healthy-peer", healthyStream)

	relay.mu.Lock()
	relay.inboundLinks = []*peerLink{staleLink, healthyLink}
	relay.mu.Unlock()

	type findResult struct {
		link    *peerLink
		err     error
		elapsed time.Duration
	}
	resultCh := make(chan findResult, 1)
	go func() {
		startedAt := time.Now()
		link, err := relay.findHostRelay("target-nat")
		resultCh <- findResult{link: link, err: err, elapsed: time.Since(startedAt)}
	}()

	var result findResult
	select {
	case result = <-resultCh:
	case <-time.After(time.Second):
		relay.cancel()
		select {
		case <-resultCh:
		case <-time.After(time.Second):
		}
		t.Fatal("findHostRelay blocked behind the stale first link")
	}
	if result.err != nil {
		t.Fatalf("findHostRelay returned error: %v", result.err)
	}
	if result.link != healthyLink {
		t.Fatalf("findHostRelay returned link %p, want healthy link %p", result.link, healthyLink)
	}
	if result.elapsed >= time.Second {
		t.Fatalf("findHostRelay took %v, want significantly less than the 5s FIND deadline", result.elapsed)
	}

	select {
	case <-staleStarted:
	case <-time.After(time.Second):
		t.Fatal("stale link send was not started")
	}
	select {
	case <-staleCanceled:
	case <-time.After(time.Second):
		t.Fatal("stale link send did not stop when the FIND call completed")
	}
}

func TestFindHostRelayFanoutAllBlockedUsesSharedDeadline(t *testing.T) {
	relay, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	t.Cleanup(func() { _ = relay.Close() })

	deadlines := make(chan time.Time, 2)
	firstCanceled := make(chan struct{})
	secondCanceled := make(chan struct{})
	blockUntilCanceled := func(canceled chan struct{}) func(context.Context, *network.Message) error {
		return func(ctx context.Context, _ *network.Message) error {
			deadline, ok := ctx.Deadline()
			if !ok {
				return errors.New("FIND send context has no deadline")
			}
			deadlines <- deadline
			<-ctx.Done()
			close(canceled)
			return ctx.Err()
		}
	}

	firstLink := newFindFanoutPeer(relay, "blocked-peer-1", &findFanoutTestStream{
		send: blockUntilCanceled(firstCanceled),
	})
	secondLink := newFindFanoutPeer(relay, "blocked-peer-2", &findFanoutTestStream{
		send: blockUntilCanceled(secondCanceled),
	})
	relay.mu.Lock()
	relay.inboundLinks = []*peerLink{firstLink, secondLink}
	relay.mu.Unlock()

	type findResult struct {
		link    *peerLink
		err     error
		elapsed time.Duration
	}
	startedAt := time.Now()
	resultCh := make(chan findResult, 1)
	go func() {
		link, err := relay.findHostRelay("missing-target")
		resultCh <- findResult{link: link, err: err, elapsed: time.Since(startedAt)}
	}()

	var firstDeadline, secondDeadline time.Time
	for index := 0; index < 2; index++ {
		select {
		case deadline := <-deadlines:
			if index == 0 {
				firstDeadline = deadline
			} else {
				secondDeadline = deadline
			}
		case <-time.After(time.Second):
			relay.cancel()
			t.Fatal("not all blocked sends started")
		}
	}
	if !firstDeadline.Equal(secondDeadline) {
		relay.cancel()
		t.Fatalf("blocked sends received different deadlines: %v and %v", firstDeadline, secondDeadline)
	}
	if timeout := firstDeadline.Sub(startedAt); timeout < 4500*time.Millisecond || timeout > 5500*time.Millisecond {
		relay.cancel()
		t.Fatalf("shared FIND deadline is %v from start, want about 5s", timeout)
	}

	var result findResult
	select {
	case result = <-resultCh:
	case <-time.After(7 * time.Second):
		relay.cancel()
		t.Fatal("findHostRelay did not stop at the shared FIND deadline")
	}
	if result.err == nil {
		t.Fatal("findHostRelay unexpectedly found a host when every send was blocked")
	}
	if result.link != nil {
		t.Fatalf("findHostRelay returned link %p when every send was blocked", result.link)
	}
	if result.elapsed < 4500*time.Millisecond || result.elapsed > 6500*time.Millisecond {
		t.Fatalf("findHostRelay returned after %v, want the shared 5s deadline", result.elapsed)
	}
	select {
	case <-firstCanceled:
	case <-time.After(time.Second):
		t.Fatal("first blocked send was not canceled at the shared deadline")
	}
	select {
	case <-secondCanceled:
	case <-time.After(time.Second):
		t.Fatal("second blocked send was not canceled at the shared deadline")
	}
}
