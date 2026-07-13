package networkFrameWork

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"bnfs_p2p/network"
)

type failingReconnectStream struct {
	closed chan struct{}
	once   sync.Once
}

func newFailingReconnectStream() *failingReconnectStream {
	return &failingReconnectStream{closed: make(chan struct{})}
}

func (s *failingReconnectStream) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func (s *failingReconnectStream) NextMessage(context.Context) (*network.Message, error) {
	<-s.closed
	return nil, errors.New("closed")
}

func (s *failingReconnectStream) SendMessage(context.Context, *network.Message) error {
	return errors.New("send failed")
}
func (s *failingReconnectStream) SendMessageAsync(ctx context.Context, message *network.Message, callback network.MessageResultCallback) error {
	err := s.SendMessage(ctx, message)
	if callback != nil {
		callback(network.MessageResult{Error: err})
	}
	return err
}

func (s *failingReconnectStream) NodeId() string                     { return "node" }
func (s *failingReconnectStream) ConnectionId() string               { return "connection" }
func (s *failingReconnectStream) SetCryptoSuite(network.EncrypSuite) {}

func TestLegAvailableSignalBroadcastsToAllWaiters(t *testing.T) {
	dual := newDualStream("node", "connection")
	defer dual.Close()
	signal := dual.currentLegSignal()

	const waiters = 8
	var waitGroup sync.WaitGroup
	waitGroup.Add(waiters)
	for index := 0; index < waiters; index++ {
		go func() {
			defer waitGroup.Done()
			<-signal
		}()
	}
	dual.signalLegAvailable()

	done := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("leg 恢复通知没有唤醒全部在途发送")
	}
}

func TestResumeLegMarkerPreservesExtraFlag(t *testing.T) {
	message := &network.Message{Header: &network.Header{}}
	markExtraLeg(message)
	markResumeLeg(message)
	if !isExtraLegMarked(message) || !isResumeLegMarked(message) {
		t.Fatalf("恢复 leg 应同时保留 extra/resume 标记: flags=%08b", message.Header.LegFlags)
	}
}

func TestReconnectSurvivalRequiresCompletedHandshake(t *testing.T) {
	dual := newDualStream("node", "connection")
	stream := newFailingReconnectStream()
	if err := dual.attach(streamTransportTCP, stream); err != nil {
		t.Fatal(err)
	}
	dual.setPersistentReconnectDialer(streamTransportTCP, func(context.Context) (network.Stream, error) {
		return nil, errors.New("relay unavailable")
	})

	dual.handleLegFailure(streamTransportTCP, stream)
	select {
	case <-dual.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("握手前所有 leg 断开后逻辑流应立即关闭")
	}
}

func TestReconnectSurvivalKeepsEstablishedStreamAlive(t *testing.T) {
	dual := newDualStream("node", "connection")
	defer dual.Close()
	stream := newFailingReconnectStream()
	if err := dual.attach(streamTransportTCP, stream); err != nil {
		t.Fatal(err)
	}
	dual.setPersistentReconnectDialer(streamTransportTCP, func(context.Context) (network.Stream, error) {
		return nil, errors.New("relay unavailable")
	})
	dual.EnableReconnectSurvival()

	dual.handleLegFailure(streamTransportTCP, stream)
	select {
	case <-dual.ctx.Done():
		t.Fatal("握手后的逻辑流应等待 Relay 恢复或切换")
	case <-time.After(50 * time.Millisecond):
	}
}
